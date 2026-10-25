//! `docker.prune` — remove orphaned engine resources.
//!
//! Candidates are dangling images, dangling **anonymous** volumes and compose
//! networks no container uses. Named volumes are never candidates: a volume
//! qualifies only when the engine stamped it `com.docker.volume.anonymous`,
//! and never when compose declared it by name (`com.docker.compose.volume`).
//!
//! A `--stack` prune attributes a volume by its `orca.stack` label, else its
//! `com.docker.compose.project` label, else a container that mounts it.
//! Compose (2.31 and 2.40, measured on the fleet) labels anonymous volumes
//! with neither, and a dangling volume has no container by definition, so
//! only anonymous volumes created with orca's labels (`volume-label`, by
//! core's container create per orca#772) are found that way.
//!
//! Networks that any managed stack declares `external: true` are never
//! candidates. When a stack's config cannot be read, no network is a
//! candidate, because any of them might be that stack's external network.
//!
//! Opt-in, host-wide only: `unusedImages` adds tagged images that no
//! container, running or stopped, uses directly or through a parent or child
//! image, last pulled or tagged (`Metadata.LastTagTime`) at least
//! `minPullAgeDays` (default 1) and, if set, `olderThanDays` ago, and only the
//! oldest-created until the unused ones left fit `keepBytes`; `buildCache`
//! prunes the build cache down to `buildCacheKeepBytes`; `orphanVolumes` adds
//! named volumes no container mounts that carry no compose project or
//! `orca.stack` label and were created at least `orphanVolumeMinAgeDays`
//! (default 7) ago. Image bytes count only layers no other image shares.
//!
//! An image is removed by one DELETE of its id without force, which the engine
//! refuses atomically when anything uses it. An image with several tags is
//! refused that way too; it is then untagged one tag at a time, each right
//! after re-checking that no container uses it, stopping at the first that
//! does.
//!
//! `dry_run` returns the plan, which lists every candidate by key. A volume's
//! key carries its creation time and the build cache's its reclaimable size,
//! so a recreated volume or a changed cache is not what was planned. Execute
//! takes those keys back, recomputes the candidates, and removes only keys
//! present in both. The engine still refuses to remove anything in use, which
//! is reported as skipped.
#![allow(clippy::disallowed_types)]

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::time::Duration;

use bollard::Docker;
use bollard::models::{ContainerSummary, ImageSummary, Network, Volume};
use bollard::query_parameters::{
    DataUsageOptions, ListContainersOptionsBuilder, ListImagesOptionsBuilder,
    ListNetworksOptionsBuilder, ListVolumesOptionsBuilder, PruneBuildOptionsBuilder,
    RemoveImageOptionsBuilder, RemoveVolumeOptionsBuilder,
};
use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::prelude::*;

use crate::execute;

pub const ANONYMOUS_VOLUME_LABEL: &str = "com.docker.volume.anonymous";
pub const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";
pub const COMPOSE_VOLUME_LABEL: &str = "com.docker.compose.volume";

const TOOL: &str = "docker.prune";

/// What a candidate is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "lowercase")]
pub enum ResourceKind {
    Image,
    Volume,
    Network,
    BuildCache,
}

impl ResourceKind {
    fn prefix(self) -> &'static str {
        match self {
            ResourceKind::Image => "image",
            ResourceKind::Volume => "volume",
            ResourceKind::Network => "network",
            ResourceKind::BuildCache => "buildcache",
        }
    }
}

/// One removable resource. `key` (`<kind>:<engine id or name>`) is what the
/// plan lists and what execute takes back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct Candidate {
    pub key: String,
    pub kind: ResourceKind,
    /// Engine id (images, networks) or name (volumes) used to remove it.
    pub id: String,
    pub detail: String,
    #[serde(default)]
    pub bytes: i64,
}

impl Candidate {
    fn new(kind: ResourceKind, id: &str, detail: String) -> Self {
        Self {
            key: format!("{}:{id}", kind.prefix()),
            kind,
            id: id.to_string(),
            detail,
            bytes: 0,
        }
    }
}

/// What a prune may consider.
#[derive(Debug, Clone, Copy, Default)]
pub struct Scope<'a> {
    /// Limit to one compose project.
    pub project: Option<&'a str>,
    /// Networks managed stacks declare `external: true`, by name or id.
    /// `None` means unknown, so no network is a candidate.
    pub external_networks: Option<&'a HashSet<String>>,
    pub extras: Extras,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnusedImages {
    pub now: i64,
    pub older_than_secs: Option<i64>,
    pub keep_bytes: Option<i64>,
    pub min_pull_age_secs: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OrphanVolumes {
    pub now: i64,
    pub min_age_secs: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Extras {
    pub unused_images: Option<UnusedImages>,
    pub build_cache_keep_bytes: Option<i64>,
    pub orphan_volumes: Option<OrphanVolumes>,
}

const DAY: u64 = 86_400;
const DEFAULT_MIN_PULL_AGE_DAYS: u64 = 1;
const DEFAULT_ORPHAN_VOLUME_MIN_AGE_DAYS: u64 = 7;

fn epoch(date: Option<&str>) -> Option<i64> {
    plugin_toolkit::time::Timestamp::parse_rfc3339(date?)
        .ok()
        .map(|t| t.unix_seconds())
        .filter(|&t| t > 0)
}

fn unique_bytes(i: &ImageSummary) -> i64 {
    if i.shared_size < 0 {
        i.size.max(0)
    } else {
        (i.size - i.shared_size).max(0)
    }
}

fn container_image_ids<'a>(
    images: &'a [ImageSummary],
    containers: &'a [ContainerSummary],
) -> HashSet<&'a str> {
    let mut used = HashSet::new();
    for c in containers {
        if let Some(id) = c.image_id.as_deref().filter(|id| !id.is_empty()) {
            used.insert(id);
            continue;
        }
        let Some(name) = c.image.as_deref() else {
            continue;
        };
        if let Some(i) = images.iter().find(|i| {
            i.repo_tags.iter().any(|t| t == name)
                || i.repo_digests.iter().any(|d| d == name)
                || i.id == name
        }) {
            used.insert(i.id.as_str());
        }
    }
    used
}

fn protected_images<'a>(
    images: &'a [ImageSummary],
    containers: &'a [ContainerSummary],
) -> HashSet<&'a str> {
    let parent: HashMap<&str, &str> = images
        .iter()
        .filter(|i| !i.parent_id.is_empty())
        .map(|i| (i.id.as_str(), i.parent_id.as_str()))
        .collect();
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for (child, p) in &parent {
        children.entry(p).or_default().push(child);
    }
    let used = container_image_ids(images, containers);
    let mut out: HashSet<&str> = HashSet::new();
    for &id in &used {
        let mut cur = id;
        while let Some(&p) = parent.get(cur) {
            if !out.insert(p) {
                break;
            }
            cur = p;
        }
        let mut stack = vec![id];
        while let Some(n) = stack.pop() {
            if out.insert(n) {
                stack.extend(children.get(n).into_iter().flatten().copied());
            }
        }
    }
    out
}

fn unused_images<'a>(
    images: &'a [ImageSummary],
    containers: &[ContainerSummary],
) -> Vec<&'a ImageSummary> {
    let protected = protected_images(images, containers);
    images
        .iter()
        .filter(|i| !is_dangling_image(i) && !protected.contains(i.id.as_str()))
        .collect()
}

pub fn unused_image_candidates(
    images: &[ImageSummary],
    containers: &[ContainerSummary],
    u: UnusedImages,
    tagged_at: &HashMap<String, i64>,
) -> Vec<Candidate> {
    let unused = unused_images(images, containers);
    let min_age = u.older_than_secs.unwrap_or(0).max(u.min_pull_age_secs);
    let mut eligible: Vec<&ImageSummary> = unused
        .iter()
        .copied()
        .filter(|i| tagged_at.get(&i.id).is_some_and(|&t| t <= u.now - min_age))
        .collect();
    eligible.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
    if let Some(budget) = u.keep_bytes {
        let mut total: i64 = unused.iter().map(|i| unique_bytes(i)).sum();
        eligible.retain(|i| {
            if total <= budget {
                return false;
            }
            total -= unique_bytes(i);
            true
        });
    }
    eligible
        .into_iter()
        .map(|i| Candidate {
            bytes: unique_bytes(i),
            ..Candidate::new(
                ResourceKind::Image,
                &i.id,
                format!(
                    "unused image {}, created {}d ago, last pulled or tagged {}d ago, {} unique bytes",
                    i.repo_tags.join(", "),
                    (u.now - i.created).max(0) / 86_400,
                    tagged_at.get(&i.id).map_or(0, |t| (u.now - t).max(0) / 86_400),
                    unique_bytes(i)
                ),
            )
        })
        .collect()
}

fn volume_candidate(v: &Volume, detail: &str) -> Candidate {
    let mut c = Candidate::new(ResourceKind::Volume, &v.name, detail.to_string());
    if let Some(created) = v.created_at.as_deref() {
        c.key = format!("{}@{created}", c.key);
    }
    c
}

pub fn orphan_volume_candidates(
    volumes: &[Volume],
    project: Option<&str>,
    mounts: &HashMap<String, String>,
    o: OrphanVolumes,
) -> Vec<Candidate> {
    volumes
        .iter()
        .filter(|v| {
            !v.labels.contains_key(ANONYMOUS_VOLUME_LABEL)
                || v.labels.contains_key(COMPOSE_VOLUME_LABEL)
        })
        .filter(|v| {
            !v.labels.contains_key(COMPOSE_PROJECT_LABEL)
                && !v.labels.contains_key(crate::labels::STACK)
        })
        .filter(|v| epoch(v.created_at.as_deref()).is_some_and(|t| t <= o.now - o.min_age_secs))
        .filter(|v| match project {
            Some(p) => crate::label_audit::volume_owner(v, mounts).as_deref() == Some(p),
            None => true,
        })
        .map(|v| volume_candidate(v, "orphaned named volume, no container mounts it"))
        .collect()
}

fn as_bytes(name: &str, v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| anyhow!("{TOOL}: `{name}` is too large"))
}

fn days(name: &str, d: u64) -> Result<i64> {
    as_bytes(name, d.saturating_mul(DAY))
}

pub fn extras(args: &DockerPruneArgs, now: i64) -> Result<Extras> {
    if !args.unused_images
        && (args.older_than_days.is_some()
            || args.keep_bytes.is_some()
            || args.min_pull_age_days.is_some())
    {
        bail!("{TOOL}: `olderThanDays`, `minPullAgeDays` and `keepBytes` need `unusedImages`");
    }
    if !args.orphan_volumes && args.orphan_volume_min_age_days.is_some() {
        bail!("{TOOL}: `orphanVolumeMinAgeDays` needs `orphanVolumes`");
    }
    if !args.build_cache && args.build_cache_keep_bytes.is_some() {
        bail!("{TOOL}: `buildCacheKeepBytes` needs `buildCache`");
    }
    if args.stack.is_some() && (args.unused_images || args.build_cache || args.orphan_volumes) {
        bail!(
            "{TOOL}: `unusedImages`, `buildCache` and `orphanVolumes` are host-wide; drop `stack`"
        );
    }
    let unused_images = if args.unused_images {
        Some(UnusedImages {
            now,
            older_than_secs: args
                .older_than_days
                .map(|d| days("olderThanDays", d))
                .transpose()?,
            keep_bytes: args
                .keep_bytes
                .map(|b| as_bytes("keepBytes", b))
                .transpose()?,
            min_pull_age_secs: days(
                "minPullAgeDays",
                args.min_pull_age_days.unwrap_or(DEFAULT_MIN_PULL_AGE_DAYS),
            )?,
        })
    } else {
        None
    };
    let build_cache_keep_bytes = if args.build_cache {
        Some(as_bytes(
            "buildCacheKeepBytes",
            args.build_cache_keep_bytes.unwrap_or(0),
        )?)
    } else {
        None
    };
    let orphan_volumes = if args.orphan_volumes {
        Some(OrphanVolumes {
            now,
            min_age_secs: days(
                "orphanVolumeMinAgeDays",
                args.orphan_volume_min_age_days
                    .unwrap_or(DEFAULT_ORPHAN_VOLUME_MIN_AGE_DAYS),
            )?,
        })
    } else {
        None
    };
    Ok(Extras {
        unused_images,
        build_cache_keep_bytes,
        orphan_volumes,
    })
}

/// Untagged images, including ones pulled by digest only.
fn is_dangling_image(img: &ImageSummary) -> bool {
    img.repo_tags.iter().all(|t| t == "<none>:<none>")
}

/// Dangling images. Images carry no compose project, so a project-scoped
/// prune has none.
pub fn image_candidates(images: &[ImageSummary], project: Option<&str>) -> Vec<Candidate> {
    if project.is_some() {
        return Vec::new();
    }
    images
        .iter()
        .filter(|i| is_dangling_image(i))
        .map(|i| Candidate {
            bytes: unique_bytes(i),
            ..Candidate::new(
                ResourceKind::Image,
                &i.id,
                format!("dangling image, {} unique bytes", unique_bytes(i)),
            )
        })
        .collect()
}

/// Anonymous volumes from a `dangling=true` listing. In a project scope, a
/// volume not attributed to that project (see the module doc; `mounts` maps
/// volume names to the owner of a container mounting them) is left alone.
pub fn volume_candidates(
    volumes: &[Volume],
    project: Option<&str>,
    mounts: &HashMap<String, String>,
) -> Vec<Candidate> {
    volumes
        .iter()
        .filter(|v| v.labels.contains_key(ANONYMOUS_VOLUME_LABEL))
        .filter(|v| !v.labels.contains_key(COMPOSE_VOLUME_LABEL))
        .filter(|v| match project {
            Some(p) => crate::label_audit::volume_owner(v, mounts).as_deref() == Some(p),
            None => true,
        })
        .map(|v| volume_candidate(v, "dangling anonymous volume"))
        .collect()
}

/// Compose-created networks that no container, running or stopped, is
/// attached to and no managed stack uses as external. A stopped container
/// still needs its network to start again.
pub fn network_candidates(
    networks: &[Network],
    containers: &[ContainerSummary],
    scope: Scope<'_>,
) -> Vec<Candidate> {
    let Some(external) = scope.external_networks else {
        return Vec::new();
    };
    let project = scope.project;
    let mut used: HashSet<&str> = HashSet::new();
    for c in containers {
        let attached = c
            .network_settings
            .as_ref()
            .and_then(|n| n.networks.as_ref());
        for (name, ep) in attached.into_iter().flatten() {
            used.insert(name.as_str());
            if let Some(id) = ep.network_id.as_deref() {
                used.insert(id);
            }
        }
    }
    networks
        .iter()
        .filter_map(|n| {
            let id = n.id.as_deref()?;
            let name = n.name.as_deref().unwrap_or_default();
            let owner = n.labels.as_ref()?.get(COMPOSE_PROJECT_LABEL)?;
            if project.is_some_and(|p| p != owner) {
                return None;
            }
            if used.contains(id) || used.contains(name) {
                return None;
            }
            if external.contains(id) || external.contains(name) {
                return None;
            }
            Some(Candidate::new(
                ResourceKind::Network,
                id,
                format!("compose network '{name}' of project '{owner}', no containers attached"),
            ))
        })
        .collect()
}

fn engine_err(what: &str, e: bollard::errors::Error) -> plugin_toolkit::anyhow::Error {
    anyhow!("{what}: {e}")
}

const ATTEMPTS: u32 = 3;
const CALL_TIMEOUT: Duration = Duration::from_secs(120);
const PRUNE_BUILD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MIN_RESERVED_SPACE_API: (u32, u32) = (1, 48);

fn retryable(e: &bollard::errors::Error, mutating: bool) -> bool {
    match e {
        bollard::errors::Error::DockerResponseServerError { status_code, .. } => {
            *status_code >= 500
        }
        bollard::errors::Error::RequestTimeoutError => !mutating,
        _ => true,
    }
}

async fn attempt<T, F, Fut>(
    f: F,
    mutating: bool,
) -> (u32, std::result::Result<T, bollard::errors::Error>)
where
    F: Fn() -> Fut,
    Fut: Future<Output = std::result::Result<T, bollard::errors::Error>>,
{
    let mut attempt = 0;
    loop {
        attempt += 1;
        let r = plugin_toolkit::time::timeout(CALL_TIMEOUT, f())
            .await
            .unwrap_or(Err(bollard::errors::Error::RequestTimeoutError));
        match r {
            Err(e) if attempt < ATTEMPTS && retryable(&e, mutating) => {
                plugin_toolkit::time::sleep(Duration::from_millis(250 << attempt)).await
            }
            r => return (attempt, r),
        }
    }
}

async fn call<T, F, Fut>(f: F) -> std::result::Result<T, bollard::errors::Error>
where
    F: Fn() -> Fut,
    Fut: Future<Output = std::result::Result<T, bollard::errors::Error>>,
{
    attempt(f, false).await.1
}

async fn delete<T, F, Fut>(f: F) -> std::result::Result<(), bollard::errors::Error>
where
    F: Fn() -> Fut,
    Fut: Future<Output = std::result::Result<T, bollard::errors::Error>>,
{
    match attempt(f, true).await {
        (_, Ok(_)) => Ok(()),
        (n, Err(e)) if n > 1 && is_404(&e) => Ok(()),
        (_, Err(e)) => Err(e),
    }
}

fn is_404(e: &bollard::errors::Error) -> bool {
    matches!(
        e,
        bollard::errors::Error::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

fn api_at_least(version: &str, min: (u32, u32)) -> bool {
    let mut parts = version.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    (parts.next().unwrap_or(0), parts.next().unwrap_or(0)) >= min
}

fn label_filter(project: Option<&str>) -> HashMap<&'static str, Vec<String>> {
    let label = match project {
        Some(p) => format!("{COMPOSE_PROJECT_LABEL}={p}"),
        None => COMPOSE_PROJECT_LABEL.to_string(),
    };
    HashMap::from([("label", vec![label])])
}

fn dangling_filter() -> HashMap<&'static str, Vec<&'static str>> {
    HashMap::from([("dangling", vec!["true"])])
}

/// The dangling-image candidates alone.
pub async fn dangling_images(docker: &Docker) -> Result<Vec<Candidate>> {
    let images = call(|| {
        docker.list_images(Some(
            ListImagesOptionsBuilder::new()
                .filters(&dangling_filter())
                .shared_size(true)
                .build(),
        ))
    })
    .await
    .map_err(|e| engine_err("list images", e))?;
    Ok(image_candidates(&images, None))
}

async fn list_containers(docker: &Docker) -> Result<Vec<ContainerSummary>> {
    call(|| docker.list_containers(Some(ListContainersOptionsBuilder::new().all(true).build())))
        .await
        .map_err(|e| engine_err("list containers", e))
}

async fn build_cache_candidate(docker: &Docker, keep: i64) -> Result<Option<Candidate>> {
    let usage = call(|| docker.df(Some(DataUsageOptions::default())))
        .await
        .map_err(|e| engine_err("build cache usage", e))?
        .build_cache_usage;
    let id = keep.to_string();
    let Some(reclaimable) = usage.and_then(|u| u.reclaimable) else {
        return Ok(Some(Candidate::new(
            ResourceKind::BuildCache,
            &id,
            format!("build cache down to {keep} bytes; the engine reports no reclaimable size"),
        )));
    };
    let bytes = (reclaimable - keep).max(0);
    Ok((bytes > 0).then(|| {
        let mut c = Candidate {
            bytes,
            ..Candidate::new(
                ResourceKind::BuildCache,
                &id,
                format!("build cache down to {keep} bytes, at most {bytes} bytes reclaimed"),
            )
        };
        c.key = format!("{}@{reclaimable}", c.key);
        c
    }))
}

/// Every current candidate within `scope`.
pub async fn candidates(docker: &Docker, scope: Scope<'_>) -> Result<Vec<Candidate>> {
    let project = scope.project;
    let dangling = dangling_filter();
    let volumes = call(|| {
        docker.list_volumes(Some(
            ListVolumesOptionsBuilder::new().filters(&dangling).build(),
        ))
    })
    .await
    .map_err(|e| engine_err("list volumes", e))?
    .volumes
    .unwrap_or_default();
    let networks = call(|| {
        docker.list_networks(Some(
            ListNetworksOptionsBuilder::new()
                .filters(&label_filter(project))
                .build(),
        ))
    })
    .await
    .map_err(|e| engine_err("list networks", e))?;
    let containers = list_containers(docker).await?;

    let mut out = match (project, scope.extras.unused_images) {
        (Some(_), _) => Vec::new(),
        (None, None) => dangling_images(docker).await?,
        (None, Some(u)) => {
            let images = call(|| {
                docker.list_images(Some(
                    ListImagesOptionsBuilder::new().shared_size(true).build(),
                ))
            })
            .await
            .map_err(|e| engine_err("list images", e))?;
            let mut tagged_at = HashMap::new();
            for i in unused_images(&images, &containers) {
                let inspected = match call(|| docker.inspect_image(&i.id)).await {
                    Ok(inspected) => inspected,
                    Err(e) if is_404(&e) => continue,
                    Err(e) => return Err(engine_err("inspect image", e)),
                };
                let last_tag = inspected
                    .metadata
                    .and_then(|m| m.last_tag_time)
                    .and_then(|t| epoch(Some(&t)));
                if let Some(t) = last_tag {
                    tagged_at.insert(i.id.clone(), t);
                }
            }
            let mut found = image_candidates(&images, None);
            found.extend(unused_image_candidates(&images, &containers, u, &tagged_at));
            found
        }
    };
    let mounts = crate::label_audit::mount_owners(&containers);
    out.extend(volume_candidates(&volumes, project, &mounts));
    if let Some(o) = scope.extras.orphan_volumes {
        out.extend(orphan_volume_candidates(&volumes, project, &mounts, o));
    }
    out.extend(network_candidates(&networks, &containers, scope));
    if let (None, Some(keep)) = (project, scope.extras.build_cache_keep_bytes) {
        out.extend(build_cache_candidate(docker, keep).await?);
    }
    Ok(out)
}

/// Why a confirmed item was not removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct Skipped {
    pub item: String,
    pub reason: String,
}

/// The record of an executed prune.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "camelCase")]
pub struct PruneApplied {
    /// true: nothing was changed.
    pub dry_run: bool,
    pub removed: Vec<String>,
    /// Not removed, and not an error: no longer a candidate, already gone,
    /// or refused by the engine as in use.
    pub skipped: Vec<Skipped>,
    pub failed: Vec<Skipped>,
    pub bytes_freed: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(untagged)]
pub enum PruneChange {
    Plan(ExecutionPlan),
    Applied(PruneApplied),
}

/// Whether any container, running or stopped, is attached to network `id`.
/// The engine itself lets a network go when only stopped containers use it.
async fn containers_where(docker: &Docker, key: &str, id: &str) -> Result<bool> {
    let filters = HashMap::from([(key, vec![id])]);
    let found = call(|| {
        docker.list_containers(Some(
            ListContainersOptionsBuilder::new()
                .all(true)
                .filters(&filters)
                .build(),
        ))
    })
    .await
    .map_err(|e| engine_err(&format!("list containers by {key}"), e))?;
    Ok(!found.is_empty())
}

async fn network_in_use(docker: &Docker, id: &str) -> Result<bool> {
    containers_where(docker, "network", id).await
}

enum Recheck {
    Remove(Vec<String>),
    Skip(&'static str),
}

const IN_USE: &str = "in use: a container uses it or an image built from it";

async fn recheck_image(docker: &Docker, id: &str) -> Result<Recheck> {
    let tags = match call(|| docker.inspect_image(id)).await {
        Ok(i) => i
            .repo_tags
            .unwrap_or_default()
            .into_iter()
            .filter(|t| t != "<none>:<none>")
            .collect(),
        Err(e) if is_404(&e) => return Ok(Recheck::Skip("already gone")),
        Err(e) => return Err(engine_err("inspect image", e)),
    };
    if containers_where(docker, "ancestor", id).await? {
        return Ok(Recheck::Skip(IN_USE));
    }
    Ok(Recheck::Remove(tags))
}

fn remove_image_opts() -> bollard::query_parameters::RemoveImageOptions {
    RemoveImageOptionsBuilder::new().force(false).build()
}

enum Removal {
    Removed(i64),
    Skipped(String),
}

fn is_multi_ref(e: &bollard::errors::Error) -> bool {
    matches!(
        e,
        bollard::errors::Error::DockerResponseServerError { status_code: 409, message }
            if message.contains("multiple repositories")
    )
}

async fn remove_image(
    docker: &Docker,
    c: &Candidate,
    tags: &[String],
) -> std::result::Result<Removal, bollard::errors::Error> {
    match delete(|| docker.remove_image(&c.id, Some(remove_image_opts()), None)).await {
        Ok(()) => return Ok(Removal::Removed(c.bytes)),
        Err(e) if is_multi_ref(&e) => {}
        Err(e) => return Err(e),
    }
    let mut untagged = Vec::new();
    for tag in tags {
        let still_ours = match call(|| docker.inspect_image(tag)).await {
            Ok(i) => i.id.as_deref() == Some(c.id.as_str()),
            Err(e) if is_404(&e) => false,
            Err(e) => return Err(e),
        };
        if !still_ours {
            continue;
        }
        let in_use = containers_where(docker, "ancestor", &c.id)
            .await
            .map_err(|e| bollard::errors::Error::IOError {
                err: std::io::Error::other(e.to_string()),
            })?;
        if in_use {
            return Ok(Removal::Skipped(if untagged.is_empty() {
                IN_USE.to_string()
            } else {
                format!("{IN_USE}; already untagged {}", untagged.join(", "))
            }));
        }
        match delete(|| docker.remove_image(tag, Some(remove_image_opts()), None)).await {
            Ok(()) => untagged.push(tag.clone()),
            Err(e) if is_404(&e) => {}
            Err(e) => return Err(e),
        }
    }
    match delete(|| docker.remove_image(&c.id, Some(remove_image_opts()), None)).await {
        Ok(()) => Ok(Removal::Removed(c.bytes)),
        Err(e) if is_404(&e) => Ok(Removal::Removed(c.bytes)),
        Err(e) => Err(e),
    }
}

async fn prune_build_cache(
    docker: &Docker,
    keep: i64,
) -> std::result::Result<Removal, bollard::errors::Error> {
    let api = call(|| docker.version())
        .await?
        .api_version
        .unwrap_or_default();
    if !api_at_least(&api, MIN_RESERVED_SPACE_API) {
        return Err(bollard::errors::Error::IOError {
            err: std::io::Error::other(format!(
                "engine API {api} predates 1.48 and ignores reserved-space; refusing to prune the whole build cache"
            )),
        });
    }
    let docker = docker.clone().with_timeout(PRUNE_BUILD_TIMEOUT);
    let r = plugin_toolkit::time::timeout(
        PRUNE_BUILD_TIMEOUT,
        docker.prune_build(Some(
            PruneBuildOptionsBuilder::new()
                .reserved_space(keep)
                .all(true)
                .build(),
        )),
    )
    .await
    .unwrap_or(Err(bollard::errors::Error::RequestTimeoutError))?;
    Ok(Removal::Removed(r.space_reclaimed.unwrap_or(0)))
}

// Removal is by id without force, so the engine refuses anything in use. A
// window of one round trip remains between the last check and the DELETE for
// a container attaching to a network.
async fn remove(
    docker: &Docker,
    c: &Candidate,
    tags: &[String],
) -> std::result::Result<Removal, bollard::errors::Error> {
    match c.kind {
        ResourceKind::Image => remove_image(docker, c, tags).await,
        ResourceKind::Volume => {
            delete(|| {
                docker.remove_volume(
                    &c.id,
                    Some(RemoveVolumeOptionsBuilder::new().force(false).build()),
                )
            })
            .await?;
            Ok(Removal::Removed(0))
        }
        ResourceKind::Network => {
            delete(|| docker.remove_network(&c.id)).await?;
            Ok(Removal::Removed(0))
        }
        ResourceKind::BuildCache => {
            prune_build_cache(docker, c.id.parse::<i64>().unwrap_or(0)).await
        }
    }
}

/// Remove the confirmed keys that are still candidates.
pub async fn apply(
    docker: &Docker,
    scope: Scope<'_>,
    confirmed: &[String],
) -> Result<PruneApplied> {
    let current = candidates(docker, scope).await?;
    let keys: Vec<String> = current.iter().map(|c| c.key.clone()).collect();
    execute::require_confirmed(TOOL, confirmed, &keys)?;
    let (act, dropped) = execute::intersect(confirmed, &keys);
    let mut applied = PruneApplied {
        skipped: dropped
            .into_iter()
            .map(|item| Skipped {
                item,
                reason: "no longer a candidate".into(),
            })
            .collect(),
        ..Default::default()
    };
    for key in act {
        let Some(c) = current.iter().find(|c| c.key == key) else {
            continue;
        };
        let mut tags = Vec::new();
        if c.kind == ResourceKind::Image {
            match recheck_image(docker, &c.id).await {
                Ok(Recheck::Remove(t)) => tags = t,
                Ok(Recheck::Skip(reason)) => {
                    applied.skipped.push(Skipped {
                        item: key,
                        reason: reason.into(),
                    });
                    continue;
                }
                Err(e) => {
                    applied.failed.push(Skipped {
                        item: key,
                        reason: e.to_string(),
                    });
                    continue;
                }
            }
        }
        if c.kind == ResourceKind::Network {
            match network_in_use(docker, &c.id).await {
                Ok(false) => {}
                Ok(true) => {
                    applied.skipped.push(Skipped {
                        item: key,
                        reason: "in use: a container attached since the plan".into(),
                    });
                    continue;
                }
                Err(e) => {
                    applied.failed.push(Skipped {
                        item: key,
                        reason: e.to_string(),
                    });
                    continue;
                }
            }
        }
        match remove(docker, c, &tags).await {
            Ok(Removal::Removed(bytes)) => {
                applied.bytes_freed += bytes;
                applied.removed.push(key);
            }
            Ok(Removal::Skipped(reason)) => applied.skipped.push(Skipped { item: key, reason }),
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => applied.skipped.push(Skipped {
                item: key,
                reason: "already gone".into(),
            }),
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 409,
                message,
            }) => applied.skipped.push(Skipped {
                item: key,
                reason: format!("in use: {message}"),
            }),
            // The engine answers 403 for a network it will not remove.
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 403,
                message,
            }) if c.kind == ResourceKind::Network => applied.skipped.push(Skipped {
                item: key,
                reason: format!("in use: {message}"),
            }),
            Err(e) => applied.failed.push(Skipped {
                item: key,
                reason: e.to_string(),
            }),
        }
    }
    Ok(applied)
}

/// The dry-run plan for `candidates`.
pub fn plan<A: Serialize>(
    args: &A,
    scope: Option<&str>,
    candidates: &[Candidate],
    networks_withheld: bool,
) -> Result<ExecutionPlan> {
    let inputs = plugin_toolkit::serde_json::to_value(args)?;
    let where_ = scope
        .map(|s| format!(" in stack '{s}'"))
        .unwrap_or_default();
    let bytes_of = |kind| -> i64 {
        candidates
            .iter()
            .filter(|c| c.kind == kind)
            .map(|c| c.bytes)
            .sum()
    };
    let freed: Vec<String> = [
        (ResourceKind::Image, "at least {} bytes of images"),
        (ResourceKind::BuildCache, "at most {} bytes of build cache"),
    ]
    .into_iter()
    .filter(|(kind, _)| candidates.iter().any(|c| c.kind == *kind))
    .map(|(kind, label)| label.replace("{}", &bytes_of(kind).to_string()))
    .collect();
    let summary = if candidates.is_empty() {
        format!("nothing to prune{where_}")
    } else if freed.is_empty() {
        format!("remove {} orphaned resource(s){where_}", candidates.len())
    } else {
        format!(
            "remove {} orphaned resource(s){where_}, freeing {}",
            candidates.len(),
            freed.join(" and ")
        )
    };
    let summary = if networks_withheld {
        format!(
            "{summary}; networks not considered: a managed stack's compose config could not be read"
        )
    } else {
        summary
    };
    let changes = candidates
        .iter()
        .map(|c| PlannedChange::new(&c.key, "remove").with_detail(&c.detail))
        .collect();
    let mut p = ExecutionPlan::generic(TOOL, inputs.into()).detailed(summary, changes);
    p.how_to_execute = format!(
        "re-invoke {TOOL} without `dry_run`, with `items` set to the change targets to remove; only items still orphaned are removed"
    );
    Ok(p)
}

#[orca_struct(args)]
pub struct DockerPruneArgs {
    /// Limit to one managed stack's compose project.
    #[arg(long)]
    #[serde(default)]
    pub stack: Option<String>,
    /// The plan's change targets to remove (when executing). Comma-separated on
    /// the CLI.
    #[arg(long, value_delimiter = ',')]
    #[serde(default)]
    pub items: Vec<String>,
    /// Return the plan and change nothing. Omitted, applies.
    #[arg(long)]
    #[serde(default, rename = "dryRun", alias = "dry_run")]
    pub dry_run: bool,
    /// Also remove tagged images no container, running or stopped, uses.
    #[arg(long)]
    #[serde(default, rename = "unusedImages")]
    pub unused_images: bool,
    /// With `unusedImages`: only images last pulled or tagged more than this
    /// many days ago. `minPullAgeDays` (default 1) is a floor on the same age.
    #[arg(long)]
    #[serde(default, rename = "olderThanDays")]
    pub older_than_days: Option<u64>,
    #[arg(long)]
    #[serde(default, rename = "minPullAgeDays")]
    pub min_pull_age_days: Option<u64>,
    /// With `unusedImages`: remove the oldest-created unused images until the
    /// unused images left total at most this many bytes.
    #[arg(long)]
    #[serde(default, rename = "keepBytes")]
    pub keep_bytes: Option<u64>,
    /// Also prune the build cache, keeping `buildCacheKeepBytes` (default 0).
    #[arg(long)]
    #[serde(default, rename = "buildCache")]
    pub build_cache: bool,
    #[arg(long)]
    #[serde(default, rename = "buildCacheKeepBytes")]
    pub build_cache_keep_bytes: Option<u64>,
    /// Also remove named volumes no container, running or stopped, mounts,
    /// with no compose project or `orca.stack` label, created at least
    /// `orphanVolumeMinAgeDays` (default 7) days ago.
    #[arg(long)]
    #[serde(default, rename = "orphanVolumes")]
    pub orphan_volumes: bool,
    #[arg(long)]
    #[serde(default, rename = "orphanVolumeMinAgeDays")]
    pub orphan_volume_min_age_days: Option<u64>,
}

async fn project_for(stack: &str) -> Result<String> {
    let row = crate::stacks::find_here(stack).await?;
    Ok(row
        .compose(&crate::stacks::allowed_roots()?)?
        .project_name()
        .await?)
}

/// Networks every managed stack declares external, or `None` when any
/// stack's config cannot be read.
async fn external_networks() -> Result<Option<HashSet<String>>> {
    let mut out = HashSet::new();
    for row in crate::stacks::all_here().await? {
        let Ok(compose) = row.compose(&crate::stacks::allowed_roots()?) else {
            return Ok(None);
        };
        match compose.config_json().await {
            Ok(raw) => out.extend(crate::compose::parse_external_networks(&raw)),
            Err(_) => return Ok(None),
        }
    }
    Ok(Some(out))
}

/// **Remove orphaned engine resources**: dangling images, dangling anonymous
/// volumes and compose networks no container uses; opt-in, unused tagged
/// images (`unusedImages`, `olderThanDays`, `keepBytes`), the build cache
/// (`buildCache`, `buildCacheKeepBytes`) and orphaned named volumes
/// (`orphanVolumes`). With `dry_run`, returns the candidates and the bytes
/// they free, and changes nothing.
#[orca_tool(
    domain = "docker",
    verb = "prune",
    role = "admin",
    execute_gated = false,
    dry_run_aware = true
)]
async fn docker_prune(args: DockerPruneArgs, ctx: &ToolCtx) -> Result<PruneChange> {
    let args = DockerPruneArgs {
        dry_run: args.dry_run || ctx.dry_run(),
        ..args
    };
    execute::require_admin(TOOL, ctx)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow!("{e}"))?
        .as_secs() as i64;
    let extras = extras(&args, now)?;
    let project = match &args.stack {
        Some(s) => Some(project_for(s).await?),
        None => None,
    };
    let docker = &crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    let external = external_networks().await?;
    let scope = Scope {
        project: project.as_deref(),
        external_networks: external.as_ref(),
        extras,
    };
    if !args.dry_run {
        return Ok(PruneChange::Applied(
            apply(docker, scope, &args.items).await?,
        ));
    }
    let found = candidates(docker, scope).await?;
    Ok(PruneChange::Plan(plan(
        &args,
        args.stack.as_deref(),
        &found,
        external.is_none(),
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};

    fn image(id: &str, tags: &[&str], digests: &[&str]) -> String {
        format!(
            r#"{{"Id":"{id}","ParentId":"","RepoTags":{},"RepoDigests":{},"Created":0,"Size":100,"SharedSize":-1,"Labels":{{}},"Containers":-1}}"#,
            plugin_toolkit::serde_json::to_string(tags).unwrap(),
            plugin_toolkit::serde_json::to_string(digests).unwrap()
        )
    }

    fn volume(name: &str, labels: &[(&str, &str)]) -> String {
        let labels: HashMap<&str, &str> = labels.iter().copied().collect();
        format!(
            r#"{{"Name":"{name}","Driver":"local","Mountpoint":"/var/lib/docker/volumes/{name}/_data","Labels":{},"Scope":"local","Options":{{}}}}"#,
            plugin_toolkit::serde_json::to_string(&labels).unwrap()
        )
    }

    fn volume_at(name: &str, labels: &[(&str, &str)], created: i64) -> String {
        let labels: HashMap<&str, &str> = labels.iter().copied().collect();
        format!(
            r#"{{"Name":"{name}","Driver":"local","Mountpoint":"/var/lib/docker/volumes/{name}/_data","CreatedAt":"{}","Labels":{},"Scope":"local","Options":{{}}}}"#,
            rfc3339(created),
            plugin_toolkit::serde_json::to_string(&labels).unwrap()
        )
    }

    fn rfc3339(secs: i64) -> String {
        plugin_toolkit::time::Timestamp::from_unix_seconds(secs)
            .unwrap()
            .to_rfc3339()
    }

    fn network(id: &str, name: &str, project: Option<&str>) -> String {
        let labels = match project {
            Some(p) => format!(r#"{{"{COMPOSE_PROJECT_LABEL}":"{p}"}}"#),
            None => "{}".to_string(),
        };
        format!(r#"{{"Id":"{id}","Name":"{name}","Labels":{labels}}}"#)
    }

    fn container_on(id: &str, state: &str, network_name: &str, network_id: &str) -> String {
        format!(
            r#"{{"Id":"{id}","Names":["/{id}"],"State":"{state}","NetworkSettings":{{"Networks":{{"{network_name}":{{"NetworkID":"{network_id}"}}}}}}}}"#
        )
    }

    /// Anonymous volumes carry only the anonymous label, as compose 2.31 and
    /// 2.40 create them on the fleet.
    fn engine(extra: Vec<Route>) -> FakeEngine {
        let images = format!(
            "[{},{},{}]",
            image("sha256:dead", &[], &[]),
            image("sha256:digestonly", &["<none>:<none>"], &["app@sha256:abc"]),
            image("sha256:tagged", &["nginx:latest"], &[])
        );
        let volumes = format!(
            r#"{{"Volumes":[{},{},{},{}],"Warnings":[]}}"#,
            volume("anon1", &[(ANONYMOUS_VOLUME_LABEL, "")]),
            volume("anon2", &[(ANONYMOUS_VOLUME_LABEL, "")]),
            volume(
                "media_data",
                &[
                    (COMPOSE_PROJECT_LABEL, "media"),
                    (COMPOSE_VOLUME_LABEL, "data")
                ]
            ),
            volume("looks_like_a_hash_0123456789abcdef0123456789abcdef", &[]),
        );
        let networks = format!(
            "[{},{},{},{},{},{}]",
            network("n-used", "media_default", Some("media")),
            network("n-stopped", "media_backend", Some("media")),
            network("n-media-orphan", "media_old", Some("media")),
            network("n-orphan", "old_default", Some("old")),
            network("n-proxy", "proxy", Some("caddy")),
            network("n-bridge", "bridge", None),
        );
        let containers = format!(
            "[{},{}]",
            container_on("web", "running", "media_default", "n-used"),
            container_on("job", "exited", "media_backend", "n-stopped"),
        );
        let mut routes = extra;
        routes.extend([
            // The pre-DELETE re-check filters by network; nothing attached.
            Route::new("GET", "/containers/json", 200, "[]").when_query(r#""network""#),
            Route::new("GET", "/containers/json", 200, "[]").when_query("ancestor"),
            Route::new(
                "GET",
                "/images/sha256:dead/json",
                200,
                r#"{"Id":"sha256:dead","RepoTags":[]}"#,
            ),
            Route::new("GET", "/images/json", 200, images),
            Route::new("GET", "/volumes", 200, volumes),
            Route::new("GET", "/networks", 200, networks),
            Route::new("GET", "/containers/json", 200, containers),
        ]);
        FakeEngine::routed(routes)
    }

    fn external() -> HashSet<String> {
        ["proxy".to_string()].into()
    }

    fn all(ext: &HashSet<String>) -> Scope<'_> {
        Scope {
            project: None,
            external_networks: Some(ext),
            extras: Extras::default(),
        }
    }

    fn keys(c: &[Candidate]) -> Vec<&str> {
        c.iter().map(|c| c.key.as_str()).collect()
    }

    fn found(e: &FakeEngine, scope: Scope<'_>) -> Vec<Candidate> {
        plugin_toolkit::reactor::block_on(candidates(&e.client(), scope)).unwrap()
    }

    #[test]
    fn candidates_are_dangling_images_anonymous_volumes_and_unused_compose_networks() {
        let e = engine(vec![]);
        let ext = external();
        assert_eq!(
            keys(&found(&e, all(&ext))),
            vec![
                "image:sha256:dead",
                "image:sha256:digestonly",
                "volume:anon1",
                "volume:anon2",
                "network:n-media-orphan",
                "network:n-orphan",
            ]
        );
    }

    #[test]
    fn listings_ask_the_engine_for_dangling_and_all_containers() {
        let e = engine(vec![]);
        let ext = external();
        found(&e, all(&ext));
        let gets = e.targets("GET");
        let with = |path: &str| {
            gets.iter()
                .find(|t| t.split('?').next().unwrap_or_default().ends_with(path))
                .cloned()
                .unwrap_or_else(|| panic!("no GET {path} in {gets:?}"))
        };
        assert!(with("/containers/json").contains("all=true"), "{gets:?}");
        assert!(
            with("/volumes").contains(r#""dangling":["true"]"#),
            "{gets:?}"
        );
        assert!(
            with("/images/json").contains(r#""dangling":["true"]"#),
            "{gets:?}"
        );
    }

    #[test]
    fn a_network_used_only_by_a_stopped_container_is_never_a_candidate() {
        let e = engine(vec![]);
        let ext = external();
        assert!(!found(&e, all(&ext)).iter().any(|c| c.id == "n-stopped"));
    }

    #[test]
    fn external_networks_of_managed_stacks_are_never_candidates() {
        let e = engine(vec![]);
        let ext = external();
        assert!(!found(&e, all(&ext)).iter().any(|c| c.id == "n-proxy"));
        let none = HashSet::new();
        assert!(found(&e, all(&none)).iter().any(|c| c.id == "n-proxy"));
    }

    #[test]
    fn unknown_external_networks_withhold_every_network() {
        let e = engine(vec![]);
        let f = found(&e, Scope::default());
        assert!(!f.iter().any(|c| c.kind == ResourceKind::Network), "{f:?}");
        assert!(f.iter().any(|c| c.kind == ResourceKind::Volume));
    }

    #[test]
    fn named_volumes_are_never_candidates() {
        let e = engine(vec![]);
        let ext = external();
        let f = found(&e, all(&ext));
        // Neither a compose-named volume nor an unlabeled hash-looking name.
        assert!(!f.iter().any(|c| c.id == "media_data"));
        assert!(!f.iter().any(|c| c.id.starts_with("looks_like")));
    }

    #[test]
    fn anonymous_label_alone_does_not_override_a_compose_volume_name() {
        let v: Volume = plugin_toolkit::serde_json::from_str(&volume(
            "media_data",
            &[(ANONYMOUS_VOLUME_LABEL, ""), (COMPOSE_VOLUME_LABEL, "data")],
        ))
        .unwrap();
        assert!(volume_candidates(&[v], None, &HashMap::new()).is_empty());
    }

    #[test]
    fn stack_scope_limits_to_the_project_and_finds_no_unattributable_volumes() {
        let e = engine(vec![]);
        let ext = external();
        let scope = Scope {
            project: Some("media"),
            external_networks: Some(&ext),
            extras: Extras::default(),
        };
        assert_eq!(keys(&found(&e, scope)), vec!["network:n-media-orphan"]);
    }

    #[test]
    fn stack_scope_prefers_orca_stack_then_compose_project_then_mounts() {
        let parse = |name: &str, labels: &[(&str, &str)]| -> Volume {
            plugin_toolkit::serde_json::from_str(&volume(name, labels)).unwrap()
        };
        let vols = [
            parse(
                "a",
                &[
                    (ANONYMOUS_VOLUME_LABEL, ""),
                    (crate::labels::STACK, "media"),
                    (COMPOSE_PROJECT_LABEL, "other"),
                ],
            ),
            parse(
                "b",
                &[
                    (ANONYMOUS_VOLUME_LABEL, ""),
                    (COMPOSE_PROJECT_LABEL, "media"),
                ],
            ),
            parse("c", &[(ANONYMOUS_VOLUME_LABEL, "")]),
            parse(
                "d",
                &[
                    (ANONYMOUS_VOLUME_LABEL, ""),
                    (crate::labels::STACK, "other"),
                ],
            ),
        ];
        let mounts = HashMap::from([
            ("c".to_string(), "media".to_string()),
            ("d".to_string(), "media".to_string()),
        ]);
        let ids: Vec<_> = volume_candidates(&vols, Some("media"), &mounts)
            .into_iter()
            .map(|c| c.id)
            .collect();
        // `d` names another stack itself; a mount does not override that.
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn plan_lists_every_candidate_and_changes_nothing() {
        let e = engine(vec![]);
        let ext = external();
        let f = found(&e, all(&ext));
        let args = DockerPruneArgs {
            stack: None,
            items: vec![],
            dry_run: true,
            ..Default::default()
        };
        let p = plan(&args, None, &f, false).unwrap();
        assert!(p.dry_run && p.detailed);
        let targets: Vec<_> = p.changes.iter().map(|c| c.target.as_str()).collect();
        assert_eq!(targets, keys(&f));
        assert!(e.paths("DELETE").is_empty());
        assert!(
            plan(&args, None, &f, true)
                .unwrap()
                .summary
                .contains("networks not considered")
        );
    }

    #[test]
    fn execute_removes_only_confirmed_items_still_orphaned() {
        let e = engine(vec![
            Route::new("DELETE", "/images/sha256:dead", 200, "[]"),
            Route::new("DELETE", "/volumes/anon1", 204, ""),
            Route::new("DELETE", "/networks/n-orphan", 204, ""),
        ]);
        let confirmed = vec![
            "image:sha256:dead".to_string(),
            "volume:anon1".to_string(),
            "network:n-orphan".to_string(),
            "volume:gone-since-plan".to_string(),
        ];
        let ext = external();
        let applied =
            plugin_toolkit::reactor::block_on(apply(&e.client(), all(&ext), &confirmed)).unwrap();
        assert_eq!(
            applied.removed,
            vec!["image:sha256:dead", "volume:anon1", "network:n-orphan"]
        );
        assert_eq!(applied.skipped.len(), 1);
        assert_eq!(applied.skipped[0].item, "volume:gone-since-plan");
        // Candidates that were not confirmed are untouched.
        let deletes = e.paths("DELETE");
        assert_eq!(deletes.len(), 3, "{deletes:?}");
        assert!(!deletes.iter().any(|p| p.ends_with("/volumes/anon2")));
        assert!(
            !deletes
                .iter()
                .any(|p| p.ends_with("/networks/n-media-orphan"))
        );
        // The network was re-checked for attached containers right before.
        assert!(
            e.targets("GET")
                .iter()
                .any(|t| t.contains("/containers/json") && t.contains(r#""network":["n-orphan"]"#)),
            "{:?}",
            e.targets("GET")
        );
    }

    #[test]
    fn a_container_attached_since_the_plan_skips_the_network() {
        let e = engine(vec![
            Route::new(
                "GET",
                "/containers/json",
                200,
                format!(
                    "[{}]",
                    container_on("late", "created", "old_default", "n-orphan")
                ),
            )
            .when_query(r#""network":["n-orphan"]"#),
        ]);
        let ext = external();
        let applied = plugin_toolkit::reactor::block_on(apply(
            &e.client(),
            all(&ext),
            &["network:n-orphan".to_string()],
        ))
        .unwrap();
        assert!(applied.removed.is_empty());
        assert!(applied.skipped[0].reason.contains("in use"), "{applied:?}");
        assert!(e.paths("DELETE").is_empty());
    }

    #[test]
    fn engine_refusal_is_skipped_not_failed() {
        let e = engine(vec![
            Route::new(
                "DELETE",
                "/volumes/anon2",
                409,
                r#"{"message":"volume is in use"}"#,
            ),
            Route::new(
                "DELETE",
                "/networks/n-orphan",
                403,
                r#"{"message":"has active endpoints"}"#,
            ),
        ]);
        let ext = external();
        let applied = plugin_toolkit::reactor::block_on(apply(
            &e.client(),
            all(&ext),
            &["volume:anon2".to_string(), "network:n-orphan".to_string()],
        ))
        .unwrap();
        assert!(applied.removed.is_empty());
        assert_eq!(applied.skipped.len(), 2, "{applied:?}");
        assert!(applied.skipped.iter().all(|s| s.reason.contains("in use")));
        assert!(applied.failed.is_empty());
    }

    #[test]
    fn execute_without_items_is_refused_when_there_are_candidates() {
        let e = engine(vec![]);
        let ext = external();
        let err =
            plugin_toolkit::reactor::block_on(apply(&e.client(), all(&ext), &[])).unwrap_err();
        assert!(err.to_string().contains("items from the dry run"), "{err}");
        assert!(e.paths("DELETE").is_empty());
    }

    fn ctx_without_caller() -> ToolCtx {
        ToolCtx::new(std::sync::Arc::new(
            plugin_toolkit::contract::config::Config {
                anthropic_api_key: None,
                lmstudio_url: String::new(),
                ollama_url: String::new(),
                default_model: plugin_toolkit::contract::config::Model::LMStudio {
                    id: String::new(),
                    url: String::new(),
                },
                app_dir: std::env::temp_dir(),
                memory_root: std::env::temp_dir(),
                db_path: std::env::temp_dir().join("orca-test.db"),
                ports: Default::default(),
            },
        ))
    }

    #[test]
    fn execute_without_an_admin_caller_is_refused() {
        let args = DockerPruneArgs {
            stack: None,
            items: vec!["volume:anon1".into()],
            dry_run: false,
            ..Default::default()
        };
        let err = plugin_toolkit::reactor::block_on(docker_prune(args, &ctx_without_caller()))
            .unwrap_err();
        assert!(err.to_string().contains("no caller identity"), "{err}");
    }

    #[test]
    fn a_dry_run_needs_an_admin_caller() {
        for ctx in crate::test_support::non_admins() {
            let args = DockerPruneArgs {
                stack: None,
                items: vec![],
                dry_run: true,
                ..Default::default()
            };
            let err = plugin_toolkit::reactor::block_on(docker_prune(args, &ctx)).unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
        }
    }

    fn img(id: &str, parent: &str, tags: &[&str], created: i64, size: i64) -> String {
        format!(
            r#"{{"Id":"{id}","ParentId":"{parent}","RepoTags":{},"RepoDigests":[],"Created":{created},"Size":{size},"SharedSize":-1,"Labels":{{}},"Containers":-1}}"#,
            plugin_toolkit::serde_json::to_string(tags).unwrap()
        )
    }

    fn uses(id: &str, state: &str, image: &str, image_id: &str) -> String {
        format!(
            r#"{{"Id":"{id}","Names":["/{id}"],"Image":"{image}","ImageID":"{image_id}","State":"{state}"}}"#
        )
    }

    const DAY: i64 = 86_400;
    const NOW: i64 = 100 * DAY;

    fn parse<T: plugin_toolkit::serde::de::DeserializeOwned>(json: &str) -> T {
        plugin_toolkit::serde_json::from_str(json).unwrap()
    }

    fn fleet_images() -> String {
        format!(
            "[{}]",
            [
                img("sha256:run", "", &["app:1"], NOW - 50 * DAY, 10),
                img("sha256:stopped", "", &["job:1"], NOW - 60 * DAY, 10),
                img("sha256:base", "", &["base:1"], NOW - 90 * DAY, 10),
                img(
                    "sha256:built",
                    "sha256:base",
                    &["built:1"],
                    NOW - 80 * DAY,
                    10
                ),
                img(
                    "sha256:child",
                    "sha256:run",
                    &["child:1"],
                    NOW - 40 * DAY,
                    10
                ),
                img("sha256:byname", "", &["named:1"], NOW - 70 * DAY, 10),
                img(
                    "sha256:ci",
                    "",
                    &["ci-rust:1.95.0", "ci-rust:latest"],
                    NOW - 30 * DAY,
                    400
                ),
                img(
                    "sha256:runner",
                    "",
                    &["gitea/runner-images:ubuntu-latest"],
                    NOW - 20 * DAY,
                    300
                ),
                img("sha256:fresh", "", &["busybox:latest"], NOW - DAY, 100),
                img("sha256:dangle", "", &[], NOW - 99 * DAY, 5),
            ]
            .join(",")
        )
    }

    fn fleet_containers() -> String {
        format!(
            "[{}]",
            [
                uses("a", "running", "app:1", "sha256:run"),
                uses("b", "exited", "job:1", "sha256:stopped"),
                uses("c", "created", "built:1", "sha256:built"),
                uses("d", "exited", "named:1", ""),
            ]
            .join(",")
        )
    }

    fn tagged_at_created(images: &[ImageSummary]) -> HashMap<String, i64> {
        images.iter().map(|i| (i.id.clone(), i.created)).collect()
    }

    fn unused(u: UnusedImages) -> Vec<String> {
        let images: Vec<ImageSummary> = parse(&fleet_images());
        let containers: Vec<ContainerSummary> = parse(&fleet_containers());
        unused_image_candidates(&images, &containers, u, &tagged_at_created(&images))
            .into_iter()
            .map(|c| c.key)
            .collect()
    }

    fn every(now: i64) -> UnusedImages {
        UnusedImages {
            now,
            older_than_secs: None,
            keep_bytes: None,
            min_pull_age_secs: 0,
        }
    }

    #[test]
    fn unused_images_are_tagged_images_no_container_uses_through_any_chain() {
        assert_eq!(
            unused(every(NOW)),
            vec![
                "image:sha256:ci",
                "image:sha256:runner",
                "image:sha256:fresh"
            ]
        );
    }

    #[test]
    fn a_stopped_or_created_container_keeps_its_image_and_its_parents() {
        let keys = unused(every(NOW));
        for kept in [
            "sha256:stopped",
            "sha256:built",
            "sha256:base",
            "sha256:byname",
        ] {
            assert!(
                !keys.iter().any(|k| k.ends_with(kept)),
                "{kept} in {keys:?}"
            );
        }
    }

    #[test]
    fn a_child_of_a_used_image_is_kept() {
        assert!(
            !unused(every(NOW))
                .iter()
                .any(|k| k.ends_with("sha256:child"))
        );
    }

    #[test]
    fn dangling_images_are_not_unused_image_candidates() {
        assert!(
            !unused(every(NOW))
                .iter()
                .any(|k| k.ends_with("sha256:dangle"))
        );
    }

    #[test]
    fn older_than_keeps_recent_images() {
        let u = UnusedImages {
            older_than_secs: Some(7 * DAY),
            ..every(NOW)
        };
        assert_eq!(unused(u), vec!["image:sha256:ci", "image:sha256:runner"]);
    }

    #[test]
    fn keep_bytes_evicts_oldest_created_first_until_within_budget() {
        let u = UnusedImages {
            keep_bytes: Some(350),
            ..every(NOW)
        };
        assert_eq!(unused(u), vec!["image:sha256:ci", "image:sha256:runner"]);
        let u = UnusedImages {
            keep_bytes: Some(500),
            ..every(NOW)
        };
        assert_eq!(unused(u), vec!["image:sha256:ci"]);
    }

    #[test]
    fn keep_bytes_already_met_removes_nothing() {
        let u = UnusedImages {
            keep_bytes: Some(800),
            ..every(NOW)
        };
        assert!(unused(u).is_empty());
    }

    #[test]
    fn keep_bytes_with_older_than_only_evicts_old_enough_images() {
        let u = UnusedImages {
            keep_bytes: Some(0),
            older_than_secs: Some(25 * DAY),
            ..every(NOW)
        };
        assert_eq!(unused(u), vec!["image:sha256:ci"]);
    }

    #[test]
    fn unused_candidates_carry_their_size() {
        let images: Vec<ImageSummary> = parse(&fleet_images());
        let containers: Vec<ContainerSummary> = parse(&fleet_containers());
        let c = unused_image_candidates(
            &images,
            &containers,
            every(NOW),
            &tagged_at_created(&images),
        );
        assert_eq!(c[0].bytes, 400);
        assert!(c[0].detail.contains("ci-rust:1.95.0"), "{}", c[0].detail);
    }

    fn extras_engine(extra: Vec<Route>) -> FakeEngine {
        let volumes = format!(
            r#"{{"Volumes":[{},{}],"Warnings":[]}}"#,
            volume("anon1", &[(ANONYMOUS_VOLUME_LABEL, "")]),
            volume_at("act-toolcache", &[], NOW - 30 * DAY),
        );
        let images: Vec<ImageSummary> = parse(&fleet_images());
        let mut routes = extra;
        for i in &images {
            let body = format!(
                r#"{{"Id":"{}","RepoTags":{},"Metadata":{{"LastTagTime":"{}"}}}}"#,
                i.id,
                plugin_toolkit::serde_json::to_string(&i.repo_tags).unwrap(),
                rfc3339(i.created)
            );
            for name in i.repo_tags.iter().chain([&i.id]) {
                routes.push(Route::new(
                    "GET",
                    format!("/images/{name}/json"),
                    200,
                    body.clone(),
                ));
            }
        }
        routes.extend([
            Route::new("GET", "/containers/json", 200, "[]").when_query("ancestor"),
            Route::new("GET", "/images/json", 200, fleet_images()),
            Route::new("GET", "/volumes", 200, volumes),
            Route::new("GET", "/networks", 200, "[]"),
            Route::new("GET", "/containers/json", 200, fleet_containers()),
            Route::new("GET", "/version", 200, r#"{"ApiVersion":"1.52"}"#),
            Route::new(
                "GET",
                "/system/df",
                200,
                r#"{"BuildCacheUsage":{"ActiveCount":0,"TotalCount":3,"Reclaimable":5000,"TotalSize":6000}}"#,
            ),
        ]);
        FakeEngine::routed(routes)
    }

    fn host_wide(ext: &HashSet<String>, extras: Extras) -> Scope<'_> {
        Scope { extras, ..all(ext) }
    }

    fn opted_in() -> Extras {
        Extras {
            unused_images: Some(every(NOW)),
            build_cache_keep_bytes: Some(1000),
            orphan_volumes: Some(OrphanVolumes {
                now: NOW,
                min_age_secs: 7 * DAY,
            }),
        }
    }

    #[test]
    fn opted_in_candidates_add_unused_images_build_cache_and_orphan_volumes() {
        let e = extras_engine(vec![]);
        let ext = external();
        let f = found(&e, host_wide(&ext, opted_in()));
        assert_eq!(
            keys(&f),
            vec![
                "image:sha256:dangle",
                "image:sha256:ci",
                "image:sha256:runner",
                "image:sha256:fresh",
                "volume:anon1",
                &act_key(),
                "buildcache:1000@5000",
            ]
        );
        assert_eq!(f.last().unwrap().bytes, 4000);
    }

    #[test]
    fn without_opt_in_no_tagged_image_build_cache_or_named_volume_is_a_candidate() {
        let e = extras_engine(vec![]);
        let ext = external();
        let f = found(&e, all(&ext));
        assert_eq!(keys(&f), vec!["image:sha256:dangle", "volume:anon1"]);
        assert!(e.paths("GET").iter().all(|p| !p.ends_with("/system/df")));
    }

    fn act_key() -> String {
        format!("volume:act-toolcache@{}", rfc3339(NOW - 30 * DAY))
    }

    #[test]
    fn plan_reports_bytes_freed() {
        let e = extras_engine(vec![]);
        let ext = external();
        let f = found(&e, host_wide(&ext, opted_in()));
        let p = plan(&DockerPruneArgs::default(), None, &f, false).unwrap();
        assert!(
            p.summary.contains("at least 805 bytes of images")
                && p.summary.contains("at most 4000 bytes of build cache"),
            "{}",
            p.summary
        );
        assert!(e.paths("DELETE").is_empty());
        assert!(e.paths("POST").is_empty());
    }

    fn run_apply(e: &FakeEngine, extras: Extras, items: &[&str]) -> PruneApplied {
        let ext = external();
        let items: Vec<String> = items.iter().map(|s| s.to_string()).collect();
        plugin_toolkit::reactor::block_on(apply(&e.client(), host_wide(&ext, extras), &items))
            .unwrap()
    }

    const MULTI_REF: &str = r#"{"message":"conflict: unable to delete sha256:ci (must be forced) - image is referenced in multiple repositories"}"#;

    #[test]
    fn execute_deletes_by_id_first_then_each_tag_of_a_multi_tag_image() {
        let e = extras_engine(vec![
            Route::new("DELETE", "/images/sha256:ci", 409, MULTI_REF).times(1),
            Route::new("DELETE", "/images/ci-rust:1.95.0", 200, "[]"),
            Route::new("DELETE", "/images/ci-rust:latest", 200, "[]"),
        ]);
        let applied = run_apply(&e, opted_in(), &["image:sha256:ci"]);
        assert_eq!(applied.removed, vec!["image:sha256:ci"], "{applied:?}");
        assert_eq!(applied.bytes_freed, 400);
        let deletes = e.paths("DELETE");
        assert!(deletes[0].ends_with("/images/sha256:ci"), "{deletes:?}");
        assert!(
            deletes[1].ends_with("/images/ci-rust:1.95.0"),
            "{deletes:?}"
        );
        assert!(
            deletes[2].ends_with("/images/ci-rust:latest"),
            "{deletes:?}"
        );
        assert!(
            e.targets("DELETE")
                .iter()
                .all(|t| t.contains("force=false")),
            "{:?}",
            e.targets("DELETE")
        );
    }

    #[test]
    fn a_container_attaching_mid_prune_stops_a_multi_tag_removal_at_that_tag() {
        let late = format!(
            "[{}]",
            uses("late", "created", "ci-rust:latest", "sha256:ci")
        );
        let e = extras_engine(vec![
            Route::new("GET", "/containers/json", 200, "[]")
                .when_query("ancestor")
                .times(2),
            Route::new("GET", "/containers/json", 200, late).when_query("ancestor"),
            Route::new("DELETE", "/images/sha256:ci", 409, MULTI_REF),
            Route::new("DELETE", "/images/ci-rust:1.95.0", 200, "[]"),
            Route::new("DELETE", "/images/ci-rust:latest", 200, "[]"),
        ]);
        let applied = run_apply(&e, opted_in(), &["image:sha256:ci"]);
        assert!(applied.removed.is_empty(), "{applied:?}");
        assert!(applied.failed.is_empty(), "{applied:?}");
        assert!(applied.skipped[0].reason.contains("in use"), "{applied:?}");
        assert_eq!(applied.bytes_freed, 0);
        let deletes = e.paths("DELETE");
        assert_eq!(deletes.len(), 2, "{deletes:?}");
        assert!(
            !deletes
                .iter()
                .any(|d| d.ends_with("/images/ci-rust:latest"))
        );
    }

    #[test]
    fn a_tag_moved_to_another_image_since_the_plan_is_left_alone() {
        let e = extras_engine(vec![
            Route::new(
                "GET",
                "/images/ci-rust:1.95.0/json",
                200,
                r#"{"Id":"sha256:newpull","RepoTags":["ci-rust:1.95.0"]}"#,
            ),
            Route::new("DELETE", "/images/sha256:ci", 409, MULTI_REF).times(1),
            Route::new("DELETE", "/images/ci-rust:latest", 200, "[]"),
        ]);
        let applied = run_apply(&e, opted_in(), &["image:sha256:ci"]);
        assert_eq!(applied.removed, vec!["image:sha256:ci"], "{applied:?}");
        assert!(
            !e.paths("DELETE")
                .iter()
                .any(|d| d.ends_with("/images/ci-rust:1.95.0"))
        );
    }

    #[test]
    fn a_single_tag_image_is_removed_by_id_so_the_engine_checks_use_atomically() {
        let e = extras_engine(vec![Route::new(
            "DELETE",
            "/images/sha256:fresh",
            200,
            "[]",
        )]);
        let applied = run_apply(&e, opted_in(), &["image:sha256:fresh"]);
        assert_eq!(applied.removed, vec!["image:sha256:fresh"], "{applied:?}");
        assert_eq!(e.paths("DELETE").len(), 1);
    }

    #[test]
    fn an_image_a_container_started_using_since_the_plan_is_skipped() {
        let late = format!(
            "[{},{}]",
            uses("a", "running", "app:1", "sha256:run"),
            uses("late", "created", "ci-rust:latest", "sha256:ci"),
        );
        let e = extras_engine(vec![
            Route::new("GET", "/containers/json", 200, late).when_query("ancestor"),
        ]);
        let applied = run_apply(&e, opted_in(), &["image:sha256:ci"]);
        assert!(applied.removed.is_empty(), "{applied:?}");
        assert!(applied.skipped[0].reason.contains("in use"), "{applied:?}");
        assert!(applied.failed.is_empty());
        assert!(e.paths("DELETE").is_empty());
    }

    #[test]
    fn engine_refusing_an_in_use_image_is_skipped_not_failed() {
        let e = extras_engine(vec![Route::new(
            "DELETE",
            "/images/sha256:runner",
            409,
            r#"{"message":"conflict: unable to remove repository reference: container abc is using its referenced image"}"#,
        )]);
        let applied = run_apply(&e, opted_in(), &["image:sha256:runner"]);
        assert!(applied.removed.is_empty());
        assert!(applied.failed.is_empty(), "{applied:?}");
        assert!(applied.skipped[0].reason.contains("in use"), "{applied:?}");
        assert_eq!(applied.bytes_freed, 0);
    }

    #[test]
    fn an_image_gone_since_the_plan_is_skipped() {
        let e = extras_engine(vec![Route::new(
            "GET",
            "/images/sha256:fresh/json",
            404,
            r#"{"message":"No such image"}"#,
        )]);
        let applied = run_apply(&e, opted_in(), &["image:sha256:fresh"]);
        assert!(applied.removed.is_empty());
        assert!(applied.failed.is_empty(), "{applied:?}");
        assert!(e.paths("DELETE").is_empty());
    }

    #[test]
    fn execute_prunes_build_cache_with_the_keep_cap() {
        let e = extras_engine(vec![Route::new(
            "POST",
            "/build/prune",
            200,
            r#"{"CachesDeleted":["x"],"SpaceReclaimed":3500}"#,
        )]);
        let applied = run_apply(&e, opted_in(), &["buildcache:1000@5000"]);
        assert_eq!(applied.removed, vec!["buildcache:1000@5000"]);
        assert_eq!(applied.bytes_freed, 3500);
        let t = e.targets("POST");
        assert!(
            t[0].contains("reserved-space=1000") && t[0].contains("all=true"),
            "{t:?}"
        );
    }

    #[test]
    fn build_cache_prune_is_refused_on_an_engine_that_ignores_reserved_space() {
        let e = extras_engine(vec![
            Route::new("GET", "/version", 200, r#"{"ApiVersion":"1.47"}"#),
            Route::new("POST", "/build/prune", 200, r#"{"SpaceReclaimed":1}"#),
        ]);
        let applied = run_apply(&e, opted_in(), &["buildcache:1000@5000"]);
        assert!(applied.removed.is_empty(), "{applied:?}");
        assert!(applied.failed[0].reason.contains("1.48"), "{applied:?}");
        assert!(e.paths("POST").is_empty());
    }

    #[test]
    fn a_build_cache_grown_since_the_plan_is_no_longer_the_planned_item() {
        let e = extras_engine(vec![
            Route::new(
                "GET",
                "/system/df",
                200,
                r#"{"BuildCacheUsage":{"Reclaimable":9000}}"#,
            ),
            Route::new("POST", "/build/prune", 200, r#"{"SpaceReclaimed":1}"#),
        ]);
        let applied = run_apply(&e, opted_in(), &["buildcache:1000@5000"]);
        assert!(applied.removed.is_empty());
        assert_eq!(applied.skipped[0].reason, "no longer a candidate");
        assert!(e.paths("POST").is_empty());
    }

    #[test]
    fn build_cache_prune_is_attempted_once() {
        let e = extras_engine(vec![Route::new(
            "POST",
            "/build/prune",
            500,
            r#"{"message":"boom"}"#,
        )]);
        let applied = run_apply(&e, opted_in(), &["buildcache:1000@5000"]);
        assert_eq!(applied.failed.len(), 1, "{applied:?}");
        assert_eq!(e.paths("POST").len(), 1);
    }

    #[test]
    fn mutations_never_retry_a_timeout() {
        let timeout = bollard::errors::Error::RequestTimeoutError;
        assert!(retryable(&timeout, false));
        assert!(!retryable(&timeout, true));
        let server = bollard::errors::Error::DockerResponseServerError {
            status_code: 500,
            message: "boom".into(),
        };
        assert!(retryable(&server, true));
    }

    #[test]
    fn a_404_after_a_retried_delete_counts_as_removed() {
        let e = extras_engine(vec![
            Route::new(
                "DELETE",
                "/images/sha256:fresh",
                500,
                r#"{"message":"boom"}"#,
            )
            .times(1),
        ]);
        let applied = run_apply(&e, opted_in(), &["image:sha256:fresh"]);
        assert_eq!(applied.removed, vec!["image:sha256:fresh"], "{applied:?}");
        assert_eq!(e.paths("DELETE").len(), 2);
    }

    #[test]
    fn execute_removes_an_opted_in_orphan_named_volume() {
        let e = extras_engine(vec![Route::new(
            "DELETE",
            "/volumes/act-toolcache",
            204,
            "",
        )]);
        let applied = run_apply(&e, opted_in(), &[&act_key()]);
        assert_eq!(applied.removed, vec![act_key()]);
        let without = run_apply(&e, Extras::default(), &[&act_key()]);
        assert!(without.removed.is_empty());
        assert_eq!(without.skipped[0].reason, "no longer a candidate");
    }

    #[test]
    fn a_volume_recreated_since_the_plan_is_not_removed() {
        let e = extras_engine(vec![Route::new(
            "DELETE",
            "/volumes/act-toolcache",
            204,
            "",
        )]);
        let stale = format!("volume:act-toolcache@{}", rfc3339(NOW - 40 * DAY));
        let applied = run_apply(&e, opted_in(), &[&stale]);
        assert!(applied.removed.is_empty());
        assert_eq!(applied.skipped[0].reason, "no longer a candidate");
        assert!(e.paths("DELETE").is_empty());
    }

    fn orphans(vols: &[String]) -> Vec<String> {
        let vols: Vec<Volume> = vols.iter().map(|v| parse(v)).collect();
        orphan_volume_candidates(
            &vols,
            None,
            &HashMap::new(),
            OrphanVolumes {
                now: NOW,
                min_age_secs: 7 * DAY,
            },
        )
        .into_iter()
        .map(|c| c.id)
        .collect()
    }

    #[test]
    fn a_downed_stacks_named_volume_is_kept() {
        let old = NOW - 30 * DAY;
        assert_eq!(
            orphans(&[
                volume_at(
                    "media_data",
                    &[
                        (COMPOSE_PROJECT_LABEL, "media"),
                        (COMPOSE_VOLUME_LABEL, "data")
                    ],
                    old
                ),
                volume_at("orca_vol", &[(crate::labels::STACK, "media")], old),
                volume_at("loose", &[], old),
            ]),
            vec!["loose"]
        );
    }

    #[test]
    fn a_young_or_undated_orphan_volume_is_kept() {
        assert!(orphans(&[volume_at("young", &[], NOW - DAY), volume("undated", &[]),]).is_empty());
    }

    #[test]
    fn olderthan_and_min_pull_age_gate_on_the_last_tag_time() {
        let images: Vec<ImageSummary> = parse(&format!(
            "[{},{}]",
            img("sha256:repulled", "", &["old:1"], NOW - 90 * DAY, 10),
            img("sha256:stale", "", &["old:2"], NOW - 90 * DAY, 10),
        ));
        let tagged = HashMap::from([
            ("sha256:repulled".to_string(), NOW - 3600),
            ("sha256:stale".to_string(), NOW - 30 * DAY),
        ]);
        let keys = |u| -> Vec<String> {
            unused_image_candidates(&images, &[], u, &tagged)
                .into_iter()
                .map(|c| c.id)
                .collect()
        };
        let older = UnusedImages {
            older_than_secs: Some(7 * DAY),
            ..every(NOW)
        };
        assert_eq!(keys(older), vec!["sha256:stale"]);
        let pull_age = UnusedImages {
            min_pull_age_secs: DAY,
            ..every(NOW)
        };
        assert_eq!(keys(pull_age), vec!["sha256:stale"]);
        let untagged_time = HashMap::new();
        assert!(unused_image_candidates(&images, &[], pull_age, &untagged_time).is_empty());
    }

    #[test]
    fn candidates_read_the_last_tag_time_from_inspect() {
        let e = extras_engine(vec![Route::new(
            "GET",
            "/images/sha256:ci/json",
            200,
            format!(
                r#"{{"Id":"sha256:ci","RepoTags":["ci-rust:1.95.0","ci-rust:latest"],"Metadata":{{"LastTagTime":"{}"}}}}"#,
                rfc3339(NOW - 3600)
            ),
        )]);
        let ext = external();
        let extras = Extras {
            unused_images: Some(UnusedImages {
                min_pull_age_secs: DAY,
                ..every(NOW)
            }),
            ..Extras::default()
        };
        let f = found(&e, host_wide(&ext, extras));
        assert!(!keys(&f).contains(&"image:sha256:ci"), "{f:?}");
        assert!(keys(&f).contains(&"image:sha256:runner"), "{f:?}");
    }

    #[test]
    fn unique_bytes_exclude_layers_shared_with_other_images() {
        let shared = |id: &str, created: i64| {
            format!(
                r#"{{"Id":"{id}","ParentId":"","RepoTags":["{id}:1"],"RepoDigests":[],"Created":{created},"Size":100,"SharedSize":60,"Labels":{{}},"Containers":-1}}"#
            )
        };
        let images: Vec<ImageSummary> = parse(&format!(
            "[{},{}]",
            shared("a", NOW - 20 * DAY),
            shared("b", NOW - 10 * DAY)
        ));
        let tagged = tagged_at_created(&images);
        let all = unused_image_candidates(&images, &[], every(NOW), &tagged);
        assert_eq!(
            all.iter().map(|c| c.bytes).collect::<Vec<_>>(),
            vec![40, 40]
        );
        let u = UnusedImages {
            keep_bytes: Some(50),
            ..every(NOW)
        };
        let ids: Vec<_> = unused_image_candidates(&images, &[], u, &tagged)
            .into_iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(ids, vec!["a"]);
    }

    #[test]
    fn image_listings_ask_for_shared_size() {
        let e = extras_engine(vec![]);
        let ext = external();
        found(&e, host_wide(&ext, opted_in()));
        assert!(
            e.targets("GET")
                .iter()
                .filter(|t| t.contains("/images/json"))
                .all(|t| t.contains("shared-size=true")),
            "{:?}",
            e.targets("GET")
        );
    }

    #[test]
    fn a_container_naming_its_image_by_digest_keeps_it() {
        let images: Vec<ImageSummary> = parse(&format!(
            "[{}]",
            r#"{"Id":"sha256:pinned","ParentId":"","RepoTags":["app:1"],"RepoDigests":["app@sha256:abc"],"Created":0,"Size":10,"SharedSize":-1,"Labels":{},"Containers":-1}"#
        ));
        let containers: Vec<ContainerSummary> =
            parse(&format!("[{}]", uses("p", "exited", "app@sha256:abc", "")));
        assert!(
            unused_image_candidates(
                &images,
                &containers,
                every(NOW),
                &tagged_at_created(&images)
            )
            .is_empty()
        );
    }

    #[test]
    fn a_server_error_is_retried_then_reported() {
        let e = FakeEngine::routed(vec![Route::new(
            "GET",
            "/images/json",
            500,
            r#"{"message":"boom"}"#,
        )]);
        let err = plugin_toolkit::reactor::block_on(dangling_images(&e.client())).unwrap_err();
        assert!(err.to_string().contains("boom"), "{err}");
        assert_eq!(e.paths("GET").len(), 3);
    }

    #[test]
    fn a_client_error_is_not_retried() {
        let e = FakeEngine::routed(vec![Route::new(
            "GET",
            "/images/json",
            400,
            r#"{"message":"bad filter"}"#,
        )]);
        assert!(plugin_toolkit::reactor::block_on(dangling_images(&e.client())).is_err());
        assert_eq!(e.paths("GET").len(), 1);
    }

    #[test]
    fn extras_follow_the_args() {
        let args = DockerPruneArgs {
            unused_images: true,
            older_than_days: Some(7),
            keep_bytes: Some(2_000_000_000),
            build_cache: true,
            orphan_volumes: true,
            ..Default::default()
        };
        assert_eq!(
            extras(&args, NOW).unwrap(),
            Extras {
                unused_images: Some(UnusedImages {
                    now: NOW,
                    older_than_secs: Some(7 * DAY),
                    keep_bytes: Some(2_000_000_000),
                    min_pull_age_secs: DAY,
                }),
                build_cache_keep_bytes: Some(0),
                orphan_volumes: Some(OrphanVolumes {
                    now: NOW,
                    min_age_secs: 7 * DAY,
                }),
            }
        );
        assert_eq!(
            extras(&DockerPruneArgs::default(), NOW).unwrap(),
            Extras::default()
        );
    }

    #[test]
    fn image_filters_without_unused_images_are_refused() {
        for args in [
            DockerPruneArgs {
                older_than_days: Some(1),
                ..Default::default()
            },
            DockerPruneArgs {
                keep_bytes: Some(1),
                ..Default::default()
            },
            DockerPruneArgs {
                build_cache_keep_bytes: Some(1),
                ..Default::default()
            },
            DockerPruneArgs {
                min_pull_age_days: Some(1),
                ..Default::default()
            },
            DockerPruneArgs {
                orphan_volume_min_age_days: Some(1),
                ..Default::default()
            },
        ] {
            assert!(extras(&args, NOW).is_err());
        }
    }

    #[test]
    fn host_wide_options_with_a_stack_are_refused() {
        let args = DockerPruneArgs {
            stack: Some("media".into()),
            unused_images: true,
            ..Default::default()
        };
        let err = extras(&args, NOW).unwrap_err();
        assert!(err.to_string().contains("stack"), "{err}");
    }

    #[test]
    fn an_oversized_budget_is_refused() {
        let args = DockerPruneArgs {
            unused_images: true,
            keep_bytes: Some(u64::MAX),
            ..Default::default()
        };
        assert!(extras(&args, NOW).is_err());
    }
}
