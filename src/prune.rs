//! `docker.prune` — remove orphaned engine resources.
//!
//! Candidates are dangling images, dangling **anonymous** volumes and compose
//! networks no container uses. Named volumes are never candidates: a volume
//! qualifies only when the engine stamped it `com.docker.volume.anonymous`,
//! and never when compose declared it by name (`com.docker.compose.volume`).
//!
//! Compose (2.31 and 2.40, measured on the fleet) does not label anonymous
//! volumes with `com.docker.compose.project`, and a dangling volume has no
//! container to attribute it by, so a `--stack` prune finds no volumes.
//!
//! Networks that any managed stack declares `external: true` are never
//! candidates. When a stack's config cannot be read, no network is a
//! candidate, because any of them might be that stack's external network.
//!
//! Dry run by default: the plan lists every candidate by key. Execute takes
//! those keys back, recomputes the candidates, and removes only keys present
//! in both. The engine still refuses to remove anything in use, which is
//! reported as skipped.
#![allow(clippy::disallowed_types)]

use std::collections::{HashMap, HashSet};

use bollard::Docker;
use bollard::models::{ContainerSummary, ImageSummary, Network, Volume};
use bollard::query_parameters::{
    ListContainersOptionsBuilder, ListImagesOptionsBuilder, ListNetworksOptionsBuilder,
    ListVolumesOptionsBuilder, RemoveImageOptionsBuilder, RemoveVolumeOptionsBuilder,
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
}

impl ResourceKind {
    fn prefix(self) -> &'static str {
        match self {
            ResourceKind::Image => "image",
            ResourceKind::Volume => "volume",
            ResourceKind::Network => "network",
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
}

impl Candidate {
    fn new(kind: ResourceKind, id: &str, detail: String) -> Self {
        Self {
            key: format!("{}:{id}", kind.prefix()),
            kind,
            id: id.to_string(),
            detail,
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
        .map(|i| {
            Candidate::new(
                ResourceKind::Image,
                &i.id,
                format!("dangling image, {} bytes", i.size),
            )
        })
        .collect()
}

/// Anonymous volumes from a `dangling=true` listing. In a project scope, a
/// volume without that project's label is left alone.
pub fn volume_candidates(volumes: &[Volume], project: Option<&str>) -> Vec<Candidate> {
    volumes
        .iter()
        .filter(|v| v.labels.contains_key(ANONYMOUS_VOLUME_LABEL))
        .filter(|v| !v.labels.contains_key(COMPOSE_VOLUME_LABEL))
        .filter(|v| match project {
            Some(p) => v.labels.get(COMPOSE_PROJECT_LABEL).map(String::as_str) == Some(p),
            None => true,
        })
        .map(|v| {
            Candidate::new(
                ResourceKind::Volume,
                &v.name,
                "dangling anonymous volume".to_string(),
            )
        })
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

fn label_filter(project: Option<&str>) -> HashMap<&'static str, Vec<String>> {
    let label = match project {
        Some(p) => format!("{COMPOSE_PROJECT_LABEL}={p}"),
        None => COMPOSE_PROJECT_LABEL.to_string(),
    };
    HashMap::from([("label", vec![label])])
}

/// Every current candidate within `scope`.
pub async fn candidates(docker: &Docker, scope: Scope<'_>) -> Result<Vec<Candidate>> {
    let project = scope.project;
    let dangling = HashMap::from([("dangling", vec!["true"])]);
    let images = docker
        .list_images(Some(
            ListImagesOptionsBuilder::new().filters(&dangling).build(),
        ))
        .await
        .map_err(|e| engine_err("list images", e))?;
    let volumes = docker
        .list_volumes(Some(
            ListVolumesOptionsBuilder::new().filters(&dangling).build(),
        ))
        .await
        .map_err(|e| engine_err("list volumes", e))?
        .volumes
        .unwrap_or_default();
    let networks = docker
        .list_networks(Some(
            ListNetworksOptionsBuilder::new()
                .filters(&label_filter(project))
                .build(),
        ))
        .await
        .map_err(|e| engine_err("list networks", e))?;
    let containers = docker
        .list_containers(Some(ListContainersOptionsBuilder::new().all(true).build()))
        .await
        .map_err(|e| engine_err("list containers", e))?;

    let mut out = image_candidates(&images, project);
    out.extend(volume_candidates(&volumes, project));
    out.extend(network_candidates(&networks, &containers, scope));
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
    /// Always `false`: changes were applied.
    pub dry_run: bool,
    pub removed: Vec<String>,
    /// Not removed, and not an error: no longer a candidate, already gone,
    /// or refused by the engine as in use.
    pub skipped: Vec<Skipped>,
    pub failed: Vec<Skipped>,
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
async fn network_in_use(docker: &Docker, id: &str) -> Result<bool> {
    let filters = HashMap::from([("network", vec![id])]);
    let attached = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::new()
                .all(true)
                .filters(&filters)
                .build(),
        ))
        .await
        .map_err(|e| engine_err("list containers on network", e))?;
    Ok(!attached.is_empty())
}

// Removal is by id without force, so the engine refuses anything in use. Two
// windows of one round trip remain between the last check and the DELETE: a
// container attaching to a network, and an image being tagged (an image with
// one tag is untagged and deleted by an id DELETE).
async fn remove(docker: &Docker, c: &Candidate) -> std::result::Result<(), bollard::errors::Error> {
    match c.kind {
        ResourceKind::Image => docker
            .remove_image(
                &c.id,
                Some(RemoveImageOptionsBuilder::new().force(false).build()),
                None,
            )
            .await
            .map(|_| ()),
        ResourceKind::Volume => {
            docker
                .remove_volume(
                    &c.id,
                    Some(RemoveVolumeOptionsBuilder::new().force(false).build()),
                )
                .await
        }
        ResourceKind::Network => docker.remove_network(&c.id).await,
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
        match remove(docker, c).await {
            Ok(()) => applied.removed.push(key),
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
    let summary = if candidates.is_empty() {
        format!("nothing to prune{where_}")
    } else {
        format!("remove {} orphaned resource(s){where_}", candidates.len())
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
        "re-invoke {TOOL} with `execute: true` and `items` set to the change targets to remove; only items still orphaned are removed"
    );
    Ok(p)
}

#[orca_struct(args)]
pub struct DockerPruneArgs {
    /// Limit to one managed stack's compose project.
    #[arg(long)]
    #[serde(default)]
    pub stack: Option<String>,
    /// The plan's change targets to remove (execute only). Comma-separated on
    /// the CLI.
    #[arg(long, value_delimiter = ',')]
    #[serde(default)]
    pub items: Vec<String>,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

async fn project_for(stack: &str) -> Result<String> {
    let row = crate::stacks::require(stack)?;
    Ok(row.compose()?.project_name().await?)
}

/// Networks every managed stack declares external, or `None` when any
/// stack's config cannot be read.
async fn external_networks() -> Result<Option<HashSet<String>>> {
    let mut out = HashSet::new();
    for row in crate::stacks::list()? {
        let Ok(compose) = row.compose() else {
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
/// volumes and compose networks no container uses. Named volumes are never
/// removed. Without `execute`, returns the candidates and changes nothing.
#[orca_tool(
    domain = "docker",
    verb = "prune",
    role = "admin",
    execute_gated = false
)]
async fn docker_prune(args: DockerPruneArgs, ctx: &ToolCtx) -> Result<PruneChange> {
    execute::guard(TOOL, args.execute, ctx)?;
    let project = match &args.stack {
        Some(s) => Some(project_for(s).await?),
        None => None,
    };
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    let external = external_networks().await?;
    let scope = Scope {
        project: project.as_deref(),
        external_networks: external.as_ref(),
    };
    if args.execute {
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
        assert!(volume_candidates(&[v], None).is_empty());
    }

    #[test]
    fn stack_scope_limits_to_the_project_and_finds_no_unattributable_volumes() {
        let e = engine(vec![]);
        let ext = external();
        let scope = Scope {
            project: Some("media"),
            external_networks: Some(&ext),
        };
        assert_eq!(keys(&found(&e, scope)), vec!["network:n-media-orphan"]);
    }

    #[test]
    fn plan_lists_every_candidate_and_changes_nothing() {
        let e = engine(vec![]);
        let ext = external();
        let f = found(&e, all(&ext));
        let args = DockerPruneArgs {
            stack: None,
            items: vec![],
            execute: false,
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
            execute: true,
        };
        let err = plugin_toolkit::reactor::block_on(docker_prune(args, &ctx_without_caller()))
            .unwrap_err();
        assert!(err.to_string().contains("no caller identity"), "{err}");
    }

    #[test]
    fn a_dry_run_needs_no_admin_caller() {
        let args = DockerPruneArgs {
            stack: None,
            items: vec![],
            execute: false,
        };
        // With no engine or core DB under test the call may still fail, but
        // never on the caller's role.
        if let Err(e) = plugin_toolkit::reactor::block_on(docker_prune(args, &ctx_without_caller()))
        {
            let msg = e.to_string();
            assert!(
                !msg.contains("caller identity") && !msg.contains("requires role"),
                "{msg}"
            );
        }
    }
}
