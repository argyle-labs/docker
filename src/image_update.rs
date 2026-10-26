//! `docker.image_status` — whether a newer image is published for each
//! stack service. Read-only.
//!
//! The remote digest comes from the engine's distribution endpoint
//! (`GET /distribution/{ref}/json`): the daemon resolves the registry and
//! applies its own mirror config. Its descriptor is whatever the tag points
//! at — the index (manifest list) for a multi-arch image, the manifest
//! otherwise — and is compared against the image's `RepoDigests`, which a
//! pull by tag on the classic image store records as that same descriptor
//! digest. The endpoint lists an index's platforms without their manifest
//! digests, so a multi-arch comparison is index-level (`basis: index`): a
//! re-pushed index (new attestations, a rebuild of another platform) reports
//! an update even when this platform's manifest is unchanged.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use bollard::Docker;
use bollard::auth::DockerCredentials;
use bollard::models::{ContainerSummary, DistributionInspect};
use bollard::query_parameters::{InspectContainerOptionsBuilder, ListContainersOptionsBuilder};
use plugin_toolkit::prelude::*;

use crate::image_ref::repository;
use crate::prune::COMPOSE_PROJECT_LABEL;
use crate::stacks::{Discovery, StackRow};

pub const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";
pub const COMPOSE_ONEOFF_LABEL: &str = "com.docker.compose.oneoff";

/// The registry host of `reference`, normalized as in [`repository`].
pub fn registry_host(reference: &str) -> String {
    let repo = repository(reference);
    repo.split('/').next().unwrap_or_default().to_string()
}

/// The secret holding credentials for registry `host`, as `username:password`
/// (a password or access token).
pub fn auth_secret_name(host: &str) -> String {
    format!("registry.{host}.auth")
}

pub fn parse_credentials(value: &str) -> Option<DockerCredentials> {
    let (username, password) = value.trim().split_once(':')?;
    if username.is_empty() || password.is_empty() {
        return None;
    }
    Some(DockerCredentials {
        username: Some(username.to_string()),
        password: Some(password.to_string()),
        ..Default::default()
    })
}

/// Credentials for `reference`'s registry from orca's secrets backend; `None`
/// when no usable secret is registered or the backend is unreachable.
pub(crate) fn registry_credentials(reference: &str) -> Option<DockerCredentials> {
    let name = auth_secret_name(&registry_host(reference));
    let value = plugin_toolkit::secrets::get(&name).ok().flatten()?;
    parse_credentials(value.expose_secret())
}

/// The digest a reference pins with `@sha256:...`, if any.
pub fn pinned_digest(reference: &str) -> Option<&str> {
    reference.split_once('@').map(|(_, d)| d)
}

/// The digests among `repo_digests` (`repo@sha256:...`) recorded for the
/// repository `reference` names. One image can carry digests for several
/// repositories when it was pulled or tagged under more than one name.
pub fn local_digests(repo_digests: &[String], reference: &str) -> Vec<String> {
    let repo = repository(reference);
    repo_digests
        .iter()
        .filter_map(|rd| rd.split_once('@'))
        .filter(|(name, _)| repository(name) == repo)
        .map(|(_, d)| d.to_string())
        .collect()
}

/// `None` when either side is unknown: a failed remote lookup, or a local
/// image with no registry digest (built or loaded locally), is never "up to
/// date".
pub fn update_available(local: &[String], remote: Option<&str>) -> Option<bool> {
    let remote = remote?;
    if local.is_empty() {
        return None;
    }
    Some(!local.iter().any(|d| d == remote))
}

/// What the remote digest identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "lowercase")]
pub enum Basis {
    /// A multi-platform index: changes whenever any platform or attestation
    /// in it changes.
    Index,
    /// A single-platform manifest.
    Platform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDigest {
    pub digest: String,
    pub basis: Basis,
}

/// The tag's current digest from a distribution inspect response.
pub fn parse_distribution(inspect: &DistributionInspect) -> Result<RemoteDigest> {
    let digest = inspect
        .descriptor
        .digest
        .as_deref()
        .ok_or_else(|| anyhow!("registry returned no digest"))?;
    if !crate::policy::is_digest(digest) {
        bail!("registry returned malformed digest '{digest}'");
    }
    let basis = match inspect.descriptor.media_type.as_deref() {
        Some(
            "application/vnd.oci.image.manifest.v1+json"
            | "application/vnd.docker.distribution.manifest.v2+json"
            | "application/vnd.docker.distribution.manifest.v1+prettyjws",
        ) => Basis::Platform,
        _ => Basis::Index,
    };
    Ok(RemoteDigest {
        digest: digest.to_string(),
        basis,
    })
}

fn remote_err(reference: &str, e: bollard::errors::Error) -> plugin_toolkit::anyhow::Error {
    match e {
        bollard::errors::Error::DockerResponseServerError {
            status_code: 401 | 403,
            message,
        } => anyhow!(
            "{reference}: registry denied access (set secret '{}' for a private image): {message}",
            auth_secret_name(&registry_host(reference))
        ),
        bollard::errors::Error::DockerResponseServerError {
            status_code: 404,
            message,
        } => anyhow!("{reference}: not found in registry: {message}"),
        e => anyhow!("{reference}: registry lookup failed: {e}"),
    }
}

/// The registry's current digest for `reference`'s tag.
pub async fn remote_digest(
    docker: &Docker,
    reference: &str,
    credentials: Option<DockerCredentials>,
) -> Result<RemoteDigest> {
    let inspect = docker
        .inspect_registry_image(reference, credentials)
        .await
        .map_err(|e| remote_err(reference, e))?;
    parse_distribution(&inspect)
}

/// The `RepoDigests` digests of image `image_id` for `reference`.
pub async fn image_repo_digests(
    docker: &Docker,
    image_id: &str,
    reference: &str,
) -> Result<Vec<String>> {
    let image = docker
        .inspect_image(image_id)
        .await
        .map_err(|e| anyhow!("inspect image {image_id}: {e}"))?;
    Ok(local_digests(
        &image.repo_digests.unwrap_or_default(),
        reference,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "camelCase")]
pub struct ServiceImageStatus {
    pub service: String,
    /// Whether any of the service's containers is running.
    pub running: bool,
    /// The image reference compose runs the service with.
    pub image: String,
    /// The local registry digest equal to the remote digest; `None` when none
    /// matches.
    pub local_digest: Option<String>,
    /// Every registry digest the local image records for `image`'s repository.
    pub local_digests: Vec<String>,
    pub remote_digest: Option<String>,
    /// What `remoteDigest` identifies; `None` when there is no remote digest
    /// or the reference pins one.
    pub basis: Option<Basis>,
    /// `None` when either digest is unknown.
    pub update_available: Option<bool>,
    pub error: Option<String>,
}

/// How a stack's compose project was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "lowercase")]
pub enum StackSource {
    Registered,
    Discovered,
    /// Its containers disagree on the project's dir or files.
    Conflict,
    /// A label is missing or names a path that cannot be read.
    Unreadable,
    /// Containers carry the project label but no stack claims it.
    Unmatched,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "camelCase")]
pub struct StackImageStatus {
    pub stack: String,
    pub source: StackSource,
    pub services: Vec<ServiceImageStatus>,
    /// Set when the stack's project, files or containers could not be read;
    /// services are still reported from their containers.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct ImageStatus {
    pub stacks: Vec<StackImageStatus>,
    /// Containers that belong to no compose project, by container name.
    pub standalone: Vec<ServiceImageStatus>,
}

pub type RemoteCache = HashMap<String, std::result::Result<RemoteDigest, String>>;

/// The non-one-off containers of compose project `project`, running or not,
/// grouped by service.
async fn project_services(
    docker: &Docker,
    project: &str,
) -> Result<BTreeMap<String, Vec<ContainerSummary>>> {
    let filters: HashMap<&str, Vec<String>> = HashMap::from([(
        "label",
        vec![
            format!("{COMPOSE_PROJECT_LABEL}={project}"),
            format!("{COMPOSE_ONEOFF_LABEL}=False"),
        ],
    )]);
    let containers = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::new()
                .all(true)
                .filters(&filters)
                .build(),
        ))
        .await
        .map_err(|e| anyhow!("list containers: {e}"))?;
    let mut by_service: BTreeMap<String, Vec<ContainerSummary>> = BTreeMap::new();
    for c in containers {
        if let Some(s) = service_of(&c) {
            by_service.entry(s.to_string()).or_default().push(c);
        }
    }
    Ok(by_service)
}

fn service_of(c: &ContainerSummary) -> Option<&str> {
    let labels = c.labels.as_ref()?;
    if labels.get(COMPOSE_ONEOFF_LABEL).map(String::as_str) == Some("True") {
        return None;
    }
    labels.get(COMPOSE_SERVICE_LABEL).map(String::as_str)
}

fn is_running(c: &ContainerSummary) -> bool {
    c.state.as_ref().map(|s| s.to_string()).as_deref() == Some("running")
}

/// The reference a container was created from. `ContainerSummary.Image`
/// becomes the bare image ID once the tag moves to a newer pull, so the
/// container's config is the source.
async fn container_reference(docker: &Docker, c: &ContainerSummary) -> Result<String> {
    let id =
        c.id.as_deref()
            .ok_or_else(|| anyhow!("container has no id"))?;
    let inspect = docker
        .inspect_container(id, Some(InspectContainerOptionsBuilder::new().build()))
        .await
        .map_err(|e| anyhow!("inspect container {id}: {e}"))?;
    inspect
        .config
        .and_then(|c| c.image)
        .filter(|i| !i.is_empty())
        .ok_or_else(|| anyhow!("container {id} has no configured image"))
}

async fn service_status(
    docker: &Docker,
    service: &str,
    containers: &[ContainerSummary],
    remote: &mut RemoteCache,
) -> ServiceImageStatus {
    let mut status = ServiceImageStatus {
        service: service.to_string(),
        running: containers.iter().any(is_running),
        image: String::new(),
        local_digest: None,
        local_digests: Vec::new(),
        remote_digest: None,
        basis: None,
        update_available: None,
        error: None,
    };
    let ids: BTreeSet<&str> = containers
        .iter()
        .filter_map(|c| c.image_id.as_deref())
        .collect();
    if ids.len() > 1 {
        let ids: Vec<&str> = ids.into_iter().collect();
        status.error = Some(format!("replicas run different images: {}", ids.join(", ")));
        return status;
    }
    let Some(first) = containers
        .iter()
        .find(|c| is_running(c))
        .or(containers.first())
    else {
        return status;
    };
    let image = match container_reference(docker, first).await {
        Ok(i) => i,
        Err(e) => {
            status.error = Some(e.to_string());
            return status;
        }
    };
    status.image = image.clone();
    let local = match ids.into_iter().next() {
        Some(id) => match image_repo_digests(docker, id, &image).await {
            Ok(l) => l,
            Err(e) => {
                status.error = Some(e.to_string());
                return status;
            }
        },
        None => Vec::new(),
    };
    let fetched = match pinned_digest(&image) {
        // A digest-pinned reference cannot move.
        Some(d) => Ok((d.to_string(), None)),
        None => {
            let r = match remote.get(&image) {
                Some(r) => r.clone(),
                None => {
                    let r = remote_digest(docker, &image, registry_credentials(&image))
                        .await
                        .map_err(|e| e.to_string());
                    remote.insert(image.clone(), r.clone());
                    r
                }
            };
            r.map(|r| (r.digest, Some(r.basis)))
        }
    };
    match fetched {
        Ok((d, basis)) => {
            status.remote_digest = Some(d);
            status.basis = basis;
        }
        Err(e) => status.error = Some(e),
    }
    status.update_available = update_available(&local, status.remote_digest.as_deref());
    status.local_digest = status
        .remote_digest
        .as_ref()
        .filter(|r| local.contains(r))
        .cloned();
    if status.error.is_none() && status.remote_digest.is_some() && local.is_empty() {
        status.error = Some(format!("{image}: local image has no registry digest"));
    }
    status.local_digests = local;
    status
}

/// The image status of each service of compose project `project`.
pub async fn stack_status(
    docker: &Docker,
    stack: &str,
    project: &str,
    remote: &mut RemoteCache,
) -> StackImageStatus {
    let mut out = StackImageStatus {
        stack: stack.to_string(),
        source: StackSource::Registered,
        services: Vec::new(),
        error: None,
    };
    match project_services(docker, project).await {
        Ok(services) => {
            for (service, containers) in &services {
                out.services
                    .push(service_status(docker, service, containers, remote).await);
            }
        }
        Err(e) => out.error = Some(e.to_string()),
    }
    out
}

/// One stack to report: its compose project and why it may be incomplete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub stack: String,
    pub project: String,
    pub source: StackSource,
    pub error: Option<String>,
}

/// A target for every registered stack, every discovery outcome and every
/// compose project in `projects` neither claims.
pub fn targets(
    registered: Vec<(StackRow, std::result::Result<String, String>)>,
    discovered: Vec<Discovery>,
    projects: &BTreeSet<String>,
) -> Vec<Target> {
    let mut out: Vec<Target> = registered
        .into_iter()
        .map(|(row, project)| match project {
            Ok(project) => Target {
                stack: row.name,
                project,
                source: StackSource::Registered,
                error: None,
            },
            Err(e) => Target {
                project: row.name.clone(),
                stack: row.name,
                source: StackSource::Registered,
                error: Some(e),
            },
        })
        .collect();
    for d in discovered {
        out.push(match d {
            Discovery::Ok(p) => Target {
                stack: p.name.clone(),
                project: p.name,
                source: StackSource::Discovered,
                error: (!p.problems.is_empty()).then(|| p.problems.join("; ")),
            },
            Discovery::Conflict { name, detail, dirs } => {
                let dirs: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
                Target {
                    stack: name.clone(),
                    project: name,
                    source: StackSource::Conflict,
                    error: Some(format!("{detail} (dirs: {})", dirs.join(", "))),
                }
            }
            Discovery::Unreadable {
                name, path, cause, ..
            } => Target {
                stack: name.clone(),
                project: name,
                source: StackSource::Unreadable,
                error: Some(format!("{}: {cause}", path.display())),
            },
        });
    }
    for p in projects {
        if !out.iter().any(|t| &t.project == p) {
            out.push(Target {
                stack: p.clone(),
                project: p.clone(),
                source: StackSource::Unmatched,
                error: Some("no registered or discovered stack claims this compose project".into()),
            });
        }
    }
    out
}

fn compose_project(c: &ContainerSummary) -> Option<&String> {
    c.labels.as_ref()?.get(COMPOSE_PROJECT_LABEL)
}

fn container_name(c: &ContainerSummary) -> String {
    c.names
        .iter()
        .flatten()
        .next()
        .map(|n| n.trim_start_matches('/').to_string())
        .or_else(|| c.id.clone())
        .unwrap_or_default()
}

async fn all_containers(docker: &Docker) -> Result<Vec<ContainerSummary>> {
    docker
        .list_containers(Some(ListContainersOptionsBuilder::new().all(true).build()))
        .await
        .map_err(|e| anyhow!("list containers: {e}"))
}

/// The status of every stack `targets` names and of every container outside
/// a compose project, against `containers`.
pub async fn report(
    docker: &Docker,
    targets: Vec<Target>,
    containers: &[ContainerSummary],
    standalone: bool,
) -> ImageStatus {
    let mut remote = RemoteCache::new();
    let mut out = ImageStatus::default();
    for t in targets {
        let mut s = stack_status(docker, &t.stack, &t.project, &mut remote).await;
        s.source = t.source;
        s.error = match (t.error, s.error) {
            (Some(a), Some(b)) => Some(format!("{a}; {b}")),
            (a, b) => a.or(b),
        };
        out.stacks.push(s);
    }
    if standalone {
        for c in containers.iter().filter(|c| compose_project(c).is_none()) {
            out.standalone.push(
                service_status(
                    docker,
                    &container_name(c),
                    std::slice::from_ref(c),
                    &mut remote,
                )
                .await,
            );
        }
    }
    out
}

#[orca_struct(args)]
pub struct DockerImageStatusArgs {
    /// Limit to one stack, registered or discovered.
    #[arg(long)]
    #[serde(default)]
    pub stack: Option<String>,
}

fn require_docker(absent: bool) -> Result<()> {
    if absent {
        bail!(
            "docker not present on this host: no registered runtime, DOCKER_HOST or docker socket"
        );
    }
    Ok(())
}

/// **Check every container on the host for image updates**: each registered
/// stack, each compose project discovered from container labels (`source`
/// says which, or `conflict`/`unreadable`/`unmatched` with the reason in
/// `error` while its services are still reported from their containers), and
/// each container outside any compose project under `standalone`. Per
/// service (running or stopped; one-off containers excluded), the local and
/// registry digests of its image and whether they differ. A registry lookup
/// that fails reports `updateAvailable: null` with the error, never "up to
/// date". `basis` says whether the comparison was against a multi-platform
/// index or a single-platform manifest; an index can change without this
/// platform's image changing. Private registries authenticate with the secret
/// `registry.<host>.auth` (`username:password`, host as in `ghcr.io` or
/// `docker.io`); without one they report the access error. Each unpinned tag
/// is a registry manifest lookup per run, which may count against Docker
/// Hub's rate limit for anonymous and free accounts. Changes nothing.
#[orca_tool(
    domain = "docker",
    verb = "image_status",
    role = "read",
    execute_gated = false
)]
async fn docker_image_status(args: DockerImageStatusArgs, _ctx: &ToolCtx) -> Result<ImageStatus> {
    require_docker(crate::tools::docker_absent()?)?;
    let docker = &crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    let containers = all_containers(docker).await?;
    let roots = crate::stacks::allowed_roots()?;
    let rows = crate::stacks::list()?;
    let discovered = crate::stacks::from_labels(&containers, &rows, &roots);
    let mut registered = Vec::new();
    for row in rows {
        if args.stack.as_ref().is_some_and(|s| s != &row.name) {
            continue;
        }
        let project = match row.compose(&roots) {
            Ok(c) => c.project_name().await.map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        registered.push((row, project));
    }
    let projects: BTreeSet<String> = containers
        .iter()
        .filter_map(compose_project)
        .cloned()
        .collect();
    let mut found = targets(registered, discovered, &projects);
    if let Some(s) = &args.stack {
        found.retain(|t| &t.stack == s);
        if found.is_empty() {
            bail!("no stack named '{s}'");
        }
    }
    Ok(report(docker, found, &containers, args.stack.is_none()).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};

    #[test]
    fn image_status_without_docker_says_docker_is_absent() {
        let err = require_docker(true).unwrap_err().to_string();
        assert!(err.contains("docker not present on this host"), "{err}");
        require_docker(false).unwrap();
    }

    const INDEX: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const OLD: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const AMD64: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

    fn index_body(digest: &str) -> String {
        format!(
            r#"{{"Descriptor":{{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"{digest}","size":1609}},"Platforms":[{{"architecture":"amd64","os":"linux"}},{{"architecture":"arm64","os":"linux"}}]}}"#
        )
    }

    fn manifest_body(digest: &str) -> String {
        format!(
            r#"{{"Descriptor":{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{digest}","size":1000}},"Platforms":[{{"architecture":"amd64","os":"linux"}}]}}"#
        )
    }

    #[test]
    fn repository_puts_explicit_hub_single_names_under_library() {
        assert_eq!(repository("docker.io/nginx"), "docker.io/library/nginx");
        assert_eq!(
            repository("index.docker.io/redis:7"),
            "docker.io/library/redis"
        );
        assert_eq!(
            repository("registry-1.docker.io/redis"),
            "docker.io/library/redis"
        );
        assert_eq!(
            local_digests(&[format!("nginx@{OLD}")], "docker.io/nginx:latest"),
            vec![OLD.to_string()]
        );
    }

    #[test]
    fn credentials_come_from_the_registry_host_secret() {
        assert_eq!(registry_host("nginx"), "docker.io");
        assert_eq!(registry_host("ghcr.io/org/app:1"), "ghcr.io");
        assert_eq!(auth_secret_name("ghcr.io"), "registry.ghcr.io.auth");
        let c = parse_credentials("bot:tok:en\n").unwrap();
        assert_eq!(c.username.as_deref(), Some("bot"));
        assert_eq!(c.password.as_deref(), Some("tok:en"));
        assert!(parse_credentials("nopassword").is_none());
        assert!(parse_credentials(":x").is_none());
    }

    #[test]
    fn local_digests_pick_the_reference_repository() {
        let rd = vec![
            format!("nginx@{OLD}"),
            format!("mirror.example/library/nginx@{AMD64}"),
        ];
        assert_eq!(local_digests(&rd, "nginx:latest"), vec![OLD.to_string()]);
        assert_eq!(
            local_digests(&rd, "docker.io/library/nginx"),
            vec![OLD.to_string()]
        );
        assert!(local_digests(&rd, "ghcr.io/x/nginx").is_empty());
    }

    #[test]
    fn comparison_treats_unknown_as_unknown() {
        let local = vec![INDEX.to_string()];
        assert_eq!(update_available(&local, Some(INDEX)), Some(false));
        assert_eq!(update_available(&local, Some(OLD)), Some(true));
        assert_eq!(update_available(&local, None), None);
        assert_eq!(update_available(&[], Some(INDEX)), None);
        assert_eq!(
            update_available(&[OLD.to_string(), INDEX.to_string()], Some(INDEX)),
            Some(false)
        );
    }

    #[test]
    fn parses_index_and_rejects_missing_or_malformed_digest() {
        let ok: DistributionInspect =
            plugin_toolkit::serde_json::from_str(&index_body(INDEX)).unwrap();
        assert_eq!(
            parse_distribution(&ok).unwrap(),
            RemoteDigest {
                digest: INDEX.to_string(),
                basis: Basis::Index
            }
        );
        let none: DistributionInspect = plugin_toolkit::serde_json::from_str(
            r#"{"Descriptor":{"mediaType":"application/vnd.docker.distribution.manifest.v2+json"},"Platforms":[]}"#,
        )
        .unwrap();
        assert!(parse_distribution(&none).is_err());
        let bad: DistributionInspect =
            plugin_toolkit::serde_json::from_str(&index_body("sha256:zz")).unwrap();
        assert!(parse_distribution(&bad).is_err());
    }

    #[test]
    fn single_manifest_is_platform_basis() {
        let list: DistributionInspect = plugin_toolkit::serde_json::from_str(&format!(
            r#"{{"Descriptor":{{"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","digest":"{INDEX}"}},"Platforms":[]}}"#
        ))
        .unwrap();
        assert_eq!(parse_distribution(&list).unwrap().basis, Basis::Index);
        let single: DistributionInspect =
            plugin_toolkit::serde_json::from_str(&manifest_body(AMD64)).unwrap();
        assert_eq!(
            parse_distribution(&single).unwrap(),
            RemoteDigest {
                digest: AMD64.to_string(),
                basis: Basis::Platform
            }
        );
    }

    fn remote(routes: Vec<Route>, reference: &str) -> Result<RemoteDigest> {
        let e = FakeEngine::routed(routes);
        plugin_toolkit::reactor::block_on(remote_digest(&e.client(), reference, None))
    }

    #[test]
    fn remote_digest_is_the_index_digest() {
        let d = remote(
            vec![Route::new(
                "GET",
                "/distribution/lscr.io/linuxserver/sonarr:latest/json",
                200,
                index_body(INDEX),
            )],
            "lscr.io/linuxserver/sonarr:latest",
        )
        .unwrap();
        assert_eq!(d.digest, INDEX);
    }

    #[test]
    fn remote_denied_and_missing_are_errors() {
        let denied = remote(
            vec![Route::new(
                "GET",
                "/distribution/ghcr.io/org/private:1/json",
                401,
                r#"{"message":"unauthorized: authentication required"}"#,
            )],
            "ghcr.io/org/private:1",
        )
        .unwrap_err()
        .to_string();
        assert!(denied.contains("denied access"), "{denied}");
        assert!(denied.contains("registry.ghcr.io.auth"), "{denied}");
        let missing = remote(vec![], "nginx:nope").unwrap_err().to_string();
        assert!(missing.contains("not found"), "{missing}");
    }

    fn container(name: &str, service: &str, image: &str, id: Option<&str>, state: &str) -> String {
        let id = id.map_or("null".to_string(), |i| format!(r#""{i}""#));
        format!(
            r#"{{"Id":"c-{name}","Names":["/media-{name}"],"Image":"{image}","ImageID":{id},"State":"{state}","Labels":{{"{COMPOSE_PROJECT_LABEL}":"media","{COMPOSE_SERVICE_LABEL}":"{service}","{COMPOSE_ONEOFF_LABEL}":"False"}}}}"#
        )
    }

    fn inspect(name: &str, reference: &str) -> Route {
        Route::new(
            "GET",
            format!("/containers/c-{name}/json"),
            200,
            format!(r#"{{"Id":"c-{name}","Config":{{"Image":"{reference}"}}}}"#),
        )
    }

    fn image(id: &str, digests: &[String]) -> String {
        format!(
            r#"{{"Id":"{id}","RepoDigests":{}}}"#,
            plugin_toolkit::serde_json::to_string(digests).unwrap()
        )
    }

    fn run(routes: Vec<Route>) -> (StackImageStatus, FakeEngine) {
        let e = FakeEngine::routed(routes);
        let mut cache = RemoteCache::new();
        let s = plugin_toolkit::reactor::block_on(stack_status(
            &e.client(),
            "media",
            "media",
            &mut cache,
        ));
        (s, e)
    }

    fn by(s: &StackImageStatus, n: &str) -> ServiceImageStatus {
        s.services.iter().find(|x| x.service == n).unwrap().clone()
    }

    #[test]
    fn stack_status_reports_current_stale_and_unknown_services() {
        let containers = format!(
            "[{},{},{},{}]",
            // The tag moved after a newer pull: the summary shows the bare ID.
            container(
                "web-1",
                "web",
                "sha256:img-web",
                Some("sha256:img-web"),
                "running"
            ),
            container(
                "web-2",
                "web",
                "sha256:img-web",
                Some("sha256:img-web"),
                "running"
            ),
            container(
                "tv-1",
                "tv",
                "lscr.io/linuxserver/sonarr:latest",
                Some("sha256:img-tv"),
                "exited"
            ),
            container(
                "priv-1",
                "priv",
                "ghcr.io/org/private:1",
                Some("sha256:img-priv"),
                "running"
            ),
        );
        let (s, e) = run(vec![
            Route::new("GET", "/containers/json", 200, containers),
            inspect("web-1", "nginx:latest"),
            inspect("tv-1", "lscr.io/linuxserver/sonarr:latest"),
            inspect("priv-1", "ghcr.io/org/private:1"),
            Route::new(
                "GET",
                "/images/sha256:img-web/json",
                200,
                image("sha256:img-web", &[format!("nginx@{INDEX}")]),
            ),
            Route::new(
                "GET",
                "/images/sha256:img-tv/json",
                200,
                image(
                    "sha256:img-tv",
                    &[format!("lscr.io/linuxserver/sonarr@{OLD}")],
                ),
            ),
            Route::new(
                "GET",
                "/images/sha256:img-priv/json",
                200,
                image("sha256:img-priv", &[format!("ghcr.io/org/private@{OLD}")]),
            ),
            Route::new(
                "GET",
                "/distribution/nginx:latest/json",
                200,
                index_body(INDEX),
            ),
            Route::new(
                "GET",
                "/distribution/lscr.io/linuxserver/sonarr:latest/json",
                200,
                manifest_body(AMD64),
            ),
            Route::new(
                "GET",
                "/distribution/ghcr.io/org/private:1/json",
                401,
                r#"{"message":"unauthorized"}"#,
            ),
        ]);
        assert_eq!(s.error, None);
        assert_eq!(s.services.len(), 3);
        let web = by(&s, "web");
        assert!(web.running);
        assert_eq!(web.image, "nginx:latest");
        assert_eq!(web.update_available, Some(false));
        assert_eq!(web.local_digest.as_deref(), Some(INDEX));
        assert_eq!(web.basis, Some(Basis::Index));
        let tv = by(&s, "tv");
        assert!(!tv.running);
        assert_eq!(tv.update_available, Some(true));
        assert_eq!(tv.local_digest, None);
        assert_eq!(tv.local_digests, vec![OLD.to_string()]);
        assert_eq!(tv.remote_digest.as_deref(), Some(AMD64));
        assert_eq!(tv.basis, Some(Basis::Platform));
        let private = by(&s, "priv");
        assert_eq!(private.update_available, None);
        assert_eq!(private.remote_digest, None);
        assert!(private.error.is_some());
        let targets = e.targets("GET");
        let list = targets
            .iter()
            .find(|t| t.starts_with("/containers/json"))
            .unwrap();
        assert!(list.contains("all=true"), "{list}");
        assert!(list.contains("com.docker.compose.project=media"), "{list}");
        assert!(list.contains("com.docker.compose.oneoff=False"), "{list}");
        assert!(!list.contains("status"), "{list}");
        assert!(e.paths("POST").is_empty() && e.paths("DELETE").is_empty());
    }

    #[test]
    fn stack_status_skips_the_registry_for_pinned_and_flags_missing_image_id() {
        let pinned = format!("ghcr.io/org/app@{INDEX}");
        let containers = format!(
            "[{},{}]",
            container("app-1", "app", &pinned, Some("sha256:img-app"), "running"),
            container("built-1", "built", "local/built:dev", None, "running"),
        );
        let (s, e) = run(vec![
            Route::new("GET", "/containers/json", 200, containers),
            inspect("app-1", &pinned),
            inspect("built-1", "local/built:dev"),
            Route::new(
                "GET",
                "/images/sha256:img-app/json",
                200,
                image("sha256:img-app", &[format!("ghcr.io/org/app@{INDEX}")]),
            ),
            Route::new(
                "GET",
                "/distribution/local/built:dev/json",
                200,
                manifest_body(AMD64),
            ),
        ]);
        let app = by(&s, "app");
        assert_eq!(app.update_available, Some(false));
        assert_eq!(app.remote_digest.as_deref(), Some(INDEX));
        assert_eq!(app.basis, None);
        let built = by(&s, "built");
        assert_eq!(built.update_available, None);
        assert!(built.local_digests.is_empty());
        assert!(
            built
                .error
                .as_deref()
                .unwrap()
                .contains("no registry digest"),
            "{built:?}"
        );
        assert!(
            !e.paths("GET")
                .iter()
                .any(|p| p.contains("/distribution/ghcr.io")),
            "pinned reference hit the registry"
        );
    }

    #[test]
    fn stack_status_reports_divergent_replicas() {
        let containers = format!(
            "[{},{}]",
            container(
                "web-1",
                "web",
                "nginx:latest",
                Some("sha256:img-a"),
                "running"
            ),
            container(
                "web-2",
                "web",
                "nginx:latest",
                Some("sha256:img-b"),
                "running"
            ),
        );
        let (s, _) = run(vec![Route::new("GET", "/containers/json", 200, containers)]);
        let web = by(&s, "web");
        assert_eq!(web.update_available, None);
        assert_eq!(
            web.error.as_deref(),
            Some("replicas run different images: sha256:img-a, sha256:img-b")
        );
    }

    #[test]
    fn stack_status_ignores_one_off_containers() {
        let oneoff = format!(
            r#"{{"Id":"c-run","Names":["/media-web-run-1"],"Image":"nginx","ImageID":"sha256:x","State":"running","Labels":{{"{COMPOSE_PROJECT_LABEL}":"media","{COMPOSE_SERVICE_LABEL}":"web","{COMPOSE_ONEOFF_LABEL}":"True"}}}}"#
        );
        let (s, e) = run(vec![Route::new(
            "GET",
            "/containers/json",
            200,
            format!("[{oneoff}]"),
        )]);
        assert!(s.services.is_empty(), "{s:?}");
        assert!(!e.paths("GET").iter().any(|p| p.contains("c-run")));
    }

    fn row(name: &str) -> StackRow {
        StackRow {
            name: name.into(),
            dir: format!("/opt/stacks/{name}"),
            file: "compose.yaml".into(),
            enabled: true,
            allow: Vec::new(),
            files: Vec::new(),
            env_files: Vec::new(),
        }
    }

    #[test]
    fn targets_cover_every_stack_outcome_and_unclaimed_project() {
        let discovered = vec![
            Discovery::Ok(crate::stacks::DiscoveredProject {
                name: "found".into(),
                dir: "/opt/stacks/found".into(),
                files: vec!["/opt/stacks/found/compose.yaml".into()],
                env_files: Vec::new(),
                problems: vec!["/x/.env: cannot be opened".into()],
            }),
            Discovery::Conflict {
                name: "split".into(),
                detail: "its containers disagree".into(),
                dirs: vec!["/opt/stacks/a".into(), "/opt/stacks/b".into()],
            },
            Discovery::Unreadable {
                name: "locked".into(),
                dir: "/mnt/user/appdata/locked".into(),
                path: "/mnt/user/appdata/locked".into(),
                cause: "the working dir is not a directory inside the stacks roots".into(),
                running: true,
            },
        ];
        let projects: BTreeSet<String> = ["web", "found", "split", "locked", "renamed", "stray"]
            .into_iter()
            .map(String::from)
            .collect();
        let t = targets(
            vec![
                (row("web"), Ok("web".into())),
                (row("broken"), Err("compose file unreadable".into())),
                (row("other"), Ok("renamed".into())),
            ],
            discovered,
            &projects,
        );
        let got: Vec<(&str, &str, StackSource, bool)> = t
            .iter()
            .map(|t| {
                (
                    t.stack.as_str(),
                    t.project.as_str(),
                    t.source,
                    t.error.is_some(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("web", "web", StackSource::Registered, false),
                ("broken", "broken", StackSource::Registered, true),
                ("other", "renamed", StackSource::Registered, false),
                ("found", "found", StackSource::Discovered, true),
                ("split", "split", StackSource::Conflict, true),
                ("locked", "locked", StackSource::Unreadable, true),
                ("stray", "stray", StackSource::Unmatched, true),
            ]
        );
        assert!(
            t[4].error
                .as_deref()
                .unwrap()
                .contains("/opt/stacks/a, /opt/stacks/b")
        );
        assert!(
            t[5].error
                .as_deref()
                .unwrap()
                .starts_with("/mnt/user/appdata/locked: ")
        );
    }

    #[test]
    fn report_keeps_unreadable_stacks_and_lists_standalone_containers() {
        let compose = container(
            "tv-1",
            "tv",
            "lscr.io/linuxserver/sonarr:latest",
            Some("sha256:img-tv"),
            "running",
        );
        let standalone = r#"{"Id":"c-sync","Names":["/syncthing"],"Image":"syncthing/syncthing:1","ImageID":"sha256:img-sync","State":"running","Labels":{}}"#;
        let all: Vec<ContainerSummary> =
            plugin_toolkit::serde_json::from_str(&format!("[{compose},{standalone}]")).unwrap();
        let e = FakeEngine::routed(vec![
            Route::new("GET", "/containers/json", 200, format!("[{compose}]")),
            inspect("tv-1", "lscr.io/linuxserver/sonarr:latest"),
            inspect("sync", "syncthing/syncthing:1"),
            Route::new(
                "GET",
                "/images/sha256:img-tv/json",
                200,
                image(
                    "sha256:img-tv",
                    &[format!("lscr.io/linuxserver/sonarr@{OLD}")],
                ),
            ),
            Route::new(
                "GET",
                "/images/sha256:img-sync/json",
                200,
                image("sha256:img-sync", &[format!("syncthing/syncthing@{INDEX}")]),
            ),
            Route::new(
                "GET",
                "/distribution/lscr.io/linuxserver/sonarr:latest/json",
                200,
                manifest_body(AMD64),
            ),
            Route::new(
                "GET",
                "/distribution/syncthing/syncthing:1/json",
                200,
                index_body(INDEX),
            ),
        ]);
        let target = Target {
            stack: "media".into(),
            project: "media".into(),
            source: StackSource::Unreadable,
            error: Some("/mnt/user/appdata/media: cannot be opened".into()),
        };
        let out = plugin_toolkit::reactor::block_on(report(&e.client(), vec![target], &all, true));
        assert_eq!(out.stacks.len(), 1);
        let media = &out.stacks[0];
        assert_eq!(media.source, StackSource::Unreadable);
        assert_eq!(
            media.error.as_deref(),
            Some("/mnt/user/appdata/media: cannot be opened")
        );
        assert_eq!(by(media, "tv").update_available, Some(true));
        assert_eq!(out.standalone.len(), 1);
        let sync = &out.standalone[0];
        assert_eq!(sync.service, "syncthing");
        assert_eq!(sync.image, "syncthing/syncthing:1");
        assert_eq!(sync.update_available, Some(false));
        let none = plugin_toolkit::reactor::block_on(report(&e.client(), Vec::new(), &all, false));
        assert!(none.standalone.is_empty());
    }
}
