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

use crate::prune::COMPOSE_PROJECT_LABEL;

pub const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";
pub const COMPOSE_ONEOFF_LABEL: &str = "com.docker.compose.oneoff";

const DOCKER_HUB: &str = "docker.io";

/// `registry/path` of an image reference with its tag and digest removed,
/// with Docker Hub's implied registry and `library/` namespace filled in.
pub fn repository(reference: &str) -> String {
    let name = reference.split('@').next().unwrap_or(reference);
    // A `:` after the last `/` is a tag; before it, a registry port.
    let name = match name.rfind(':') {
        Some(i) if !name[i..].contains('/') => &name[..i],
        _ => name,
    };
    let (registry, path) = match name.split_once('/') {
        Some((first, rest))
            if first.contains('.') || first.contains(':') || first == "localhost" =>
        {
            (first, rest)
        }
        _ => (DOCKER_HUB, name),
    };
    let registry = match registry {
        "index.docker.io" | "registry-1.docker.io" => DOCKER_HUB,
        r => r,
    };
    if registry == DOCKER_HUB && !path.contains('/') {
        format!("{DOCKER_HUB}/library/{path}")
    } else {
        format!("{registry}/{path}")
    }
}

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
    parse_credentials(&value)
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "camelCase")]
pub struct StackImageStatus {
    pub stack: String,
    pub services: Vec<ServiceImageStatus>,
    /// Set when the stack's project or containers could not be read.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct ImageStatus {
    pub stacks: Vec<StackImageStatus>,
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

#[orca_struct(args)]
pub struct DockerImageStatusArgs {
    /// Limit to one managed stack.
    #[arg(long)]
    #[serde(default)]
    pub stack: Option<String>,
}

/// **Check managed stacks for image updates**: per service (running or
/// stopped; one-off containers excluded), the local and registry digests of
/// its image and whether they differ. A registry lookup that fails reports
/// `updateAvailable: null` with the error, never "up to date". `basis` says
/// whether the comparison was against a multi-platform index or a
/// single-platform manifest; an index can change without this platform's
/// image changing. Private registries authenticate with the secret
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
    let rows = match &args.stack {
        Some(s) => vec![crate::stacks::require(s)?],
        None => crate::stacks::list()?,
    };
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    let mut remote = RemoteCache::new();
    let mut out = ImageStatus::default();
    for row in rows {
        let project = match row.compose() {
            Ok(c) => c.project_name().await.map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        out.stacks.push(match project {
            Ok(p) => stack_status(docker, &row.name, &p, &mut remote).await,
            Err(e) => StackImageStatus {
                stack: row.name.clone(),
                services: Vec::new(),
                error: Some(e),
            },
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};

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
    fn repository_normalizes_hub_and_strips_tag_and_digest() {
        assert_eq!(repository("nginx"), "docker.io/library/nginx");
        assert_eq!(repository("nginx:1.27"), "docker.io/library/nginx");
        assert_eq!(
            repository("docker.io/library/nginx:latest"),
            "docker.io/library/nginx"
        );
        assert_eq!(
            repository("index.docker.io/grafana/grafana"),
            "docker.io/grafana/grafana"
        );
        assert_eq!(
            repository("grafana/grafana:11"),
            "docker.io/grafana/grafana"
        );
        assert_eq!(
            repository("lscr.io/linuxserver/sonarr:latest"),
            "lscr.io/linuxserver/sonarr"
        );
        assert_eq!(
            repository(&format!("ghcr.io/org/app@{INDEX}")),
            "ghcr.io/org/app"
        );
        assert_eq!(
            repository("gitea.example:3000/org/app:v1"),
            "gitea.example:3000/org/app"
        );
        assert_eq!(repository("localhost/app"), "localhost/app");
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
}
