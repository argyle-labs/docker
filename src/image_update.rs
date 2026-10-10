//! `docker.image_status` — whether a newer image is published for each
//! running stack service. Read-only.
//!
//! The remote digest comes from the engine's distribution endpoint
//! (`GET /distribution/{ref}/json`), so the daemon resolves the registry,
//! performs the anonymous token exchange for public images and applies its
//! own mirror config — the same path a `docker pull` takes. Its descriptor is
//! whatever the tag points at: the index (manifest list) for a multi-arch
//! image, the manifest otherwise. A pull by tag records that same digest in
//! the image's `RepoDigests`, so the two compare like with like without
//! resolving a platform.
#![allow(clippy::disallowed_types)]

use std::collections::HashMap;

use bollard::Docker;
use bollard::models::{ContainerSummary, DistributionInspect};
use bollard::query_parameters::ListContainersOptionsBuilder;
use plugin_toolkit::prelude::*;

use crate::prune::COMPOSE_PROJECT_LABEL;

pub const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";

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
            (first, rest.to_string())
        }
        Some(_) => (DOCKER_HUB, name.to_string()),
        None => (DOCKER_HUB, format!("library/{name}")),
    };
    let registry = match registry {
        "index.docker.io" | "registry-1.docker.io" => DOCKER_HUB,
        r => r,
    };
    format!("{registry}/{path}")
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

/// The tag's current digest from a distribution inspect response.
pub fn parse_distribution(inspect: &DistributionInspect) -> Result<String> {
    let digest = inspect
        .descriptor
        .digest
        .as_deref()
        .ok_or_else(|| anyhow!("registry returned no digest"))?;
    if !crate::policy::is_digest(digest) {
        bail!("registry returned malformed digest '{digest}'");
    }
    Ok(digest.to_string())
}

fn remote_err(reference: &str, e: bollard::errors::Error) -> plugin_toolkit::anyhow::Error {
    match e {
        bollard::errors::Error::DockerResponseServerError {
            status_code: 401 | 403,
            message,
        } => anyhow!(
            "{reference}: registry denied access (private image without credentials?): {message}"
        ),
        bollard::errors::Error::DockerResponseServerError {
            status_code: 404,
            message,
        } => anyhow!("{reference}: not found in registry: {message}"),
        e => anyhow!("{reference}: registry lookup failed: {e}"),
    }
}

/// The registry's current digest for `reference`'s tag.
pub async fn remote_digest(docker: &Docker, reference: &str) -> Result<String> {
    let inspect = docker
        .inspect_registry_image(reference, None)
        .await
        .map_err(|e| remote_err(reference, e))?;
    parse_distribution(&inspect)
}

/// The `RepoDigests` digests of image `image_id` for `reference`.
pub async fn local_digest(docker: &Docker, image_id: &str, reference: &str) -> Result<Vec<String>> {
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
    /// The image reference compose runs the service with.
    pub image: String,
    /// The local registry digest; the one matching the remote when several
    /// are recorded.
    pub local_digest: Option<String>,
    pub remote_digest: Option<String>,
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
    /// Running services only.
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

/// One running container per service of compose project `project`.
async fn running_services(docker: &Docker, project: &str) -> Result<Vec<ContainerSummary>> {
    let filters: HashMap<&str, Vec<String>> = HashMap::from([
        ("label", vec![format!("{COMPOSE_PROJECT_LABEL}={project}")]),
        ("status", vec!["running".to_string()]),
    ]);
    let mut containers = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::new()
                .filters(&filters)
                .build(),
        ))
        .await
        .map_err(|e| anyhow!("list containers: {e}"))?;
    containers.sort_by_key(|c| service_of(c).map(str::to_string));
    containers.dedup_by_key(|c| service_of(c).map(str::to_string));
    Ok(containers
        .into_iter()
        .filter(|c| service_of(c).is_some())
        .collect())
}

fn service_of(c: &ContainerSummary) -> Option<&str> {
    c.labels
        .as_ref()?
        .get(COMPOSE_SERVICE_LABEL)
        .map(String::as_str)
}

async fn service_status(
    docker: &Docker,
    c: &ContainerSummary,
    remote: &mut HashMap<String, std::result::Result<String, String>>,
) -> ServiceImageStatus {
    let service = service_of(c).unwrap_or_default().to_string();
    let image = c.image.clone().unwrap_or_default();
    let mut status = ServiceImageStatus {
        service,
        image: image.clone(),
        local_digest: None,
        remote_digest: None,
        update_available: None,
        error: None,
    };
    let local = match c.image_id.as_deref() {
        Some(id) => match local_digest(docker, id, &image).await {
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
        Some(d) => Ok(d.to_string()),
        None => match remote.get(&image) {
            Some(r) => r.clone(),
            None => {
                let r = remote_digest(docker, &image)
                    .await
                    .map_err(|e| e.to_string());
                remote.insert(image.clone(), r.clone());
                r
            }
        },
    };
    match fetched {
        Ok(d) => status.remote_digest = Some(d),
        Err(e) => status.error = Some(e),
    }
    status.update_available = update_available(&local, status.remote_digest.as_deref());
    status.local_digest = status
        .remote_digest
        .as_ref()
        .filter(|r| local.contains(r))
        .cloned()
        .or_else(|| local.first().cloned());
    if status.error.is_none() && status.remote_digest.is_some() && local.is_empty() {
        status.error = Some(format!("{image}: local image has no registry digest"));
    }
    status
}

/// The image status of each running service of compose project `project`.
pub async fn stack_status(
    docker: &Docker,
    stack: &str,
    project: &str,
    remote: &mut HashMap<String, std::result::Result<String, String>>,
) -> StackImageStatus {
    let mut out = StackImageStatus {
        stack: stack.to_string(),
        services: Vec::new(),
        error: None,
    };
    match running_services(docker, project).await {
        Ok(containers) => {
            for c in &containers {
                out.services.push(service_status(docker, c, remote).await);
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

/// **Check managed stacks for image updates**: per running service, the
/// local and registry digests of its image and whether they differ. A
/// registry lookup that fails reports `updateAvailable: null` with the error,
/// never "up to date". Changes nothing.
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
    let mut remote = HashMap::new();
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
        assert_eq!(parse_distribution(&ok).unwrap(), INDEX);
        let none: DistributionInspect = plugin_toolkit::serde_json::from_str(
            r#"{"Descriptor":{"mediaType":"application/vnd.docker.distribution.manifest.v2+json"},"Platforms":[]}"#,
        )
        .unwrap();
        assert!(parse_distribution(&none).is_err());
        let bad: DistributionInspect =
            plugin_toolkit::serde_json::from_str(&index_body("sha256:zz")).unwrap();
        assert!(parse_distribution(&bad).is_err());
    }

    fn remote(routes: Vec<Route>, reference: &str) -> Result<String> {
        let e = FakeEngine::routed(routes);
        plugin_toolkit::reactor::block_on(remote_digest(&e.client(), reference))
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
        assert_eq!(d, INDEX);
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
        let missing = remote(vec![], "nginx:nope").unwrap_err().to_string();
        assert!(missing.contains("not found"), "{missing}");
    }

    fn container(service: &str, image: &str, id: &str) -> String {
        format!(
            r#"{{"Id":"c-{service}","Names":["/media-{service}-1"],"Image":"{image}","ImageID":"{id}","State":"running","Labels":{{"{COMPOSE_PROJECT_LABEL}":"media","{COMPOSE_SERVICE_LABEL}":"{service}"}}}}"#
        )
    }

    fn image(id: &str, digests: &[String]) -> String {
        format!(
            r#"{{"Id":"{id}","RepoDigests":{}}}"#,
            plugin_toolkit::serde_json::to_string(digests).unwrap()
        )
    }

    #[test]
    fn stack_status_reports_current_stale_and_unknown_services() {
        let containers = format!(
            "[{},{},{},{}]",
            container("web", "nginx:latest", "sha256:img-web"),
            container("web", "nginx:latest", "sha256:img-web"),
            container("tv", "lscr.io/linuxserver/sonarr:latest", "sha256:img-tv"),
            container("priv", "ghcr.io/org/private:1", "sha256:img-priv"),
        );
        let e = FakeEngine::routed(vec![
            Route::new("GET", "/containers/json", 200, containers),
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
                index_body(INDEX),
            ),
            Route::new(
                "GET",
                "/distribution/ghcr.io/org/private:1/json",
                401,
                r#"{"message":"unauthorized"}"#,
            ),
        ]);
        let mut cache = HashMap::new();
        let s = plugin_toolkit::reactor::block_on(stack_status(
            &e.client(),
            "media",
            "media",
            &mut cache,
        ));
        assert_eq!(s.error, None);
        let by = |n: &str| s.services.iter().find(|x| x.service == n).unwrap().clone();
        assert_eq!(s.services.len(), 3);
        let web = by("web");
        assert_eq!(web.update_available, Some(false));
        assert_eq!(web.local_digest.as_deref(), Some(INDEX));
        let tv = by("tv");
        assert_eq!(tv.update_available, Some(true));
        assert_eq!(tv.local_digest.as_deref(), Some(OLD));
        assert_eq!(tv.remote_digest.as_deref(), Some(INDEX));
        let private = by("priv");
        assert_eq!(private.update_available, None);
        assert_eq!(private.remote_digest, None);
        assert!(private.error.is_some());
        let targets = e.targets("GET");
        assert!(
            targets
                .iter()
                .any(|t| t.contains("status") && t.contains("com.docker.compose.project=media")),
            "{targets:?}"
        );
        assert!(e.paths("POST").is_empty() && e.paths("DELETE").is_empty());
    }
}
