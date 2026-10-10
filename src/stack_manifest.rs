//! `docker.stack_manifest` — what moving a compose stack to another docker
//! host has to carry: every image pinned by the exact digest the source runs,
//! since a `:latest` pull on the target would silently upgrade.
#![allow(clippy::disallowed_types)]

use std::collections::HashMap;

use bollard::Docker;
use bollard::models::{ContainerInspectResponse, ContainerSummary};
use bollard::query_parameters::{InspectContainerOptionsBuilder, ListContainersOptionsBuilder};
use plugin_toolkit::prelude::*;

use crate::prune::COMPOSE_PROJECT_LABEL;

const TOOL: &str = "docker.stack_manifest";
const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";

/// `ref` without its tag or digest: `ghcr.io/a/b:1` → `ghcr.io/a/b`.
pub fn repo_of(reference: &str) -> &str {
    let no_digest = reference.split('@').next().unwrap_or(reference);
    let slash = no_digest.rfind('/').map_or(0, |i| i + 1);
    match no_digest[slash..].rfind(':') {
        Some(i) => &no_digest[..slash + i],
        None => no_digest,
    }
}

/// `docker.io/library/redis`, `index.docker.io/library/redis` and `redis`
/// name the same repository.
fn normalize(repo: &str) -> &str {
    let r = repo
        .strip_prefix("docker.io/")
        .or_else(|| repo.strip_prefix("index.docker.io/"))
        .or_else(|| repo.strip_prefix("registry-1.docker.io/"))
        .unwrap_or(repo);
    r.strip_prefix("library/").unwrap_or(r)
}

/// `reference` pinned to the digest among `repo_digests` for its repository,
/// or why it cannot be.
pub fn pin(reference: &str, repo_digests: &[String]) -> std::result::Result<String, String> {
    if reference.contains("@sha256:") {
        return Ok(reference.to_owned());
    }
    let repo = normalize(repo_of(reference));
    let found = repo_digests
        .iter()
        .find(|d| normalize(repo_of(d)) == repo)
        .and_then(|d| d.split_once('@'));
    match found {
        Some((_, digest)) => Ok(format!("{}@{digest}", repo_of(reference))),
        None if repo_digests.is_empty() => {
            Err("no registry digest: built locally or never pulled".into())
        }
        None => Err(format!(
            "no digest for '{repo}' among {}",
            repo_digests.join(", ")
        )),
    }
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedImage {
    pub service: String,
    pub container: String,
    /// The reference the container was created from (`Config.Image`).
    pub image: String,
    /// `repo@sha256:…` to pull on the target, when it can be pinned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StackManifest {
    pub stack: String,
    pub images: Vec<PinnedImage>,
    /// `true` when every image is pinned.
    pub complete: bool,
}

/// What pinning needs from one `docker inspect` of a container.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StackContainer {
    pub name: String,
    pub service: String,
    /// `Config.Image`: the reference as written, not the resolved id.
    pub reference: String,
    /// `Image`: the id it runs.
    pub image_id: String,
}

impl StackContainer {
    pub fn from_inspect(c: &ContainerInspectResponse) -> Self {
        let config = c.config.as_ref();
        StackContainer {
            name: c
                .name
                .as_deref()
                .unwrap_or_default()
                .trim_start_matches('/')
                .to_owned(),
            service: config
                .and_then(|cfg| cfg.labels.as_ref())
                .and_then(|l| l.get(COMPOSE_SERVICE_LABEL))
                .cloned()
                .unwrap_or_default(),
            reference: config.and_then(|cfg| cfg.image.clone()).unwrap_or_default(),
            image_id: c.image.clone().unwrap_or_default(),
        }
    }
}

/// One entry per container, replicas included, sorted by service then name.
/// An image whose digests could not be read is that entry's problem.
pub fn images(
    containers: &[StackContainer],
    digests: &HashMap<String, std::result::Result<Vec<String>, String>>,
) -> Vec<PinnedImage> {
    let mut out: Vec<PinnedImage> = containers
        .iter()
        .map(|c| {
            let pinned = match digests.get(&c.image_id) {
                Some(Err(e)) => Err(e.clone()),
                found => pin(
                    &c.reference,
                    found
                        .and_then(|d| d.as_ref().ok())
                        .map_or(&[][..], Vec::as_slice),
                ),
            };
            let (pinned, problem) = match pinned {
                Ok(p) => (Some(p), None),
                Err(e) => (None, Some(e)),
            };
            PinnedImage {
                service: c.service.clone(),
                container: c.name.clone(),
                image: c.reference.clone(),
                pinned,
                problem,
            }
        })
        .collect();
    out.sort_by(|a, b| (&a.service, &a.container).cmp(&(&b.service, &b.container)));
    out
}

async fn containers_of(docker: &Docker, stack: &str) -> Result<Vec<ContainerSummary>> {
    let filters = HashMap::from([(
        "label".to_string(),
        vec![format!("{COMPOSE_PROJECT_LABEL}={stack}")],
    )]);
    docker
        .list_containers(Some(
            ListContainersOptionsBuilder::new()
                .all(true)
                .filters(&filters)
                .build(),
        ))
        .await
        .map_err(|e| anyhow!("list containers: {e}"))
}

pub async fn collect(docker: &Docker, stack: &str) -> Result<StackManifest> {
    let summaries = containers_of(docker, stack).await?;
    if summaries.is_empty() {
        bail!("no containers carry {COMPOSE_PROJECT_LABEL}={stack}");
    }
    let mut containers = Vec::new();
    for id in summaries.iter().filter_map(|c| c.id.as_deref()) {
        let opts = InspectContainerOptionsBuilder::new().build();
        match docker.inspect_container(id, Some(opts)).await {
            Ok(c) => containers.push(StackContainer::from_inspect(&c)),
            // Removed since listing.
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(e) => bail!("inspect container {id}: {e}"),
        }
    }
    let mut digests = HashMap::new();
    for c in &containers {
        if digests.contains_key(&c.image_id) {
            continue;
        }
        let found = docker
            .inspect_image(&c.image_id)
            .await
            .map(|i| i.repo_digests.unwrap_or_default())
            .map_err(|e| format!("inspect image {}: {e}", c.image_id));
        digests.insert(c.image_id.clone(), found);
    }
    let images = images(&containers, &digests);
    Ok(StackManifest {
        stack: stack.to_owned(),
        complete: images.iter().all(|i| i.pinned.is_some()),
        images,
    })
}

#[orca_struct(args)]
pub struct DockerStackManifestArgs {
    /// Compose project name.
    #[arg(long)]
    pub stack: String,
}

/// **What moving a stack to another host must carry**: each service's image
/// pinned by the digest this host runs (`repo@sha256:…`), so the target
/// never pulls a newer `:latest`. Images with no registry digest (built
/// locally) are reported, not guessed. Read-only.
#[orca_tool(
    domain = "docker",
    verb = "stack_manifest",
    role = "admin",
    execute_gated = false
)]
async fn docker_stack_manifest(
    args: DockerStackManifestArgs,
    ctx: &ToolCtx,
) -> Result<StackManifest> {
    crate::execute::require_admin(TOOL, ctx)?;
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    collect(docker, &args.stack).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_of_strips_tag_and_digest_but_not_registry_port() {
        assert_eq!(repo_of("redis:7"), "redis");
        assert_eq!(repo_of("ghcr.io/a/b:1.2"), "ghcr.io/a/b");
        assert_eq!(repo_of("reg:5000/app"), "reg:5000/app");
        assert_eq!(repo_of("reg:5000/app:v1"), "reg:5000/app");
        assert_eq!(repo_of("app@sha256:abc"), "app");
    }

    #[test]
    fn pins_by_the_matching_repository_digest() {
        let d = vec![
            "docker.io/library/redis@sha256:aaa".to_string(),
            "mirror.local/redis@sha256:bbb".to_string(),
        ];
        assert_eq!(pin("redis:latest", &d).unwrap(), "redis@sha256:aaa");
        assert_eq!(
            pin("mirror.local/redis:7", &d).unwrap(),
            "mirror.local/redis@sha256:bbb"
        );
        assert_eq!(pin("app@sha256:ccc", &[]).unwrap(), "app@sha256:ccc");
    }

    #[test]
    fn a_local_build_cannot_be_pinned() {
        assert!(pin("myapp:dev", &[]).unwrap_err().contains("built locally"));
        assert!(pin("other:1", &["redis@sha256:a".into()]).is_err());
    }

    fn container(name: &str, service: &str, reference: &str, id: &str) -> StackContainer {
        StackContainer {
            name: name.into(),
            service: service.into(),
            reference: reference.into(),
            image_id: id.into(),
        }
    }

    #[test]
    fn every_replica_gets_an_entry() {
        let cs = [
            container("web-2", "web", "nginx:latest", "sha256:1"),
            container("web-1", "web", "nginx:latest", "sha256:1"),
            container("app-1", "app", "app:dev", "sha256:2"),
            container("db-1", "db", "postgres:16", "sha256:3"),
        ];
        let digests = HashMap::from([
            (
                "sha256:1".to_string(),
                Ok(vec!["nginx@sha256:n".to_string()]),
            ),
            (
                "sha256:3".to_string(),
                Err("inspect image sha256:3: gone".to_string()),
            ),
        ]);
        let got = images(&cs, &digests);
        let names: Vec<&str> = got.iter().map(|i| i.container.as_str()).collect();
        assert_eq!(names, ["app-1", "db-1", "web-1", "web-2"]);
        assert!(got[0].problem.as_deref().unwrap().contains("built locally"));
        assert_eq!(
            got[1].problem.as_deref(),
            Some("inspect image sha256:3: gone"),
            "one failed image does not abort the rest"
        );
        assert_eq!(got[3].pinned.as_deref(), Some("nginx@sha256:n"));
    }

    #[test]
    fn the_reference_comes_from_config_image_not_the_resolved_id() {
        use bollard::models::ContainerConfig;
        let c = ContainerInspectResponse {
            name: Some("/media-web-1".into()),
            image: Some("sha256:abc".into()),
            config: Some(ContainerConfig {
                image: Some("nginx:1.27".into()),
                labels: Some(HashMap::from([(
                    COMPOSE_SERVICE_LABEL.to_string(),
                    "web".to_string(),
                )])),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            StackContainer::from_inspect(&c),
            container("media-web-1", "web", "nginx:1.27", "sha256:abc")
        );
    }

    #[test]
    fn index_docker_io_names_the_hub() {
        let d = vec!["index.docker.io/library/redis@sha256:a".to_string()];
        assert_eq!(pin("redis:7", &d).unwrap(), "redis@sha256:a");
        assert_eq!(
            pin("docker.io/library/redis:7", &d).unwrap(),
            "docker.io/library/redis@sha256:a"
        );
    }

    #[test]
    fn refuses_a_non_admin_caller() {
        for ctx in crate::test_support::non_admins() {
            let err = plugin_toolkit::reactor::block_on(docker_stack_manifest(
                DockerStackManifestArgs { stack: "s".into() },
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
        }
    }
}
