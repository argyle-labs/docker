//! `docker.container_delete` — remove one container by name. A running
//! container is refused unless `force`; the dry run inspects and reports the
//! exact container that would be removed.

use bollard::Docker;
use bollard::models::ContainerInspectResponse;
use bollard::query_parameters::{InspectContainerOptionsBuilder, RemoveContainerOptionsBuilder};
use plugin_toolkit::prelude::*;

const TOOL: &str = "docker.container_delete";

#[orca_struct(args)]
pub struct DockerContainerDeleteArgs {
    /// Container name (as `docker ps` shows it, without the leading `/`).
    #[arg(long)]
    pub name: String,
    /// Stop and remove a running container.
    #[arg(long)]
    #[serde(default)]
    pub force: bool,
    /// Return what would be removed and change nothing. Omitted, applies.
    #[arg(long)]
    #[serde(default, rename = "dryRun", alias = "dry_run")]
    pub dry_run: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerDeleteOutput {
    pub executed: bool,
    pub id: String,
    pub name: String,
    pub image: String,
    pub running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
    pub force: bool,
}

/// A container name as the engine accepts it: `[A-Za-z0-9][A-Za-z0-9_.-]*`,
/// an optional leading `/` dropped.
pub fn parse_name(raw: &str) -> Result<String> {
    let name = raw.trim().strip_prefix('/').unwrap_or(raw.trim());
    let mut chars = name.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !valid {
        bail!("'{raw}' is not a valid container name");
    }
    Ok(name.to_owned())
}

pub fn describe(c: &ContainerInspectResponse, force: bool) -> ContainerDeleteOutput {
    let config = c.config.as_ref();
    ContainerDeleteOutput {
        executed: false,
        id: c.id.clone().unwrap_or_default(),
        name: c
            .name
            .as_deref()
            .map(|n| n.trim_start_matches('/').to_owned())
            .unwrap_or_default(),
        image: config.and_then(|c| c.image.clone()).unwrap_or_default(),
        running: c.state.as_ref().and_then(|s| s.running).unwrap_or(false),
        stack: config
            .and_then(|c| c.labels.as_ref())
            .and_then(|l| l.get("com.docker.compose.project").cloned()),
        force,
    }
}

pub async fn plan(
    docker: &Docker,
    args: &DockerContainerDeleteArgs,
) -> Result<ContainerDeleteOutput> {
    let name = parse_name(&args.name)?;
    let opts = InspectContainerOptionsBuilder::new().build();
    let c = match docker.inspect_container(&name, Some(opts)).await {
        Ok(c) => c,
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => bail!("no container named '{name}'"),
        Err(e) => bail!("inspect container {name}: {e}"),
    };
    let out = describe(&c, args.force);
    if out.name != name {
        bail!(
            "'{name}' resolves to container '{}'; pass its exact name",
            out.name
        );
    }
    if out.running && !args.force {
        bail!("container '{name}' is running; stop it first or pass force");
    }
    Ok(out)
}

pub async fn apply(
    docker: &Docker,
    args: &DockerContainerDeleteArgs,
) -> Result<ContainerDeleteOutput> {
    let mut out = plan(docker, args).await?;
    if args.dry_run {
        return Ok(out);
    }
    let opts = RemoveContainerOptionsBuilder::new()
        .force(args.force)
        .v(false)
        .build();
    docker
        .remove_container(&out.id, Some(opts))
        .await
        .map_err(|e| anyhow!("remove container {}: {e}", out.name))?;
    out.executed = true;
    Ok(out)
}

/// **Remove a container** by name. Refuses a running container unless
/// `force`; anonymous volumes are kept. `dryRun` reports the container that
/// would be removed.
#[orca_tool(
    domain = "docker",
    verb = "container_delete",
    role = "admin",
    execute_gated = false,
    dry_run_aware = true
)]
async fn docker_container_delete(
    args: DockerContainerDeleteArgs,
    ctx: &ToolCtx,
) -> Result<ContainerDeleteOutput> {
    let args = DockerContainerDeleteArgs {
        dry_run: args.dry_run || ctx.dry_run(),
        ..args
    };
    crate::execute::require_admin(TOOL, ctx)?;
    let docker = &crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    apply(docker, &args).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};
    use plugin_toolkit::serde_json::json;

    fn args(name: &str, force: bool, dry_run: bool) -> DockerContainerDeleteArgs {
        DockerContainerDeleteArgs {
            name: name.into(),
            force,
            dry_run,
        }
    }

    fn engine(running: bool) -> FakeEngine {
        FakeEngine::routed(vec![
            Route::new(
                "GET",
                "/containers/web-1/json",
                200,
                json!({
                    "Id": "abc123",
                    "Name": "/web-1",
                    "State": { "Running": running },
                    "Config": {
                        "Image": "nginx:1",
                        "Labels": { "com.docker.compose.project": "site" },
                    },
                })
                .to_string(),
            ),
            Route::new("DELETE", "/containers/abc123", 204, ""),
        ])
    }

    fn run(e: &FakeEngine, a: DockerContainerDeleteArgs) -> Result<ContainerDeleteOutput> {
        plugin_toolkit::reactor::block_on(apply(&e.client(), &a))
    }

    #[test]
    fn names_are_validated_the_same_for_dry_run_and_execute() {
        assert_eq!(parse_name("/web-1").unwrap(), "web-1");
        assert_eq!(parse_name("a.b_c-1").unwrap(), "a.b_c-1");
        for bad in ["", "-x", "a/b", "a b", "../x"] {
            assert!(parse_name(bad).is_err(), "{bad}");
        }
        let e = FakeEngine::routed(vec![]);
        for dry in [true, false] {
            assert!(run(&e, args("a b", false, dry)).is_err());
        }
        assert!(e.requests().is_empty());
    }

    #[test]
    fn a_dry_run_reports_the_container_and_removes_nothing() {
        let e = engine(false);
        let out = run(&e, args("web-1", false, true)).unwrap();
        assert!(!out.executed);
        assert_eq!(out.id, "abc123");
        assert_eq!(out.image, "nginx:1");
        assert_eq!(out.stack.as_deref(), Some("site"));
        assert!(e.paths("DELETE").is_empty());
    }

    #[test]
    fn a_running_container_is_refused_without_force_in_both_modes() {
        for dry in [true, false] {
            let e = engine(true);
            let err = run(&e, args("web-1", false, dry)).unwrap_err();
            assert!(err.to_string().contains("is running"), "{err}");
            assert!(e.paths("DELETE").is_empty());
        }
    }

    #[test]
    fn execute_removes_by_id_and_force_is_passed() {
        let e = engine(true);
        let out = run(&e, args("web-1", true, false)).unwrap();
        assert!(out.executed && out.running && out.force);
        let deletes = e.targets("DELETE");
        assert_eq!(deletes.len(), 1);
        assert!(deletes[0].contains("/containers/abc123"), "{deletes:?}");
        assert!(deletes[0].contains("force=true"), "{deletes:?}");
    }

    #[test]
    fn a_missing_container_is_an_error() {
        let e = FakeEngine::routed(vec![]);
        let err = run(&e, args("gone", false, true)).unwrap_err();
        assert!(
            err.to_string().contains("no container named 'gone'"),
            "{err}"
        );
    }

    #[test]
    fn refuses_a_non_admin_caller() {
        for ctx in crate::test_support::non_admins() {
            let err = plugin_toolkit::reactor::block_on(docker_container_delete(
                args("web-1", false, true),
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
        }
    }
}
