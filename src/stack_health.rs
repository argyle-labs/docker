//! `docker.stack_wait_healthy` — the last step of a stack move: after `up`
//! on the target, wait until every container of the stack is running and
//! passing its healthcheck, and report how long that took.
#![allow(clippy::disallowed_types)]

use std::time::{Duration, Instant};

use bollard::Docker;
use bollard::models::{ContainerInspectResponse, ContainerStateStatusEnum, HealthStatusEnum};
use bollard::query_parameters::InspectContainerOptionsBuilder;
use plugin_toolkit::prelude::*;

use crate::stack_manifest::{StackContainer, containers_of};

const TOOL: &str = "docker.stack_wait_healthy";
const POLL: Duration = Duration::from_secs(2);
const DEFAULT_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "camelCase")]
pub enum Readiness {
    /// Running, and healthy or declaring no healthcheck.
    Ready,
    /// Running or restarting, healthcheck not yet passed.
    Starting,
    Unhealthy,
    /// Created, exited, dead or paused.
    Stopped,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerReadiness {
    pub service: String,
    pub container: String,
    pub readiness: Readiness,
    /// Engine state, and health status when a healthcheck is declared.
    pub detail: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StackHealth {
    pub stack: String,
    /// Every container is `ready` (and there is at least one).
    pub ready: bool,
    /// Milliseconds from the call until `ready`, or until the timeout.
    pub waited_ms: u64,
    pub containers: Vec<ContainerReadiness>,
}

pub fn judge(c: &ContainerInspectResponse) -> ContainerReadiness {
    let meta = StackContainer::from_inspect(c);
    let state = c.state.as_ref();
    let status = state.and_then(|s| s.status);
    let health = state
        .and_then(|s| s.health.as_ref())
        .and_then(|h| h.status)
        .filter(|h| *h != HealthStatusEnum::EMPTY && *h != HealthStatusEnum::NONE);
    let readiness = match (status, health) {
        (Some(ContainerStateStatusEnum::RUNNING), None | Some(HealthStatusEnum::HEALTHY)) => {
            Readiness::Ready
        }
        (Some(ContainerStateStatusEnum::RUNNING), Some(HealthStatusEnum::UNHEALTHY)) => {
            Readiness::Unhealthy
        }
        (Some(ContainerStateStatusEnum::RUNNING | ContainerStateStatusEnum::RESTARTING), _) => {
            Readiness::Starting
        }
        _ => Readiness::Stopped,
    };
    let mut detail = status.map_or_else(|| "unknown".to_owned(), |s| s.to_string());
    if let Some(h) = health {
        detail = format!("{detail} ({h})");
    }
    ContainerReadiness {
        service: meta.service,
        container: meta.name,
        readiness,
        detail,
    }
}

async fn snapshot(docker: &Docker, stack: &str) -> Result<Vec<ContainerReadiness>> {
    let mut out = Vec::new();
    for id in containers_of(docker, stack)
        .await?
        .iter()
        .filter_map(|c| c.id.as_deref())
    {
        let opts = InspectContainerOptionsBuilder::new().build();
        match docker.inspect_container(id, Some(opts)).await {
            Ok(c) => out.push(judge(&c)),
            // Replaced since listing; the next poll sees its successor.
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(e) => bail!("inspect container {id}: {e}"),
        }
    }
    out.sort_by(|a, b| (&a.service, &a.container).cmp(&(&b.service, &b.container)));
    Ok(out)
}

pub async fn wait(docker: &Docker, stack: &str, timeout: Duration) -> Result<StackHealth> {
    let start = Instant::now();
    loop {
        let containers = snapshot(docker, stack).await?;
        let ready =
            !containers.is_empty() && containers.iter().all(|c| c.readiness == Readiness::Ready);
        let elapsed = start.elapsed();
        if ready || elapsed >= timeout {
            return Ok(StackHealth {
                stack: stack.to_owned(),
                ready,
                waited_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                containers,
            });
        }
        plugin_toolkit::time::sleep(POLL.min(timeout - elapsed)).await;
    }
}

#[orca_struct(args)]
pub struct DockerStackWaitHealthyArgs {
    /// Compose project name.
    #[arg(long)]
    pub stack: String,
    /// Give up after this many seconds (default 120).
    #[arg(long)]
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// **Wait for a stack to come up healthy**: polls every container of the
/// compose project until all are running and passing their healthcheck (or
/// declare none), or the timeout passes. Reports each container's readiness
/// and the time waited. Read-only.
#[orca_tool(
    domain = "docker",
    verb = "stack_wait_healthy",
    role = "admin",
    execute_gated = false
)]
async fn docker_stack_wait_healthy(
    args: DockerStackWaitHealthyArgs,
    ctx: &ToolCtx,
) -> Result<StackHealth> {
    crate::execute::require_admin(TOOL, ctx)?;
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    let secs = args.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    wait(docker, &args.stack, Duration::from_secs(secs)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};
    use plugin_toolkit::serde_json::{self, json};

    fn inspect(status: &str, health: Option<&str>) -> ContainerInspectResponse {
        let mut state = json!({ "Status": status });
        if let Some(h) = health {
            state["Health"] = json!({ "Status": h });
        }
        serde_json::from_value(json!({
            "Name": "/web-1",
            "State": state,
            "Config": { "Labels": { "com.docker.compose.service": "web" } },
        }))
        .unwrap()
    }

    #[test]
    fn readiness_follows_state_and_health() {
        let r = |s, h| judge(&inspect(s, h)).readiness;
        assert_eq!(r("running", None), Readiness::Ready);
        assert_eq!(r("running", Some("none")), Readiness::Ready);
        assert_eq!(r("running", Some("healthy")), Readiness::Ready);
        assert_eq!(r("running", Some("starting")), Readiness::Starting);
        assert_eq!(r("restarting", None), Readiness::Starting);
        assert_eq!(r("running", Some("unhealthy")), Readiness::Unhealthy);
        assert_eq!(r("exited", None), Readiness::Stopped);
        assert_eq!(r("created", Some("healthy")), Readiness::Stopped);
    }

    #[test]
    fn detail_names_service_container_and_health() {
        let c = judge(&inspect("running", Some("starting")));
        assert_eq!(c.service, "web");
        assert_eq!(c.container, "web-1");
        assert_eq!(c.detail, "running (starting)");
    }

    fn engine(health: &str) -> FakeEngine {
        FakeEngine::routed(vec![
            Route::new("GET", "/containers/json", 200, r#"[{"Id":"abc"}]"#),
            Route::new(
                "GET",
                "/containers/abc/json",
                200,
                json!({
                    "Name": "/web-1",
                    "State": { "Status": "running", "Health": { "Status": health } },
                    "Config": { "Labels": { "com.docker.compose.service": "web" } },
                })
                .to_string(),
            ),
        ])
    }

    #[test]
    fn a_healthy_stack_is_ready_on_the_first_poll() {
        let e = engine("healthy");
        let out =
            plugin_toolkit::reactor::block_on(wait(&e.client(), "app", Duration::from_secs(60)))
                .unwrap();
        assert!(out.ready);
        assert_eq!(out.containers.len(), 1);
        assert!(
            e.targets("GET")
                .iter()
                .any(|t| t.contains("com.docker.compose.project=app"))
        );
    }

    #[test]
    fn an_unhealthy_stack_times_out_not_ready() {
        let e = engine("unhealthy");
        let out =
            plugin_toolkit::reactor::block_on(wait(&e.client(), "app", Duration::ZERO)).unwrap();
        assert!(!out.ready);
        assert_eq!(out.containers[0].readiness, Readiness::Unhealthy);
    }

    #[test]
    fn a_stack_with_no_containers_is_not_ready() {
        let e = FakeEngine::routed(vec![Route::new("GET", "/containers/json", 200, "[]")]);
        let out =
            plugin_toolkit::reactor::block_on(wait(&e.client(), "app", Duration::ZERO)).unwrap();
        assert!(!out.ready);
        assert!(out.containers.is_empty());
    }

    #[test]
    fn refuses_a_non_admin_caller() {
        for ctx in crate::test_support::non_admins() {
            let err = plugin_toolkit::reactor::block_on(docker_stack_wait_healthy(
                DockerStackWaitHealthyArgs {
                    stack: "app".into(),
                    timeout_secs: None,
                },
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
        }
    }
}
