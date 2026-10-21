//! `docker.manageability_audit` — the container analogue of the VM guest-agent
//! rule: every container orca runs must declare a healthcheck, carry
//! compose/orca provenance, and pin its timezone. Containers missing any of
//! these look fine from outside while being unmanageable.
#![allow(clippy::disallowed_types)]

use std::collections::HashMap;

use bollard::Docker;
use bollard::exec::{CreateExecOptions, StartExecOptions};
use bollard::models::ContainerInspectResponse;
use bollard::query_parameters::{InspectContainerOptionsBuilder, ListContainersOptionsBuilder};
use plugin_toolkit::prelude::*;

use crate::labels;
use crate::prune::COMPOSE_PROJECT_LABEL;

const TOOL: &str = "docker.manageability_audit";
pub const GAP_HEALTHCHECK: &str = "healthcheck";
pub const GAP_PROVENANCE: &str = "provenance";
pub const GAP_TZ: &str = "tz";
pub const GAP_EXEC: &str = "exec";
/// Tried in order; the first that exits 0 proves an exec path. Distroless
/// images have no shell, so a bare `true` is the fallback.
const EXEC_PROBES: &[&[&str]] = &[&["sh", "-c", ":"], &["true"]];

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerContract {
    pub container: String,
    /// Compose project or `orca.stack`, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Unmet parts of the contract: `healthcheck`, `provenance`, `tz`, and
    /// with `execProbe`, `exec`.
    pub gaps: Vec<String>,
}

/// An empty test inherits from the image, which docker has already merged
/// into the container's config; `NONE` disables it.
fn has_healthcheck(c: &ContainerInspectResponse) -> bool {
    c.config
        .as_ref()
        .and_then(|cfg| cfg.healthcheck.as_ref())
        .and_then(|h| h.test.as_ref())
        .and_then(|t| t.first())
        .is_some_and(|kind| kind != "NONE")
}

fn has_tz(c: &ContainerInspectResponse) -> bool {
    let env = c.config.as_ref().and_then(|cfg| cfg.env.as_ref());
    let tz_env = env
        .into_iter()
        .flatten()
        .any(|kv| kv.strip_prefix("TZ=").is_some_and(|v| !v.is_empty()));
    let localtime = c
        .mounts
        .iter()
        .flatten()
        .any(|m| m.destination.as_deref() == Some("/etc/localtime"));
    tz_env || localtime
}

pub fn judge(c: &ContainerInspectResponse) -> ContainerContract {
    let labels: HashMap<String, String> = c
        .config
        .as_ref()
        .and_then(|cfg| cfg.labels.clone())
        .unwrap_or_default();
    let owner = labels
        .get(labels::STACK)
        .or_else(|| labels.get(COMPOSE_PROJECT_LABEL))
        .filter(|s| !s.is_empty())
        .cloned();
    let mut gaps = Vec::new();
    if !has_healthcheck(c) {
        gaps.push(GAP_HEALTHCHECK.to_owned());
    }
    if owner.is_none() {
        gaps.push(GAP_PROVENANCE.to_owned());
    }
    if !has_tz(c) {
        gaps.push(GAP_TZ.to_owned());
    }
    ContainerContract {
        container: c
            .name
            .as_deref()
            .unwrap_or_default()
            .trim_start_matches('/')
            .to_owned(),
        owner,
        gaps,
    }
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManageabilityAudit {
    /// Containers with at least one gap.
    pub failing: Vec<ContainerContract>,
    pub checked: usize,
    /// Containers whose exec probe did not finish within the call's budget;
    /// their other gaps are still in `failing`. Re-run to probe them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unprobed: Vec<String>,
}

pub fn audit(containers: &[ContainerInspectResponse]) -> ManageabilityAudit {
    report(containers.iter().map(judge), containers.len(), Vec::new())
}

fn report(
    judged: impl Iterator<Item = ContainerContract>,
    checked: usize,
    mut unprobed: Vec<String>,
) -> ManageabilityAudit {
    let mut failing: Vec<ContainerContract> = judged.filter(|c| !c.gaps.is_empty()).collect();
    failing.sort_by(|a, b| a.container.cmp(&b.container));
    unprobed.sort();
    ManageabilityAudit {
        failing,
        checked,
        unprobed,
    }
}

pub async fn inspect_running(docker: &Docker) -> Result<Vec<ContainerInspectResponse>> {
    let list = docker
        .list_containers(Some(ListContainersOptionsBuilder::new().build()))
        .await
        .map_err(|e| anyhow!("list containers: {e}"))?;
    let mut out = Vec::new();
    for id in list.iter().filter_map(|c| c.id.as_deref()) {
        let opts = InspectContainerOptionsBuilder::new().build();
        out.push(
            docker
                .inspect_container(id, Some(opts))
                .await
                .map_err(|e| anyhow!("inspect container {id}: {e}"))?,
        );
    }
    Ok(out)
}

/// Record the exec probe's verdict on `contract`.
pub fn with_exec(mut contract: ContainerContract, exec_ok: bool) -> ContainerContract {
    if !exec_ok {
        contract.gaps.push(GAP_EXEC.to_owned());
    }
    contract
}

/// Polls of one probe's exit status (100 ms apart).
const EXEC_POLLS: u32 = 100;
/// Stays under orca's 35 s plugin call timeout so a few wedged containers
/// cost their own probe, not the whole audit.
const PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(25);
const PROBE_CONCURRENCY: usize = 8;

/// The probe's exit status, read through the Engine API exec endpoints.
async fn probe_succeeds(docker: &Docker, id: &str, cmd: &[&str]) -> bool {
    let Ok(exec) = docker
        .create_exec(
            id,
            CreateExecOptions {
                cmd: Some(cmd.iter().map(|s| (*s).to_owned()).collect()),
                ..Default::default()
            },
        )
        .await
    else {
        return false;
    };
    let detached = StartExecOptions {
        detach: true,
        ..Default::default()
    };
    if docker.start_exec(&exec.id, Some(detached)).await.is_err() {
        return false;
    }
    matches!(
        crate::exec::wait_exit(docker, &exec.id, EXEC_POLLS).await,
        Ok(Some(0))
    )
}

async fn exec_ok(docker: &Docker, id: &str) -> bool {
    for probe in EXEC_PROBES {
        if probe_succeeds(docker, id, probe).await {
            return true;
        }
    }
    false
}

/// Probes every container, `PROBE_CONCURRENCY` at a time, until `budget`
/// runs out. `None` marks a container whose probe did not finish in time.
async fn probe_all(
    docker: &Docker,
    containers: &[ContainerInspectResponse],
    budget: std::time::Duration,
) -> Vec<Option<bool>> {
    let deadline = std::time::Instant::now() + budget;
    let mut out = Vec::with_capacity(containers.len());
    for batch in containers.chunks(PROBE_CONCURRENCY) {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        out.extend(
            plugin_toolkit::reactor::join_all(batch.iter().map(|c| {
                let id = c.id.as_deref().unwrap_or_default();
                plugin_toolkit::time::timeout(left, exec_ok(docker, id))
            }))
            .await,
        );
    }
    out
}

#[orca_struct(args)]
pub struct DockerManageabilityAuditArgs {
    /// Also run a no-op (`sh -c :`, else `true`) inside each container to
    /// prove orca can enter it.
    #[arg(long)]
    #[serde(default)]
    pub exec_probe: bool,
}

/// **Audit the container manageability contract**: every running container
/// must declare a healthcheck (its own or its image's), carry compose or
/// `orca.stack` provenance, and pin its timezone (`TZ` or an
/// `/etc/localtime` bind). With `exec_probe`, also proves an exec path by
/// running a no-op inside each, concurrently within a 25 s budget; containers
/// not probed in time are listed in `unprobed`. Lists containers with gaps.
/// Changes nothing; `execProbe` only starts a short-lived process in each
/// container. Admin.
#[orca_tool(
    domain = "docker",
    verb = "manageability_audit",
    role = "admin",
    execute_gated = false
)]
async fn docker_manageability_audit(
    args: DockerManageabilityAuditArgs,
    ctx: &ToolCtx,
) -> Result<ManageabilityAudit> {
    crate::execute::require_admin(TOOL, ctx)?;
    let docker = &crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    let containers = inspect_running(docker).await?;
    if !args.exec_probe {
        return Ok(audit(&containers));
    }
    let probed = probe_all(docker, &containers, PROBE_BUDGET).await;
    let mut unprobed = Vec::new();
    let judged: Vec<ContainerContract> = containers
        .iter()
        .zip(probed)
        .map(|(c, ok)| match ok {
            Some(ok) => with_exec(judge(c), ok),
            None => {
                let j = judge(c);
                unprobed.push(j.container.clone());
                j
            }
        })
        .collect();
    Ok(report(judged.into_iter(), containers.len(), unprobed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{ContainerConfig, HealthConfig, MountPoint};

    fn container(
        name: &str,
        health: Option<&[&str]>,
        labels: &[(&str, &str)],
        env: &[&str],
    ) -> ContainerInspectResponse {
        ContainerInspectResponse {
            name: Some(format!("/{name}")),
            config: Some(ContainerConfig {
                healthcheck: health.map(|t| HealthConfig {
                    test: Some(t.iter().map(|s| s.to_string()).collect()),
                    ..Default::default()
                }),
                labels: Some(
                    labels
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                ),
                env: Some(env.iter().map(|s| s.to_string()).collect()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_compliant_container_has_no_gaps() {
        let c = container(
            "web",
            Some(&["CMD", "curl", "-f", "localhost"]),
            &[(COMPOSE_PROJECT_LABEL, "media")],
            &["TZ=Etc/UTC"],
        );
        let got = judge(&c);
        assert!(got.gaps.is_empty(), "{got:?}");
        assert_eq!(got.container, "web");
        assert_eq!(got.owner.as_deref(), Some("media"));
    }

    #[test]
    fn missing_pieces_are_named() {
        let c = container("bare", None, &[], &["TZ="]);
        assert_eq!(judge(&c).gaps, [GAP_HEALTHCHECK, GAP_PROVENANCE, GAP_TZ]);
        let disabled = container("off", Some(&["NONE"]), &[(labels::STACK, "s")], &["TZ=UTC"]);
        assert_eq!(judge(&disabled).gaps, [GAP_HEALTHCHECK]);
    }

    #[test]
    fn a_localtime_bind_pins_the_timezone() {
        let mut c = container(
            "t",
            Some(&["CMD-SHELL", "true"]),
            &[(labels::STACK, "s")],
            &[],
        );
        c.mounts = Some(vec![MountPoint {
            destination: Some("/etc/localtime".into()),
            ..Default::default()
        }]);
        assert!(judge(&c).gaps.is_empty());
    }

    #[test]
    fn audit_lists_only_failing_sorted() {
        let ok = container(
            "a",
            Some(&["CMD", "x"]),
            &[(labels::STACK, "s")],
            &["TZ=UTC"],
        );
        let z = container("z", None, &[], &[]);
        let b = container("b", None, &[(labels::STACK, "s")], &["TZ=UTC"]);
        let got = audit(&[z, ok, b]);
        assert_eq!(got.checked, 3);
        let names: Vec<&str> = got.failing.iter().map(|c| c.container.as_str()).collect();
        assert_eq!(names, ["b", "z"]);
    }

    #[test]
    fn refuses_a_non_admin_caller() {
        for ctx in crate::test_support::non_admins() {
            let err = plugin_toolkit::reactor::block_on(docker_manageability_audit(
                DockerManageabilityAuditArgs { exec_probe: false },
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
        }
    }

    #[test]
    fn a_failed_exec_probe_is_a_gap() {
        let ok = container(
            "a",
            Some(&["CMD", "x"]),
            &[(labels::STACK, "s")],
            &["TZ=UTC"],
        );
        assert!(with_exec(judge(&ok), true).gaps.is_empty());
        assert_eq!(with_exec(judge(&ok), false).gaps, [GAP_EXEC]);
    }

    fn exec_engine(exit_code: i64) -> crate::test_engine::FakeEngine {
        use crate::test_engine::{FakeEngine, Route};
        FakeEngine::routed(vec![
            Route::new("POST", "/containers/c1/exec", 201, r#"{"Id":"e1"}"#),
            Route::new("POST", "/exec/e1/start", 200, ""),
            Route::new(
                "GET",
                "/exec/e1/json",
                200,
                format!(r#"{{"Running":false,"ExitCode":{exit_code}}}"#),
            ),
        ])
    }

    #[test]
    fn the_exec_probe_reads_the_exit_code_through_the_engine() {
        let ok = exec_engine(0);
        assert!(plugin_toolkit::reactor::block_on(exec_ok(
            &ok.client(),
            "c1"
        )));
        let failed = exec_engine(126);
        assert!(!plugin_toolkit::reactor::block_on(exec_ok(
            &failed.client(),
            "c1"
        )));
        assert_eq!(
            failed
                .paths("POST")
                .iter()
                .filter(|p| p.ends_with("/containers/c1/exec"))
                .count(),
            EXEC_PROBES.len(),
            "every fallback probe is tried"
        );
    }

    #[test]
    fn a_wedged_probe_is_unprobed_not_a_gap() {
        use crate::test_engine::{FakeEngine, Route};
        let wedged = FakeEngine::routed(vec![
            Route::new("POST", "/containers/c1/exec", 201, r#"{"Id":"e1"}"#),
            Route::new("POST", "/exec/e1/start", 200, ""),
            Route::new("GET", "/exec/e1/json", 200, r#"{"Running":true}"#),
        ]);
        let mut c = container("c1", None, &[], &[]);
        c.id = Some("c1".into());
        let got = plugin_toolkit::reactor::block_on(probe_all(
            &wedged.client(),
            std::slice::from_ref(&c),
            std::time::Duration::from_millis(300),
        ));
        assert_eq!(got, [None]);
        let audit = report(std::iter::once(judge(&c)), 1, vec!["c1".into()]);
        assert_eq!(audit.unprobed, ["c1"]);
        assert!(!audit.failing[0].gaps.contains(&GAP_EXEC.to_owned()));
    }
}
