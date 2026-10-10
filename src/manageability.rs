//! `docker.manageability_audit` — the container analogue of the VM guest-agent
//! rule: every container orca runs must declare a healthcheck, carry
//! compose/orca provenance, and pin its timezone. Containers missing any of
//! these look fine from outside while being unmanageable.
#![allow(clippy::disallowed_types)]

use std::collections::HashMap;

use bollard::Docker;
use bollard::models::ContainerInspectResponse;
use bollard::query_parameters::{InspectContainerOptionsBuilder, ListContainersOptionsBuilder};
use plugin_toolkit::prelude::*;

use crate::labels;
use crate::prune::COMPOSE_PROJECT_LABEL;

const TOOL: &str = "docker.manageability_audit";
pub const GAP_HEALTHCHECK: &str = "healthcheck";
pub const GAP_PROVENANCE: &str = "provenance";
pub const GAP_TZ: &str = "tz";

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerContract {
    pub container: String,
    /// Compose project or `orca.stack`, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Unmet parts of the contract: `healthcheck`, `provenance`, `tz`.
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
}

pub fn audit(containers: &[ContainerInspectResponse]) -> ManageabilityAudit {
    let mut failing: Vec<ContainerContract> = containers
        .iter()
        .map(judge)
        .filter(|c| !c.gaps.is_empty())
        .collect();
    failing.sort_by(|a, b| a.container.cmp(&b.container));
    ManageabilityAudit {
        failing,
        checked: containers.len(),
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

#[orca_struct(args)]
pub struct DockerManageabilityAuditArgs {}

/// **Audit the container manageability contract**: every running container
/// must declare a healthcheck (its own or its image's), carry compose or
/// `orca.stack` provenance, and pin its timezone (`TZ` or an
/// `/etc/localtime` bind). Lists containers with gaps. Read-only; admin.
#[orca_tool(
    domain = "docker",
    verb = "manageability_audit",
    role = "admin",
    execute_gated = false
)]
async fn docker_manageability_audit(
    _args: DockerManageabilityAuditArgs,
    ctx: &ToolCtx,
) -> Result<ManageabilityAudit> {
    crate::execute::require_admin(TOOL, ctx)?;
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    Ok(audit(&inspect_running(docker).await?))
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
                DockerManageabilityAuditArgs {},
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
        }
    }
}
