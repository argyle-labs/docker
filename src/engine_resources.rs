//! `docker.engine_resources` — every volume and network name on this engine,
//! so a plugin labelling compose resources (dockge) can tell which already
//! exist before claiming them.
#![allow(clippy::disallowed_types)]

use bollard::Docker;
use bollard::query_parameters::{ListNetworksOptions, ListVolumesOptions};
use plugin_toolkit::prelude::*;

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineResources {
    /// Sorted.
    pub volumes: Vec<String>,
    /// Sorted, built-in networks included.
    pub networks: Vec<String>,
}

pub fn sorted(mut volumes: Vec<String>, mut networks: Vec<String>) -> EngineResources {
    volumes.sort();
    volumes.dedup();
    networks.sort();
    networks.dedup();
    EngineResources { volumes, networks }
}

pub async fn collect(docker: &Docker) -> Result<EngineResources> {
    let volumes = docker
        .list_volumes(None::<ListVolumesOptions>)
        .await
        .map_err(|e| anyhow!("list volumes: {e}"))?
        .volumes
        .unwrap_or_default()
        .into_iter()
        .map(|v| v.name)
        .collect();
    let networks = docker
        .list_networks(None::<ListNetworksOptions>)
        .await
        .map_err(|e| anyhow!("list networks: {e}"))?
        .into_iter()
        .filter_map(|n| n.name)
        .collect();
    Ok(sorted(volumes, networks))
}

#[orca_struct(args)]
pub struct DockerEngineResourcesArgs {}

/// **Every volume and network name on this docker engine.** Lets another
/// plugin (dockge's ownership labeller) check what exists before labelling
/// compose resources. Read-only; admin.
#[orca_tool(
    domain = "docker",
    verb = "engine_resources",
    role = "admin",
    execute_gated = false
)]
async fn docker_engine_resources(
    _args: DockerEngineResourcesArgs,
    ctx: &ToolCtx,
) -> Result<EngineResources> {
    crate::execute::require_admin("docker.engine_resources", ctx)?;
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    collect(docker).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json;

    #[test]
    fn sorted_dedups_and_serializes_as_dockge_reads_it() {
        let r = sorted(
            vec!["b".into(), "a".into(), "a".into()],
            vec!["bridge".into(), "media_default".into()],
        );
        assert_eq!(r.volumes, ["a", "b"]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["volumes"][0], "a");
        assert_eq!(v["networks"][1], "media_default");
    }

    #[test]
    fn refuses_a_non_admin_caller() {
        for ctx in crate::test_support::non_admins() {
            let err = plugin_toolkit::reactor::block_on(docker_engine_resources(
                DockerEngineResourcesArgs {},
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
        }
    }
}
