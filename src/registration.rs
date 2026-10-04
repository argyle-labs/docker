//! Domain-backend wrappers for the hybrid export.
//!
//! docker contributes four typed facets to orca's `contract` registries,
//! wired up via the toolkit's `Plugin` builder in `main.rs`:
//!
//! - `topology` ([`DockerTopology`]) — one [`TopologyClaim`] per container with
//!   its network MACs, for fleet parent-host nesting.
//! - `container_runtime` ([`DockerAdapter`]) — the bollard-backed
//!   [`RuntimeAdapter`] that drives orca's self-healing reconciler. This is the
//!   seam that keeps bollard in the plugin and out of orca core.
//! - `unit` ([`DockerUnitProvider`]) — the declarative container/stack unit
//!   surface.
//! - `subprocess_env` ([`DockerEnv`]) — exposes `DOCKER_HOST` for the active
//!   runtime to every subprocess orca spawns (MCP servers).

use std::sync::OnceLock;

use plugin_toolkit::contract::subprocess_env::{EnvProvider, EnvVar};
use plugin_toolkit::contract::topology::{TopologyClaim, TopologyCollector};

use crate::runtime_adapter::DockerAdapter;
use crate::unit_provider::DockerUnitProvider;

/// Process-wide docker adapter used to back the [`DockerUnitProvider`], which
/// borrows a `'static` adapter. The `container_runtime` facet gets its own
/// owned adapter (construction does no I/O; the bollard client is lazy).
pub(crate) fn adapter() -> &'static DockerAdapter {
    static ADAPTER: OnceLock<DockerAdapter> = OnceLock::new();
    ADAPTER.get_or_init(DockerAdapter::new)
}

/// Build the `unit` facet provider, borrowing the process-wide adapter.
pub fn unit_provider() -> DockerUnitProvider {
    DockerUnitProvider::new(adapter())
}

/// `topology` facet: wraps the free [`crate::topology::collect_claims`].
pub struct DockerTopology;

#[plugin_toolkit::async_trait::async_trait]
impl TopologyCollector for DockerTopology {
    fn name(&self) -> &str {
        "docker"
    }
    async fn collect_claims(&self) -> plugin_toolkit::anyhow::Result<Vec<TopologyClaim>> {
        crate::topology::collect_claims().await
    }
}

/// `subprocess_env` facet: expose `DOCKER_HOST`, resolved through the full
/// fallback chain (registered runtime → colima → well-known socket). This is
/// what lets an unconfigured Unraid host — where no runtime is registered but
/// the engine listens on the standard socket — still inject a concrete
/// `DOCKER_HOST` into a docker-based MCP subprocess. Returns an empty set only
/// when nothing is discoverable (the subprocess then uses its default).
pub struct DockerEnv;

impl EnvProvider for DockerEnv {
    fn name(&self) -> &str {
        "docker"
    }
    fn env(&self) -> plugin_toolkit::anyhow::Result<Vec<EnvVar>> {
        Ok(match crate::tools::resolve_docker_host() {
            Some(host) => vec![EnvVar {
                key: "DOCKER_HOST".to_string(),
                value: host,
            }],
            None => Vec::new(),
        })
    }
}

/// The plugin-scoped SQL schema orca declares in the Hello handshake: the
/// `docker.stacks` table (physical `plug__docker__stacks`), mirroring
/// [`crate::stacks::StackRow`] with `name` as the natural key, and
/// `docker.volume_policies`, mirroring
/// [`crate::volume_coverage::VolumePolicy`] keyed `<stack>/<volume>`.
pub fn schema_json() -> String {
    r#"{"namespace":"docker","tables":[{"table":"stacks","columns":[{"name":"name","sql_type":"TEXT","not_null":true,"primary_key":true},{"name":"dir","sql_type":"TEXT","not_null":true},{"name":"file","sql_type":"TEXT","not_null":true},{"name":"enabled","sql_type":"INTEGER","not_null":true,"default":"1"}]},{"table":"volume_policies","columns":[{"name":"id","sql_type":"TEXT","not_null":true,"primary_key":true},{"name":"stack","sql_type":"TEXT","not_null":true},{"name":"volume","sql_type":"TEXT","not_null":true},{"name":"strategy","sql_type":"TEXT","not_null":true},{"name":"service","sql_type":"TEXT"},{"name":"command","sql_type":"TEXT"}]}]}"#.to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn schema_declares_both_tables() {
        let v: plugin_toolkit::serde_json::Value =
            plugin_toolkit::serde_json::from_str(&super::schema_json()).unwrap();
        let tables: Vec<_> = v["tables"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["table"].as_str().unwrap())
            .collect();
        assert_eq!(tables, vec!["stacks", "volume_policies"]);
    }
}
