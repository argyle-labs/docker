//! Domain-backend registration for the hybrid export.
//!
//! docker contributes two backends to orca's `contract` registries, both routed
//! back through the FFI `invoke` under a distinct prefix:
//!
//! - `topology` (`docker.__topo.collect_claims`) — one [`TopologyClaim`] per
//!   container with its network MACs, for fleet parent-host nesting.
//! - `container_runtime` (`docker.__runtime.<op>`) — the bollard-backed
//!   [`RuntimeAdapter`] that drives orca's self-healing reconciler
//!   (list/inspect/start/stop/logs/exec/…). This is the seam that keeps bollard
//!   in the plugin and out of orca core.
//!
//! [`backend_dispatch`] answers those calls; the toolkit's hybrid `invoke`
//! routes everything else to the `docker.` tool surface.

use std::sync::OnceLock;

use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::backend_def::{topology_backend_def, unit_backend_def};
use plugin_toolkit::containers::{self, RuntimeAdapter};
use plugin_toolkit::contract::unit::{self, UnitProvider};
use plugin_toolkit::reactor;
use plugin_toolkit::serde_json;

use crate::runtime_adapter::DockerAdapter;
use crate::unit_provider::DockerUnitProvider;

const TOPO_PREFIX: &str = "docker.__topo";
const RUNTIME_PREFIX: &str = "docker.__runtime";
const UNIT_PREFIX: &str = "docker.__unit";
const ENV_PREFIX: &str = "docker.__env";

fn adapter() -> &'static DockerAdapter {
    static ADAPTER: OnceLock<DockerAdapter> = OnceLock::new();
    ADAPTER.get_or_init(DockerAdapter::new)
}

fn unit_provider() -> &'static DockerUnitProvider {
    static PROVIDER: OnceLock<DockerUnitProvider> = OnceLock::new();
    PROVIDER.get_or_init(|| DockerUnitProvider::new(adapter()))
}

/// Backend descriptors this plugin advertises: a topology collector and a
/// container-runtime adapter, each routed back under its own prefix. The docker
/// adapter does not (yet) support in-place wedge recovery, so it advertises no
/// `wedge_recover` capability — the reconciler escalates instead.
pub fn backends_json() -> String {
    let defs = vec![
        // Topology + unit descriptors are derived from the live surface via the
        // toolkit's export helpers (the descriptor orca registers is exactly the
        // backend's own — advertised kinds/verbs stay in sync automatically).
        topology_backend_def("docker", TOPO_PREFIX),
        BackendDef {
            domain: "container_runtime".to_string(),
            name: "docker".to_string(),
            kind: "docker".to_string(),
            invoke_prefix: RUNTIME_PREFIX.to_string(),
            ..Default::default()
        },
        unit_backend_def(unit_provider() as &dyn UnitProvider, UNIT_PREFIX),
        // subprocess_env: expose DOCKER_HOST for the active runtime to every
        // subprocess orca spawns (MCP servers), via the generic seam — orca core
        // no longer knows about docker.
        BackendDef {
            domain: "subprocess_env".to_string(),
            name: "docker".to_string(),
            kind: "docker".to_string(),
            invoke_prefix: ENV_PREFIX.to_string(),
            ..Default::default()
        },
    ];
    serde_json::to_string(&defs).unwrap_or_else(|_| "[]".to_string())
}

/// The plugin-scoped SQL schema orca declares in the Hello handshake: the
/// `docker.stacks` table (physical `plug__docker__stacks`). Mirrors the
/// [`crate::stacks::StackRow`] columns; `name` is the natural key.
pub fn schema_json() -> String {
    r#"{"namespace":"docker","tables":[{"table":"stacks","columns":[{"name":"name","sql_type":"TEXT","not_null":true,"primary_key":true},{"name":"dir","sql_type":"TEXT","not_null":true},{"name":"file","sql_type":"TEXT","not_null":true},{"name":"enabled","sql_type":"INTEGER","not_null":true,"default":"1"}]}]}"#.to_string()
}

/// Handle the loader's `docker.__topo.*` / `docker.__runtime.*` backend calls.
/// Returns `None` for anything else so the toolkit falls through to the
/// `docker.` tool surface. Async work runs on the toolkit's shared reactor via
/// `reactor::block_on` — the sync bridge the subprocess `serve` loop calls.
pub fn backend_dispatch(name: &str, args_json: &str) -> Option<Result<String, String>> {
    if let Some(op) = name
        .strip_prefix(TOPO_PREFIX)
        .and_then(|s| s.strip_prefix('.'))
    {
        return Some(dispatch_topology(op));
    }
    if let Some(op) = name
        .strip_prefix(RUNTIME_PREFIX)
        .and_then(|s| s.strip_prefix('.'))
    {
        let out = reactor::block_on(containers::dispatch_op(
            adapter() as &dyn RuntimeAdapter,
            op,
            args_json,
        ));
        return Some(out);
    }
    if let Some(op) = name
        .strip_prefix(UNIT_PREFIX)
        .and_then(|s| s.strip_prefix('.'))
    {
        return Some(reactor::block_on(unit::dispatch_op(
            unit_provider() as &dyn UnitProvider,
            op,
            args_json,
        )));
    }
    if let Some(op) = name
        .strip_prefix(ENV_PREFIX)
        .and_then(|s| s.strip_prefix('.'))
    {
        return Some(dispatch_env(op));
    }
    None
}

/// Answer the `subprocess_env` seam's `env` op: expose `DOCKER_HOST`, resolved
/// through the full fallback chain (registered runtime → colima → well-known
/// socket). This is what lets an unconfigured Unraid host — where no runtime is
/// registered but the engine listens on the standard socket — still inject a
/// concrete `DOCKER_HOST` into a docker-based MCP subprocess. Returns an empty
/// set only when nothing is discoverable (the subprocess then uses its default).
fn dispatch_env(op: &str) -> Result<String, String> {
    use plugin_toolkit::contract::subprocess_env::{ENV_OP, EnvVar};
    if op != ENV_OP {
        return Err(format!("unknown subprocess_env op '{op}'"));
    }
    let vars: Vec<EnvVar> = match crate::tools::resolve_docker_host() {
        Some(host) => vec![EnvVar {
            key: "DOCKER_HOST".to_string(),
            value: host,
        }],
        None => Vec::new(),
    };
    serde_json::to_string(&vars).map_err(|e| e.to_string())
}

fn dispatch_topology(op: &str) -> Result<String, String> {
    match op {
        "collect_claims" => {
            let claims =
                reactor::block_on(crate::topology::collect_claims()).map_err(|e| e.to_string())?;
            serde_json::to_string(&claims).map_err(|e| e.to_string())
        }
        other => Err(format!("unknown topology op: {other}")),
    }
}
