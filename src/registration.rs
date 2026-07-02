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
use plugin_toolkit::containers::{self, RuntimeAdapter};
use plugin_toolkit::contract::unit::{self as unit_domain, UnitProvider};
use plugin_toolkit::export::runtime;
use plugin_toolkit::serde_json;

use crate::runtime_adapter::DockerAdapter;
use crate::unit_provider::DockerUnitProvider;

const TOPO_PREFIX: &str = "docker.__topo";
const RUNTIME_PREFIX: &str = "docker.__runtime";
const UNIT_PREFIX: &str = "docker.__unit";

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
        BackendDef {
            domain: "topology".to_string(),
            name: "docker".to_string(),
            invoke_prefix: TOPO_PREFIX.to_string(),
            ..Default::default()
        },
        BackendDef {
            domain: "container_runtime".to_string(),
            name: "docker".to_string(),
            kind: "docker".to_string(),
            invoke_prefix: RUNTIME_PREFIX.to_string(),
            ..Default::default()
        },
        BackendDef {
            domain: "unit".to_string(),
            name: "docker".to_string(),
            invoke_prefix: UNIT_PREFIX.to_string(),
            ..Default::default()
        },
    ];
    serde_json::to_string(&defs).unwrap_or_else(|_| "[]".to_string())
}

/// Handle the loader's `docker.__topo.*` / `docker.__runtime.*` backend calls.
/// Returns `None` for anything else so the toolkit falls through to the
/// `docker.` tool surface. Async work runs on the toolkit's shared runtime
/// behind the synchronous FFI boundary.
pub fn backend_dispatch(name: &str, args_json: &str) -> Option<Result<String, String>> {
    if let Some(op) = name.strip_prefix(TOPO_PREFIX).and_then(|s| s.strip_prefix('.')) {
        return Some(dispatch_topology(op));
    }
    if let Some(op) = name
        .strip_prefix(RUNTIME_PREFIX)
        .and_then(|s| s.strip_prefix('.'))
    {
        let out = runtime().block_on(containers::dispatch_op(
            adapter() as &dyn RuntimeAdapter,
            op,
            args_json,
        ));
        return Some(out);
    }
    if let Some(op) = name.strip_prefix(UNIT_PREFIX).and_then(|s| s.strip_prefix('.')) {
        let out = runtime()
            .block_on(unit_domain::dispatch_op(unit_provider() as &dyn UnitProvider, op, args_json));
        return Some(out);
    }
    None
}

fn dispatch_topology(op: &str) -> Result<String, String> {
    match op {
        "collect_claims" => {
            let claims = runtime()
                .block_on(crate::topology::collect_claims())
                .map_err(|e| e.to_string())?;
            serde_json::to_string(&claims).map_err(|e| e.to_string())
        }
        other => Err(format!("unknown topology op: {other}")),
    }
}
