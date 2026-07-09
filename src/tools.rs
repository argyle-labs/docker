//! Docker runtime registry: `docker.{list, detail, create, update, delete}` —
//! the registered docker **runtimes** (colima socket, TCP remote, or web
//! orchestrator URL), generated wholesale by `#[endpoint_resource]`. The macro
//! emits the row struct (`EndpointRow`, aliased `DockerRuntime`), db helpers
//! (`endpoint_db::{list,get,require,insert,update,upsert,remove}`), the schema
//! fragment, args/output types, and the five `#[orca_tool]` functions in one
//! shot — every op routed through core's single connection via the thin
//! `db_op` capability (no second SQLite connection, no `db` crate linkage).
//!
//! Containers, compose stacks, engine status, and per-service stats are NOT
//! tools here — they surface as units through [`crate::unit_provider`] (the
//! generic five-verb + `action` surface) and as lifecycle tools in
//! [`crate::lifecycle`]. This module owns only the runtime registry.

use plugin_toolkit::prelude::*;

// ═══════════════════════════════════════════════════════════════════════════
// docker.{list,detail,create,update,delete} — runtime registry CRUD.
// One declaration → five tools, three transports each, schema fragment, db
// helpers, row struct, args/output types.
// ═══════════════════════════════════════════════════════════════════════════

/// A registered docker runtime. Exactly one of `socket_path` / `host` / `url`
/// identifies where the engine lives; `socket_path` (e.g.
/// `~/.colima/default/docker.sock`) and `host` (e.g. `tcp://remote:2376`) yield
/// a `DOCKER_HOST`, while `url` names a web orchestrator (Dockge, Portainer).
#[endpoint_resource(plugin = "docker")]
pub struct DockerRuntime {
    pub socket_path: Option<String>,
    pub host: Option<String>,
    pub url: Option<String>,
    pub enabled: bool,
}

impl EndpointRow {
    /// The `DOCKER_HOST` value to inject for socket/tcp runtimes; web-only
    /// runtimes (`url` set, no socket/host) yield `None`.
    pub fn docker_host(&self) -> Option<String> {
        if let Some(sock) = &self.socket_path {
            Some(format!(
                "unix://{}",
                plugin_toolkit::path::expand_tilde(sock)
            ))
        } else {
            self.host.clone()
        }
    }
}

/// The `DOCKER_HOST` value of the first enabled socket/tcp runtime, for
/// subprocess injection. Web-only runtimes (`url` only) are skipped.
pub fn active_host() -> Option<String> {
    endpoint_db::list()
        .ok()?
        .into_iter()
        .filter(|r| r.enabled)
        .find_map(|r| r.docker_host())
}
