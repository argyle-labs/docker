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

/// Well-known docker socket locations probed when no runtime is registered.
/// An unconfigured host — notably Unraid, where the engine listens on the
/// standard socket — still yields an explicit `DOCKER_HOST` this way, so the
/// `subprocess_env` seam injects a concrete value instead of nothing.
const WELL_KNOWN_SOCKETS: &[&str] = &["/var/run/docker.sock", "/run/docker.sock"];

/// First existing socket in `paths`, formatted as a `unix://` `DOCKER_HOST`.
/// Pure over the filesystem so it can be unit-tested with a temp path.
fn first_existing_socket(paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|p| format!("unix://{p}"))
}

/// Resolve the `DOCKER_HOST` to inject, trying every source in order:
/// 1. the first enabled registered runtime (socket/tcp),
/// 2. colima's default socket,
/// 3. a docker socket present at a well-known path (covers Unraid and any
///    host running the engine on the standard socket without registration).
///
/// Returns `None` only when nothing is discoverable, in which case a direct
/// bollard client falls back to its own compiled-in default.
pub fn resolve_docker_host() -> Option<String> {
    if let Some(host) = active_host() {
        return Some(host);
    }
    if let Ok(home) = std::env::var("HOME") {
        let colima = format!("{home}/.colima/default/docker.sock");
        if std::path::Path::new(&colima).exists() {
            return Some(format!("unix://{colima}"));
        }
    }
    first_existing_socket(WELL_KNOWN_SOCKETS)
}

#[cfg(test)]
mod resolve_tests {
    use super::first_existing_socket;

    #[test]
    fn first_existing_socket_picks_present_path_and_formats_unix() {
        let dir = std::env::temp_dir();
        let present = dir.join("orca-docker-test.sock");
        std::fs::write(&present, b"").unwrap();
        let present = present.to_str().unwrap().to_string();
        let missing = "/definitely/not/a/real/docker.sock";

        // Missing-first: skips it, picks the present one.
        assert_eq!(
            first_existing_socket(&[missing, &present]),
            Some(format!("unix://{present}"))
        );
        // Nothing present → None.
        assert_eq!(first_existing_socket(&[missing]), None);

        std::fs::remove_file(&present).ok();
    }
}
