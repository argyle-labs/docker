//! docker — orca's Docker Engine + Compose plugin.
//!
//! An out-of-process orca plugin: orca's boot-time scan finds this executable
//! in its install dir, spawns it, and speaks the UDS wire protocol to it. The
//! plugin owns the `docker.` tool namespace plus its hybrid domain backends
//! (topology / container_runtime / unit / subprocess_env), dispatched through
//! [`docker::registration::backend_dispatch`].

use plugin_toolkit::serve::{PluginSpec, serve};

fn main() -> plugin_toolkit::anyhow::Result<()> {
    serve(PluginSpec {
        name: "docker".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        prefixes: vec!["docker.".to_string()],
        backends_json: docker::registration::backends_json(),
        schema_json: docker::registration::schema_json(),
        backend_dispatch: Some(docker::registration::backend_dispatch),
    })
}
