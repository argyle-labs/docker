//! docker — orca's Docker Engine + Compose plugin.
//!
//! An out-of-process orca plugin: orca's boot-time scan finds this executable
//! in its install dir, spawns it, and speaks the UDS wire protocol to it. The
//! plugin owns the `docker.` tool namespace plus four typed domain facets
//! (topology / container_runtime / unit / subprocess_env), wired through the
//! toolkit's `Plugin` builder.

plugin_toolkit::instrument::bootstrap!();

use plugin_toolkit::plugin::Plugin;

// Force-link the `#[orca_tool]` inventory surfaces so their registrations
// survive into the final binary.
use docker::lifecycle as _;
use docker::tools as _;

fn main() -> plugin_toolkit::anyhow::Result<()> {
    Plugin::named("docker")
        .version(env!("CARGO_PKG_VERSION"))
        .tools(["docker."])
        .schema_json(docker::registration::schema_json())
        .container_runtime(docker::runtime_adapter::DockerAdapter::new())
        .unit(docker::registration::unit_provider())
        .topology(docker::registration::DockerTopology)
        .subprocess_env(docker::registration::DockerEnv)
        .serve()
}
