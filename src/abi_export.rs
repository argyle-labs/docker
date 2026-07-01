//! ABI-stable cdylib export for the docker plugin.
//!
//! docker is a **hybrid** plugin: the `docker.` tool surface PLUS two domain
//! backends — a `topology` collector and a bollard-backed `container_runtime`
//! adapter (see [`crate::registration`]). The toolkit's [`export_tool_plugin!`]
//! hybrid arm generates the metadata fns, the `docker.`-scoped manifest, and an
//! `invoke` that tries the backend dispatch first (the `docker.__topo.*` /
//! `docker.__runtime.*` calls the loader makes) then falls through to tool
//! dispatch.
//!
//! `abi_stable` remains a direct dep because `#[export_root_module]` (which the
//! macro invokes) expands to bare `::abi_stable` paths.

plugin_toolkit::export_tool_plugin! {
    name: "docker",
    target_compat: ">=20.10",
    backends: crate::registration::backends_json(),
    backend_dispatch: crate::registration::backend_dispatch,
}
