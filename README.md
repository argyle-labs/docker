# docker — orca plugin

A standalone [orca](https://github.com/scottdkey/orca) plugin that adapts the
**docker engine** and **docker compose** into orca's containers domain. It is
CLI-based: the `docker` binary is the API. The plugin probes the local engine
(colima vs Docker Desktop vs distro Engine), wraps compose projects, reads
container stats, and contributes container→host topology claims to orca's
network graph.

This repository is the canonical home of the plugin. It builds as a
`cdylib` that orca's `plugin-loader` `dlopen`s, and as an `rlib` so the
in-crate test harness and a checked-out orca workspace can use it directly.

## Tool surface

| Tool | Purpose |
|------|---------|
| `docker.list` | Engine status + registered runtimes; optionally one project's services (`path`) or a directory scan (`root`). |
| `docker.detail` | One compose project: services + logs + live container stats. |
| `docker.create` | Register a new docker runtime (socket / host / url). |
| `docker.update` | Combine: start the engine, update a runtime, run a compose action. |
| `docker.delete` | Remove a registered docker runtime. |
| `docker.install` | Provision + start the engine on this host (`scripts/install.sh`). |
| `docker.engine_update` | Upgrade the engine package / colima image (`scripts/update.sh`). |
| `docker.backup` | Archive the engine's persistent state (colima/lima profile). |

Every tool inherits orca's universal `--peer <host>` flag, so
`docker.list --peer <host>.local` lists containers on a paired peer via mesh
dispatch.

Example payloads live in [`examples/`](./examples).

## The two-dependency rule

This plugin has **exactly two** entries under `[dependencies]`:

```toml
[dependencies]
plugin-toolkit = { git = "https://github.com/scottdkey/orca", tag = "v0.0.8-rc.8" }
abi_stable = "0.11"
```

Everything else a plugin could possibly need — `serde`, `serde_json`,
`schemars`, `clap`, `chrono`, `tokio`, `anyhow`, and the orca domain crates
(`containers`, `db`, `contract`, `dispatch`) — is reached through
`plugin_toolkit::*` or its prelude:

```rust
use plugin_toolkit::prelude::*;     // ToolCtx, Result, #[orca_tool], #[plugin_struct], …
use plugin_toolkit::containers;     // the containers domain
use plugin_toolkit::db;             // the docker_runtimes table
```

Hand-written structs use `#[plugin_struct]` (or `#[plugin_struct(args)]` for a
clap CLI), which injects `Serialize`/`Deserialize`/`JsonSchema` (and
`clap::Args`) with every crate path anchored at `::plugin_toolkit::*`. Internal
structs that don't cross a tool boundary use a bare
`#[derive(Serialize, Deserialize)]` plus `#[serde(crate = "plugin_toolkit::serde")]`.
The compose-layer error enum hand-rolls `Display`/`Error`/`From` rather than
deriving `thiserror`, so the crate carries no path dependency on the derive's
emitted `::thiserror` root.

If you ever feel you need a third dependency, that is a signal the toolkit is
missing a primitive — [file a toolkit gap](https://github.com/scottdkey/orca/issues)
rather than adding the crate here.

## Why `abi_stable` is the unavoidable exception

The plugin is loaded as a C-ABI dynamic library. The single FFI entrypoint in
[`src/abi_export.rs`](./src/abi_export.rs) uses `#[export_root_module]`, which
expands to **bare `::abi_stable` paths in this crate's root** — it cannot be
routed through the toolkit because the macro hard-codes the crate name at the
dylib boundary the loader inspects. It is pinned to `0.11` to match the version
the orca workspace links, so the `StableAbi` layout hash baked into the cdylib
matches what `plugin-loader` checks at load time. This is the same exception
every orca plugin makes, and the only one.

## Deploy

Unlike a media-server plugin, **docker is not a containerized workload** — you
do not run an image of docker to manage docker. The plugin is a `cdylib`
loaded into the orca daemon on a host that already has (or will have) a docker
engine. Deployment is therefore:

1. Build the cdylib: `cargo build --release` → `target/release/libdocker.{so,dylib}`.
2. Place it where the host's orca daemon scans for plugins, or install via the
   orca plugin registry once published.
3. If the host has no engine yet, run `docker.install` (or `scripts/install.sh`
   directly) to provision colima / Docker Engine.

The `scripts/` directory holds the bootstrap payload the lifecycle tools
orchestrate:

| Script | Tool | Action |
|--------|------|--------|
| `install.sh` | `docker.install` | install + start colima / Docker Engine |
| `update.sh` | `docker.engine_update` | upgrade the engine, restart the daemon |
| `backup.sh` | `docker.backup` | tar the colima/lima state dir |
| `restore.sh` | — | restore engine state from a backup tarball |

There is no `Dockerfile` or `compose.yml` for the plugin itself, by design.

## Building locally against an orca checkout

The committed [`.cargo/config.toml`](./.cargo/config.toml) redirects the
`plugin-toolkit` git dep to `../orca/projects/plugin-toolkit` via `[patch]`, so
with the (private) orca repo checked out alongside this one:

```
~/code/orca      # the orca workspace
~/code/docker    # this repo
```

`cargo build && cargo test && cargo clippy --all-targets -- -D warnings`
resolves the toolkit from your local tree. CI has no `../orca`, so it exercises
the pinned git-tag resolution path instead.

## Authoring a fresh tool on this plugin

```rust
use plugin_toolkit::prelude::*;

#[plugin_struct(args)]
pub struct DockerPruneArgs {
    /// Also remove unused volumes.
    #[arg(long)]
    #[serde(default)]
    pub volumes: bool,
}

#[plugin_struct]
#[serde(rename_all = "camelCase")]
pub struct DockerPruneOutput {
    pub reclaimed_bytes: u64,
}

/// [MUTATES STATE] Prune dangling images/containers on this host.
#[orca_tool(domain = "docker", verb = "prune")]
async fn docker_prune(args: DockerPruneArgs, _ctx: &ToolCtx) -> Result<DockerPruneOutput> {
    let mut a = vec!["system", "prune", "-f"];
    if args.volumes { a.push("--volumes"); }
    let out = crate::run(&a, None).await?;
    // parse `out` for reclaimed space …
    let _ = out;
    Ok(DockerPruneOutput { reclaimed_bytes: 0 })
}
```

Add the `#[orca_tool]` and its inventory entry is picked up automatically; the
`docker.*` filter in `src/abi_export.rs` admits it across the ABI. No Cargo
changes, no manual registration.
