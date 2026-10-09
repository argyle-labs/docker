//! Docker runtime registry: `docker.{list, detail, create, update, delete}` —
//! the registered docker **runtimes** (colima socket, TCP remote, or web
//! orchestrator URL). `#[endpoint_resource]` emits the row struct
//! (`EndpointRow`, aliased `DockerRuntime`) and db helpers
//! (`endpoint_db::{list,get,require,insert,update,upsert,remove}`); all five
//! tools are hand-written here. The shared `endpoints` table keeps only the
//! name, routes and enabled flag, so `socket_path`, `host`, `url` and
//! `stacks_root` live in the docker-owned `runtime_settings` table. Writes are
//! admin-only with a dry run. Every op is routed through core's single
//! connection via the thin `db_op` capability (no second SQLite connection,
//! no `db` crate linkage).
//!
//! Containers, compose stacks, engine status, and per-service stats are NOT
//! tools here — they surface as units through [`crate::unit_provider`] (the
//! generic five-verb + `action` surface) and as lifecycle tools in
//! [`crate::lifecycle`]. This module owns only the runtime registry.

use std::path::{Component, Path};

use plugin_toolkit::abi::{DbOp, DbRow, DbValue};
use plugin_toolkit::prelude::*;
use plugin_toolkit::route::{Route, Routes};
use plugin_toolkit::runtime::{db_op, field_from_row};

use crate::execute;

/// A registered docker runtime. Exactly one of `socket_path` / `host` / `url`
/// identifies where the engine lives; `socket_path` (e.g.
/// `~/.colima/default/docker.sock`) and `host` (e.g. `tcp://remote:2376`) yield
/// a `DOCKER_HOST`, while `url` names a web orchestrator (Dockge, Portainer).
#[endpoint_resource(plugin = "docker", skip = "list, detail, create, update, delete")]
pub struct DockerRuntime {
    pub socket_path: Option<String>,
    pub host: Option<String>,
    pub url: Option<String>,
    pub enabled: bool,
}

/// Stacks root used when no registered runtime sets one.
pub const DEFAULT_STACKS_ROOT: &str = "/opt/stacks";

const SETTINGS_TABLE: &str = "runtime_settings";
const CREATE_TOOL: &str = "docker.create";
const UPDATE_TOOL: &str = "docker.update";
const DELETE_TOOL: &str = "docker.delete";

/// A registered runtime as stored: the shared `endpoints` row joined with its
/// `runtime_settings` row.
#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq)]
pub struct Runtime {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Directory managed stacks must live under; absent means the default
    /// (`/opt/stacks`) applies unless another runtime sets one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stacks_root: Option<String>,
    pub routes: Routes,
    pub enabled: bool,
}

impl Runtime {
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

    fn endpoint_row(&self) -> EndpointRow {
        EndpointRow {
            name: self.name.clone(),
            socket_path: None,
            host: None,
            url: None,
            routes: self.routes.clone(),
            enabled: self.enabled,
        }
    }
}

fn text(v: &Option<String>) -> DbValue {
    v.as_ref()
        .map_or(DbValue::Null, |s| DbValue::Text(s.clone()))
}

fn joined(row: EndpointRow) -> Result<Runtime> {
    let reply = db_op(&DbOp::Get {
        namespace: "docker".to_string(),
        table: SETTINGS_TABLE.to_string(),
        key_col: "name".to_string(),
        key: row.name.clone(),
    })?;
    let setting = |col: &str| -> Result<Option<String>> {
        match reply.rows.first() {
            Some(r) => Ok(field_from_row::<Option<String>>(r, col)?),
            None => Ok(None),
        }
    };
    Ok(Runtime {
        socket_path: setting("socket_path")?,
        host: setting("host")?,
        url: setting("url")?,
        stacks_root: setting("stacks_root")?,
        name: row.name,
        routes: row.routes,
        enabled: row.enabled,
    })
}

fn store_settings(rt: &Runtime) -> Result<()> {
    let mut row = DbRow::new();
    row.insert("name".to_string(), DbValue::Text(rt.name.clone()));
    row.insert("socket_path".to_string(), text(&rt.socket_path));
    row.insert("host".to_string(), text(&rt.host));
    row.insert("url".to_string(), text(&rt.url));
    row.insert("stacks_root".to_string(), text(&rt.stacks_root));
    db_op(&DbOp::Upsert {
        namespace: "docker".to_string(),
        table: SETTINGS_TABLE.to_string(),
        row,
    })?;
    Ok(())
}

fn remove_settings(name: &str) -> Result<()> {
    db_op(&DbOp::Delete {
        namespace: "docker".to_string(),
        table: SETTINGS_TABLE.to_string(),
        key_col: "name".to_string(),
        key: name.to_string(),
    })?;
    Ok(())
}

/// Every registered runtime, ordered by name.
pub fn runtimes() -> Result<Vec<Runtime>> {
    let mut all = endpoint_db::list()?
        .into_iter()
        .map(joined)
        .collect::<Result<Vec<_>>>()?;
    all.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(all)
}

pub fn runtime(name: &str) -> Result<Option<Runtime>> {
    endpoint_db::get(name)?.map(joined).transpose()
}

/// The stacks roots of every registered runtime, disabled ones included
/// (a root is configuration, not liveness), else [`DEFAULT_STACKS_ROOT`].
/// Stack dirs must resolve inside one of these.
pub fn stacks_roots() -> Result<Vec<String>> {
    let mut roots = Vec::new();
    for rt in runtimes()? {
        if let Some(root) = rt.stacks_root
            && !roots.contains(&root)
        {
            roots.push(root);
        }
    }
    if roots.is_empty() {
        roots.push(DEFAULT_STACKS_ROOT.to_string());
    }
    Ok(roots)
}

fn validate_stacks_root(root: &str) -> Result<()> {
    let path = Path::new(root);
    if !path.is_absolute() {
        bail!("stacks_root '{root}' is not an absolute path");
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || root.split('/').any(|seg| seg == "." || seg == "..")
    {
        bail!("stacks_root '{root}' contains '.' or '..'");
    }
    if path.parent().is_none() {
        bail!("stacks_root '/' would admit every host path");
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.list / docker.detail — read the registry
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct DockerListArgs {
    /// Max runtimes to return this page (clamped to [1, 200]; default 50).
    #[arg(long)]
    #[serde(default)]
    pub limit: Option<u32>,
    /// Opaque cursor from a previous page's `nextCursor`. Omit for the first
    /// page.
    #[arg(long)]
    #[serde(default)]
    pub cursor: Option<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerListOutput {
    pub endpoints: Vec<Runtime>,
    /// Opaque cursor for the next page, or absent on the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Total runtimes across all pages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

/// List registered docker runtimes.
#[orca_tool(domain = "docker", verb = "list")]
async fn docker_list(args: DockerListArgs, _ctx: &ToolCtx) -> Result<DockerListOutput> {
    let params = plugin_toolkit::contract::paging::PageParams {
        limit: args.limit,
        cursor: args.cursor,
    };
    let page = plugin_toolkit::contract::paging::Page::from_slice(runtimes()?, &params);
    Ok(DockerListOutput {
        endpoints: page.items,
        next_cursor: page.next_cursor,
        total: page.total,
    })
}

#[orca_struct(args)]
pub struct DockerDetailArgs {
    #[arg(long)]
    pub name: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerDetailOutput {
    pub endpoint: Runtime,
}

/// Detail for a single docker runtime.
#[orca_tool(domain = "docker", verb = "detail")]
async fn docker_detail(args: DockerDetailArgs, _ctx: &ToolCtx) -> Result<DockerDetailOutput> {
    let endpoint = runtime(&args.name)?
        .ok_or_else(|| plugin_toolkit::runtime::missing_row_error("docker", &args.name))?;
    Ok(DockerDetailOutput { endpoint })
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.create — register a runtime
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct DockerCreateArgs {
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    #[serde(default, alias = "socket_path")]
    pub socket_path: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub host: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub url: Option<String>,
    /// Absolute directory managed stacks must live under (default
    /// `/opt/stacks`).
    #[arg(long)]
    #[serde(default, alias = "stacks_root")]
    pub stacks_root: Option<String>,
    /// Reachable path(s), tried in order. Repeatable: `--route kind=url`
    /// or a JSON object. e.g. `--route lan=http://10.0.0.5:8989`.
    #[arg(
        long = "route",
        value_parser = plugin_toolkit::route::parse_route,
        action = plugin_toolkit::clap::ArgAction::Append,
    )]
    #[serde(default)]
    pub routes: Vec<Route>,
    /// Register the runtime. Omitted, validates and returns what would be
    /// registered, changing nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerCreateOutput {
    /// `true`: nothing was written.
    pub dry_run: bool,
    /// Dry run: what would be stored. Execute: what was read back after the
    /// write.
    pub endpoint: Runtime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// [MUTATES STATE] Register a new docker runtime. Errors if `name` is already
/// taken. Without `execute`, returns what would be registered and changes
/// nothing.
#[orca_tool(
    domain = "docker",
    verb = "create",
    role = "admin",
    execute_gated = false
)]
pub(crate) async fn docker_create(
    args: DockerCreateArgs,
    ctx: &ToolCtx,
) -> Result<DockerCreateOutput> {
    execute::require_admin(CREATE_TOOL, ctx)?;
    if let Some(root) = &args.stacks_root {
        validate_stacks_root(root)?;
    }
    if endpoint_db::get(&args.name)?.is_some() {
        bail!(
            "docker endpoint '{}' already exists; use docker.update",
            args.name
        );
    }
    let rt = Runtime {
        name: args.name,
        socket_path: args.socket_path,
        host: args.host,
        url: args.url,
        stacks_root: args.stacks_root,
        routes: Routes::from(args.routes),
        enabled: true,
    };
    if !args.execute {
        return Ok(DockerCreateOutput {
            dry_run: true,
            endpoint: rt,
            how_to_execute: Some(format!("re-invoke {CREATE_TOOL} with `execute: true`")),
        });
    }
    endpoint_db::insert(&rt.endpoint_row())
        .map_err(|e| plugin_toolkit::runtime::map_insert_conflict(e, "docker", &rt.name))?;
    store_settings(&rt)?;
    let endpoint =
        runtime(&rt.name)?.ok_or_else(|| anyhow!("runtime '{}' did not read back", rt.name))?;
    Ok(DockerCreateOutput {
        dry_run: false,
        endpoint,
        how_to_execute: None,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.update — patch a registered runtime
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct DockerUpdateArgs {
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    #[serde(default, alias = "socket_path")]
    pub socket_path: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub host: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub url: Option<String>,
    /// Absolute directory managed stacks must live under.
    #[arg(long)]
    #[serde(default, alias = "stacks_root")]
    pub stacks_root: Option<String>,
    /// Replace the reachable-path set. Repeatable: `--route kind=url`
    /// or a JSON object. Omit to leave routes unchanged.
    #[arg(
        long = "route",
        value_parser = plugin_toolkit::route::parse_route,
        action = plugin_toolkit::clap::ArgAction::Append,
    )]
    #[serde(default)]
    pub routes: Vec<Route>,
    #[arg(long)]
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Apply the patch. Omitted, returns the patched runtime and changes
    /// nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerUpdateOutput {
    /// `true`: nothing was written.
    pub dry_run: bool,
    /// Dry run: the patched runtime. Execute: what was read back after the
    /// write.
    pub endpoint: Runtime,
    pub applied: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// [MUTATES STATE] Modify an existing docker runtime. PATCH semantics — must
/// already exist. Without `execute`, returns the patched runtime and changes
/// nothing.
#[orca_tool(
    domain = "docker",
    verb = "update",
    role = "admin",
    execute_gated = false
)]
async fn docker_update(args: DockerUpdateArgs, ctx: &ToolCtx) -> Result<DockerUpdateOutput> {
    execute::require_admin(UPDATE_TOOL, ctx)?;
    if let Some(root) = &args.stacks_root {
        validate_stacks_root(root)?;
    }
    let mut rt = runtime(&args.name)?
        .ok_or_else(|| plugin_toolkit::runtime::missing_row_error("docker", &args.name))?;
    let mut applied = Vec::new();
    let mut endpoint_changed = false;
    let mut patch = |field: &mut Option<String>, value: Option<String>, name: &str| {
        if let Some(v) = value {
            *field = Some(v);
            applied.push(name.to_string());
        }
    };
    patch(&mut rt.socket_path, args.socket_path, "socket_path");
    patch(&mut rt.host, args.host, "host");
    patch(&mut rt.url, args.url, "url");
    patch(&mut rt.stacks_root, args.stacks_root, "stacks_root");
    if !args.routes.is_empty() {
        rt.routes = Routes::from(args.routes);
        applied.push("routes".to_string());
        endpoint_changed = true;
    }
    if let Some(v) = args.enabled {
        rt.enabled = v;
        applied.push("enabled".to_string());
        endpoint_changed = true;
    }
    if applied.is_empty() {
        bail!("no fields to update; pass at least one flag");
    }
    if !args.execute {
        return Ok(DockerUpdateOutput {
            dry_run: true,
            endpoint: rt,
            applied,
            how_to_execute: Some(format!("re-invoke {UPDATE_TOOL} with `execute: true`")),
        });
    }
    if endpoint_changed && !endpoint_db::update(&rt.endpoint_row())? {
        bail!("update reported no row change for `{}`", rt.name);
    }
    store_settings(&rt)?;
    let endpoint =
        runtime(&rt.name)?.ok_or_else(|| anyhow!("runtime '{}' did not read back", rt.name))?;
    Ok(DockerUpdateOutput {
        dry_run: false,
        endpoint,
        applied,
        how_to_execute: None,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.delete — deregister a runtime
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct DockerDeleteArgs {
    #[arg(long)]
    pub name: String,
    /// Remove the runtime. Omitted, reports whether it exists and changes
    /// nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerDeleteOutput {
    /// `true`: nothing was removed.
    pub dry_run: bool,
    pub name: String,
    /// Dry run: whether a runtime would be removed. Execute: whether one was.
    pub changed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// [MUTATES STATE] Remove a registered docker runtime. Idempotent. Without
/// `execute`, reports whether it exists and changes nothing.
#[orca_tool(
    domain = "docker",
    verb = "delete",
    role = "admin",
    execute_gated = false
)]
async fn docker_delete(args: DockerDeleteArgs, ctx: &ToolCtx) -> Result<DockerDeleteOutput> {
    execute::require_admin(DELETE_TOOL, ctx)?;
    if !args.execute {
        let changed = endpoint_db::get(&args.name)?.is_some();
        return Ok(DockerDeleteOutput {
            dry_run: true,
            name: args.name,
            changed,
            how_to_execute: Some(format!("re-invoke {DELETE_TOOL} with `execute: true`")),
        });
    }
    let changed = endpoint_db::remove(&args.name)?;
    remove_settings(&args.name)?;
    Ok(DockerDeleteOutput {
        dry_run: false,
        name: args.name,
        changed,
        how_to_execute: None,
    })
}

/// The `DOCKER_HOST` value of the first enabled socket/tcp runtime, for
/// subprocess injection. Web-only runtimes (`url` only) are skipped.
pub fn active_host() -> Option<String> {
    runtimes()
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

#[cfg(test)]
mod registry_tests {
    use super::*;
    use crate::test_support::{admin, assert_admin_refusal, non_admins, with_db};
    use plugin_toolkit::contract::OrcaToolDef;
    use plugin_toolkit::reactor::block_on;

    fn create_args(execute: bool) -> DockerCreateArgs {
        DockerCreateArgs {
            name: "local".into(),
            socket_path: Some("/var/run/test-docker.sock".into()),
            host: None,
            url: None,
            stacks_root: Some("/srv/stacks".into()),
            routes: Vec::new(),
            execute,
        }
    }

    fn update_args(execute: bool) -> DockerUpdateArgs {
        DockerUpdateArgs {
            name: "local".into(),
            socket_path: None,
            host: None,
            url: None,
            stacks_root: Some("/srv/other".into()),
            routes: Vec::new(),
            enabled: None,
            execute,
        }
    }

    #[test]
    fn registry_writes_are_admin_only_and_own_their_execute_flag() {
        fn admin_self_gated<T: OrcaToolDef>() {
            assert_eq!(T::REQUIRED_ROLE, "admin", "{}", T::NAME);
            assert!(!T::EXECUTE_GATED, "{}", T::NAME);
        }
        admin_self_gated::<DockerCreate>();
        admin_self_gated::<DockerUpdate>();
        admin_self_gated::<DockerDelete>();
    }

    #[test]
    fn non_admins_get_neither_the_dry_run_nor_execute() {
        let (errs, tables) = with_db(|| {
            let mut errs = Vec::new();
            for ctx in non_admins() {
                for execute in [false, true] {
                    block_on(async {
                        errs.push(docker_create(create_args(execute), &ctx).await.unwrap_err());
                        errs.push(docker_update(update_args(execute), &ctx).await.unwrap_err());
                        let args = DockerDeleteArgs {
                            name: "local".into(),
                            execute,
                        };
                        errs.push(docker_delete(args, &ctx).await.unwrap_err());
                    });
                }
            }
            errs
        });
        assert_eq!(errs.len(), 18);
        for err in errs {
            assert_admin_refusal(&err.to_string());
        }
        assert!(tables.values().all(Vec::is_empty), "{tables:?}");
    }

    #[test]
    fn dry_runs_change_nothing_and_execute_echoes_what_was_stored() {
        let ((), tables) = with_db(|| {
            block_on(async {
                let ctx = admin();
                let out = docker_create(create_args(false), &ctx).await.unwrap();
                assert!(out.dry_run && out.how_to_execute.is_some());
                assert_eq!(out.endpoint.stacks_root.as_deref(), Some("/srv/stacks"));
                assert!(runtimes().unwrap().is_empty());
                assert_eq!(stacks_roots().unwrap(), [DEFAULT_STACKS_ROOT]);

                let out = docker_create(create_args(true), &ctx).await.unwrap();
                assert!(!out.dry_run && out.endpoint.enabled);
                assert_eq!(Some(out.endpoint.clone()), runtime("local").unwrap());
                assert_eq!(
                    out.endpoint.socket_path.as_deref(),
                    Some("/var/run/test-docker.sock")
                );
                assert_eq!(stacks_roots().unwrap(), ["/srv/stacks"]);

                let out = docker_update(update_args(false), &ctx).await.unwrap();
                assert!(out.dry_run);
                assert_eq!(out.applied, ["stacks_root"]);
                assert_eq!(out.endpoint.stacks_root.as_deref(), Some("/srv/other"));
                assert_eq!(stacks_roots().unwrap(), ["/srv/stacks"]);

                let out = docker_update(update_args(true), &ctx).await.unwrap();
                assert_eq!(Some(out.endpoint.clone()), runtime("local").unwrap());
                assert_eq!(out.endpoint.stacks_root.as_deref(), Some("/srv/other"));
                assert_eq!(
                    out.endpoint.socket_path.as_deref(),
                    Some("/var/run/test-docker.sock"),
                    "a patch keeps the fields it does not name"
                );

                let mut disable = update_args(true);
                disable.stacks_root = None;
                disable.enabled = Some(false);
                docker_update(disable, &ctx).await.unwrap();
                assert_eq!(
                    stacks_roots().unwrap(),
                    ["/srv/other"],
                    "a disabled runtime's root still counts"
                );

                let args = DockerDeleteArgs {
                    name: "local".into(),
                    execute: false,
                };
                let out = docker_delete(args, &ctx).await.unwrap();
                assert!(out.dry_run && out.changed);
                assert_eq!(runtimes().unwrap().len(), 1);

                let args = DockerDeleteArgs {
                    name: "local".into(),
                    execute: true,
                };
                assert!(docker_delete(args, &ctx).await.unwrap().changed);
                assert_eq!(stacks_roots().unwrap(), [DEFAULT_STACKS_ROOT]);
            })
        });
        assert!(tables.values().all(Vec::is_empty), "{tables:?}");
    }

    #[test]
    fn a_registered_socket_is_the_active_docker_host() {
        let (host, _) = with_db(|| {
            block_on(docker_create(create_args(true), &admin())).unwrap();
            let listed = block_on(docker_list(DockerListArgs::default(), &admin())).unwrap();
            assert_eq!(
                listed.endpoints[0].socket_path.as_deref(),
                Some("/var/run/test-docker.sock")
            );
            active_host()
        });
        assert_eq!(host.as_deref(), Some("unix:///var/run/test-docker.sock"));
    }

    #[test]
    fn stacks_root_must_be_an_absolute_path_below_root() {
        for bad in ["relative/stacks", "/srv/../etc", "/srv/./x", "/"] {
            let mut args = create_args(false);
            args.stacks_root = Some(bad.into());
            let err = with_db(|| block_on(docker_create(args, &admin())).unwrap_err()).0;
            assert!(err.to_string().contains("stacks_root"), "{bad}: {err}");
        }
    }
}
