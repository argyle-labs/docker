//! Docker runtime registry: `docker.{list, detail, create, update, delete}` —
//! the registered docker **runtimes** (colima socket, TCP remote, or web
//! orchestrator URL). `#[endpoint_resource]` emits the row struct
//! (`EndpointRow`, aliased `DockerRuntime`), db helpers
//! (`endpoint_db::{list,get,require,insert,update,upsert,remove}`), and the
//! `list` / `detail` tools; `create` / `update` / `delete` are hand-written
//! here so they can be admin-only with a dry run. Every op is routed through
//! core's single connection via the thin `db_op` capability (no second SQLite
//! connection, no `db` crate linkage).
//!
//! Containers, compose stacks, engine status, and per-service stats are NOT
//! tools here — they surface as units through [`crate::unit_provider`] (the
//! generic five-verb + `action` surface) and as lifecycle tools in
//! [`crate::lifecycle`]. This module owns only the runtime registry.

use std::path::{Component, Path};

use plugin_toolkit::abi::{DbOp, DbRow, DbValue};
use plugin_toolkit::prelude::*;
use plugin_toolkit::route::Route;
use plugin_toolkit::runtime::{db_op, field_from_row};

use crate::execute;

// ═══════════════════════════════════════════════════════════════════════════
// docker.{list,detail} — generated; create/update/delete below.
// ═══════════════════════════════════════════════════════════════════════════

/// A registered docker runtime. Exactly one of `socket_path` / `host` / `url`
/// identifies where the engine lives; `socket_path` (e.g.
/// `~/.colima/default/docker.sock`) and `host` (e.g. `tcp://remote:2376`) yield
/// a `DOCKER_HOST`, while `url` names a web orchestrator (Dockge, Portainer).
#[endpoint_resource(plugin = "docker", skip = "create, update, delete")]
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

/// Stacks root used when no enabled runtime sets one.
pub const DEFAULT_STACKS_ROOT: &str = "/opt/stacks";

const SETTINGS_TABLE: &str = "runtime_settings";
const CREATE_TOOL: &str = "docker.create";
const UPDATE_TOOL: &str = "docker.update";
const DELETE_TOOL: &str = "docker.delete";

/// A runtime's `stacks_root`. Kept in the docker-owned `runtime_settings`
/// table because the shared `endpoints` table persists no plugin fields.
fn stored_stacks_root(name: &str) -> Result<Option<String>> {
    let reply = db_op(&DbOp::Get {
        namespace: "docker".to_string(),
        table: SETTINGS_TABLE.to_string(),
        key_col: "name".to_string(),
        key: name.to_string(),
    })?;
    match reply.rows.first() {
        Some(r) => Ok(field_from_row::<Option<String>>(r, "stacks_root")?),
        None => Ok(None),
    }
}

fn put_stacks_root(name: &str, root: Option<&str>) -> Result<()> {
    let mut row = DbRow::new();
    row.insert("name".to_string(), DbValue::Text(name.to_string()));
    row.insert(
        "stacks_root".to_string(),
        root.map_or(DbValue::Null, |r| DbValue::Text(r.to_string())),
    );
    db_op(&DbOp::Upsert {
        namespace: "docker".to_string(),
        table: SETTINGS_TABLE.to_string(),
        row,
    })?;
    Ok(())
}

fn remove_stacks_root(name: &str) -> Result<()> {
    db_op(&DbOp::Delete {
        namespace: "docker".to_string(),
        table: SETTINGS_TABLE.to_string(),
        key_col: "name".to_string(),
        key: name.to_string(),
    })?;
    Ok(())
}

/// Every enabled runtime's stacks root, or [`DEFAULT_STACKS_ROOT`] when none
/// sets one. Stack dirs must resolve inside one of these.
pub fn stacks_roots() -> Result<Vec<String>> {
    let mut roots = Vec::new();
    for row in endpoint_db::list()?.into_iter().filter(|r| r.enabled) {
        if let Some(root) = stored_stacks_root(&row.name)?
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
    if path.components().any(|c| c == Component::ParentDir) {
        bail!("stacks_root '{root}' contains '..'");
    }
    if path.parent().is_none() {
        bail!("stacks_root '/' would admit every host path");
    }
    Ok(())
}

fn entry(row: &EndpointRow) -> EndpointEntry {
    EndpointEntry {
        name: row.name.clone(),
        socket_path: row.socket_path.clone(),
        host: row.host.clone(),
        url: row.url.clone(),
        routes: row.routes.clone(),
        enabled: row.enabled,
    }
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
    pub endpoint: EndpointEntry,
    pub stacks_root: String,
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
    let row = EndpointRow {
        name: args.name.clone(),
        socket_path: args.socket_path,
        host: args.host,
        url: args.url,
        routes: plugin_toolkit::route::Routes::from(args.routes),
        enabled: true,
    };
    let stacks_root = args
        .stacks_root
        .clone()
        .unwrap_or_else(|| DEFAULT_STACKS_ROOT.to_string());
    if !args.execute {
        return Ok(DockerCreateOutput {
            dry_run: true,
            endpoint: entry(&row),
            stacks_root,
            how_to_execute: Some(format!("re-invoke {CREATE_TOOL} with `execute: true`")),
        });
    }
    endpoint_db::insert(&row)
        .map_err(|e| plugin_toolkit::runtime::map_insert_conflict(e, "docker", &row.name))?;
    put_stacks_root(&row.name, args.stacks_root.as_deref())?;
    Ok(DockerCreateOutput {
        dry_run: false,
        endpoint: entry(&row),
        stacks_root,
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
    pub endpoint: EndpointEntry,
    pub stacks_root: String,
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
    let mut row = endpoint_db::get(&args.name)?
        .ok_or_else(|| plugin_toolkit::runtime::missing_row_error("docker", &args.name))?;
    let mut applied = Vec::new();
    if let Some(v) = args.socket_path {
        row.socket_path = Some(v);
        applied.push("socket_path".to_string());
    }
    if let Some(v) = args.host {
        row.host = Some(v);
        applied.push("host".to_string());
    }
    if let Some(v) = args.url {
        row.url = Some(v);
        applied.push("url".to_string());
    }
    if !args.routes.is_empty() {
        row.routes = plugin_toolkit::route::Routes::from(args.routes);
        applied.push("routes".to_string());
    }
    if let Some(v) = args.enabled {
        row.enabled = v;
        applied.push("enabled".to_string());
    }
    let stacks_root = match &args.stacks_root {
        Some(root) => {
            applied.push("stacks_root".to_string());
            Some(root.clone())
        }
        None => stored_stacks_root(&row.name)?,
    };
    if applied.is_empty() {
        bail!("no fields to update; pass at least one flag");
    }
    let shown = stacks_root
        .clone()
        .unwrap_or_else(|| DEFAULT_STACKS_ROOT.to_string());
    if !args.execute {
        return Ok(DockerUpdateOutput {
            dry_run: true,
            endpoint: entry(&row),
            stacks_root: shown,
            applied,
            how_to_execute: Some(format!("re-invoke {UPDATE_TOOL} with `execute: true`")),
        });
    }
    if !endpoint_db::update(&row)? {
        bail!("update reported no row change for `{}`", row.name);
    }
    if args.stacks_root.is_some() {
        put_stacks_root(&row.name, stacks_root.as_deref())?;
    }
    Ok(DockerUpdateOutput {
        dry_run: false,
        endpoint: entry(&row),
        stacks_root: shown,
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
    remove_stacks_root(&args.name)?;
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

#[cfg(test)]
mod registry_tests {
    use super::*;
    use crate::test_support::{admin, assert_admin_refusal, non_admins, with_db};
    use plugin_toolkit::contract::OrcaToolDef;
    use plugin_toolkit::reactor::block_on;

    fn create_args(execute: bool) -> DockerCreateArgs {
        DockerCreateArgs {
            name: "local".into(),
            socket_path: None,
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
    fn dry_runs_change_nothing_and_execute_records_the_stacks_root() {
        let ((), tables) = with_db(|| {
            block_on(async {
                let ctx = admin();
                let out = docker_create(create_args(false), &ctx).await.unwrap();
                assert!(out.dry_run && out.how_to_execute.is_some());
                assert_eq!(out.stacks_root, "/srv/stacks");
                assert!(endpoint_db::list().unwrap().is_empty());
                assert_eq!(stacks_roots().unwrap(), [DEFAULT_STACKS_ROOT]);

                let out = docker_create(create_args(true), &ctx).await.unwrap();
                assert!(!out.dry_run && out.endpoint.enabled);
                assert_eq!(stacks_roots().unwrap(), ["/srv/stacks"]);

                let out = docker_update(update_args(false), &ctx).await.unwrap();
                assert!(out.dry_run);
                assert_eq!(out.applied, ["stacks_root"]);
                assert_eq!(out.stacks_root, "/srv/other");
                assert_eq!(stacks_roots().unwrap(), ["/srv/stacks"]);

                docker_update(update_args(true), &ctx).await.unwrap();
                assert_eq!(stacks_roots().unwrap(), ["/srv/other"]);

                let args = DockerDeleteArgs {
                    name: "local".into(),
                    execute: false,
                };
                let out = docker_delete(args, &ctx).await.unwrap();
                assert!(out.dry_run && out.changed);
                assert_eq!(endpoint_db::list().unwrap().len(), 1);

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
    fn stacks_root_must_be_an_absolute_path_below_root() {
        for bad in ["relative/stacks", "/srv/../etc", "/"] {
            let mut args = create_args(false);
            args.stacks_root = Some(bad.into());
            let err = with_db(|| block_on(docker_create(args, &admin())).unwrap_err()).0;
            assert!(err.to_string().contains("stacks_root"), "{bad}: {err}");
        }
    }
}
