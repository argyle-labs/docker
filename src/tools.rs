//! Docker tool surface — flat 4-tool surface (`docker.{list, detail, update,
//! delete}`). A docker container/service is the primary resource; engine
//! status, registered runtimes, and compose projects nest into the listing
//! or are addressed through `update` args without a sub-resource flag.
//!
//! Pod awareness: every tool inherits the universal `--peer <host>` flag —
//! `docker.list --peer host-b` lists containers on that peer via mesh dispatch.

use std::path::{Path, PathBuf};

use plugin_toolkit::anyhow;
use plugin_toolkit::clap;
use plugin_toolkit::contract;
use plugin_toolkit::db;
use plugin_toolkit::prelude::{orca_tool, plugin_struct};

use crate::{Compose, ComposeError, Engine};

// ── Row shapes ──────────────────────────────────────────────────────────────

#[plugin_struct]
#[derive(Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum DockerEngineKind {
    Colima,
    Desktop,
    #[default]
    None,
}

#[plugin_struct]
#[derive(Clone, Default)]
pub struct DockerEngineStatus {
    pub engine: DockerEngineKind,
    pub running: bool,
}

#[plugin_struct]
#[derive(Clone)]
pub struct DockerServiceRow {
    pub name: String,
    pub state: String,
    pub running: bool,
    pub health: String,
    pub ports: Vec<String>,
}

#[plugin_struct]
#[derive(Clone)]
pub struct DockerProjectRow {
    pub project: String,
    pub path: String,
    pub services: Vec<DockerServiceRow>,
}

#[plugin_struct]
#[derive(Clone)]
#[serde(rename_all = "camelCase")]
pub struct DockerRuntimeRow {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub enabled: bool,
}

#[plugin_struct]
#[derive(Clone)]
pub struct DockerContainerStats {
    pub id: String,
    pub name: String,
    pub cpu_percent: f64,
    pub mem_usage_mb: u64,
    pub mem_limit_mb: u64,
    pub block_read_bytes: u64,
    pub block_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

fn map_engine(e: Engine) -> DockerEngineKind {
    match e {
        Engine::Colima => DockerEngineKind::Colima,
        Engine::Desktop => DockerEngineKind::Desktop,
        Engine::None => DockerEngineKind::None,
    }
}

fn list_runtime_rows() -> anyhow::Result<Vec<DockerRuntimeRow>> {
    let conn = db::open_default()?;
    Ok(db::docker_runtimes::list(&conn)?
        .into_iter()
        .map(|r| DockerRuntimeRow {
            name: r.name,
            socket_path: r.socket_path,
            host: r.host,
            url: r.url,
            enabled: r.enabled,
        })
        .collect())
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.list — primary resource = containers; runtime/engine surface alongside
// ═══════════════════════════════════════════════════════════════════════════

#[plugin_struct(args)]
#[serde(default)]
pub struct DockerListArgs {
    /// Single compose project path. Returns its services.
    #[arg(long)]
    pub path: Option<String>,
    /// Scan this directory for compose projects (default `$HOME/code`).
    /// Mutually exclusive with `path`.
    #[arg(long)]
    pub root: Option<String>,
}

#[plugin_struct]
#[derive(Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DockerListOutput {
    /// Local engine status (always populated).
    pub engine: DockerEngineStatus,
    /// Registered docker runtimes (always populated).
    pub runtimes: Vec<DockerRuntimeRow>,
    /// Services for a single project (`path` arg) — empty otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compose_file: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<DockerServiceRow>,
    /// Project scan results (`root` arg) — empty otherwise.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<DockerProjectRow>,
}

/// List docker resources on this host: local engine status + registered
/// runtimes always; plus compose services for `path` or a project scan for `root`.
#[orca_tool(domain = "docker", verb = "list")]
async fn docker_list(
    args: DockerListArgs,
    _ctx: &contract::ToolCtx,
) -> anyhow::Result<DockerListOutput> {
    if args.path.is_some() && args.root.is_some() {
        anyhow::bail!("pass either `path` or `root`, not both");
    }
    let s = crate::engine::status().await;
    let mut out = DockerListOutput {
        engine: DockerEngineStatus {
            engine: map_engine(s.engine),
            running: s.running,
        },
        runtimes: list_runtime_rows()?,
        ..Default::default()
    };

    if let Some(path) = args.path.as_deref() {
        if let Some(compose) = Compose::find(Path::new(path)) {
            let services = compose.services().await.map_err(anyhow::Error::from)?;
            out.compose_file = compose.file().to_str().map(str::to_string);
            out.services = services
                .into_iter()
                .map(|s| DockerServiceRow {
                    name: s.name,
                    state: s.state,
                    running: s.running,
                    health: s.health,
                    ports: s.ports,
                })
                .collect();
        }
    } else if let Some(root_arg) = args.root.as_deref() {
        let home = std::env::var("HOME").unwrap_or_default();
        let root = if root_arg.is_empty() {
            format!("{home}/code")
        } else {
            root_arg.to_string()
        };
        if let Ok(entries) = std::fs::read_dir(&root) {
            let project_dirs: Vec<PathBuf> = entries
                .flatten()
                .filter_map(|e| {
                    let p = e.path();
                    (p.is_dir() && Compose::find(&p).is_some()).then_some(p)
                })
                .collect();
            for project_path in project_dirs {
                let path_str = project_path.to_string_lossy().into_owned();
                let name = project_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path_str.clone());
                let services = match Compose::find(&project_path) {
                    None => Vec::new(),
                    Some(c) => c
                        .services()
                        .await
                        .map(|svcs| {
                            svcs.into_iter()
                                .map(|s| DockerServiceRow {
                                    name: s.name,
                                    state: s.state,
                                    running: s.running,
                                    health: s.health,
                                    ports: s.ports,
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                };
                out.projects.push(DockerProjectRow {
                    project: name,
                    path: path_str,
                    services,
                });
            }
        }
    }
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.detail — one compose project: logs + stats
// ═══════════════════════════════════════════════════════════════════════════

#[plugin_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct DockerDetailArgs {
    /// Compose project path.
    pub path: String,
    /// Optional service to scope logs.
    #[serde(default)]
    #[arg(long)]
    pub service: Option<String>,
    /// Tail length for logs (default 200).
    #[serde(default)]
    #[arg(long)]
    pub tail: Option<u32>,
}

#[plugin_struct]
#[serde(rename_all = "camelCase")]
pub struct DockerDetailOutput {
    pub compose_file: Option<String>,
    pub services: Vec<DockerServiceRow>,
    pub logs: String,
    pub stats: Vec<DockerContainerStats>,
}

#[orca_tool(domain = "docker", verb = "detail")]
async fn docker_detail(
    args: DockerDetailArgs,
    _ctx: &contract::ToolCtx,
) -> anyhow::Result<DockerDetailOutput> {
    let compose = Compose::find(Path::new(&args.path))
        .ok_or_else(|| anyhow::anyhow!("no compose file under {}", args.path))?;
    let tail = args.tail.unwrap_or(200);
    let svc = args.service.as_deref();
    let services_filter: Vec<&str> = svc.into_iter().collect();
    let logs = compose
        .logs(&services_filter, tail)
        .await
        .map_err(anyhow::Error::from)?;
    let services = compose
        .services()
        .await
        .map_err(anyhow::Error::from)?
        .into_iter()
        .map(|s| DockerServiceRow {
            name: s.name,
            state: s.state,
            running: s.running,
            health: s.health,
            ports: s.ports,
        })
        .collect();
    let stats = crate::containers::live_stats()
        .await?
        .into_iter()
        .map(|s| DockerContainerStats {
            id: s.id,
            name: s.name,
            cpu_percent: s.cpu_percent,
            mem_usage_mb: s.mem_usage_mb,
            mem_limit_mb: s.mem_limit_mb,
            block_read_bytes: s.block_read_bytes,
            block_write_bytes: s.block_write_bytes,
            net_rx_bytes: s.net_rx_bytes,
            net_tx_bytes: s.net_tx_bytes,
        })
        .collect();
    Ok(DockerDetailOutput {
        compose_file: compose.file().to_str().map(str::to_string),
        services,
        logs,
        stats,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.create — register a new docker runtime
// ═══════════════════════════════════════════════════════════════════════════

#[plugin_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct DockerCreateArgs {
    /// Runtime name (unique).
    #[arg(long)]
    pub runtime_name: String,
    #[arg(long)]
    pub socket_path: Option<String>,
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long)]
    pub url: Option<String>,
}

#[plugin_struct]
#[serde(rename_all = "camelCase")]
pub struct DockerCreateOutput {
    pub name: String,
}

/// [MUTATES STATE] Register a new docker runtime. Errors if `runtime_name`
/// already exists; use `docker.update` to modify.
#[orca_tool(domain = "docker", verb = "create")]
async fn docker_create(
    args: DockerCreateArgs,
    _ctx: &contract::ToolCtx,
) -> anyhow::Result<DockerCreateOutput> {
    if args.socket_path.is_none() && args.host.is_none() && args.url.is_none() {
        anyhow::bail!("runtime registration needs socket_path, host, or url");
    }
    let conn = db::open_default()?;
    if db::docker_runtimes::exists(&conn, &args.runtime_name)? {
        anyhow::bail!(
            "docker runtime '{}' already exists; use docker.update to modify",
            args.runtime_name
        );
    }
    let row = db::docker_runtimes::RuntimeRow {
        name: args.runtime_name.clone(),
        socket_path: args.socket_path,
        host: args.host,
        url: args.url,
        enabled: true,
    };
    db::docker_runtimes::insert(&conn, &row)?;
    Ok(DockerCreateOutput {
        name: args.runtime_name,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.update — engine start, runtime field updates, compose action
// ═══════════════════════════════════════════════════════════════════════════

#[plugin_struct(args)]
#[serde(rename_all = "camelCase", default)]
pub struct DockerUpdateArgs {
    /// Start the local docker engine (colima/desktop).
    #[arg(long)]
    pub engine_start: bool,

    /// Update an existing docker runtime — errors if name unknown.
    #[arg(long)]
    pub runtime_name: Option<String>,
    #[arg(long)]
    pub socket_path: Option<String>,
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long)]
    pub url: Option<String>,

    /// Run a compose lifecycle action. Set `path` and `action`.
    #[arg(long)]
    pub path: Option<String>,
    /// `up`, `down`, `restart`, `start`, `stop`, `build`, `pull`, `logs`.
    #[arg(long)]
    pub action: Option<String>,
    /// Scope the compose action to one service.
    #[arg(long)]
    pub service: Option<String>,
    #[arg(long)]
    pub tail: Option<u32>,
}

#[plugin_struct]
#[derive(Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DockerUpdateOutput {
    pub applied: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compose_file: Option<String>,
}

/// [MUTATES STATE] Combine any of: start the local engine, update an existing
/// docker runtime, run a compose action. Args determine which sub-operations
/// fire. Use `docker.create` to register a new runtime.
#[orca_tool(domain = "docker", verb = "update")]
async fn docker_update(
    args: DockerUpdateArgs,
    _ctx: &contract::ToolCtx,
) -> anyhow::Result<DockerUpdateOutput> {
    let mut out = DockerUpdateOutput::default();

    if args.engine_start {
        out.output = crate::engine::start().await?;
        out.applied.push("engine-start".into());
    }

    if let Some(name) = &args.runtime_name {
        if args.socket_path.is_none() && args.host.is_none() && args.url.is_none() {
            anyhow::bail!("runtime update needs socket_path, host, or url");
        }
        let row = db::docker_runtimes::RuntimeRow {
            name: name.clone(),
            socket_path: args.socket_path.clone(),
            host: args.host.clone(),
            url: args.url.clone(),
            enabled: true,
        };
        let conn = db::open_default()?;
        db::docker_runtimes::update(&conn, &row)?;
        out.applied.push(format!("runtime-updated:{name}"));
    }

    match (args.path.as_deref(), args.action.as_deref()) {
        (Some(path), Some(action)) => {
            let compose = Compose::find(Path::new(path))
                .ok_or_else(|| anyhow::anyhow!("no compose file under {path}"))?;
            let output = compose
                .run_action(action, args.service.as_deref(), args.tail)
                .await
                .map_err(|e| match e {
                    ComposeError::UnknownAction(a) => anyhow::anyhow!("unknown action: {a}"),
                    other => anyhow::Error::from(other),
                })?;
            if out.output.is_empty() {
                out.output = output;
            } else {
                out.output.push('\n');
                out.output.push_str(&output);
            }
            out.compose_file = compose.file().to_str().map(str::to_string);
            out.applied.push(format!("compose-{action}"));
        }
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!("compose action needs both `path` and `action`");
        }
        (None, None) => {}
    }

    if out.applied.is_empty() {
        anyhow::bail!("no docker.update operation specified");
    }
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.delete — remove a registered docker runtime
// ═══════════════════════════════════════════════════════════════════════════

#[plugin_struct(args)]
pub struct DockerDeleteArgs {
    /// Runtime name to remove.
    pub runtime: String,
}

#[plugin_struct]
pub struct DockerDeleteOutput {
    pub name: String,
    pub changed: bool,
}

#[orca_tool(domain = "docker", verb = "delete")]
async fn docker_delete(
    args: DockerDeleteArgs,
    _ctx: &contract::ToolCtx,
) -> anyhow::Result<DockerDeleteOutput> {
    let conn = db::open_default()?;
    let changed = db::docker_runtimes::remove(&conn, &args.runtime)?;
    Ok(DockerDeleteOutput {
        name: args.runtime,
        changed,
    })
}
