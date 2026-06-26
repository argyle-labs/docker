//! Docker engine lifecycle tool surface.
//!
//! Net-new over the inventory/compose surface: these `#[orca_tool]`s own the
//! deploy lifecycle of the **docker engine itself** on a host — provision
//! (install + start), update (upgrade the engine package / image set), and
//! back up the engine's persistent state (registered runtimes + colima VM
//! profile). Unlike a media server, docker is not a containerized workload, so
//! the lifecycle here drives the host package manager (`apt`/`brew`) and
//! `colima` rather than `docker run` against an image of itself.
//!
//! Imports flow through `plugin_toolkit::prelude::*` only. Process exec uses
//! the toolkit's re-exported `tokio`.
#![allow(clippy::disallowed_types)]

use std::process::Output;

use plugin_toolkit::prelude::*;
use plugin_toolkit::tokio::process::Command;

/// Which engine flavor the lifecycle tools target on this host.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    plugin_toolkit::serde::Serialize,
    plugin_toolkit::serde::Deserialize,
    plugin_toolkit::schemars::JsonSchema,
    plugin_toolkit::clap::ValueEnum,
)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "lowercase")]
pub enum EngineFlavor {
    /// colima (lima-backed) — the default for headless Linux/macOS hosts.
    #[default]
    Colima,
    /// Docker Engine via the distro package (`docker-ce`).
    Engine,
}

async fn run(cmd: &mut Command) -> Result<Output> {
    let output = cmd
        .output()
        .await
        .with_context(|| "failed to spawn command".to_string())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("command failed ({}): {}", output.status, stderr.trim());
    }
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.install — provision + start the engine on this host
// ═══════════════════════════════════════════════════════════════════════════

#[plugin_struct(args)]
pub struct DockerInstallArgs {
    /// Engine flavor to provision.
    #[arg(long, value_enum, default_value_t = EngineFlavor::Colima)]
    #[serde(default)]
    pub flavor: EngineFlavor,
    /// Path to the bootstrap script. Defaults to the repo-relative
    /// `scripts/install.sh`; override for a non-standard layout.
    #[arg(long)]
    #[serde(default)]
    pub bootstrap_path: Option<String>,
}

#[plugin_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerInstallOutput {
    pub provisioned: bool,
    pub log: String,
}

/// **Provision the docker engine on this host.** Runs `scripts/install.sh`,
/// which installs colima (or Docker Engine) via the host package manager and
/// starts it. Idempotent: a present, running engine is left untouched.
#[orca_tool(domain = "docker", verb = "install", local_only = true)]
async fn docker_install(args: DockerInstallArgs, _ctx: &ToolCtx) -> Result<DockerInstallOutput> {
    let script = args
        .bootstrap_path
        .clone()
        .unwrap_or_else(|| "scripts/install.sh".to_string());
    let flavor = match args.flavor {
        EngineFlavor::Colima => "colima",
        EngineFlavor::Engine => "engine",
    };
    let output = run(Command::new("bash").arg(&script).arg(flavor)).await?;
    Ok(DockerInstallOutput {
        provisioned: true,
        log: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.engine_update — upgrade the engine package / colima image
// ═══════════════════════════════════════════════════════════════════════════

#[plugin_struct(args)]
pub struct DockerEngineUpdateArgs {
    /// Engine flavor to upgrade.
    #[arg(long, value_enum, default_value_t = EngineFlavor::Colima)]
    #[serde(default)]
    pub flavor: EngineFlavor,
    /// Path to the update script. Defaults to `scripts/update.sh`.
    #[arg(long)]
    #[serde(default)]
    pub bootstrap_path: Option<String>,
}

#[plugin_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerEngineUpdateOutput {
    pub updated: bool,
    pub log: String,
}

/// **Upgrade the docker engine** on this host. Runs `scripts/update.sh`, which
/// bumps the engine package (or colima/lima) to the latest available release
/// and restarts the daemon. Distinct from `docker.update`, which runs compose
/// lifecycle actions against deployed stacks.
#[orca_tool(domain = "docker", verb = "engine_update", local_only = true)]
async fn docker_engine_update(
    args: DockerEngineUpdateArgs,
    _ctx: &ToolCtx,
) -> Result<DockerEngineUpdateOutput> {
    let script = args
        .bootstrap_path
        .clone()
        .unwrap_or_else(|| "scripts/update.sh".to_string());
    let flavor = match args.flavor {
        EngineFlavor::Colima => "colima",
        EngineFlavor::Engine => "engine",
    };
    let output = run(Command::new("bash").arg(&script).arg(flavor)).await?;
    Ok(DockerEngineUpdateOutput {
        updated: true,
        log: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.backup — archive the engine's persistent state
// ═══════════════════════════════════════════════════════════════════════════

#[plugin_struct(args)]
pub struct DockerBackupArgs {
    /// Directory to write the `.tar.gz` into. Created if missing.
    #[arg(long)]
    pub destination: String,
    /// Host path of the docker/colima state dir to archive
    /// (default `$HOME/.colima`).
    #[arg(long)]
    #[serde(default)]
    pub state_path: Option<String>,
}

#[plugin_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerBackupOutput {
    /// Absolute path of the archive written.
    pub archive: String,
}

/// **Back up the engine's persistent state** (the colima/lima profile dir, or a
/// supplied state path) to a `.tar.gz` in the destination directory. Captures
/// the engine VM profile + config so a reprovisioned host can be restored.
#[orca_tool(domain = "docker", verb = "backup", local_only = true)]
async fn docker_backup(args: DockerBackupArgs, _ctx: &ToolCtx) -> Result<DockerBackupOutput> {
    let home = std::env::var("HOME").unwrap_or_default();
    let state = args
        .state_path
        .clone()
        .unwrap_or_else(|| format!("{home}/.colima"));
    if !std::path::Path::new(&state).is_dir() {
        bail!("state path '{state}' is not a directory");
    }
    run(Command::new("mkdir").arg("-p").arg(&args.destination)).await?;
    let stamp = plugin_toolkit::chrono::Utc::now()
        .format("%Y%m%d-%H%M%S")
        .to_string();
    let archive = format!(
        "{}/docker-engine-state-{}.tar.gz",
        args.destination.trim_end_matches('/'),
        stamp
    );
    run(Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(&state)
        .arg("."))
    .await?;
    Ok(DockerBackupOutput { archive })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::tokio;

    #[plugin_toolkit::tokio::test]
    async fn backup_rejects_missing_state_dir() {
        let args = DockerBackupArgs {
            destination: "/tmp/docker-bk-dest".to_string(),
            state_path: Some("/nonexistent/docker/state".to_string()),
        };
        let err = docker_backup(args, &test_ctx()).await.unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    fn test_ctx() -> ToolCtx {
        use plugin_toolkit::contract::config::{Config, Model, Ports};
        use std::sync::Arc;
        ToolCtx::new(Arc::new(Config {
            anthropic_api_key: None,
            lmstudio_url: String::new(),
            ollama_url: String::new(),
            default_model: Model::LMStudio {
                id: String::new(),
                url: String::new(),
            },
            app_dir: std::env::temp_dir(),
            memory_root: std::env::temp_dir(),
            db_path: std::env::temp_dir().join("orca-test.db"),
            ports: Ports::default(),
        }))
    }
}
