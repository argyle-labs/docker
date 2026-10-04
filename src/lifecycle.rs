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
//! the orca `process` seam (the `reactor` feature); the plugin names no runtime.
#![allow(clippy::disallowed_types)]

use plugin_toolkit::prelude::*;
use plugin_toolkit::process::{Command, Output};

/// Which container runtime the lifecycle tools install/upgrade on this host.
/// The scripts map each variant onto the right per-target install method
/// (macOS/brew, apt/apk/pacman/dnf, or rpm-ostree layering on atomic hosts).
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
pub enum ContainerRuntime {
    /// colima (lima-backed) — provides dockerd on macOS and headless hosts.
    #[default]
    Colima,
    /// Docker Engine proper (`docker-ce` / distro `docker`); on macOS this is
    /// backed by colima since there is no native daemon.
    Docker,
    /// Podman — daemonless, rootless; preinstalled on atomic distros.
    Podman,
}

impl ContainerRuntime {
    /// The argument passed to `scripts/install.sh` / `scripts/update.sh`.
    fn as_arg(self) -> &'static str {
        match self {
            ContainerRuntime::Colima => "colima",
            ContainerRuntime::Docker => "docker",
            ContainerRuntime::Podman => "podman",
        }
    }
}

// Embedded so the tools work from any working directory: the daemon's cwd is
// not the plugin checkout, and the install dir ships only the binary.
const INSTALL_SH: &str = include_str!("../scripts/install.sh");
const UPDATE_SH: &str = include_str!("../scripts/update.sh");
const RESTORE_SH: &str = include_str!("../scripts/restore.sh");

/// `bash` running a lifecycle script: the operator's `override_path` when
/// given, else the embedded copy via `bash -c` with `name` as `$0`. The
/// embedded body is visible in `ps`, so never put secrets in these scripts.
fn script_command(
    name: &str,
    embedded: &str,
    override_path: Option<&str>,
    args: &[&str],
) -> Command {
    let cmd = match override_path {
        Some(path) => Command::new("bash").arg(path),
        None => Command::new("bash").arg("-c").arg(embedded).arg(name),
    };
    cmd.args(args)
}

async fn run(cmd: Command) -> Result<Output> {
    let output = cmd
        .output()
        .await
        .with_context(|| "failed to spawn command".to_string())?;
    if !output.status.success {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "command failed ({:?}): {}",
            output.status.code,
            stderr.trim()
        );
    }
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.install — provision + start the engine on this host
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
pub struct DockerInstallArgs {
    /// Container runtime to provision.
    #[arg(long, value_enum, default_value_t = ContainerRuntime::Colima)]
    #[serde(default)]
    pub runtime: ContainerRuntime,
    /// Path to a bootstrap script to run instead of the `scripts/install.sh`
    /// embedded in the plugin.
    #[arg(long)]
    #[serde(default)]
    pub bootstrap_path: Option<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerInstallOutput {
    pub provisioned: bool,
    pub log: String,
}

/// **Provision a container runtime on this host.** Runs `scripts/install.sh`,
/// which installs the requested runtime (docker engine, colima, or podman) via
/// the right method for this target — brew on macOS; apt/apk/pacman/dnf on
/// Linux; rpm-ostree layering on atomic hosts (Bazzite/Silverblue) — and starts
/// it. Idempotent: a present, running runtime is left untouched.
#[orca_tool(domain = "docker", verb = "install", local_only = true)]
async fn docker_install(args: DockerInstallArgs, _ctx: &ToolCtx) -> Result<DockerInstallOutput> {
    let output = run(script_command(
        "install.sh",
        INSTALL_SH,
        args.bootstrap_path.as_deref(),
        &[args.runtime.as_arg()],
    ))
    .await?;
    Ok(DockerInstallOutput {
        provisioned: true,
        log: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.engine_update — upgrade the engine package / colima image
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
pub struct DockerEngineUpdateArgs {
    /// Container runtime to upgrade.
    #[arg(long, value_enum, default_value_t = ContainerRuntime::Colima)]
    #[serde(default)]
    pub runtime: ContainerRuntime,
    /// Path to an update script to run instead of the embedded
    /// `scripts/update.sh`.
    #[arg(long)]
    #[serde(default)]
    pub bootstrap_path: Option<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerEngineUpdateOutput {
    pub updated: bool,
    pub log: String,
}

/// **Upgrade a container runtime** on this host. Runs `scripts/update.sh`, which
/// bumps the runtime (docker engine, colima/lima, or podman) to the latest
/// available release and restarts the daemon. Distinct from `docker.update`,
/// which runs compose lifecycle actions against deployed stacks.
#[orca_tool(domain = "docker", verb = "engine_update", local_only = true)]
async fn docker_engine_update(
    args: DockerEngineUpdateArgs,
    _ctx: &ToolCtx,
) -> Result<DockerEngineUpdateOutput> {
    let output = run(script_command(
        "update.sh",
        UPDATE_SH,
        args.bootstrap_path.as_deref(),
        &[args.runtime.as_arg()],
    ))
    .await?;
    Ok(DockerEngineUpdateOutput {
        updated: true,
        log: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.backup — archive the engine's persistent state
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
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

#[orca_struct]
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
    let stamp = plugin_toolkit::time::now().compact();
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

// ═══════════════════════════════════════════════════════════════════════════
// docker.restore — restore engine state from a backup archive
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
pub struct DockerRestoreArgs {
    /// Path to a `.tar.gz` produced by `docker.backup`.
    #[arg(long)]
    pub archive: String,
    /// Host path of the docker/colima state dir to restore into
    /// (default `$HOME/.colima`).
    #[arg(long)]
    #[serde(default)]
    pub state_path: Option<String>,
    /// Path to a restore script to run instead of the embedded
    /// `scripts/restore.sh`.
    #[arg(long)]
    #[serde(default)]
    pub bootstrap_path: Option<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerRestoreOutput {
    pub restored: bool,
    /// Host path the state was restored into.
    pub state_path: String,
}

/// **Restore the engine's persistent state** from a `.tar.gz` produced by
/// `docker.backup`, unpacking it into the colima/lima profile dir (or a supplied
/// state path). Pair with `docker.install` to rebuild a host from a backup.
#[orca_tool(domain = "docker", verb = "restore", local_only = true)]
async fn docker_restore(args: DockerRestoreArgs, _ctx: &ToolCtx) -> Result<DockerRestoreOutput> {
    if !std::path::Path::new(&args.archive).is_file() {
        bail!("archive '{}' is not a file", args.archive);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let state = args
        .state_path
        .clone()
        .unwrap_or_else(|| format!("{home}/.colima"));
    run(script_command(
        "restore.sh",
        RESTORE_SH,
        args.bootstrap_path.as_deref(),
        &[&args.archive, &state],
    ))
    .await?;
    Ok(DockerRestoreOutput {
        restored: true,
        state_path: state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_rejects_missing_state_dir() {
        plugin_toolkit::reactor::block_on(async {
            let args = DockerBackupArgs {
                destination: "/tmp/docker-bk-dest".to_string(),
                state_path: Some("/nonexistent/docker/state".to_string()),
            };
            let err = docker_backup(args, &test_ctx()).await.unwrap_err();
            assert!(err.to_string().contains("not a directory"), "{err}");
        });
    }

    #[test]
    fn restore_rejects_missing_archive() {
        plugin_toolkit::reactor::block_on(async {
            let args = DockerRestoreArgs {
                archive: "/nonexistent/docker-state.tar.gz".to_string(),
                state_path: Some("/tmp/docker-restore-dest".to_string()),
                bootstrap_path: None,
            };
            let err = docker_restore(args, &test_ctx()).await.unwrap_err();
            assert!(err.to_string().contains("is not a file"), "{err}");
        });
    }

    #[test]
    fn restore_runs_the_embedded_script_from_a_foreign_working_dir() {
        let work = tempfile::tempdir().unwrap();
        let src = work.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("marker"), b"state").unwrap();
        let archive = work.path().join("state.tar.gz");
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&src)
            .arg(".")
            .status()
            .unwrap();
        assert!(status.success());

        // No `scripts/` here: a repo-relative path would fail to resolve.
        let foreign = tempfile::tempdir().unwrap();
        assert!(!foreign.path().join("scripts").exists());
        let state = work.path().join("restored");
        let cmd = script_command(
            "restore.sh",
            RESTORE_SH,
            None,
            &[archive.to_str().unwrap(), state.to_str().unwrap()],
        )
        .current_dir(foreign.path());
        let out = plugin_toolkit::reactor::block_on(run(cmd)).unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("restored engine state"));
        assert_eq!(std::fs::read(state.join("marker")).unwrap(), b"state");
    }

    #[test]
    fn bootstrap_path_override_runs_the_given_script() {
        let foreign = tempfile::tempdir().unwrap();
        let script = foreign.path().join("custom.sh");
        std::fs::write(&script, "echo \"custom $1\"\n").unwrap();
        let cmd = script_command("install.sh", INSTALL_SH, script.to_str(), &["podman"]);
        let out = plugin_toolkit::reactor::block_on(run(cmd)).unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "custom podman");
    }

    #[test]
    fn embedded_scripts_are_the_shipped_ones() {
        let shipped = |name: &str| {
            std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("scripts")
                    .join(name),
            )
            .unwrap()
        };
        assert_eq!(INSTALL_SH, shipped("install.sh"));
        assert_eq!(UPDATE_SH, shipped("update.sh"));
        assert_eq!(RESTORE_SH, shipped("restore.sh"));
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
