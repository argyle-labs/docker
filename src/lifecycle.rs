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

use std::path::{Component, Path, PathBuf};

use plugin_toolkit::prelude::*;
use plugin_toolkit::process::{Command, Output};

use crate::execute;

const INSTALL_TOOL: &str = "docker.install";
const ENGINE_UPDATE_TOOL: &str = "docker.engine_update";
const RESTORE_TOOL: &str = "docker.restore";

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

/// `bash -c` running an embedded lifecycle script with `name` as `$0`. Only
/// the embedded scripts ever run: a caller-supplied script path would execute
/// arbitrary code as the daemon user. The body is visible in `ps`, so never
/// put secrets in these scripts.
fn script_command(name: &str, embedded: &str, args: &[&str]) -> Command {
    Command::new("bash")
        .arg("-c")
        .arg(embedded)
        .arg(name)
        .args(args)
}

/// `path` with every existing prefix canonicalized and the not-yet-created tail
/// appended, so a symlink anywhere along it is resolved before the root check.
fn resolve(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("'{}' is not an absolute path", path.display());
    }
    if path.components().any(|c| c == Component::ParentDir) {
        bail!("'{}' contains '..'", path.display());
    }
    let mut existing = path;
    let mut tail = Vec::new();
    // `symlink_metadata` so a dangling symlink stops the walk and then fails
    // to canonicalize, rather than being treated as a fresh directory name.
    while existing.symlink_metadata().is_err() {
        let (Some(name), Some(parent)) = (existing.file_name(), existing.parent()) else {
            bail!("'{}' has no existing ancestor", path.display());
        };
        tail.push(name);
        existing = parent;
    }
    let mut out = existing
        .canonicalize()
        .with_context(|| format!("failed to resolve '{}'", existing.display()))?;
    out.extend(tail.iter().rev());
    Ok(out)
}

/// The engine state dir to restore into: `requested`, or the colima profile
/// dir by default, and in every case inside `$HOME/.colima` once resolved.
fn state_dir(requested: Option<&str>, home: &str) -> Result<PathBuf> {
    if home.is_empty() {
        bail!("HOME is unset, so the engine state root cannot be located");
    }
    let root = resolve(&Path::new(home).join(".colima"))?;
    let Some(requested) = requested else {
        return Ok(root);
    };
    let state = resolve(Path::new(requested))?;
    if !state.starts_with(&root) {
        bail!(
            "state path '{requested}' resolves to '{}', outside the engine state root '{}'",
            state.display(),
            root.display()
        );
    }
    Ok(state)
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
    /// Run the install. Omitted, returns what would run and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerInstallOutput {
    /// `true`: nothing ran.
    pub dry_run: bool,
    /// The script and runtime execute runs.
    pub plan: String,
    pub provisioned: bool,
    /// The script's stdout (execute only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// **Provision a container runtime on this host.** Runs `scripts/install.sh`,
/// which installs the requested runtime (docker engine, colima, or podman) via
/// the right method for this target — brew on macOS; apt/apk/pacman/dnf on
/// Linux; rpm-ostree layering on atomic hosts (Bazzite/Silverblue) — and starts
/// it. Idempotent: a present, running runtime is left untouched. Without
/// `execute`, returns what would run and changes nothing.
#[orca_tool(
    domain = "docker",
    verb = "install",
    local_only = true,
    role = "admin",
    execute_gated = false
)]
async fn docker_install(args: DockerInstallArgs, ctx: &ToolCtx) -> Result<DockerInstallOutput> {
    execute::guard(INSTALL_TOOL, args.execute, ctx)?;
    let runtime = args.runtime.as_arg();
    let plan = format!("run the embedded install.sh {runtime}");
    if !args.execute {
        return Ok(DockerInstallOutput {
            dry_run: true,
            plan,
            provisioned: false,
            log: None,
            how_to_execute: Some(format!("re-invoke {INSTALL_TOOL} with `execute: true`")),
        });
    }
    let output = run(script_command("install.sh", INSTALL_SH, &[runtime])).await?;
    Ok(DockerInstallOutput {
        dry_run: false,
        plan,
        provisioned: true,
        log: Some(String::from_utf8_lossy(&output.stdout).into_owned()),
        how_to_execute: None,
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
    /// Run the upgrade. Omitted, returns what would run and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerEngineUpdateOutput {
    /// `true`: nothing ran.
    pub dry_run: bool,
    /// The script and runtime execute runs.
    pub plan: String,
    pub updated: bool,
    /// The script's stdout (execute only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// **Upgrade a container runtime** on this host. Runs `scripts/update.sh`, which
/// bumps the runtime (docker engine, colima/lima, or podman) to the latest
/// available release and restarts the daemon. Distinct from `docker.update`,
/// which runs compose lifecycle actions against deployed stacks. Without
/// `execute`, returns what would run and changes nothing.
#[orca_tool(
    domain = "docker",
    verb = "engine_update",
    local_only = true,
    role = "admin",
    execute_gated = false
)]
async fn docker_engine_update(
    args: DockerEngineUpdateArgs,
    ctx: &ToolCtx,
) -> Result<DockerEngineUpdateOutput> {
    execute::guard(ENGINE_UPDATE_TOOL, args.execute, ctx)?;
    let runtime = args.runtime.as_arg();
    let plan = format!("run the embedded update.sh {runtime}");
    if !args.execute {
        return Ok(DockerEngineUpdateOutput {
            dry_run: true,
            plan,
            updated: false,
            log: None,
            how_to_execute: Some(format!(
                "re-invoke {ENGINE_UPDATE_TOOL} with `execute: true`"
            )),
        });
    }
    let output = run(script_command("update.sh", UPDATE_SH, &[runtime])).await?;
    Ok(DockerEngineUpdateOutput {
        dry_run: false,
        plan,
        updated: true,
        log: Some(String::from_utf8_lossy(&output.stdout).into_owned()),
        how_to_execute: None,
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
    /// Absolute host path of the colima state dir to restore into (default
    /// `$HOME/.colima`). Must resolve, symlinks included, inside
    /// `$HOME/.colima`.
    #[arg(long)]
    #[serde(default)]
    pub state_path: Option<String>,
    /// Run the restore. Omitted, validates the paths, returns what would run
    /// and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerRestoreOutput {
    /// `true`: nothing ran.
    pub dry_run: bool,
    pub restored: bool,
    /// Resolved host path the state is (or would be) restored into.
    pub state_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// **Restore the engine's persistent state** from a `.tar.gz` produced by
/// `docker.backup`, unpacking it into the colima/lima profile dir (or a supplied
/// state path inside it). Pair with `docker.install` to rebuild a host from a
/// backup. Without `execute`, returns what would run and changes nothing.
#[orca_tool(
    domain = "docker",
    verb = "restore",
    local_only = true,
    role = "admin",
    execute_gated = false
)]
async fn docker_restore(args: DockerRestoreArgs, ctx: &ToolCtx) -> Result<DockerRestoreOutput> {
    let home = std::env::var("HOME").unwrap_or_default();
    restore(args, &home, ctx).await
}

async fn restore(
    args: DockerRestoreArgs,
    home: &str,
    ctx: &ToolCtx,
) -> Result<DockerRestoreOutput> {
    execute::guard(RESTORE_TOOL, args.execute, ctx)?;
    if !Path::new(&args.archive).is_file() {
        bail!("archive '{}' is not a file", args.archive);
    }
    let state = state_dir(args.state_path.as_deref(), home)?;
    let state_path = state.to_string_lossy().into_owned();
    if !args.execute {
        return Ok(DockerRestoreOutput {
            dry_run: true,
            restored: false,
            state_path,
            how_to_execute: Some(format!("re-invoke {RESTORE_TOOL} with `execute: true`")),
        });
    }
    run(script_command(
        "restore.sh",
        RESTORE_SH,
        &[&args.archive, &state_path],
    ))
    .await?;
    Ok(DockerRestoreOutput {
        dry_run: false,
        restored: true,
        state_path,
        how_to_execute: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::contract::{CallerIdentity, OrcaToolDef};

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
                state_path: None,
                execute: false,
            };
            let err = docker_restore(args, &test_ctx()).await.unwrap_err();
            assert!(err.to_string().contains("is not a file"), "{err}");
        });
    }

    #[test]
    fn lifecycle_verbs_require_admin_and_own_their_execute_flag() {
        fn admin_self_gated<T: OrcaToolDef>() {
            assert_eq!(T::REQUIRED_ROLE, "admin", "{}", T::NAME);
            assert!(!T::EXECUTE_GATED, "{}", T::NAME);
            assert!(T::LOCAL_ONLY, "{}", T::NAME);
        }
        admin_self_gated::<DockerInstall>();
        admin_self_gated::<DockerEngineUpdate>();
        admin_self_gated::<DockerRestore>();
    }

    #[test]
    fn lifecycle_args_accept_no_script_path() {
        fn properties<T: plugin_toolkit::schemars::JsonSchema>() -> Vec<String> {
            let schema =
                plugin_toolkit::serde_json::to_value(plugin_toolkit::schemars::schema_for!(T))
                    .unwrap();
            let mut keys: Vec<String> = schema["properties"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect();
            keys.sort();
            keys
        }
        assert_eq!(properties::<DockerInstallArgs>(), ["execute", "runtime"]);
        assert_eq!(
            properties::<DockerEngineUpdateArgs>(),
            ["execute", "runtime"]
        );
        assert_eq!(
            properties::<DockerRestoreArgs>(),
            ["archive", "execute", "state_path"]
        );
    }

    #[test]
    fn install_and_engine_update_dry_run_by_default() {
        plugin_toolkit::reactor::block_on(async {
            let args: DockerInstallArgs =
                plugin_toolkit::serde_json::from_value(plugin_toolkit::serde_json::json!({}))
                    .unwrap();
            assert!(!args.execute);
            let out = docker_install(args, &test_ctx()).await.unwrap();
            assert!(out.dry_run && !out.provisioned && out.log.is_none());
            assert_eq!(out.plan, "run the embedded install.sh colima");

            let args = DockerEngineUpdateArgs {
                runtime: ContainerRuntime::Podman,
                execute: false,
            };
            let out = docker_engine_update(args, &test_ctx()).await.unwrap();
            assert!(out.dry_run && !out.updated && out.log.is_none());
            assert_eq!(out.plan, "run the embedded update.sh podman");
        });
    }

    #[test]
    fn execute_without_an_admin_caller_runs_nothing() {
        plugin_toolkit::reactor::block_on(async {
            let args = DockerInstallArgs {
                runtime: ContainerRuntime::Colima,
                execute: true,
            };
            let err = docker_install(args, &test_ctx()).await.unwrap_err();
            assert!(err.to_string().contains("no caller identity"), "{err}");
            let args = DockerEngineUpdateArgs {
                runtime: ContainerRuntime::Colima,
                execute: true,
            };
            let ctx = test_ctx().with_auth(caller("user"));
            let err = docker_engine_update(args, &ctx).await.unwrap_err();
            assert!(err.to_string().contains("requires role 'admin'"), "{err}");
        });
    }

    #[test]
    fn restore_dry_run_and_refused_execute_leave_no_state() {
        let (work, archive) = state_archive();
        let home = work.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let home = home.to_str().unwrap();
        let args = |execute| DockerRestoreArgs {
            archive: archive.to_str().unwrap().to_string(),
            state_path: None,
            execute,
        };
        plugin_toolkit::reactor::block_on(async {
            let out = restore(args(false), home, &test_ctx()).await.unwrap();
            assert!(out.dry_run && !out.restored && out.how_to_execute.is_some());
            assert!(out.state_path.ends_with(".colima"), "{}", out.state_path);
            let err = restore(args(true), home, &test_ctx()).await.unwrap_err();
            assert!(err.to_string().contains("no caller identity"), "{err}");
        });
        assert!(!Path::new(home).join(".colima").exists());
    }

    #[test]
    fn restore_executes_for_an_admin_into_the_state_root() {
        let (work, archive) = state_archive();
        let home = work.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let target = home.join(".colima").join("default");
        let args = DockerRestoreArgs {
            archive: archive.to_str().unwrap().to_string(),
            state_path: Some(target.to_str().unwrap().to_string()),
            execute: true,
        };
        let ctx = test_ctx().with_auth(caller("admin"));
        let out =
            plugin_toolkit::reactor::block_on(restore(args, home.to_str().unwrap(), &ctx)).unwrap();
        assert!(!out.dry_run && out.restored);
        let restored = std::fs::read(Path::new(&out.state_path).join("marker")).unwrap();
        assert_eq!(restored, b"state");
    }

    #[test]
    fn state_dir_defaults_to_the_colima_root() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().canonicalize().unwrap().join(".colima");
        assert_eq!(
            state_dir(None, home.path().to_str().unwrap()).unwrap(),
            root
        );
        let nested = home.path().join(".colima/profiles/default");
        assert_eq!(
            state_dir(nested.to_str(), home.path().to_str().unwrap()).unwrap(),
            root.join("profiles/default")
        );
    }

    #[test]
    fn state_dir_refuses_paths_outside_the_root() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path().to_str().unwrap();
        let err = |p: &str| state_dir(Some(p), h).unwrap_err().to_string();
        assert!(err("relative/.colima").contains("not an absolute path"));
        assert!(err(&format!("{h}/.colima/../.ssh")).contains("contains '..'"));
        assert!(err("/etc").contains("outside the engine state root"));
        assert!(err(&format!("{h}/.colimax")).contains("outside the engine state root"));
        assert!(state_dir(None, "").is_err());
    }

    #[test]
    fn state_dir_refuses_a_symlink_escaping_the_root() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = home.path().join(".colima");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("escape")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("missing"), root.join("dangling")).unwrap();
        let h = home.path().to_str().unwrap();
        let escape = root.join("escape/sub");
        let err = state_dir(escape.to_str(), h).unwrap_err();
        assert!(
            err.to_string().contains("outside the engine state root"),
            "{err}"
        );
        let dangling = root.join("dangling");
        assert!(state_dir(dangling.to_str(), h).is_err());
    }

    #[test]
    fn restore_runs_the_embedded_script_from_a_foreign_working_dir() {
        let (work, archive) = state_archive();
        // No `scripts/` here: a repo-relative path would fail to resolve.
        let foreign = tempfile::tempdir().unwrap();
        assert!(!foreign.path().join("scripts").exists());
        let state = work.path().join("restored");
        let cmd = script_command(
            "restore.sh",
            RESTORE_SH,
            &[archive.to_str().unwrap(), state.to_str().unwrap()],
        )
        .current_dir(foreign.path());
        let out = plugin_toolkit::reactor::block_on(run(cmd)).unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("restored engine state"));
        assert_eq!(std::fs::read(state.join("marker")).unwrap(), b"state");
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

    /// A tempdir holding `state.tar.gz` of a single `marker` file.
    fn state_archive() -> (tempfile::TempDir, PathBuf) {
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
        (work, archive)
    }

    fn caller(role: &str) -> CallerIdentity {
        CallerIdentity {
            user_id: "u".into(),
            username: "op".into(),
            role: role.into(),
            can_mutate: true,
        }
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
