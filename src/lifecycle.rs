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

use crate::{engine_state, execute};

const INSTALL_TOOL: &str = "docker.install";
const ENGINE_UPDATE_TOOL: &str = "docker.engine_update";
const BACKUP_TOOL: &str = "docker.backup";
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
pub(crate) fn resolve(path: &Path) -> Result<PathBuf> {
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

/// The engine state dir to back up or restore into: `requested`, or the colima
/// profile dir by default, and in every case inside `$HOME/.colima` once
/// resolved.
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

/// `requested` resolved, refused unless it lies inside one of `roots`: the
/// daemon's backup roots, which a caller cannot widen.
pub(crate) fn in_backup_root(requested: &str, roots: &[String]) -> Result<PathBuf> {
    let dest = resolve(Path::new(requested))?;
    let allowed: Vec<PathBuf> = roots
        .iter()
        .filter_map(|r| resolve(Path::new(r)).ok())
        .collect();
    if !allowed.iter().any(|root| dest.starts_with(root)) {
        bail!(
            "'{requested}' resolves to '{}', outside the backup roots ({}); set {} on the daemon to allow another root",
            dest.display(),
            roots.join(", "),
            engine_state::BACKUP_ROOTS_ENV
        );
    }
    Ok(dest)
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
    execute::require_admin(INSTALL_TOOL, ctx)?;
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
/// which patches a registered runtime. Without `execute`, returns what would
/// run and changes nothing.
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
    execute::require_admin(ENGINE_UPDATE_TOOL, ctx)?;
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
    /// Absolute directory to write the `.tar.gz` into, created if missing.
    /// Must resolve, symlinks included, inside one of the daemon's backup
    /// roots (`ORCA_DOCKER_BACKUP_ROOTS`, else `/mnt/backups`).
    #[arg(long)]
    pub destination: String,
    /// Absolute host path of the colima state dir to archive (default
    /// `$HOME/.colima`). Must resolve inside `$HOME/.colima`.
    #[arg(long)]
    #[serde(default)]
    pub state_path: Option<String>,
    /// Write the archive. Omitted, validates the paths, returns what would
    /// run and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerBackupOutput {
    /// `true`: nothing was written.
    pub dry_run: bool,
    /// Resolved directory the archive is (or would be) written into.
    pub destination: String,
    /// Resolved state dir that is (or would be) archived.
    pub state_path: String,
    /// Absolute path of the archive written, mode 0600 (execute only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<String>,
    /// State entries left out of the archive, with the reason.
    pub excluded: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// **Back up the engine's persistent state** (the colima/lima profile dir, or a
/// supplied state path inside it) to a `.tar.gz` in the destination directory.
/// Captures the engine VM profile + config so a reprovisioned host can be
/// restored. Without `execute`, returns what would run and changes nothing.
#[orca_tool(
    domain = "docker",
    verb = "backup",
    local_only = true,
    role = "admin",
    execute_gated = false
)]
async fn docker_backup(args: DockerBackupArgs, ctx: &ToolCtx) -> Result<DockerBackupOutput> {
    let home = std::env::var("HOME").unwrap_or_default();
    backup(args, &home, &engine_state::backup_roots(), ctx).await
}

async fn backup(
    args: DockerBackupArgs,
    home: &str,
    roots: &[String],
    ctx: &ToolCtx,
) -> Result<DockerBackupOutput> {
    execute::require_admin(BACKUP_TOOL, ctx)?;
    let state = state_dir(args.state_path.as_deref(), home)?;
    if !state.is_dir() {
        bail!("state path '{}' is not a directory", state.display());
    }
    let root = state_dir(None, home)?;
    let destination = in_backup_root(&args.destination, roots)?;
    let state_path = state.to_string_lossy().into_owned();
    if !args.execute {
        let (_, excluded) = engine_state::members(&state, &root)?;
        return Ok(DockerBackupOutput {
            dry_run: true,
            destination: destination.to_string_lossy().into_owned(),
            state_path,
            archive: None,
            excluded,
            how_to_execute: Some(format!("re-invoke {BACKUP_TOOL} with `execute: true`")),
        });
    }
    std::fs::create_dir_all(&destination)
        .with_context(|| format!("failed to create '{}'", destination.display()))?;
    // A path component swapped for a symlink while the dir was created would
    // move the write; resolve again now that it exists.
    let created = in_backup_root(&args.destination, roots)?;
    if created != destination {
        bail!(
            "destination '{}' moved to '{}' while it was created",
            destination.display(),
            created.display()
        );
    }
    let stamp = plugin_toolkit::time::now().compact();
    let (archive, excluded) = engine_state::pack(&state, &root, &destination, &stamp)?;
    Ok(DockerBackupOutput {
        dry_run: false,
        destination: destination.to_string_lossy().into_owned(),
        state_path,
        archive: Some(archive.to_string_lossy().into_owned()),
        excluded,
        how_to_execute: None,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.restore — restore engine state from a backup archive
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
pub struct DockerRestoreArgs {
    /// Absolute path to a `.tar.gz` produced by `docker.backup`, inside one of
    /// the daemon's backup roots.
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
    /// The replaced state dir, when it could not be removed after the swap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leftover: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// **Restore the engine's persistent state** from a `.tar.gz` produced by
/// `docker.backup`, unpacking it into the colima/lima profile dir (or a supplied
/// state path inside it). Pair with `docker.install` to rebuild a host from a
/// backup. An archive with any entry that could land outside the state dir is
/// refused, as is a state dir already holding a symlink that leaves it.
/// Without `execute`, returns what would run and changes nothing.
#[orca_tool(
    domain = "docker",
    verb = "restore",
    local_only = true,
    role = "admin",
    execute_gated = false
)]
async fn docker_restore(args: DockerRestoreArgs, ctx: &ToolCtx) -> Result<DockerRestoreOutput> {
    let home = std::env::var("HOME").unwrap_or_default();
    restore(args, &home, &engine_state::backup_roots(), ctx).await
}

async fn restore(
    args: DockerRestoreArgs,
    home: &str,
    roots: &[String],
    ctx: &ToolCtx,
) -> Result<DockerRestoreOutput> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    execute::require_admin(RESTORE_TOOL, ctx)?;
    let archive = in_backup_root(&args.archive, roots)?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&archive)
        .with_context(|| format!("archive '{}' cannot be opened", args.archive))?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        bail!("archive '{}' is not a file", args.archive);
    }
    // The file read from here on is this descriptor: it must be the file that
    // was resolved inside the root, and still lie inside it by its own path.
    let at_path = std::fs::symlink_metadata(&archive)?;
    if (opened.dev(), opened.ino()) != (at_path.dev(), at_path.ino()) {
        bail!("archive '{}' changed while it was opened", args.archive);
    }
    let real = engine_state::fd_path(&file)?;
    in_backup_root(&real.to_string_lossy(), roots)?;
    let state = state_dir(args.state_path.as_deref(), home)?;
    let outward = engine_state::outward_links(&state)?;
    if !outward.is_empty() {
        bail!(
            "state dir '{}' holds symlinks leading outside it: {}",
            state.display(),
            outward.join(", ")
        );
    }
    engine_state::validate(&mut file)?;
    let state_path = state.to_string_lossy().into_owned();
    if !args.execute {
        return Ok(DockerRestoreOutput {
            dry_run: true,
            restored: false,
            state_path,
            leftover: None,
            how_to_execute: Some(format!("re-invoke {RESTORE_TOOL} with `execute: true`")),
        });
    }
    if let Some(parent) = state.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create '{}'", parent.display()))?;
    }
    if state_dir(args.state_path.as_deref(), home)? != state {
        bail!("state dir '{}' moved while it was created", state.display());
    }
    let leftover = engine_state::restore_into(&mut file, &state)?;
    Ok(DockerRestoreOutput {
        dry_run: false,
        restored: true,
        state_path,
        leftover: leftover.map(|p| p.to_string_lossy().into_owned()),
        how_to_execute: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::contract::{CallerIdentity, OrcaToolDef};
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn block<F: std::future::Future>(f: F) -> F::Output {
        plugin_toolkit::reactor::block_on(f)
    }

    fn s(p: &Path) -> String {
        p.to_str().unwrap().to_string()
    }

    #[test]
    fn lifecycle_verbs_require_admin_and_own_their_execute_flag() {
        // LOCAL_ONLY is not asserted: it is compile-time metadata the host
        // does not enforce for plugin tools.
        fn admin_self_gated<T: OrcaToolDef>() {
            assert_eq!(T::REQUIRED_ROLE, "admin", "{}", T::NAME);
            assert!(!T::EXECUTE_GATED, "{}", T::NAME);
        }
        admin_self_gated::<DockerInstall>();
        admin_self_gated::<DockerEngineUpdate>();
        admin_self_gated::<DockerBackup>();
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
            properties::<DockerBackupArgs>(),
            ["destination", "execute", "state_path"]
        );
        assert_eq!(
            properties::<DockerRestoreArgs>(),
            ["archive", "execute", "state_path"]
        );
    }

    #[test]
    fn install_and_engine_update_dry_run_by_default() {
        let ctx = admin();
        block(async {
            let args: DockerInstallArgs =
                plugin_toolkit::serde_json::from_value(plugin_toolkit::serde_json::json!({}))
                    .unwrap();
            assert!(!args.execute);
            let out = docker_install(args, &ctx).await.unwrap();
            assert!(out.dry_run && !out.provisioned && out.log.is_none());
            assert_eq!(out.plan, "run the embedded install.sh colima");

            let args = DockerEngineUpdateArgs {
                runtime: ContainerRuntime::Podman,
                execute: false,
            };
            let out = docker_engine_update(args, &ctx).await.unwrap();
            assert!(out.dry_run && !out.updated && out.log.is_none());
            assert_eq!(out.plan, "run the embedded update.sh podman");
        });
    }

    #[test]
    fn non_admins_get_neither_the_dry_run_nor_execute() {
        let (home, root) = backup_fixture();
        let (h, r) = (s(home.path()), s(root.path()));
        let roots = [r.clone()];
        let archive = s(&root.path().join("missing.tar.gz"));
        for ctx in [test_ctx(), test_ctx().with_auth(caller("user"))] {
            for execute in [false, true] {
                let errs = block(async {
                    let runtime = ContainerRuntime::Colima;
                    [
                        docker_install(DockerInstallArgs { runtime, execute }, &ctx)
                            .await
                            .unwrap_err(),
                        docker_engine_update(DockerEngineUpdateArgs { runtime, execute }, &ctx)
                            .await
                            .unwrap_err(),
                        backup(
                            DockerBackupArgs {
                                destination: r.clone(),
                                state_path: None,
                                execute,
                            },
                            &h,
                            &roots,
                            &ctx,
                        )
                        .await
                        .unwrap_err(),
                        restore(
                            DockerRestoreArgs {
                                archive: archive.clone(),
                                state_path: None,
                                execute,
                            },
                            &h,
                            &roots,
                            &ctx,
                        )
                        .await
                        .unwrap_err(),
                    ]
                });
                for err in errs {
                    let err = err.to_string();
                    assert!(
                        err.contains("requires role 'admin'") || err.contains("no caller identity"),
                        "{err}"
                    );
                }
            }
        }
    }

    /// A home whose `.colima` holds a marker and lima's key, and a backup root.
    fn backup_fixture() -> (tempfile::TempDir, tempfile::TempDir) {
        let home = tempfile::tempdir().unwrap();
        let state = home.path().join(".colima");
        std::fs::create_dir_all(state.join("_lima/_config")).unwrap();
        std::fs::write(state.join("marker"), b"state").unwrap();
        std::fs::write(state.join("_lima/_config/user"), b"PRIVATE").unwrap();
        (home, tempfile::tempdir().unwrap())
    }

    #[test]
    fn backup_rejects_missing_state_dir() {
        let home = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let args = DockerBackupArgs {
            destination: s(dest.path()),
            state_path: None,
            execute: false,
        };
        let err = block(backup(args, &s(home.path()), &[s(dest.path())], &admin())).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    #[test]
    fn backup_dry_run_writes_nothing() {
        let (home, root) = backup_fixture();
        let dest = root.path().join("engine");
        let args = DockerBackupArgs {
            destination: s(&dest),
            state_path: None,
            execute: false,
        };
        let out = block(backup(args, &s(home.path()), &[s(root.path())], &admin())).unwrap();
        assert!(out.dry_run && out.archive.is_none() && out.how_to_execute.is_some());
        assert_eq!(out.excluded.len(), 1, "{:?}", out.excluded);
        assert!(!dest.exists());
    }

    #[test]
    fn backup_executes_for_an_admin_into_a_0600_archive() {
        let (home, root) = backup_fixture();
        let args = DockerBackupArgs {
            destination: s(&root.path().join("engine")),
            state_path: None,
            execute: true,
        };
        let out = block(backup(args, &s(home.path()), &[s(root.path())], &admin())).unwrap();
        assert!(!out.dry_run);
        let archive = out.archive.unwrap();
        let mode = std::fs::metadata(&archive).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(out.excluded[0].starts_with("_lima/_config/user"));
    }

    #[test]
    fn backup_destination_must_resolve_inside_a_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("escape")).unwrap();
        let roots = [s(root.path())];
        let r = s(root.path());
        let err = |p: &str| in_backup_root(p, &roots).unwrap_err().to_string();
        assert!(err("relative/dir").contains("not an absolute path"));
        assert!(err(&format!("{r}/a/../../etc")).contains("contains '..'"));
        assert!(err("/etc").contains("outside the backup roots"));
        assert!(err(&format!("{r}/escape/sub")).contains("outside the backup roots"));
        assert_eq!(
            in_backup_root(&format!("{r}/engine"), &roots).unwrap(),
            root.path().canonicalize().unwrap().join("engine")
        );
    }

    #[test]
    fn backup_state_path_must_resolve_inside_the_colima_root() {
        let (home, root) = backup_fixture();
        let args = DockerBackupArgs {
            destination: s(root.path()),
            state_path: Some(s(root.path())),
            execute: false,
        };
        let err = block(backup(args, &s(home.path()), &[s(root.path())], &admin())).unwrap_err();
        assert!(
            err.to_string().contains("outside the engine state root"),
            "{err}"
        );
    }

    /// `tar -czPf <root>/crafted.tar.gz -C <work> <members>` (system tar),
    /// after `setup` populates `<work>`.
    fn crafted_archive(root: &Path, setup: impl FnOnce(&Path), members: &[&str]) -> String {
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        setup(&work);
        let archive = root.join("crafted.tar.gz");
        let status = std::process::Command::new("tar")
            .arg("-czPf")
            .arg(&archive)
            .arg("-C")
            .arg(&work)
            .args(members)
            .status()
            .unwrap();
        assert!(status.success());
        s(&archive)
    }

    /// An archive of `entries` built header by header, so names, link targets
    /// and owner fields are exactly as given.
    fn built_archive(root: &Path, entries: &[(EntryKind, &str, &str)]) -> String {
        let path = root.join("built.tar.gz");
        let gz = flate2::write::GzEncoder::new(
            std::fs::File::create(&path).unwrap(),
            flate2::Compression::default(),
        );
        let mut builder = tar::Builder::new(gz);
        for (kind, name, target) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_username("x n -> safe").unwrap();
            h.set_groupname("g").unwrap();
            h.set_size(0);
            let name_bytes = name.as_bytes();
            h.as_old_mut().name[..name_bytes.len()].copy_from_slice(name_bytes);
            match kind {
                EntryKind::File => h.set_entry_type(tar::EntryType::Regular),
                EntryKind::Symlink | EntryKind::Hardlink => {
                    h.set_entry_type(if matches!(kind, EntryKind::Symlink) {
                        tar::EntryType::Symlink
                    } else {
                        tar::EntryType::Link
                    });
                    let t = target.as_bytes();
                    h.as_old_mut().linkname[..t.len()].copy_from_slice(t);
                }
            }
            h.set_cksum();
            builder.append(&h, std::io::empty()).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
        s(&path)
    }

    enum EntryKind {
        File,
        Symlink,
        Hardlink,
    }

    fn archive_error(archive: &str) -> String {
        let mut file = std::fs::File::open(archive).unwrap();
        engine_state::validate(&mut file).unwrap_err().to_string()
    }

    #[test]
    fn archive_check_accepts_files_dirs_and_inward_links() {
        let root = tempfile::tempdir().unwrap();
        let archive = crafted_archive(
            root.path(),
            |src| {
                std::fs::create_dir_all(src.join("sub")).unwrap();
                std::fs::write(src.join("sub/a"), b"x").unwrap();
                std::fs::hard_link(src.join("sub/a"), src.join("h")).unwrap();
                symlink("sub/a", src.join("my link")).unwrap();
            },
            &["."],
        );
        engine_state::validate(&mut std::fs::File::open(archive).unwrap()).unwrap();
    }

    #[test]
    fn archive_check_refuses_an_absolute_entry() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let file = outside.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        let archive = crafted_archive(root.path(), |_| {}, &[file.to_str().unwrap()]);
        let err = archive_error(&archive);
        assert!(err.contains("would extract outside"), "{err}");
    }

    #[test]
    fn archive_check_refuses_a_dotdot_entry() {
        let root = tempfile::tempdir().unwrap();
        let archive = crafted_archive(
            root.path(),
            |src| std::fs::write(src.parent().unwrap().join("up"), b"x").unwrap(),
            &["../up"],
        );
        let err = archive_error(&archive);
        assert!(err.contains("would extract outside"), "{err}");
    }

    #[test]
    fn archive_check_refuses_escaping_symlinks() {
        for target in ["/etc", "../outside", "sub/../.."] {
            let root = tempfile::tempdir().unwrap();
            let archive = crafted_archive(
                root.path(),
                |src| symlink(target, src.join("link")).unwrap(),
                &["."],
            );
            let err = archive_error(&archive);
            assert!(
                err.contains(&format!("links to '{target}'")),
                "{target}: {err}"
            );
        }
    }

    #[test]
    fn archive_check_refuses_an_escaping_hard_link() {
        let root = tempfile::tempdir().unwrap();
        let archive = built_archive(
            root.path(),
            &[
                (EntryKind::File, "ok", ""),
                (EntryKind::Hardlink, "h", "../up"),
            ],
        );
        let err = archive_error(&archive);
        assert!(err.contains("'h' links to '../up'"), "{err}");
    }

    #[test]
    fn archive_check_ignores_owner_names_that_look_like_link_syntax() {
        // A listing parser can be fooled by an owner of `x n -> safe`; the
        // header's own link target cannot.
        let root = tempfile::tempdir().unwrap();
        let archive = built_archive(root.path(), &[(EntryKind::Symlink, "n", "/etc")]);
        let err = archive_error(&archive);
        assert!(err.contains("'n' links to '/etc'"), "{err}");
    }

    #[test]
    fn restore_refuses_an_escaping_archive_before_extracting() {
        let (home, root) = backup_fixture();
        let archive = built_archive(
            root.path(),
            &[
                (EntryKind::File, "first", ""),
                (EntryKind::Symlink, "n", "/etc"),
            ],
        );
        let state = home.path().join(".colima/fresh");
        let args = DockerRestoreArgs {
            archive,
            state_path: Some(s(&state)),
            execute: true,
        };
        let err = block(restore(args, &s(home.path()), &[s(root.path())], &admin())).unwrap_err();
        assert!(err.to_string().contains("links to '/etc'"), "{err}");
        assert!(!state.exists());
    }

    #[test]
    fn restore_needs_an_absolute_archive_inside_the_backup_root() {
        let (home, root) = backup_fixture();
        let outside = tempfile::tempdir().unwrap();
        let elsewhere = state_archive(outside.path());
        let roots = [s(root.path())];
        let err = |archive: String| {
            let args = DockerRestoreArgs {
                archive,
                state_path: None,
                execute: false,
            };
            block(restore(args, &s(home.path()), &roots, &admin()))
                .unwrap_err()
                .to_string()
        };
        assert!(err("state.tar.gz".into()).contains("not an absolute path"));
        assert!(err(s(&elsewhere)).contains("outside the backup roots"));
        assert!(err(s(&root.path().join("missing.tar.gz"))).contains("cannot be opened"));
    }

    #[test]
    fn restore_refuses_a_state_dir_with_an_outward_symlink() {
        let (home, root) = backup_fixture();
        let archive = state_archive(root.path());
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), home.path().join(".colima/out")).unwrap();
        let args = DockerRestoreArgs {
            archive: s(&archive),
            state_path: None,
            execute: true,
        };
        let err = block(restore(args, &s(home.path()), &[s(root.path())], &admin())).unwrap_err();
        assert!(
            err.to_string().contains("symlinks leading outside"),
            "{err}"
        );
        assert!(!outside.path().join("marker").exists());
    }

    #[test]
    fn restore_dry_run_leaves_no_state() {
        let home = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let archive = state_archive(root.path());
        let args = DockerRestoreArgs {
            archive: s(&archive),
            state_path: None,
            execute: false,
        };
        let out = block(restore(args, &s(home.path()), &[s(root.path())], &admin())).unwrap();
        assert!(out.dry_run && !out.restored && out.how_to_execute.is_some());
        assert!(out.state_path.ends_with(".colima"), "{}", out.state_path);
        assert!(!home.path().join(".colima").exists());
    }

    #[test]
    fn restore_executes_for_an_admin_into_the_state_root() {
        let home = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let archive = state_archive(root.path());
        let target = home.path().join(".colima").join("default");
        let args = DockerRestoreArgs {
            archive: s(&archive),
            state_path: Some(s(&target)),
            execute: true,
        };
        let out = block(restore(args, &s(home.path()), &[s(root.path())], &admin())).unwrap();
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
        symlink(outside.path(), root.join("escape")).unwrap();
        symlink(outside.path().join("missing"), root.join("dangling")).unwrap();
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
    }

    /// `<dir>/state.tar.gz` of a single `marker` file, made by system tar.
    fn state_archive(dir: &Path) -> PathBuf {
        let src = dir.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("marker"), b"state").unwrap();
        let archive = dir.join("state.tar.gz");
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&src)
            .arg(".")
            .status()
            .unwrap();
        assert!(status.success());
        archive
    }

    fn caller(role: &str) -> CallerIdentity {
        CallerIdentity {
            user_id: "u".into(),
            username: "op".into(),
            role: role.into(),
            can_mutate: true,
        }
    }

    fn admin() -> ToolCtx {
        test_ctx().with_auth(caller("admin"))
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
