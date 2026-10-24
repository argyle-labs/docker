//! Docker integration. CLI-based today (matches every existing caller —
//! server, plugin, ops scripts). Two layers:
//!
//! - [`engine`] — Engine status / start (colima vs Docker Desktop probing).
//! - [`compose`] — Compose project wrapper (find file, services, action, ps).
//!
//! No bollard yet. When a real Engine API call site lands (exec streaming,
//! event subscription) we'll add a third layer rather than retro-fitting.

pub mod cgroup;
pub mod compose;
pub mod compose_config;
pub mod container_delete;
pub mod container_inspect;
pub mod containers;
pub mod daemon_config;
pub mod deploy;
pub mod engine;
pub mod engine_resources;
pub mod engine_state;
mod exec;
pub mod execute;
pub mod fsat;
pub mod image_update;
pub mod init;
pub mod label_audit;
pub mod labels;
pub mod lifecycle;
pub mod lint;
pub mod manageability;
pub mod mounts;
pub mod normalize;
pub mod ownership;
pub mod path_writable;
pub mod policy;
pub mod prune;
pub mod registration;
pub mod runtime_adapter;
pub mod stack_health;
pub mod stack_manifest;
pub mod stack_move;
pub mod stack_pull;
pub mod stack_relocate;
pub mod stack_volumes;
pub mod stacks;
pub mod stacks_root_drift;
#[cfg(test)]
mod test_engine;
#[cfg(test)]
mod test_support;
pub mod tools;
pub mod topology;
pub mod unit_provider;
pub mod volume_coverage;

pub use compose::{Compose, ComposeError, ServiceStatus, ServiceSummary};
pub use containers::ContainerSummary;
pub use engine::{Engine, EngineStatus};

/// Resolve the absolute path of the `docker` CLI for daemon environments
/// where /opt/homebrew/bin etc. aren't on PATH. Falls back to bare `docker`
/// when nothing is found.
pub fn resolve_docker_bin() -> &'static str {
    static DOCKER: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DOCKER.get_or_init(|| {
        for candidate in &[
            "/opt/homebrew/bin/docker",
            "/usr/local/bin/docker",
            "/usr/bin/docker",
            "/snap/bin/docker",
        ] {
            if std::path::Path::new(candidate).exists() {
                return candidate.to_string();
            }
        }
        "docker".to_string()
    })
}

/// Returns the DOCKER_HOST value to inject when the engine isn't on the
/// default unix socket. Resolves through the shared fallback chain: the first
/// enabled socket/tcp registry entry → colima's socket → a docker socket
/// present at a well-known path (e.g. Unraid's standard socket). Returns None
/// when nothing is discoverable and the client's own default should be used.
pub async fn docker_host() -> plugin_toolkit::anyhow::Result<Option<String>> {
    tools::resolve_docker_host()
}

/// The daemon's environment variables a docker or compose child gets; every
/// other one is withheld, since compose interpolates its environment into a
/// stack's config, which is then run and echoed.
/// - `PATH`: the CLI finds `docker-credential-*` helpers, and a bare
///   `docker`, on it.
/// - `HOME`, `DOCKER_CONFIG`: the CLI config dir (auth, contexts,
///   `cli-plugins` where compose itself lives).
/// - `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_TLS_VERIFY`, `DOCKER_CERT_PATH`:
///   which engine to reach and how, when no registered runtime says.
const PASSED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "DOCKER_CONFIG",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
];

/// `KEY=value` for each of [`PASSED_ENV`] that `get` has, with `host` in
/// place of `DOCKER_HOST` when given.
fn passed_env(get: impl Fn(&str) -> Option<String>, host: Option<String>) -> Vec<String> {
    PASSED_ENV
        .iter()
        .filter_map(|key| {
            let value = match (*key, &host) {
                ("DOCKER_HOST", Some(h)) => Some(h.clone()),
                _ => get(key),
            };
            value.map(|v| format!("{key}={v}"))
        })
        .collect()
}

/// `program` under `env -i`, with only [`PASSED_ENV`] and the resolved
/// engine's `DOCKER_HOST`. The toolkit's `Command` cannot clear the
/// environment itself.
pub async fn clean_command(
    program: &str,
) -> plugin_toolkit::anyhow::Result<plugin_toolkit::process::Command> {
    let env = passed_env(|k| std::env::var(k).ok(), docker_host().await?);
    Ok(plugin_toolkit::process::Command::new("/usr/bin/env")
        .arg("-i")
        .args(env)
        .arg(program))
}

/// Run the docker CLI with `args`, optionally in `cwd`, returning stdout,
/// under the same environment as [`clean_command`]. The child leads its own
/// process group so a timeout also kills the compose plugin it spawns; the
/// toolkit's `Command` cannot set a process group or expose the pid.
pub async fn run(args: &[&str], cwd: Option<&str>) -> plugin_toolkit::anyhow::Result<String> {
    let env = passed_env(|k| std::env::var(k).ok(), docker_host().await?);
    let mut cmd = std::process::Command::new("/usr/bin/env");
    cmd.arg("-i").args(env).arg(resolve_docker_bin()).args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    run_within(cmd, CLI_BUDGET).await
}

const CLI_BUDGET: std::time::Duration = std::time::Duration::from_secs(30 * 60);

fn drain(pipe: Option<impl std::io::Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = pipe {
            p.read_to_end(&mut buf).ok();
        }
        buf
    })
}

async fn run_within(
    mut cmd: std::process::Command,
    budget: std::time::Duration,
) -> plugin_toolkit::anyhow::Result<String> {
    use std::os::unix::process::CommandExt;
    let mut child = cmd
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let out_reader = drain(child.stdout.take());
    let err_reader = drain(child.stderr.take());
    let deadline = std::time::Instant::now() + budget;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let pgid = child.id() as libc::pid_t;
            unsafe {
                libc::killpg(pgid, libc::SIGKILL);
            }
            child.wait().ok();
            plugin_toolkit::anyhow::bail!(
                "docker CLI timed out after {:?} and was killed; the daemon-side operation may still be running",
                budget
            );
        }
        plugin_toolkit::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    let stdout = String::from_utf8_lossy(&out_reader.join().unwrap_or_default()).to_string();
    let stderr = String::from_utf8_lossy(&err_reader.join().unwrap_or_default()).to_string();
    if !status.success() {
        let why = if stderr.trim().is_empty() {
            &stdout
        } else {
            &stderr
        };
        plugin_toolkit::anyhow::bail!("{}", why.trim());
    }
    Ok(if stdout.is_empty() { stderr } else { stdout })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", script]);
        cmd
    }

    #[test]
    fn a_non_zero_exit_fails_even_with_stdout() {
        let err = plugin_toolkit::reactor::block_on(run_within(
            sh("echo partial; echo boom >&2; exit 3"),
            std::time::Duration::from_secs(10),
        ))
        .unwrap_err();
        assert_eq!(err.to_string(), "boom");
    }

    #[test]
    fn a_zero_exit_returns_stdout() {
        let out = plugin_toolkit::reactor::block_on(run_within(
            sh("echo ok"),
            std::time::Duration::from_secs(10),
        ))
        .unwrap();
        assert_eq!(out, "ok\n");
    }

    #[test]
    fn a_hung_cli_times_out() {
        let err = plugin_toolkit::reactor::block_on(run_within(
            sh("sleep 30"),
            std::time::Duration::from_millis(100),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
        assert!(err.to_string().contains("may still be running"), "{err}");
    }

    #[test]
    fn a_timeout_kills_the_whole_process_group() {
        let pidfile = std::env::temp_dir().join(format!("docker-pg-{}.pid", std::process::id()));
        std::fs::remove_file(&pidfile).ok();
        let script = format!("sleep 30 & echo $! > {}; wait", pidfile.display());
        plugin_toolkit::reactor::block_on(run_within(
            sh(&script),
            std::time::Duration::from_millis(300),
        ))
        .unwrap_err();
        let pid: libc::pid_t = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        std::fs::remove_file(&pidfile).ok();
        let gone = (0..50).any(|_| {
            if unsafe { libc::kill(pid, 0) } != 0 {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            false
        });
        assert!(gone, "grandchild {pid} survived the timeout");
    }

    #[test]
    fn only_the_listed_variables_reach_a_child() {
        let env = |k: &str| match k {
            "PATH" => Some("/usr/bin".to_string()),
            "DOCKER_HOST" => Some("unix:///inherited.sock".to_string()),
            "AWS_SECRET_ACCESS_KEY" => Some("leak".to_string()),
            _ => None,
        };
        assert_eq!(
            passed_env(env, None),
            ["PATH=/usr/bin", "DOCKER_HOST=unix:///inherited.sock"]
        );
        assert_eq!(
            passed_env(env, Some("unix:///registered.sock".into())),
            ["PATH=/usr/bin", "DOCKER_HOST=unix:///registered.sock"]
        );
    }

    #[test]
    fn compose_cannot_interpolate_the_daemons_environment() {
        // Cargo sets CARGO_PKG_NAME in the test process's environment.
        let Ok(name) = std::env::var("CARGO_PKG_NAME") else {
            return;
        };
        if !crate::test_support::have_compose() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("compose.yaml");
        std::fs::write(
            &file,
            "services:\n  app:\n    image: x:1\n    environment:\n      LEAK: ${CARGO_PKG_NAME:-unset}\n",
        )
        .unwrap();
        let file = file.to_string_lossy().into_owned();
        let out = crate::test_support::with_db(|| {
            plugin_toolkit::reactor::block_on(run(
                &["compose", "-f", &file, "config", "--format", "json"],
                None,
            ))
        })
        .0
        .unwrap();
        let cfg: plugin_toolkit::serde_json::Value =
            plugin_toolkit::serde_json::from_str(&out).unwrap();
        assert_eq!(
            cfg["services"]["app"]["environment"]["LEAK"], "unset",
            "{name}: {out}"
        );
    }
}
