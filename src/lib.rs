//! Docker integration. CLI-based today (matches every existing caller —
//! server, plugin, ops scripts). Two layers:
//!
//! - [`engine`] — Engine status / start (colima vs Docker Desktop probing).
//! - [`compose`] — Compose project wrapper (find file, services, action, ps).
//!
//! No bollard yet. When a real Engine API call site lands (exec streaming,
//! event subscription) we'll add a third layer rather than retro-fitting.

#[allow(clippy::disallowed_methods)]
pub mod cgroup;
pub mod compose;
pub mod compose_config;
pub mod container_delete;
pub mod container_inspect;
pub mod containers;
#[allow(clippy::disallowed_methods)]
pub mod daemon_config;
pub mod deploy;
pub mod engine;
pub mod engine_resources;
pub mod engine_state;
mod exec;
pub mod execute;
pub mod fsat;
pub mod image_ref;
pub mod image_update;
#[allow(clippy::disallowed_methods)]
pub mod init;
pub mod label_audit;
pub mod labels;
#[allow(clippy::disallowed_methods)]
pub mod lifecycle;
pub mod lint;
pub mod manageability;
#[allow(clippy::disallowed_methods)]
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

async fn clean_argv(program: &str) -> plugin_toolkit::anyhow::Result<Vec<String>> {
    let env = passed_env(|k| std::env::var(k).ok(), docker_host().await?);
    Ok(env_argv(env, program))
}

fn env_argv(env: Vec<String>, program: &str) -> Vec<String> {
    std::iter::once("-i".to_string())
        .chain(env)
        .chain(std::iter::once(program.to_string()))
        .collect()
}

/// `program` under `env -i`, with only [`PASSED_ENV`] and the resolved
/// engine's `DOCKER_HOST`. The toolkit's `Command` cannot clear the
/// environment itself.
pub async fn clean_command(
    program: &str,
) -> plugin_toolkit::anyhow::Result<plugin_toolkit::process::Command> {
    Ok(plugin_toolkit::process::Command::new("/usr/bin/env").args(clean_argv(program).await?))
}

/// Run the docker CLI with `args`, returning stdout,
/// under the same environment as [`clean_command`]. The child leads its own
/// process group, and every lingering descendant in that group is killed on
/// every return, including timeout and cancellation; the toolkit's `Command`
/// cannot set a process group or expose the pid.
pub async fn run(args: &[&str]) -> plugin_toolkit::anyhow::Result<String> {
    let mut cmd = std::process::Command::new("/usr/bin/env");
    cmd.args(clean_argv(resolve_docker_bin()).await?).args(args);
    run_within(cmd, CLI_BUDGET).await
}

/// [`run`], returning stdout and stderr apart.
pub async fn run_with_stderr(args: &[&str]) -> plugin_toolkit::anyhow::Result<(String, String)> {
    let mut cmd = std::process::Command::new("/usr/bin/env");
    cmd.args(clean_argv(resolve_docker_bin()).await?).args(args);
    run_split(cmd, CLI_BUDGET, &mut Vec::new()).await
}

const CLI_BUDGET: std::time::Duration = std::time::Duration::from_secs(30 * 60);
const DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
const POLL_MIN: std::time::Duration = std::time::Duration::from_millis(5);
const POLL_MAX: std::time::Duration = std::time::Duration::from_millis(50);

struct GroupGuard {
    child: Option<std::process::Child>,
    pgid: libc::pid_t,
}

impl GroupGuard {
    fn kill_group(&self) {
        unsafe {
            libc::killpg(self.pgid, libc::SIGKILL);
        }
    }

    fn leader_exited(&self) -> std::io::Result<bool> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pgid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ECHILD) {
                return Ok(true);
            }
            return Err(err);
        }
        Ok(info.si_signo != 0)
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            self.kill_group();
            if !matches!(child.try_wait(), Ok(Some(_))) {
                std::thread::spawn(move || {
                    child.wait().ok();
                });
            }
        }
    }
}

struct StopOnDrop(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn drain(
    pipe: Option<impl std::io::Read + std::os::fd::AsRawFd + Send + 'static>,
    slot: usize,
    tx: std::sync::mpsc::Sender<(usize, Vec<u8>)>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = pipe {
            let fd = p.as_raw_fd();
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                if flags >= 0 {
                    libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
            let mut chunk = [0u8; 65536];
            let mut pause = POLL_MIN;
            loop {
                match p.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        pause = POLL_MIN;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if stop.load(std::sync::atomic::Ordering::SeqCst) {
                            break;
                        }
                        std::thread::sleep(pause);
                        pause = (pause * 2).min(POLL_MAX);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        }
        tx.send((slot, buf)).ok();
    })
}

async fn collect(
    rx: std::sync::mpsc::Receiver<(usize, Vec<u8>)>,
) -> plugin_toolkit::anyhow::Result<[Vec<u8>; 2]> {
    let mut bufs = [Vec::new(), Vec::new()];
    let mut pending = 2;
    let deadline = std::time::Instant::now() + DRAIN_BUDGET;
    let mut pause = POLL_MIN;
    while pending > 0 {
        match rx.try_recv() {
            Ok((slot, buf)) => {
                bufs[slot] = buf;
                pending -= 1;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                plugin_toolkit::time::sleep(pause).await;
                pause = (pause * 2).min(POLL_MAX);
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
        }
    }
    if pending > 0 {
        plugin_toolkit::anyhow::bail!(
            "output drain exceeded budget; a process outside the group holds the pipe"
        );
    }
    Ok(bufs)
}

async fn run_within(
    cmd: std::process::Command,
    budget: std::time::Duration,
) -> plugin_toolkit::anyhow::Result<String> {
    run_tracked(cmd, budget, &mut Vec::new()).await
}

async fn run_tracked(
    cmd: std::process::Command,
    budget: std::time::Duration,
    drains: &mut Vec<std::thread::JoinHandle<()>>,
) -> plugin_toolkit::anyhow::Result<String> {
    let (stdout, stderr) = run_split(cmd, budget, drains).await?;
    Ok(if stdout.is_empty() { stderr } else { stdout })
}

async fn run_split(
    mut cmd: std::process::Command,
    budget: std::time::Duration,
    drains: &mut Vec<std::thread::JoinHandle<()>>,
) -> plugin_toolkit::anyhow::Result<(String, String)> {
    use std::os::unix::process::CommandExt;
    let mut child = cmd
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let (tx, rx) = std::sync::mpsc::channel();
    let stop = StopOnDrop(Default::default());
    drains.push(drain(child.stdout.take(), 0, tx.clone(), stop.0.clone()));
    drains.push(drain(child.stderr.take(), 1, tx, stop.0.clone()));
    let mut guard = GroupGuard {
        pgid: child.id() as libc::pid_t,
        child: Some(child),
    };
    let deadline = std::time::Instant::now() + budget;
    let mut pause = POLL_MIN;
    while !guard.leader_exited()? {
        if std::time::Instant::now() >= deadline {
            drop(guard);
            plugin_toolkit::anyhow::bail!(
                "docker CLI timed out after {:?} and was killed; the daemon-side operation may still be running",
                budget
            );
        }
        plugin_toolkit::time::sleep(pause).await;
        pause = (pause * 2).min(POLL_MAX);
    }
    guard.kill_group();
    let mut leader = guard.child.take().expect("leader present");
    let status = leader.wait()?;
    let [out, err] = collect(rx).await?;
    let stdout = String::from_utf8_lossy(&out).to_string();
    let stderr = String::from_utf8_lossy(&err).to_string();
    if !status.success() {
        let why = if stderr.trim().is_empty() {
            &stdout
        } else {
            &stderr
        };
        plugin_toolkit::anyhow::bail!("{}", why.trim());
    }
    Ok((stdout, stderr))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_taking_dry_run_lets_core_forward_it() {
        use plugin_toolkit::dispatch;
        let aware = dispatch::dry_run_aware_names();
        let gated = dispatch::execute_gated_names();
        assert!(aware.contains(&"docker.prune"), "{aware:?}");
        for def in dispatch::mcp_definitions() {
            let name = def["name"].as_str().unwrap_or_default();
            if !name.starts_with("docker.") {
                continue;
            }
            if def["inputSchema"]["properties"].get("dryRun").is_some() {
                assert!(
                    aware.contains(&name) || gated.contains(&name),
                    "{name} reads dryRun but core refuses to forward it"
                );
            }
        }
    }

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
        assert!(grandchild_dead(&pidfile), "grandchild survived the timeout");
    }

    fn read_pid(pidfile: &std::path::Path) -> libc::pid_t {
        for _ in 0..250 {
            if let Some(pid) = std::fs::read_to_string(pidfile)
                .ok()
                .and_then(|s| s.trim().parse().ok())
            {
                std::fs::remove_file(pidfile).ok();
                return pid;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("pidfile {} never appeared", pidfile.display());
    }

    fn grandchild_dead(pidfile: &std::path::Path) -> bool {
        let pid = read_pid(pidfile);
        (0..50).any(|_| {
            if unsafe { libc::kill(pid, 0) } != 0 || is_zombie(pid) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            false
        })
    }

    fn is_zombie(pid: libc::pid_t) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| s.rsplit_once(") ").map(|(_, rest)| rest.starts_with('Z')))
            .unwrap_or(false)
    }

    #[test]
    fn large_output_on_both_pipes_does_not_deadlock() {
        let out = plugin_toolkit::reactor::block_on(run_within(
            sh("head -c 200000 /dev/zero | tr '\\0' a; head -c 200000 /dev/zero | tr '\\0' b >&2"),
            std::time::Duration::from_secs(20),
        ))
        .unwrap();
        assert_eq!(out.len(), 200000);
    }

    #[test]
    fn a_grandchild_holding_the_pipe_does_not_stall_the_return() {
        let started = std::time::Instant::now();
        let out = plugin_toolkit::reactor::block_on(run_within(
            sh("sleep 30 & echo ok"),
            std::time::Duration::from_secs(20),
        ))
        .unwrap();
        assert_eq!(out, "ok\n");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[test]
    fn cancelling_the_future_kills_the_group() {
        let pidfile =
            std::env::temp_dir().join(format!("docker-cancel-{}.pid", std::process::id()));
        std::fs::remove_file(&pidfile).ok();
        let script = format!("sleep 30 & echo $! > {}; wait", pidfile.display());
        let done = plugin_toolkit::reactor::block_on(plugin_toolkit::time::timeout(
            std::time::Duration::from_millis(300),
            run_within(sh(&script), std::time::Duration::from_secs(60)),
        ));
        assert!(done.is_none());
        assert!(
            grandchild_dead(&pidfile),
            "grandchild survived cancellation"
        );
    }

    #[test]
    fn a_process_outside_the_group_holding_stdout_is_an_error() {
        let pidfile =
            std::env::temp_dir().join(format!("docker-setsid-{}.pid", std::process::id()));
        std::fs::remove_file(&pidfile).ok();
        let script = format!(
            "perl -e 'use POSIX; exit if fork; POSIX::setsid(); open F, \">{}\"; print F $$; close F; sleep 30' & echo ok; wait",
            pidfile.display()
        );
        let mut drains = Vec::new();
        let err = plugin_toolkit::reactor::block_on(run_tracked(
            sh(&script),
            std::time::Duration::from_secs(20),
            &mut drains,
        ))
        .unwrap_err();
        let finished = (0..100).any(|_| {
            if drains.iter().all(|h| h.is_finished()) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            false
        });
        let pid = read_pid(&pidfile);
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        assert!(err.to_string().contains("drain exceeded budget"), "{err}");
        assert!(finished, "drain threads still running after the budget");
    }

    #[test]
    fn the_argv_clears_the_environment_and_passes_only_the_allowlist() {
        let env = passed_env(
            |k| match k {
                "PATH" => Some("/usr/bin".to_string()),
                "AWS_SECRET_ACCESS_KEY" => Some("leak".to_string()),
                _ => None,
            },
            Some("unix:///d.sock".into()),
        );
        assert_eq!(
            env_argv(env, "docker"),
            [
                "-i",
                "PATH=/usr/bin",
                "DOCKER_HOST=unix:///d.sock",
                "docker"
            ]
        );
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
            plugin_toolkit::reactor::block_on(run(&[
                "compose", "-f", &file, "config", "--format", "json",
            ]))
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
