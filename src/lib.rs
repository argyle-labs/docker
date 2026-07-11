//! Docker integration. CLI-based today (matches every existing caller —
//! server, plugin, ops scripts). Two layers:
//!
//! - [`engine`] — Engine status / start (colima vs Docker Desktop probing).
//! - [`compose`] — Compose project wrapper (find file, services, action, ps).
//!
//! No bollard yet. When a real Engine API call site lands (exec streaming,
//! event subscription) we'll add a third layer rather than retro-fitting.

pub mod compose;
pub mod containers;
pub mod engine;
pub mod lifecycle;
pub mod registration;
pub mod runtime_adapter;
pub mod stacks;
pub mod tools;
pub mod topology;
pub mod unit_provider;

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
/// default unix socket. Prefers the first enabled socket/tcp entry in the
/// docker runtime registry; falls back to auto-detecting colima's socket.
/// Returns None when the default socket should be used.
pub async fn docker_host() -> Option<String> {
    if let Some(host) = tools::active_host() {
        return Some(host);
    }
    let home = std::env::var("HOME").ok()?;
    let colima = format!("{home}/.colima/default/docker.sock");
    if std::path::Path::new(&colima).exists() {
        return Some(format!("unix://{colima}"));
    }
    None
}

/// Run the docker CLI with `args`, optionally in `cwd`, returning stdout.
/// Auto-injects DOCKER_HOST when needed.
pub async fn run(args: &[&str], cwd: Option<&str>) -> plugin_toolkit::anyhow::Result<String> {
    use plugin_toolkit::process::Command;
    let mut cmd = Command::new(resolve_docker_bin()).args(args);
    if let Some(dir) = cwd {
        cmd = cmd.current_dir(dir);
    }
    if let Some(host) = docker_host().await {
        cmd = cmd.env("DOCKER_HOST", host);
    }
    let out = cmd.output().await?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success && stdout.trim().is_empty() {
        plugin_toolkit::anyhow::bail!("{}", stderr.trim());
    }
    Ok(if stdout.is_empty() { stderr } else { stdout })
}
