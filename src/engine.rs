//! Engine status and lifecycle.

use plugin_toolkit::anyhow;
use plugin_toolkit::process::Command;
use plugin_toolkit::serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(crate = "plugin_toolkit::serde")]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    Colima,
    Desktop,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
pub struct EngineStatus {
    pub engine: Engine,
    pub running: bool,
}

/// Probe the local docker setup. Returns `(engine, running)`:
///
/// - `Colima` is detected by the colima socket existing (running) or by a
///   colima binary in known locations (installed but stopped).
/// - Otherwise we ping `docker info`; if that succeeds, Desktop is running.
/// - Else `None`.
pub async fn status() -> EngineStatus {
    let home = std::env::var("HOME").unwrap_or_default();
    let colima_sock = format!("{home}/.colima/default/docker.sock");
    if std::path::Path::new(&colima_sock).exists() {
        return EngineStatus {
            engine: Engine::Colima,
            running: true,
        };
    }
    let colima_paths = [
        "/opt/homebrew/bin/colima",
        "/usr/local/bin/colima",
        &format!("{home}/.local/bin/colima"),
    ];
    if colima_paths
        .iter()
        .any(|p| std::path::Path::new(p).exists())
    {
        return EngineStatus {
            engine: Engine::Colima,
            running: false,
        };
    }
    let ping = Command::new(super::resolve_docker_bin())
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .await;
    let running = ping.map(|o| o.status.success).unwrap_or(false);
    EngineStatus {
        engine: if running {
            Engine::Desktop
        } else {
            Engine::None
        },
        running,
    }
}

/// Try to start the docker engine. Today: probes for colima and runs
/// `colima start`. When neither colima nor a startable Desktop is present,
/// returns an error pointing the user at manual start.
pub async fn start() -> anyhow::Result<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let local_bin = format!("{home}/.local/bin/colima");
    let candidates: &[&str] = &[
        "/opt/homebrew/bin/colima",
        "/usr/local/bin/colima",
        &local_bin,
    ];
    let colima_bin = candidates
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .copied();
    let Some(colima) = colima_bin else {
        anyhow::bail!("colima not found — start Docker Desktop manually");
    };
    let out = Command::new(colima).arg("start").output().await?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    Ok(if stdout.is_empty() { stderr } else { stdout })
}
