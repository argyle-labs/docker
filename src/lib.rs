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
pub mod containers;
pub mod engine;
pub mod engine_resources;
pub mod engine_state;
pub mod execute;
pub mod fsat;
pub mod host_update;
pub mod init;
pub mod label_audit;
pub mod labels;
pub mod lifecycle;
pub mod lint;
pub mod ownership;
pub mod policy;
pub mod prune;
pub mod registration;
pub mod runtime_adapter;
pub mod stacks;
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
pub async fn docker_host() -> Option<String> {
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
pub async fn clean_command(program: &str) -> plugin_toolkit::process::Command {
    let env = passed_env(|k| std::env::var(k).ok(), docker_host().await);
    plugin_toolkit::process::Command::new("/usr/bin/env")
        .arg("-i")
        .args(env)
        .arg(program)
}

/// Run the docker CLI with `args`, optionally in `cwd`, returning stdout,
/// through [`clean_command`].
pub async fn run(args: &[&str], cwd: Option<&str>) -> plugin_toolkit::anyhow::Result<String> {
    let mut cmd = clean_command(resolve_docker_bin()).await.args(args);
    if let Some(dir) = cwd {
        cmd = cmd.current_dir(dir);
    }
    let out = cmd.output().await?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success && stdout.trim().is_empty() {
        plugin_toolkit::anyhow::bail!("{}", stderr.trim());
    }
    Ok(if stdout.is_empty() { stderr } else { stdout })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let out = plugin_toolkit::reactor::block_on(run(
            &["compose", "-f", &file, "config", "--format", "json"],
            None,
        ))
        .unwrap();
        let cfg: plugin_toolkit::serde_json::Value =
            plugin_toolkit::serde_json::from_str(&out).unwrap();
        assert_eq!(
            cfg["services"]["app"]["environment"]["LEAK"], "unset",
            "{name}: {out}"
        );
    }
}
