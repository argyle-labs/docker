//! Docker Compose project wrapper. Search for the compose file, list
//! services, run lifecycle actions, parse `compose ps` output.
// serde_json::Value is used as a transient intermediate in parse_compose_ps
// to decode JSON-lines from `docker compose ps`; all outputs are typed structs.
#![allow(clippy::disallowed_types)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use plugin_toolkit::anyhow;
use plugin_toolkit::serde::{Deserialize, Serialize};
use plugin_toolkit::serde_json::{self, Value};

/// Compose-layer errors. Hand-rolled Display/Error/From (rather than a
/// thiserror derive) so the crate carries no path dependency on the derive's
/// emitted ::thiserror root — every external crate reaches this plugin only
/// through plugin_toolkit::*.
#[derive(Debug)]
pub enum ComposeError {
    NoComposeFile(PathBuf),
    Docker(anyhow::Error),
    UnknownAction(String),
}

impl std::fmt::Display for ComposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComposeError::NoComposeFile(p) => write!(f, "no compose file found in {}", p.display()),
            ComposeError::Docker(e) => write!(f, "docker error: {e}"),
            ComposeError::UnknownAction(a) => write!(f, "unknown action: {a}"),
        }
    }
}

impl std::error::Error for ComposeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ComposeError::Docker(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for ComposeError {
    fn from(e: anyhow::Error) -> Self {
        ComposeError::Docker(e)
    }
}

/// One row from `docker compose ps --format json`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
pub struct ServiceStatus {
    pub state: String,
    pub health: String,
    pub ports: Vec<String>,
}

/// Service with both declaration (name) and runtime status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
pub struct ServiceSummary {
    pub name: String,
    pub state: String,
    pub running: bool,
    pub health: String,
    pub ports: Vec<String>,
}

/// Override files compose would auto-load next to the compose file, in its
/// order. Passing `-f` turns auto-loading off, so the first one present must
/// be passed explicitly.
const OVERRIDE_FILES: &[&str] = &[
    "compose.override.yml",
    "compose.override.yaml",
    "docker-compose.override.yml",
    "docker-compose.override.yaml",
];

/// A located compose project.
#[derive(Debug, Clone)]
pub struct Compose {
    file: PathBuf,
    override_file: Option<PathBuf>,
}

impl Compose {
    /// Search `project_path` for the conventional compose filenames. Returns
    /// `None` when none are present (use [`Compose::open`] to error out).
    pub fn find(project_path: &Path) -> Option<Compose> {
        for name in &[
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ] {
            let full = project_path.join(name);
            if full.exists() {
                let override_file = OVERRIDE_FILES
                    .iter()
                    .map(|o| project_path.join(o))
                    .find(|o| o.exists());
                return Some(Compose {
                    file: full,
                    override_file,
                });
            }
        }
        None
    }

    /// Same as [`find`](Self::find) but errors out when nothing is found.
    pub fn open(project_path: &Path) -> Result<Compose, ComposeError> {
        Compose::find(project_path)
            .ok_or_else(|| ComposeError::NoComposeFile(project_path.to_path_buf()))
    }

    pub fn file(&self) -> &Path {
        &self.file
    }

    /// The compose files in `-f` order: the compose file, then its override.
    pub fn files(&self) -> Vec<&Path> {
        std::iter::once(self.file.as_path())
            .chain(self.override_file.as_deref())
            .collect()
    }

    /// `-f <file>` for each of [`files`](Self::files).
    pub fn file_args(&self) -> Vec<String> {
        self.files()
            .into_iter()
            .flat_map(|f| ["-f".to_string(), f.to_string_lossy().into_owned()])
            .collect()
    }

    /// Service names declared in the compose file.
    pub async fn service_names(&self) -> Result<Vec<String>, ComposeError> {
        let out = self.docker(&["config", "--services"]).await?;
        Ok(out
            .trim()
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    /// Service names + runtime status from `docker compose ps`.
    pub async fn services(&self) -> Result<Vec<ServiceSummary>, ComposeError> {
        let names = self.service_names().await?;
        let raw = self
            .docker(&["ps", "--format", "json"])
            .await
            .unwrap_or_default();
        let statuses = parse_compose_ps(&raw);
        Ok(names
            .iter()
            .map(|name| {
                let s = statuses.get(name.as_str()).cloned().unwrap_or_default();
                let running = s.state.to_lowercase().contains("running");
                ServiceSummary {
                    name: name.clone(),
                    state: s.state,
                    running,
                    health: s.health,
                    ports: s.ports,
                }
            })
            .collect())
    }

    /// `docker compose config --format json`: the file as compose resolves
    /// it, with interpolation applied, paths made absolute and mounts in long
    /// syntax.
    pub async fn config_json(&self) -> Result<String, ComposeError> {
        Ok(self.docker(&["config", "--format", "json"]).await?)
    }

    /// The project name from the resolved config: the value the engine stamps
    /// on `com.docker.compose.project`, which need not match the stack name.
    pub async fn project_name(&self) -> Result<String, ComposeError> {
        let raw = self.config_json().await?;
        parse_project_name(&raw).ok_or_else(|| {
            ComposeError::Docker(anyhow::anyhow!(
                "compose config for {} has no project name",
                self.file.display()
            ))
        })
    }

    pub async fn ps(&self) -> Result<HashMap<String, ServiceStatus>, ComposeError> {
        let raw = self.docker(&["ps", "--format", "json"]).await?;
        Ok(parse_compose_ps(&raw))
    }

    pub async fn start(&self, services: &[&str]) -> Result<String, ComposeError> {
        self.lifecycle("start", services).await
    }
    pub async fn stop(&self, services: &[&str]) -> Result<String, ComposeError> {
        self.lifecycle("stop", services).await
    }
    pub async fn restart(&self, services: &[&str]) -> Result<String, ComposeError> {
        self.lifecycle("restart", services).await
    }
    /// `docker compose up -d` for the given services (or all).
    pub async fn up(&self, services: &[&str]) -> Result<String, ComposeError> {
        Ok(self.docker(&up_args(services, false)).await?)
    }
    /// `up -d --remove-orphans`: also removes containers of services the
    /// compose files no longer declare. Only for callers that listed those
    /// orphans and had them confirmed.
    pub async fn up_removing_orphans(&self) -> Result<String, ComposeError> {
        Ok(self.docker(&up_args(&[], true)).await?)
    }
    /// `docker compose down`. When `services` is non-empty, falls back to
    /// `compose stop <svc>` since compose-down is project-scoped.
    pub async fn down(&self, services: &[&str]) -> Result<String, ComposeError> {
        if services.is_empty() {
            Ok(self.docker(&["down"]).await?)
        } else {
            self.lifecycle("stop", services).await
        }
    }
    pub async fn build(&self, services: &[&str]) -> Result<String, ComposeError> {
        let mut args = vec!["build", "--no-cache"];
        args.extend_from_slice(services);
        Ok(self.docker(&args).await?)
    }
    pub async fn pull(&self, services: &[&str]) -> Result<String, ComposeError> {
        Ok(self.docker(&pull_args(services)).await?)
    }
    pub async fn logs(&self, services: &[&str], tail: u32) -> Result<String, ComposeError> {
        let tail_str = tail.to_string();
        let mut args = vec!["logs", "--tail", tail_str.as_str(), "--no-color"];
        args.extend_from_slice(services);
        Ok(self.docker(&args).await?)
    }

    /// Generic action dispatcher matching the action strings the orca server
    /// accepts (`start`, `stop`, `restart`, `up`, `down`, `build`, `pull`,
    /// `logs`, `ps`). Centralizes the previous switch in the axum handler.
    pub async fn run_action(
        &self,
        action: &str,
        service: Option<&str>,
        tail: Option<u32>,
    ) -> Result<String, ComposeError> {
        let svc: Vec<&str> = service.map(|s| vec![s]).unwrap_or_default();
        match action {
            "start" => self.start(&svc).await,
            "stop" => self.stop(&svc).await,
            "restart" => self.restart(&svc).await,
            "up" => self.up(&svc).await,
            "down" => self.down(&svc).await,
            "build" => self.build(&svc).await,
            "pull" => self.pull(&svc).await,
            "logs" => self.logs(&svc, tail.unwrap_or(100)).await,
            "ps" => Ok(self.docker(&["ps", "--format", "json"]).await?),
            other => Err(ComposeError::UnknownAction(other.to_string())),
        }
    }

    async fn lifecycle(&self, action: &str, services: &[&str]) -> Result<String, ComposeError> {
        let mut args = vec![action];
        args.extend_from_slice(services);
        Ok(self.docker(&args).await?)
    }

    async fn docker(&self, sub: &[&str]) -> Result<String, anyhow::Error> {
        let files = self.file_args();
        let mut args: Vec<&str> = vec!["compose"];
        args.extend(files.iter().map(String::as_str));
        args.extend_from_slice(sub);
        super::run(&args, None).await
    }
}

fn up_args<'a>(services: &[&'a str], remove_orphans: bool) -> Vec<&'a str> {
    let mut args = vec!["up", "-d"];
    if remove_orphans {
        args.push("--remove-orphans");
    }
    args.extend_from_slice(services);
    args
}

/// `pull -q`: progress bars would fill the returned output.
fn pull_args<'a>(services: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["pull", "-q"];
    args.extend_from_slice(services);
    args
}

/// The top-level `name` of `docker compose config --format json` output.
pub fn parse_project_name(raw: &str) -> Option<String> {
    let v: Value = serde_json::from_str(raw).ok()?;
    v["name"]
        .as_str()
        .filter(|n| !n.is_empty())
        .map(str::to_string)
}

/// Engine-side names of the networks a resolved config declares
/// `external: true` (its `name`, else its key).
pub fn parse_external_networks(raw: &str) -> Vec<String> {
    let Ok(v): Result<Value, _> = serde_json::from_str(raw) else {
        return Vec::new();
    };
    let Some(nets) = v["networks"].as_object() else {
        return Vec::new();
    };
    nets.iter()
        .filter(|(_, n)| n["external"].as_bool() == Some(true))
        .map(|(key, n)| n["name"].as_str().unwrap_or(key).to_string())
        .collect()
}

/// Parse JSON-lines output of `docker compose ps --format json` into a map
/// keyed by service name.
pub fn parse_compose_ps(raw: &str) -> HashMap<String, ServiceStatus> {
    let mut out = HashMap::new();
    for line in raw.trim().lines() {
        let Ok(obj): Result<Value, _> = serde_json::from_str(line) else {
            continue;
        };
        let name = obj["Service"]
            .as_str()
            .or_else(|| obj["service"].as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let mut seen = HashSet::new();
        let empty: Vec<Value> = Vec::new();
        let ports: Vec<String> = obj["Publishers"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .filter_map(|p| {
                let pub_port = p["PublishedPort"].as_u64()?;
                let target = p["TargetPort"].as_u64()?;
                if pub_port == 0 {
                    return None;
                }
                let label = format!("{pub_port}:{target}");
                if seen.insert(label.clone()) {
                    Some(label)
                } else {
                    None
                }
            })
            .collect();
        out.insert(
            name,
            ServiceStatus {
                state: obj["State"].as_str().unwrap_or("unknown").to_string(),
                health: obj["Health"].as_str().unwrap_or("").to_string(),
                ports,
            },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn find_picks_first_match() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("compose.yaml"), "services: {}").unwrap();
        let c = Compose::find(dir.path()).unwrap();
        assert!(c.file.ends_with("compose.yaml"));
    }

    #[test]
    fn find_passes_the_override_compose_would_auto_load() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("docker-compose.yml"), "services: {}").unwrap();
        let c = Compose::find(dir.path()).unwrap();
        assert_eq!(c.file_args().len(), 2, "no override yet");
        std::fs::write(dir.path().join("docker-compose.override.yaml"), "").unwrap();
        std::fs::write(dir.path().join("compose.override.yml"), "").unwrap();
        let c = Compose::find(dir.path()).unwrap();
        let args = c.file_args();
        assert_eq!(args.len(), 4);
        assert_eq!(args[0], "-f");
        assert!(args[1].ends_with("docker-compose.yml"));
        assert!(args[3].ends_with("compose.override.yml"), "{args:?}");
    }

    #[test]
    fn find_returns_none_when_absent() {
        let dir = tempdir().unwrap();
        assert!(Compose::find(dir.path()).is_none());
    }

    #[test]
    fn parse_compose_ps_extracts_state_and_ports() {
        let raw = r#"{"Service":"web","State":"running","Health":"healthy","Publishers":[{"PublishedPort":8080,"TargetPort":80}]}
{"Service":"db","State":"exited","Health":"","Publishers":[]}
"#;
        let out = parse_compose_ps(raw);
        let web = &out["web"];
        assert_eq!(web.state, "running");
        assert_eq!(web.ports, vec!["8080:80"]);
        assert_eq!(out["db"].state, "exited");
    }

    #[test]
    fn parse_compose_ps_dedupes_repeated_publishers() {
        let raw = r#"{"Service":"web","State":"running","Health":"","Publishers":[{"PublishedPort":80,"TargetPort":80},{"PublishedPort":80,"TargetPort":80}]}
"#;
        let out = parse_compose_ps(raw);
        assert_eq!(out["web"].ports, vec!["80:80"]);
    }

    #[test]
    fn up_removes_orphans_only_when_asked_and_pull_is_quiet() {
        assert_eq!(up_args(&[], false), vec!["up", "-d"]);
        assert_eq!(up_args(&["web"], false), vec!["up", "-d", "web"]);
        assert_eq!(up_args(&[], true), vec!["up", "-d", "--remove-orphans"]);
        assert_eq!(pull_args(&[]), vec!["pull", "-q"]);
        assert_eq!(pull_args(&["web"]), vec!["pull", "-q", "web"]);
    }

    #[test]
    fn parse_project_name_reads_top_level_name() {
        assert_eq!(
            parse_project_name(r#"{"name":"media","services":{}}"#).as_deref(),
            Some("media")
        );
        assert_eq!(parse_project_name(r#"{"services":{}}"#), None);
        assert_eq!(parse_project_name("not json"), None);
    }

    #[test]
    fn parse_external_networks_reads_external_names() {
        let raw = r#"{"networks":{"default":{"name":"media_default"},"proxy":{"name":"caddy_proxy","external":true},"bare":{"external":true}}}"#;
        let mut nets = parse_external_networks(raw);
        nets.sort();
        assert_eq!(nets, vec!["bare", "caddy_proxy"]);
        assert!(parse_external_networks(r#"{"services":{}}"#).is_empty());
    }

    #[test]
    fn parse_compose_ps_skips_garbage_lines() {
        let raw = "not json\n{\"Service\":\"x\",\"State\":\"running\",\"Health\":\"\",\"Publishers\":[]}\n";
        let out = parse_compose_ps(raw);
        assert!(out.contains_key("x"));
    }
}
