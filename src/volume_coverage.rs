//! Named-volume backup coverage for managed stacks.
//!
//! A stack backup tars the stack's project directory, which misses data on
//! named volumes. Each named volume gets a policy in the `docker.volume_policies`
//! table:
//! - `export`: the stack backup tars the volume through a throwaway helper
//!   container (`docker run --rm -v <vol>:/v:ro … tar`);
//! - `dump`: the stack backup runs an app-native dump command in a service
//!   (e.g. `pg_dumpall -U postgres` for a postgres volume) and keeps its stdout.
//!
//! A volume with neither is reported as uncovered. Exports and dumps land in
//! `<stack dir>/.orca-volumes/` for the duration of the backup and travel in
//! the stack archive under that path.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bollard::Docker;
use bollard::models::Volume;
use bollard::query_parameters::ListVolumesOptionsBuilder;
use plugin_toolkit::abi::{DbOp, DbRow, DbValue};
use plugin_toolkit::anyhow::{self, Result};
use plugin_toolkit::runtime::{db_op, field_from_row};
use plugin_toolkit::schemars::JsonSchema;
use plugin_toolkit::serde::{Deserialize, Serialize};

use crate::compose_config::ComposeConfig;
use crate::prune::{COMPOSE_PROJECT_LABEL, COMPOSE_VOLUME_LABEL};

const TABLE: &str = "volume_policies";

/// Directory inside the stack dir that carries volume exports and dumps.
pub const STAGING_DIR: &str = ".orca-volumes";

/// Image for the export helper container.
pub const HELPER_IMAGE: &str = "alpine:3";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "lowercase")]
pub enum Strategy {
    /// Tar the volume through a helper container.
    Export,
    /// Run an app-native dump command in a service.
    Dump,
}

impl Strategy {
    fn as_str(self) -> &'static str {
        match self {
            Strategy::Export => "export",
            Strategy::Dump => "dump",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "export" => Ok(Strategy::Export),
            "dump" => Ok(Strategy::Dump),
            other => anyhow::bail!("unknown volume strategy '{other}'"),
        }
    }
}

/// How one stack volume is backed up. `volume` is the compose key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct VolumePolicy {
    pub stack: String,
    pub volume: String,
    pub strategy: Strategy,
    /// `dump` only: the service to run the command in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// `dump` only: run with `sh -c`; its stdout is the dump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

impl VolumePolicy {
    fn key(stack: &str, volume: &str) -> String {
        format!("{stack}/{volume}")
    }

    /// A dump needs a service the stack declares and a command.
    pub fn validate(&self, cfg: &ComposeConfig) -> Result<()> {
        if self.strategy == Strategy::Dump {
            let svc = self
                .service
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("a dump policy needs a service"))?;
            if !cfg.services.contains_key(svc) {
                anyhow::bail!("stack has no service '{svc}'");
            }
            if self.command.as_deref().is_none_or(|c| c.trim().is_empty()) {
                anyhow::bail!("a dump policy needs a command");
            }
        }
        Ok(())
    }
}

fn opt(v: &Option<String>) -> DbValue {
    match v {
        Some(s) => DbValue::Text(s.clone()),
        None => DbValue::Null,
    }
}

fn to_dbrow(p: &VolumePolicy) -> DbRow {
    let mut m = DbRow::new();
    m.insert(
        "id".to_string(),
        DbValue::Text(VolumePolicy::key(&p.stack, &p.volume)),
    );
    m.insert("stack".to_string(), DbValue::Text(p.stack.clone()));
    m.insert("volume".to_string(), DbValue::Text(p.volume.clone()));
    m.insert(
        "strategy".to_string(),
        DbValue::Text(p.strategy.as_str().to_string()),
    );
    m.insert("service".to_string(), opt(&p.service));
    m.insert("command".to_string(), opt(&p.command));
    m
}

fn from_dbrow(m: &DbRow) -> Result<VolumePolicy> {
    Ok(VolumePolicy {
        stack: field_from_row(m, "stack")?,
        volume: field_from_row(m, "volume")?,
        strategy: Strategy::parse(&field_from_row::<String>(m, "strategy")?)?,
        service: field_from_row(m, "service")?,
        command: field_from_row(m, "command")?,
    })
}

/// Policies declared for one stack.
pub fn policies(stack: &str) -> Result<Vec<VolumePolicy>> {
    let reply = db_op(&DbOp::List {
        namespace: "docker".to_string(),
        table: TABLE.to_string(),
    })?;
    Ok(reply
        .rows
        .iter()
        .map(from_dbrow)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|p| p.stack == stack)
        .collect())
}

pub fn put(p: &VolumePolicy) -> Result<()> {
    db_op(&DbOp::Upsert {
        namespace: "docker".to_string(),
        table: TABLE.to_string(),
        row: to_dbrow(p),
    })?;
    Ok(())
}

pub fn remove(stack: &str, volume: &str) -> Result<bool> {
    let reply = db_op(&DbOp::Delete {
        namespace: "docker".to_string(),
        table: TABLE.to_string(),
        key_col: "id".to_string(),
        key: VolumePolicy::key(stack, volume),
    })?;
    Ok(reply.affected > 0)
}

/// One named volume of a stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackVolume {
    /// The compose key services refer to.
    pub volume: String,
    /// The engine-side name.
    pub engine_name: String,
    /// Services that mount it.
    pub services: Vec<String>,
    /// Declared in the current compose file.
    pub declared: bool,
    /// Present on the engine.
    pub exists: bool,
    /// Created outside this stack (`external: true`).
    pub external: bool,
}

/// Named volumes of a stack, from its resolved config and the engine's
/// volumes labeled with its project. An engine volume the file no longer
/// declares still holds data, so it is listed with `declared: false`.
pub fn detect(cfg: &ComposeConfig, engine: &[Volume]) -> Vec<StackVolume> {
    let mut out: BTreeMap<String, StackVolume> = BTreeMap::new();
    for (key, v) in &cfg.volumes {
        out.insert(
            key.clone(),
            StackVolume {
                volume: key.clone(),
                engine_name: v
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("{}_{key}", cfg.name)),
                services: Vec::new(),
                declared: true,
                exists: false,
                external: v.external == Some(true),
            },
        );
    }
    for (svc, s) in &cfg.services {
        for vol in s.volumes.iter().filter_map(|m| m.named_volume()) {
            let entry = out.entry(vol.to_string()).or_insert_with(|| StackVolume {
                volume: vol.to_string(),
                engine_name: format!("{}_{vol}", cfg.name),
                services: Vec::new(),
                declared: true,
                exists: false,
                external: false,
            });
            if !entry.services.contains(svc) {
                entry.services.push(svc.clone());
            }
        }
    }
    for v in engine {
        if v.labels.get(COMPOSE_PROJECT_LABEL) != Some(&cfg.name) {
            continue;
        }
        if let Some(entry) = out.values_mut().find(|e| e.engine_name == v.name) {
            entry.exists = true;
            continue;
        }
        let key = v
            .labels
            .get(COMPOSE_VOLUME_LABEL)
            .cloned()
            .unwrap_or_else(|| v.name.clone());
        out.insert(
            key.clone(),
            StackVolume {
                volume: key,
                engine_name: v.name.clone(),
                services: Vec::new(),
                declared: false,
                exists: true,
                external: false,
            },
        );
    }
    out.into_values().collect()
}

/// Engine volumes labeled with `project`.
pub async fn engine_volumes(docker: &Docker, project: &str) -> Result<Vec<Volume>> {
    let filters = std::collections::HashMap::from([(
        "label",
        vec![format!("{COMPOSE_PROJECT_LABEL}={project}")],
    )]);
    Ok(docker
        .list_volumes(Some(
            ListVolumesOptionsBuilder::new().filters(&filters).build(),
        ))
        .await
        .map_err(|e| anyhow::anyhow!("list volumes of {project}: {e}"))?
        .volumes
        .unwrap_or_default())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct VolumeCoverage {
    #[serde(flatten)]
    pub volume: StackVolume,
    /// `export`, `dump`, or absent when uncovered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_by: Option<Strategy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackCoverage {
    pub name: String,
    pub project: String,
    pub volumes: Vec<VolumeCoverage>,
    /// One line per uncovered volume, and per policy naming a volume the
    /// stack no longer has.
    pub warnings: Vec<String>,
}

pub fn coverage(
    stack: &str,
    project: &str,
    volumes: Vec<StackVolume>,
    policies: &[VolumePolicy],
) -> StackCoverage {
    let mut warnings = Vec::new();
    let volumes: Vec<VolumeCoverage> = volumes
        .into_iter()
        .map(|v| {
            let covered_by = policies
                .iter()
                .find(|p| p.volume == v.volume)
                .map(|p| p.strategy);
            if covered_by.is_none() {
                warnings.push(format!(
                    "volume '{}' ({}) is not covered by the stack backup; declare export or dump",
                    v.volume, v.engine_name
                ));
            }
            VolumeCoverage {
                volume: v,
                covered_by,
            }
        })
        .collect();
    for p in policies {
        if !volumes.iter().any(|v| v.volume.volume == p.volume) {
            warnings.push(format!(
                "policy for volume '{}' matches no volume of this stack",
                p.volume
            ));
        }
    }
    StackCoverage {
        name: stack.to_string(),
        project: project.to_string(),
        volumes,
        warnings,
    }
}

/// Archive file name of a volume's export or dump inside [`STAGING_DIR`].
pub fn artifact_name(p: &VolumePolicy) -> String {
    match p.strategy {
        Strategy::Export => format!("{}.tar.gz", p.volume),
        Strategy::Dump => format!("{}.dump", p.volume),
    }
}

/// `docker` arguments that tar `engine_name` into `out_dir` read-only.
pub fn export_args(engine_name: &str, out_dir: &Path, artifact: &str) -> Vec<String> {
    vec![
        "run".into(),
        "--rm".into(),
        "-v".into(),
        format!("{engine_name}:/v:ro"),
        "-v".into(),
        format!("{}:/out", out_dir.display()),
        HELPER_IMAGE.into(),
        "tar".into(),
        "czf".into(),
        format!("/out/{artifact}"),
        "-C".into(),
        "/v".into(),
        ".".into(),
    ]
}

/// `sh` arguments that stream a dump to `out_file` without holding it in
/// memory. Values travel as positional parameters, never spliced into the
/// script.
pub fn dump_args(
    docker_bin: &str,
    compose_file: &Path,
    service: &str,
    command: &str,
    out_file: &Path,
) -> Vec<String> {
    vec![
        "-c".into(),
        r#""$0" compose -f "$1" exec -T "$2" sh -c "$3" > "$4""#.into(),
        docker_bin.into(),
        compose_file.display().to_string(),
        service.into(),
        command.into(),
        out_file.display().to_string(),
    ]
}

async fn run_checked(program: &str, args: &[String], what: &str) -> Result<()> {
    let mut cmd = plugin_toolkit::process::Command::new(program).args(args);
    if let Some(host) = crate::docker_host().await {
        cmd = cmd.env("DOCKER_HOST", host);
    }
    let out = cmd.output().await?;
    if !out.status.success {
        anyhow::bail!("{what}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Write every policy's export or dump into `<stack dir>/.orca-volumes/`,
/// replacing what was there. Any failure fails the backup: an archive that
/// claims coverage it lacks is worse than none.
pub async fn stage(
    stack_dir: &Path,
    compose_file: &Path,
    volumes: &[StackVolume],
    policies: &[VolumePolicy],
) -> Result<Vec<String>> {
    let staging: PathBuf = stack_dir.join(STAGING_DIR);
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .map_err(|e| anyhow::anyhow!("clear {}: {e}", staging.display()))?;
    }
    if policies.is_empty() {
        return Ok(Vec::new());
    }
    std::fs::create_dir_all(&staging)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", staging.display()))?;
    let mut staged = Vec::new();
    for p in policies {
        let artifact = artifact_name(p);
        match p.strategy {
            Strategy::Export => {
                let v = volumes
                    .iter()
                    .find(|v| v.volume == p.volume)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "volume '{}' has an export policy but does not exist",
                            p.volume
                        )
                    })?;
                run_checked(
                    crate::resolve_docker_bin(),
                    &export_args(&v.engine_name, &staging, &artifact),
                    &format!("export volume '{}'", p.volume),
                )
                .await?;
            }
            Strategy::Dump => {
                let (Some(svc), Some(command)) = (&p.service, &p.command) else {
                    anyhow::bail!("dump policy for '{}' lacks a service or command", p.volume);
                };
                run_checked(
                    "sh",
                    &dump_args(
                        crate::resolve_docker_bin(),
                        compose_file,
                        svc,
                        command,
                        &staging.join(&artifact),
                    ),
                    &format!("dump volume '{}'", p.volume),
                )
                .await?;
            }
        }
        staged.push(format!("{STAGING_DIR}/{artifact}"));
    }
    Ok(staged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose_config::FIXTURE;
    use crate::test_engine::{FakeEngine, Route};

    fn cfg() -> ComposeConfig {
        ComposeConfig::parse(FIXTURE).unwrap()
    }

    fn engine_volume(name: &str, key: Option<&str>) -> Volume {
        let mut labels = std::collections::HashMap::new();
        labels.insert(COMPOSE_PROJECT_LABEL.to_string(), "media".to_string());
        if let Some(k) = key {
            labels.insert(COMPOSE_VOLUME_LABEL.to_string(), k.to_string());
        }
        Volume {
            name: name.into(),
            driver: "local".into(),
            mountpoint: String::new(),
            labels,
            options: Default::default(),
            ..Default::default()
        }
    }

    fn policy(volume: &str, strategy: Strategy) -> VolumePolicy {
        VolumePolicy {
            stack: "media".into(),
            volume: volume.into(),
            strategy,
            service: (strategy == Strategy::Dump).then(|| "db".into()),
            command: (strategy == Strategy::Dump).then(|| "pg_dumpall -U postgres".into()),
        }
    }

    #[test]
    fn detect_merges_compose_and_engine() {
        let engine = [
            engine_volume("media_data", Some("data")),
            engine_volume("media_oldcache", Some("oldcache")),
        ];
        let v = detect(&cfg(), &engine);
        let by = |k: &str| v.iter().find(|x| x.volume == k).unwrap().clone();
        let data = by("data");
        assert_eq!(data.engine_name, "media_data");
        assert_eq!(data.services, vec!["app"]);
        assert!(data.declared && data.exists);
        let pg = by("pg");
        assert_eq!(pg.services, vec!["db"]);
        assert!(!pg.exists);
        assert!(by("shared").external);
        let old = by("oldcache");
        assert!(!old.declared && old.exists);
    }

    #[test]
    fn engine_volumes_of_other_projects_are_ignored() {
        let mut other = engine_volume("other_data", Some("data"));
        other
            .labels
            .insert(COMPOSE_PROJECT_LABEL.into(), "other".into());
        assert!(
            !detect(&cfg(), &[other])
                .iter()
                .any(|v| v.engine_name == "other_data")
        );
    }

    #[test]
    fn coverage_warns_on_uncovered_and_dangling_policies() {
        let vols = detect(&cfg(), &[]);
        let c = coverage(
            "media",
            "media",
            vols,
            &[
                policy("data", Strategy::Export),
                policy("gone", Strategy::Export),
            ],
        );
        let data = c
            .volumes
            .iter()
            .find(|v| v.volume.volume == "data")
            .unwrap();
        assert_eq!(data.covered_by, Some(Strategy::Export));
        assert!(c.warnings.iter().any(|w| w.contains("'pg'")));
        assert!(c.warnings.iter().any(|w| w.contains("'shared'")));
        assert!(
            c.warnings
                .iter()
                .any(|w| w.contains("'gone' matches no volume"))
        );
        assert!(!c.warnings.iter().any(|w| w.contains("'data' (")));
    }

    #[test]
    fn dump_policy_needs_a_declared_service_and_a_command() {
        assert!(policy("pg", Strategy::Dump).validate(&cfg()).is_ok());
        let mut p = policy("pg", Strategy::Dump);
        p.service = Some("nope".into());
        assert!(
            p.validate(&cfg())
                .unwrap_err()
                .to_string()
                .contains("no service")
        );
        let mut p = policy("pg", Strategy::Dump);
        p.command = Some("  ".into());
        assert!(
            p.validate(&cfg())
                .unwrap_err()
                .to_string()
                .contains("command")
        );
        assert!(policy("data", Strategy::Export).validate(&cfg()).is_ok());
    }

    #[test]
    fn export_mounts_the_volume_read_only_into_a_helper() {
        let a = export_args(
            "media_data",
            Path::new("/srv/media/.orca-volumes"),
            "data.tar.gz",
        );
        assert_eq!(
            a,
            vec![
                "run",
                "--rm",
                "-v",
                "media_data:/v:ro",
                "-v",
                "/srv/media/.orca-volumes:/out",
                HELPER_IMAGE,
                "tar",
                "czf",
                "/out/data.tar.gz",
                "-C",
                "/v",
                "."
            ]
        );
    }

    #[test]
    fn dump_passes_values_as_positional_parameters() {
        let a = dump_args(
            "/usr/bin/docker",
            Path::new("/srv/media/docker-compose.yml"),
            "db",
            "pg_dumpall -U postgres; rm -rf /",
            Path::new("/srv/media/.orca-volumes/pg.dump"),
        );
        // The script is fixed; the command is an argument to `sh -c` inside
        // the container, never part of the host script.
        assert_eq!(
            a[1],
            r#""$0" compose -f "$1" exec -T "$2" sh -c "$3" > "$4""#
        );
        assert_eq!(a[5], "pg_dumpall -U postgres; rm -rf /");
    }

    #[test]
    fn stage_with_no_policies_clears_stale_exports() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join(STAGING_DIR);
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("old.tar.gz"), b"x").unwrap();
        let staged = plugin_toolkit::reactor::block_on(stage(
            dir.path(),
            &dir.path().join("docker-compose.yml"),
            &[],
            &[],
        ))
        .unwrap();
        assert!(staged.is_empty());
        assert!(!stale.exists());
    }

    #[test]
    fn stage_fails_closed_when_an_export_volume_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let err = plugin_toolkit::reactor::block_on(stage(
            dir.path(),
            &dir.path().join("docker-compose.yml"),
            &[],
            &[policy("data", Strategy::Export)],
        ))
        .unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn engine_volumes_filters_by_project_label() {
        let e = FakeEngine::routed(vec![Route::new(
            "GET",
            "/volumes",
            200,
            r#"{"Volumes":[],"Warnings":[]}"#,
        )]);
        plugin_toolkit::reactor::block_on(engine_volumes(&e.client(), "media")).unwrap();
        assert!(
            e.targets("GET")[0].contains(r#""label":["com.docker.compose.project=media"]"#),
            "{:?}",
            e.targets("GET")
        );
    }

    #[test]
    fn policy_row_roundtrips() {
        let p = policy("pg", Strategy::Dump);
        assert_eq!(from_dbrow(&to_dbrow(&p)).unwrap(), p);
        let e = policy("data", Strategy::Export);
        let row = to_dbrow(&e);
        assert_eq!(row["service"], DbValue::Null);
        assert_eq!(from_dbrow(&row).unwrap(), e);
    }
}
