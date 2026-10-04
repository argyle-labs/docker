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
//! A volume with neither is reported as uncovered. Exports and dumps are
//! staged in a per-run directory beside the archive and travel in the stack
//! archive under `.orca-volumes/`.

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

/// Image for the export helper container, pinned to the multi-arch index
/// digest so a retagged `alpine:3` cannot change what reads volume data.
pub const HELPER_IMAGE: &str =
    "alpine:3@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6";

/// Lists the policies a backup skipped, inside the staging dir, so the
/// archive itself says what it lacks.
pub const SKIPPED_FILE: &str = "SKIPPED";

/// Runs the dump command in the container with `pipefail` where that shell
/// has it, so `pg_dump | gzip` fails when `pg_dump` does. The command is
/// `$1`, never spliced into the script.
const DUMP_WRAPPER: &str =
    r#"if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi; eval "$1""#;

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
    /// Anonymous volumes: compose cannot label them, and no policy can name
    /// them. `stack update action=label_volumes` converts them.
    #[serde(default)]
    pub anonymous: Vec<crate::ownership::AnonymousVolume>,
    /// Engine volumes of the stack without `orca.managed`.
    #[serde(default)]
    pub unlabeled: Vec<String>,
    /// One line per uncovered volume, per policy naming a volume the stack
    /// no longer has, and per anonymous or unlabeled volume.
    pub warnings: Vec<String>,
}

impl StackCoverage {
    /// Add the stack's anonymous volumes and its engine volumes (named or
    /// anonymous) that lack orca's labels; `engine` is every engine volume's
    /// labels.
    pub fn with_ownership(
        mut self,
        anonymous: Vec<crate::ownership::AnonymousVolume>,
        engine: &crate::ownership::EngineVolumes,
    ) -> Self {
        let names = self
            .volumes
            .iter()
            .filter(|v| v.volume.exists && !v.volume.external)
            .map(|v| v.volume.engine_name.clone())
            .chain(anonymous.iter().flat_map(|a| a.engine_names.clone()));
        let mut unlabeled: Vec<String> = names
            .filter(|n| {
                engine
                    .get(n)
                    .is_some_and(|l| !crate::labels::is_managed(l.iter()))
            })
            .collect();
        unlabeled.sort();
        unlabeled.dedup();
        for a in &anonymous {
            self.warnings.push(format!(
                "anonymous volume at {}:{} cannot be labeled or backed up by policy; run action=label_volumes",
                a.service, a.target
            ));
        }
        for n in &unlabeled {
            self.warnings
                .push(format!("volume '{n}' has no orca ownership labels"));
        }
        self.anonymous = anonymous;
        self.unlabeled = unlabeled;
        self
    }
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
        anonymous: Vec::new(),
        unlabeled: Vec::new(),
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

/// Streams the command after `$1` into the file `$1`; every value is a
/// positional parameter.
const TO_FILE: &str = r#"out="$1"; shift; exec "$@" > "$out""#;

/// `sh` arguments that run `program args…` with stdout written to `out`.
fn to_file_args(out: &Path, program: &str, args: Vec<String>) -> Vec<String> {
    let mut v = vec![
        "-c".to_string(),
        TO_FILE.to_string(),
        "sh".to_string(),
        out.display().to_string(),
        program.to_string(),
    ];
    v.extend(args);
    v
}

/// `docker` arguments that stream a tar.gz of `engine_name` to stdout, from
/// a helper with no network and the volume mounted read-only.
pub fn export_args(engine_name: &str) -> Vec<String> {
    vec![
        "run".into(),
        "--rm".into(),
        "--network".into(),
        "none".into(),
        "--mount".into(),
        format!("type=volume,src={engine_name},dst=/v,readonly"),
        HELPER_IMAGE.into(),
        "tar".into(),
        "czf".into(),
        "-".into(),
        "-C".into(),
        "/v".into(),
        ".".into(),
    ]
}

/// `sh` arguments that stream a dump to `out_file` without holding it in
/// memory, through every compose file of the stack (`compose_files`, the
/// `-f` pairs). Values travel as positional parameters, never spliced into
/// either script.
pub fn dump_args(
    docker_bin: &str,
    compose_files: &[String],
    service: &str,
    command: &str,
    out_file: &Path,
) -> Vec<String> {
    let mut args: Vec<String> = vec!["compose".into()];
    args.extend(compose_files.iter().cloned());
    args.extend([
        "exec".into(),
        "-T".into(),
        service.into(),
        "sh".into(),
        "-c".into(),
        DUMP_WRAPPER.into(),
        "orca-dump".into(),
        command.into(),
    ]);
    to_file_args(out_file, docker_bin, args)
}

/// Create `path` empty with mode 0600; refuses an existing file.
pub fn create_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", path.display()))?;
    Ok(())
}

/// Whether the engine has a volume named `name`. External volumes and ones
/// with an explicit `name:` carry no project label, so only an inspect by
/// name answers this.
pub async fn volume_exists(docker: &Docker, name: &str) -> Result<bool> {
    match docker.inspect_volume(name).await {
        Ok(_) => Ok(true),
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("inspect volume {name}: {e}")),
    }
}

/// Set `exists` on volumes the project-label listing could not see.
pub async fn mark_existing(docker: &Docker, volumes: &mut [StackVolume]) -> Result<()> {
    for v in volumes.iter_mut().filter(|v| !v.exists) {
        v.exists = volume_exists(docker, &v.engine_name).await?;
    }
    Ok(())
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

/// A policy the backup did not stage, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedVolume {
    pub volume: String,
    pub reason: String,
}

/// What [`stage`] wrote and what it skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Staged {
    pub artifacts: Vec<String>,
    pub skipped: Vec<SkippedVolume>,
}

/// A fresh staging dir (mode 0700) for one backup run, under `parent`.
/// Unique per run, so concurrent backups never share or clear each other's
/// staging.
pub fn staging_root(parent: &Path, stack: &str) -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let root = parent.join(format!(
        ".orca-staging-{stack}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", root.display()))?;
    Ok(root)
}

/// Write every policy's export or dump into `<root>/.orca-volumes/` (mode
/// 0700; artifacts 0600). `root` comes from [`staging_root`] and is the
/// caller's to remove. A policy whose volume does not exist on the engine is
/// skipped and listed in [`SKIPPED_FILE`]: exporting it would create and
/// archive an empty volume. An export or dump that fails or writes nothing
/// fails the backup: an archive that claims coverage it lacks is worse than
/// none.
pub async fn stage(
    docker: &Docker,
    root: &Path,
    compose: &crate::Compose,
    volumes: &[StackVolume],
    policies: &[VolumePolicy],
) -> Result<Staged> {
    use std::os::unix::fs::DirBuilderExt;
    if policies.is_empty() {
        return Ok(Staged::default());
    }
    let staging = root.join(STAGING_DIR);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", staging.display()))?;
    let mut staged = Staged::default();
    for p in policies {
        let found = volumes.iter().find(|v| v.volume == p.volume);
        let exists = match found {
            Some(v) => volume_exists(docker, &v.engine_name).await?,
            None => false,
        };
        let (Some(v), true) = (found, exists) else {
            staged.skipped.push(SkippedVolume {
                volume: p.volume.clone(),
                reason: "the volume does not exist on the engine; nothing to back up".into(),
            });
            continue;
        };
        let artifact = artifact_name(p);
        let out = staging.join(&artifact);
        create_private(&out)?;
        let what = match p.strategy {
            Strategy::Export => {
                let what = format!("export volume '{}'", p.volume);
                run_checked(
                    "sh",
                    &to_file_args(
                        &out,
                        crate::resolve_docker_bin(),
                        export_args(&v.engine_name),
                    ),
                    &what,
                )
                .await?;
                what
            }
            Strategy::Dump => {
                let (Some(svc), Some(command)) = (&p.service, &p.command) else {
                    anyhow::bail!("dump policy for '{}' lacks a service or command", p.volume);
                };
                let what = format!("dump volume '{}'", p.volume);
                run_checked(
                    "sh",
                    &dump_args(
                        crate::resolve_docker_bin(),
                        &compose.file_args(),
                        svc,
                        command,
                        &out,
                    ),
                    &what,
                )
                .await?;
                what
            }
        };
        let len = std::fs::metadata(&out)
            .map_err(|e| anyhow::anyhow!("stat {}: {e}", out.display()))?
            .len();
        if len == 0 {
            anyhow::bail!("{what} produced no output");
        }
        staged.artifacts.push(format!("{STAGING_DIR}/{artifact}"));
    }
    if !staged.skipped.is_empty() {
        let lines: String = staged
            .skipped
            .iter()
            .map(|s| format!("{}: {}\n", s.volume, s.reason))
            .collect();
        let path = staging.join(SKIPPED_FILE);
        std::fs::write(&path, lines)
            .map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))?;
        for s in &staged.skipped {
            plugin_toolkit::tracing::warn!(target: "docker::volumes", volume = %s.volume, reason = %s.reason, "volume backup skipped");
        }
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
    fn coverage_reports_anonymous_and_unlabeled_volumes() {
        let engine = [
            engine_volume("media_data", Some("data")),
            engine_volume("media_pg", Some("pg")),
        ];
        let mut labels: crate::ownership::EngineVolumes = engine
            .iter()
            .map(|v| (v.name.clone(), v.labels.clone()))
            .collect();
        labels
            .get_mut("media_pg")
            .unwrap()
            .insert(crate::labels::MANAGED.into(), "true".into());
        labels.insert("abc123".into(), Default::default());
        let anon = vec![crate::ownership::AnonymousVolume {
            service: "app".into(),
            target: "/cache".into(),
            engine_names: vec!["abc123".into()],
        }];
        let c =
            coverage("media", "media", detect(&cfg(), &engine), &[]).with_ownership(anon, &labels);
        assert_eq!(c.unlabeled, vec!["abc123", "media_data"]);
        assert_eq!(c.anonymous[0].target, "/cache");
        assert!(c.warnings.iter().any(|w| w.contains("app:/cache")));
        assert!(!c.warnings.iter().any(|w| w.contains("'media_pg' has no")));
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
    fn export_streams_from_a_networkless_pinned_helper_with_the_volume_read_only() {
        assert_eq!(
            export_args("media_data"),
            vec![
                "run",
                "--rm",
                "--network",
                "none",
                "--mount",
                "type=volume,src=media_data,dst=/v,readonly",
                HELPER_IMAGE,
                "tar",
                "czf",
                "-",
                "-C",
                "/v",
                "."
            ]
        );
        assert!(HELPER_IMAGE.contains("@sha256:"));
        let a = to_file_args(Path::new("/s/data.tar.gz"), "docker", export_args("v"));
        assert_eq!(a[..5], ["-c", TO_FILE, "sh", "/s/data.tar.gz", "docker"]);
    }

    #[test]
    fn dump_passes_values_as_positional_parameters_through_every_compose_file() {
        let files = vec![
            "-f".to_string(),
            "/srv/media/docker-compose.yml".to_string(),
            "-f".to_string(),
            "/srv/media/compose.override.yml".to_string(),
        ];
        let a = dump_args(
            "/usr/bin/docker",
            &files,
            "db",
            "pg_dumpall -U postgres; rm -rf /",
            Path::new("/srv/media/.orca-volumes/pg.dump"),
        );
        // Both scripts are fixed; the command is the last positional argument.
        assert_eq!(a[1], r#"out="$1"; shift; exec "$@" > "$out""#);
        assert_eq!(a[3], "/srv/media/.orca-volumes/pg.dump");
        assert_eq!(
            a[4..10],
            [
                "/usr/bin/docker",
                "compose",
                "-f",
                "/srv/media/docker-compose.yml",
                "-f",
                "/srv/media/compose.override.yml"
            ]
        );
        assert_eq!(a[10..13], ["exec", "-T", "db"]);
        assert_eq!(a[15], DUMP_WRAPPER);
        assert!(DUMP_WRAPPER.contains("set -o pipefail") && DUMP_WRAPPER.contains(r#"eval "$1""#));
        assert_eq!(a.last().unwrap(), "pg_dumpall -U postgres; rm -rf /");
    }

    fn compose_in(dir: &Path) -> crate::Compose {
        std::fs::write(dir.join("docker-compose.yml"), "services: {}\n").unwrap();
        crate::Compose::open(dir).unwrap()
    }

    const VOLUME_JSON: &str =
        r#"{"Name":"x","Driver":"local","Mountpoint":"","Labels":{},"Scope":"local","Options":{}}"#;

    #[test]
    fn stage_with_no_policies_stages_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let e = FakeEngine::routed(vec![]);
        let staged = plugin_toolkit::reactor::block_on(stage(
            &e.client(),
            dir.path(),
            &compose_in(dir.path()),
            &[],
            &[],
        ))
        .unwrap();
        assert_eq!(staged, Staged::default());
        assert!(!dir.path().join(STAGING_DIR).exists());
    }

    #[test]
    fn stage_skips_and_reports_volumes_that_do_not_exist() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let e = FakeEngine::routed(vec![]);
        let declared_only = detect(&cfg(), &[]);
        let staged = plugin_toolkit::reactor::block_on(stage(
            &e.client(),
            dir.path(),
            &compose_in(dir.path()),
            &declared_only,
            &[
                policy("data", Strategy::Export),
                policy("gone", Strategy::Export),
            ],
        ))
        .unwrap();
        assert!(staged.artifacts.is_empty(), "nothing exported: {staged:?}");
        let skipped: Vec<_> = staged.skipped.iter().map(|s| s.volume.as_str()).collect();
        assert_eq!(skipped, vec!["data", "gone"]);
        // Existence was asked of the engine by name.
        assert!(
            e.paths("GET")
                .iter()
                .any(|p| p.ends_with("/volumes/media_data"))
        );
        let staging = dir.path().join(STAGING_DIR);
        let listed = std::fs::read_to_string(staging.join(SKIPPED_FILE)).unwrap();
        assert!(
            listed.contains("data: ") && listed.contains("gone: "),
            "{listed}"
        );
        let mode = std::fs::metadata(&staging).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn external_and_explicitly_named_volumes_exist_when_the_engine_has_them() {
        let e = FakeEngine::routed(vec![
            Route::new("GET", "/volumes/shared", 200, VOLUME_JSON),
            Route::new("GET", "/volumes/media_data", 200, VOLUME_JSON),
        ]);
        let mut vols = detect(&cfg(), &[]);
        plugin_toolkit::reactor::block_on(mark_existing(&e.client(), &mut vols)).unwrap();
        let by = |k: &str| vols.iter().find(|v| v.volume == k).unwrap().exists;
        assert!(by("shared") && by("data"));
        assert!(!by("pg"));
    }

    #[test]
    fn a_dump_without_a_command_fails_the_stage() {
        let dir = tempfile::tempdir().unwrap();
        let e = FakeEngine::routed(vec![Route::new(
            "GET",
            "/volumes/media_pg",
            200,
            VOLUME_JSON,
        )]);
        let mut p = policy("pg", Strategy::Dump);
        p.command = None;
        let err = plugin_toolkit::reactor::block_on(stage(
            &e.client(),
            dir.path(),
            &compose_in(dir.path()),
            &detect(&cfg(), &[]),
            &[p],
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("lacks a service or command"),
            "{err}"
        );
    }

    #[test]
    fn artifacts_are_created_private_and_never_reused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pg.dump");
        create_private(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(create_private(&p).is_err());
    }

    #[test]
    fn each_run_gets_its_own_private_staging_root() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let a = staging_root(dir.path(), "media").unwrap();
        let b = staging_root(dir.path(), "media").unwrap();
        assert_ne!(a, b);
        let mode = std::fs::metadata(&a).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
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
