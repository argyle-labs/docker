//! Named-volume backup coverage for managed stacks.
//!
//! A stack backup tars the stack's project directory, which misses data on
//! named volumes. Each named volume gets a policy in the `docker.volume_policies`
//! table:
//! - `export`: the stack backup archives the volume through the Engine API
//!   (see [`crate::stack_volumes`]) and a stack restore writes it back;
//! - `dump`: the stack backup execs an app-native dump command in the
//!   service's container (e.g. `pg_dumpall -U postgres` for a postgres
//!   volume) and keeps its stdout; restoring a dump is left to the app.
//!
//! A volume with neither is reported as uncovered. Exports and dumps are
//! staged in a per-run directory beside the archive and travel in the stack
//! archive under `.orca-volumes/`, with a [`MANIFEST_FILE`] of their sha256
//! sums that every restore checks before it writes anything.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use bollard::Docker;
use bollard::container::LogOutput;
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::models::Volume;
use bollard::query_parameters::{ListContainersOptionsBuilder, ListVolumesOptionsBuilder};
use plugin_toolkit::abi::{DbOp, DbRow, DbValue};
use plugin_toolkit::anyhow::{self, Result};
use plugin_toolkit::runtime::{db_op, field_from_row};
use plugin_toolkit::schemars::JsonSchema;
use plugin_toolkit::serde::{Deserialize, Serialize};

use crate::compose_config::ComposeConfig;
use crate::ownership::COMPOSE_SERVICE_LABEL;
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

/// The [`VolumesManifest`] inside the staging dir.
pub const MANIFEST_FILE: &str = "manifest.json";
const MAX_MANIFEST_BYTES: u64 = 16 << 20;
/// Dump stderr kept for the error message.
const MAX_STDERR_BYTES: usize = 64 << 10;

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

/// An export or dump that wrote nothing backs nothing up.
pub fn ensure_nonempty(path: &Path, what: &str) -> Result<()> {
    let len = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("stat {}: {e}", path.display()))?
        .len();
    if len == 0 {
        anyhow::bail!("{what} produced no output");
    }
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

/// The id of a running container of compose `service` in `project`.
async fn service_container(docker: &Docker, project: &str, service: &str) -> Result<String> {
    let filters = HashMap::from([
        (
            "label".to_string(),
            vec![
                format!("{COMPOSE_PROJECT_LABEL}={project}"),
                format!("{COMPOSE_SERVICE_LABEL}={service}"),
            ],
        ),
        ("status".to_string(), vec!["running".to_string()]),
    ]);
    let found = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::new()
                .filters(&filters)
                .build(),
        ))
        .await
        .map_err(|e| anyhow::anyhow!("list containers of service {service}: {e}"))?;
    found
        .into_iter()
        .find_map(|c| c.id)
        .ok_or_else(|| anyhow::anyhow!("service '{service}' has no running container to dump from"))
}

/// Exec `command` in `container` through [`DUMP_WRAPPER`], streaming its
/// stdout into `out`. A non-zero exit fails with its stderr.
async fn dump(docker: &Docker, container: &str, command: &str, out: &Path) -> Result<()> {
    let cmd = ["sh", "-c", DUMP_WRAPPER, "orca-dump", command]
        .map(String::from)
        .to_vec();
    let exec = docker
        .create_exec(
            container,
            CreateExecOptions {
                cmd: Some(cmd),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("create dump exec: {e}"))?;
    let started = docker
        .start_exec(&exec.id, None)
        .await
        .map_err(|e| anyhow::anyhow!("start dump exec: {e}"))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(out)
        .map_err(|e| anyhow::anyhow!("open {}: {e}", out.display()))?;
    let mut stderr = Vec::new();
    if let StartExecResults::Attached { mut output, .. } = started {
        while let Some(chunk) = plugin_toolkit::stream::next(&mut output).await {
            match chunk.map_err(|e| anyhow::anyhow!("read dump output: {e}"))? {
                LogOutput::StdErr { message } => {
                    let room = MAX_STDERR_BYTES.saturating_sub(stderr.len());
                    stderr.extend_from_slice(&message[..message.len().min(room)]);
                }
                LogOutput::StdOut { message } | LogOutput::Console { message } => {
                    file.write_all(&message)?
                }
                LogOutput::StdIn { .. } => {}
            }
        }
    }
    file.sync_all()?;
    // The exit code is only known once the attached stream has drained.
    let code = docker
        .inspect_exec(&exec.id)
        .await
        .map_err(|e| anyhow::anyhow!("inspect dump exec: {e}"))?
        .exit_code;
    if code != Some(0) {
        anyhow::bail!(
            "exit {}: {}",
            code.map_or("unknown".into(), |c| c.to_string()),
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    Ok(())
}

/// A policy the backup did not stage, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
pub struct SkippedVolume {
    pub volume: String,
    pub reason: String,
}

fn local_driver() -> String {
    "local".into()
}

/// One staged export or dump. `driver`, `labels` and `options` are the
/// volume's at backup, so a restore can create it as it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
#[serde(rename_all = "camelCase")]
pub struct VolumeArtifact {
    pub volume: String,
    pub engine_name: String,
    pub strategy: Strategy,
    /// File name inside [`STAGING_DIR`].
    pub artifact: String,
    pub sha256: String,
    pub size: u64,
    #[serde(default = "local_driver")]
    pub driver: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
}

/// What [`stage`] wrote and what it skipped; written as [`MANIFEST_FILE`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
pub struct VolumesManifest {
    pub artifacts: Vec<VolumeArtifact>,
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
/// none. Dumps run in a running container of the policy's service in compose
/// project `project`.
pub async fn stage(
    docker: &Docker,
    root: &Path,
    project: &str,
    volumes: &[StackVolume],
    policies: &[VolumePolicy],
) -> Result<VolumesManifest> {
    use std::os::unix::fs::DirBuilderExt;
    if policies.is_empty() {
        return Ok(VolumesManifest::default());
    }
    let staging = root.join(STAGING_DIR);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", staging.display()))?;
    let mut staged = VolumesManifest::default();
    for p in policies {
        let found = volumes.iter().find(|v| v.volume == p.volume);
        let have = match found {
            Some(v) => crate::stack_volumes::existing(docker, &v.engine_name).await?,
            None => None,
        };
        let (Some(v), Some(have)) = (found, have) else {
            staged.skipped.push(SkippedVolume {
                volume: p.volume.clone(),
                reason: "the volume does not exist on the engine; nothing to back up".into(),
            });
            continue;
        };
        let artifact = artifact_name(p);
        let out = staging.join(&artifact);
        let (sha256, size) = match p.strategy {
            Strategy::Export => crate::stack_volumes::export_one(docker, &v.engine_name, &out)
                .await
                .map_err(|e| e.context(format!("export volume '{}'", p.volume)))?,
            Strategy::Dump => {
                let (Some(svc), Some(command)) = (&p.service, &p.command) else {
                    anyhow::bail!("dump policy for '{}' lacks a service or command", p.volume);
                };
                let what = format!("dump volume '{}'", p.volume);
                create_private(&out)?;
                let container = service_container(docker, project, svc).await?;
                dump(docker, &container, command, &out)
                    .await
                    .map_err(|e| e.context(what.clone()))?;
                ensure_nonempty(&out, &what)?;
                let size = std::fs::metadata(&out)?.len();
                (plugin_toolkit::hash::sha256_file(&out)?, size)
            }
        };
        staged.artifacts.push(VolumeArtifact {
            volume: p.volume.clone(),
            engine_name: v.engine_name.clone(),
            strategy: p.strategy,
            artifact,
            sha256,
            size,
            driver: have.driver,
            labels: have.labels.into_iter().collect(),
            options: have.options.into_iter().collect(),
        });
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
    let path = staging.join(MANIFEST_FILE);
    create_private(&path)?;
    std::fs::write(&path, plugin_toolkit::serde_json::to_vec_pretty(&staged)?)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))?;
    Ok(staged)
}

/// Volume data a stack archive carries, as [`verify_archive`] found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveVolumes {
    /// No [`STAGING_DIR`] in the archive.
    None,
    /// Every artifact matches the manifest's sha256 and size.
    Verified(VolumesManifest),
    /// [`STAGING_DIR`] without a [`MANIFEST_FILE`]: a backup made before
    /// volume checksums, whose volume data cannot be checked.
    Unverified,
}

/// `path` relative to [`STAGING_DIR`] when it is a file directly in it.
fn staged_name(path: &Path) -> Option<String> {
    let mut parts = path
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir));
    if parts.next()?.as_os_str() != STAGING_DIR {
        return None;
    }
    let name = parts.next()?.as_os_str().to_str()?.to_string();
    parts.next().is_none().then_some(name)
}

/// Check the volume artifacts of the stack archive (`.tar.gz`) read from
/// `file` against its [`MANIFEST_FILE`], hashing each entry as it streams,
/// so nothing is written. Leaves `file` rewound.
pub fn verify_archive(file: &mut std::fs::File) -> Result<ArchiveVolumes> {
    use sha2::Digest;
    use std::io::Seek;
    file.rewind()?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&mut *file));
    let mut seen = false;
    let mut manifest = None;
    let mut sums: BTreeMap<String, (String, u64)> = BTreeMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path
            .components()
            .find(|c| !matches!(c, std::path::Component::CurDir))
            .is_some_and(|c| c.as_os_str() == STAGING_DIR)
        {
            seen = true;
        }
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let Some(name) = staged_name(&path) else {
            continue;
        };
        if name == MANIFEST_FILE {
            let mut buf = Vec::new();
            (&mut entry)
                .take(MAX_MANIFEST_BYTES + 1)
                .read_to_end(&mut buf)?;
            if buf.len() as u64 > MAX_MANIFEST_BYTES {
                anyhow::bail!("volume manifest is larger than {MAX_MANIFEST_BYTES} bytes");
            }
            let parsed: VolumesManifest = plugin_toolkit::serde_json::from_slice(&buf)
                .map_err(|e| anyhow::anyhow!("volume manifest: {e}"))?;
            manifest = Some(parsed);
            continue;
        }
        let mut hasher = sha2::Sha256::new();
        let size = std::io::copy(&mut entry, &mut hasher)?;
        sums.insert(
            name,
            (plugin_toolkit::hash::hex_encode(&hasher.finalize()), size),
        );
    }
    file.rewind()?;
    let Some(manifest) = manifest else {
        return Ok(if seen {
            ArchiveVolumes::Unverified
        } else {
            ArchiveVolumes::None
        });
    };
    for a in &manifest.artifacts {
        let Some((sha, size)) = sums.get(&a.artifact) else {
            anyhow::bail!(
                "volume '{}': artifact '{}' is missing from the archive",
                a.volume,
                a.artifact
            );
        };
        crate::stack_volumes::check_sum(sha, &a.sha256, &format!("volume '{}'", a.volume))?;
        if *size != a.size {
            anyhow::bail!(
                "volume '{}': {size} bytes, the manifest says {}",
                a.volume,
                a.size
            );
        }
    }
    Ok(ArchiveVolumes::Verified(manifest))
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

    const HELPER_ARCHIVE: &str = "/containers/h1/archive";

    /// A volume archive as the Engine API returns it: rooted at `v/`.
    fn volume_tar() -> String {
        let mut b = tar::Builder::new(Vec::new());
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_mode(0o755);
        dir.set_size(0);
        b.append_data(&mut dir, "v/", std::io::empty()).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o644);
        h.set_size(4);
        b.append_data(&mut h, "v/db", &b"rows"[..]).unwrap();
        String::from_utf8(b.into_inner().unwrap()).unwrap()
    }

    fn export_engine() -> FakeEngine {
        FakeEngine::routed(vec![
            Route::new("GET", "/volumes/media_data", 200, VOLUME_JSON),
            Route::new(
                "POST",
                "/containers/create",
                201,
                r#"{"Id":"h1","Warnings":[]}"#,
            ),
            Route::new("GET", HELPER_ARCHIVE, 200, volume_tar()),
            Route::new("DELETE", "/containers/h1", 204, ""),
            Route::new("GET", "/json", 200, r#"{"Id":"sha256:helper"}"#),
        ])
    }

    /// A stack archive of `root`'s staging dir, as the backup writes it.
    fn stack_archive(root: &Path) -> std::fs::File {
        let mut file = tempfile::tempfile().unwrap();
        let gz = flate2::write::GzEncoder::new(&mut file, flate2::Compression::default());
        let mut b = tar::Builder::new(gz);
        b.append_dir_all(STAGING_DIR, root.join(STAGING_DIR))
            .unwrap();
        b.into_inner().unwrap().finish().unwrap();
        file
    }

    #[test]
    fn export_stages_an_engine_api_archive_and_its_sum() {
        let dir = tempfile::tempdir().unwrap();
        let e = export_engine();
        let staged = plugin_toolkit::reactor::block_on(stage(
            &e.client(),
            dir.path(),
            "media",
            &detect(&cfg(), &[]),
            &[policy("data", Strategy::Export)],
        ))
        .unwrap();
        assert!(e.paths("GET").iter().any(|p| p.ends_with(HELPER_ARCHIVE)));
        let a = &staged.artifacts[0];
        assert_eq!(
            (a.engine_name.as_str(), a.artifact.as_str()),
            ("media_data", "data.tar.gz")
        );
        let staging = dir.path().join(STAGING_DIR);
        let sum = plugin_toolkit::hash::sha256_file(&staging.join(&a.artifact)).unwrap();
        assert_eq!(a.sha256, sum);
        let written: VolumesManifest = plugin_toolkit::serde_json::from_slice(
            &std::fs::read(staging.join(MANIFEST_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(written, staged);
        assert_eq!(
            verify_archive(&mut stack_archive(dir.path())).unwrap(),
            ArchiveVolumes::Verified(staged)
        );
    }

    #[test]
    fn verify_archive_refuses_a_changed_artifact_and_flags_unsummed_ones() {
        let dir = tempfile::tempdir().unwrap();
        let e = export_engine();
        plugin_toolkit::reactor::block_on(stage(
            &e.client(),
            dir.path(),
            "media",
            &detect(&cfg(), &[]),
            &[policy("data", Strategy::Export)],
        ))
        .unwrap();
        let staging = dir.path().join(STAGING_DIR);
        std::fs::write(staging.join("data.tar.gz"), b"changed").unwrap();
        let err = verify_archive(&mut stack_archive(dir.path())).unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
        std::fs::remove_file(staging.join(MANIFEST_FILE)).unwrap();
        assert_eq!(
            verify_archive(&mut stack_archive(dir.path())).unwrap(),
            ArchiveVolumes::Unverified
        );
        std::fs::remove_dir_all(&staging).unwrap();
        std::fs::create_dir(&staging).unwrap();
        let mut none = tempfile::tempfile().unwrap();
        {
            let gz = flate2::write::GzEncoder::new(&mut none, flate2::Compression::default());
            let mut b = tar::Builder::new(gz);
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_size(3);
            b.append_data(&mut h, "./compose.yaml", &b"x: 1"[..3])
                .unwrap();
            b.into_inner().unwrap().finish().unwrap();
        }
        assert_eq!(verify_archive(&mut none).unwrap(), ArchiveVolumes::None);
    }

    #[test]
    fn a_dump_needs_a_running_container_of_its_service() {
        let dir = tempfile::tempdir().unwrap();
        let e = FakeEngine::routed(vec![
            Route::new("GET", "/volumes/media_pg", 200, VOLUME_JSON),
            Route::new("GET", "/containers/json", 200, "[]"),
        ]);
        let err = plugin_toolkit::reactor::block_on(stage(
            &e.client(),
            dir.path(),
            "media",
            &detect(&cfg(), &[]),
            &[policy("pg", Strategy::Dump)],
        ))
        .unwrap_err();
        assert!(err.to_string().contains("no running container"), "{err}");
        let listed = e.targets("GET");
        let query = listed
            .iter()
            .find(|t| t.contains("/containers/json"))
            .unwrap();
        assert!(
            query.contains("com.docker.compose.project=media")
                && query.contains("com.docker.compose.service=db"),
            "{query}"
        );
        assert!(DUMP_WRAPPER.contains("set -o pipefail") && DUMP_WRAPPER.contains(r#"eval "$1""#));
    }

    const VOLUME_JSON: &str =
        r#"{"Name":"x","Driver":"local","Mountpoint":"","Labels":{},"Scope":"local","Options":{}}"#;

    #[test]
    fn stage_with_no_policies_stages_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let e = FakeEngine::routed(vec![]);
        let staged =
            plugin_toolkit::reactor::block_on(stage(&e.client(), dir.path(), "media", &[], &[]))
                .unwrap();
        assert_eq!(staged, VolumesManifest::default());
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
            "media",
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
            "media",
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
    fn an_empty_artifact_fails_the_stage() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pg.dump");
        create_private(&p).unwrap();
        let err = ensure_nonempty(&p, "dump volume 'pg'").unwrap_err();
        assert!(err.to_string().contains("produced no output"), "{err}");
        std::fs::write(&p, b"x").unwrap();
        assert!(ensure_nonempty(&p, "dump").is_ok());
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
