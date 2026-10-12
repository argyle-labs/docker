//! `docker.stack_volumes_export` / `docker.stack_volumes_import` — the named
//! volumes of a stack move. Each half acts on its own host's engine: the
//! source writes each data volume to a gzip tar beside a manifest of sha256
//! sums; the target checks every sum before it creates a volume with the
//! source's labels and restores into it. Data moves through the Engine API's
//! container archive endpoints on a helper container that is never started.
#![allow(clippy::disallowed_types)]

use std::collections::{BTreeMap, HashMap};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use bollard::Docker;
use bollard::models::{ContainerCreateBody, HostConfig, Volume, VolumeCreateRequest};
use bollard::query_parameters::{
    CreateContainerOptions, DownloadFromContainerOptionsBuilder, InspectContainerOptionsBuilder,
    RemoveContainerOptionsBuilder, UploadToContainerOptionsBuilder,
};
use flate2::Compression;
use flate2::write::GzEncoder;
use plugin_toolkit::prelude::*;

use crate::engine_state::{self, Limits};
use crate::lifecycle::{in_backup_root, open_archive};
use crate::prune::COMPOSE_VOLUME_LABEL;
use crate::stack_manifest::repo_of;
use crate::volume_coverage::{HELPER_IMAGE, engine_volumes, volume_exists};

const EXPORT_TOOL: &str = "docker.stack_volumes_export";
const IMPORT_TOOL: &str = "docker.stack_volumes_import";
const MANIFEST_FILE: &str = "manifest.json";
/// Set by the engine on a volume it created for an anonymous mount.
const ANONYMOUS_LABEL: &str = "com.docker.volume.anonymous";
const MOUNT: &str = "/v";
/// Images whose volumes hold only a cache the service rebuilds on start.
const CACHE_IMAGES: &[&str] = &["redis", "valkey", "memcached", "keydb", "dragonfly"];

/// Volume data can far exceed the engine state [`engine_state::LIMITS`] is
/// sized for.
const VOLUME_LIMITS: Limits = Limits {
    bytes: 1 << 40,
    entries: 10_000_000,
};
/// Import holds an archive in memory so the bytes it restores are the bytes
/// whose sum it checked.
const MAX_ARCHIVE_BYTES: u64 = 2 << 30;
const MAX_MANIFEST_BYTES: u64 = 16 << 20;
/// Enough of a volume's tar to see whether anything follows its root entry.
const PEEK_BYTES: usize = 64 << 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "camelCase")]
pub enum VolumeKind {
    /// Created on the target and its data copied.
    Data,
    /// Data lives outside the engine (another driver, or `local` with
    /// device options): created on the target with the same options, not
    /// copied.
    External,
    /// Skipped: only cache images mount it.
    Cache,
    /// Skipped: compose creates a fresh one.
    Anonymous,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeEntry {
    pub name: String,
    /// The compose key (`com.docker.compose.volume`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub driver: String,
    /// Recreated verbatim on the target, compose's config-hash included.
    pub labels: BTreeMap<String, String>,
    pub options: BTreeMap<String, String>,
    pub kind: VolumeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Archive file name, beside the manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Why a data volume could not be exported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeManifest {
    pub stack: String,
    pub volumes: Vec<VolumeEntry>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub name: String,
    pub kind: VolumeKind,
    pub reason: String,
}

fn skipped(volumes: &[VolumeEntry]) -> Vec<Skipped> {
    volumes
        .iter()
        .filter(|v| matches!(v.kind, VolumeKind::Cache | VolumeKind::Anonymous))
        .map(|v| Skipped {
            name: v.name.clone(),
            kind: v.kind,
            reason: v.reason.clone().unwrap_or_default(),
        })
        .collect()
}

fn is_cache_image(image: &str) -> bool {
    let repo = repo_of(image);
    CACHE_IMAGES.contains(&repo.rsplit('/').next().unwrap_or(repo))
}

/// What a move does with `vol`, mounted by containers of `images`; a name
/// in `include` is copied even when only cache images mount it.
pub fn classify(
    vol: &Volume,
    images: &[String],
    include: &[String],
) -> (VolumeKind, Option<String>) {
    if vol.labels.contains_key(ANONYMOUS_LABEL) || !vol.labels.contains_key(COMPOSE_VOLUME_LABEL) {
        let why = if images.is_empty() {
            "stale anonymous volume: no container mounts it"
        } else {
            "anonymous volume: compose creates a fresh one"
        };
        return (VolumeKind::Anonymous, Some(why.into()));
    }
    if vol.driver != "local" || !vol.options.is_empty() {
        return (
            VolumeKind::External,
            Some(format!(
                "driver '{}' with options: data is not on this host; recreated with the same options, not copied",
                vol.driver
            )),
        );
    }
    if !images.is_empty()
        && images.iter().all(|i| is_cache_image(i))
        && !include.contains(&vol.name)
    {
        return (
            VolumeKind::Cache,
            Some(format!(
                "cache of {}, rebuilt on start; name it in include to copy it",
                images.join(", ")
            )),
        );
    }
    (VolumeKind::Data, None)
}

/// Every volume the stack's containers mount or that carries its project
/// label, sorted by name.
pub async fn collect(docker: &Docker, stack: &str, include: &[String]) -> Result<Vec<VolumeEntry>> {
    let mut images: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for id in crate::stack_manifest::containers_of(docker, stack)
        .await?
        .iter()
        .filter_map(|c| c.id.as_deref())
    {
        let opts = InspectContainerOptionsBuilder::new().build();
        let c = match docker.inspect_container(id, Some(opts)).await {
            Ok(c) => c,
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => continue,
            Err(e) => bail!("inspect container {id}: {e}"),
        };
        let image = c
            .config
            .as_ref()
            .and_then(|cfg| cfg.image.clone())
            .unwrap_or_default();
        // Only volume mounts carry a name.
        for name in c
            .mounts
            .unwrap_or_default()
            .into_iter()
            .filter_map(|m| m.name)
        {
            let users = images.entry(name).or_default();
            if !users.contains(&image) {
                users.push(image.clone());
            }
        }
    }
    for v in engine_volumes(docker, stack).await? {
        images.entry(v.name).or_default();
    }
    if images.is_empty() {
        bail!("stack '{stack}' has no volumes on this host");
    }
    let mut out = Vec::new();
    for (name, users) in &images {
        let vol = match docker.inspect_volume(name).await {
            Ok(v) => v,
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => continue,
            Err(e) => bail!("inspect volume {name}: {e}"),
        };
        let (kind, reason) = classify(&vol, users, include);
        out.push(VolumeEntry {
            name: vol.name.clone(),
            key: vol.labels.get(COMPOSE_VOLUME_LABEL).cloned(),
            driver: vol.driver.clone(),
            labels: vol.labels.into_iter().collect(),
            options: vol.options.into_iter().collect(),
            kind,
            reason,
            archive: None,
            sha256: None,
            problem: None,
        });
    }
    Ok(out)
}

async fn ensure_helper_image(docker: &Docker) -> Result<()> {
    match docker.inspect_image(HELPER_IMAGE).await {
        Ok(_) => Ok(()),
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => crate::stack_pull::pull(docker, HELPER_IMAGE)
            .await
            .map_err(|e| anyhow!("pull {HELPER_IMAGE}: {e}")),
        Err(e) => Err(anyhow!("inspect image {HELPER_IMAGE}: {e}")),
    }
}

/// A created, never started, network-less container with `volume` at
/// [`MOUNT`]; the archive endpoints mount its volumes themselves.
async fn helper(docker: &Docker, volume: &str, read_only: bool) -> Result<String> {
    ensure_helper_image(docker).await?;
    let mode = if read_only { ":ro" } else { "" };
    let body = ContainerCreateBody {
        image: Some(HELPER_IMAGE.into()),
        network_disabled: Some(true),
        host_config: Some(HostConfig {
            binds: Some(vec![format!("{volume}:{MOUNT}{mode}")]),
            ..Default::default()
        }),
        ..Default::default()
    };
    Ok(docker
        .create_container(None::<CreateContainerOptions>, body)
        .await
        .map_err(|e| anyhow!("create helper for {volume}: {e}"))?
        .id)
}

async fn remove_helper(docker: &Docker, id: &str) -> Result<()> {
    // `v: false`: the volume under the helper is the one being moved.
    let opts = RemoveContainerOptionsBuilder::new()
        .force(true)
        .v(false)
        .build();
    docker
        .remove_container(id, Some(opts))
        .await
        .map_err(|e| anyhow!("remove helper {id}: {e}"))
}

async fn download(docker: &Docker, id: &str, path: &Path) -> Result<()> {
    let opts = DownloadFromContainerOptionsBuilder::new()
        .path(MOUNT)
        .build();
    let mut stream = Box::pin(docker.download_from_container(id, Some(opts)));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create '{}'", path.display()))?;
    let mut gz = GzEncoder::new(file, Compression::default());
    while let Some(chunk) = plugin_toolkit::stream::next(&mut stream).await {
        gz.write_all(&chunk.map_err(|e| anyhow!("read volume archive: {e}"))?)?;
    }
    gz.finish()?.sync_all()?;
    Ok(())
}

/// Write `volume` to `path` and return its sha256. The archive is checked as
/// import will check it, so a volume import would refuse fails here instead.
async fn export_one(docker: &Docker, volume: &str, path: &Path) -> Result<String> {
    let id = helper(docker, volume, true).await?;
    let written = download(docker, &id, path).await;
    let removed = remove_helper(docker, &id).await;
    let checked = written.and(removed).and_then(|()| {
        let mut f = File::open(path)?;
        engine_state::validate_within(&mut f, VOLUME_LIMITS)?;
        plugin_toolkit::hash::sha256_file(path)
    });
    if checked.is_err() {
        let _removed = std::fs::remove_file(path);
    }
    checked
}

/// Whether the volume mounted in helper `id` holds nothing, from the first
/// entries of its archive. Anything unreadable is an error, never "empty".
async fn is_empty(docker: &Docker, id: &str) -> Result<bool> {
    let opts = DownloadFromContainerOptionsBuilder::new()
        .path(MOUNT)
        .build();
    let mut stream = Box::pin(docker.download_from_container(id, Some(opts)));
    let mut buf = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = plugin_toolkit::stream::next(&mut stream).await {
        buf.extend_from_slice(&chunk.map_err(|e| anyhow!("read target volume: {e}"))?);
        if buf.len() >= PEEK_BYTES {
            truncated = true;
            break;
        }
    }
    let mut archive = tar::Archive::new(&buf[..]);
    let mut root = false;
    if let Ok(entries) = archive.entries() {
        for entry in entries {
            let Ok(entry) = entry else { break };
            let Ok(path) = entry.path() else { break };
            if path.components().count() > 1 {
                return Ok(false);
            }
            root = true;
        }
    }
    if !root || truncated {
        bail!("could not tell whether the target volume is empty");
    }
    Ok(true)
}

fn valid_stack(stack: &str) -> Result<()> {
    let ok = !stack.is_empty()
        && !stack.starts_with('.')
        && stack
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if !ok {
        bail!("'{stack}' is not a compose project name");
    }
    Ok(())
}

#[orca_struct(args)]
pub struct DockerStackVolumesExportArgs {
    /// Compose project name.
    #[arg(long)]
    pub stack: String,
    /// Absolute dir inside the daemon's backup roots; the export goes in a
    /// fresh `<stack>-volumes-<stamp>` dir under it.
    #[arg(long)]
    pub destination: String,
    /// Volume names to copy even though only cache images mount them.
    /// Comma-separated on the CLI.
    #[arg(long, value_delimiter = ',')]
    #[serde(default)]
    pub include: Vec<String>,
    /// Apply. Omitted, lists what would be exported and writes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StackVolumesExportOutput {
    pub executed: bool,
    pub stack: String,
    pub volumes: Vec<VolumeEntry>,
    pub skipped: Vec<Skipped>,
    /// `true` when every data volume was exported.
    pub complete: bool,
    /// Pass with [`Self::manifest_sha256`] to `docker.stack_volumes_import`
    /// on the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
}

pub async fn export(
    docker: &Docker,
    args: &DockerStackVolumesExportArgs,
    roots: &[String],
) -> Result<StackVolumesExportOutput> {
    valid_stack(&args.stack)?;
    let destination = in_backup_root(&args.destination, roots)?;
    let mut volumes = collect(docker, &args.stack, &args.include).await?;
    let mut out = StackVolumesExportOutput {
        executed: args.execute,
        stack: args.stack.clone(),
        skipped: skipped(&volumes),
        ..Default::default()
    };
    if !args.execute {
        out.complete = true;
        out.volumes = volumes;
        return Ok(out);
    }
    std::fs::create_dir_all(&destination)
        .with_context(|| format!("failed to create '{}'", destination.display()))?;
    // A component swapped for a symlink while the dir was created would move
    // the write.
    if in_backup_root(&args.destination, roots)? != destination {
        bail!(
            "destination '{}' moved while it was created",
            destination.display()
        );
    }
    let stamp = plugin_toolkit::time::now().compact();
    let bundle = destination.join(format!("{}-volumes-{stamp}", args.stack));
    DirBuilder::new()
        .mode(0o700)
        .create(&bundle)
        .with_context(|| format!("failed to create '{}'", bundle.display()))?;
    for v in volumes.iter_mut().filter(|v| v.kind == VolumeKind::Data) {
        let name = format!("{}.tar.gz", v.name);
        match export_one(docker, &v.name, &bundle.join(&name)).await {
            Ok(sha) => {
                v.archive = Some(name);
                v.sha256 = Some(sha);
            }
            Err(e) => v.problem = Some(format!("{e:#}")),
        }
    }
    let manifest = VolumeManifest {
        stack: args.stack.clone(),
        volumes,
    };
    let json = plugin_toolkit::serde_json::to_vec_pretty(&manifest)?;
    let path = bundle.join(MANIFEST_FILE);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| {
            f.write_all(&json)?;
            f.sync_all()
        })
        .with_context(|| format!("failed to write '{}'", path.display()))?;
    out.complete = manifest.volumes.iter().all(|v| v.problem.is_none());
    out.volumes = manifest.volumes;
    out.manifest = Some(path.to_string_lossy().into_owned());
    out.manifest_sha256 = Some(plugin_toolkit::hash::sha256_hex(&json));
    Ok(out)
}

/// **Export a stack's named volumes for a move** (source host): each data
/// volume to a gzip tar, read through the Engine API, plus a manifest with
/// every volume's labels, driver options and archive sha256. Anonymous
/// volumes and cache-only volumes (redis, valkey, memcached, …) are skipped
/// and listed with the reason.
#[orca_tool(
    domain = "docker",
    verb = "stack_volumes_export",
    role = "admin",
    execute_gated = false
)]
async fn docker_stack_volumes_export(
    args: DockerStackVolumesExportArgs,
    ctx: &ToolCtx,
) -> Result<StackVolumesExportOutput> {
    crate::execute::require_admin(EXPORT_TOOL, ctx)?;
    crate::execute::guard(EXPORT_TOOL, args.execute, ctx)?;
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    export(docker, &args, &engine_state::backup_roots()).await
}

fn read_capped(file: &mut File, cap: u64, what: &str) -> Result<Vec<u8>> {
    if file.metadata()?.len() > cap {
        bail!("{what} is larger than {cap} bytes; refusing it");
    }
    let mut buf = Vec::new();
    file.take(cap + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        bail!("{what} is larger than {cap} bytes; refusing it");
    }
    Ok(buf)
}

fn check_sum(data: &[u8], want: &str, what: &str) -> Result<()> {
    let got = plugin_toolkit::hash::sha256_hex(data);
    if !got.eq_ignore_ascii_case(want.trim()) {
        bail!("{what}: sha256 {got} does not match {want}; refusing it");
    }
    Ok(())
}

fn load(manifest: &str, sha256: &str, roots: &[String]) -> Result<(VolumeManifest, PathBuf)> {
    let mut file = open_archive(manifest, roots)?;
    let dir = engine_state::fd_path(&file)?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("manifest '{manifest}' has no parent dir"))?;
    let data = read_capped(&mut file, MAX_MANIFEST_BYTES, "manifest")?;
    check_sum(&data, sha256, "manifest")?;
    let parsed = plugin_toolkit::serde_json::from_slice(&data)
        .map_err(|e| anyhow!("manifest '{manifest}': {e}"))?;
    Ok((parsed, dir))
}

/// The archive of `v`, read once, sum-checked and entry-checked: the bytes
/// returned are the bytes that passed.
fn verified_archive(dir: &Path, v: &VolumeEntry, roots: &[String]) -> Result<Vec<u8>> {
    let (Some(name), Some(sha)) = (v.archive.as_deref(), v.sha256.as_deref()) else {
        bail!(
            "volume '{}' has no archive and sha256 in the manifest",
            v.name
        );
    };
    if name.contains('/') || name.starts_with('.') {
        bail!(
            "volume '{}': archive '{name}' is not a file beside the manifest",
            v.name
        );
    }
    let path = dir.join(name);
    let mut file = open_archive(&path.to_string_lossy(), roots)?;
    let what = format!("archive of volume '{}'", v.name);
    let data = read_capped(&mut file, MAX_ARCHIVE_BYTES, &what)?;
    check_sum(&data, sha, &what)?;
    engine_state::validate_bytes(&data, VOLUME_LIMITS).with_context(|| what.clone())?;
    Ok(data)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "camelCase")]
pub enum ImportAction {
    Create,
    CreateAndRestore,
    /// Exists: restored only if it turns out empty.
    RestoreIfEmpty,
    /// Exists: restored over its contents (`force`).
    Overwrite,
    /// Exists and holds no copied data: left as is.
    Keep,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedVolume {
    pub name: String,
    pub action: ImportAction,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportFinding {
    pub name: String,
    pub message: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StackVolumesImportOutput {
    pub executed: bool,
    pub stack: String,
    pub created: Vec<String>,
    pub restored: Vec<String>,
    pub skipped: Vec<Skipped>,
    pub findings: Vec<ImportFinding>,
    /// Dry run only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plan: Vec<PlannedVolume>,
}

#[orca_struct(args)]
pub struct DockerStackVolumesImportArgs {
    /// Absolute path of the `manifest.json` from `docker.stack_volumes_export`,
    /// inside the daemon's backup roots, its archives beside it.
    #[arg(long)]
    pub manifest: String,
    /// The export's `manifestSha256`.
    #[arg(long)]
    pub manifest_sha256: String,
    /// Restore into an existing volume that already holds data.
    #[arg(long)]
    #[serde(default)]
    pub force: bool,
    /// Apply. Omitted, verifies every checksum, lists what would be done and
    /// changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

fn action(v: &VolumeEntry, exists: bool, force: bool) -> ImportAction {
    match (exists, v.kind, force) {
        (false, VolumeKind::Data, _) => ImportAction::CreateAndRestore,
        (false, _, _) => ImportAction::Create,
        (true, VolumeKind::Data, false) => ImportAction::RestoreIfEmpty,
        (true, VolumeKind::Data, true) => ImportAction::Overwrite,
        (true, _, _) => ImportAction::Keep,
    }
}

async fn apply_one(
    docker: &Docker,
    v: &VolumeEntry,
    act: ImportAction,
    dir: &Path,
    roots: &[String],
    out: &mut StackVolumesImportOutput,
) -> Result<()> {
    if matches!(act, ImportAction::Create | ImportAction::CreateAndRestore) {
        docker
            .create_volume(VolumeCreateRequest {
                name: Some(v.name.clone()),
                driver: Some(v.driver.clone()),
                driver_opts: Some(v.options.clone().into_iter().collect::<HashMap<_, _>>()),
                labels: Some(v.labels.clone().into_iter().collect::<HashMap<_, _>>()),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow!("create volume {}: {e}", v.name))?;
        out.created.push(v.name.clone());
    }
    if matches!(act, ImportAction::Create | ImportAction::Keep) {
        return Ok(());
    }
    // Read and checked again: the file may have changed since the pre-check.
    let data = verified_archive(dir, v, roots)?;
    let id = helper(docker, &v.name, false).await?;
    let restored = async {
        if act == ImportAction::RestoreIfEmpty && !is_empty(docker, &id).await? {
            bail!(
                "volume '{}' already holds data; pass force to restore over it",
                v.name
            );
        }
        let opts = UploadToContainerOptionsBuilder::new().path("/").build();
        docker
            .upload_to_container(&id, Some(opts), bollard::body_full(data.into()))
            .await
            .map_err(|e| anyhow!("restore volume {}: {e}", v.name))
    }
    .await;
    let removed = remove_helper(docker, &id).await;
    restored.and(removed)?;
    out.restored.push(v.name.clone());
    Ok(())
}

pub async fn import(
    docker: &Docker,
    args: &DockerStackVolumesImportArgs,
    roots: &[String],
) -> Result<StackVolumesImportOutput> {
    let (manifest, dir) = load(&args.manifest, &args.manifest_sha256, roots)?;
    let mut out = StackVolumesImportOutput {
        executed: args.execute,
        stack: manifest.stack.clone(),
        skipped: skipped(&manifest.volumes),
        ..Default::default()
    };
    let mut todo = Vec::new();
    // Every archive passes before any volume is created.
    for v in &manifest.volumes {
        match v.kind {
            VolumeKind::Cache | VolumeKind::Anonymous => {}
            VolumeKind::Data if v.problem.is_some() => out.findings.push(ImportFinding {
                name: v.name.clone(),
                message: format!(
                    "not exported on the source: {}",
                    v.problem.as_deref().unwrap_or_default()
                ),
            }),
            VolumeKind::Data => {
                verified_archive(&dir, v, roots)?;
                todo.push(v);
            }
            VolumeKind::External => todo.push(v),
        }
    }
    for v in todo {
        let act = action(v, volume_exists(docker, &v.name).await?, args.force);
        if !args.execute {
            out.plan.push(PlannedVolume {
                name: v.name.clone(),
                action: act,
            });
            continue;
        }
        if let Err(e) = apply_one(docker, v, act, &dir, roots, &mut out).await {
            out.findings.push(ImportFinding {
                name: v.name.clone(),
                message: format!("{e:#}"),
            });
        }
    }
    Ok(out)
}

/// **Import a moved stack's named volumes** (target host) from a
/// `docker.stack_volumes_export`: checks the manifest's sha256 and every
/// archive's sum and entries before anything is created, then creates each
/// volume with the source's labels and driver options and restores its data
/// through the Engine API. An existing volume that holds data is refused
/// unless `force`. Skipped volumes are listed with the reason.
#[orca_tool(
    domain = "docker",
    verb = "stack_volumes_import",
    role = "admin",
    execute_gated = false
)]
async fn docker_stack_volumes_import(
    args: DockerStackVolumesImportArgs,
    ctx: &ToolCtx,
) -> Result<StackVolumesImportOutput> {
    crate::execute::require_admin(IMPORT_TOOL, ctx)?;
    crate::execute::guard(IMPORT_TOOL, args.execute, ctx)?;
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    import(docker, &args, &engine_state::backup_roots()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};

    fn block<F: std::future::Future>(f: F) -> F::Output {
        plugin_toolkit::reactor::block_on(f)
    }

    fn volume(name: &str, key: Option<&str>, driver: &str, opts: &[(&str, &str)]) -> Volume {
        let mut labels = HashMap::from([
            ("com.docker.compose.project".to_string(), "s".to_string()),
            (
                "com.docker.compose.config-hash".to_string(),
                "h1".to_string(),
            ),
        ]);
        if let Some(k) = key {
            labels.insert(COMPOSE_VOLUME_LABEL.into(), k.into());
        }
        Volume {
            name: name.into(),
            driver: driver.into(),
            labels,
            options: opts
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            scope: Some(bollard::models::VolumeScopeEnum::LOCAL),
            ..Default::default()
        }
    }

    fn volume_json(name: &str, key: Option<&str>) -> String {
        plugin_toolkit::serde_json::to_string(&volume(name, key, "local", &[])).unwrap()
    }

    /// A volume archive as the Engine API returns it: rooted at `v/`.
    fn volume_tar(files: &[(&str, &str)]) -> String {
        let mut b = tar::Builder::new(Vec::new());
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_mode(0o755);
        dir.set_size(0);
        b.append_data(&mut dir, "v/", std::io::empty()).unwrap();
        for (path, body) in files {
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_size(body.len() as u64);
            b.append_data(&mut h, format!("v/{path}"), body.as_bytes())
                .unwrap();
        }
        String::from_utf8(b.into_inner().unwrap()).unwrap()
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classify_skips_anonymous_and_cache_and_keeps_external_uncopied() {
        let data = volume("s_data", Some("data"), "local", &[]);
        assert_eq!(classify(&data, &strs(&["app:1"]), &[]).0, VolumeKind::Data);
        assert_eq!(classify(&data, &[], &[]).0, VolumeKind::Data);

        let anon = volume("0a1b", None, "local", &[]);
        let (kind, why) = classify(&anon, &[], &[]);
        assert_eq!(kind, VolumeKind::Anonymous);
        assert!(why.unwrap().contains("stale"));
        let mut labelled_anon = data.clone();
        labelled_anon
            .labels
            .insert(ANONYMOUS_LABEL.into(), String::new());
        assert_eq!(
            classify(&labelled_anon, &strs(&["app:1"]), &[]).0,
            VolumeKind::Anonymous
        );

        let cache = volume("s_cache", Some("cache"), "local", &[]);
        let redis = strs(&["docker.io/library/redis:7@sha256:a", "valkey/valkey:8"]);
        assert_eq!(classify(&cache, &redis, &[]).0, VolumeKind::Cache);
        assert_eq!(
            classify(&cache, &redis, &strs(&["s_cache"])).0,
            VolumeKind::Data
        );
        assert_eq!(
            classify(&cache, &strs(&["redis:7", "app:1"]), &[]).0,
            VolumeKind::Data
        );

        let nfs = volume("s_nfs", Some("nfs"), "local", &[("type", "nfs")]);
        assert_eq!(classify(&nfs, &[], &[]).0, VolumeKind::External);
    }

    fn export_engine() -> FakeEngine {
        let inspect = |name: &str, image: &str, mounts: &str| {
            format!(
                r#"{{"Id":"{name}","Name":"/{name}","Image":"sha256:x","Config":{{"Image":"{image}"}},"Mounts":[{mounts}]}}"#
            )
        };
        FakeEngine::routed(vec![
            Route::new(
                "GET",
                "/containers/json",
                200,
                r#"[{"Id":"app1"},{"Id":"redis1"}]"#,
            ),
            Route::new(
                "GET",
                "/containers/app1/json",
                200,
                inspect(
                    "app1",
                    "app:1",
                    r#"{"Type":"volume","Name":"s_data","Destination":"/data"},{"Type":"volume","Name":"0a1b","Destination":"/tmp"},{"Type":"bind","Source":"/x","Destination":"/y"}"#,
                ),
            ),
            Route::new(
                "GET",
                "/containers/redis1/json",
                200,
                inspect(
                    "redis1",
                    "redis:7",
                    r#"{"Type":"volume","Name":"s_cache","Destination":"/data"}"#,
                ),
            ),
            Route::new(
                "GET",
                "/volumes",
                200,
                format!(r#"{{"Volumes":[{}]}}"#, volume_json("s_old", Some("old"))),
            ),
            Route::new(
                "GET",
                "/volumes/s_data",
                200,
                volume_json("s_data", Some("data")),
            ),
            Route::new(
                "GET",
                "/volumes/s_old",
                200,
                volume_json("s_old", Some("old")),
            ),
            Route::new(
                "GET",
                "/volumes/s_cache",
                200,
                volume_json("s_cache", Some("cache")),
            ),
            Route::new("GET", "/volumes/0a1b", 200, volume_json("0a1b", None)),
            Route::new(
                "POST",
                "/containers/create",
                201,
                r#"{"Id":"h1","Warnings":[]}"#,
            ),
            Route::new(
                "GET",
                "/containers/h1/archive",
                200,
                volume_tar(&[("db", "rows")]),
            ),
            Route::new("DELETE", "/containers/h1", 204, ""),
            Route::new("GET", "/json", 200, r#"{"Id":"sha256:helper"}"#),
        ])
    }

    fn export_args(dest: &Path, execute: bool) -> DockerStackVolumesExportArgs {
        DockerStackVolumesExportArgs {
            stack: "s".into(),
            destination: dest.to_string_lossy().into_owned(),
            include: vec![],
            execute,
        }
    }

    fn roots(dir: &Path) -> Vec<String> {
        vec![dir.to_string_lossy().into_owned()]
    }

    #[test]
    fn export_writes_checksummed_archives_and_reports_skips() {
        let root = tempfile::tempdir().unwrap();
        let e = export_engine();
        let out = block(export(
            &e.client(),
            &export_args(root.path(), true),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(out.executed && out.complete);
        let mut skips: Vec<_> = out
            .skipped
            .iter()
            .map(|s| (s.name.as_str(), s.kind))
            .collect();
        skips.sort_by_key(|s| s.0);
        assert_eq!(
            skips,
            [
                ("0a1b", VolumeKind::Anonymous),
                ("s_cache", VolumeKind::Cache)
            ]
        );
        let manifest = PathBuf::from(out.manifest.unwrap());
        let json = std::fs::read(&manifest).unwrap();
        assert_eq!(
            out.manifest_sha256.unwrap(),
            plugin_toolkit::hash::sha256_hex(&json)
        );
        let parsed: VolumeManifest = plugin_toolkit::serde_json::from_slice(&json).unwrap();
        let data: Vec<_> = parsed
            .volumes
            .iter()
            .filter(|v| v.kind == VolumeKind::Data)
            .collect();
        assert_eq!(data.len(), 2, "s_data and the unmounted s_old");
        for v in data {
            let archive = manifest
                .parent()
                .unwrap()
                .join(v.archive.as_deref().unwrap());
            assert_eq!(
                v.sha256.as_deref().unwrap(),
                plugin_toolkit::hash::sha256_file(&archive).unwrap()
            );
            assert_eq!(v.labels["com.docker.compose.config-hash"], "h1");
        }
        let creates = e.bodies("/containers/create");
        assert!(
            creates
                .iter()
                .all(|b| b.contains(":/v:ro") && b.contains(HELPER_IMAGE))
        );
        assert!(
            e.paths("DELETE")
                .iter()
                .all(|p| p.ends_with("/containers/h1"))
        );
        assert!(e.targets("DELETE").iter().all(|t| t.contains("v=false")));
    }

    #[test]
    fn export_dry_run_writes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let e = export_engine();
        let out = block(export(
            &e.client(),
            &export_args(root.path(), false),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(!out.executed && out.manifest.is_none());
        assert_eq!(out.skipped.len(), 2);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        assert!(e.paths("POST").is_empty());
    }

    #[test]
    fn export_refuses_a_destination_outside_the_roots() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let e = export_engine();
        let err = block(export(
            &e.client(),
            &export_args(other.path(), false),
            &roots(root.path()),
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("outside the backup roots"),
            "{err}"
        );
    }

    /// A bundle as export writes it: one data volume, one skipped cache.
    fn bundle(dir: &Path, files: &[(&str, &str)]) -> (String, String) {
        let tar = volume_tar(files);
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(tar.as_bytes()).unwrap();
        let archive = gz.finish().unwrap();
        std::fs::write(dir.join("s_data.tar.gz"), &archive).unwrap();
        let data = VolumeEntry {
            name: "s_data".into(),
            key: Some("data".into()),
            driver: "local".into(),
            labels: volume("s_data", Some("data"), "local", &[])
                .labels
                .into_iter()
                .collect(),
            options: BTreeMap::new(),
            kind: VolumeKind::Data,
            reason: None,
            archive: Some("s_data.tar.gz".into()),
            sha256: Some(plugin_toolkit::hash::sha256_hex(&archive)),
            problem: None,
        };
        let cache = VolumeEntry {
            name: "s_cache".into(),
            kind: VolumeKind::Cache,
            reason: Some("cache".into()),
            archive: None,
            sha256: None,
            ..data.clone()
        };
        let json = plugin_toolkit::serde_json::to_vec(&VolumeManifest {
            stack: "s".into(),
            volumes: vec![data, cache],
        })
        .unwrap();
        let path = dir.join(MANIFEST_FILE);
        std::fs::write(&path, &json).unwrap();
        (
            path.to_string_lossy().into_owned(),
            plugin_toolkit::hash::sha256_hex(&json),
        )
    }

    fn import_args(
        manifest: &str,
        sha: &str,
        force: bool,
        execute: bool,
    ) -> DockerStackVolumesImportArgs {
        DockerStackVolumesImportArgs {
            manifest: manifest.into(),
            manifest_sha256: sha.into(),
            force,
            execute,
        }
    }

    fn target_engine(existing: Option<&[(&str, &str)]>) -> FakeEngine {
        let mut routes = vec![];
        match existing {
            Some(files) => {
                routes.push(Route::new(
                    "GET",
                    "/volumes/s_data",
                    200,
                    volume_json("s_data", Some("data")),
                ));
                routes.push(Route::new(
                    "GET",
                    "/containers/h1/archive",
                    200,
                    volume_tar(files),
                ));
            }
            None => routes.push(Route::new(
                "GET",
                "/volumes/s_data",
                404,
                r#"{"message":"no such volume"}"#,
            )),
        }
        routes.extend([
            Route::new(
                "POST",
                "/volumes/create",
                201,
                volume_json("s_data", Some("data")),
            ),
            Route::new(
                "POST",
                "/containers/create",
                201,
                r#"{"Id":"h1","Warnings":[]}"#,
            ),
            Route::new("PUT", "/containers/h1/archive", 200, ""),
            Route::new("DELETE", "/containers/h1", 204, ""),
            Route::new("GET", "/json", 200, r#"{"Id":"sha256:helper"}"#),
        ]);
        FakeEngine::routed(routes)
    }

    #[test]
    fn import_creates_with_source_labels_and_restores() {
        let root = tempfile::tempdir().unwrap();
        let (manifest, sha) = bundle(root.path(), &[("db", "rows")]);
        let e = target_engine(None);
        let out = block(import(
            &e.client(),
            &import_args(&manifest, &sha, false, true),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(out.findings.is_empty(), "{:?}", out.findings);
        assert_eq!(out.created, ["s_data"]);
        assert_eq!(out.restored, ["s_data"]);
        assert_eq!(out.skipped.len(), 1);
        let create = &e.bodies("/volumes/create")[0];
        assert!(create.contains("com.docker.compose.config-hash") && create.contains("\"s_data\""));
        assert!(
            e.targets("PUT")
                .iter()
                .any(|t| t.contains("/containers/h1/archive") && t.contains("path=/"))
        );
        assert!(e.bodies("/containers/create")[0].contains("s_data:/v\""));
    }

    #[test]
    fn import_refuses_a_bad_sum_before_touching_the_engine() {
        let root = tempfile::tempdir().unwrap();
        let (manifest, sha) = bundle(root.path(), &[("db", "rows")]);
        let e = target_engine(None);
        let err = block(import(
            &e.client(),
            &import_args(&manifest, &"0".repeat(64), false, true),
            &roots(root.path()),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("manifest: sha256"), "{err}");

        let archive = root.path().join("s_data.tar.gz");
        let mut bytes = std::fs::read(&archive).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&archive, bytes).unwrap();
        let err = block(import(
            &e.client(),
            &import_args(&manifest, &sha, false, true),
            &roots(root.path()),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
        assert!(e.requests().is_empty());
    }

    #[test]
    fn import_refuses_a_non_empty_volume_unless_forced() {
        let root = tempfile::tempdir().unwrap();
        let (manifest, sha) = bundle(root.path(), &[("db", "rows")]);
        let e = target_engine(Some(&[("old", "x")]));
        let out = block(import(
            &e.client(),
            &import_args(&manifest, &sha, false, true),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(out.restored.is_empty() && out.created.is_empty());
        assert!(out.findings[0].message.contains("already holds data"));
        assert!(e.paths("PUT").is_empty());
        assert_eq!(e.paths("DELETE").len(), 1, "the helper is removed");

        let e = target_engine(Some(&[("old", "x")]));
        let out = block(import(
            &e.client(),
            &import_args(&manifest, &sha, true, true),
            &roots(root.path()),
        ))
        .unwrap();
        assert_eq!(out.restored, ["s_data"]);
        assert!(e.paths("GET").iter().all(|p| !p.ends_with("/archive")));
    }

    #[test]
    fn import_restores_into_an_existing_empty_volume() {
        let root = tempfile::tempdir().unwrap();
        let (manifest, sha) = bundle(root.path(), &[("db", "rows")]);
        let e = target_engine(Some(&[]));
        let out = block(import(
            &e.client(),
            &import_args(&manifest, &sha, false, true),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(out.created.is_empty());
        assert_eq!(out.restored, ["s_data"]);
    }

    #[test]
    fn import_dry_run_plans_and_changes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let (manifest, sha) = bundle(root.path(), &[("db", "rows")]);
        let e = target_engine(None);
        let out = block(import(
            &e.client(),
            &import_args(&manifest, &sha, false, false),
            &roots(root.path()),
        ))
        .unwrap();
        assert_eq!(
            out.plan,
            [PlannedVolume {
                name: "s_data".into(),
                action: ImportAction::CreateAndRestore
            }]
        );
        assert!(e.paths("POST").is_empty() && e.paths("PUT").is_empty());
    }

    #[test]
    fn both_halves_refuse_a_non_admin_caller() {
        for ctx in crate::test_support::non_admins() {
            let err = block(docker_stack_volumes_export(
                export_args(Path::new("/mnt/backups"), false),
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
            let err = block(docker_stack_volumes_import(
                import_args("/mnt/backups/m.json", "x", false, false),
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
        }
    }
}
