//! `docker.stack_volumes_export` / `docker.stack_volumes_import` — the named
//! volumes of a stack move. Each half acts on its own host's engine: the
//! source writes each data volume to a gzip tar beside a manifest of sha256
//! sums; the target checks every sum before it creates a volume with the
//! source's labels and restores into it. Data moves through the Engine API's
//! container archive endpoints on a helper container that is never started.
#![allow(clippy::disallowed_types)]

use std::collections::{BTreeMap, HashMap};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use bollard::Docker;
use bollard::models::{
    ContainerCreateBody, ContainerSummary, HostConfig, Volume, VolumeCreateRequest,
};
use bollard::query_parameters::{
    CreateContainerOptions, DownloadFromContainerOptionsBuilder, InspectContainerOptionsBuilder,
    ListContainersOptionsBuilder, RemoveContainerOptionsBuilder, RemoveVolumeOptionsBuilder,
    UploadToContainerOptionsBuilder,
};
use flate2::Compression;
use flate2::write::GzEncoder;
use plugin_toolkit::prelude::*;

use crate::engine_state::{self, Limits};
use crate::lifecycle::{in_backup_root, open_archive};
use crate::prune::{COMPOSE_PROJECT_LABEL, COMPOSE_VOLUME_LABEL};
use crate::stack_manifest::repo_of;
use crate::volume_coverage::{HELPER_IMAGE, engine_volumes};

const EXPORT_TOOL: &str = "docker.stack_volumes_export";
const IMPORT_TOOL: &str = "docker.stack_volumes_import";
const MANIFEST_FILE: &str = "manifest.json";
/// Set by the engine on a volume it created for an anonymous mount.
const ANONYMOUS_LABEL: &str = "com.docker.volume.anonymous";
const MOUNT: &str = "/v";
/// The top dir of a volume archive: the engine names it after [`MOUNT`].
const ARCHIVE_ROOT: &str = "v";
/// Images whose volumes hold only a cache the service rebuilds on start.
const CACHE_IMAGES: &[&str] = &["redis", "valkey", "memcached", "keydb", "dragonfly"];

/// Volume data can far exceed the engine state [`engine_state::LIMITS`] is
/// sized for.
const VOLUME_LIMITS: Limits = Limits {
    bytes: 1 << 40,
    entries: 10_000_000,
};
const MAX_MANIFEST_BYTES: u64 = 16 << 20;
/// Enough of a volume's tar to see whether anything follows its root entry.
const PEEK_BYTES: usize = 64 << 10;
const UPLOAD_CHUNK: usize = 1 << 20;

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
    /// Skipped: another compose project owns it (`external: true` here).
    Foreign,
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
    pub labels: BTreeMap<String, String>,
    pub options: BTreeMap<String, String>,
    pub kind: VolumeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Running containers that mount it at export; its archive may then not
    /// be a consistent snapshot.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub running: Vec<String>,
    /// Archive file name, beside the manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Archive size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
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

fn is_skipped(kind: VolumeKind) -> bool {
    matches!(
        kind,
        VolumeKind::Cache | VolumeKind::Anonymous | VolumeKind::Foreign
    )
}

fn skipped(volumes: &[VolumeEntry]) -> Vec<Skipped> {
    volumes
        .iter()
        .filter(|v| is_skipped(v.kind))
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

/// What a move of `stack` does with `vol`, mounted by containers of
/// `images`; a name in `include` is copied even when only cache images mount
/// it.
pub fn classify(
    vol: &Volume,
    stack: &str,
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
    if let Some(owner) = vol.labels.get(COMPOSE_PROJECT_LABEL)
        && owner != stack
    {
        return (
            VolumeKind::Foreign,
            Some(format!("owned by project {owner}")),
        );
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

#[derive(Default)]
struct Users {
    images: Vec<String>,
    running: Vec<String>,
}

/// Every volume the stack's containers mount or that carries its project
/// label, sorted by name.
pub async fn collect(docker: &Docker, stack: &str, include: &[String]) -> Result<Vec<VolumeEntry>> {
    let mut users: BTreeMap<String, Users> = BTreeMap::new();
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
        let running = c.state.as_ref().and_then(|s| s.running).unwrap_or(false);
        let cname = c
            .name
            .as_deref()
            .unwrap_or(id)
            .trim_start_matches('/')
            .to_string();
        // Only volume mounts carry a name.
        for name in c
            .mounts
            .unwrap_or_default()
            .into_iter()
            .filter_map(|m| m.name)
        {
            let u = users.entry(name).or_default();
            if !u.images.contains(&image) {
                u.images.push(image.clone());
            }
            if running && !u.running.contains(&cname) {
                u.running.push(cname.clone());
            }
        }
    }
    for v in engine_volumes(docker, stack).await? {
        users.entry(v.name).or_default();
    }
    if users.is_empty() {
        bail!("stack '{stack}' has no volumes on this host");
    }
    let mut out = Vec::new();
    for (name, u) in users {
        let vol = match docker.inspect_volume(&name).await {
            Ok(v) => v,
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => continue,
            Err(e) => bail!("inspect volume {name}: {e}"),
        };
        let (kind, reason) = classify(&vol, stack, &u.images, include);
        out.push(VolumeEntry {
            name: vol.name.clone(),
            key: vol.labels.get(COMPOSE_VOLUME_LABEL).cloned(),
            driver: vol.driver.clone(),
            labels: vol.labels.into_iter().collect(),
            options: vol.options.into_iter().collect(),
            kind,
            reason,
            running: u.running,
            archive: None,
            sha256: None,
            size: None,
            problem: None,
        });
    }
    Ok(out)
}

async fn helper_image_present(docker: &Docker) -> Result<bool> {
    match docker.inspect_image(HELPER_IMAGE).await {
        Ok(_) => Ok(true),
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => Ok(false),
        Err(e) => Err(anyhow!("inspect image {HELPER_IMAGE}: {e}")),
    }
}

async fn ensure_helper_image(docker: &Docker) -> Result<()> {
    if helper_image_present(docker).await? {
        return Ok(());
    }
    crate::stack_pull::pull(docker, HELPER_IMAGE)
        .await
        .map_err(|e| anyhow!("pull {HELPER_IMAGE}: {e}"))
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

/// Write `volume` to `path` and return its sha256 and size. The archive is
/// checked as import will check it, so a volume import would refuse fails
/// here instead.
pub(crate) async fn export_one(
    docker: &Docker,
    volume: &str,
    path: &Path,
) -> Result<(String, u64)> {
    let id = helper(docker, volume, true).await?;
    let written = download(docker, &id, path).await;
    let removed = remove_helper(docker, &id).await;
    let checked = written.and(removed).and_then(|()| {
        let mut f = File::open(path)?;
        engine_state::validate_volume(&mut f, ARCHIVE_ROOT, VOLUME_LIMITS)?;
        Ok((fd_sha256(&mut f)?, f.metadata()?.len()))
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
    /// fresh `<stack>-volumes-<stamp>-<ms>` dir under it.
    #[arg(long)]
    pub destination: String,
    /// Volume names to copy even though only cache images mount them.
    /// Comma-separated on the CLI.
    #[arg(long, value_delimiter = ',')]
    #[serde(default)]
    pub include: Vec<String>,
    /// Export data volumes that running containers mount. Their archives may
    /// not be consistent; each records the containers in `running`.
    #[arg(long)]
    #[serde(default)]
    pub allow_running: bool,
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
    /// Dry run only, when a data volume would be copied: whether the helper
    /// image is already on this host (execute pulls it otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_image_present: Option<bool>,
    /// Pass with [`Self::manifest_sha256`] to `docker.stack_volumes_import`
    /// on the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
}

fn running_refusal(volumes: &[VolumeEntry]) -> Option<String> {
    let busy: Vec<String> = volumes
        .iter()
        .filter(|v| v.kind == VolumeKind::Data && !v.running.is_empty())
        .map(|v| format!("{} ({})", v.name, v.running.join(", ")))
        .collect();
    (!busy.is_empty()).then(|| {
        format!(
            "running containers mount data volumes: {}; stop the stack first or pass allowRunning",
            busy.join("; ")
        )
    })
}

pub async fn export(
    docker: &Docker,
    args: &DockerStackVolumesExportArgs,
    roots: &[String],
) -> Result<StackVolumesExportOutput> {
    valid_stack(&args.stack)?;
    let destination = in_backup_root(&args.destination, roots)?;
    let mut volumes = collect(docker, &args.stack, &args.include).await?;
    let refusal = (!args.allow_running)
        .then(|| running_refusal(&volumes))
        .flatten();
    let mut out = StackVolumesExportOutput {
        executed: args.execute,
        stack: args.stack.clone(),
        skipped: skipped(&volumes),
        ..Default::default()
    };
    if !args.execute {
        if let Some(why) = &refusal {
            for v in volumes
                .iter_mut()
                .filter(|v| v.kind == VolumeKind::Data && !v.running.is_empty())
            {
                v.problem = Some(why.clone());
            }
        }
        if volumes.iter().any(|v| v.kind == VolumeKind::Data) {
            out.helper_image_present = Some(helper_image_present(docker).await?);
        }
        out.complete = volumes.iter().all(|v| v.problem.is_none());
        out.volumes = volumes;
        return Ok(out);
    }
    if let Some(why) = refusal {
        bail!("{why}");
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
    let now = plugin_toolkit::time::now();
    let base = format!(
        "{}-volumes-{}-{:03}",
        args.stack,
        now.compact(),
        now.unix_millis().rem_euclid(1000)
    );
    let mut bundle = destination.join(&base);
    let mut n = 1;
    while let Err(e) = DirBuilder::new().mode(0o700).create(&bundle) {
        if e.kind() != std::io::ErrorKind::AlreadyExists || n > 99 {
            return Err(e).with_context(|| format!("failed to create '{}'", bundle.display()));
        }
        bundle.set_file_name(format!("{base}-{n}"));
        n += 1;
    }
    for v in volumes.iter_mut().filter(|v| v.kind == VolumeKind::Data) {
        let name = format!("{}.tar.gz", v.name);
        match export_one(docker, &v.name, &bundle.join(&name)).await {
            Ok((sha, size)) => {
                v.archive = Some(name);
                v.sha256 = Some(sha);
                v.size = Some(size);
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
/// every volume's labels, driver options, archive sha256 and size. Refused
/// while running containers mount a data volume unless `allowRunning`.
/// Anonymous volumes, cache-only volumes (redis, valkey, memcached, …) and
/// volumes another project owns are skipped and listed with the reason.
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

pub(crate) fn check_sum(got: &str, want: &str, what: &str) -> Result<()> {
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
    check_sum(&plugin_toolkit::hash::sha256_hex(&data), sha256, "manifest")?;
    let parsed = plugin_toolkit::serde_json::from_slice(&data)
        .map_err(|e| anyhow!("manifest '{manifest}': {e}"))?;
    Ok((parsed, dir))
}

/// sha256 of everything `file` holds, read through its own descriptor.
pub(crate) fn fd_sha256(file: &mut File) -> Result<String> {
    // On macOS `/dev/fd/N` shares this descriptor's offset.
    file.rewind()?;
    let sum =
        plugin_toolkit::hash::sha256_file(Path::new(&format!("/dev/fd/{}", file.as_raw_fd())))?;
    file.rewind()?;
    Ok(sum)
}

/// Sum-check and entry-check `file` as the archive of `volume`, leaving it
/// rewound.
fn verify(file: &mut File, volume: &str, sha: &str) -> Result<()> {
    let what = format!("archive of volume '{volume}'");
    check_sum(&fd_sha256(file)?, sha, &what)?;
    engine_state::validate_volume(file, ARCHIVE_ROOT, VOLUME_LIMITS)
        .with_context(|| what.clone())?;
    file.rewind()?;
    Ok(())
}

/// The archive of `v`, opened read-only from beside the manifest.
fn open_volume_archive<'a>(
    dir: &Path,
    v: &'a VolumeEntry,
    roots: &[String],
) -> Result<(File, &'a str)> {
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
    Ok((open_archive(&dir.join(name).to_string_lossy(), roots)?, sha))
}

/// Check the archive of `v` in place.
fn check_archive(dir: &Path, v: &VolumeEntry, roots: &[String]) -> Result<()> {
    let (mut src, sha) = open_volume_archive(dir, v, roots)?;
    verify(&mut src, &v.name, sha)
}

/// The archive of `v` copied to a private unlinked temp file and checked
/// there: the returned descriptor holds exactly the bytes that passed,
/// whatever happens to the original, and the backup dir may be read-only.
/// The copy needs scratch space in the temp dir equal to the archive size.
fn verified_archive(dir: &Path, v: &VolumeEntry, roots: &[String]) -> Result<File> {
    let (src, sha) = open_volume_archive(dir, v, roots)?;
    verified_copy(src, &v.name, sha)
}

/// `src` copied to a private unlinked temp file, checked there against `sha`.
pub(crate) fn verified_copy(mut src: File, volume: &str, sha: &str) -> Result<File> {
    let mut copy = tempfile::tempfile().context("failed to create a temp file")?;
    let needed = src.metadata()?.len();
    enough_scratch(free_space(&copy)?, needed).map_err(|e| {
        anyhow!(
            "volume '{volume}': {e} in {}; set TMPDIR to a larger disk",
            std::env::temp_dir().display()
        )
    })?;
    std::io::copy(&mut src, &mut copy)?;
    verify(&mut copy, volume, sha)?;
    Ok(copy)
}

/// Bytes available to an unprivileged writer on the filesystem holding `f`.
fn free_space(f: &File) -> Result<u64> {
    use std::os::fd::AsRawFd;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid open fd and a properly sized out-param.
    if unsafe { libc::fstatvfs(f.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to stat the temp filesystem");
    }
    Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// Headroom so the copy never fills the scratch filesystem completely.
const SCRATCH_MARGIN: u64 = 64 * 1024 * 1024;

fn enough_scratch(available: u64, needed: u64) -> Result<()> {
    let want = needed.saturating_add(SCRATCH_MARGIN);
    if available < want {
        bail!("not enough scratch space: need {want} bytes, {available} available");
    }
    Ok(())
}

/// A file read in chunks as a request body.
struct FileBody(File);

impl futures_core::Stream for FileBody {
    type Item = std::io::Result<bytes::Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let mut buf = vec![0u8; UPLOAD_CHUNK];
        Poll::Ready(match self.0.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some(Ok(buf.into()))
            }
            Err(e) => Some(Err(e)),
        })
    }
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
    /// Exists: removed, recreated empty with its own driver, options and
    /// labels, then restored (`force`).
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
    /// Dry run only, when a volume would be restored: whether the helper
    /// image is already on this host (execute pulls it otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_image_present: Option<bool>,
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
    /// Replace an existing volume that already holds data: it is removed and
    /// recreated empty before the restore.
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

pub(crate) async fn existing(docker: &Docker, name: &str) -> Result<Option<Volume>> {
    match docker.inspect_volume(name).await {
        Ok(v) => Ok(Some(v)),
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => Ok(None),
        Err(e) => Err(anyhow!("inspect volume {name}: {e}")),
    }
}

/// Why keeping `have` as `v` would not match the source, if it would not.
fn keep_mismatch(v: &VolumeEntry, have: &Volume) -> Option<String> {
    let options: BTreeMap<String, String> = have.options.clone().into_iter().collect();
    (have.driver != v.driver || options != v.options).then(|| {
        format!(
            "exists with driver '{}' options {:?}; the source has driver '{}' options {:?}; left as is",
            have.driver, options, v.driver, v.options
        )
    })
}

async fn containers_using(docker: &Docker, volume: &str) -> Result<Vec<ContainerSummary>> {
    let filters = HashMap::from([("volume".to_string(), vec![volume.to_string()])]);
    docker
        .list_containers(Some(
            ListContainersOptionsBuilder::new()
                .all(true)
                .filters(&filters)
                .build(),
        ))
        .await
        .map_err(|e| anyhow!("list containers using {volume}: {e}"))
}

fn container_name(c: &ContainerSummary) -> String {
    c.names
        .as_ref()
        .and_then(|n| n.first())
        .map(|n| n.trim_start_matches('/').to_string())
        .or_else(|| c.id.clone())
        .unwrap_or_default()
}

/// Refuse a restore into `volume` while a container runs on it, and an
/// overwrite while any container references it: the volume is removed to
/// empty it, which the engine refuses for a volume in use.
async fn refuse_in_use(docker: &Docker, volume: &str, act: ImportAction) -> Result<()> {
    let users = containers_using(docker, volume).await?;
    refuse_live(volume, &users, None)?;
    if act == ImportAction::Overwrite && !users.is_empty() {
        let names: Vec<String> = users.iter().map(container_name).collect();
        bail!(
            "volume '{volume}' is referenced by containers: {}; remove them (compose down) before overwriting it",
            names.join(", ")
        );
    }
    Ok(())
}

/// Anything but created/exited/dead may write to the volume (running, paused,
/// restarting, removing); an unknown state counts as live.
fn is_live(c: &ContainerSummary) -> bool {
    !matches!(
        c.state.as_ref().map(|s| s.to_string()).as_deref(),
        Some("created" | "exited" | "dead")
    )
}

fn refuse_live(volume: &str, users: &[ContainerSummary], helper: Option<&str>) -> Result<()> {
    let running: Vec<String> = users
        .iter()
        .filter(|c| c.id.as_deref().is_none_or(|id| Some(id) != helper) && is_live(c))
        .map(container_name)
        .collect();
    if !running.is_empty() {
        bail!(
            "volume '{volume}' is mounted by running containers: {}; stop them first",
            running.join(", ")
        );
    }
    Ok(())
}

async fn create(
    docker: &Docker,
    name: &str,
    driver: &str,
    opts: HashMap<String, String>,
    labels: HashMap<String, String>,
) -> Result<()> {
    docker
        .create_volume(VolumeCreateRequest {
            name: Some(name.into()),
            driver: Some(driver.into()),
            driver_opts: Some(opts),
            labels: Some(labels),
            ..Default::default()
        })
        .await
        .map(|_| ())
        .map_err(|e| anyhow!("create volume {name}: {e}"))
}

/// Empty `have` by removing it and creating it again as it was. Only a plain
/// local volume: removing one with driver options leaves its data in place.
async fn recreate(docker: &Docker, have: &Volume) -> Result<()> {
    if have.driver != "local" || !have.options.is_empty() {
        bail!(
            "volume '{}' has driver '{}' with options; it cannot be emptied here",
            have.name,
            have.driver
        );
    }
    docker
        .remove_volume(
            &have.name,
            Some(RemoveVolumeOptionsBuilder::new().force(false).build()),
        )
        .await
        .map_err(|e| anyhow!("remove volume {}: {e}", have.name))?;
    create(
        docker,
        &have.name,
        &have.driver,
        have.options.clone(),
        have.labels.clone(),
    )
    .await
    .with_context(|| format!("volume '{}' was removed; rerun to create it", have.name))
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
        create(
            docker,
            &v.name,
            &v.driver,
            v.options.clone().into_iter().collect(),
            v.labels.clone().into_iter().collect(),
        )
        .await?;
        out.created.push(v.name.clone());
    }
    if matches!(act, ImportAction::Create | ImportAction::Keep) {
        return Ok(());
    }
    if matches!(act, ImportAction::RestoreIfEmpty | ImportAction::Overwrite) {
        refuse_in_use(docker, &v.name, act).await?;
    }
    // Checked again: the file may have changed since the pre-check.
    let archive = verified_archive(dir, v, roots)?;
    restore_into(docker, &v.name, act, archive).await?;
    out.restored.push(v.name.clone());
    Ok(())
}

/// Write the verified `archive` into volume `name`, emptying it first for
/// an overwrite.
async fn restore_into(docker: &Docker, name: &str, act: ImportAction, archive: File) -> Result<()> {
    if act == ImportAction::Overwrite {
        let have = existing(docker, name)
            .await?
            .ok_or_else(|| anyhow!("volume '{name}' was removed during the import"))?;
        recreate(docker, &have).await?;
    }
    let id = helper(docker, name, false).await?;
    let restored = async {
        if act == ImportAction::RestoreIfEmpty && !is_empty(docker, &id).await? {
            bail!("volume '{name}' already holds data; pass force to replace it");
        }
        // The stack may have been started since the first check.
        refuse_live(name, &containers_using(docker, name).await?, Some(&id))?;
        let opts = UploadToContainerOptionsBuilder::new().path("/").build();
        docker
            .upload_to_container(&id, Some(opts), bollard::body_try_stream(FileBody(archive)))
            .await
            .map_err(|e| anyhow!("restore volume {name}: {e}; partial restore; rerun with force"))
    }
    .await;
    let removed = remove_helper(docker, &id).await;
    restored.and(removed)
}

/// Restore volume `name` of a stack backup from `src`, checked against
/// `sha`: replaced when it exists, else created as the backup recorded it.
pub(crate) async fn restore_stack_volume(
    docker: &Docker,
    name: &str,
    driver: &str,
    options: &BTreeMap<String, String>,
    labels: &BTreeMap<String, String>,
    sha: &str,
    src: File,
) -> Result<()> {
    let act = if existing(docker, name).await?.is_some() {
        ImportAction::Overwrite
    } else {
        ImportAction::CreateAndRestore
    };
    if act == ImportAction::Overwrite {
        refuse_in_use(docker, name, act).await?;
    }
    let archive = verified_copy(src, name, sha)?;
    if act == ImportAction::CreateAndRestore {
        create(
            docker,
            name,
            driver,
            options.clone().into_iter().collect(),
            labels.clone().into_iter().collect(),
        )
        .await?;
    }
    restore_into(docker, name, act, archive).await
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
            k if is_skipped(k) => {}
            VolumeKind::Data if v.problem.is_some() => out.findings.push(ImportFinding {
                name: v.name.clone(),
                message: format!(
                    "not exported on the source: {}",
                    v.problem.as_deref().unwrap_or_default()
                ),
            }),
            VolumeKind::Data => {
                check_archive(&dir, v, roots)?;
                todo.push(v);
            }
            _ => todo.push(v),
        }
    }
    let mut restores = false;
    for v in todo {
        let have = existing(docker, &v.name).await?;
        let act = action(v, have.is_some(), args.force);
        if act == ImportAction::Keep
            && let Some(why) = have.as_ref().and_then(|h| keep_mismatch(v, h))
        {
            out.findings.push(ImportFinding {
                name: v.name.clone(),
                message: why,
            });
        }
        if !args.execute {
            if matches!(act, ImportAction::RestoreIfEmpty | ImportAction::Overwrite)
                && let Err(e) = refuse_in_use(docker, &v.name, act).await
            {
                out.findings.push(ImportFinding {
                    name: v.name.clone(),
                    message: format!("{e:#}"),
                });
            }
            restores |= !matches!(act, ImportAction::Create | ImportAction::Keep);
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
    if restores {
        out.helper_image_present = Some(helper_image_present(docker).await?);
    }
    Ok(out)
}

/// **Import a moved stack's named volumes** (target host) from a
/// `docker.stack_volumes_export`: checks the manifest's sha256 and every
/// archive's sum and entries before anything is created, then creates each
/// volume with the source's labels and driver options and restores its data
/// through the Engine API. A volume a running container mounts is refused;
/// an existing volume that holds data is refused unless `force`, which
/// removes and recreates it empty first. Skipped volumes are listed with the
/// reason. Keep the stack down for the whole import: a container that starts
/// on a volume between the last check and its upload is not seen.
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

    #[test]
    fn scratch_space_must_cover_archive_and_margin() {
        assert!(enough_scratch(100 + SCRATCH_MARGIN, 100).is_ok());
        assert!(enough_scratch(99 + SCRATCH_MARGIN, 100).is_err());
        assert!(enough_scratch(0, 0).is_err());
    }

    fn block<F: std::future::Future>(f: F) -> F::Output {
        plugin_toolkit::reactor::block_on(f)
    }

    fn volume(name: &str, key: Option<&str>, driver: &str, opts: &[(&str, &str)]) -> Volume {
        let mut labels = HashMap::from([(COMPOSE_PROJECT_LABEL.to_string(), "s".to_string())]);
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
        assert_eq!(
            classify(&data, "s", &strs(&["app:1"]), &[]).0,
            VolumeKind::Data
        );
        assert_eq!(classify(&data, "s", &[], &[]).0, VolumeKind::Data);

        let anon = volume("0a1b", None, "local", &[]);
        let (kind, why) = classify(&anon, "s", &[], &[]);
        assert_eq!(kind, VolumeKind::Anonymous);
        assert!(why.unwrap().contains("stale"));
        let mut labelled_anon = data.clone();
        labelled_anon
            .labels
            .insert(ANONYMOUS_LABEL.into(), String::new());
        assert_eq!(
            classify(&labelled_anon, "s", &strs(&["app:1"]), &[]).0,
            VolumeKind::Anonymous
        );

        let cache = volume("s_cache", Some("cache"), "local", &[]);
        let redis = strs(&["docker.io/library/redis:7@sha256:a", "valkey/valkey:8"]);
        assert_eq!(classify(&cache, "s", &redis, &[]).0, VolumeKind::Cache);
        assert_eq!(
            classify(&cache, "s", &redis, &strs(&["s_cache"])).0,
            VolumeKind::Data
        );
        assert_eq!(
            classify(&cache, "s", &strs(&["redis:7", "app:1"]), &[]).0,
            VolumeKind::Data
        );

        let nfs = volume("s_nfs", Some("nfs"), "local", &[("type", "nfs")]);
        assert_eq!(classify(&nfs, "s", &[], &[]).0, VolumeKind::External);

        let mut shared = volume("other_data", Some("data"), "local", &[]);
        shared
            .labels
            .insert(COMPOSE_PROJECT_LABEL.into(), "other".into());
        let (kind, why) = classify(&shared, "s", &strs(&["app:1"]), &[]);
        assert_eq!(kind, VolumeKind::Foreign);
        assert_eq!(why.unwrap(), "owned by project other");
    }

    fn export_engine() -> FakeEngine {
        export_engine_with(false)
    }

    fn export_engine_with(app_running: bool) -> FakeEngine {
        let inspect = move |name: &str, image: &str, mounts: &str| {
            let running = app_running && name == "app1";
            format!(
                r#"{{"Id":"{name}","Name":"/{name}","Image":"sha256:x","State":{{"Running":{running}}},"Config":{{"Image":"{image}"}},"Mounts":[{mounts}]}}"#
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
            allow_running: false,
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
            assert_eq!(v.size, Some(std::fs::metadata(&archive).unwrap().len()));
            assert!(v.running.is_empty());
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
            running: vec![],
            sha256: Some(plugin_toolkit::hash::sha256_hex(&archive)),
            size: Some(archive.len() as u64),
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
        target_engine_with(existing, "[]", 200)
    }

    /// `users` answers the volume-filtered container list; `put` is the
    /// upload's status.
    fn target_engine_with(existing: Option<&[(&str, &str)]>, users: &str, put: u16) -> FakeEngine {
        let mut routes = vec![Route::new("GET", "/containers/json", 200, users)];
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
            Route::new(
                "PUT",
                "/containers/h1/archive",
                put,
                r#"{"message":"disk full"}"#,
            ),
            Route::new("DELETE", "/containers/h1", 204, ""),
            Route::new("DELETE", "/volumes/s_data", 204, ""),
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
        assert!(create.contains(COMPOSE_PROJECT_LABEL) && create.contains("\"s_data\""));
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
        assert!(
            e.targets("GET")
                .iter()
                .any(|t| t.contains("/containers/json") && t.contains(r#""volume":["s_data"]"#))
        );
        let reqs = e.requests();
        let removed = reqs
            .iter()
            .position(|r| r.starts_with("DELETE") && r.contains("/volumes/s_data"))
            .expect("the volume is removed to empty it");
        let created = reqs
            .iter()
            .position(|r| r.starts_with("POST") && r.contains("/volumes/create"))
            .expect("and created again");
        let put = reqs.iter().position(|r| r.starts_with("PUT")).unwrap();
        assert!(removed < created && created < put);
        assert!(e.bodies("/volumes/create")[0].contains(COMPOSE_PROJECT_LABEL));
        assert!(out.created.is_empty());
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
    #[test]
    fn export_refuses_running_data_volumes_unless_allowed() {
        let root = tempfile::tempdir().unwrap();
        let e = export_engine_with(true);
        let err = block(export(
            &e.client(),
            &export_args(root.path(), true),
            &roots(root.path()),
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("s_data (app1)") && err.contains("allowRunning"),
            "{err}"
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);

        let out = block(export(
            &e.client(),
            &export_args(root.path(), false),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(!out.complete);
        let data = out.volumes.iter().find(|v| v.name == "s_data").unwrap();
        assert!(data.problem.as_deref().unwrap().contains("allowRunning"));

        let mut args = export_args(root.path(), true);
        args.allow_running = true;
        let out = block(export(&e.client(), &args, &roots(root.path()))).unwrap();
        assert!(out.complete);
        let json = std::fs::read(out.manifest.unwrap()).unwrap();
        let parsed: VolumeManifest = plugin_toolkit::serde_json::from_slice(&json).unwrap();
        let data = parsed.volumes.iter().find(|v| v.name == "s_data").unwrap();
        assert_eq!(data.running, ["app1"]);
    }

    #[test]
    fn export_bundles_never_collide() {
        let root = tempfile::tempdir().unwrap();
        let e = export_engine();
        let a = block(export(
            &e.client(),
            &export_args(root.path(), true),
            &roots(root.path()),
        ))
        .unwrap();
        let b = block(export(
            &e.client(),
            &export_args(root.path(), true),
            &roots(root.path()),
        ))
        .unwrap();
        assert_ne!(a.manifest, b.manifest);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
    }

    #[test]
    fn dry_runs_report_the_helper_image() {
        let root = tempfile::tempdir().unwrap();
        let out = block(export(
            &export_engine().client(),
            &export_args(root.path(), false),
            &roots(root.path()),
        ))
        .unwrap();
        assert_eq!(out.helper_image_present, Some(true));

        let (manifest, sha) = bundle(root.path(), &[("db", "rows")]);
        let e = FakeEngine::routed(vec![
            Route::new("GET", "/containers/json", 200, "[]"),
            Route::new(
                "GET",
                "/volumes/s_data",
                404,
                r#"{"message":"no such volume"}"#,
            ),
        ]);
        let out = block(import(
            &e.client(),
            &import_args(&manifest, &sha, false, false),
            &roots(root.path()),
        ))
        .unwrap();
        assert_eq!(out.helper_image_present, Some(false));
        assert!(e.paths("POST").is_empty(), "inspect only, never pull");
    }

    #[test]
    fn import_refuses_a_volume_a_running_container_mounts() {
        let root = tempfile::tempdir().unwrap();
        let (manifest, sha) = bundle(root.path(), &[("db", "rows")]);
        let users = r#"[{"Id":"c1","Names":["/s-app-1"],"State":"running"}]"#;
        for force in [false, true] {
            let e = target_engine_with(Some(&[]), users, 200);
            let out = block(import(
                &e.client(),
                &import_args(&manifest, &sha, force, true),
                &roots(root.path()),
            ))
            .unwrap();
            assert!(out.restored.is_empty());
            assert!(
                out.findings[0]
                    .message
                    .contains("running containers: s-app-1")
            );
            assert!(e.paths("PUT").is_empty() && e.paths("DELETE").is_empty());
        }
    }

    #[test]
    fn import_refuses_paused_and_restarting_containers() {
        let root = tempfile::tempdir().unwrap();
        let (manifest, sha) = bundle(root.path(), &[("db", "rows")]);
        for state in ["paused", "restarting"] {
            let users = format!(r#"[{{"Id":"c1","Names":["/s-app-1"],"State":"{state}"}}]"#);
            let e = target_engine_with(Some(&[]), &users, 200);
            let out = block(import(
                &e.client(),
                &import_args(&manifest, &sha, false, true),
                &roots(root.path()),
            ))
            .unwrap();
            assert!(out.restored.is_empty(), "{state}");
            assert!(
                out.findings[0]
                    .message
                    .contains("running containers: s-app-1"),
                "{state}"
            );
            assert!(e.paths("PUT").is_empty(), "{state}");
        }
    }

    #[test]
    fn upload_rechecks_users_after_the_helper_is_created() {
        let root = tempfile::tempdir().unwrap();
        let (manifest, sha) = bundle(root.path(), &[("db", "rows")]);
        // A new volume has no users to check up front, so only the re-check
        // before the upload can see this container.
        let users = r#"[{"Id":"c1","Names":["/s-app-1"],"State":"running"}]"#;
        let e = target_engine_with(None, users, 200);
        let out = block(import(
            &e.client(),
            &import_args(&manifest, &sha, false, true),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(out.restored.is_empty());
        assert!(
            out.findings[0]
                .message
                .contains("running containers: s-app-1")
        );
        assert!(e.paths("PUT").is_empty());
        assert!(
            e.paths("DELETE")
                .iter()
                .any(|p| p.ends_with("/containers/h1"))
        );

        let helper = r#"[{"Id":"h1","Names":["/helper"],"State":"running"}]"#;
        let e = target_engine_with(None, helper, 200);
        let out = block(import(
            &e.client(),
            &import_args(&manifest, &sha, false, true),
            &roots(root.path()),
        ))
        .unwrap();
        assert_eq!(out.restored, ["s_data"], "the helper is not a user");
    }

    #[test]
    fn overwrite_refuses_a_volume_a_stopped_container_references() {
        let root = tempfile::tempdir().unwrap();
        let (manifest, sha) = bundle(root.path(), &[("db", "rows")]);
        let users = r#"[{"Id":"c1","Names":["/s-app-1"],"State":"exited"}]"#;
        let e = target_engine_with(Some(&[("old", "x")]), users, 200);
        let out = block(import(
            &e.client(),
            &import_args(&manifest, &sha, true, true),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(out.restored.is_empty());
        assert!(
            out.findings[0]
                .message
                .contains("referenced by containers: s-app-1")
        );
        assert!(e.paths("DELETE").is_empty() && e.paths("PUT").is_empty());

        let e = target_engine_with(Some(&[]), users, 200);
        let out = block(import(
            &e.client(),
            &import_args(&manifest, &sha, false, true),
            &roots(root.path()),
        ))
        .unwrap();
        assert_eq!(
            out.restored,
            ["s_data"],
            "an empty volume is restored in place"
        );
    }

    #[test]
    fn a_failed_upload_says_rerun_with_force() {
        let root = tempfile::tempdir().unwrap();
        let (manifest, sha) = bundle(root.path(), &[("db", "rows")]);
        let e = target_engine_with(None, "[]", 500);
        let out = block(import(
            &e.client(),
            &import_args(&manifest, &sha, false, true),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(out.restored.is_empty());
        assert!(
            out.findings[0]
                .message
                .contains("partial restore; rerun with force"),
            "{:?}",
            out.findings
        );
    }

    #[test]
    fn keep_reports_a_driver_or_options_mismatch() {
        let root = tempfile::tempdir().unwrap();
        let nfs = VolumeEntry {
            name: "s_nfs".into(),
            key: Some("nfs".into()),
            driver: "local".into(),
            labels: BTreeMap::new(),
            options: BTreeMap::from([("type".to_string(), "nfs".to_string())]),
            kind: VolumeKind::External,
            reason: None,
            running: vec![],
            archive: None,
            sha256: None,
            size: None,
            problem: None,
        };
        let json = plugin_toolkit::serde_json::to_vec(&VolumeManifest {
            stack: "s".into(),
            volumes: vec![nfs],
        })
        .unwrap();
        let path = root.path().join(MANIFEST_FILE);
        std::fs::write(&path, &json).unwrap();
        let sha = plugin_toolkit::hash::sha256_hex(&json);
        let run = |opts: &[(&str, &str)]| {
            let e = FakeEngine::routed(vec![Route::new(
                "GET",
                "/volumes/s_nfs",
                200,
                plugin_toolkit::serde_json::to_string(&volume("s_nfs", Some("nfs"), "local", opts))
                    .unwrap(),
            )]);
            block(import(
                &e.client(),
                &import_args(&path.to_string_lossy(), &sha, false, false),
                &roots(root.path()),
            ))
            .unwrap()
        };
        let out = run(&[("type", "nfs4")]);
        assert_eq!(out.plan[0].action, ImportAction::Keep);
        assert!(
            out.findings[0].message.contains("nfs4"),
            "{:?}",
            out.findings
        );
        assert!(run(&[("type", "nfs")]).findings.is_empty());
    }

    fn volume_archive(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> File {
        let mut b = tar::Builder::new(Vec::new());
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_mode(0o755);
        dir.set_size(0);
        b.append_data(&mut dir, "v/", std::io::empty()).unwrap();
        build(&mut b);
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&b.into_inner().unwrap()).unwrap();
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(&gz.finish().unwrap()).unwrap();
        f
    }

    fn special(
        b: &mut tar::Builder<Vec<u8>>,
        kind: tar::EntryType,
        path: &str,
        link: Option<&str>,
    ) {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(kind);
        h.set_mode(0o644);
        h.set_size(0);
        match link {
            Some(target) => b.append_link(&mut h, path, target).unwrap(),
            None => b.append_data(&mut h, path, std::io::empty()).unwrap(),
        }
    }

    fn admit(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Result<()> {
        engine_state::validate_volume(&mut volume_archive(build), ARCHIVE_ROOT, VOLUME_LIMITS)
    }

    #[test]
    fn volume_archives_admit_any_symlink_but_no_devices_fifos_or_escapes() {
        admit(|b| {
            special(b, tar::EntryType::Symlink, "v/abs", Some("/etc/passwd"));
            special(b, tar::EntryType::Symlink, "v/up", Some("../../x"));
            special(b, tar::EntryType::Link, "v/hard", Some("v/abs"));
        })
        .unwrap();
        let refused = |build: fn(&mut tar::Builder<Vec<u8>>), why: &str| {
            let err = format!("{:#}", admit(build).unwrap_err());
            assert!(err.contains(why), "{err}");
        };
        refused(
            |b| special(b, tar::EntryType::Char, "v/null", None),
            "device node",
        );
        refused(
            |b| special(b, tar::EntryType::Block, "v/sda", None),
            "device node",
        );
        refused(|b| special(b, tar::EntryType::Fifo, "v/pipe", None), "fifo");
        refused(
            |b| special(b, tar::EntryType::Regular, "w/x", None),
            "not under 'v/'",
        );
        refused(
            |b| special(b, tar::EntryType::Link, "v/h", Some("etc/shadow")),
            "outside 'v/'",
        );
    }
}
