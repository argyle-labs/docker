//! `docker.stack_move_export` / `docker.stack_move_import` /
//! `docker.stack_move_finish` — the per-host halves of moving a stack between
//! docker hosts. The source pins every image by digest, stops the stack and
//! exports its named volumes beside a checksummed `move.json`; orca carries
//! the bundle dir to the target, which verifies every sum, restores the
//! volumes, recreates the containers on the pinned images and waits for them
//! to come up healthy, removing them again when they do not. The source is
//! then stopped, removed, or restarted as the rollback.
#![allow(clippy::disallowed_types)]

use std::collections::{BTreeMap, HashMap};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bollard::Docker;
use bollard::models::{
    ContainerCreateBody, ContainerInspectResponse, EndpointSettings, HostConfig, Ipam,
    NetworkCreateRequest, NetworkingConfig,
};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, InspectContainerOptionsBuilder, InspectNetworkOptions,
    RemoveContainerOptionsBuilder, StartContainerOptions, StopContainerOptions,
};
use plugin_toolkit::prelude::*;
use plugin_toolkit::secrets::{self, ResolveSecret, SecretRef};
use plugin_toolkit::serde_json::{self, Map, Value};

use crate::engine_state;
use crate::lifecycle::{in_backup_root, open_archive};
use crate::prune::COMPOSE_PROJECT_LABEL;
use crate::stack_health::{self, StackHealth};
use crate::stack_manifest::{self, containers_of};
use crate::stack_pull::{self, Pin};
use crate::stack_volumes::{
    self, DockerStackVolumesExportArgs, DockerStackVolumesImportArgs, StackVolumesExportOutput,
    StackVolumesImportOutput, check_sum, read_capped,
};

const EXPORT_TOOL: &str = "docker.stack_move_export";
const IMPORT_TOOL: &str = "docker.stack_move_import";
const FINISH_TOOL: &str = "docker.stack_move_finish";
const BUNDLE_FILE: &str = "move.json";
const MAX_BUNDLE_BYTES: u64 = 16 << 20;
const BUILTIN_NETWORKS: &[&str] = &["bridge", "host", "none", "default"];
/// HostConfig fields carried to the target as they are.
const KEPT_HOST_FIELDS: &[&str] = &[
    "RestartPolicy",
    "PortBindings",
    "LogConfig",
    "ExtraHosts",
    "Memory",
    "MemoryReservation",
    "MemorySwap",
    "NanoCpus",
    "CpuShares",
    "CpuQuota",
    "CpuPeriod",
    "CpusetCpus",
    "PidsLimit",
    "ShmSize",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
#[serde(rename_all = "camelCase")]
pub struct SecretEnv {
    pub key: String,
    pub secret: SecretRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
#[serde(rename_all = "camelCase")]
pub struct ContainerSpec {
    pub name: String,
    pub service: String,
    pub image: String,
    pub pinned: String,
    /// The create body, without the env entries in [`Self::secret_env`].
    pub create: Value,
    /// Env entries with secret-shaped names, held in the secrets domain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_env: Vec<SecretEnv>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
#[serde(rename_all = "camelCase")]
pub struct NetworkSpec {
    pub name: String,
    pub driver: String,
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
    #[serde(default)]
    pub internal: bool,
    #[serde(default)]
    pub attachable: bool,
    #[serde(default)]
    pub enable_ipv6: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipam: Option<Ipam>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
#[serde(rename_all = "camelCase")]
pub struct MoveBundle {
    pub stack: String,
    pub containers: Vec<ContainerSpec>,
    pub networks: Vec<NetworkSpec>,
    /// File name of the volume manifest beside this bundle.
    pub volumes_manifest: String,
    pub volumes_manifest_sha256: String,
}

fn not_found(e: &bollard::errors::Error) -> bool {
    matches!(
        e,
        bollard::errors::Error::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

fn already(e: &bollard::errors::Error) -> bool {
    matches!(
        e,
        bollard::errors::Error::DockerResponseServerError {
            status_code: 304,
            ..
        }
    )
}

fn is_default(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty() || a.iter().all(is_default),
        Value::Object(o) => o.is_empty(),
    }
}

fn valid_volume_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// The source of a `src:dst[:opts]` bind when it names a volume, not a host
/// path.
pub fn bind_volume(bind: &str) -> Option<&str> {
    let mut parts = bind.split(':');
    let src = parts.next()?;
    let dst = parts.next()?;
    let opts_ok = parts.next().is_none_or(|o| {
        o.split(',')
            .all(|f| matches!(f, "ro" | "rw" | "nocopy" | "z" | "Z" | ""))
    });
    (valid_volume_name(src) && dst.starts_with('/') && parts.next().is_none() && opts_ok)
        .then_some(src)
}

fn mount_refusal(m: &Value) -> Option<String> {
    let kind = m.get("Type").and_then(Value::as_str).unwrap_or_default();
    let source = m.get("Source").and_then(Value::as_str).unwrap_or_default();
    if m.get("BindOptions").is_some_and(|b| !is_default(b)) {
        return Some(format!("Mounts {kind} {source}: bind options"));
    }
    match kind {
        "volume" => {
            let driver = m
                .pointer("/VolumeOptions/DriverConfig")
                .is_some_and(|d| !is_default(d));
            (driver || !(source.is_empty() || valid_volume_name(source)))
                .then(|| format!("Mounts volume {source}"))
        }
        "tmpfs" => {
            let opts = m
                .pointer("/TmpfsOptions/Options")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_array)
                .flatten()
                .filter_map(Value::as_str);
            let mut risky = opts.filter(|o| matches!(*o, "exec" | "suid"));
            risky.next().map(|o| format!("Mounts tmpfs {o}"))
        }
        other => Some(format!("Mounts {other} {source}")),
    }
}

/// The HostConfig the target recreates `name` with: only the allowlisted
/// fields, every capability dropped and no new privileges. Any other field
/// set away from its default is refused.
pub fn rebuild_host_config(name: &str, h: &HostConfig) -> Result<HostConfig> {
    let Value::Object(src) = serde_json::to_value(h)? else {
        bail!("{name}: HostConfig is not an object");
    };
    let mut kept = Map::new();
    let mut refused = Vec::new();
    let text = |v: &Value| v.as_str().unwrap_or_default().to_owned();
    for (k, v) in src {
        match k.as_str() {
            f if KEPT_HOST_FIELDS.contains(&f) => {
                kept.insert(k, v);
            }
            "NetworkMode" => {
                let m = text(&v);
                if m == "host" || m.starts_with("container:") {
                    refused.push(format!("NetworkMode {m}"));
                } else {
                    kept.insert(k, v);
                }
            }
            "Binds" => {
                for b in v.as_array().into_iter().flatten() {
                    let b = text(b);
                    if bind_volume(&b).is_none() {
                        refused.push(format!("Binds {b}"));
                    }
                }
                kept.insert(k, v);
            }
            "Mounts" => {
                refused.extend(v.as_array().into_iter().flatten().filter_map(mount_refusal));
                kept.insert(k, v);
            }
            "IpcMode" if matches!(text(&v).as_str(), "" | "private" | "shareable") => {}
            "CgroupnsMode" if matches!(text(&v).as_str(), "" | "private") => {}
            "Runtime" if matches!(text(&v).as_str(), "" | "runc") => {}
            "MaskedPaths" | "ReadonlyPaths" if v.as_array().is_some_and(|a| a.is_empty()) => {
                refused.push(format!("{k} empty"));
            }
            "MaskedPaths" | "ReadonlyPaths" => {}
            "SecurityOpt"
                if v.as_array().into_iter().flatten().all(|o| {
                    matches!(
                        o.as_str(),
                        Some("no-new-privileges" | "no-new-privileges:true")
                    )
                }) => {}
            "CapDrop" | "ConsoleSize" => {}
            _ if is_default(&v) => {}
            _ => refused.push(k),
        }
    }
    if !refused.is_empty() {
        bail!("{name}: refusing HostConfig {}", refused.join(", "));
    }
    kept.insert("CapDrop".into(), serde_json::json!(["ALL"]));
    kept.insert(
        "SecurityOpt".into(),
        serde_json::json!(["no-new-privileges:true"]),
    );
    Ok(serde_json::from_value(Value::Object(kept))?)
}

/// The spec of `c` on `pinned`, and the env entries with secret-shaped names
/// taken out of it.
pub fn spec_of(
    c: &ContainerInspectResponse,
    pinned: &str,
) -> Result<(ContainerSpec, Vec<(String, String)>)> {
    let meta = stack_manifest::StackContainer::from_inspect(c);
    let mut create: ContainerCreateBody = match &c.config {
        Some(cfg) => serde_json::from_value(serde_json::to_value(cfg)?)?,
        None => ContainerCreateBody::default(),
    };
    create.image = Some(pinned.to_owned());
    create.host_config = c.host_config.clone();
    let mut secret = Vec::new();
    if let Some(env) = create.env.take() {
        let (hidden, plain): (Vec<String>, Vec<String>) = env.into_iter().partition(|e| {
            plugin_toolkit::scrub::is_sensitive_key(e.split_once('=').map_or(e.as_str(), |p| p.0))
        });
        secret = hidden
            .into_iter()
            .filter_map(|e| e.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
            .collect();
        create.env = Some(plain);
    }
    let endpoints: HashMap<String, EndpointSettings> = c
        .network_settings
        .as_ref()
        .and_then(|n| n.networks.as_ref())
        .into_iter()
        .flatten()
        .map(|(net, ep)| {
            (
                net.clone(),
                EndpointSettings {
                    aliases: ep.aliases.clone(),
                    ..Default::default()
                },
            )
        })
        .collect();
    if !endpoints.is_empty() {
        create.networking_config = Some(NetworkingConfig {
            endpoints_config: Some(endpoints),
        });
    }
    Ok((
        ContainerSpec {
            name: meta.name,
            service: meta.service,
            image: meta.reference,
            pinned: pinned.to_owned(),
            create: serde_json::to_value(&create)?,
            secret_env: Vec::new(),
        },
        secret,
    ))
}

fn secret_name(stack: &str, container: &str, key: &str) -> String {
    format!("docker.move.{stack}.{container}.{key}")
}

/// The create body the target runs `spec` with, after every check that does
/// not need the secrets.
fn checked_body(stack: &str, spec: &ContainerSpec) -> Result<ContainerCreateBody> {
    let mut body: ContainerCreateBody = serde_json::from_value(spec.create.clone())
        .map_err(|e| anyhow!("spec of {}: {e}", spec.name))?;
    let project = body
        .labels
        .as_ref()
        .and_then(|l| l.get(COMPOSE_PROJECT_LABEL))
        .map(String::as_str);
    if project != Some(stack) {
        bail!(
            "{}: labelled for project {project:?}, not '{stack}'; refusing a retarget",
            spec.name
        );
    }
    body.host_config = Some(rebuild_host_config(
        &spec.name,
        &body.host_config.unwrap_or_default(),
    )?);
    body.image = Some(spec.pinned.clone());
    Ok(body)
}

fn check_network(n: &NetworkSpec) -> Result<()> {
    if n.driver != "bridge" {
        bail!(
            "network '{}' uses driver '{}'; only bridge networks move",
            n.name,
            n.driver
        );
    }
    Ok(())
}

async fn inspect_all(docker: &Docker, stack: &str) -> Result<Vec<ContainerInspectResponse>> {
    let mut out = Vec::new();
    for id in containers_of(docker, stack)
        .await?
        .iter()
        .filter_map(|c| c.id.as_deref())
    {
        let opts = InspectContainerOptionsBuilder::new().build();
        match docker.inspect_container(id, Some(opts)).await {
            Ok(c) => out.push(c),
            Err(e) if not_found(&e) => {}
            Err(e) => bail!("inspect container {id}: {e}"),
        }
    }
    Ok(out)
}

fn is_running(c: &ContainerInspectResponse) -> bool {
    c.state.as_ref().and_then(|s| s.running) == Some(true)
}

struct SourcePlan {
    specs: Vec<(ContainerSpec, Vec<(String, String)>)>,
    networks: Vec<NetworkSpec>,
    running: Vec<String>,
}

async fn source_plan(docker: &Docker, stack: &str) -> Result<SourcePlan> {
    let manifest = stack_manifest::collect(docker, stack).await?;
    if !manifest.complete {
        let problems: Vec<String> = manifest
            .images
            .iter()
            .filter_map(|i| i.problem.as_ref().map(|p| format!("{}: {p}", i.container)))
            .collect();
        bail!(
            "not every image can be pinned by digest: {}",
            problems.join("; ")
        );
    }
    let pins: HashMap<&str, &str> = manifest
        .images
        .iter()
        .filter_map(|i| Some((i.container.as_str(), i.pinned.as_deref()?)))
        .collect();
    let inspected = inspect_all(docker, stack).await?;
    let mut specs = Vec::new();
    let mut running = Vec::new();
    let mut nets = Vec::new();
    for c in &inspected {
        let name = c
            .name
            .as_deref()
            .unwrap_or_default()
            .trim_start_matches('/');
        let pinned = pins
            .get(name)
            .ok_or_else(|| anyhow!("{name} appeared after the manifest was read"))?;
        if is_running(c) {
            running.push(name.to_owned());
        }
        nets.extend(
            c.network_settings
                .as_ref()
                .and_then(|n| n.networks.as_ref())
                .into_iter()
                .flat_map(|n| n.keys().cloned()),
        );
        let spec = spec_of(c, pinned)?;
        checked_body(stack, &spec.0)?;
        specs.push(spec);
    }
    specs.sort_by(|a, b| a.0.name.cmp(&b.0.name));
    nets.sort();
    nets.dedup();
    let mut networks = Vec::new();
    for name in nets
        .iter()
        .filter(|n| !BUILTIN_NETWORKS.contains(&n.as_str()))
    {
        let n = docker
            .inspect_network(name, None::<InspectNetworkOptions>)
            .await
            .map_err(|e| anyhow!("inspect network {name}: {e}"))?;
        let spec = NetworkSpec {
            name: name.clone(),
            driver: n.driver.unwrap_or_else(|| "bridge".into()),
            labels: n.labels.unwrap_or_default().into_iter().collect(),
            options: n.options.unwrap_or_default().into_iter().collect(),
            internal: n.internal.unwrap_or(false),
            attachable: n.attachable.unwrap_or(false),
            enable_ipv6: n.enable_ipv6.unwrap_or(false),
            ipam: n.ipam,
        };
        check_network(&spec)?;
        networks.push(spec);
    }
    Ok(SourcePlan {
        specs,
        networks,
        running,
    })
}

async fn stop(docker: &Docker, name: &str) -> Result<()> {
    match docker
        .stop_container(name, None::<StopContainerOptions>)
        .await
    {
        Ok(()) => Ok(()),
        Err(e) if already(&e) || not_found(&e) => Ok(()),
        Err(e) => Err(anyhow!("stop {name}: {e}")),
    }
}

async fn start(docker: &Docker, name: &str) -> Result<()> {
    match docker
        .start_container(name, None::<StartContainerOptions>)
        .await
    {
        Ok(()) => Ok(()),
        Err(e) if already(&e) => Ok(()),
        Err(e) => Err(anyhow!("start {name}: {e}")),
    }
}

async fn remove(docker: &Docker, name: &str) -> Result<()> {
    let opts = RemoveContainerOptionsBuilder::new()
        .force(true)
        .v(false)
        .build();
    match docker.remove_container(name, Some(opts)).await {
        Ok(()) => Ok(()),
        Err(e) if not_found(&e) => Ok(()),
        Err(e) => Err(anyhow!("remove {name}: {e}")),
    }
}

/// Restarts what was stopped; the errors of the restart are the result.
async fn restart_all(docker: &Docker, names: &[String]) -> Vec<String> {
    let mut failed = Vec::new();
    for n in names {
        if let Err(e) = start(docker, n).await {
            failed.push(format!("{e:#}"));
        }
    }
    failed
}

fn rollback_context(
    cause: plugin_toolkit::anyhow::Error,
    failed: &[String],
) -> plugin_toolkit::anyhow::Error {
    if failed.is_empty() {
        cause.context("source restarted")
    } else {
        cause.context(format!("source restart FAILED: {}", failed.join("; ")))
    }
}

#[orca_struct(args)]
pub struct DockerStackMoveExportArgs {
    /// Compose project name.
    #[arg(long)]
    pub stack: String,
    /// Absolute dir inside the daemon's backup roots for the bundle dir.
    #[arg(long)]
    pub destination: String,
    /// Leave the stack running through the export; its volume archives may
    /// then be inconsistent. Stop it with `docker.stack_move_finish` once the
    /// target is healthy.
    #[arg(long)]
    #[serde(default, rename = "keepRunning", alias = "keep_running")]
    pub keep_running: bool,
    /// Return the plan and change nothing. Omitted, applies.
    #[arg(long)]
    #[serde(default, rename = "dryRun", alias = "dry_run")]
    pub dry_run: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedContainer {
    pub name: String,
    pub service: String,
    pub pinned: String,
    pub running: bool,
    /// Env names stored in the secrets domain instead of `move.json`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_env: Vec<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StackMoveExportOutput {
    pub executed: bool,
    pub stack: String,
    pub containers: Vec<PlannedContainer>,
    pub networks: Vec<String>,
    /// Containers stopped for the export (execute), or that would be.
    pub stopped: Vec<String>,
    pub volumes: StackVolumesExportOutput,
    /// Path of `move.json`; carry its whole dir to the target and pass it
    /// with [`Self::bundle_sha256`] to `docker.stack_move_import`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_sha256: Option<String>,
}

fn write_bundle(dir: &Path, bundle: &MoveBundle) -> Result<(PathBuf, String)> {
    let json = serde_json::to_vec_pretty(bundle)?;
    let path = dir.join(BUNDLE_FILE);
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
    Ok((path, plugin_toolkit::hash::sha256_hex(&json)))
}

/// Stores each secret-shaped env value in the secrets domain and leaves only
/// its reference in the spec.
fn store_secrets(
    stack: &str,
    specs: Vec<(ContainerSpec, Vec<(String, String)>)>,
) -> Result<Vec<ContainerSpec>> {
    specs
        .into_iter()
        .map(|(mut spec, hidden)| {
            for (key, value) in hidden {
                let name = secret_name(stack, &spec.name, &key);
                let secret = secrets::set(&name, &value, Some("docker stack move env"))
                    .with_context(|| format!("store {key} of {} as a secret", spec.name))?;
                spec.secret_env.push(SecretEnv { key, secret });
            }
            Ok(spec)
        })
        .collect()
}

/// The bundle dir, once more resolved inside the backup roots.
fn bundle_dir(manifest: &Path, roots: &[String]) -> Result<PathBuf> {
    let dir = manifest
        .parent()
        .ok_or_else(|| anyhow!("volume manifest '{}' has no dir", manifest.display()))?;
    let resolved = in_backup_root(&dir.to_string_lossy(), roots)?;
    if resolved != dir {
        bail!(
            "bundle dir '{}' moved outside the backup roots",
            dir.display()
        );
    }
    Ok(resolved)
}

pub async fn export(
    docker: &Docker,
    args: &DockerStackMoveExportArgs,
    roots: &[String],
) -> Result<StackMoveExportOutput> {
    let plan = source_plan(docker, &args.stack).await?;
    let stopping = if args.keep_running {
        Vec::new()
    } else {
        plan.running.clone()
    };
    let mut out = StackMoveExportOutput {
        executed: !args.dry_run,
        stack: args.stack.clone(),
        containers: plan
            .specs
            .iter()
            .map(|(s, hidden)| PlannedContainer {
                name: s.name.clone(),
                service: s.service.clone(),
                pinned: s.pinned.clone(),
                running: plan.running.contains(&s.name),
                secret_env: hidden.iter().map(|(k, _)| k.clone()).collect(),
            })
            .collect(),
        networks: plan.networks.iter().map(|n| n.name.clone()).collect(),
        stopped: stopping.clone(),
        ..Default::default()
    };
    let volume_args = DockerStackVolumesExportArgs {
        stack: args.stack.clone(),
        destination: args.destination.clone(),
        include: vec![],
        allow_running: args.keep_running || args.dry_run,
        dry_run: args.dry_run,
    };
    if args.dry_run {
        out.volumes = stack_volumes::export(docker, &volume_args, roots).await?;
        return Ok(out);
    }
    let specs = store_secrets(&args.stack, plan.specs)?;
    let mut stopped = Vec::new();
    for n in &stopping {
        if let Err(e) = stop(docker, n).await {
            let failed = restart_all(docker, &stopped).await;
            return Err(rollback_context(e, &failed));
        }
        stopped.push(n.clone());
    }
    let written = async {
        let exported = stack_volumes::export(docker, &volume_args, roots).await?;
        if !exported.complete {
            let problems: Vec<String> = exported
                .volumes
                .iter()
                .filter_map(|e| e.problem.as_ref().map(|p| format!("{}: {p}", e.name)))
                .collect();
            bail!("volume export incomplete: {}", problems.join("; "));
        }
        let manifest = PathBuf::from(exported.manifest.clone().unwrap_or_default());
        let dir = bundle_dir(&manifest, roots)?;
        let (Some(file), Some(sha)) = (manifest.file_name(), exported.manifest_sha256.clone())
        else {
            bail!("volume export wrote no manifest");
        };
        let bundle = MoveBundle {
            stack: args.stack.clone(),
            containers: specs,
            networks: plan.networks,
            volumes_manifest: file.to_string_lossy().into_owned(),
            volumes_manifest_sha256: sha,
        };
        let (path, sha) = write_bundle(&dir, &bundle)?;
        Ok((exported, path, sha))
    }
    .await;
    let (exported, path, sha) = match written {
        Ok(w) => w,
        Err(e) => {
            let failed = restart_all(docker, &stopped).await;
            return Err(rollback_context(e, &failed));
        }
    };
    out.volumes = exported;
    out.bundle = Some(path.to_string_lossy().into_owned());
    out.bundle_sha256 = Some(sha);
    Ok(out)
}

/// **Export a stack for a move** (source host): pins every image by the
/// digest this host runs, stops the stack unless `keepRunning`, exports its
/// named volumes with sha256 sums, and writes `move.json` (mode 0600:
/// container specs on the pinned images, networks, the volume manifest's sum)
/// beside them. Env values with secret-shaped names go to the secrets domain;
/// `move.json` holds only their references. A stop or export failure
/// restarts what was stopped. Refused when an image cannot be pinned or a
/// container's host config would not be recreated on the target.
#[orca_tool(
    domain = "docker",
    verb = "stack_move_export",
    role = "admin",
    execute_gated = false
)]
async fn docker_stack_move_export(
    args: DockerStackMoveExportArgs,
    ctx: &ToolCtx,
) -> Result<StackMoveExportOutput> {
    crate::execute::require_admin(EXPORT_TOOL, ctx)?;
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    export(docker, &args, &engine_state::backup_roots()).await
}

fn load_bundle(path: &str, sha256: &str, roots: &[String]) -> Result<(MoveBundle, PathBuf)> {
    let mut file = open_archive(path, roots)?;
    let dir = engine_state::fd_path(&file)?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("bundle '{path}' has no parent dir"))?;
    let data = read_capped(&mut file, MAX_BUNDLE_BYTES, "bundle")?;
    check_sum(&plugin_toolkit::hash::sha256_hex(&data), sha256, "bundle")?;
    let bundle: MoveBundle =
        serde_json::from_slice(&data).map_err(|e| anyhow!("bundle '{path}': {e}"))?;
    let m = &bundle.volumes_manifest;
    if m.is_empty() || m.contains('/') || m.starts_with('.') {
        bail!("bundle names volume manifest '{m}' outside its dir");
    }
    for c in &bundle.containers {
        stack_pull::parse(&format!("{}={}", c.image, c.pinned))?;
    }
    Ok((bundle, dir))
}

#[orca_struct(args)]
pub struct DockerStackMoveImportArgs {
    /// Absolute path of `move.json` from `docker.stack_move_export`, inside
    /// the daemon's backup roots, the rest of its bundle dir beside it.
    #[arg(long)]
    pub bundle: String,
    /// The export's `bundleSha256`.
    #[arg(long)]
    #[serde(rename = "bundleSha256", alias = "bundle_sha256")]
    pub bundle_sha256: String,
    /// Seconds to wait for the stack to come up healthy (default and
    /// maximum 25).
    #[arg(long)]
    #[serde(default, rename = "timeoutSecs", alias = "timeout_secs")]
    pub timeout_secs: Option<u64>,
    /// Return the plan and change nothing. Omitted, applies.
    #[arg(long)]
    #[serde(default, rename = "dryRun", alias = "dry_run")]
    pub dry_run: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StackMoveImportOutput {
    pub executed: bool,
    pub stack: String,
    pub volumes: StackVolumesImportOutput,
    /// `image=pinned` pairs pulled (execute), or that would be.
    pub pulled: Vec<String>,
    pub networks_created: Vec<String>,
    /// Containers created on the pinned images (execute), or that would be.
    pub containers: Vec<String>,
    /// `container: user` each container runs as; `image default` when unset.
    pub users: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<StackHealth>,
    /// The stack did not come up healthy and its containers and created
    /// networks were removed; restart the source with
    /// `docker.stack_move_finish`.
    pub rolled_back: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rollback_failures: Vec<String>,
}

async fn create_networks(
    docker: &Docker,
    networks: &[NetworkSpec],
    created: &mut Vec<String>,
) -> Result<()> {
    for n in networks {
        match docker
            .inspect_network(&n.name, None::<InspectNetworkOptions>)
            .await
        {
            Ok(_) => continue,
            Err(e) if not_found(&e) => {}
            Err(e) => bail!("inspect network {}: {e}", n.name),
        }
        docker
            .create_network(NetworkCreateRequest {
                name: n.name.clone(),
                driver: Some(n.driver.clone()),
                labels: Some(n.labels.clone().into_iter().collect()),
                options: Some(n.options.clone().into_iter().collect()),
                internal: Some(n.internal),
                attachable: Some(n.attachable),
                enable_ipv6: Some(n.enable_ipv6),
                ipam: n.ipam.clone(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow!("create network {}: {e}", n.name))?;
        created.push(n.name.clone());
    }
    Ok(())
}

/// Removes what the import created; the failures are the result.
async fn undo(docker: &Docker, containers: &[String], networks: &[String]) -> Vec<String> {
    let mut failed = Vec::new();
    for n in containers {
        if let Err(e) = remove(docker, n).await {
            failed.push(format!("{e:#}"));
        }
    }
    for n in networks {
        if let Err(e) = docker.remove_network(n).await {
            failed.push(format!("remove network {n}: {e}"));
        }
    }
    failed
}

fn with_volumes(
    e: plugin_toolkit::anyhow::Error,
    v: &StackVolumesImportOutput,
    failed: &[String],
) -> plugin_toolkit::anyhow::Error {
    let e = if failed.is_empty() {
        e
    } else {
        e.context(format!("rollback FAILED: {}", failed.join("; ")))
    };
    if v.created.is_empty() && v.restored.is_empty() {
        return e;
    }
    e.context(format!(
        "volumes left on this host: created [{}], restored [{}]",
        v.created.join(", "),
        v.restored.join(", ")
    ))
}

fn resolve_env(spec: &ContainerSpec, dry_run: bool) -> Result<Vec<String>> {
    spec.secret_env
        .iter()
        .map(|s| {
            let value = if dry_run {
                if !secrets::exists(&s.secret.0)? {
                    bail!("no secret '{}' on this host", s.secret.0);
                }
                String::new()
            } else {
                s.secret.resolve()?
            };
            Ok(format!("{}={value}", s.key))
        })
        .collect::<Result<_>>()
        .with_context(|| format!("secret env of {}", spec.name))
}

pub async fn import(
    docker: &Docker,
    args: &DockerStackMoveImportArgs,
    roots: &[String],
) -> Result<StackMoveImportOutput> {
    let (bundle, dir) = load_bundle(&args.bundle, &args.bundle_sha256, roots)?;
    for n in &bundle.networks {
        check_network(n)?;
    }
    let mut bodies = Vec::new();
    for c in &bundle.containers {
        let mut body = checked_body(&bundle.stack, c)?;
        let env = resolve_env(c, args.dry_run)?;
        if !args.dry_run {
            body.env.get_or_insert_with(Vec::new).extend(env);
        }
        bodies.push(body);
    }
    for c in &bundle.containers {
        let opts = InspectContainerOptionsBuilder::new().build();
        match docker.inspect_container(&c.name, Some(opts)).await {
            Ok(_) => bail!(
                "container '{}' already exists on this host; remove it first",
                c.name
            ),
            Err(e) if not_found(&e) => {}
            Err(e) => bail!("inspect container {}: {e}", c.name),
        }
    }
    let volume_args = DockerStackVolumesImportArgs {
        manifest: dir
            .join(&bundle.volumes_manifest)
            .to_string_lossy()
            .into_owned(),
        manifest_sha256: bundle.volumes_manifest_sha256.clone(),
        force: false,
        dry_run: args.dry_run,
    };
    let pins: Vec<Pin> = bundle
        .containers
        .iter()
        .map(|c| Pin {
            image: c.image.clone(),
            pinned: c.pinned.clone(),
        })
        .collect();
    let mut out = StackMoveImportOutput {
        executed: !args.dry_run,
        stack: bundle.stack.clone(),
        containers: bundle.containers.iter().map(|c| c.name.clone()).collect(),
        users: bundle
            .containers
            .iter()
            .zip(&bodies)
            .map(|(c, b)| {
                let user = b.user.as_deref().filter(|u| !u.is_empty());
                format!("{}: {}", c.name, user.unwrap_or("image default"))
            })
            .collect(),
        ..Default::default()
    };
    if args.dry_run {
        out.volumes = stack_volumes::import(docker, &volume_args, roots).await?;
        out.pulled = pins
            .iter()
            .map(|p| format!("{}={}", p.image, p.pinned))
            .collect();
        out.networks_created = bundle.networks.iter().map(|n| n.name.clone()).collect();
        return Ok(out);
    }
    out.volumes = stack_volumes::import(docker, &volume_args, roots).await?;
    if !out.volumes.findings.is_empty() {
        let f: Vec<String> = out
            .volumes
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.name, f.message))
            .collect();
        return Err(with_volumes(
            anyhow!("volume import incomplete: {}", f.join("; ")),
            &out.volumes,
            &[],
        ));
    }
    let pulled = stack_pull::apply(docker, &pins).await;
    if !pulled.findings.is_empty() {
        let f: Vec<String> = pulled
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.image, f.message))
            .collect();
        return Err(with_volumes(
            anyhow!("pinned pull failed: {}", f.join("; ")),
            &out.volumes,
            &[],
        ));
    }
    out.pulled = pulled.pulled;
    let mut networks = Vec::new();
    let mut created = Vec::new();
    let brought_up = async {
        create_networks(docker, &bundle.networks, &mut networks).await?;
        for (c, body) in bundle.containers.iter().zip(bodies) {
            let opts = CreateContainerOptionsBuilder::new().name(&c.name).build();
            docker
                .create_container(Some(opts), body)
                .await
                .map_err(|e| anyhow!("create {}: {e}", c.name))?;
            created.push(c.name.clone());
        }
        for c in &created {
            start(docker, c).await?;
        }
        stack_health::wait(docker, &bundle.stack, health_timeout(args.timeout_secs)).await
    }
    .await;
    out.networks_created = networks;
    let health = match brought_up {
        Ok(h) => h,
        Err(e) => {
            let failed = undo(docker, &created, &out.networks_created).await;
            return Err(with_volumes(
                e.context("created containers and networks removed"),
                &out.volumes,
                &failed,
            ));
        }
    };
    if !health.ready {
        out.rollback_failures = undo(docker, &created, &out.networks_created).await;
        out.rolled_back = true;
    }
    out.health = Some(health);
    Ok(out)
}

fn health_timeout(requested: Option<u64>) -> Duration {
    Duration::from_secs(requested.map_or(25, |s| s.clamp(1, 25)))
}

/// **Bring a moved stack up on this host** (target): checks `move.json`'s
/// sha256, restores the named volumes (every archive sum-checked before any
/// volume is created; volumes on another driver or with driver options are
/// refused), pulls each image by its pinned digest, creates the stack's
/// bridge networks and recreates its containers on the pinned images with an
/// allowlisted host config, every capability dropped and no new privileges,
/// then waits until they are healthy. A stack that fails or is not healthy
/// in time has its containers and created networks removed (`rolledBack`);
/// restore the source with `docker.stack_move_finish` `restart`. Refused when
/// one of its containers already exists here.
#[orca_tool(
    domain = "docker",
    verb = "stack_move_import",
    role = "admin",
    execute_gated = false
)]
async fn docker_stack_move_import(
    args: DockerStackMoveImportArgs,
    ctx: &ToolCtx,
) -> Result<StackMoveImportOutput> {
    crate::execute::require_admin(IMPORT_TOOL, ctx)?;
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    import(docker, &args, &engine_state::backup_roots()).await
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    plugin_toolkit::serde::Serialize,
    plugin_toolkit::serde::Deserialize,
    plugin_toolkit::schemars::JsonSchema,
    plugin_toolkit::clap::ValueEnum,
)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "lowercase")]
pub enum FinishAction {
    /// Stop the source stack, keeping its containers.
    Stop,
    /// Stop and remove the source containers; volumes stay. Needs the move's
    /// `bundle` and `bundleSha256`.
    Remove,
    /// Rollback: start the source stack again.
    Restart,
}

#[orca_struct(args)]
pub struct DockerStackMoveFinishArgs {
    /// Compose project name.
    #[arg(long)]
    pub stack: String,
    /// `stop`, `remove`, or `restart` (the rollback).
    #[arg(long, value_enum)]
    #[serde(default)]
    pub action: Option<FinishAction>,
    /// `remove` only: the `move.json` this host exported for the move.
    #[arg(long)]
    #[serde(default)]
    pub bundle: Option<String>,
    /// `remove` only: the export's `bundleSha256`.
    #[arg(long)]
    #[serde(default, rename = "bundleSha256", alias = "bundle_sha256")]
    pub bundle_sha256: Option<String>,
    /// Return the plan and change nothing. Omitted, applies.
    #[arg(long)]
    #[serde(default, rename = "dryRun", alias = "dry_run")]
    pub dry_run: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StackMoveFinishOutput {
    pub executed: bool,
    pub stack: String,
    /// Containers acted on (execute), or that would be.
    pub containers: Vec<String>,
    pub failures: Vec<String>,
}

/// `remove` acts only on the containers the verified bundle moved.
fn bound_to_move(
    args: &DockerStackMoveFinishArgs,
    names: &[String],
    roots: &[String],
) -> Result<()> {
    let (Some(bundle), Some(sha)) = (&args.bundle, &args.bundle_sha256) else {
        bail!("remove needs the move's bundle and bundleSha256");
    };
    let (bundle, _) = load_bundle(bundle, sha, roots)?;
    if bundle.stack != args.stack {
        bail!(
            "bundle moved stack '{}', not '{}'",
            bundle.stack,
            args.stack
        );
    }
    let unmoved: Vec<&str> = names
        .iter()
        .filter(|n| !bundle.containers.iter().any(|c| &c.name == *n))
        .map(String::as_str)
        .collect();
    if !unmoved.is_empty() {
        bail!(
            "containers not in the move's bundle: {}",
            unmoved.join(", ")
        );
    }
    Ok(())
}

pub async fn finish(
    docker: &Docker,
    args: &DockerStackMoveFinishArgs,
    roots: &[String],
) -> Result<StackMoveFinishOutput> {
    let Some(action) = args.action else {
        bail!("action is required: stop, remove or restart");
    };
    let mut names: Vec<String> = inspect_all(docker, &args.stack)
        .await?
        .iter()
        .map(|c| {
            c.name
                .as_deref()
                .unwrap_or_default()
                .trim_start_matches('/')
                .to_owned()
        })
        .collect();
    names.sort();
    if names.is_empty() {
        bail!("stack '{}' has no containers on this host", args.stack);
    }
    if action == FinishAction::Remove {
        bound_to_move(args, &names, roots)?;
    }
    let mut out = StackMoveFinishOutput {
        executed: !args.dry_run,
        stack: args.stack.clone(),
        containers: names.clone(),
        ..Default::default()
    };
    if args.dry_run {
        return Ok(out);
    }
    out.failures = match action {
        FinishAction::Restart => restart_all(docker, &names).await,
        FinishAction::Remove => undo(docker, &names, &[]).await,
        FinishAction::Stop => {
            let mut failed = Vec::new();
            for n in &names {
                if let Err(e) = stop(docker, n).await {
                    failed.push(format!("{e:#}"));
                }
            }
            failed
        }
    };
    Ok(out)
}

/// **Finish a stack move on the source host**: once the target is healthy,
/// `stop` the stack or `remove` its containers (volumes stay; only with the
/// move's verified `bundle`, and only the containers it moved); when the
/// target failed, `restart` it as the rollback.
#[orca_tool(
    domain = "docker",
    verb = "stack_move_finish",
    role = "admin",
    execute_gated = false
)]
async fn docker_stack_move_finish(
    args: DockerStackMoveFinishArgs,
    ctx: &ToolCtx,
) -> Result<StackMoveFinishOutput> {
    crate::execute::require_admin(FINISH_TOOL, ctx)?;
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    finish(docker, &args, &engine_state::backup_roots()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};
    use crate::test_support::with_secrets;
    use plugin_toolkit::serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    const A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn block<T>(f: impl std::future::Future<Output = T>) -> T {
        plugin_toolkit::reactor::block_on(f)
    }

    fn roots(dir: &Path) -> Vec<String> {
        vec![dir.to_string_lossy().into_owned()]
    }

    fn writes(e: &FakeEngine) -> Vec<String> {
        ["POST", "PUT", "DELETE"]
            .iter()
            .flat_map(|m| e.paths(m))
            .collect()
    }

    fn source_routes() -> Vec<Route> {
        vec![
            Route::new("GET", "/containers/json", 200, r#"[{"Id":"c1"}]"#),
            Route::new(
                "GET",
                "/containers/c1/json",
                200,
                json!({
                    "Name": "/s-cache-1",
                    "Image": "sha256:img",
                    "State": { "Status": "running", "Running": true },
                    "Config": {
                        "Image": "redis:7",
                        "User": "999",
                        "Env": ["MODE=fast", "DB_PASSWORD=hunter2"],
                        "Labels": {
                            "com.docker.compose.project": "s",
                            "com.docker.compose.service": "cache"
                        }
                    },
                    "HostConfig": { "NetworkMode": "s_default", "MaskedPaths": ["/proc/kcore"] },
                    "Mounts": [{ "Type": "volume", "Name": "s_cache", "Destination": "/data" }],
                    "NetworkSettings": { "Networks": { "s_default": { "Aliases": ["cache"] } } }
                })
                .to_string(),
            ),
            Route::new(
                "GET",
                "/images/sha256:img/json",
                200,
                json!({ "RepoDigests": [format!("redis@{A}")] }).to_string(),
            ),
            Route::new(
                "GET",
                "/networks/s_default",
                200,
                r#"{"Name":"s_default","Driver":"bridge","Internal":true,"Options":{"com.docker.network.bridge.enable_icc":"false"},"Labels":{"com.docker.compose.project":"s"}}"#,
            ),
            Route::new("GET", "/volumes", 200, r#"{"Volumes":[]}"#),
            Route::new(
                "GET",
                "/volumes/s_cache",
                200,
                json!({
                    "Name": "s_cache",
                    "Driver": "local",
                    "Mountpoint": "/var/lib/docker/volumes/s_cache/_data",
                    "Labels": {
                        "com.docker.compose.project": "s",
                        "com.docker.compose.volume": "cache"
                    },
                    "Options": {},
                    "Scope": "local"
                })
                .to_string(),
            ),
            Route::new("POST", "/containers/s-cache-1/stop", 204, ""),
            Route::new("POST", "/containers/s-cache-1/start", 204, ""),
        ]
    }

    fn source_engine() -> FakeEngine {
        FakeEngine::routed(source_routes())
    }

    fn export_args(dir: &Path, dry_run: bool) -> DockerStackMoveExportArgs {
        DockerStackMoveExportArgs {
            stack: "s".into(),
            destination: dir.to_string_lossy().into_owned(),
            keep_running: false,
            dry_run,
        }
    }

    #[test]
    fn export_pins_by_digest_stops_and_writes_a_checksummed_bundle() {
        let root = tempfile::tempdir().unwrap();
        let e = source_engine();
        let (out, store) = with_secrets(BTreeMap::new(), || {
            block(export(
                &e.client(),
                &export_args(root.path(), false),
                &roots(root.path()),
            ))
            .unwrap()
        });
        assert!(out.executed);
        assert_eq!(out.stopped, ["s-cache-1"]);
        assert_eq!(out.containers[0].pinned, format!("redis@{A}"));
        assert_eq!(out.containers[0].secret_env, ["DB_PASSWORD"]);
        assert!(
            e.paths("POST")
                .iter()
                .any(|p| p.ends_with("/containers/s-cache-1/stop"))
        );
        let path = out.bundle.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let json = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&json).contains("hunter2"));
        assert_eq!(
            store
                .get("docker.move.s.s-cache-1.DB_PASSWORD")
                .map(String::as_str),
            Some("hunter2")
        );
        assert_eq!(
            out.bundle_sha256.unwrap(),
            plugin_toolkit::hash::sha256_hex(&json)
        );
        let bundle: MoveBundle = plugin_toolkit::serde_json::from_slice(&json).unwrap();
        let c = &bundle.containers[0];
        assert_eq!(c.create["Image"], format!("redis@{A}"));
        assert_eq!(c.create["Env"], json!(["MODE=fast"]));
        assert_eq!(c.secret_env[0].key, "DB_PASSWORD");
        assert_eq!(c.image, "redis:7");
        let n = &bundle.networks[0];
        assert_eq!(n.name, "s_default");
        assert!(n.internal);
        assert_eq!(n.options["com.docker.network.bridge.enable_icc"], "false");
        assert_eq!(
            bundle.volumes_manifest_sha256,
            plugin_toolkit::hash::sha256_hex(
                &std::fs::read(Path::new(&path).with_file_name(&bundle.volumes_manifest)).unwrap()
            )
        );
    }

    #[test]
    fn export_dry_run_writes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let e = source_engine();
        let out = block(export(
            &e.client(),
            &export_args(root.path(), true),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(!out.executed && out.bundle.is_none());
        assert_eq!(out.stopped, ["s-cache-1"]);
        assert_eq!(out.containers[0].secret_env, ["DB_PASSWORD"]);
        assert!(writes(&e).is_empty(), "{:?}", writes(&e));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_failed_export_reports_a_failed_source_restart() {
        let root = tempfile::tempdir().unwrap();
        let mut routes = vec![
            Route::new("GET", "/volumes", 500, r#"{"message":"boom"}"#),
            Route::new(
                "POST",
                "/containers/s-cache-1/start",
                500,
                r#"{"message":"no start"}"#,
            ),
        ];
        routes.extend(source_routes());
        let e = FakeEngine::routed(routes);
        let err = with_secrets(BTreeMap::new(), || {
            block(export(
                &e.client(),
                &export_args(root.path(), false),
                &roots(root.path()),
            ))
            .unwrap_err()
        })
        .0;
        assert!(
            format!("{err:#}").contains("source restart FAILED"),
            "{err:#}"
        );
        assert!(
            e.paths("POST")
                .iter()
                .any(|p| p.ends_with("/containers/s-cache-1/start"))
        );
    }

    #[test]
    fn bundle_dir_stays_within_the_roots() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let inside = root.path().canonicalize().unwrap().join("m.json");
        assert!(bundle_dir(&inside, &roots(root.path())).is_ok());
        let outside = other.path().canonicalize().unwrap().join("m.json");
        assert!(bundle_dir(&outside, &roots(root.path())).is_err());
    }

    fn spec_named(name: &str, host_config: Value) -> ContainerSpec {
        ContainerSpec {
            name: name.into(),
            service: "cache".into(),
            image: "redis:7".into(),
            pinned: format!("redis@{A}"),
            create: json!({
                "Image": format!("redis@{A}"),
                "Labels": { "com.docker.compose.project": "s" },
                "HostConfig": host_config
            }),
            secret_env: vec![],
        }
    }

    fn spec(host_config: Value) -> ContainerSpec {
        spec_named("s-cache-1", host_config)
    }

    fn write_bundle_at(dir: &Path, bundle: &MoveBundle) -> (String, String) {
        let json = plugin_toolkit::serde_json::to_vec(bundle).unwrap();
        let path = dir.join(BUNDLE_FILE);
        std::fs::write(&path, &json).unwrap();
        (
            path.to_string_lossy().into_owned(),
            plugin_toolkit::hash::sha256_hex(&json),
        )
    }

    fn bundle_of(volume_sha: Option<&str>, containers: Vec<ContainerSpec>) -> MoveBundle {
        MoveBundle {
            stack: "s".into(),
            containers,
            networks: vec![NetworkSpec {
                name: "s_default".into(),
                driver: "bridge".into(),
                labels: BTreeMap::new(),
                options: BTreeMap::new(),
                internal: true,
                attachable: false,
                enable_ipv6: false,
                ipam: None,
            }],
            volumes_manifest: "manifest.json".into(),
            volumes_manifest_sha256: volume_sha.map_or_else(
                || plugin_toolkit::hash::sha256_hex(br#"{"stack":"s","volumes":[]}"#),
                str::to_owned,
            ),
        }
    }

    /// A bundle dir holding an empty volume manifest; returns the bundle path
    /// and its sum.
    fn target_bundle(dir: &Path, volume_sha: Option<&str>, c: ContainerSpec) -> (String, String) {
        std::fs::write(dir.join("manifest.json"), br#"{"stack":"s","volumes":[]}"#).unwrap();
        write_bundle_at(dir, &bundle_of(volume_sha, vec![c]))
    }

    fn target_routes(health: &str) -> Vec<Route> {
        vec![
            Route::new(
                "GET",
                "/containers/s-cache-1/json",
                404,
                r#"{"message":"no such container"}"#,
            ),
            Route::new(
                "GET",
                "/containers/s-db-1/json",
                404,
                r#"{"message":"no such container"}"#,
            ),
            Route::new("POST", "/images/create", 200, r#"{"status":"ok"}"#),
            Route::new("POST", "/tag", 201, ""),
            Route::new(
                "GET",
                "/networks/s_default",
                404,
                r#"{"message":"no such network"}"#,
            ),
            Route::new(
                "POST",
                "/networks/create",
                201,
                r#"{"Id":"n1","Warning":""}"#,
            ),
            Route::new(
                "POST",
                "/containers/create",
                201,
                r#"{"Id":"new1","Warnings":[]}"#,
            ),
            Route::new("POST", "/containers/s-cache-1/start", 204, ""),
            Route::new("GET", "/containers/json", 200, r#"[{"Id":"new1"}]"#),
            Route::new(
                "GET",
                "/containers/new1/json",
                200,
                json!({
                    "Name": "/s-cache-1",
                    "State": { "Status": "running", "Health": { "Status": health } },
                    "Config": { "Labels": { "com.docker.compose.service": "cache" } }
                })
                .to_string(),
            ),
            Route::new("DELETE", "/containers/s-cache-1", 204, ""),
            Route::new("DELETE", "/containers/s-db-1", 204, ""),
            Route::new("DELETE", "/networks/s_default", 204, ""),
        ]
    }

    fn target_engine(health: &str) -> FakeEngine {
        FakeEngine::routed(target_routes(health))
    }

    fn import_args(bundle: &str, sha: &str, dry_run: bool) -> DockerStackMoveImportArgs {
        DockerStackMoveImportArgs {
            bundle: bundle.into(),
            bundle_sha256: sha.into(),
            timeout_secs: Some(1),
            dry_run,
        }
    }

    #[test]
    fn import_recreates_on_the_pinned_digest_without_privileges() {
        let root = tempfile::tempdir().unwrap();
        let mut c = spec(json!({ "CapAdd": null }));
        c.create["User"] = json!("999");
        c.secret_env.push(SecretEnv {
            key: "DB_PASSWORD".into(),
            secret: SecretRef("docker.move.s.s-cache-1.DB_PASSWORD".into()),
        });
        let (bundle, sha) = target_bundle(root.path(), None, c);
        let e = target_engine("healthy");
        let seed = BTreeMap::from([(
            "docker.move.s.s-cache-1.DB_PASSWORD".to_string(),
            "hunter2".to_string(),
        )]);
        let out = with_secrets(seed, || {
            block(import(
                &e.client(),
                &import_args(&bundle, &sha, false),
                &roots(root.path()),
            ))
            .unwrap()
        })
        .0;
        assert!(out.executed && !out.rolled_back);
        assert!(out.health.unwrap().ready);
        assert_eq!(out.networks_created, ["s_default"]);
        assert_eq!(out.users, ["s-cache-1: 999"]);
        assert!(
            e.targets("POST").iter().any(
                |t| t.contains("/images/create") && t.contains(&format!("fromImage=redis@{A}"))
            )
        );
        assert!(e.bodies("/networks/create")[0].contains("\"Internal\":true"));
        let creates = e.bodies("/containers/create");
        assert_eq!(creates.len(), 1);
        let body: Value = plugin_toolkit::serde_json::from_str(&creates[0]).unwrap();
        assert_eq!(body["Image"], format!("redis@{A}"));
        assert_eq!(body["Env"], json!(["DB_PASSWORD=hunter2"]));
        assert_eq!(body["HostConfig"]["CapDrop"], json!(["ALL"]));
        assert_eq!(
            body["HostConfig"]["SecurityOpt"],
            json!(["no-new-privileges:true"])
        );
        assert!(e.paths("DELETE").is_empty());
    }

    #[test]
    fn import_refuses_a_missing_secret() {
        let root = tempfile::tempdir().unwrap();
        let mut c = spec(json!({}));
        c.secret_env.push(SecretEnv {
            key: "DB_PASSWORD".into(),
            secret: SecretRef("docker.move.s.s-cache-1.DB_PASSWORD".into()),
        });
        let (bundle, sha) = target_bundle(root.path(), None, c);
        let e = target_engine("healthy");
        let err = with_secrets(BTreeMap::new(), || {
            block(import(
                &e.client(),
                &import_args(&bundle, &sha, true),
                &roots(root.path()),
            ))
            .unwrap_err()
        })
        .0;
        assert!(format!("{err:#}").contains("no secret"), "{err:#}");
        assert!(e.requests().is_empty());
    }

    #[test]
    fn an_unhealthy_target_is_rolled_back() {
        let root = tempfile::tempdir().unwrap();
        let (bundle, sha) = target_bundle(root.path(), None, spec(json!({})));
        let e = target_engine("unhealthy");
        let out = block(import(
            &e.client(),
            &import_args(&bundle, &sha, false),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(out.rolled_back);
        assert!(out.rollback_failures.is_empty());
        assert!(!out.health.unwrap().ready);
        let deletes = e.paths("DELETE");
        assert!(deletes.iter().any(|p| p.ends_with("/containers/s-cache-1")));
        assert!(deletes.iter().any(|p| p.ends_with("/networks/s_default")));
        assert!(e.targets("DELETE").iter().all(|t| !t.contains("v=true")));
    }

    #[test]
    fn a_failed_health_wait_is_rolled_back() {
        let root = tempfile::tempdir().unwrap();
        let (bundle, sha) = target_bundle(root.path(), None, spec(json!({})));
        let mut routes = vec![Route::new(
            "GET",
            "/containers/json",
            500,
            r#"{"message":"boom"}"#,
        )];
        routes.extend(target_routes("healthy"));
        let e = FakeEngine::routed(routes);
        let err = block(import(
            &e.client(),
            &import_args(&bundle, &sha, false),
            &roots(root.path()),
        ))
        .unwrap_err();
        assert!(format!("{err:#}").contains("removed"), "{err:#}");
        let deletes = e.paths("DELETE");
        assert!(deletes.iter().any(|p| p.ends_with("/containers/s-cache-1")));
        assert!(deletes.iter().any(|p| p.ends_with("/networks/s_default")));
    }

    #[test]
    fn a_mid_list_create_failure_removes_only_what_was_created() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("manifest.json"),
            br#"{"stack":"s","volumes":[]}"#,
        )
        .unwrap();
        let (bundle, sha) = write_bundle_at(
            root.path(),
            &bundle_of(None, vec![spec(json!({})), spec_named("s-db-1", json!({}))]),
        );
        let mut routes = vec![
            Route::new("POST", "/containers/create", 500, r#"{"message":"no"}"#)
                .when_query("name=s-db-1"),
        ];
        routes.extend(target_routes("healthy"));
        let e = FakeEngine::routed(routes);
        let err = block(import(
            &e.client(),
            &import_args(&bundle, &sha, false),
            &roots(root.path()),
        ))
        .unwrap_err();
        assert!(format!("{err:#}").contains("create s-db-1"), "{err:#}");
        let deletes = e.paths("DELETE");
        assert!(deletes.iter().any(|p| p.ends_with("/containers/s-cache-1")));
        assert!(!deletes.iter().any(|p| p.ends_with("/containers/s-db-1")));
        assert!(deletes.iter().any(|p| p.ends_with("/networks/s_default")));
        assert!(e.paths("POST").iter().all(|p| !p.ends_with("/start")));
    }

    #[test]
    fn a_checksum_mismatch_aborts_before_any_write() {
        let root = tempfile::tempdir().unwrap();
        let (bundle, _) = target_bundle(root.path(), None, spec(json!({})));
        let e = target_engine("healthy");
        let err = block(import(
            &e.client(),
            &import_args(&bundle, &"0".repeat(64), false),
            &roots(root.path()),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("bundle: sha256"), "{err}");

        let (bundle, sha) = target_bundle(root.path(), Some(&"0".repeat(64)), spec(json!({})));
        let err = block(import(
            &e.client(),
            &import_args(&bundle, &sha, false),
            &roots(root.path()),
        ))
        .unwrap_err();
        assert!(format!("{err:#}").contains("manifest: sha256"), "{err:#}");
        assert!(writes(&e).is_empty(), "{:?}", writes(&e));
    }

    #[test]
    fn an_archive_mismatch_aborts_the_move_before_any_write() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("s_cache.tar"), b"not the archive").unwrap();
        let manifest = json!({
            "stack": "s",
            "volumes": [{
                "name": "s_cache",
                "key": "cache",
                "driver": "local",
                "labels": {},
                "options": {},
                "kind": "data",
                "archive": "s_cache.tar",
                "sha256": "0".repeat(64),
                "size": 15
            }]
        })
        .to_string();
        std::fs::write(root.path().join("manifest.json"), &manifest).unwrap();
        let (bundle, sha) = write_bundle_at(
            root.path(),
            &bundle_of(
                Some(&plugin_toolkit::hash::sha256_hex(manifest.as_bytes())),
                vec![spec(json!({}))],
            ),
        );
        let e = target_engine("healthy");
        let err = block(import(
            &e.client(),
            &import_args(&bundle, &sha, false),
            &roots(root.path()),
        ))
        .unwrap_err();
        assert!(format!("{err:#}").contains("sha256"), "{err:#}");
        assert!(writes(&e).is_empty(), "{:?}", writes(&e));
    }

    #[test]
    fn import_refuses_an_external_volume() {
        let root = tempfile::tempdir().unwrap();
        let manifest = json!({
            "stack": "s",
            "volumes": [{
                "name": "s_nfs",
                "driver": "local",
                "labels": {},
                "options": { "type": "nfs" },
                "kind": "external"
            }]
        })
        .to_string();
        std::fs::write(root.path().join("manifest.json"), &manifest).unwrap();
        let (bundle, sha) = write_bundle_at(
            root.path(),
            &bundle_of(
                Some(&plugin_toolkit::hash::sha256_hex(manifest.as_bytes())),
                vec![spec(json!({}))],
            ),
        );
        let e = target_engine("healthy");
        let err = block(import(
            &e.client(),
            &import_args(&bundle, &sha, false),
            &roots(root.path()),
        ))
        .unwrap_err();
        assert!(format!("{err:#}").contains("option 'type'"), "{err:#}");
        assert!(writes(&e).is_empty(), "{:?}", writes(&e));
    }

    #[test]
    fn a_bundle_outside_the_roots_or_through_a_symlink_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let (real, sha) = target_bundle(other.path(), None, spec(json!({})));
        let e = target_engine("healthy");
        let traversal = format!(
            "{}/../{}/{BUNDLE_FILE}",
            root.path().display(),
            other.path().file_name().unwrap().to_string_lossy()
        );
        let link = root.path().join("link.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        for path in [real.clone(), traversal, link.to_string_lossy().into_owned()] {
            assert!(
                block(import(
                    &e.client(),
                    &import_args(&path, &sha, true),
                    &roots(root.path()),
                ))
                .is_err(),
                "{path}"
            );
        }
        let mut b = bundle_of(None, vec![spec(json!({}))]);
        b.volumes_manifest = "../manifest.json".into();
        let (path, sha) = write_bundle_at(root.path(), &b);
        let err = block(import(
            &e.client(),
            &import_args(&path, &sha, true),
            &roots(root.path()),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("outside its dir"), "{err}");
        assert!(e.requests().is_empty());
    }

    #[test]
    fn import_refuses_a_retarget() {
        let root = tempfile::tempdir().unwrap();
        let mut c = spec(json!({}));
        c.create["Labels"]["com.docker.compose.project"] = json!("other");
        let (bundle, sha) = target_bundle(root.path(), None, c);
        let e = target_engine("healthy");
        let err = block(import(
            &e.client(),
            &import_args(&bundle, &sha, false),
            &roots(root.path()),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("retarget"), "{err}");
        assert!(e.requests().is_empty());
    }

    #[test]
    fn import_dry_run_writes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let (bundle, sha) = target_bundle(root.path(), None, spec(json!({})));
        let e = target_engine("healthy");
        let out = block(import(
            &e.client(),
            &import_args(&bundle, &sha, true),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(!out.executed);
        assert_eq!(out.pulled, [format!("redis:7=redis@{A}")]);
        assert_eq!(out.containers, ["s-cache-1"]);
        assert!(writes(&e).is_empty(), "{:?}", writes(&e));
    }

    fn refused(host: Value) -> String {
        let h: HostConfig = plugin_toolkit::serde_json::from_value(host).unwrap();
        rebuild_host_config("c", &h).unwrap_err().to_string()
    }

    #[test]
    fn rebuild_refuses_every_host_reaching_field() {
        for (host, want) in [
            (json!({ "Privileged": true }), "Privileged"),
            (json!({ "Binds": ["/etc:/x"] }), "Binds /etc:/x"),
            (json!({ "Binds": ["~/x:/x"] }), "Binds ~/x:/x"),
            (json!({ "Binds": ["vol:/x:shared"] }), "Binds vol:/x:shared"),
            (
                json!({ "Mounts": [{ "Type": "bind", "Source": "/etc", "Target": "/x" }] }),
                "Mounts bind",
            ),
            (
                json!({ "Mounts": [{ "Type": "volume", "Source": "v", "Target": "/x",
                    "VolumeOptions": { "DriverConfig": { "Name": "nfs" } } }] }),
                "Mounts volume v",
            ),
            (
                json!({ "Mounts": [{ "Type": "tmpfs", "Target": "/x",
                    "TmpfsOptions": { "Options": [["exec"]] } }] }),
                "Mounts tmpfs exec",
            ),
            (
                json!({ "Mounts": [{ "Type": "tmpfs", "Target": "/x",
                    "TmpfsOptions": { "Options": [["suid"]] } }] }),
                "Mounts tmpfs suid",
            ),
            (json!({ "NetworkMode": "host" }), "NetworkMode host"),
            (
                json!({ "NetworkMode": "container:abc" }),
                "NetworkMode container:abc",
            ),
            (json!({ "PidMode": "host" }), "PidMode"),
            (json!({ "PidMode": "container:abc" }), "PidMode"),
            (json!({ "IpcMode": "host" }), "IpcMode"),
            (json!({ "IpcMode": "container:abc" }), "IpcMode"),
            (json!({ "UTSMode": "host" }), "UTSMode"),
            (json!({ "UsernsMode": "host" }), "UsernsMode"),
            (json!({ "CgroupnsMode": "host" }), "CgroupnsMode"),
            (
                json!({ "SecurityOpt": ["seccomp=unconfined"] }),
                "SecurityOpt",
            ),
            (
                json!({ "SecurityOpt": ["apparmor=unconfined"] }),
                "SecurityOpt",
            ),
            (json!({ "SecurityOpt": ["label=disable"] }), "SecurityOpt"),
            (
                json!({ "SecurityOpt": ["systempaths=unconfined"] }),
                "SecurityOpt",
            ),
            (json!({ "CapAdd": ["SYS_ADMIN"] }), "CapAdd"),
            (
                json!({ "Devices": [{ "PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda" }] }),
                "Devices",
            ),
            (
                json!({ "DeviceRequests": [{ "Driver": "nvidia", "Count": -1 }] }),
                "DeviceRequests",
            ),
            (
                json!({ "DeviceCgroupRules": ["c 1:3 mr"] }),
                "DeviceCgroupRules",
            ),
            (json!({ "CgroupParent": "/x" }), "CgroupParent"),
            (json!({ "Runtime": "kata" }), "Runtime"),
            (
                json!({ "Sysctls": { "net.ipv4.ip_forward": "1" } }),
                "Sysctls",
            ),
            (json!({ "VolumesFrom": ["other"] }), "VolumesFrom"),
            (json!({ "VolumeDriver": "nfs" }), "VolumeDriver"),
            (json!({ "MaskedPaths": [] }), "MaskedPaths empty"),
            (json!({ "ReadonlyPaths": [] }), "ReadonlyPaths empty"),
        ] {
            let err = refused(host.clone());
            assert!(err.contains(want), "{host}: {err}");
        }
    }

    #[test]
    fn rebuild_keeps_the_allowlist_and_drops_every_capability() {
        let h: HostConfig = plugin_toolkit::serde_json::from_value(json!({
            "RestartPolicy": { "Name": "unless-stopped" },
            "PortBindings": { "80/tcp": [{ "HostPort": "8080" }] },
            "Binds": ["s_cache:/data:ro"],
            "Mounts": [
                { "Type": "volume", "Source": "s_db", "Target": "/db" },
                { "Type": "tmpfs", "Target": "/tmp", "TmpfsOptions": { "Options": [["noexec"]] } }
            ],
            "Memory": 1024,
            "NanoCpus": 1000,
            "LogConfig": { "Type": "json-file" },
            "ExtraHosts": ["a:10.0.0.1"],
            "NetworkMode": "s_default",
            "IpcMode": "private",
            "CapDrop": ["NET_RAW"],
            "SecurityOpt": ["no-new-privileges"],
            "MaskedPaths": ["/proc/kcore"]
        }))
        .unwrap();
        let out =
            plugin_toolkit::serde_json::to_value(rebuild_host_config("c", &h).unwrap()).unwrap();
        assert_eq!(out["CapDrop"], json!(["ALL"]));
        assert_eq!(out["SecurityOpt"], json!(["no-new-privileges:true"]));
        assert_eq!(out["Binds"], json!(["s_cache:/data:ro"]));
        assert_eq!(out["Memory"], 1024);
        assert_eq!(out["ExtraHosts"], json!(["a:10.0.0.1"]));
        assert!(out.get("IpcMode").is_none() && out.get("MaskedPaths").is_none());
    }

    #[test]
    fn bind_sources_parse_strictly() {
        assert_eq!(bind_volume("data:/x"), Some("data"));
        assert_eq!(bind_volume("data:/x:ro,nocopy"), Some("data"));
        for b in [
            "/etc:/x",
            "~/d:/x",
            "./d:/x",
            "data",
            "data:x",
            "data:/x:ro:z",
            "data:/x:rshared",
        ] {
            assert_eq!(bind_volume(b), None, "{b}");
        }
    }

    fn finish_args(action: FinishAction, dry_run: bool) -> DockerStackMoveFinishArgs {
        DockerStackMoveFinishArgs {
            stack: "s".into(),
            action: Some(action),
            bundle: None,
            bundle_sha256: None,
            dry_run,
        }
    }

    #[test]
    fn finish_restart_is_the_rollback_and_dry_run_writes_nothing() {
        let e = source_engine();
        let r = roots(Path::new("/nonexistent"));
        let out = block(finish(
            &e.client(),
            &finish_args(FinishAction::Restart, true),
            &r,
        ))
        .unwrap();
        assert_eq!(out.containers, ["s-cache-1"]);
        assert!(writes(&e).is_empty());
        let out = block(finish(
            &e.client(),
            &finish_args(FinishAction::Restart, false),
            &r,
        ))
        .unwrap();
        assert!(out.executed && out.failures.is_empty());
        assert!(
            e.paths("POST")
                .iter()
                .any(|p| p.ends_with("/containers/s-cache-1/start"))
        );
    }

    #[test]
    fn finish_remove_is_bound_to_the_move() {
        let root = tempfile::tempdir().unwrap();
        let mut routes = vec![Route::new("DELETE", "/containers/s-cache-1", 204, "")];
        routes.extend(source_routes());
        let e = FakeEngine::routed(routes);
        let r = roots(root.path());
        let err = block(finish(
            &e.client(),
            &finish_args(FinishAction::Remove, false),
            &r,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("bundleSha256"), "{err}");

        let (bundle, sha) = target_bundle(root.path(), None, spec_named("s-other-1", json!({})));
        let mut args = finish_args(FinishAction::Remove, false);
        args.bundle = Some(bundle);
        args.bundle_sha256 = Some(sha);
        let err = block(finish(&e.client(), &args, &r)).unwrap_err();
        assert!(err.to_string().contains("not in the move"), "{err}");
        args.bundle_sha256 = Some("0".repeat(64));
        assert!(block(finish(&e.client(), &args, &r)).is_err());
        assert!(writes(&e).is_empty(), "{:?}", writes(&e));

        let (bundle, sha) = target_bundle(root.path(), None, spec(json!({})));
        args.bundle = Some(bundle);
        args.bundle_sha256 = Some(sha);
        let out = block(finish(&e.client(), &args, &r)).unwrap();
        assert!(out.failures.is_empty(), "{:?}", out.failures);
        assert!(
            e.paths("DELETE")
                .iter()
                .any(|p| p.ends_with("/containers/s-cache-1"))
        );
    }

    #[test]
    fn refuses_a_non_admin_caller() {
        for ctx in crate::test_support::non_admins() {
            let err = block(docker_stack_move_finish(
                finish_args(FinishAction::Stop, true),
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
            let err =
                block(docker_stack_move_import(import_args("/x", "0", true), &ctx)).unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
            let err = block(docker_stack_move_export(
                export_args(Path::new("/x"), true),
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
        }
    }
}
