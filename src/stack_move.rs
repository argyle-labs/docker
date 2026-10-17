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
    ContainerCreateBody, ContainerInspectResponse, EndpointSettings, HostConfig,
    NetworkCreateRequest, NetworkingConfig,
};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, InspectContainerOptionsBuilder, InspectNetworkOptions,
    RemoveContainerOptionsBuilder, StartContainerOptions, StopContainerOptions,
};
use plugin_toolkit::prelude::*;

use crate::engine_state;
use crate::lifecycle::open_archive;
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
#[serde(rename_all = "camelCase")]
pub struct ContainerSpec {
    pub name: String,
    pub service: String,
    pub image: String,
    pub pinned: String,
    pub create: plugin_toolkit::serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
#[serde(rename_all = "camelCase")]
pub struct NetworkSpec {
    pub name: String,
    pub driver: String,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// What the target refuses to recreate from a bundle: anything that widens
/// the container's reach onto the host.
fn host_reach(name: &str, h: &HostConfig) -> Option<String> {
    let host = |m: &Option<String>| m.as_deref() == Some("host");
    let mut why = Vec::new();
    if h.privileged == Some(true) {
        why.push("privileged".to_owned());
    }
    if h.cap_add.as_ref().is_some_and(|c| !c.is_empty()) {
        why.push("cap_add".to_owned());
    }
    if h.devices.as_ref().is_some_and(|d| !d.is_empty()) {
        why.push("devices".to_owned());
    }
    if host(&h.network_mode) || host(&h.pid_mode) || host(&h.ipc_mode) || host(&h.userns_mode) {
        why.push("host namespace".to_owned());
    }
    if h.binds
        .iter()
        .flatten()
        .any(|b| b.starts_with('/') || b.starts_with('.'))
    {
        why.push("host bind mount".to_owned());
    }
    (!why.is_empty()).then(|| format!("{name}: {}", why.join(", ")))
}

pub fn spec_of(c: &ContainerInspectResponse, pinned: &str) -> Result<ContainerSpec> {
    let meta = stack_manifest::StackContainer::from_inspect(c);
    let mut create: ContainerCreateBody = match &c.config {
        Some(cfg) => {
            plugin_toolkit::serde_json::from_value(plugin_toolkit::serde_json::to_value(cfg)?)?
        }
        None => ContainerCreateBody::default(),
    };
    create.image = Some(pinned.to_owned());
    create.host_config = c.host_config.clone();
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
    Ok(ContainerSpec {
        name: meta.name,
        service: meta.service,
        image: meta.reference,
        pinned: pinned.to_owned(),
        create: plugin_toolkit::serde_json::to_value(&create)?,
    })
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

async fn source_plan(
    docker: &Docker,
    stack: &str,
) -> Result<(Vec<ContainerSpec>, Vec<NetworkSpec>, Vec<String>)> {
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
        specs.push(spec_of(c, pinned)?);
    }
    specs.sort_by(|a, b| a.name.cmp(&b.name));
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
        networks.push(NetworkSpec {
            name: name.clone(),
            driver: n.driver.unwrap_or_else(|| "bridge".into()),
            labels: n.labels.unwrap_or_default().into_iter().collect(),
        });
    }
    Ok((specs, networks, running))
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
    let json = plugin_toolkit::serde_json::to_vec_pretty(bundle)?;
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

pub async fn export(
    docker: &Docker,
    args: &DockerStackMoveExportArgs,
    roots: &[String],
) -> Result<StackMoveExportOutput> {
    let (specs, networks, running) = source_plan(docker, &args.stack).await?;
    let stopping = if args.keep_running {
        Vec::new()
    } else {
        running.clone()
    };
    let mut out = StackMoveExportOutput {
        executed: !args.dry_run,
        stack: args.stack.clone(),
        containers: specs
            .iter()
            .map(|s| PlannedContainer {
                name: s.name.clone(),
                service: s.service.clone(),
                pinned: s.pinned.clone(),
                running: running.contains(&s.name),
            })
            .collect(),
        networks: networks.iter().map(|n| n.name.clone()).collect(),
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
    let mut stopped = Vec::new();
    for n in &stopping {
        if let Err(e) = stop(docker, n).await {
            let failed = restart_all(docker, &stopped).await;
            return Err(rollback_context(e, &failed));
        }
        stopped.push(n.clone());
    }
    let exported = match stack_volumes::export(docker, &volume_args, roots).await {
        Ok(v) if v.complete => v,
        Ok(v) => {
            let problems: Vec<String> = v
                .volumes
                .iter()
                .filter_map(|e| e.problem.as_ref().map(|p| format!("{}: {p}", e.name)))
                .collect();
            let failed = restart_all(docker, &stopped).await;
            return Err(rollback_context(
                anyhow!("volume export incomplete: {}", problems.join("; ")),
                &failed,
            ));
        }
        Err(e) => {
            let failed = restart_all(docker, &stopped).await;
            return Err(rollback_context(e, &failed));
        }
    };
    let manifest = PathBuf::from(exported.manifest.clone().unwrap_or_default());
    let (Some(dir), Some(file), Some(sha)) = (
        manifest.parent(),
        manifest.file_name(),
        exported.manifest_sha256.clone(),
    ) else {
        let failed = restart_all(docker, &stopped).await;
        return Err(rollback_context(
            anyhow!("volume export wrote no manifest"),
            &failed,
        ));
    };
    let bundle = MoveBundle {
        stack: args.stack.clone(),
        containers: specs,
        networks,
        volumes_manifest: file.to_string_lossy().into_owned(),
        volumes_manifest_sha256: sha,
    };
    let (path, sha) = match write_bundle(dir, &bundle) {
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
/// named volumes with sha256 sums, and writes `move.json` (container specs on
/// the pinned images, networks, the volume manifest's sum) beside them. A
/// stop or export failure restarts what was stopped. Refused when an image
/// cannot be pinned.
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
    let bundle: MoveBundle = plugin_toolkit::serde_json::from_slice(&data)
        .map_err(|e| anyhow!("bundle '{path}': {e}"))?;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<StackHealth>,
    /// The stack did not come up healthy and its containers were removed;
    /// restart the source with `docker.stack_move_finish`.
    pub rolled_back: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rollback_failures: Vec<String>,
}

async fn create_networks(docker: &Docker, networks: &[NetworkSpec]) -> Result<Vec<String>> {
    let mut created = Vec::new();
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
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow!("create network {}: {e}", n.name))?;
        created.push(n.name.clone());
    }
    Ok(created)
}

async fn create_and_start(docker: &Docker, spec: &ContainerSpec) -> Result<()> {
    let mut body: ContainerCreateBody = plugin_toolkit::serde_json::from_value(spec.create.clone())
        .map_err(|e| anyhow!("spec of {}: {e}", spec.name))?;
    body.image = Some(spec.pinned.clone());
    let opts = CreateContainerOptionsBuilder::new()
        .name(&spec.name)
        .build();
    docker
        .create_container(Some(opts), body)
        .await
        .map_err(|e| anyhow!("create {}: {e}", spec.name))?;
    start(docker, &spec.name).await
}

async fn remove_all(docker: &Docker, names: &[String]) -> Vec<String> {
    let mut failed = Vec::new();
    for n in names {
        if let Err(e) = remove(docker, n).await {
            failed.push(format!("{e:#}"));
        }
    }
    failed
}

pub async fn import(
    docker: &Docker,
    args: &DockerStackMoveImportArgs,
    roots: &[String],
) -> Result<StackMoveImportOutput> {
    let (bundle, dir) = load_bundle(&args.bundle, &args.bundle_sha256, roots)?;
    for c in &bundle.containers {
        let create: ContainerCreateBody = plugin_toolkit::serde_json::from_value(c.create.clone())
            .map_err(|e| anyhow!("spec of {}: {e}", c.name))?;
        if let Some(why) = create
            .host_config
            .as_ref()
            .and_then(|h| host_reach(&c.name, h))
        {
            bail!("refusing to recreate a container with host reach: {why}");
        }
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
        bail!("volume import incomplete: {}", f.join("; "));
    }
    let pulled = stack_pull::apply(docker, &pins).await;
    if !pulled.findings.is_empty() {
        let f: Vec<String> = pulled
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.image, f.message))
            .collect();
        bail!("pinned pull failed: {}", f.join("; "));
    }
    out.pulled = pulled.pulled;
    out.networks_created = create_networks(docker, &bundle.networks).await?;
    let mut created = Vec::new();
    for c in &bundle.containers {
        let result = create_and_start(docker, c).await;
        created.push(c.name.clone());
        if let Err(e) = result {
            let failed = remove_all(docker, &created).await;
            return Err(if failed.is_empty() {
                e.context("created containers removed")
            } else {
                e.context(format!(
                    "removing created containers FAILED: {}",
                    failed.join("; ")
                ))
            });
        }
    }
    let health =
        stack_health::wait(docker, &bundle.stack, health_timeout(args.timeout_secs)).await?;
    if !health.ready {
        out.rollback_failures = remove_all(docker, &created).await;
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
/// volume is created), pulls each image by its pinned digest, creates the
/// stack's networks and recreates its containers on the pinned images, then
/// waits until they are healthy. A stack that is not healthy in time has its
/// containers removed (`rolledBack`); restore the source with
/// `docker.stack_move_finish` `restart`. Refused when one of its containers
/// already exists here or a container would reach onto the host.
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
    /// Stop and remove the source containers; volumes stay.
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

pub async fn finish(
    docker: &Docker,
    args: &DockerStackMoveFinishArgs,
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
        FinishAction::Remove => remove_all(docker, &names).await,
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
/// `stop` the stack or `remove` its containers (volumes stay); when the
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
    finish(docker, &args).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};
    use plugin_toolkit::serde_json::json;

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

    fn source_engine() -> FakeEngine {
        FakeEngine::routed(vec![
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
                        "Labels": {
                            "com.docker.compose.project": "s",
                            "com.docker.compose.service": "cache"
                        }
                    },
                    "HostConfig": { "NetworkMode": "s_default" },
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
                r#"{"Name":"s_default","Driver":"bridge","Labels":{"com.docker.compose.project":"s"}}"#,
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
        ])
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
        let out = block(export(
            &e.client(),
            &export_args(root.path(), false),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(out.executed);
        assert_eq!(out.stopped, ["s-cache-1"]);
        assert_eq!(out.containers[0].pinned, format!("redis@{A}"));
        assert!(
            e.paths("POST")
                .iter()
                .any(|p| p.ends_with("/containers/s-cache-1/stop"))
        );
        let path = out.bundle.unwrap();
        let json = std::fs::read(&path).unwrap();
        assert_eq!(
            out.bundle_sha256.unwrap(),
            plugin_toolkit::hash::sha256_hex(&json)
        );
        let bundle: MoveBundle = plugin_toolkit::serde_json::from_slice(&json).unwrap();
        assert_eq!(bundle.containers[0].create["Image"], format!("redis@{A}"));
        assert_eq!(bundle.containers[0].image, "redis:7");
        assert_eq!(bundle.networks[0].name, "s_default");
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
        assert!(writes(&e).is_empty(), "{:?}", writes(&e));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    fn spec(host_config: plugin_toolkit::serde_json::Value) -> ContainerSpec {
        ContainerSpec {
            name: "s-cache-1".into(),
            service: "cache".into(),
            image: "redis:7".into(),
            pinned: format!("redis@{A}"),
            create: json!({
                "Image": format!("redis@{A}"),
                "Labels": { "com.docker.compose.project": "s" },
                "HostConfig": host_config
            }),
        }
    }

    /// A bundle dir holding an empty volume manifest; returns the bundle path
    /// and its sum.
    fn target_bundle(dir: &Path, volume_sha: Option<&str>, c: ContainerSpec) -> (String, String) {
        let manifest = br#"{"stack":"s","volumes":[]}"#;
        std::fs::write(dir.join("manifest.json"), manifest).unwrap();
        let bundle = MoveBundle {
            stack: "s".into(),
            containers: vec![c],
            networks: vec![NetworkSpec {
                name: "s_default".into(),
                driver: "bridge".into(),
                labels: BTreeMap::new(),
            }],
            volumes_manifest: "manifest.json".into(),
            volumes_manifest_sha256: volume_sha
                .map_or_else(|| plugin_toolkit::hash::sha256_hex(manifest), str::to_owned),
        };
        let json = plugin_toolkit::serde_json::to_vec(&bundle).unwrap();
        let path = dir.join(BUNDLE_FILE);
        std::fs::write(&path, &json).unwrap();
        (
            path.to_string_lossy().into_owned(),
            plugin_toolkit::hash::sha256_hex(&json),
        )
    }

    fn target_engine(health: &str) -> FakeEngine {
        FakeEngine::routed(vec![
            Route::new(
                "GET",
                "/containers/s-cache-1/json",
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
        ])
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
    fn import_recreates_on_the_pinned_digest() {
        let root = tempfile::tempdir().unwrap();
        let (bundle, sha) = target_bundle(root.path(), None, spec(json!({})));
        let e = target_engine("healthy");
        let out = block(import(
            &e.client(),
            &import_args(&bundle, &sha, false),
            &roots(root.path()),
        ))
        .unwrap();
        assert!(out.executed && !out.rolled_back);
        assert!(out.health.unwrap().ready);
        assert_eq!(out.networks_created, ["s_default"]);
        assert!(
            e.targets("POST").iter().any(
                |t| t.contains("/images/create") && t.contains(&format!("fromImage=redis@{A}"))
            )
        );
        let creates = e.bodies("/containers/create");
        assert_eq!(creates.len(), 1);
        assert!(
            creates[0].contains(&format!("\"Image\":\"redis@{A}\"")),
            "{}",
            creates[0]
        );
        assert!(e.paths("DELETE").is_empty());
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
        assert!(
            e.paths("DELETE")
                .iter()
                .any(|p| p.ends_with("/containers/s-cache-1"))
        );
        assert!(e.targets("DELETE").iter().all(|t| t.contains("v=false")));
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

    #[test]
    fn import_refuses_a_container_with_host_reach() {
        let root = tempfile::tempdir().unwrap();
        let (bundle, sha) = target_bundle(
            root.path(),
            None,
            spec(json!({ "Privileged": true, "Binds": ["/etc:/x"] })),
        );
        let e = target_engine("healthy");
        let err = block(import(
            &e.client(),
            &import_args(&bundle, &sha, false),
            &roots(root.path()),
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("privileged, host bind mount"),
            "{err}"
        );
        assert!(e.requests().is_empty());
    }

    #[test]
    fn finish_restart_is_the_rollback_and_dry_run_writes_nothing() {
        let e = source_engine();
        let args = |dry_run| DockerStackMoveFinishArgs {
            stack: "s".into(),
            action: Some(FinishAction::Restart),
            dry_run,
        };
        let out = block(finish(&e.client(), &args(true))).unwrap();
        assert_eq!(out.containers, ["s-cache-1"]);
        assert!(writes(&e).is_empty());
        let out = block(finish(&e.client(), &args(false))).unwrap();
        assert!(out.executed && out.failures.is_empty());
        assert!(
            e.paths("POST")
                .iter()
                .any(|p| p.ends_with("/containers/s-cache-1/start"))
        );
    }

    #[test]
    fn refuses_a_non_admin_caller() {
        for ctx in crate::test_support::non_admins() {
            let err = block(docker_stack_move_finish(
                DockerStackMoveFinishArgs {
                    stack: "s".into(),
                    action: Some(FinishAction::Stop),
                    dry_run: true,
                },
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
