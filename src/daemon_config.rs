#![allow(clippy::disallowed_types)]

use std::path::{Path, PathBuf};

use plugin_toolkit::prelude::*;
use plugin_toolkit::process::Command;
use plugin_toolkit::serde_json::{Map, Value};

use crate::execute;
use crate::init::{self, Init};

const TOOL: &str = "docker.daemon_config";
const UPDATE_TOOL: &str = "docker.daemon_config_update";
const DAEMON_JSON: &str = "etc/docker/daemon.json";
const UNRAID_VERSION: &str = "etc/unraid-version";
const UNRAID_CFG: &str = "boot/config/docker.cfg";
const UNRAID_RC: &str = "etc/rc.d/rc.docker";
const OPTS_KEY: &str = "DOCKER_OPTS";
const MIRRORS: &str = "registry-mirrors";
const INSECURE: &str = "insecure-registries";
const MIRROR_FLAG: &str = "--registry-mirror";
const INSECURE_FLAG: &str = "--insecure-registry";
const MANAGED: [&str; 2] = [MIRRORS, INSECURE];
const DOCKERD: [&str; 3] = [
    "/usr/bin/dockerd",
    "/usr/local/bin/dockerd",
    "/usr/sbin/dockerd",
];
const MACOS: &str = "unsupported on macOS: the engine runs inside the colima VM, whose daemon config is edited with `colima start --edit` (the `docker:` section)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    Unraid,
    Standard(Init),
}

impl Host {
    pub fn as_str(self) -> &'static str {
        match self {
            Host::Unraid => "unraid",
            Host::Standard(i) => i.as_str(),
        }
    }
}

pub fn detect(root: &Path) -> Host {
    if root.join(UNRAID_VERSION).is_file() {
        Host::Unraid
    } else {
        Host::Standard(init::detect(root))
    }
}

fn refuse_macos(tool: &str) -> Result<()> {
    if cfg!(target_os = "macos") {
        bail!("{tool}: {MACOS}");
    }
    Ok(())
}

pub fn read_json(root: &Path) -> Result<Map<String, Value>> {
    let path = root.join(DAEMON_JSON);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(e) => return Err(e).with_context(|| format!("failed to read '/{DAEMON_JSON}'")),
    };
    if text.trim().is_empty() {
        return Ok(Map::new());
    }
    match plugin_toolkit::serde_json::from_str(&text)
        .with_context(|| format!("'/{DAEMON_JSON}' is not valid JSON"))?
    {
        Value::Object(m) => Ok(m),
        _ => bail!("'/{DAEMON_JSON}' is not a JSON object"),
    }
}

pub fn deep_merge(base: &mut Value, patch: &Value) {
    match (base, patch) {
        (Value::Object(b), Value::Object(p)) => {
            for (k, v) in p {
                match b.get_mut(k) {
                    Some(existing) => deep_merge(existing, v),
                    None => {
                        b.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (b, p) => *b = p.clone(),
    }
}

#[orca_struct]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DaemonConfigPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_mirrors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure_registries: Option<Vec<String>>,
}

impl DaemonConfigPatch {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        if let Some(v) = &self.registry_mirrors {
            m.insert(MIRRORS.into(), v.clone().into());
        }
        if let Some(v) = &self.insecure_registries {
            m.insert(INSECURE.into(), v.clone().into());
        }
        Value::Object(m)
    }

    pub fn is_empty(&self) -> bool {
        self.registry_mirrors.is_none() && self.insecure_registries.is_none()
    }
}

fn strings(config: &Map<String, Value>, key: &str) -> Result<Vec<String>> {
    match config.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("'{key}' must hold only strings"))
            })
            .collect(),
        Some(_) => bail!("'{key}' must be an array of strings"),
    }
}

fn plain(value: &str) -> bool {
    !value.is_empty()
        && !value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '\'' || c == '\\')
}

pub fn mirror_authority(url: &str) -> Result<(&str, &str)> {
    if !plain(url) {
        bail!(
            "mirror '{}' holds whitespace, quotes or control characters",
            url.escape_debug()
        );
    }
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| anyhow!("mirror '{url}' is not a URL"))?;
    if scheme != "http" && scheme != "https" {
        bail!("mirror '{url}' must be http or https");
    }
    if rest.contains(['?', '#']) {
        bail!("mirror '{url}' must not carry a query or fragment");
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.contains('@') {
        bail!("mirror '{url}' must not carry credentials; use `docker login` for the mirror");
    }
    if authority.is_empty() || authority.starts_with(':') {
        bail!("mirror '{url}' has no host");
    }
    Ok((scheme, authority))
}

pub fn validate(config: &Map<String, Value>) -> Result<()> {
    let mirrors = strings(config, MIRRORS)?;
    let insecure = strings(config, INSECURE)?;
    if let Some(bad) = insecure.iter().find(|r| !plain(r)) {
        bail!(
            "insecure registry '{}' holds whitespace, quotes or control characters",
            bad.escape_debug()
        );
    }
    for m in &mirrors {
        let (scheme, authority) = mirror_authority(m)?;
        if scheme == "http" && !insecure.iter().any(|r| r == authority) {
            bail!(
                "http mirror '{m}' needs '{authority}' in insecure_registries; add it to the same update"
            );
        }
    }
    Ok(())
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq)]
pub struct KeyChange {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
}

pub fn diff(before: &Map<String, Value>, after: &Map<String, Value>) -> Vec<KeyChange> {
    let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|k| before.get(*k) != after.get(*k))
        .map(|k| KeyChange {
            key: k.clone(),
            before: before.get(k).cloned(),
            after: after.get(k).cloned(),
        })
        .collect()
}

pub fn parse_opts(opts: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let (mut mirrors, mut insecure, mut rest) = (Vec::new(), Vec::new(), Vec::new());
    let mut words = opts.split_whitespace();
    while let Some(w) = words.next() {
        let (flag, inline) = match w.split_once('=') {
            Some((f, v)) => (f, Some(v.to_owned())),
            None => (w, None),
        };
        let into = match flag {
            MIRROR_FLAG => &mut mirrors,
            INSECURE_FLAG => &mut insecure,
            _ => {
                rest.push(w.to_owned());
                continue;
            }
        };
        if let Some(v) = inline.or_else(|| words.next().map(str::to_owned)) {
            into.push(v);
        }
    }
    (mirrors, insecure, rest)
}

fn opts_of(cfg: &str) -> String {
    cfg.lines()
        .find_map(|l| init::assignment(l, OPTS_KEY))
        .map(|(v, _)| v.to_owned())
        .unwrap_or_default()
}

pub fn set_opts(cfg: &str, mirrors: &[String], insecure: &[String]) -> String {
    let (_, _, mut words) = parse_opts(&opts_of(cfg));
    words.extend(mirrors.iter().map(|m| format!("{MIRROR_FLAG}={m}")));
    words.extend(insecure.iter().map(|r| format!("{INSECURE_FLAG}={r}")));
    init::set_var(cfg, OPTS_KEY, &words.join(" "))
}

fn read_opt(root: &Path, rel: &str) -> Result<Option<String>> {
    match std::fs::read_to_string(root.join(rel)) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("failed to read '/{rel}'")),
    }
}

fn unraid_cfg(root: &Path) -> Result<String> {
    let rc = read_opt(root, UNRAID_RC)?.unwrap_or_default();
    if !rc.contains(OPTS_KEY) {
        bail!(
            "{UPDATE_TOOL}: refused on Unraid: '/{UNRAID_RC}' does not pass {OPTS_KEY} to dockerd, so the change cannot be persisted and '/{DAEMON_JSON}' is rebuilt at boot"
        );
    }
    read_opt(root, UNRAID_CFG)?.ok_or_else(|| {
        anyhow!(
            "{UPDATE_TOOL}: refused on Unraid: '/{UNRAID_CFG}' is missing; enable Docker in Settings > Docker first so its settings live on the flash"
        )
    })
}

fn flags_json(mirrors: Vec<String>, insecure: Vec<String>) -> Map<String, Value> {
    let mut m = Map::new();
    if !mirrors.is_empty() {
        m.insert(MIRRORS.into(), mirrors.into());
    }
    if !insecure.is_empty() {
        m.insert(INSECURE.into(), insecure.into());
    }
    m
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq)]
pub struct FileWrite {
    pub path: String,
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub host: Host,
    pub current: Map<String, Value>,
    pub effective: Map<String, Value>,
    pub writes: Vec<FileWrite>,
}

fn pretty(m: &Map<String, Value>) -> Result<String> {
    if m.is_empty() {
        return Ok(String::new());
    }
    Ok(plugin_toolkit::serde_json::to_string_pretty(m)? + "\n")
}

fn write_if_changed(writes: &mut Vec<FileWrite>, rel: &str, before: String, after: String) {
    if before != after {
        writes.push(FileWrite {
            path: format!("/{rel}"),
            before,
            after,
        });
    }
}

pub fn plan(root: &Path, patch: &DaemonConfigPatch) -> Result<Plan> {
    let host = detect(root);
    let json = read_json(root)?;
    let json_text = read_opt(root, DAEMON_JSON)?.unwrap_or_default();
    let mut writes = Vec::new();
    let (current, effective) = match host {
        Host::Unraid => {
            let cfg = unraid_cfg(root)?;
            let (mirrors, insecure, _) = parse_opts(&opts_of(&cfg));
            let mut current = json.clone();
            current.extend(flags_json(mirrors, insecure));
            let mut merged = Value::Object(current.clone());
            deep_merge(&mut merged, &patch.to_json());
            let Value::Object(effective) = merged else {
                unreachable!()
            };
            validate(&effective)?;
            let new_cfg = set_opts(
                &cfg,
                &strings(&effective, MIRRORS)?,
                &strings(&effective, INSECURE)?,
            );
            write_if_changed(&mut writes, UNRAID_CFG, cfg, new_cfg);
            let mut stripped = json.clone();
            for k in MANAGED {
                stripped.remove(k);
            }
            if stripped != json {
                write_if_changed(&mut writes, DAEMON_JSON, json_text, pretty(&stripped)?);
            }
            (current, effective)
        }
        Host::Standard(_) => {
            let mut merged = Value::Object(json.clone());
            deep_merge(&mut merged, &patch.to_json());
            let Value::Object(effective) = merged else {
                unreachable!()
            };
            validate(&effective)?;
            if effective != json {
                write_if_changed(&mut writes, DAEMON_JSON, json_text, pretty(&effective)?);
            }
            (json, effective)
        }
    };
    Ok(Plan {
        host,
        current,
        effective,
        writes,
    })
}

fn replace(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("'{}' has no parent", path.display()))?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = dir.join(format!(".{name}.orca-{}", std::process::id()));
    let result = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _removed = std::fs::remove_file(&tmp);
    }
    result.with_context(|| format!("failed to write '{}'", path.display()))
}

fn backup_path(path: &Path, ts: u64) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!("{name}.bak-{ts}"))
}

pub async fn apply<F, Fut>(
    root: &Path,
    writes: &[FileWrite],
    ts: u64,
    check: F,
) -> Result<(Vec<String>, Option<String>)>
where
    F: FnOnce(PathBuf) -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    let json_path = format!("/{DAEMON_JSON}");
    let mut validated = None;
    if let Some(w) = writes.iter().find(|w| w.path == json_path) {
        let candidate = root
            .join(DAEMON_JSON)
            .with_file_name(".daemon.json.orca-candidate");
        init::write_atomic(&candidate, &w.after, 0o644)?;
        let checked = check(candidate.clone()).await;
        let _removed = std::fs::remove_file(&candidate);
        validated = Some(checked.with_context(|| {
            format!("{UPDATE_TOOL}: the new daemon.json failed validation; nothing was written")
        })?);
    }
    let mut backups = Vec::new();
    for w in writes {
        let path = root.join(w.path.trim_start_matches('/'));
        if path.exists() {
            let bak = backup_path(&path, ts);
            std::fs::copy(&path, &bak)
                .with_context(|| format!("failed to back up '{}'", path.display()))?;
            backups.push(bak.display().to_string());
        }
        if w.path == json_path {
            init::write_atomic(&path, &w.after, 0o644)?;
        } else {
            replace(&path, &w.after)?;
        }
    }
    Ok((backups, validated))
}

async fn dockerd_validate(candidate: PathBuf) -> Result<String> {
    let Some(bin) = DOCKERD.iter().find(|b| Path::new(b).exists()) else {
        return Ok("skipped: dockerd not found".into());
    };
    let path = candidate.display().to_string();
    let out = Command::new(*bin)
        .args(["--validate", "--config-file", path.as_str()])
        .output()
        .await
        .context("failed to spawn dockerd --validate")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success {
        bail!("dockerd --validate: {}", text.trim());
    }
    Ok(format!("dockerd --validate: {}", text.trim()))
}

pub fn restart_command(host: Host) -> Result<Vec<&'static str>> {
    match host {
        Host::Unraid => Ok(vec!["/etc/rc.d/rc.docker", "restart"]),
        Host::Standard(Init::Systemd) => Ok(vec!["/bin/systemctl", "restart", "docker"]),
        Host::Standard(Init::OpenRc) => Ok(vec!["/sbin/rc-service", "docker", "restart"]),
        Host::Standard(Init::Other) => {
            bail!(
                "{UPDATE_TOOL}: no known init system on this host, so dockerd cannot be restarted; restart it by hand or omit `restart`"
            )
        }
    }
}

async fn run_restart(cmd: &[&str]) -> Result<String> {
    let out = Command::new(cmd[0])
        .args(&cmd[1..])
        .output()
        .await
        .with_context(|| format!("failed to spawn {}", cmd.join(" ")))?;
    if !out.status.success {
        bail!(
            "{UPDATE_TOOL}: `{}` failed: {}",
            cmd.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

async fn running_containers() -> std::result::Result<Vec<String>, String> {
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| e.to_string())?;
    let list = docker
        .list_containers(None::<bollard::query_parameters::ListContainersOptions>)
        .await
        .map_err(|e| e.to_string())?;
    let mut names: Vec<String> = list
        .into_iter()
        .filter_map(|c| c.names?.into_iter().next())
        .map(|n| n.trim_start_matches('/').to_owned())
        .collect();
    names.sort();
    Ok(names)
}

pub fn restart_warning(running: &std::result::Result<Vec<String>, String>) -> String {
    match running {
        Ok(names) if names.is_empty() => {
            "restarting dockerd stops every container; none is running now".into()
        }
        Ok(names) => format!(
            "restarting dockerd stops every container; {} running now: {}",
            names.len(),
            names.join(", ")
        ),
        Err(e) => format!(
            "restarting dockerd stops every container; the running ones could not be listed: {e}"
        ),
    }
}

fn redacted(m: &Map<String, Value>) -> Value {
    plugin_toolkit::scrub::redact_json(Value::Object(m.clone()))
}

#[orca_struct(args)]
pub struct DockerDaemonConfigArgs {}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DaemonConfigDetail {
    /// `unraid`, `systemd`, `openrc` or `other`.
    pub host: String,
    pub path: String,
    /// `daemon.json` as parsed; `{}` when absent.
    pub daemon_json: Value,
    /// Unraid: the persisted settings file whose `DOCKER_OPTS` flags dockerd
    /// also gets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persisted_in: Option<String>,
    /// `daemonJson` with the persisted flags applied: what dockerd runs with
    /// after its next restart.
    pub effective: Value,
}

/// **Read the Docker daemon config** (`/etc/docker/daemon.json`), parsed. On
/// Unraid, also the `--registry-mirror`/`--insecure-registry` flags persisted
/// in `/boot/config/docker.cfg`, folded into `effective`. Unsupported on
/// macOS (colima owns the daemon config: `colima start --edit`).
#[orca_tool(
    domain = "docker",
    verb = "daemon_config",
    local_only = true,
    role = "admin",
    execute_gated = false
)]
async fn docker_daemon_config(
    _args: DockerDaemonConfigArgs,
    ctx: &ToolCtx,
) -> Result<DaemonConfigDetail> {
    execute::require_admin(TOOL, ctx)?;
    refuse_macos(TOOL)?;
    detail(Path::new("/"))
}

pub fn detail(root: &Path) -> Result<DaemonConfigDetail> {
    let host = detect(root);
    let json = read_json(root)?;
    let (persisted_in, effective) = match host {
        Host::Unraid => {
            let cfg = read_opt(root, UNRAID_CFG)?.unwrap_or_default();
            let (mirrors, insecure, _) = parse_opts(&opts_of(&cfg));
            let mut effective = json.clone();
            effective.extend(flags_json(mirrors, insecure));
            (Some(format!("/{UNRAID_CFG}")), effective)
        }
        Host::Standard(_) => (None, json.clone()),
    };
    Ok(DaemonConfigDetail {
        host: host.as_str().to_owned(),
        path: format!("/{DAEMON_JSON}"),
        daemon_json: redacted(&json),
        persisted_in,
        effective: redacted(&effective),
    })
}

#[orca_struct(args)]
pub struct DockerDaemonConfigUpdateArgs {
    /// Replaces `registry-mirrors`: http(s) URLs. An http mirror's host:port
    /// must also be in `insecure_registries`. Comma-separated on the CLI.
    #[arg(long, value_delimiter = ',')]
    #[serde(default)]
    pub registry_mirrors: Option<Vec<String>>,
    /// Replaces `insecure-registries`: `host:port` or CIDR entries.
    /// Comma-separated on the CLI.
    #[arg(long, value_delimiter = ',')]
    #[serde(default)]
    pub insecure_registries: Option<Vec<String>>,
    /// Restart dockerd after writing, which stops every container on this
    /// host. Omitted, the change applies at the next engine restart.
    #[arg(long)]
    #[serde(default)]
    pub restart: bool,
    /// Return the diff and change nothing. Omitted, applies.
    #[arg(long)]
    #[serde(default, rename = "dryRun", alias = "dry_run")]
    pub dry_run: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DaemonConfigUpdateOutput {
    /// true: nothing was changed.
    pub dry_run: bool,
    /// `unraid`, `systemd`, `openrc` or `other`.
    pub host: String,
    /// Effective config keys that change.
    pub changes: Vec<KeyChange>,
    /// Files written (or to write), with their full before and after text.
    pub writes: Vec<FileWrite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backups: Vec<String>,
    /// `dockerd --validate` on the new `daemon.json`, when one is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validated: Option<String>,
    /// Restarting stops every container; lists the running ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_warning: Option<String>,
    pub restarted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// **Update the Docker daemon config**: deep-merge `registry_mirrors` /
/// `insecure_registries` into `/etc/docker/daemon.json`, keeping every other
/// key. Validates the result (mirrors are http(s) URLs; an http mirror's
/// host:port must be an insecure registry), then backs each file up to
/// `<file>.bak-<unix secs>`, checks the new `daemon.json` with `dockerd
/// --validate` when dockerd is present, and writes atomically. On Unraid the
/// two keys persist as `DOCKER_OPTS` flags in `/boot/config/docker.cfg` and
/// are removed from `daemon.json`; refused when rc.docker does not pass
/// `DOCKER_OPTS`. dockerd is restarted only with `restart` (it stops every
/// container). Unsupported on macOS (colima: `colima start --edit`). With
/// `dryRun`, returns the diff and the running containers a restart stops.
#[orca_tool(
    domain = "docker",
    verb = "daemon_config_update",
    local_only = true,
    role = "admin",
    execute_gated = false
)]
async fn docker_daemon_config_update(
    args: DockerDaemonConfigUpdateArgs,
    ctx: &ToolCtx,
) -> Result<DaemonConfigUpdateOutput> {
    execute::require_admin(UPDATE_TOOL, ctx)?;
    refuse_macos(UPDATE_TOOL)?;
    let patch = DaemonConfigPatch {
        registry_mirrors: args.registry_mirrors.clone(),
        insecure_registries: args.insecure_registries.clone(),
    };
    if patch.is_empty() {
        bail!("{UPDATE_TOOL}: pass registry_mirrors and/or insecure_registries");
    }
    let root = Path::new("/");
    let plan = plan(root, &patch)?;
    let restart_cmd = if args.restart {
        Some(restart_command(plan.host)?)
    } else {
        None
    };
    let changes = diff(&plan.current, &plan.effective);
    let changed = !plan.writes.is_empty();
    let restart_warning = if changed {
        Some(restart_warning(&running_containers().await))
    } else {
        None
    };
    let mut out = DaemonConfigUpdateOutput {
        dry_run: args.dry_run,
        host: plan.host.as_str().to_owned(),
        changes,
        writes: plan.writes.clone(),
        backups: Vec::new(),
        validated: None,
        restart_warning,
        restarted: false,
        how_to_execute: None,
    };
    if args.dry_run {
        out.how_to_execute = Some(format!(
            "re-invoke {UPDATE_TOOL} without `dryRun`; add `restart` to restart dockerd now"
        ));
        return Ok(out);
    }
    if !changed {
        return Ok(out);
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let (backups, validated) = apply(root, &plan.writes, ts, dockerd_validate).await?;
    plugin_toolkit::tracing::info!(
        target: "docker::daemon_config",
        host = plan.host.as_str(),
        effective = %redacted(&plan.effective),
        "daemon config written"
    );
    out.backups = backups;
    out.validated = validated;
    if let Some(cmd) = restart_cmd {
        run_restart(&cmd).await?;
        out.restarted = true;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{admin, assert_admin_refusal, non_admins};
    use plugin_toolkit::reactor::block_on;
    use plugin_toolkit::serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        match v {
            Value::Object(m) => m,
            _ => panic!("not an object"),
        }
    }

    fn mirrors(m: &[&str], i: &[&str]) -> DaemonConfigPatch {
        DaemonConfigPatch {
            registry_mirrors: Some(m.iter().map(|s| s.to_string()).collect()),
            insecure_registries: Some(i.iter().map(|s| s.to_string()).collect()),
        }
    }

    fn put(root: &Path, rel: &str, text: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    const NVIDIA: &str = r#"{"runtimes":{"nvidia":{"path":"nvidia-container-runtime","args":[]}},"default-runtime":"nvidia","log-opts":{"max-size":"10m"}}"#;

    #[test]
    fn deep_merge_preserves_unknown_keys() {
        let mut base: Value = plugin_toolkit::serde_json::from_str(NVIDIA).unwrap();
        deep_merge(
            &mut base,
            &json!({"registry-mirrors": ["https://m"], "log-opts": {"max-file": "3"}}),
        );
        assert_eq!(
            base,
            json!({
                "runtimes": {"nvidia": {"path": "nvidia-container-runtime", "args": []}},
                "default-runtime": "nvidia",
                "log-opts": {"max-size": "10m", "max-file": "3"},
                "registry-mirrors": ["https://m"],
            })
        );
        deep_merge(&mut base, &json!({"registry-mirrors": ["https://n"]}));
        assert_eq!(base["registry-mirrors"], json!(["https://n"]));
    }

    #[test]
    fn mirrors_must_be_http_or_https_urls() {
        assert_eq!(
            mirror_authority("http://10.0.0.10:5000").unwrap(),
            ("http", "10.0.0.10:5000")
        );
        assert_eq!(
            mirror_authority("https://mirror.example/v2/").unwrap(),
            ("https", "mirror.example")
        );
        for bad in [
            "10.0.0.10:5000",
            "ftp://m",
            "https://",
            "https://:5000",
            "https://u:p@m",
            "https://m?x=1",
            "https://m\"x",
            "https://m x",
        ] {
            assert!(mirror_authority(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_http_mirror_needs_its_host_port_in_insecure_registries() {
        let config =
            |m: &[&str], i: &[&str]| obj(json!({"registry-mirrors": m, "insecure-registries": i}));
        let err = validate(&config(&["http://10.0.0.10:5000"], &[])).unwrap_err();
        assert!(
            err.to_string()
                .contains("'10.0.0.10:5000' in insecure_registries"),
            "{err}"
        );
        assert!(validate(&config(&["http://10.0.0.10:5000"], &["10.0.0.10:5000"])).is_ok());
        assert!(validate(&config(&["https://m.example"], &[])).is_ok());
        assert!(validate(&config(&[], &["a b"])).is_err());
        assert!(validate(&obj(json!({"registry-mirrors": "https://m"}))).is_err());
    }

    #[test]
    fn standard_host_dry_run_diffs_and_keeps_unknown_keys() {
        let t = tempfile::tempdir().unwrap();
        put(t.path(), DAEMON_JSON, NVIDIA);
        let p = plan(
            t.path(),
            &mirrors(&["http://10.0.0.10:5000"], &["10.0.0.10:5000"]),
        )
        .unwrap();
        assert_eq!(p.host, Host::Standard(Init::Other));
        let changes = diff(&p.current, &p.effective);
        let keys: Vec<_> = changes.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, [INSECURE, MIRRORS]);
        assert_eq!(changes[1].before, None);
        assert_eq!(changes[1].after, Some(json!(["http://10.0.0.10:5000"])));
        assert_eq!(p.writes.len(), 1);
        assert_eq!(p.writes[0].path, "/etc/docker/daemon.json");
        let after: Value = plugin_toolkit::serde_json::from_str(&p.writes[0].after).unwrap();
        assert_eq!(after["default-runtime"], "nvidia");
        assert_eq!(
            after["runtimes"]["nvidia"]["path"],
            "nvidia-container-runtime"
        );
        assert_eq!(
            std::fs::read_to_string(t.path().join(DAEMON_JSON)).unwrap(),
            NVIDIA
        );

        let again = plan(t.path(), &mirrors(&[], &[])).unwrap();
        assert!(
            diff(&again.current, &again.effective)
                .iter()
                .all(|c| c.after == Some(json!([])))
        );
    }

    #[test]
    fn an_invalid_patch_plans_nothing() {
        let t = tempfile::tempdir().unwrap();
        let err = plan(t.path(), &mirrors(&["http://10.0.0.10:5000"], &[])).unwrap_err();
        assert!(err.to_string().contains("insecure_registries"), "{err}");
    }

    #[test]
    fn apply_backs_up_validates_and_writes() {
        let t = tempfile::tempdir().unwrap();
        put(t.path(), DAEMON_JSON, NVIDIA);
        let p = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap();
        let (backups, validated) = block_on(apply(t.path(), &p.writes, 42, |c| async move {
            assert!(c.exists());
            Ok("ok".into())
        }))
        .unwrap();
        assert_eq!(validated.as_deref(), Some("ok"));
        assert_eq!(backups.len(), 1);
        assert!(backups[0].ends_with("daemon.json.bak-42"));
        assert_eq!(std::fs::read_to_string(&backups[0]).unwrap(), NVIDIA);
        assert_eq!(
            read_json(t.path()).unwrap()["registry-mirrors"],
            json!(["https://m"])
        );
        let left: Vec<_> = std::fs::read_dir(t.path().join("etc/docker"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left.len(), 2, "{left:?}");
    }

    #[test]
    fn a_failed_validation_writes_nothing() {
        let t = tempfile::tempdir().unwrap();
        put(t.path(), DAEMON_JSON, NVIDIA);
        let p = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap();
        let err = block_on(apply(t.path(), &p.writes, 1, |_| async {
            bail!("bad key")
        }))
        .unwrap_err();
        assert!(format!("{err:#}").contains("bad key"), "{err:#}");
        assert_eq!(
            std::fs::read_to_string(t.path().join(DAEMON_JSON)).unwrap(),
            NVIDIA
        );
        assert_eq!(
            std::fs::read_dir(t.path().join("etc/docker"))
                .unwrap()
                .count(),
            1
        );
    }

    fn unraid(root: &Path, cfg: &str) {
        put(root, UNRAID_VERSION, "version=\"7.0.1\"\n");
        put(
            root,
            UNRAID_RC,
            "DOCKER_OPTS=\"$DOCKER_OPTS --log-level=fatal\"\n$DOCKER $DOCKER_OPTS\n",
        );
        put(root, UNRAID_CFG, cfg);
    }

    #[test]
    fn unraid_persists_to_docker_cfg_and_strips_daemon_json() {
        let t = tempfile::tempdir().unwrap();
        unraid(
            t.path(),
            "DOCKER_ENABLED=\"yes\"\nDOCKER_OPTS=\"--storage-driver=overlay2 --registry-mirror https://old\"\n",
        );
        put(
            t.path(),
            DAEMON_JSON,
            r#"{"runtimes":{"nvidia":{}},"registry-mirrors":["https://old"]}"#,
        );
        let p = plan(
            t.path(),
            &mirrors(&["http://10.0.0.10:5000"], &["10.0.0.10:5000"]),
        )
        .unwrap();
        assert_eq!(p.host, Host::Unraid);
        let paths: Vec<_> = p.writes.iter().map(|w| w.path.as_str()).collect();
        assert_eq!(
            paths,
            ["/boot/config/docker.cfg", "/etc/docker/daemon.json"]
        );
        assert_eq!(
            p.writes[0].after,
            "DOCKER_ENABLED=\"yes\"\nDOCKER_OPTS=\"--storage-driver=overlay2 --registry-mirror=http://10.0.0.10:5000 --insecure-registry=10.0.0.10:5000\"\n"
        );
        let json: Value = plugin_toolkit::serde_json::from_str(&p.writes[1].after).unwrap();
        assert_eq!(json, json!({"runtimes": {"nvidia": {}}}));
        assert_eq!(p.effective[MIRRORS], json!(["http://10.0.0.10:5000"]));
        assert_eq!(p.current[MIRRORS], json!(["https://old"]));

        block_on(apply(t.path(), &p.writes, 7, |_| async { Ok("ok".into()) })).unwrap();
        assert!(t.path().join("boot/config/docker.cfg.bak-7").exists());
        let d = detail(t.path()).unwrap();
        assert_eq!(d.persisted_in.as_deref(), Some("/boot/config/docker.cfg"));
        assert_eq!(d.effective[INSECURE], json!(["10.0.0.10:5000"]));
        assert_eq!(
            plan(
                t.path(),
                &mirrors(&["http://10.0.0.10:5000"], &["10.0.0.10:5000"])
            )
            .unwrap()
            .writes,
            []
        );
    }

    #[test]
    fn unraid_refuses_when_nothing_would_persist() {
        let t = tempfile::tempdir().unwrap();
        put(t.path(), UNRAID_VERSION, "version=\"7.0.1\"\n");
        put(t.path(), UNRAID_RC, "exec dockerd\n");
        put(t.path(), UNRAID_CFG, "DOCKER_ENABLED=\"yes\"\n");
        let err = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap_err();
        assert!(err.to_string().contains("cannot be persisted"), "{err}");

        let t = tempfile::tempdir().unwrap();
        put(t.path(), UNRAID_VERSION, "version=\"7.0.1\"\n");
        put(t.path(), UNRAID_RC, "$DOCKER_OPTS\n");
        let err = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap_err();
        assert!(err.to_string().contains("docker.cfg' is missing"), "{err}");
    }

    #[test]
    fn opts_parse_both_flag_forms_and_keep_the_rest() {
        let (m, i, rest) = parse_opts(
            "--registry-mirror=https://a --insecure-registry b:1 --dns 1.1.1.1 --registry-mirror https://c",
        );
        assert_eq!(m, ["https://a", "https://c"]);
        assert_eq!(i, ["b:1"]);
        assert_eq!(rest, ["--dns", "1.1.1.1"]);
        assert_eq!(set_opts("", &[], &[]), "DOCKER_OPTS=\"\"\n");
    }

    #[test]
    fn restart_follows_the_host() {
        assert_eq!(
            restart_command(Host::Unraid).unwrap()[0],
            "/etc/rc.d/rc.docker"
        );
        assert_eq!(
            restart_command(Host::Standard(Init::Systemd)).unwrap(),
            ["/bin/systemctl", "restart", "docker"]
        );
        assert!(restart_command(Host::Standard(Init::Other)).is_err());
        assert!(restart_warning(&Ok(vec!["a".into(), "b".into()])).contains("2 running now: a, b"));
    }

    #[test]
    fn execute_is_the_default_and_restart_is_opt_in() {
        let args: DockerDaemonConfigUpdateArgs =
            plugin_toolkit::serde_json::from_value(json!({"registry_mirrors": ["https://m"]}))
                .unwrap();
        assert!(!args.dry_run && !args.restart);
        let args: DockerDaemonConfigUpdateArgs =
            plugin_toolkit::serde_json::from_value(json!({"dryRun": true, "restart": true}))
                .unwrap();
        assert!(args.dry_run && args.restart && args.registry_mirrors.is_none());
    }

    #[test]
    fn non_admins_are_refused() {
        for ctx in non_admins() {
            let err = block_on(docker_daemon_config(DockerDaemonConfigArgs {}, &ctx)).unwrap_err();
            assert_admin_refusal(&err.to_string());
            let args: DockerDaemonConfigUpdateArgs =
                plugin_toolkit::serde_json::from_value(json!({"dryRun": true})).unwrap();
            let err = block_on(docker_daemon_config_update(args, &ctx)).unwrap_err();
            assert_admin_refusal(&err.to_string());
        }
        let args: DockerDaemonConfigUpdateArgs =
            plugin_toolkit::serde_json::from_value(json!({"dryRun": true})).unwrap();
        let err = block_on(docker_daemon_config_update(args, &admin())).unwrap_err();
        assert!(
            err.to_string().contains("pass registry_mirrors") || err.to_string().contains("macOS"),
            "{err}"
        );
    }
}
