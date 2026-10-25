#![allow(clippy::disallowed_types)]

use std::path::{Path, PathBuf};

use plugin_toolkit::prelude::*;
use plugin_toolkit::privileged::{self, PrivilegedOps};
use plugin_toolkit::process::Command;
use plugin_toolkit::serde::Serialize;
use plugin_toolkit::serde::de::DeserializeOwned;
use plugin_toolkit::serde_json::{Map, Value};

use crate::execute;
use crate::init::{self, Init};

const PLUGIN: &str = "docker";
const READ_OP: &str = "daemon_config";
const UPDATE_OP: &str = "daemon_config_update";
const CALLER_UID_ENV: &str = "ORCA_CALLER_UID";
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
const CFG_BACKUP: &str = "docker.cfg.bak";
const JSON_BACKUPS_KEPT: usize = 3;
const SHELL_UNSAFE: [char; 6] = ['$', '`', '"', '\'', '\\', ';'];
const SYSTEMCTL: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];
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
    let Some(text) = read_opt(root, DAEMON_JSON)? else {
        return Ok(Map::new());
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

fn allowed(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_:/[]%".contains(c))
}

fn shown(value: &str) -> String {
    let (scheme, rest) = match value.split_once("://") {
        Some((s, r)) => (format!("{s}://"), r),
        None => (String::new(), value),
    };
    let host = rest.split('/').next().unwrap_or_default();
    format!("{scheme}{host}").escape_debug().to_string()
}

fn no_credentials(what: &str, value: &str) -> Result<()> {
    if value.contains('@') {
        bail!("{what} must not carry credentials; use `docker login` for the registry");
    }
    Ok(())
}

pub fn mirror_authority(url: &str) -> Result<(&str, &str)> {
    no_credentials("a mirror", url)?;
    if !allowed(url) {
        bail!(
            "mirror '{}' may hold only ASCII letters, digits and . - _ : / [ ] %",
            shown(url)
        );
    }
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| anyhow!("mirror '{}' is not a URL", shown(url)))?;
    if scheme != "http" && scheme != "https" {
        bail!("mirror '{}' must be http or https", shown(url));
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.starts_with(':') {
        bail!("mirror '{}' has no host", shown(url));
    }
    Ok((scheme, authority))
}

pub fn validate(config: &Map<String, Value>) -> Result<()> {
    let mirrors = strings(config, MIRRORS)?;
    let insecure = strings(config, INSECURE)?;
    for r in &insecure {
        no_credentials("an insecure registry", r)?;
        if !allowed(r) {
            bail!(
                "insecure registry '{}' may hold only ASCII letters, digits and . - _ : / [ ] %",
                shown(r)
            );
        }
    }
    for m in &mirrors {
        let (scheme, authority) = mirror_authority(m)?;
        if scheme == "http" && !insecure.iter().any(|r| r == authority) {
            bail!(
                "http mirror '{}' needs '{}' in insecure_registries; add it to the same update",
                shown(m),
                authority.escape_debug()
            );
        }
    }
    Ok(())
}

fn bracketed_ipv6(value: &str) -> bool {
    let rest = value.split_once("://").map_or(value, |(_, r)| r);
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if path.contains(['[', ']']) {
        return false;
    }
    let Some((ip, port)) = authority.strip_prefix('[').and_then(|a| a.split_once(']')) else {
        return false;
    };
    ip.parse::<std::net::Ipv6Addr>().is_ok()
        && (port.is_empty()
            || port
                .strip_prefix(':')
                .is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())))
}

fn unraid_brackets(config: &Map<String, Value>) -> Result<()> {
    for key in MANAGED {
        if let Some(bad) = strings(config, key)?
            .iter()
            .find(|v| v.contains(['[', ']']) && !bracketed_ipv6(v))
        {
            bail!(
                "{UPDATE_TOOL}: refused on Unraid: '{key}' value '{}' holds '[' or ']' outside a bracketed IPv6 host, which the shell sourcing '/{UNRAID_CFG}' would glob",
                shown(bad)
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
    let mut words = opts.split_whitespace().peekable();
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
        let next = || words.next_if(|n| !n.starts_with('-')).map(str::to_owned);
        if let Some(v) = inline.or_else(next) {
            into.push(v);
        }
    }
    (mirrors, insecure, rest)
}

fn opts_of(cfg: &str) -> String {
    cfg.lines()
        .rev()
        .find_map(|l| init::assignment(l, OPTS_KEY))
        .map(|(v, _)| v.to_owned())
        .unwrap_or_default()
}

pub fn set_opts(cfg: &str, mirrors: &[String], insecure: &[String]) -> Result<String> {
    let (_, _, mut words) = parse_opts(&opts_of(cfg));
    words.extend(mirrors.iter().map(|m| format!("{MIRROR_FLAG}={m}")));
    words.extend(insecure.iter().map(|r| format!("{INSECURE_FLAG}={r}")));
    if let Some(bad) = words.iter().find(|w| {
        w.chars()
            .any(|c| c.is_whitespace() || SHELL_UNSAFE.contains(&c))
    }) {
        bail!(
            "{UPDATE_TOOL}: refused: {OPTS_KEY} word '{}' would be interpreted by the shell that sources '/{UNRAID_CFG}'",
            bad.escape_debug()
        );
    }
    Ok(init::set_var(cfg, OPTS_KEY, &words.join(" ")))
}

fn sources_cfg(rc: &str) -> bool {
    rc.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .any(|l| {
            [". ", "source "].iter().any(|cmd| {
                ["$DOCKER_CFG", "\"$DOCKER_CFG\"", "${DOCKER_CFG}"]
                    .iter()
                    .any(|v| l.contains(&format!("{cmd}{v}")))
            })
        })
}

fn read_opt(root: &Path, rel: &str) -> Result<Option<String>> {
    let path = root.join(rel);
    match read_nofollow(&path) {
        Ok(b) => String::from_utf8(b)
            .map(Some)
            .with_context(|| format!("'/{rel}' is not UTF-8")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => bail!(
            "refused: '{}' is a symlink; point it at a real file first",
            path.display()
        ),
        Err(e) => Err(e).with_context(|| format!("failed to read '/{rel}'")),
    }
}

fn unraid_cfg(root: &Path) -> Result<String> {
    let rc = read_opt(root, UNRAID_RC)?.unwrap_or_default();
    if !rc.contains(OPTS_KEY) || !sources_cfg(&rc) {
        bail!(
            "{UPDATE_TOOL}: refused on Unraid: '/{UNRAID_RC}' does not source DOCKER_CFG and pass {OPTS_KEY} to dockerd, so the change cannot be persisted and '/{DAEMON_JSON}' is rebuilt at boot"
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

fn conflicts(json: &Map<String, Value>, flags: &Map<String, Value>) -> Vec<String> {
    MANAGED
        .iter()
        .filter_map(|k| match (json.get(*k), flags.get(*k)) {
            (Some(a), Some(b)) if a != b => Some(format!(
                "'{k}' differs: /{DAEMON_JSON} has {a}, {OPTS_KEY} in /{UNRAID_CFG} has {b}"
            )),
            _ => None,
        })
        .collect()
}

fn merged(base: &Map<String, Value>, patch: &DaemonConfigPatch) -> Map<String, Value> {
    let mut v = Value::Object(base.clone());
    deep_merge(&mut v, &patch.to_json());
    let Value::Object(mut m) = v else {
        unreachable!()
    };
    for k in MANAGED {
        if m.get(k)
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            m.remove(k);
        }
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
    pub candidate: Option<String>,
    pub conflicts: Vec<String>,
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
    let (current, effective, candidate, conflicts) = match host {
        Host::Unraid => {
            let raw = unraid_cfg(root)?;
            let crlf = raw.contains("\r\n");
            let cfg = if crlf {
                raw.replace("\r\n", "\n")
            } else {
                raw.clone()
            };
            if cfg.lines().any(|l| {
                l.trim_start().starts_with(&format!("{OPTS_KEY}="))
                    && init::assignment(l, OPTS_KEY).is_none()
            }) {
                bail!(
                    "{UPDATE_TOOL}: refused on Unraid: a {OPTS_KEY} line in '/{UNRAID_CFG}' spans lines or has an unterminated quote; fix it by hand first"
                );
            }
            let (mirrors, insecure, _) = parse_opts(&opts_of(&cfg));
            let flags = flags_json(mirrors, insecure);
            let conflicts = conflicts(&json, &flags);
            let mut current = json.clone();
            current.extend(flags.clone());
            let effective = merged(&current, patch);
            validate(&effective)?;
            unraid_brackets(&effective)?;
            let mut stripped = json.clone();
            for k in MANAGED {
                stripped.remove(k);
            }
            if stripped != json {
                write_if_changed(&mut writes, DAEMON_JSON, json_text, pretty(&stripped)?);
            }
            let wanted = flags_json(
                strings(&effective, MIRRORS)?,
                strings(&effective, INSECURE)?,
            );
            if wanted != flags {
                let mut new_cfg = set_opts(
                    &cfg,
                    &strings(&effective, MIRRORS)?,
                    &strings(&effective, INSECURE)?,
                )?;
                if crlf {
                    new_cfg = new_cfg.replace('\n', "\r\n");
                }
                write_if_changed(&mut writes, UNRAID_CFG, raw, new_cfg);
            }
            let mut candidate = stripped;
            candidate.extend(wanted);
            (current, effective, candidate, conflicts)
        }
        Host::Standard(_) => {
            let effective = merged(&json, patch);
            validate(&effective)?;
            if effective != json {
                write_if_changed(&mut writes, DAEMON_JSON, json_text, pretty(&effective)?);
            }
            let candidate = effective.clone();
            (json, effective, candidate, Vec::new())
        }
    };
    let candidate = if writes.is_empty() {
        None
    } else {
        Some(plugin_toolkit::serde_json::to_string_pretty(&candidate)? + "\n")
    };
    Ok(Plan {
        host,
        current,
        effective,
        writes,
        candidate,
        conflicts,
    })
}

fn backup_path(path: &Path, ts: u128) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!("{name}.bak-{ts}"))
}

fn prune_backups(path: &Path) -> Result<()> {
    let dir = path.parent().unwrap_or(path);
    let prefix = format!(
        "{}.bak-",
        path.file_name().unwrap_or_default().to_string_lossy()
    );
    let mut found: Vec<(u128, PathBuf)> = std::fs::read_dir(dir)?
        .filter_map(|e| {
            let e = e.ok()?;
            let ts = e
                .file_name()
                .to_str()?
                .strip_prefix(&prefix)?
                .parse()
                .ok()?;
            Some((ts, e.path()))
        })
        .collect();
    found.sort();
    let excess = found.len().saturating_sub(JSON_BACKUPS_KEPT);
    for (_, old) in found.into_iter().take(excess) {
        std::fs::remove_file(&old)
            .with_context(|| format!("failed to prune '{}'", old.display()))?;
    }
    Ok(())
}

fn read_nofollow(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut buf = Vec::new();
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?
        .read_to_end(&mut buf)?;
    Ok(buf)
}

struct Written {
    path: PathBuf,
    mode: u32,
    bak: Option<PathBuf>,
    fresh_bak: bool,
}

fn write_one(root: &Path, w: &FileWrite, ts: u128, done: &mut Vec<Written>) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let path = root.join(w.path.trim_start_matches('/'));
    let is_cfg = w.path == format!("/{UNRAID_CFG}");
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => Some(m),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("failed to stat '{}'", path.display())),
    };
    if meta.as_ref().is_some_and(|m| m.file_type().is_symlink()) {
        bail!(
            "refused: '{}' is a symlink; point it at a real file first",
            path.display()
        );
    }
    let mode = meta
        .as_ref()
        .map_or(0o644, |m| m.permissions().mode() & 0o7777);
    match &meta {
        Some(_) => {
            let original = read_nofollow(&path)
                .with_context(|| format!("failed to read '{}'", path.display()))?;
            if is_cfg {
                let bak = path.with_file_name(CFG_BACKUP);
                init::write_atomic(&bak, &String::from_utf8_lossy(&original), mode)?;
                done.push(Written {
                    path: path.clone(),
                    mode,
                    bak: Some(bak),
                    fresh_bak: false,
                });
            } else {
                let bak = backup_path(&path, ts);
                let mut f = init::create_new(&bak, mode)
                    .with_context(|| format!("failed to create '{}'", bak.display()))?;
                if let Err(e) = f.write_all(&original).and_then(|()| f.sync_all()) {
                    let _removed = std::fs::remove_file(&bak);
                    return Err(e)
                        .with_context(|| format!("failed to back up '{}'", path.display()));
                }
                done.push(Written {
                    path: path.clone(),
                    mode,
                    bak: Some(bak),
                    fresh_bak: true,
                });
            }
        }
        None => {
            done.push(Written {
                path: path.clone(),
                mode,
                bak: None,
                fresh_bak: false,
            });
        }
    }
    init::write_atomic(&path, &w.after, mode)
}

fn rollback(done: &[Written]) -> Vec<String> {
    done.iter()
        .rev()
        .filter_map(|w| {
            let result = match &w.bak {
                Some(b) => std::fs::read_to_string(b)
                    .context("failed to read the backup")
                    .and_then(|t: String| init::write_atomic(&w.path, &t, w.mode))
                    .and_then(|()| {
                        if w.fresh_bak {
                            std::fs::remove_file(b)?;
                        }
                        Ok(())
                    }),
                None => match std::fs::remove_file(&w.path) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        Err(e).context("failed to remove")
                    }
                    _ => Ok(()),
                },
            };
            result
                .err()
                .map(|e| format!("'{}': {e:#}", w.path.display()))
        })
        .collect()
}

pub async fn apply<F, Fut>(
    root: &Path,
    writes: &[FileWrite],
    candidate: Option<&str>,
    ts: u128,
    check: F,
) -> Result<(Vec<String>, Option<String>, Vec<String>)>
where
    F: FnOnce(PathBuf) -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    use std::io::Write;
    let mut validated = None;
    if let Some(c) = candidate {
        let path = root.join(DAEMON_JSON).with_file_name(format!(
            ".daemon.json.orca-candidate-{}-{ts}",
            std::process::id()
        ));
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let written = (|| -> std::io::Result<()> {
            let mut f = init::create_new(&path, 0o600)?;
            f.write_all(c.as_bytes())?;
            f.sync_all()
        })();
        let checked = match written.context("failed to write the candidate config") {
            Ok(()) => check(path.clone()).await,
            Err(e) => Err(e),
        };
        let _removed = std::fs::remove_file(&path);
        validated = Some(checked.with_context(|| {
            format!("{UPDATE_TOOL}: the new daemon config failed validation; nothing was written")
        })?);
    }
    let mut done = Vec::new();
    for w in writes {
        if let Err(e) = write_one(root, w, ts, &mut done) {
            let failed = rollback(&done);
            if failed.is_empty() {
                bail!("{UPDATE_TOOL}: {e:#}; rolled back");
            }
            bail!(
                "{UPDATE_TOOL}: {e:#}; rollback failed for {}",
                failed.join(", ")
            );
        }
    }
    let warnings = done
        .iter()
        .filter(|w| w.fresh_bak)
        .filter_map(|w| prune_backups(&w.path).err())
        .map(|e| format!("backups kept: {e:#}"))
        .collect();
    let backups = done
        .into_iter()
        .filter_map(|w| w.bak.map(|b| b.display().to_string()))
        .collect();
    Ok((backups, validated, warnings))
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

fn systemctl() -> &'static str {
    SYSTEMCTL
        .into_iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or(SYSTEMCTL[1])
}

pub fn restart_command(host: Host) -> Result<Vec<&'static str>> {
    match host {
        Host::Unraid => Ok(vec!["/etc/rc.d/rc.docker", "restart"]),
        Host::Standard(Init::Systemd) => Ok(vec![systemctl(), "restart", "docker"]),
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
    let docker = &crate::registration::adapter()
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

fn scrubbed(text: &str) -> String {
    text.split_inclusive('\n')
        .map(|l| plugin_toolkit::scrub::scrub_line(l).into_owned())
        .collect()
}

fn scrub_write(w: &FileWrite) -> FileWrite {
    FileWrite {
        path: w.path.clone(),
        before: scrubbed(&w.before),
        after: scrubbed(&w.after),
    }
}

fn scrub_change(c: KeyChange) -> KeyChange {
    KeyChange {
        key: c.key,
        before: c.before.map(plugin_toolkit::scrub::redact_json),
        after: c.after.map(plugin_toolkit::scrub::redact_json),
    }
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
    /// Unraid: managed keys set in both files with different values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<String>,
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
    execute_gated = false,
    reaches = ["privileged.apply"]
)]
async fn docker_daemon_config(
    _args: DockerDaemonConfigArgs,
    ctx: &ToolCtx,
) -> Result<DaemonConfigDetail> {
    execute::require_admin(TOOL, ctx)?;
    refuse_macos(TOOL)?;
    if is_root() {
        return detail(Path::new("/"));
    }
    through_seam::<(), _>(READ_OP, None).await
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

async fn through_seam<P: Serialize, T: DeserializeOwned>(
    op: &str,
    payload: Option<&P>,
) -> Result<T> {
    let detail = privileged::apply(PLUGIN, op, payload)
        .await
        .with_context(|| format!("{PLUGIN} {op} through `orca admin plugin-apply`"))?;
    plugin_toolkit::serde_json::from_str(&detail)
        .with_context(|| format!("decode the {op} privileged reply"))
}

fn caller_uid(raw: Option<&str>) -> Option<u32> {
    raw?.parse().ok()
}

fn authorize_privileged(caller: Option<u32>, euid_root: bool) -> Result<()> {
    plugin_toolkit::anyhow::ensure!(
        euid_root,
        "{} must run as root",
        privileged::PRIVILEGED_FLAG
    );
    plugin_toolkit::anyhow::ensure!(
        caller.is_some(),
        "{CALLER_UID_ENV} is missing or invalid; refusing every privileged op"
    );
    Ok(())
}

pub fn privileged_ops() -> PrivilegedOps {
    PrivilegedOps::new()
        .op(READ_OP, |(): ()| async {
            authorize_privileged(
                caller_uid(std::env::var(CALLER_UID_ENV).ok().as_deref()),
                is_root(),
            )?;
            refuse_macos(TOOL)?;
            Ok(plugin_toolkit::serde_json::to_string(&detail(Path::new(
                "/",
            ))?)?)
        })
        .op(UPDATE_OP, |args: DockerDaemonConfigUpdateArgs| async move {
            authorize_privileged(
                caller_uid(std::env::var(CALLER_UID_ENV).ok().as_deref()),
                is_root(),
            )?;
            refuse_macos(UPDATE_TOOL)?;
            Ok(plugin_toolkit::serde_json::to_string(
                &update(Path::new("/"), &args).await?,
            )?)
        })
}

pub fn detail(root: &Path) -> Result<DaemonConfigDetail> {
    let host = detect(root);
    let json = read_json(root)?;
    let (persisted_in, effective, conflicts) = match host {
        Host::Unraid => {
            let cfg = read_opt(root, UNRAID_CFG)?.unwrap_or_default();
            let (mirrors, insecure, _) = parse_opts(&opts_of(&cfg));
            let flags = flags_json(mirrors, insecure);
            let conflicts = conflicts(&json, &flags);
            let mut effective = json.clone();
            effective.extend(flags);
            (Some(format!("/{UNRAID_CFG}")), effective, conflicts)
        }
        Host::Standard(_) => (None, json.clone(), Vec::new()),
    };
    Ok(DaemonConfigDetail {
        host: host.as_str().to_owned(),
        path: format!("/{DAEMON_JSON}"),
        daemon_json: redacted(&json),
        persisted_in,
        effective: redacted(&effective),
        conflicts,
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
    /// Files written (or to write), with their full before and after text,
    /// secrets scrubbed.
    pub writes: Vec<FileWrite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backups: Vec<String>,
    /// `dockerd --validate` on the resulting daemon config, whenever anything
    /// is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validated: Option<String>,
    /// Unraid: managed keys set in both files with different values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<String>,
    /// Restarting stops every container; lists the running ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_warning: Option<String>,
    pub restarted: bool,
    /// The restart failed after the config was written; `backups` still hold
    /// the previous files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// **Update the Docker daemon config**: deep-merge `registry_mirrors` /
/// `insecure_registries` into `/etc/docker/daemon.json`, keeping every other
/// key. Validates the result (mirrors are http(s) URLs; an http mirror's
/// host:port must be an insecure registry), checks the resulting config with
/// `dockerd --validate` when dockerd is present, then backs each file up
/// (`daemon.json.bak-<unix nanos>`, newest 3 kept; `docker.cfg.bak`) and
/// writes atomically, rolling every file back if a write fails. On Unraid the
/// two keys persist as `DOCKER_OPTS` flags in `/boot/config/docker.cfg` and
/// are removed from `daemon.json`; refused when rc.docker does not source
/// `DOCKER_CFG` and pass `DOCKER_OPTS`. dockerd is restarted only with `restart` (it stops every
/// container). Unsupported on macOS (colima: `colima start --edit`). With
/// `dryRun`, returns the diff and the running containers a restart stops.
#[orca_tool(
    domain = "docker",
    verb = "daemon_config_update",
    local_only = true,
    role = "admin",
    execute_gated = false,
    reaches = ["privileged.apply"],
    dry_run_aware = true
)]
async fn docker_daemon_config_update(
    args: DockerDaemonConfigUpdateArgs,
    ctx: &ToolCtx,
) -> Result<DaemonConfigUpdateOutput> {
    let args = DockerDaemonConfigUpdateArgs {
        dry_run: args.dry_run || ctx.dry_run(),
        ..args
    };
    execute::require_admin(UPDATE_TOOL, ctx)?;
    refuse_macos(UPDATE_TOOL)?;
    if is_root() {
        return update(Path::new("/"), &args).await;
    }
    through_seam(UPDATE_OP, Some(&args)).await
}

fn require_patch(args: &DockerDaemonConfigUpdateArgs) -> Result<()> {
    if args.registry_mirrors.is_none() && args.insecure_registries.is_none() {
        bail!("{UPDATE_TOOL}: pass registry_mirrors and/or insecure_registries");
    }
    Ok(())
}

pub async fn update(
    root: &Path,
    args: &DockerDaemonConfigUpdateArgs,
) -> Result<DaemonConfigUpdateOutput> {
    let patch = DaemonConfigPatch {
        registry_mirrors: args.registry_mirrors.clone(),
        insecure_registries: args.insecure_registries.clone(),
    };
    require_patch(args)?;
    let plan = plan(root, &patch)?;
    let restart_cmd = if args.restart {
        Some(restart_command(plan.host)?)
    } else {
        None
    };
    let changes = diff(&plan.current, &plan.effective)
        .into_iter()
        .map(scrub_change)
        .collect();
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
        writes: plan.writes.iter().map(scrub_write).collect(),
        backups: Vec::new(),
        validated: None,
        conflicts: plan.conflicts.clone(),
        restart_warning,
        restarted: false,
        restart_error: None,
        warnings: Vec::new(),
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
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let (backups, validated, warnings) = apply(
        root,
        &plan.writes,
        plan.candidate.as_deref(),
        ts,
        dockerd_validate,
    )
    .await?;
    plugin_toolkit::tracing::info!(
        target: "docker::daemon_config",
        host = plan.host.as_str(),
        effective = %redacted(&plan.effective),
        "daemon config written"
    );
    out.backups = backups;
    out.validated = validated;
    out.warnings = warnings;
    if let Some(cmd) = restart_cmd {
        match run_restart(&cmd).await {
            Ok(_) => out.restarted = true,
            Err(e) => out.restart_error = Some(format!("{e:#}")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{admin, assert_admin_refusal, non_admins};
    use plugin_toolkit::reactor::block_on;
    use plugin_toolkit::serde_json::json;

    #[test]
    fn privileged_ops_need_root_and_a_caller_uid() {
        assert!(authorize_privileged(Some(999), true).is_ok());
        assert!(authorize_privileged(Some(0), true).is_ok());
        let err = authorize_privileged(Some(999), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("must run as root"), "{err}");
        let err = authorize_privileged(None, true).unwrap_err().to_string();
        assert!(err.contains(CALLER_UID_ENV), "{err}");
        assert_eq!(caller_uid(Some("999")), Some(999));
        for bad in [None, Some(""), Some("-1"), Some("orca"), Some("9 ")] {
            assert_eq!(caller_uid(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_privileged_op_set_is_closed_and_fails_closed() {
        let ops = privileged_ops();
        let r = block_on(ops.dispatch(r#"{"op":"write_file","payload":{"path":"/etc/shadow"}}"#));
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("unknown privileged op"));
        let r = block_on(
            ops.dispatch(r#"{"op":"daemon_config_update","payload":{"registry_mirrors":"x"}}"#),
        );
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("invalid payload"));
        if !is_root() {
            for req in [
                json!({"plugin": PLUGIN, "op": READ_OP}),
                json!({"plugin": PLUGIN, "op": UPDATE_OP, "payload": {"registry_mirrors": ["https://m"]}}),
            ] {
                let r = block_on(ops.dispatch(&req.to_string()));
                assert!(
                    r.error.unwrap_or_default().contains("must run as root"),
                    "{req}"
                );
            }
        }
    }

    #[test]
    fn update_args_round_trip_across_the_seam() {
        let args = DockerDaemonConfigUpdateArgs {
            registry_mirrors: Some(vec!["https://m.example".into()]),
            insecure_registries: None,
            restart: true,
            dry_run: true,
        };
        let v = plugin_toolkit::serde_json::to_value(&args).unwrap();
        let back: DockerDaemonConfigUpdateArgs = plugin_toolkit::serde_json::from_value(v).unwrap();
        assert_eq!(back.registry_mirrors, args.registry_mirrors);
        assert!(back.restart && back.dry_run);
        assert!(require_patch(&back).is_ok());
        let empty = DockerDaemonConfigUpdateArgs {
            registry_mirrors: None,
            insecure_registries: None,
            restart: false,
            dry_run: false,
        };
        assert!(require_patch(&empty).is_err());
    }

    #[test]
    fn update_output_round_trips_across_the_seam() {
        let t = tempfile::tempdir().unwrap();
        let out = block_on(update(
            t.path(),
            &DockerDaemonConfigUpdateArgs {
                registry_mirrors: Some(vec!["https://m.example".into()]),
                insecure_registries: None,
                restart: false,
                dry_run: true,
            },
        ))
        .unwrap();
        let text = plugin_toolkit::serde_json::to_string(&out).unwrap();
        let back: DaemonConfigUpdateOutput = plugin_toolkit::serde_json::from_str(&text).unwrap();
        assert!(back.dry_run);
        assert_eq!(back.writes.len(), out.writes.len());
        let detail = detail(t.path()).unwrap();
        let text = plugin_toolkit::serde_json::to_string(&detail).unwrap();
        let back: DaemonConfigDetail = plugin_toolkit::serde_json::from_str(&text).unwrap();
        assert_eq!(back.host, detail.host);
    }

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
        assert_eq!(diff(&again.current, &again.effective), []);
        assert_eq!(again.writes, []);
    }

    #[test]
    fn an_empty_list_removes_the_key() {
        let t = tempfile::tempdir().unwrap();
        put(
            t.path(),
            DAEMON_JSON,
            r#"{"registry-mirrors":["https://m"]}"#,
        );
        let p = plan(t.path(), &mirrors(&[], &[])).unwrap();
        let changes = diff(&p.current, &p.effective);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].key, MIRRORS);
        assert_eq!(changes[0].after, None);
        assert_eq!(p.writes[0].after, "");
    }

    #[test]
    fn shell_metacharacters_are_refused() {
        for bad in ["$(x)", "`x`", ";x", "${IFS}x"] {
            let t = tempfile::tempdir().unwrap();
            unraid(t.path(), WILLOW_CFG);
            let url = format!("https://m{bad}");
            assert!(plan(t.path(), &mirrors(&[&url], &[])).is_err(), "{url}");
            let reg = format!("m{bad}:5000");
            assert!(plan(t.path(), &mirrors(&[], &[&reg])).is_err(), "{reg}");
        }
        for word in ["$(x)", "`x`", "a;b", "${IFS}", "\"q", "'q", "a\\b", "a b"] {
            assert!(set_opts("", &[word.into()], &[]).is_err(), "{word}");
            assert!(set_opts("", &[], &[word.into()]).is_err(), "{word}");
        }
        assert!(set_opts("DOCKER_OPTS=\"--x=$(id)\"\n", &[], &[]).is_err());
        assert!(set_opts("", &["https://m".into()], &["10.0.0.0/8".into()]).is_ok());
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
        let (backups, validated, _) = block_on(apply(
            t.path(),
            &p.writes,
            p.candidate.as_deref(),
            42,
            |c| async move {
                assert!(c.exists());
                Ok("ok".into())
            },
        ))
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

        for ts in 43..48 {
            block_on(apply(t.path(), &p.writes, None, ts, |_| async {
                Ok(String::new())
            }))
            .unwrap();
        }
        let mut baks: Vec<_> = std::fs::read_dir(t.path().join("etc/docker"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".bak-"))
            .collect();
        baks.sort();
        assert_eq!(
            baks,
            [
                "daemon.json.bak-45",
                "daemon.json.bak-46",
                "daemon.json.bak-47"
            ]
        );
    }

    #[test]
    fn a_failed_second_write_rolls_back_the_first() {
        let t = tempfile::tempdir().unwrap();
        unraid(t.path(), "DOCKER_OPTS=\"\"\n");
        put(
            t.path(),
            DAEMON_JSON,
            r#"{"registry-mirrors":["https://old"]}"#,
        );
        let p = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap();
        assert_eq!(p.writes.len(), 2);
        let cfg = t.path().join(UNRAID_CFG);
        std::fs::remove_file(&cfg).unwrap();
        std::fs::create_dir(&cfg).unwrap();
        let err = block_on(apply(t.path(), &p.writes, None, 9, |_| async {
            Ok(String::new())
        }))
        .unwrap_err();
        assert!(err.to_string().ends_with("rolled back"), "{err}");
        assert_eq!(
            std::fs::read_to_string(t.path().join(DAEMON_JSON)).unwrap(),
            r#"{"registry-mirrors":["https://old"]}"#
        );
        assert!(!t.path().join("etc/docker/daemon.json.bak-9").exists());
    }

    #[test]
    fn writes_keep_the_original_mode_and_the_candidate_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        put(t.path(), DAEMON_JSON, NVIDIA);
        let json = t.path().join(DAEMON_JSON);
        std::fs::set_permissions(&json, std::fs::Permissions::from_mode(0o640)).unwrap();
        let p = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap();
        block_on(apply(
            t.path(),
            &p.writes,
            p.candidate.as_deref(),
            1,
            |c| async move {
                let mode = std::fs::metadata(&c).unwrap().permissions().mode() & 0o7777;
                assert_eq!(mode, 0o600);
                Ok("ok".into())
            },
        ))
        .unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&json), 0o640);

        let t = tempfile::tempdir().unwrap();
        let p = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap();
        block_on(apply(t.path(), &p.writes, None, 1, |_| async {
            Ok(String::new())
        }))
        .unwrap();
        assert_eq!(mode(&t.path().join(DAEMON_JSON)), 0o644);
    }

    #[test]
    fn credentials_are_refused_without_echoing_them() {
        for (m, i) in [
            (vec!["https://u:s3cret@m"], vec![]),
            (vec![], vec!["u:s3cret@m:5000"]),
        ] {
            let err = validate(&obj(
                json!({"registry-mirrors": m, "insecure-registries": i}),
            ))
            .unwrap_err()
            .to_string();
            assert!(err.contains("must not carry credentials"), "{err}");
            assert!(!err.contains("s3cret"), "{err}");
        }
        let err = validate(&obj(json!({"registry-mirrors": ["http://m:5000/t0ken"]})))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("'http://m:5000'") && !err.contains("t0ken"),
            "{err}"
        );
        let err = mirror_authority("ftp://m/t0ken").unwrap_err().to_string();
        assert!(!err.contains("t0ken"), "{err}");
    }

    #[test]
    fn a_symlinked_target_is_refused_at_plan_time() {
        let t = tempfile::tempdir().unwrap();
        put(t.path(), "elsewhere.json", NVIDIA);
        std::fs::create_dir_all(t.path().join("etc/docker")).unwrap();
        std::os::unix::fs::symlink(t.path().join("elsewhere.json"), t.path().join(DAEMON_JSON))
            .unwrap();
        let err = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap_err();
        assert!(err.to_string().contains("is a symlink"), "{err}");
        assert_eq!(
            std::fs::read_to_string(t.path().join("elsewhere.json")).unwrap(),
            NVIDIA
        );

        let t = tempfile::tempdir().unwrap();
        unraid(t.path(), "DOCKER_OPTS=\"\"\n");
        let cfg = t.path().join(UNRAID_CFG);
        std::fs::rename(&cfg, t.path().join("real.cfg")).unwrap();
        std::os::unix::fs::symlink(t.path().join("real.cfg"), &cfg).unwrap();
        let err = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap_err();
        assert!(err.to_string().contains("is a symlink"), "{err}");
    }

    #[test]
    fn a_symlink_swapped_in_after_planning_is_refused_at_write() {
        let t = tempfile::tempdir().unwrap();
        put(t.path(), "elsewhere.json", NVIDIA);
        put(t.path(), DAEMON_JSON, NVIDIA);
        let p = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap();
        std::fs::remove_file(t.path().join(DAEMON_JSON)).unwrap();
        std::os::unix::fs::symlink(t.path().join("elsewhere.json"), t.path().join(DAEMON_JSON))
            .unwrap();
        let err = block_on(apply(t.path(), &p.writes, None, 1, |_| async {
            Ok(String::new())
        }))
        .unwrap_err();
        assert!(err.to_string().contains("is a symlink"), "{err}");
    }

    #[test]
    fn a_failed_prune_is_a_warning_not_an_error() {
        let t = tempfile::tempdir().unwrap();
        put(t.path(), DAEMON_JSON, NVIDIA);
        let json = t.path().join(DAEMON_JSON);
        std::fs::create_dir(backup_path(&json, 1)).unwrap();
        for ts in [2, 3] {
            std::fs::write(backup_path(&json, ts), NVIDIA).unwrap();
        }
        let p = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap();
        let (backups, _, warnings) = block_on(apply(t.path(), &p.writes, None, 10, |_| async {
            Ok(String::new())
        }))
        .unwrap();
        assert_eq!(backups.len(), 1);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("failed to prune"), "{warnings:?}");
        assert_eq!(
            read_json(t.path()).unwrap()["registry-mirrors"],
            json!(["https://m"])
        );
    }

    #[test]
    fn an_exported_docker_opts_line_is_edited_in_place() {
        let cfg = "DOCKER_ENABLED=\"yes\"\nexport DOCKER_OPTS=\"--dns 10.0.0.1\"\nX=1\n";
        assert_eq!(opts_of(cfg), "--dns 10.0.0.1");
        assert_eq!(
            set_opts(cfg, &["https://m".to_owned()], &[]).unwrap(),
            "DOCKER_ENABLED=\"yes\"\nexport DOCKER_OPTS=\"--dns 10.0.0.1 --registry-mirror=https://m\"\nX=1\n"
        );
    }

    #[test]
    fn an_existing_backup_is_never_overwritten() {
        let t = tempfile::tempdir().unwrap();
        put(t.path(), DAEMON_JSON, NVIDIA);
        put(t.path(), "etc/docker/daemon.json.bak-5", "keep");
        let p = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap();
        assert!(
            block_on(apply(t.path(), &p.writes, None, 5, |_| async {
                Ok(String::new())
            }))
            .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(t.path().join("etc/docker/daemon.json.bak-5")).unwrap(),
            "keep"
        );
        assert_eq!(
            std::fs::read_to_string(t.path().join(DAEMON_JSON)).unwrap(),
            NVIDIA
        );
    }

    #[test]
    fn the_cfg_backup_is_replaced_whole_with_no_temp_left() {
        let t = tempfile::tempdir().unwrap();
        unraid(t.path(), "DOCKER_OPTS=\"\"\n");
        put(t.path(), "boot/config/docker.cfg.bak", "older");
        let p = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap();
        block_on(apply(t.path(), &p.writes, None, 1, |_| async {
            Ok(String::new())
        }))
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(t.path().join("boot/config/docker.cfg.bak")).unwrap(),
            "DOCKER_OPTS=\"\"\n"
        );
        let mut names: Vec<_> = std::fs::read_dir(t.path().join("boot/config"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["docker.cfg", "docker.cfg.bak"]);
    }

    #[test]
    fn a_commented_source_line_does_not_count() {
        assert!(sources_cfg(". $DOCKER_CFG\n"));
        assert!(!sources_cfg("# . $DOCKER_CFG\n"));
        assert!(!sources_cfg("   #source \"$DOCKER_CFG\"\n"));
    }

    #[test]
    fn an_unparseable_docker_opts_line_is_refused() {
        for cfg in [
            "DOCKER_OPTS=\"--dns 10.0.0.1\n--x\"\n",
            "DOCKER_OPTS='--dns\n",
            "  DOCKER_OPTS=\"open\n",
        ] {
            let t = tempfile::tempdir().unwrap();
            unraid(t.path(), cfg);
            let err = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap_err();
            assert!(
                err.to_string().contains("unterminated quote"),
                "{cfg:?}: {err}"
            );
        }
    }

    #[test]
    fn unraid_accepts_brackets_only_around_an_ipv6_host() {
        for (m, i) in [
            ("http://[fd00::1]:5000", "[fd00::1]:5000"),
            ("https://[fd00::1]/v2", "[fd00::1]"),
        ] {
            let t = tempfile::tempdir().unwrap();
            unraid(t.path(), "DOCKER_OPTS=\"\"\n");
            assert!(plan(t.path(), &mirrors(&[m], &[i])).is_ok(), "{m} {i}");
        }
        for (m, i) in [
            ("https://m[a]", "m:5000"),
            ("https://m", "[fd00::1"),
            ("https://m", "[nothex]:5000"),
            ("https://m", "[fd00::1]x"),
            ("https://m/[a]", "m:5000"),
            ("https://m", "[fd00::1]:"),
        ] {
            let t = tempfile::tempdir().unwrap();
            unraid(t.path(), "DOCKER_OPTS=\"\"\n");
            let err = plan(t.path(), &mirrors(&[m], &[i])).unwrap_err();
            assert!(err.to_string().contains("bracketed IPv6"), "{m} {i}: {err}");
        }
        let t = tempfile::tempdir().unwrap();
        assert!(plan(t.path(), &mirrors(&["https://m[a]"], &[])).is_ok());
    }

    #[test]
    fn a_failed_validation_writes_nothing() {
        let t = tempfile::tempdir().unwrap();
        put(t.path(), DAEMON_JSON, NVIDIA);
        let p = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap();
        let err = block_on(apply(
            t.path(),
            &p.writes,
            p.candidate.as_deref(),
            1,
            |_| async { bail!("bad key") },
        ))
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

    const WILLOW_CFG: &str = r#"DOCKER_ENABLED="yes"
DOCKER_IMAGE_FILE="/mnt/cache/system/docker/docker-dir"
DOCKER_IMAGE_SIZE="100"
DOCKER_APP_CONFIG_PATH="/mnt/user/appdata/"
DOCKER_APP_UNRAID_PATH=""
DOCKER_READMORE="no"
DOCKER_PID_LIMIT=""
DOCKER_NETWORK_TYPE="1"
DOCKER_CUSTOM_NETWORKS="br1 br2 wlan0 "
DOCKER_TIMEOUT="10"
DOCKER_LOG_ROTATION="yes"
DOCKER_LOG_SIZE="50m"
DOCKER_LOG_FILES="1"
DOCKER_AUTHORING_MODE="no"
DOCKER_USER_NETWORKS="remove"
DOCKER_BACKINGFS="native"
DOCKER_IMAGE_TYPE="folder"
"#;

    const WILLOW_RC: &str = r#"DOCKER_CFG="/boot/config/docker.cfg"
DOCKER_TIMEOUT=$(awk -F'"' '/^DOCKER_TIMEOUT=/{print $2}' $DOCKER_CFG 2>/dev/null)
docker_read_options(){
  if [[ -f $DOCKER_CFG ]]; then
    . $DOCKER_CFG
  fi
  DOCKER_OPTS="--log-level=fatal $DOCKER_OPTS"
}
docker_network_stop(){
  [[ -f $DOCKER_CFG ]] && . $DOCKER_CFG
}
start_docker(){
  nohup $UNSHARE --propagation slave -- $DOCKER -p $DOCKER_PIDFILE $DOCKER_OPTS >>$DOCKER_LOG 2>&1 &
}
"#;

    fn unraid(root: &Path, cfg: &str) {
        put(root, UNRAID_VERSION, "version=\"7.0.1\"\n");
        put(root, UNRAID_RC, WILLOW_RC);
        put(root, UNRAID_CFG, cfg);
    }

    #[test]
    fn willow_cfg_keeps_every_other_line_byte_for_byte() {
        let t = tempfile::tempdir().unwrap();
        unraid(t.path(), WILLOW_CFG);
        put(t.path(), DAEMON_JSON, NVIDIA);
        let p = plan(
            t.path(),
            &mirrors(&["http://10.0.0.10:5000"], &["10.0.0.10:5000"]),
        )
        .unwrap();
        let paths: Vec<_> = p.writes.iter().map(|w| w.path.as_str()).collect();
        assert_eq!(paths, ["/boot/config/docker.cfg"]);
        let after = &p.writes[0].after;
        let kept: Vec<_> = after
            .split_inclusive('\n')
            .filter(|l| !l.starts_with(OPTS_KEY))
            .collect();
        assert_eq!(kept.concat(), WILLOW_CFG);
        assert!(after.ends_with(
            "DOCKER_OPTS=\"--registry-mirror=http://10.0.0.10:5000 --insecure-registry=10.0.0.10:5000\"\n"
        ));

        let checked = block_on(apply(
            t.path(),
            &p.writes,
            p.candidate.as_deref(),
            3,
            |c| async move {
                let json: Value =
                    plugin_toolkit::serde_json::from_str(&std::fs::read_to_string(&c).unwrap())
                        .unwrap();
                assert_eq!(json["default-runtime"], "nvidia");
                assert_eq!(json[MIRRORS], json!(["http://10.0.0.10:5000"]));
                Ok("ok".into())
            },
        ))
        .unwrap();
        assert_eq!(checked.1.as_deref(), Some("ok"));
        assert_eq!(
            std::fs::read_to_string(t.path().join("boot/config/docker.cfg.bak")).unwrap(),
            WILLOW_CFG
        );
    }

    #[test]
    fn crlf_cfg_stays_crlf() {
        let t = tempfile::tempdir().unwrap();
        unraid(
            t.path(),
            "DOCKER_ENABLED=\"yes\"\r\nDOCKER_OPTS=\"--dns 10.0.0.1\"\r\n",
        );
        let p = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap();
        assert_eq!(
            p.writes[0].after,
            "DOCKER_ENABLED=\"yes\"\r\nDOCKER_OPTS=\"--dns 10.0.0.1 --registry-mirror=https://m\"\r\n"
        );
    }

    #[test]
    fn differing_values_in_both_files_are_a_conflict() {
        let t = tempfile::tempdir().unwrap();
        unraid(t.path(), "DOCKER_OPTS=\"--registry-mirror=https://a\"\n");
        put(
            t.path(),
            DAEMON_JSON,
            r#"{"registry-mirrors":["https://b"]}"#,
        );
        let d = detail(t.path()).unwrap();
        assert_eq!(d.conflicts.len(), 1);
        assert!(d.conflicts[0].contains(MIRRORS), "{:?}", d.conflicts);
        let p = plan(t.path(), &mirrors(&["https://a"], &[])).unwrap();
        assert_eq!(p.conflicts, d.conflicts);

        put(
            t.path(),
            DAEMON_JSON,
            r#"{"registry-mirrors":["https://a"]}"#,
        );
        assert_eq!(detail(t.path()).unwrap().conflicts, Vec::<String>::new());
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
            ["/etc/docker/daemon.json", "/boot/config/docker.cfg"]
        );
        assert_eq!(
            p.writes[1].after,
            "DOCKER_ENABLED=\"yes\"\nDOCKER_OPTS=\"--storage-driver=overlay2 --registry-mirror=http://10.0.0.10:5000 --insecure-registry=10.0.0.10:5000\"\n"
        );
        let json: Value = plugin_toolkit::serde_json::from_str(&p.writes[0].after).unwrap();
        assert_eq!(json, json!({"runtimes": {"nvidia": {}}}));
        assert_eq!(p.effective[MIRRORS], json!(["http://10.0.0.10:5000"]));
        assert_eq!(p.current[MIRRORS], json!(["https://old"]));

        let (_, validated, _) = block_on(apply(
            t.path(),
            &p.writes,
            p.candidate.as_deref(),
            7,
            |_| async { Ok("ok".into()) },
        ))
        .unwrap();
        assert_eq!(validated.as_deref(), Some("ok"));
        assert!(t.path().join("boot/config/docker.cfg.bak").exists());
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
        put(t.path(), UNRAID_CFG, "DOCKER_ENABLED=\"yes\"\n");
        let err = plan(t.path(), &mirrors(&["https://m"], &[])).unwrap_err();
        assert!(err.to_string().contains("cannot be persisted"), "{err}");

        let t = tempfile::tempdir().unwrap();
        put(t.path(), UNRAID_VERSION, "version=\"7.0.1\"\n");
        put(t.path(), UNRAID_RC, WILLOW_RC);
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
        assert_eq!(set_opts("", &[], &[]).unwrap(), "DOCKER_OPTS=\"\"\n");

        let (m, _, rest) = parse_opts("--registry-mirror --dns 10.0.0.1");
        assert!(m.is_empty());
        assert_eq!(rest, ["--dns", "10.0.0.1"]);

        let cfg =
            "DOCKER_OPTS=\"--registry-mirror=https://a\"\nX=1\nDOCKER_OPTS=\"--dns 10.0.0.1\"\n";
        assert_eq!(opts_of(cfg), "--dns 10.0.0.1");
        assert_eq!(
            set_opts(cfg, &["https://b".into()], &[]).unwrap(),
            "DOCKER_OPTS=\"--dns 10.0.0.1 --registry-mirror=https://b\"\nX=1\n"
        );
    }

    #[test]
    fn restart_follows_the_host() {
        assert_eq!(
            restart_command(Host::Unraid).unwrap()[0],
            "/etc/rc.d/rc.docker"
        );
        let systemd = restart_command(Host::Standard(Init::Systemd)).unwrap();
        assert!(SYSTEMCTL.contains(&systemd[0]), "{systemd:?}");
        assert_eq!(systemd[1..], ["restart", "docker"]);
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
