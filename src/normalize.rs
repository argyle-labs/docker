#![allow(clippy::disallowed_types)]

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use bollard::Docker;
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{Map, Value};

use crate::lint::{block_service, indent_of, is_content};
use crate::policy::{self, Grant};
use crate::stacks::{self, StackRow};

pub const ICON_LABEL: &str = "net.unraid.docker.icon";
pub const WEBUI_LABEL: &str = "net.unraid.docker.webui";
const CONTAINER_NAME: &str = "container_name";
const ICON_BASE: &str = "https://gitea.scottkey.me/argyle-labs";
const ICON_PATH: &str = "raw/branch/main/assets/icon-256.png";
const PROBE_ATTEMPTS: usize = 3;
const PROBE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(200);
const ALIASES: &[(&str, &str)] = &[
    ("act_runner", "gitea"),
    ("gitea-runner", "gitea"),
    ("proxmox-backup-server", "pbs"),
    ("faster-whisper", "whisper-ai"),
    ("wyoming-whisper", "whisper-ai"),
    ("whisper", "whisper-ai"),
];
const ARCH_SUFFIXES: &[&str] = &["-linux-amd64", "-linux-arm64", "-amd64", "-arm64"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct Change {
    pub service: String,
    pub key: String,
    pub value: String,
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}={}", self.service, self.key, self.value)
    }
}

pub struct Plan {
    pub before: String,
    pub after: String,
    pub changes: Vec<Change>,
    pub warnings: Vec<String>,
    /// Contract items orca cannot fill in; they do not block the rewrite.
    pub unrepaired: Vec<String>,
    cfg: Value,
}

impl Plan {
    pub fn report(&self) -> Vec<String> {
        self.changes
            .iter()
            .map(ToString::to_string)
            .chain(self.warnings.iter().map(|w| format!("warning: {w}")))
            .chain(self.unrepaired.iter().map(|u| format!("unrepaired: {u}")))
            .collect()
    }
}

fn str_at<'a>(svc: &'a Value, key: &str) -> Option<&'a str> {
    svc.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn has_label(svc: &Value, key: &str) -> bool {
    match svc.get("labels") {
        Some(Value::Object(m)) => m.contains_key(key),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .any(|l| l.split('=').next() == Some(key)),
        _ => false,
    }
}

fn many(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Number(n)) => n.as_u64().is_none_or(|n| n > 1),
        Some(Value::String(s)) => s.trim().parse::<u64>().map_or(true, |n| n > 1),
        Some(_) => true,
    }
}

fn replicated(svc: &Value) -> bool {
    many(svc.get("scale")) || many(svc.pointer("/deploy/replicas"))
}

fn first_port(svc: &Value) -> Option<u64> {
    svc.get("ports")?.as_array()?.iter().find_map(|p| match p {
        Value::Object(m) => m
            .get("published")
            .filter(|v| !v.is_null())
            .and(m.get("target"))
            .and_then(|t| t.as_u64().or_else(|| t.as_str()?.parse().ok())),
        Value::String(s) => {
            let target = s.rsplit(':').next()?.split('/').next()?;
            s.contains(':').then(|| target.parse().ok()).flatten()
        }
        _ => None,
    })
}

fn valid_app(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

fn image_app(image: &str) -> String {
    let i = image.split('@').next().unwrap_or(image);
    let last = i.rsplit('/').next().unwrap_or(i);
    let name = last.split(':').next().unwrap_or(last);
    ARCH_SUFFIXES
        .iter()
        .find_map(|s| name.strip_suffix(s))
        .unwrap_or(name)
        .to_string()
}

pub fn candidates(stack: &str, service: &str, image: Option<&str>) -> Vec<String> {
    let from_image = image.map(image_app);
    let mut out: Vec<String> = Vec::new();
    for c in from_image
        .into_iter()
        .chain([service.to_string(), stack.to_string()])
    {
        let c = ALIASES
            .iter()
            .find(|(from, _)| *from == c)
            .map_or(c.clone(), |(_, to)| (*to).to_string());
        if valid_app(&c) && !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

pub fn icon_url(app: &str) -> String {
    format!("{ICON_BASE}/{app}/{ICON_PATH}")
}

fn probe(url: &str) -> Option<bool> {
    let req = plugin_toolkit::abi::HttpRequest {
        method: "HEAD".into(),
        url: url.into(),
        headers: Vec::new(),
        body: Vec::new(),
        timeout_ms: Some(5_000),
        insecure: false,
        max_body_bytes: Some(0),
        body_b64: true,
        follow_redirects: None,
        connect_timeout_ms: Some(2_000),
        retry: Some(false),
    };
    for attempt in 0..PROBE_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(PROBE_BACKOFF * u32::try_from(attempt).unwrap_or(1));
        }
        match plugin_toolkit::capsink::http_request(&req) {
            Ok(r) if r.status < 500 => return Some((200..300).contains(&r.status)),
            Err(e) if e.to_string().contains("capability unavailable") => return None,
            _ => {}
        }
    }
    None
}

fn icon_cache() -> &'static Mutex<HashMap<String, bool>> {
    static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

fn has_icon(app: &str, probe: &dyn Fn(&str) -> Option<bool>) -> bool {
    if let Some(hit) = icon_cache().lock().ok().and_then(|c| c.get(app).copied()) {
        return hit;
    }
    let Some(found) = probe(&icon_url(app)) else {
        return false;
    };
    if let Ok(mut c) = icon_cache().lock() {
        c.insert(app.to_string(), found);
    }
    found
}

pub fn icon_for(candidates: &[String]) -> Option<String> {
    candidates
        .iter()
        .find(|c| has_icon(c, &probe))
        .map(|c| icon_url(c))
}

pub fn is_unraid() -> bool {
    crate::daemon_config::detect(std::path::Path::new("/")) == crate::daemon_config::Host::Unraid
}

pub fn plan(
    stack: &str,
    cfg: &Value,
    naming: bool,
    unraid: bool,
    icon: &dyn Fn(&[String]) -> Option<String>,
) -> (Vec<Change>, Vec<String>) {
    let Some(services) = cfg.get("services").and_then(Value::as_object) else {
        return (Vec::new(), Vec::new());
    };
    let single = services.len() == 1;
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for (name, svc) in services {
        let change = |key: &str, value: String| Change {
            service: name.clone(),
            key: key.to_string(),
            value,
        };
        if str_at(svc, CONTAINER_NAME).is_none() {
            if !naming {
                warnings.push(format!(
                    "{name}: container_name not set: no engine connection to check the name is free"
                ));
            } else if replicated(svc) {
                warnings.push(format!(
                    "{name}: container_name not set: the service runs replicas"
                ));
            } else {
                let value = if single { stack } else { name };
                out.push(change(CONTAINER_NAME, value.to_string()));
            }
        }
        if !unraid {
            continue;
        }
        if !has_label(svc, ICON_LABEL)
            && let Some(url) = icon(&candidates(stack, name, str_at(svc, "image")))
        {
            out.push(change(ICON_LABEL, url));
        }
        if !has_label(svc, WEBUI_LABEL)
            && let Some(port) = first_port(svc)
        {
            out.push(change(WEBUI_LABEL, format!("http://[IP]:[PORT:{port}]/")));
        }
    }
    (out, warnings)
}

pub const TZ_KEY: &str = "TZ";

/// Whether `kv` (`KEY=value`) sets `TZ`, matched case-insensitively.
fn sets_tz(kv: &str) -> bool {
    kv.split_once('=')
        .is_some_and(|(k, v)| k.eq_ignore_ascii_case(TZ_KEY) && !v.is_empty())
}
pub const HEALTHCHECK_KEY: &str = "healthcheck";
/// `$$` keeps compose from interpolating, so the shell expands the
/// container's own env; the defaults mirror the postgres image entrypoint.
const PG_ISREADY: &[&str] = &[
    "CMD-SHELL",
    r#"pg_isready -h 127.0.0.1 -p "$${PGPORT:-5432}" -U "$${POSTGRES_USER:-postgres}" -d "$${POSTGRES_DB:-$${POSTGRES_USER:-postgres}}""#,
];
/// Timing for injected checks; `start_period` covers a slow first init.
const HEALTHCHECK_TIMING: &[(&str, &str)] = &[
    ("interval", "30s"),
    ("timeout", "5s"),
    ("retries", "5"),
    ("start_period", "60s"),
];
/// Checks for images that ship no `HEALTHCHECK`, keyed by image name.
const KNOWN_HEALTHCHECKS: &[(&str, &[&str])] = &[
    ("postgres", PG_ISREADY),
    ("pgvecto-rs", PG_ISREADY),
    ("ollama", &["CMD", "ollama", "list"]),
];

/// Password envs of the Bitnami images; the official images take only
/// `--requirepass`.
const REDIS_PASSWORD_ENVS: &[&str] = &["REDIS_PASSWORD", "VALKEY_PASSWORD"];

/// The env var `token` references, in any of `$V`, `${V}`, `$$V`, `$${V}`.
fn env_ref(token: &str) -> Option<&str> {
    let t = token.trim_matches(|c| c == '"' || c == '\'');
    let t = t.strip_prefix("$$").or_else(|| t.strip_prefix('$'))?;
    let t = t
        .strip_prefix('{')
        .and_then(|t| t.strip_suffix('}'))
        .unwrap_or(t);
    let valid = !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    valid.then_some(t)
}

/// The value `svc` sets for env `key`, from `environment` or an `env_file`;
/// `Err` names an `env_file` that could not be read.
fn env_value(
    svc: &Value,
    contract: &Contract,
    key: &str,
) -> std::result::Result<Option<String>, String> {
    let env = match svc.get("environment") {
        Some(Value::Object(m)) => m.get(key).and_then(Value::as_str).map(str::to_string),
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).find_map(|kv| {
            kv.strip_prefix(key)
                .and_then(|r| r.strip_prefix('='))
                .map(str::to_string)
        }),
        _ => None,
    };
    if env.as_deref().is_some_and(|v| !v.is_empty()) {
        return Ok(env);
    }
    for (path, _) in env_file_paths(svc) {
        match contract.env_files.get(&path) {
            Some(Ok(text)) => {
                if let Some((_, v)) = stacks::env_pairs(text)
                    .into_iter()
                    .find(|(k, v)| k == key && !v.is_empty())
                {
                    return Ok(Some(v));
                }
            }
            Some(Err(why)) => return Err(format!("env_file '{path}' {why}")),
            None => return Err(format!("env_file '{path}' was not read")),
        }
    }
    Ok(None)
}

/// A redis/valkey check that fails unless the reply is `PONG`; with auth on,
/// `ping` prints NOAUTH yet exits 0. The password is read from the
/// container's env at runtime, never written into compose.
fn redis_check(
    svc: &Value,
    contract: &Contract,
    cli: &str,
) -> std::result::Result<Vec<String>, String> {
    let command = match svc.get("command") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    };
    let mut tokens = command.split_whitespace();
    let pass = tokens
        .by_ref()
        .position(|t| t.trim_start_matches('-') == "requirepass")
        .map(|_| tokens.next().unwrap_or(""));
    let var = match pass {
        Some(token) => match env_ref(token) {
            Some(var) if env_value(svc, contract, var)?.is_some() => Some(var.to_string()),
            _ => {
                return Err(
                    "requirepass is not set from a container env var the check can read"
                        .to_string(),
                );
            }
        },
        None => {
            let mut found = None;
            for key in REDIS_PASSWORD_ENVS {
                if env_value(svc, contract, key)?.is_some() {
                    found = Some(key.to_string());
                    break;
                }
            }
            found
        }
    };
    let auth = var
        .map(|v| format!(r#"REDISCLI_AUTH="$${{{v}}}" VALKEYCLI_AUTH="$${{{v}}}" "#))
        .unwrap_or_default();
    Ok(vec![
        "CMD-SHELL".to_string(),
        format!("{auth}{cli} ping | grep -q PONG"),
    ])
}

/// What the manageability contract repair needs from the host.
#[derive(Debug, Default)]
pub struct Contract {
    pub tz: Option<String>,
    /// Per image reference: whether the image declares its own healthcheck.
    /// An image missing here could not be inspected.
    pub image_health: HashMap<String, bool>,
    /// Image references whose config sets a non-empty `TZ`.
    pub image_tz: std::collections::HashSet<String>,
    /// Image references whose inspect failed, with a credential-free reason.
    pub image_errors: HashMap<String, String>,
    /// No Docker connection, so no image could be inspected.
    pub docker_unavailable: bool,
    /// Per `env_file` path as the config names it: its text, or why it
    /// could not be read.
    pub env_files: HashMap<String, std::result::Result<String, String>>,
}

/// The `env_file` paths of `svc`, in both the string and list forms, and
/// whether compose requires each.
fn env_file_paths(svc: &Value) -> Vec<(String, bool)> {
    let one = |v: &Value| match v {
        Value::String(s) => Some((s.clone(), true)),
        Value::Object(m) => m.get("path").and_then(Value::as_str).map(|p| {
            let required = m.get("required").and_then(Value::as_bool).unwrap_or(true);
            (p.to_string(), required)
        }),
        _ => None,
    };
    match svc.get("env_file") {
        Some(Value::Array(a)) => a.iter().filter_map(one).collect(),
        Some(v) => one(v).into_iter().collect(),
        None => Vec::new(),
    }
}

/// The text of every `env_file` in `cfg`, read relative to the project `dir`
/// without leaving it.
fn read_env_files(
    dir: Option<&stacks::StackDir>,
    cfg: &Value,
) -> HashMap<String, std::result::Result<String, String>> {
    let mut out = HashMap::new();
    let services = cfg.get("services").and_then(Value::as_object);
    for svc in services.into_iter().flat_map(|s| s.values()) {
        for (path, required) in env_file_paths(svc) {
            if out.contains_key(&path) {
                continue;
            }
            let read = match dir {
                None => Err("no project dir to read it from".to_string()),
                Some(d) => {
                    let p = std::path::Path::new(&path);
                    match p
                        .strip_prefix(d.path())
                        .ok()
                        .or(p.is_relative().then_some(p))
                    {
                        None => Err("outside the project dir".to_string()),
                        Some(rel) => match d.read_rel(rel) {
                            Ok(Some(text)) => Ok(text),
                            Ok(None) if !required => Ok(String::new()),
                            Ok(None) => Err("does not exist".to_string()),
                            Err(e) => Err(format!("{e:#}")),
                        },
                    }
                }
            };
            out.insert(path, read);
        }
    }
    out
}

/// The docker host's IANA timezone, in order: dockerd's `TZ` or
/// `/etc/timezone`, the `zoneinfo/` target of the `/etc/localtime` symlink,
/// Unraid's `/boot/config/ident.cfg` `timeZone`. Host files are read through
/// dockerd's `/proc/<pid>/root`; in a container that cannot see dockerd its
/// own files are not the host's, so the zone is unknown. A localtime of UTC
/// yields to ident.cfg, since Unraid leaves it UTC whatever its zone.
pub fn host_tz(proc: &impl crate::mounts::Proc) -> Option<String> {
    let pid = crate::mounts::dockerd_pid(proc);
    let root = match pid {
        Some(pid) => format!("/proc/{pid}/root"),
        None if proc.exists("/.dockerenv") || proc.exists("/run/.containerenv") => return None,
        None => String::new(),
    };
    let valid = |z: &str| {
        let z = z.trim().trim_start_matches(':');
        let named = !z.is_empty()
            && z.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_+-".contains(c))
            });
        (named
            && (proc.exists(&format!("{root}/usr/share/zoneinfo/{z}"))
                || proc.exists(&format!("/usr/share/zoneinfo/{z}"))))
        .then(|| z.to_string())
    };
    let env = pid
        .and_then(|pid| proc.read(&format!("/proc/{pid}/environ")).ok())
        .and_then(|e| {
            e.split('\0')
                .find_map(|kv| kv.strip_prefix("TZ="))
                .and_then(valid)
        });
    if let Some(z) = env.or_else(|| {
        proc.read(&format!("{root}/etc/timezone"))
            .ok()
            .and_then(|s| valid(&s))
    }) {
        return Some(z);
    }
    let link = proc
        .readlink(&format!("{root}/etc/localtime"))
        .ok()
        .and_then(|l| l.split_once("zoneinfo/").and_then(|(_, z)| valid(z)));
    let ident = || {
        proc.read(&format!("{root}/boot/config/ident.cfg"))
            .ok()?
            .lines()
            .find_map(|l| l.trim().strip_prefix("timeZone="))
            .and_then(|v| valid(v.trim().trim_matches('"')))
    };
    match link {
        Some(z) if !matches!(z.as_str(), "UTC" | "Etc/UTC") => Some(z),
        utc => ident().or(utc),
    }
}

/// Whether `svc` already sets a timezone; `Err` names an `env_file` that
/// could not be read, so whether it sets `TZ` is unknown.
fn has_tz(svc: &Value, contract: &Contract) -> std::result::Result<bool, String> {
    let set = |v: &str| !v.is_empty();
    let env = match svc.get("environment") {
        Some(Value::Object(m)) => m
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case(TZ_KEY) && v.as_str().is_some_and(set)),
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).any(sets_tz),
        _ => false,
    };
    let localtime = svc
        .get("volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|v| match v {
            Value::Object(m) => m.get("target").and_then(Value::as_str) == Some("/etc/localtime"),
            Value::String(s) => s.split(':').nth(1) == Some("/etc/localtime"),
            _ => false,
        });
    if env || localtime || str_at(svc, "image").is_some_and(|i| contract.image_tz.contains(i)) {
        return Ok(true);
    }
    for (path, _) in env_file_paths(svc) {
        match contract.env_files.get(&path) {
            Some(Ok(text)) => {
                if stacks::env_pairs(text)
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case(TZ_KEY) && set(v))
                {
                    return Ok(true);
                }
            }
            Some(Err(why)) => return Err(format!("env_file '{path}' {why}")),
            None => return Err(format!("env_file '{path}' was not read")),
        }
    }
    Ok(false)
}

/// The `tz` and `healthcheck` items of `docker.manageability_audit`'s
/// contract each service of `cfg` lacks, and the ones orca cannot fill in.
/// A service with any `healthcheck` key, `disable` included, is left alone.
pub fn contract_plan(cfg: &Value, contract: &Contract) -> (Vec<Change>, Vec<String>) {
    let Some(services) = cfg.get("services").and_then(Value::as_object) else {
        return (Vec::new(), Vec::new());
    };
    let mut out = Vec::new();
    let mut unrepaired = Vec::new();
    for (name, svc) in services {
        let change = |key: &str, value: String| Change {
            service: name.clone(),
            key: key.to_string(),
            value,
        };
        let image = str_at(svc, "image");
        let uninspectable = image.and_then(|i| {
            if contract.docker_unavailable {
                Some(format!("docker unavailable; image {i} not inspectable"))
            } else {
                contract.image_errors.get(i).map(|why| {
                    format!("image {i} not inspectable ({why}); pull it and rerun normalize")
                })
            }
        });
        let unknown = |item: &str, why: String| format!("{name}: {item}: {why}");
        match has_tz(svc, contract) {
            Ok(true) => {}
            Ok(false) => match (uninspectable.clone(), &contract.tz) {
                (Some(u), _) => unrepaired.push(unknown("tz", u)),
                (None, Some(tz)) => out.push(change(TZ_KEY, tz.clone())),
                (None, None) => unrepaired.push(format!(
                    "{name}: tz: host timezone unknown; set TZ in the compose file"
                )),
            },
            Err(why) => unrepaired.push(format!(
                "{name}: tz: {why}, so whether it sets TZ is unknown; set TZ in the compose file"
            )),
        }
        if svc.get(HEALTHCHECK_KEY).is_some() {
            continue;
        }
        if let Some(u) = uninspectable {
            unrepaired.push(unknown("healthcheck", u));
            continue;
        }
        if image.and_then(|i| contract.image_health.get(i)) == Some(&true) {
            continue;
        }
        let app = image.map(image_app);
        let known = match app.as_deref() {
            Some(app @ ("redis" | "valkey")) => {
                match redis_check(svc, contract, &format!("{app}-cli")) {
                    Ok(test) => Some(test),
                    Err(why) => {
                        unrepaired.push(format!(
                            "{name}: healthcheck: {why}; set one in the compose file"
                        ));
                        continue;
                    }
                }
            }
            app => app.and_then(|app| {
                KNOWN_HEALTHCHECKS
                    .iter()
                    .find(|(k, _)| *k == app)
                    .map(|(_, t)| t.iter().map(|s| s.to_string()).collect())
            }),
        };
        match known {
            Some(test) => out.push(change(
                HEALTHCHECK_KEY,
                plugin_toolkit::serde_json::to_string(&test).unwrap_or_default(),
            )),
            None => unrepaired.push(format!(
                "{name}: healthcheck: none known for image '{}'; set one in the compose file",
                image.unwrap_or("(built)")
            )),
        }
    }
    (out, unrepaired)
}

/// The reason an image inspect failed, built only from the status so no
/// registry detail or credential reaches the report.
fn inspect_reason(e: &bollard::errors::Error) -> String {
    match e {
        bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        } => "not present locally".to_string(),
        bollard::errors::Error::DockerResponseServerError { status_code, .. } => {
            format!("docker returned HTTP {status_code}")
        }
        _ => "docker request failed".to_string(),
    }
}

/// Per inspected image: whether it declares a healthcheck, the images whose
/// config sets `TZ`, and the images that could not be inspected.
async fn image_facts(
    docker: &Docker,
    cfg: &Value,
) -> (
    HashMap<String, bool>,
    std::collections::HashSet<String>,
    HashMap<String, String>,
) {
    let images: std::collections::BTreeSet<&str> = cfg
        .get("services")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|s| s.values())
        .filter_map(|svc| str_at(svc, "image"))
        .collect();
    let mut out = HashMap::new();
    let mut tz = std::collections::HashSet::new();
    let mut errors = HashMap::new();
    for image in images {
        let info = match docker.inspect_image(image).await {
            Ok(info) => info,
            Err(e) => {
                errors.insert(image.to_string(), inspect_reason(&e));
                continue;
            }
        };
        let config = info.config.unwrap_or_default();
        if config.env.iter().flatten().any(|kv| sets_tz(kv)) {
            tz.insert(image.to_string());
        }
        let own = config
            .healthcheck
            .and_then(|h| h.test)
            .and_then(|t| t.into_iter().next())
            .is_some_and(|kind| kind != "NONE");
        out.insert(image.to_string(), own);
    }
    (out, tz, errors)
}

fn quoted(v: &str) -> Result<String> {
    if v.chars().any(char::is_control) {
        bail!("value holds a control character");
    }
    Ok(format!(
        "\"{}\"",
        v.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn set_name(lines: &mut Vec<String>, c: &Change) -> Result<()> {
    let (header, end, child) = block_service(lines, &c.service).map_err(|e| anyhow!(e))?;
    let line = format!(
        "{}{CONTAINER_NAME}: {}",
        " ".repeat(child),
        quoted(&c.value)?
    );
    match (header + 1..end).find(|&i| {
        indent_of(&lines[i]) == child
            && lines[i]
                .trim_start()
                .starts_with(&format!("{CONTAINER_NAME}:"))
    }) {
        Some(i) => lines[i] = line,
        None => lines.insert(header + 1, line),
    }
    Ok(())
}

fn find_key(lines: &[String], header: usize, end: usize, child: usize, key: &str) -> Option<usize> {
    let prefix = format!("{key}:");
    (header + 1..end)
        .find(|&i| indent_of(&lines[i]) == child && lines[i].trim_start().starts_with(&prefix))
}

fn set_healthcheck(lines: &mut Vec<String>, c: &Change) -> Result<()> {
    let (header, end, child) = block_service(lines, &c.service).map_err(|e| anyhow!(e))?;
    if find_key(lines, header, end, child, HEALTHCHECK_KEY).is_some() {
        bail!("the compose file already sets a healthcheck");
    }
    let pad = " ".repeat(child);
    lines.insert(header + 1, format!("{pad}{HEALTHCHECK_KEY}:"));
    lines.insert(header + 2, format!("{pad}  test: {}", c.value));
    for (i, (k, v)) in HEALTHCHECK_TIMING.iter().enumerate() {
        lines.insert(header + 3 + i, format!("{pad}  {k}: {v}"));
    }
    Ok(())
}

fn set_label(lines: &mut Vec<String>, c: &Change) -> Result<()> {
    set_entry(lines, "labels", c)
}

fn set_entry(lines: &mut Vec<String>, block: &str, c: &Change) -> Result<()> {
    let (header, end, child) = block_service(lines, &c.service).map_err(|e| anyhow!(e))?;
    let pad = " ".repeat(child);
    let Some(at) = find_key(lines, header, end, child, block) else {
        let line = format!("{pad}  {}: {}", c.key, quoted(&c.value)?);
        lines.insert(header + 1, format!("{pad}{block}:"));
        lines.insert(header + 2, line);
        return Ok(());
    };
    let rest = lines[at]
        .trim_start()
        .trim_start_matches(&format!("{block}:"))
        .split('#')
        .next()
        .unwrap_or_default()
        .trim();
    if !rest.is_empty() {
        bail!("{block} are written in flow style");
    }
    let next = lines[at + 1..end].iter().find(|l| is_content(l));
    let (inner, list) = match next {
        Some(l) if indent_of(l) > child => (indent_of(l), l.trim_start().starts_with('-')),
        _ => (child + 2, false),
    };
    let pad = " ".repeat(inner);
    let line = if list {
        format!("{pad}- {}", quoted(&format!("{}={}", c.key, c.value))?)
    } else {
        format!("{pad}{}: {}", c.key, quoted(&c.value)?)
    };
    lines.insert(at + 1, line);
    Ok(())
}

pub fn apply(yaml: &str, changes: &[Change]) -> (String, Vec<Change>, Vec<String>) {
    let mut lines: Vec<String> = yaml.lines().map(str::to_string).collect();
    let mut applied = Vec::new();
    let mut warnings = Vec::new();
    for c in changes {
        let mut next = lines.clone();
        let done = match c.key.as_str() {
            CONTAINER_NAME => set_name(&mut next, c),
            TZ_KEY => set_entry(&mut next, "environment", c),
            HEALTHCHECK_KEY => set_healthcheck(&mut next, c),
            _ => set_label(&mut next, c),
        };
        match done {
            Ok(()) => {
                lines = next;
                applied.push(c.clone());
            }
            Err(e) => warnings.push(format!("{}: {} skipped: {e}", c.service, c.key)),
        }
    }
    let mut out = lines.join("\n");
    if yaml.ends_with('\n') {
        out.push('\n');
    }
    (out, applied, warnings)
}

pub fn rebind(allow: &mut [Grant], before: &Value, changes: &[Change]) {
    let mut after = before.clone();
    for c in changes {
        let Some(svc) = after.pointer_mut(&format!("/services/{}", c.service)) else {
            continue;
        };
        let block = match c.key.as_str() {
            CONTAINER_NAME => {
                svc[CONTAINER_NAME] = Value::String(c.value.clone());
                continue;
            }
            HEALTHCHECK_KEY => {
                let test = plugin_toolkit::serde_json::from_str(&c.value).unwrap_or(Value::Null);
                svc[HEALTHCHECK_KEY] = plugin_toolkit::serde_json::json!({ "test": test });
                continue;
            }
            TZ_KEY => "environment",
            _ => "labels",
        };
        if !svc.get(block).is_some_and(Value::is_object) {
            svc[block] = Value::Object(Map::new());
        }
        svc[block][&c.key] = Value::String(c.value.clone());
    }
    let (old, new) = (policy::digests(before), policy::digests(&after));
    for g in allow.iter_mut() {
        if old.get(&g.service) == Some(&g.definition)
            && let Some(d) = new.get(&g.service)
        {
            g.definition = d.clone();
        }
    }
}

pub async fn collision(docker: &Docker, project: &str, name: &str) -> Option<String> {
    match docker.inspect_container(name, None).await {
        Ok(info) => {
            let owner = info
                .config
                .as_ref()
                .and_then(|c| c.labels.as_ref())
                .and_then(|l| l.get(crate::prune::COMPOSE_PROJECT_LABEL));
            (owner.map(String::as_str) != Some(project)).then(|| {
                format!("container name '{name}' is already used on this host outside stack project '{project}'; set container_name in the compose file")
            })
        }
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => None,
        Err(e) => Some(format!("check container name '{name}': {e}")),
    }
}

/// `repair_contract` adds the `contract_plan` repairs; only the explicit
/// stack `normalize` action sets it, so deploy/set/adopt never inject them.
async fn plan_text(
    name: &str,
    before: String,
    cfg: Value,
    docker: Option<&Docker>,
    repair_contract: bool,
    dir: Option<&stacks::StackDir>,
) -> Plan {
    let (mut planned, mut warnings) = plan(name, &cfg, docker.is_some(), is_unraid(), &icon_for);
    let mut unrepaired = Vec::new();
    if repair_contract {
        let (image_health, image_tz, image_errors) = match docker {
            Some(d) => image_facts(d, &cfg).await,
            None => Default::default(),
        };
        let contract = Contract {
            tz: host_tz(&crate::mounts::HostProc),
            image_health,
            image_tz,
            image_errors,
            docker_unavailable: docker.is_none(),
            env_files: read_env_files(dir, &cfg),
        };
        let (repairs, missing) = contract_plan(&cfg, &contract);
        planned.extend(repairs);
        unrepaired = missing;
    }
    let project = cfg
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(name)
        .to_string();
    let mut free = Vec::new();
    for c in planned {
        if c.key == CONTAINER_NAME
            && let Some(docker) = docker
            && let Some(why) = collision(docker, &project, &c.value).await
        {
            warnings.push(format!("{}: {why}", c.service));
            continue;
        }
        free.push(c);
    }
    let (after, changes, skipped) = apply(&before, &free);
    warnings.extend(skipped);
    Plan {
        before,
        after,
        changes,
        warnings,
        unrepaired,
        cfg,
    }
}

pub async fn plan_stack(
    row: &StackRow,
    docker: Option<&Docker>,
    repair_contract: bool,
) -> Result<Plan> {
    let cfg = policy::user_cfg(row).await?;
    let roots = crate::stacks::allowed_roots()?;
    let before = row.read_compose(&roots)?;
    let dir = row.open_dir(&roots)?;
    Ok(plan_text(&row.name, before, cfg, docker, repair_contract, Some(&dir)).await)
}

pub async fn plan_inline(
    name: &str,
    dir: &std::path::Path,
    yaml: &str,
    docker: Option<&Docker>,
) -> Result<Plan> {
    let tmp = crate::fsat::PrivateDir::new("orca-normalize-")?;
    let file = tmp.write("compose.yaml", yaml.as_bytes())?;
    let project_dir = if dir.is_dir() { dir } else { tmp.path() };
    let compose = crate::compose::Compose::new(vec![file], Vec::new(), None)
        .ok_or_else(|| plugin_toolkit::anyhow::anyhow!("no compose file"))?;
    let raw = stacks::resolved_config(project_dir, &compose).await?;
    let cfg: Value = plugin_toolkit::serde_json::from_str(&raw)?;
    Ok(plan_text(name, yaml.to_string(), cfg, docker, false, None).await)
}

pub async fn write(row: &mut StackRow, plan: &Plan, docker: Option<&Docker>) -> Result<()> {
    if plan.changes.is_empty() {
        return Ok(());
    }
    let mut allow = row.allow.clone();
    rebind(&mut allow, &plan.cfg, &plan.changes);
    let rebound = StackRow {
        allow,
        ..row.clone()
    };
    rebound
        .write_compose_if_unchanged(
            &plan.after,
            &plan.before,
            &crate::stacks::allowed_roots()?,
            docker,
        )
        .await?;
    *row = rebound;
    if stacks::get(&row.name)?.is_some() {
        stacks::store(row).await?;
    }
    Ok(())
}

pub async fn normalize(row: &mut StackRow, docker: Option<&Docker>) -> Vec<String> {
    let plan = match plan_stack(row, docker, false).await {
        Ok(p) => p,
        Err(e) => return vec![format!("warning: normalize skipped: {e:#}")],
    };
    match write(row, &plan, docker).await {
        Ok(()) => plan.report(),
        Err(e) => vec![format!("warning: normalize not written: {e:#}")],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json::json;

    fn no_icon(_: &[String]) -> Option<String> {
        None
    }

    fn ch(service: &str, key: &str, value: &str) -> Change {
        Change {
            service: service.into(),
            key: key.into(),
            value: value.into(),
        }
    }

    #[test]
    fn every_service_without_a_name_gets_one() {
        let cfg = json!({"services": {
            "app": {"image": "x:1"},
            "db": {"image": "postgres:16", "container_name": "pg"}
        }});
        let (changes, warnings) = plan("web", &cfg, true, false, &no_icon);
        assert_eq!(changes, [ch("app", CONTAINER_NAME, "app")]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn a_single_service_stack_is_named_after_the_stack() {
        let cfg = json!({"services": {"server": {"image": "dxflrs/garage:v1"}}});
        let (changes, _) = plan("garage", &cfg, true, false, &no_icon);
        assert_eq!(changes[0].value, "garage");
    }

    #[test]
    fn replicated_services_get_no_name() {
        let cfg = json!({"services": {
            "a": {"image": "x:1", "scale": 2},
            "b": {"image": "x:1", "deploy": {"replicas": 3}},
            "c": {"image": "x:1", "deploy": {"replicas": "${N}"}},
            "d": {"image": "x:1", "deploy": {"replicas": "1"}, "scale": 1}
        }});
        let (changes, warnings) = plan("web", &cfg, true, false, &no_icon);
        assert_eq!(changes, [ch("d", CONTAINER_NAME, "d")]);
        assert_eq!(warnings.len(), 3, "{warnings:?}");
        assert!(
            warnings.iter().all(|w| w.contains("replicas")),
            "{warnings:?}"
        );
    }

    #[test]
    fn without_an_engine_no_name_is_added() {
        let cfg = json!({"services": {"app": {"image": "x:1"}}});
        let (changes, warnings) = plan("web", &cfg, false, false, &no_icon);
        assert!(changes.is_empty());
        assert!(warnings[0].contains("no engine connection"), "{warnings:?}");
    }

    #[test]
    fn unraid_adds_icon_and_webui_only_when_absent() {
        let cfg = json!({"services": {
            "zot": {"image": "ghcr.io/project-zot/zot-linux-amd64:v2", "container_name": "zot",
                    "ports": [{"target": 5000, "published": "5000", "protocol": "tcp"}]},
            "set": {"image": "x:1", "container_name": "set",
                    "labels": {ICON_LABEL: "a", WEBUI_LABEL: "b"},
                    "ports": [{"target": 80, "published": "8080"}]}
        }});
        let icon = |c: &[String]| (c[0] == "zot").then(|| icon_url(&c[0]));
        let (changes, _) = plan("registry", &cfg, true, true, &icon);
        let shown: Vec<String> = changes.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown,
            [
                format!("zot: {ICON_LABEL}={}", icon_url("zot")),
                format!("zot: {WEBUI_LABEL}=http://[IP]:[PORT:5000]/"),
            ]
        );
        assert!(plan("registry", &cfg, true, false, &icon).0.is_empty());
    }

    #[test]
    fn icon_candidates_map_images_and_aliases() {
        assert_eq!(
            candidates("ci", "runner", Some("gitea/act_runner:latest")),
            ["gitea", "runner", "ci"]
        );
        assert_eq!(
            candidates("ollama", "ollama", Some("ollama/ollama@sha256:ab")),
            ["ollama"]
        );
        assert_eq!(
            candidates("s", "pbs", Some("ayufan/proxmox-backup-server:latest")),
            ["pbs", "s"]
        );
        assert_eq!(
            candidates("My Stack", "a..b", Some("x/Bad$Name:1")),
            Vec::<String>::new()
        );
        assert_eq!(
            icon_url("garage"),
            "https://gitea.scottkey.me/argyle-labs/garage/raw/branch/main/assets/icon-256.png"
        );
    }

    #[test]
    fn icon_probes_are_cached_per_app() {
        let calls = std::cell::Cell::new(0);
        let probe = |_: &str| {
            calls.set(calls.get() + 1);
            Some(true)
        };
        assert!(has_icon("cache-test-app", &probe));
        assert!(has_icon("cache-test-app", &probe));
        assert_eq!(calls.get(), 1);
        let gave_up = |_: &str| {
            calls.set(calls.get() + 1);
            None
        };
        assert!(!has_icon("cache-test-unreachable", &gave_up));
        assert!(!has_icon("cache-test-unreachable", &gave_up));
        assert_eq!(calls.get(), 3, "a give-up is not cached");
        assert!(has_icon("cache-test-unreachable", &probe));
    }

    #[test]
    fn icon_lookup_outside_orca_finds_nothing() {
        assert_eq!(icon_for(&["no-sink-app".into()]), None);
    }

    #[test]
    fn apply_inserts_names_and_labels_in_both_label_styles() {
        let yaml = "services:\n  app:\n    image: x:1\n    labels:\n      a: b\n  db:\n    image: y:1\n    labels:\n      - c=d\n  web:\n    image: z:1\n";
        let (out, applied, warnings) = apply(
            yaml,
            &[
                ch("app", CONTAINER_NAME, "app"),
                ch("app", ICON_LABEL, "i"),
                ch("db", WEBUI_LABEL, "w"),
                ch("web", ICON_LABEL, "j"),
            ],
        );
        assert_eq!(applied.len(), 4);
        assert!(warnings.is_empty());
        assert_eq!(
            out,
            format!(
                "services:\n  app:\n    container_name: \"app\"\n    image: x:1\n    labels:\n      {ICON_LABEL}: \"i\"\n      a: b\n  db:\n    image: y:1\n    labels:\n      - \"{WEBUI_LABEL}=w\"\n      - c=d\n  web:\n    labels:\n      {ICON_LABEL}: \"j\"\n    image: z:1\n"
            )
        );
    }

    #[test]
    fn an_empty_container_name_is_replaced_not_duplicated() {
        let yaml = "services:\n  app:\n    image: x:1\n    container_name: \"\"\n";
        let (out, _, _) = apply(yaml, &[ch("app", CONTAINER_NAME, "app")]);
        assert_eq!(
            out,
            "services:\n  app:\n    image: x:1\n    container_name: \"app\"\n"
        );
    }

    #[test]
    fn services_the_file_text_cannot_take_are_skipped_with_a_warning() {
        let yaml = "x-base: &base\n  image: x:1\nservices:\n  anchored: *base\n  merged:\n    <<: *base\n  child:\n    extends:\n      service: merged\n  flow:\n    image: y:1\n    labels: {a: b}\n";
        let (out, applied, warnings) = apply(
            yaml,
            &[
                ch("anchored", CONTAINER_NAME, "anchored"),
                ch("merged", CONTAINER_NAME, "merged"),
                ch("child", CONTAINER_NAME, "child"),
                ch("included", CONTAINER_NAME, "included"),
                ch("flow", ICON_LABEL, "i"),
                ch("merged", ICON_LABEL, "bad\nvalue"),
            ],
        );
        let names: Vec<&str> = applied.iter().map(|c| c.service.as_str()).collect();
        assert_eq!(names, ["merged", "child"]);
        assert_eq!(warnings.len(), 4, "{warnings:?}");
        for skipped in ["anchored", "included", "flow", "control character"] {
            assert!(
                warnings.iter().any(|w| w.contains(skipped)),
                "{skipped}: {warnings:?}"
            );
        }
        assert!(out.contains("  anchored: *base\n"));
        assert!(out.contains("  merged:\n    container_name: \"merged\"\n    <<: *base\n"));
        assert!(out.contains("  child:\n    container_name: \"child\"\n    extends:\n"));
    }

    #[test]
    fn rebind_moves_only_grants_bound_to_the_current_definition() {
        let cfg = json!({"name": "web", "services": {"app": {"image": "x:1", "privileged": true}}});
        let old = policy::digests(&cfg)["app"].clone();
        let grant = |definition: &str| Grant {
            service: "app".into(),
            image: "x:1".into(),
            definition: definition.into(),
            image_digest: "sha256:a".into(),
            allow: "privileged".into(),
        };
        let mut allow = vec![grant(&old), grant("sha256:stale")];
        rebind(&mut allow, &cfg, &[ch("app", CONTAINER_NAME, "app")]);
        assert_ne!(allow[0].definition, old);
        assert_eq!(allow[1].definition, "sha256:stale");
        let mut expected = cfg.clone();
        expected["services"]["app"][CONTAINER_NAME] = json!("app");
        assert_eq!(allow[0].definition, policy::digests(&expected)["app"]);
    }

    #[test]
    fn a_name_taken_outside_the_stack_is_reported() {
        use crate::test_engine::{FakeEngine, Route};
        let engine = FakeEngine::routed(vec![
            Route::new(
                "GET",
                "/containers/app/json",
                200,
                json!({"Id": "c1", "Config": {"Labels": {"com.docker.compose.project": "other"}}})
                    .to_string(),
            ),
            Route::new(
                "GET",
                "/containers/mine/json",
                200,
                json!({"Id": "c2", "Config": {"Labels": {"com.docker.compose.project": "web"}}})
                    .to_string(),
            ),
        ]);
        let docker = engine.client();
        let run = |name: &str| plugin_toolkit::reactor::block_on(collision(&docker, "web", name));
        assert!(run("app").unwrap().contains("already used on this host"));
        assert_eq!(run("mine"), None);
        assert_eq!(run("free"), None);
    }

    fn tz(tz: &str) -> Contract {
        Contract {
            tz: Some(tz.into()),
            ..Default::default()
        }
    }

    #[test]
    fn only_the_explicit_normalize_repairs_the_contract() {
        let yaml = "services:\n  db:\n    image: postgres:16\n";
        let cfg = json!({"services": {"db": {"image": "postgres:16"}}});
        let deploy = plugin_toolkit::reactor::block_on(plan_text(
            "web",
            yaml.into(),
            cfg.clone(),
            None,
            false,
            None,
        ));
        assert!(
            deploy
                .changes
                .iter()
                .all(|c| c.key != TZ_KEY && c.key != HEALTHCHECK_KEY),
            "{:?}",
            deploy.changes
        );
        assert!(deploy.unrepaired.is_empty(), "{:?}", deploy.unrepaired);
        assert_eq!(deploy.after, yaml);
        let explicit =
            plugin_toolkit::reactor::block_on(plan_text("web", yaml.into(), cfg, None, true, None));
        assert!(
            explicit
                .changes
                .iter()
                .all(|c| c.key != TZ_KEY && c.key != HEALTHCHECK_KEY),
            "{:?}",
            explicit.changes
        );
        assert_eq!(
            explicit.unrepaired,
            [
                "db: tz: docker unavailable; image postgres:16 not inspectable",
                "db: healthcheck: docker unavailable; image postgres:16 not inspectable",
            ]
        );
    }

    #[test]
    fn contract_repair_adds_tz_and_known_healthchecks() {
        let cfg = json!({"services": {
            "db": {"image": "ghcr.io/immich-app/postgres:14"},
            "cache": {"image": "valkey/valkey:8@sha256:ab", "environment": {"TZ": ""}},
            "llm": {"image": "ollama/ollama:latest", "environment": {"TZ": "Etc/UTC"}}
        }});
        let (changes, unrepaired) = contract_plan(&cfg, &tz("America/Denver"));
        let shown: Vec<String> = changes.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown,
            [
                r#"cache: TZ=America/Denver"#,
                r#"cache: healthcheck=["CMD-SHELL","valkey-cli ping | grep -q PONG"]"#,
                r#"db: TZ=America/Denver"#,
                r#"db: healthcheck=["CMD-SHELL","pg_isready -h 127.0.0.1 -p \"$${PGPORT:-5432}\" -U \"$${POSTGRES_USER:-postgres}\" -d \"$${POSTGRES_DB:-$${POSTGRES_USER:-postgres}}\""]"#,
                r#"llm: healthcheck=["CMD","ollama","list"]"#,
            ]
        );
        assert!(unrepaired.is_empty(), "{unrepaired:?}");
    }

    #[test]
    fn redis_auth_check_reads_the_password_env_at_runtime() {
        let cfg = json!({"services": {
            "env": {"image": "redis:7", "environment": {"TZ": "UTC", "REDIS_PASSWORD": "s3cret"}},
            "pass": {
                "image": "redis:7",
                "environment": ["TZ=UTC", "PW=s3cret"],
                "command": "redis-server --requirepass $${PW}"
            },
            "lit": {"image": "valkey/valkey:8", "environment": {"TZ": "UTC"}, "command": ["valkey-server", "--requirepass", "s3cret"]}
        }});
        let (changes, unrepaired) = contract_plan(&cfg, &tz("UTC"));
        let shown: Vec<String> = changes.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown,
            [
                r#"env: healthcheck=["CMD-SHELL","REDISCLI_AUTH=\"$${REDIS_PASSWORD}\" VALKEYCLI_AUTH=\"$${REDIS_PASSWORD}\" redis-cli ping | grep -q PONG"]"#,
                r#"pass: healthcheck=["CMD-SHELL","REDISCLI_AUTH=\"$${PW}\" VALKEYCLI_AUTH=\"$${PW}\" redis-cli ping | grep -q PONG"]"#,
            ]
        );
        assert_eq!(unrepaired.len(), 1, "{unrepaired:?}");
        assert!(
            unrepaired[0].starts_with("lit: healthcheck: requirepass"),
            "{unrepaired:?}"
        );
        assert!(!unrepaired[0].contains("s3cret"), "{unrepaired:?}");
    }

    #[test]
    fn contract_repair_leaves_met_items_alone() {
        let cfg = json!({"services": {
            "own": {"image": "zot:2", "environment": ["TZ=UTC"]},
            "set": {"image": "x:1", "healthcheck": {"disable": true},
                    "volumes": [{"type": "bind", "source": "/etc/localtime", "target": "/etc/localtime"}]}
        }});
        let contract = Contract {
            tz: None,
            image_health: HashMap::from([("zot:2".to_string(), true)]),
            ..Default::default()
        };
        let (changes, unrepaired) = contract_plan(&cfg, &contract);
        assert!(changes.is_empty(), "{changes:?}");
        assert!(unrepaired.is_empty(), "{unrepaired:?}");
    }

    #[test]
    fn an_uninspectable_image_is_unrepaired_not_overridden() {
        let cfg = json!({"services": {
            "gone": {"image": "postgres:16"},
            "seen": {"image": "postgres:17"}
        }});
        let contract = Contract {
            image_health: HashMap::from([("postgres:17".to_string(), false)]),
            image_errors: HashMap::from([(
                "postgres:16".to_string(),
                inspect_reason(&bollard::errors::Error::DockerResponseServerError {
                    status_code: 404,
                    message: "pull access denied for https://user:secret@reg".into(),
                }),
            )]),
            ..tz("America/Denver")
        };
        let (changes, unrepaired) = contract_plan(&cfg, &contract);
        assert!(changes.iter().all(|c| c.service == "seen"), "{changes:?}");
        let mut keys: Vec<&str> = changes.iter().map(|c| c.key.as_str()).collect();
        keys.sort();
        let mut want = vec![HEALTHCHECK_KEY, TZ_KEY];
        want.sort();
        assert_eq!(keys, want);
        assert_eq!(
            unrepaired,
            [
                "gone: tz: image postgres:16 not inspectable (not present locally); pull it and rerun normalize",
                "gone: healthcheck: image postgres:16 not inspectable (not present locally); pull it and rerun normalize",
            ]
        );
        assert!(unrepaired.iter().all(|u| !u.contains("secret")));
    }

    #[test]
    fn no_docker_connection_leaves_image_facts_unrepaired() {
        let cfg = json!({"services": {
            "bare": {"image": "postgres:16"},
            "set": {
                "image": "redis:7",
                "environment": {"TZ": "UTC"},
                "healthcheck": {"test": ["CMD", "true"]}
            },
            "built": {"build": ".", "environment": ["TZ=UTC"]}
        }});
        let contract = Contract {
            docker_unavailable: true,
            ..tz("America/Denver")
        };
        let (changes, unrepaired) = contract_plan(&cfg, &contract);
        assert!(changes.is_empty(), "{changes:?}");
        assert_eq!(
            unrepaired,
            [
                "bare: tz: docker unavailable; image postgres:16 not inspectable",
                "bare: healthcheck: docker unavailable; image postgres:16 not inspectable",
                "built: healthcheck: none known for image '(built)'; set one in the compose file",
            ]
        );
    }

    #[test]
    fn lowercase_tz_counts_as_set_everywhere() {
        let cfg = json!({"services": {
            "map": {"image": "a:1", "environment": {"tz": "Europe/Paris"}},
            "list": {"image": "a:1", "environment": ["Tz=Europe/Paris"]},
            "file": {"image": "a:1", "env_file": "/srv/app/app.env"},
            "empty": {"image": "a:1", "environment": {"tz": ""}}
        }});
        let contract = Contract {
            env_files: HashMap::from([(
                "/srv/app/app.env".to_string(),
                Ok("tz=Europe/Paris\n".to_string()),
            )]),
            ..tz("America/Denver")
        };
        let (changes, _) = contract_plan(&cfg, &contract);
        let tz: Vec<&str> = changes
            .iter()
            .filter(|c| c.key == TZ_KEY)
            .map(|c| c.service.as_str())
            .collect();
        assert_eq!(tz, ["empty"]);
    }

    #[test]
    fn sets_tz_matches_the_key_case_insensitively_and_needs_a_value() {
        assert!(sets_tz("TZ=UTC"));
        assert!(sets_tz("tz=UTC"));
        assert!(!sets_tz("tz="));
        assert!(!sets_tz("TZDIR=/x"));
        assert!(!sets_tz("TZ"));
    }

    #[test]
    fn tz_set_by_an_env_file_or_the_image_is_not_injected() {
        let cfg = json!({"services": {
            "one": {"image": "a:1", "env_file": "/srv/app/app.env"},
            "list": {"image": "a:1", "env_file": ["/srv/app/x.env", {"path": "/srv/app/app.env", "required": true}]},
            "img": {"image": "zone:1"},
            "bare": {"image": "a:1", "env_file": ["/srv/app/x.env"]}
        }});
        let contract = Contract {
            image_tz: ["zone:1".to_string()].into(),
            env_files: HashMap::from([
                (
                    "/srv/app/app.env".to_string(),
                    Ok("# z\nTZ=Europe/Paris\n".to_string()),
                ),
                ("/srv/app/x.env".to_string(), Ok("K=v\n".to_string())),
            ]),
            ..tz("America/Denver")
        };
        let (changes, unrepaired) = contract_plan(&cfg, &contract);
        let tz: Vec<&str> = changes
            .iter()
            .filter(|c| c.key == TZ_KEY)
            .map(|c| c.service.as_str())
            .collect();
        assert_eq!(tz, ["bare"]);
        assert!(
            unrepaired.iter().all(|u| !u.contains("tz:")),
            "{unrepaired:?}"
        );
    }

    #[test]
    fn an_unreadable_env_file_leaves_tz_unrepaired() {
        let cfg = json!({"services": {"app": {"image": "a:1", "env_file": "/srv/app/gone.env"}}});
        let contract = Contract {
            env_files: HashMap::from([(
                "/srv/app/gone.env".to_string(),
                Err("does not exist".to_string()),
            )]),
            ..tz("America/Denver")
        };
        let (changes, unrepaired) = contract_plan(&cfg, &contract);
        assert!(changes.iter().all(|c| c.key != TZ_KEY), "{changes:?}");
        assert!(
            unrepaired
                .iter()
                .any(|u| u.starts_with("app: tz: env_file '/srv/app/gone.env' does not exist")),
            "{unrepaired:?}"
        );
    }

    #[test]
    fn env_files_are_read_inside_the_project_dir_only() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        let dir = base.join("app");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("app.env"), "TZ=Europe/Paris\n").unwrap();
        let roots = [base.to_string_lossy().into_owned()];
        let sd = stacks::StackDir::open(&dir.to_string_lossy(), &roots, false)
            .unwrap()
            .unwrap();
        let abs = dir.join("app.env").to_string_lossy().into_owned();
        let missing = dir.join("no.env").to_string_lossy().into_owned();
        let cfg = json!({"services": {"a": {"env_file": [
            abs, "rel.env", "/etc/passwd", {"path": missing, "required": false}
        ]}}});
        let read = read_env_files(Some(&sd), &cfg);
        assert_eq!(read[&abs], Ok("TZ=Europe/Paris\n".to_string()));
        assert_eq!(read["rel.env"], Err("does not exist".to_string()));
        assert_eq!(
            read["/etc/passwd"],
            Err("outside the project dir".to_string())
        );
        assert_eq!(read[&missing], Ok(String::new()));
        assert!(read_env_files(None, &cfg)[&abs].is_err());
    }

    #[test]
    fn contract_items_orca_cannot_fill_are_named() {
        let cfg = json!({"services": {
            "app": {"image": "louislam/dockge:1"},
            "built": {"build": "."}
        }});
        let contract = Contract {
            tz: None,
            image_health: HashMap::from([("louislam/dockge:1".to_string(), false)]),
            ..Default::default()
        };
        let (changes, unrepaired) = contract_plan(&cfg, &contract);
        assert!(changes.is_empty());
        assert_eq!(unrepaired.len(), 4, "{unrepaired:?}");
        assert!(
            unrepaired[1].contains("'louislam/dockge:1'"),
            "{unrepaired:?}"
        );
        assert!(unrepaired[3].contains("(built)"), "{unrepaired:?}");
    }

    #[test]
    fn apply_writes_tz_in_both_env_styles_and_a_healthcheck_block() {
        let yaml = "services:\n  a:\n    image: x:1\n    environment:\n      K: v\n  b:\n    image: y:1\n    environment:\n      - K=v\n  c:\n    image: z:1\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n";
        let (out, applied, warnings) = apply(
            yaml,
            &[
                ch("a", TZ_KEY, "Etc/UTC"),
                ch("a", HEALTHCHECK_KEY, r#"["CMD","pg_isready"]"#),
                ch("b", TZ_KEY, "Etc/UTC"),
                ch("c", TZ_KEY, "Etc/UTC"),
                ch("c", HEALTHCHECK_KEY, r#"["CMD","x"]"#),
            ],
        );
        assert_eq!(applied.len(), 4);
        assert!(
            warnings[0].contains("already sets a healthcheck"),
            "{warnings:?}"
        );
        assert_eq!(
            out,
            "services:\n  a:\n    healthcheck:\n      test: [\"CMD\",\"pg_isready\"]\n      interval: 30s\n      timeout: 5s\n      retries: 5\n      start_period: 60s\n    image: x:1\n    environment:\n      TZ: \"Etc/UTC\"\n      K: v\n  b:\n    image: y:1\n    environment:\n      - \"TZ=Etc/UTC\"\n      - K=v\n  c:\n    environment:\n      TZ: \"Etc/UTC\"\n    image: z:1\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n"
        );
    }

    #[test]
    fn postgres_healthcheck_reads_container_env_with_escaped_dollars() {
        let cfg = json!({"services": {"db": {"image": "postgres:16"}}});
        let (changes, _) = contract_plan(&cfg, &Contract::default());
        let hc: Vec<_> = changes
            .into_iter()
            .filter(|c| c.key == HEALTHCHECK_KEY)
            .collect();
        let (out, applied, warnings) = apply("services:\n  db:\n    image: postgres:16\n", &hc);
        assert_eq!(applied.len(), 1, "{warnings:?}");
        assert_eq!(
            out,
            concat!(
                "services:\n  db:\n    healthcheck:\n",
                r#"      test: ["CMD-SHELL","pg_isready -h 127.0.0.1 -p \"$${PGPORT:-5432}\" -U \"$${POSTGRES_USER:-postgres}\" -d \"$${POSTGRES_DB:-$${POSTGRES_USER:-postgres}}\""]"#,
                "\n      interval: 30s\n      timeout: 5s\n      retries: 5\n      start_period: 60s\n    image: postgres:16\n"
            )
        );
    }

    #[test]
    fn rebind_follows_contract_repairs() {
        let cfg = json!({"name": "web", "services": {"app": {"image": "x:1"}}});
        let old = policy::digests(&cfg)["app"].clone();
        let mut allow = vec![Grant {
            service: "app".into(),
            image: "x:1".into(),
            definition: old,
            image_digest: "sha256:a".into(),
            allow: "privileged".into(),
        }];
        rebind(
            &mut allow,
            &cfg,
            &[
                ch("app", TZ_KEY, "Etc/UTC"),
                ch("app", HEALTHCHECK_KEY, r#"["CMD","true"]"#),
            ],
        );
        let mut expected = cfg.clone();
        expected["services"]["app"]["environment"] = json!({"TZ": "Etc/UTC"});
        expected["services"]["app"]["healthcheck"] = json!({"test": ["CMD", "true"]});
        assert_eq!(allow[0].definition, policy::digests(&expected)["app"]);
    }

    /// A fake host; unlisted paths are absent.
    #[derive(Default)]
    struct Host {
        files: HashMap<String, String>,
        links: HashMap<String, String>,
    }

    impl Host {
        fn file(mut self, p: &str, body: &str) -> Self {
            self.files.insert(p.into(), body.into());
            self
        }

        fn link(mut self, p: &str, target: &str) -> Self {
            self.links.insert(p.into(), target.into());
            self
        }

        /// dockerd as pid 42, its root carrying every zone used below.
        fn dockerd() -> Self {
            let mut h = Host::default()
                .file("/var/run/docker.pid", "42\n")
                .file("/proc/42/comm", "dockerd\n")
                .link("/proc/self/ns/pid", "pid:[1]")
                .link("/proc/42/ns/pid", "pid:[1]");
            for z in ["Europe/Oslo", "Asia/Tokyo", "America/Denver", "Etc/UTC"] {
                h = h.file(&format!("/proc/42/root/usr/share/zoneinfo/{z}"), "TZif");
            }
            h
        }
    }

    impl crate::mounts::Proc for Host {
        fn read(&self, p: &str) -> std::io::Result<String> {
            self.files
                .get(p)
                .cloned()
                .ok_or_else(|| std::io::ErrorKind::NotFound.into())
        }

        fn readlink(&self, p: &str) -> std::io::Result<String> {
            self.links
                .get(p)
                .cloned()
                .ok_or_else(|| std::io::ErrorKind::NotFound.into())
        }

        fn exists(&self, p: &str) -> bool {
            self.files.contains_key(p) || self.links.contains_key(p)
        }
    }

    #[test]
    fn host_tz_reads_dockerds_tz_env_first() {
        let h = Host::dockerd()
            .file("/proc/42/environ", "PATH=/bin\0TZ=:America/Denver\0")
            .file("/proc/42/root/etc/timezone", "Asia/Tokyo\n");
        assert_eq!(host_tz(&h).as_deref(), Some("America/Denver"));
    }

    #[test]
    fn host_tz_reads_the_hosts_etc_timezone() {
        let h = Host::dockerd()
            .file("/proc/42/root/etc/timezone", "Asia/Tokyo\n")
            .link(
                "/proc/42/root/etc/localtime",
                "/usr/share/zoneinfo/Europe/Oslo",
            );
        assert_eq!(host_tz(&h).as_deref(), Some("Asia/Tokyo"));
    }

    #[test]
    fn host_tz_reads_the_localtime_link() {
        let h = Host::dockerd().link(
            "/proc/42/root/etc/localtime",
            "../usr/share/zoneinfo/Europe/Oslo",
        );
        assert_eq!(host_tz(&h).as_deref(), Some("Europe/Oslo"));
    }

    #[test]
    fn host_tz_reads_unraids_ident_cfg_over_a_utc_or_missing_localtime() {
        let ident = "NAME=\"tower\"\ntimeZone=\"America/Denver\"\n";
        let missing = Host::dockerd().file("/proc/42/root/boot/config/ident.cfg", ident);
        assert_eq!(host_tz(&missing).as_deref(), Some("America/Denver"));
        let utc = Host::dockerd()
            .file("/proc/42/root/boot/config/ident.cfg", ident)
            .link("/proc/42/root/etc/localtime", "/usr/share/zoneinfo/Etc/UTC");
        assert_eq!(host_tz(&utc).as_deref(), Some("America/Denver"));
    }

    #[test]
    fn host_tz_unknown_is_none_and_the_service_unrepaired() {
        let copied = Host::dockerd().file("/proc/42/root/etc/localtime", "TZif");
        let bogus = Host::dockerd()
            .file("/proc/42/root/etc/timezone", "Mars/Olympus\n")
            .file(
                "/proc/42/root/boot/config/ident.cfg",
                "timeZone=\"../../etc/passwd\"\n",
            );
        let container = Host::default()
            .file("/.dockerenv", "")
            .file("/etc/timezone", "Asia/Tokyo\n")
            .file("/usr/share/zoneinfo/Asia/Tokyo", "TZif");
        for h in [copied, bogus, container] {
            assert_eq!(host_tz(&h), None);
        }
        let cfg = json!({"services": {"app": {"image": "x:1"}}});
        let (changes, unrepaired) = contract_plan(&cfg, &Contract::default());
        assert!(changes.iter().all(|c| c.key != TZ_KEY), "{changes:?}");
        assert!(
            unrepaired
                .iter()
                .any(|u| u.starts_with("app: tz: host timezone unknown")),
            "{unrepaired:?}"
        );
    }
}
