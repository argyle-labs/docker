use std::collections::BTreeMap;
use std::path::{Component, Path};

use bollard::Docker;
use bollard::models::ContainerInspectResponse;
use bollard::query_parameters::InspectContainerOptionsBuilder;
use plugin_toolkit::prelude::*;
use plugin_toolkit::scrub::{is_secret, is_secret_value, is_sensitive_key, scrub_line};
use plugin_toolkit::serde_json::{self, Value, json};

const REDACTED: &str = "***";
pub const RUNTIME_SOCKETS: [&str; 8] = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/podman/podman.sock",
    "/var/run/podman/podman.sock",
    "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/var/run/crio/crio.sock",
];
const RUNTIME_SOCKET_MARKERS: [&str; 4] = ["docker", "podman", "containerd", "crio"];
const SENSITIVE_HOST_PATHS: [&str; 17] = [
    "/run",
    "/var/run",
    "/",
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/boot",
    "/dev",
    "/var/lib/docker",
    "/var/lib/containers",
    "/var/lib/containerd",
    "/var/lib/kubelet",
    "/var/lib/lxc",
    "/usr",
    "/private/etc",
    "/private/var/lib/docker",
];
const SENSITIVE_HOME_SUBPATHS: [&str; 7] = [
    ".ssh",
    ".docker",
    ".kube",
    ".aws",
    ".gnupg",
    ".config/gcloud",
    ".netrc",
];
const COMPOSE_LABEL_PREFIX: &str = "com.docker.compose.";
const COMPOSE_PATH_LABELS: [&str; 3] = [
    "com.docker.compose.project.working_dir",
    "com.docker.compose.project.config_files",
    "com.docker.compose.project.environment_file",
];
const DEFAULT_SHM_SIZE: i64 = 64 * 1024 * 1024;

#[orca_struct(args)]
pub struct DockerContainerInspectArgs {
    /// Container name or id.
    #[arg(long)]
    pub container: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
    pub redacted: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PortMapping {
    pub container_port: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_port: Option<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MountInfo {
    #[serde(rename = "type")]
    pub kind: String,
    pub source: String,
    pub target: String,
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_name: Option<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SensitiveBind {
    pub source: String,
    pub class: String,
    pub read_only: bool,
    pub basis: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestartInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_retry_count: Option<i64>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceRequestInfo {
    pub driver: String,
    pub count: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_ids: Vec<String>,
    pub capabilities: Vec<Vec<String>>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceInfo {
    pub path_on_host: String,
    pub path_in_container: String,
    pub cgroup_permissions: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HealthcheckInfo {
    pub test: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_ns: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ns: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_period_ns: Option<i64>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UlimitInfo {
    pub name: String,
    pub soft: i64,
    pub hard: i64,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerInspectOutput {
    pub id: String,
    pub name: String,
    pub image: String,
    pub image_id: String,
    pub repo_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_digests_error: Option<String>,
    pub command: Vec<String>,
    pub entrypoint: Vec<String>,
    pub env: Vec<EnvVar>,
    pub network_mode: String,
    pub networks: Vec<String>,
    pub ports: Vec<PortMapping>,
    pub mounts: Vec<MountInfo>,
    pub sensitive_binds: Vec<SensitiveBind>,
    pub restart_policy: RestartInfo,
    pub device_requests: Vec<DeviceRequestInfo>,
    pub devices: Vec<DeviceInfo>,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    pub privileged: bool,
    pub read_only_rootfs: bool,
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_labels: Vec<String>,
    pub init: bool,
    pub user: String,
    pub working_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<HealthcheckInfo>,
    pub tmpfs: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shm_size: Option<i64>,
    pub sysctls: BTreeMap<String, String>,
    pub ulimits: Vec<UlimitInfo>,
    pub security_opt: Vec<String>,
    pub extra_hosts: Vec<String>,
    pub pid_mode: String,
    pub ipc_mode: String,
    pub uts_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nano_cpus: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids_limit: Option<i64>,
    pub log_driver: String,
    pub log_options: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_log_options: Vec<String>,
    pub stop_signal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_timeout: Option<i64>,
    pub hostname: String,
    pub dns: Vec<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerComposeOutput {
    pub service: String,
    pub yaml: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Admin,
    Reader,
    Names,
}

impl View {
    pub fn of(ctx: &ToolCtx) -> Self {
        if crate::execute::require_admin("docker.container_compose", ctx).is_ok() {
            View::Admin
        } else {
            View::Reader
        }
    }
}

fn redact_args(args: &[String], replace: impl Fn(&str) -> String) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut pending: Option<String> = None;
    for arg in args {
        if let Some(flag) = pending.take() {
            out.push(replace(&flag));
        } else if arg.contains(char::is_whitespace) {
            let (masked, trailing) = redact_command_string(arg, &replace, 0);
            pending = trailing;
            out.push(masked);
        } else if let Some(masked) = redact_token(arg, &replace) {
            out.push(masked);
        } else {
            if takes_secret_value(arg) {
                pending = Some(arg.clone());
            }
            out.push(arg.clone());
        }
    }
    out
}

const MAX_NESTING: usize = 4;

/// Returns the redacted string and, if it ends with a flag whose value is the next argv
/// element, that flag.
fn redact_command_string(
    arg: &str,
    replace: &impl Fn(&str) -> String,
    depth: usize,
) -> (String, Option<String>) {
    let scrubbed = scrub_line(arg);
    let mut changed = matches!(scrubbed, std::borrow::Cow::Owned(_));
    let Some(words) = shell_words(&scrubbed) else {
        return (redact_unparsed(&scrubbed, replace), None);
    };
    let mut pending: Option<String> = None;
    let mut out: Vec<String> = Vec::new();
    for (raw, word) in words {
        if let Some(flag) = pending.take() {
            out.push(replace(&flag));
            changed = true;
        } else if let Some(masked) = redact_token(&word, replace) {
            out.push(masked);
            changed = true;
        } else if word.contains(char::is_whitespace) {
            if depth + 1 >= MAX_NESTING {
                out.push(replace("ARG"));
                changed = true;
                continue;
            }
            let (inner, trailing) = redact_command_string(&word, replace, depth + 1);
            if trailing.is_some() {
                out.push(replace("ARG"));
                changed = true;
                pending = trailing;
            } else if inner != word {
                out.push(format!("'{}'", inner.replace('\'', "'\\''")));
                changed = true;
            } else {
                out.push(raw.to_owned());
            }
        } else {
            if takes_secret_value(&word) {
                pending = Some(word);
            }
            out.push(raw.to_owned());
        }
    }
    let joined = if changed {
        out.join(" ")
    } else {
        arg.to_owned()
    };
    (joined, pending)
}

/// Splits on unquoted whitespace, yielding each word's raw text and its unquoted value.
/// `None` on an unbalanced quote or trailing backslash.
fn shell_words(s: &str) -> Option<Vec<(&str, String)>> {
    let mut words = Vec::new();
    let mut chars = s.char_indices().peekable();
    while let Some(&(start, c)) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut value = String::new();
        let mut end = s.len();
        while let Some((i, c)) = chars.next() {
            match c {
                c if c.is_whitespace() => {
                    end = i;
                    break;
                }
                '\\' => value.push(chars.next()?.1),
                '\'' => loop {
                    match chars.next()?.1 {
                        '\'' => break,
                        c => value.push(c),
                    }
                },
                '"' => loop {
                    match chars.next()?.1 {
                        '"' => break,
                        '\\' => {
                            let (_, e) = chars.next()?;
                            if !matches!(e, '"' | '\\' | '$' | '`') {
                                value.push('\\');
                            }
                            value.push(e);
                        }
                        c => value.push(c),
                    }
                },
                c => value.push(c),
            }
        }
        words.push((&s[start..end], value));
    }
    Some(words)
}

// Without word boundaries a secret's extent is unknowable, so everything from the first
// sensitive token on is masked.
fn redact_unparsed(s: &str, replace: &impl Fn(&str) -> String) -> String {
    let mut out: Vec<String> = Vec::new();
    for tok in s.split_whitespace() {
        if let Some(masked) = redact_token(tok, replace) {
            out.push(masked);
            return out.join(" ");
        }
        if takes_secret_value(tok) {
            out.push(tok.to_owned());
            out.push(replace(tok));
            return out.join(" ");
        }
        out.push(tok.to_owned());
    }
    s.to_owned()
}

fn redact_token(tok: &str, replace: &impl Fn(&str) -> String) -> Option<String> {
    // Fails closed: `-name`/`-all` get masked too, since `-xahunter` is indistinguishable.
    if !tok.starts_with("-D")
        && let Some((flag, value)) = split_value_short_flag(tok)
        && !value.is_empty()
    {
        return Some(format!("{flag}{}", replace(flag)));
    }
    let bare = tok.trim_start_matches('-');
    if let Some((name, value)) = bare.split_once('=')
        && (is_secret(name, value)
            || tok
                .strip_prefix("-D")
                .is_some_and(|_| is_secret(&name[1..], value)))
    {
        return Some(format!(
            "{}{name}={}",
            &tok[..tok.len() - bare.len()],
            replace(name)
        ));
    }
    if is_secret_value(tok) {
        return Some(replace("ARG"));
    }
    if let Some((flag, value)) = split_value_short_flag(tok)
        && !value.is_empty()
    {
        return Some(format!("{flag}{}", replace(flag)));
    }
    // `-p<secret>` is the mysql-client password form; `-p80`/`-p-1` are ports/numbers.
    if tok.len() > 2
        && tok.starts_with("-p")
        && !tok[2..].starts_with(|c: char| c.is_ascii_digit() || c == '-')
    {
        return Some(format!("-p{}", replace("-p")));
    }
    None
}

fn takes_secret_value(tok: &str) -> bool {
    tok.starts_with('-')
        && (matches!(tok, "-a" | "-u" | "-H" | "--header" | "--user")
            || is_value_short_flag_cluster(tok)
            || is_sensitive_key(tok.trim_start_matches('-')))
}

const VALUE_SHORT_FLAGS: [char; 3] = ['a', 'u', 'H'];

// `curl -fsu user:pw` / `curl -sHvalue`: within a short-flag cluster the first value-taking
// flag consumes the rest of the token, or the next word when nothing follows it.
fn split_value_short_flag(tok: &str) -> Option<(&str, &str)> {
    let body = tok.strip_prefix('-').filter(|b| !b.starts_with('-'))?;
    let i = body.find(|c: char| {
        VALUE_SHORT_FLAGS.contains(&c)
            || matches!(c, '-' | '=' | '/' | '.' | ':' | '+')
            || c.is_whitespace()
    })?;
    let flag = body[i..].chars().next()?;
    if !VALUE_SHORT_FLAGS.contains(&flag) {
        return None;
    }
    // `-Dkey=value` is a JVM system property, not a cluster; its key is vetted by `redact_token`.
    if i > 0 && body.starts_with('D') && body[i..].contains('=') {
        return None;
    }
    let cut = 1 + i + flag.len_utf8();
    Some((&tok[..cut], &tok[cut..]))
}

fn is_value_short_flag_cluster(tok: &str) -> bool {
    tok.len() > 2 && split_value_short_flag(tok).is_some_and(|(_, rest)| rest.is_empty())
}

fn unless_redacted(value: &str, name: &str) -> String {
    if value == REDACTED {
        env_ref(name)
    } else {
        lit(value)
    }
}

fn env_ref(name: &str) -> String {
    if name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return format!("${{{name}}}");
    }
    let clean: String = name
        .trim_start_matches('-')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("${{SECRET_{clean}}}")
}

fn normalize_path(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    let mut absolute = false;
    for component in Path::new(path).components() {
        match component {
            Component::RootDir => absolute = true,
            Component::Normal(part) => parts.push(part.to_str()?),
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::CurDir | Component::Prefix(_) => {}
        }
    }
    let joined = parts.join("/");
    Some(if absolute {
        format!("/{joined}")
    } else {
        joined
    })
}

fn is_runtime_socket_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or("");
    base.contains(".sock") && RUNTIME_SOCKET_MARKERS.iter().any(|m| lower.contains(m))
}

fn home_relative(path: &str) -> Option<&str> {
    if let Some(rest) = path.strip_prefix("/root/") {
        return Some(rest);
    }
    let rest = path
        .strip_prefix("/home/")
        .or_else(|| path.strip_prefix("/users/"))?;
    let (user, tail) = rest.split_once('/')?;
    (!user.is_empty()).then_some(tail)
}

fn is_home_credential(path: &str) -> bool {
    home_relative(path).is_some_and(|rel| {
        SENSITIVE_HOME_SUBPATHS
            .iter()
            .any(|sub| rel == *sub || rel.starts_with(&format!("{sub}/")))
    })
}

fn is_rootless_socket(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/run/user") else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let Some((uid, tail)) = rest
        .strip_prefix('/')
        .map(|r| r.split_once('/').unwrap_or((r, "")))
    else {
        return false;
    };
    !uid.is_empty()
        && uid.chars().all(|c| c.is_ascii_digit())
        && matches!(tail, "" | "podman" | "podman/podman.sock" | "docker.sock")
}

fn classify_normalized(s: &str) -> Option<&'static str> {
    // Host filesystems may be case-insensitive (macOS), so `/ETC` must match `/etc`.
    let s = s.to_ascii_lowercase();
    let s = s.as_str();
    if RUNTIME_SOCKETS
        .iter()
        .any(|sock| *sock == s || sock.starts_with(&format!("{s}/")))
        || is_rootless_socket(s)
        || is_runtime_socket_file(s)
    {
        Some("runtimeSocket")
    } else if SENSITIVE_HOST_PATHS
        .iter()
        .any(|p| s == *p || (*p != "/" && s.starts_with(&format!("{p}/"))))
        || is_home_credential(s)
    {
        Some("sensitivePath")
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Local,
    Remote,
}

impl Endpoint {
    /// `host` is the resolved `DOCKER_HOST`; `None` means bollard's default
    /// local socket.
    pub fn of(host: Option<&str>) -> Self {
        if !cfg!(target_os = "linux") {
            // Every engine off Linux runs inside a VM with its own filesystem.
            return Endpoint::Remote;
        }
        let Some(host) = host else {
            return Endpoint::Local;
        };
        match host.strip_prefix("unix://") {
            Some(path)
                if !["/.colima/", "/.lima/", "/.docker/desktop/", "/.docker/run/"]
                    .iter()
                    .any(|vm| path.contains(vm)) =>
            {
                Endpoint::Local
            }
            _ => Endpoint::Remote,
        }
    }

    pub fn current() -> Self {
        Endpoint::of(
            crate::tools::resolve_docker_host()
                .ok()
                .flatten()
                .as_deref(),
        )
    }
}

/// Returns the class and the basis (`lexical` or `resolved`). Symlinks are
/// resolved only for a local engine, since a remote engine's paths live on
/// another filesystem.
pub fn classify_bind(source: &str, endpoint: Endpoint) -> Option<(&'static str, &'static str)> {
    let Some(lexical) = normalize_path(source) else {
        return Some(("sensitivePath", "lexical"));
    };
    let real = (endpoint == Endpoint::Local && Path::new(source).is_absolute())
        .then(|| std::fs::canonicalize(source).ok())
        .flatten()
        .and_then(|p| p.to_str().map(str::to_owned));
    let resolved = real.filter(|real| *real != lexical);
    let lexical_class = classify_normalized(&lexical);
    let classes = [
        lexical_class,
        resolved.as_deref().and_then(classify_normalized),
    ];
    let class = classes
        .into_iter()
        .find(|c| *c == Some("runtimeSocket"))
        .or_else(|| classes.into_iter().find(|c| c.is_some()))
        .flatten()?;
    let basis = if Some(class) == lexical_class {
        "lexical"
    } else {
        "resolved"
    };
    Some((class, basis))
}

fn is_anonymous_volume(name: &str) -> bool {
    name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn env_var(raw: &str, view: View) -> EnvVar {
    let (name, value) = raw.split_once('=').unwrap_or((raw, ""));
    let secret = is_secret(name, value);
    let redacted = match view {
        View::Admin => false,
        View::Reader | View::Names => secret,
    };
    EnvVar {
        name: name.to_owned(),
        value: if redacted || view == View::Names {
            REDACTED.to_owned()
        } else {
            value.to_owned()
        },
        redacted,
    }
}

fn mask_hosts(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(&mask_ip_tokens(head));
        let end = tail
            .find(|c: char| matches!(c, '/' | '?' | '#' | ',' | '"' | '\'') || c.is_whitespace())
            .unwrap_or(tail.len());
        if end > 0 {
            out.push_str(REDACTED);
        }
        rest = &tail[end..];
    }
    out.push_str(&mask_ip_tokens(rest));
    out
}

fn mask_ip_tokens(s: &str) -> String {
    let is_tok =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '[' | ']' | '%' | '-' | '_');
    let mut out = String::with_capacity(s.len());
    let mut start = 0;
    for (i, c) in s.char_indices() {
        if !is_tok(c) {
            out.push_str(&mask_token(&s[start..i]));
            out.push(c);
            start = i + c.len_utf8();
        }
    }
    out.push_str(&mask_token(&s[start..]));
    out
}

fn mask_token(t: &str) -> String {
    let is_ip = |t: &str| {
        let t = t
            .strip_prefix('[')
            .and_then(|t| t.strip_suffix(']'))
            .unwrap_or(t);
        let t = t.split_once('%').map_or(t, |(ip, _)| ip);
        t.parse::<std::net::IpAddr>().is_ok()
    };
    if is_ip(t) {
        return REDACTED.to_owned();
    }
    let is_port = |p: &str| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit());
    let is_host = |h: &str| {
        is_ip(h)
            || (h.chars().any(|c| c.is_ascii_alphabetic())
                && h.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
    };
    let Some((host, port)) = t.rsplit_once(':').filter(|(_, p)| is_port(p)) else {
        return t.to_owned();
    };
    if is_host(host) {
        return format!("{REDACTED}:{port}");
    }
    match host.rsplit_once(':') {
        Some((h, mid)) if is_port(mid) && is_host(h) => format!("{REDACTED}:{mid}:{port}"),
        _ => t.to_owned(),
    }
}

fn admin_only(value: String, view: View) -> String {
    match view {
        View::Admin => value,
        View::Reader | View::Names => REDACTED.to_owned(),
    }
}

pub fn describe(
    c: &ContainerInspectResponse,
    view: View,
    endpoint: Endpoint,
) -> ContainerInspectOutput {
    let config = c.config.clone().unwrap_or_default();
    let host = c.host_config.clone().unwrap_or_default();
    let mut ports: Vec<PortMapping> = host
        .port_bindings
        .unwrap_or_default()
        .into_iter()
        .flat_map(|(port, bindings)| {
            let bindings = bindings.unwrap_or_default();
            if bindings.is_empty() {
                return vec![PortMapping {
                    container_port: port,
                    ..Default::default()
                }];
            }
            bindings
                .into_iter()
                .map(|b| PortMapping {
                    container_port: port.clone(),
                    host_ip: b.host_ip.filter(|s| !s.is_empty()).map(|ip| {
                        if matches!(ip.as_str(), "0.0.0.0" | "::") {
                            ip
                        } else {
                            admin_only(ip, view)
                        }
                    }),
                    host_port: b.host_port.filter(|s| !s.is_empty()),
                })
                .collect()
        })
        .collect();
    ports.sort_by(|a, b| a.container_port.cmp(&b.container_port));
    let mut networks: Vec<String> = c
        .network_settings
        .as_ref()
        .and_then(|n| n.networks.as_ref())
        .map(|n| n.keys().cloned().collect())
        .unwrap_or_default();
    networks.sort();
    let mounts_raw = c.mounts.clone().unwrap_or_default();
    let mut sensitive_binds: Vec<SensitiveBind> = mounts_raw
        .iter()
        .filter(|m| m.typ.as_deref() == Some("bind"))
        .filter_map(|m| {
            let source = m.source.clone().unwrap_or_default();
            classify_bind(&source, endpoint).map(|(class, basis)| SensitiveBind {
                source: admin_only(source, view),
                class: class.to_owned(),
                read_only: !m.rw.unwrap_or(true),
                basis: basis.to_owned(),
            })
        })
        .collect();
    sensitive_binds.sort_by(|a, b| a.source.cmp(&b.source));
    let restart = host.restart_policy.unwrap_or_default();
    let mut redacted_labels = Vec::new();
    let labels = config
        .labels
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| {
            if is_secret(&k, &v) {
                redacted_labels.push(k.clone());
                (k, REDACTED.to_owned())
            } else if view != View::Admin && COMPOSE_PATH_LABELS.contains(&k.as_str()) {
                (k, REDACTED.to_owned())
            } else if view != View::Admin && mask_hosts(&v) != v {
                redacted_labels.push(k.clone());
                (k, mask_hosts(&v))
            } else {
                (k, v)
            }
        })
        .collect();
    redacted_labels.sort();
    let masked = |a: Vec<String>| match view {
        View::Admin => a,
        View::Reader | View::Names => redact_args(&a, |_| REDACTED.to_owned()),
    };
    let log = host.log_config.clone().unwrap_or_default();
    let mut redacted_log_options = Vec::new();
    let log_options = log
        .config
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| {
            if is_secret(&k, &v) {
                redacted_log_options.push(k.clone());
                (k, REDACTED.to_owned())
            } else if let std::borrow::Cow::Owned(scrubbed) = scrub_line(&v) {
                redacted_log_options.push(k.clone());
                (k, scrubbed)
            } else if view != View::Admin && mask_hosts(&v) != v {
                redacted_log_options.push(k.clone());
                (k, mask_hosts(&v))
            } else {
                (k, v)
            }
        })
        .collect();
    redacted_log_options.sort();
    ContainerInspectOutput {
        id: c.id.clone().unwrap_or_default(),
        name: c
            .name
            .as_deref()
            .map(|n| n.trim_start_matches('/').to_owned())
            .unwrap_or_default(),
        image: config.image.unwrap_or_default(),
        image_id: c.image.clone().unwrap_or_default(),
        repo_digests: Vec::new(),
        repo_digests_error: None,
        command: masked(config.cmd.unwrap_or_default()),
        entrypoint: masked(config.entrypoint.unwrap_or_default()),
        env: config
            .env
            .unwrap_or_default()
            .iter()
            .map(|e| env_var(e, view))
            .collect(),
        network_mode: host.network_mode.unwrap_or_default(),
        networks,
        ports,
        mounts: mounts_raw
            .into_iter()
            .map(|m| MountInfo {
                kind: m.typ.map(|t| t.to_string()).unwrap_or_default(),
                source: admin_only(m.source.unwrap_or_default(), view),
                target: m.destination.unwrap_or_default(),
                read_only: !m.rw.unwrap_or(true),
                volume_name: m.name.filter(|s| !s.is_empty()),
            })
            .collect(),
        sensitive_binds,
        restart_policy: RestartInfo {
            name: restart.name.map(|n| n.to_string()).unwrap_or_default(),
            maximum_retry_count: restart.maximum_retry_count.filter(|n| *n > 0),
        },
        device_requests: host
            .device_requests
            .unwrap_or_default()
            .into_iter()
            .map(|d| DeviceRequestInfo {
                driver: d.driver.unwrap_or_default(),
                count: d.count.unwrap_or_default(),
                device_ids: d.device_ids.unwrap_or_default(),
                capabilities: d.capabilities.unwrap_or_default(),
            })
            .collect(),
        devices: host
            .devices
            .unwrap_or_default()
            .into_iter()
            .map(|d| DeviceInfo {
                path_on_host: admin_only(d.path_on_host.unwrap_or_default(), view),
                path_in_container: d.path_in_container.unwrap_or_default(),
                cgroup_permissions: d.cgroup_permissions.unwrap_or_default(),
            })
            .collect(),
        cap_add: host.cap_add.unwrap_or_default(),
        cap_drop: host.cap_drop.unwrap_or_default(),
        privileged: host.privileged.unwrap_or(false),
        read_only_rootfs: host.readonly_rootfs.unwrap_or(false),
        labels,
        redacted_labels,
        init: host.init.unwrap_or(false),
        user: config.user.unwrap_or_default(),
        working_dir: admin_only(config.working_dir.unwrap_or_default(), view),
        healthcheck: config.healthcheck.and_then(|h| {
            let test = h.test.unwrap_or_default();
            (!test.is_empty()).then_some(HealthcheckInfo {
                test: masked(test),
                interval_ns: h.interval.filter(|n| *n > 0),
                timeout_ns: h.timeout.filter(|n| *n > 0),
                retries: h.retries.filter(|n| *n > 0),
                start_period_ns: h.start_period.filter(|n| *n > 0),
            })
        }),
        tmpfs: host.tmpfs.unwrap_or_default().into_iter().collect(),
        shm_size: host.shm_size.filter(|n| *n > 0),
        sysctls: host.sysctls.unwrap_or_default().into_iter().collect(),
        ulimits: host
            .ulimits
            .unwrap_or_default()
            .into_iter()
            .map(|u| UlimitInfo {
                name: u.name.unwrap_or_default(),
                soft: u.soft.unwrap_or_default(),
                hard: u.hard.unwrap_or_default(),
            })
            .collect(),
        security_opt: host.security_opt.unwrap_or_default(),
        extra_hosts: host
            .extra_hosts
            .unwrap_or_default()
            .into_iter()
            .map(|h| match (view, h.split_once(':')) {
                (View::Admin, _) | (_, None) => h,
                (_, Some((name, _))) => format!("{name}:{REDACTED}"),
            })
            .collect(),
        pid_mode: host.pid_mode.unwrap_or_default(),
        ipc_mode: host.ipc_mode.unwrap_or_default(),
        uts_mode: host.uts_mode.unwrap_or_default(),
        nano_cpus: host.nano_cpus.filter(|n| *n > 0),
        memory: host.memory.filter(|n| *n > 0),
        pids_limit: host.pids_limit.filter(|n| *n > 0),
        log_driver: log.typ.unwrap_or_default(),
        log_options,
        redacted_log_options,
        stop_signal: config.stop_signal.unwrap_or_default(),
        stop_timeout: config.stop_timeout.filter(|n| *n >= 0),
        hostname: config.hostname.unwrap_or_default(),
        dns: host
            .dns
            .unwrap_or_default()
            .into_iter()
            .map(|d| admin_only(d, view))
            .collect(),
    }
}

fn duration(ns: i64) -> String {
    match ns {
        n if n % 1_000_000_000 == 0 => format!("{}s", n / 1_000_000_000),
        n if n % 1_000_000 == 0 => format!("{}ms", n / 1_000_000),
        n if n % 1_000 == 0 => format!("{}us", n / 1_000),
        n => format!("{n}ns"),
    }
}

fn lit(s: &str) -> String {
    s.replace('$', "$$")
}

fn compose_args(v: &[String]) -> Vec<String> {
    let mut prev: Option<&str> = None;
    v.iter()
        .map(|arg| {
            let out = if arg == REDACTED {
                env_ref(
                    prev.filter(|p| p.starts_with('-') && !p.contains('='))
                        .unwrap_or("ARG"),
                )
            } else if let Some(name) = arg.strip_suffix(&format!("={REDACTED}")) {
                format!("{}={}", lit(name), env_ref(name))
            } else {
                lit(arg)
            };
            prev = Some(arg);
            out
        })
        .collect()
}

fn is_named_network(mode: &str) -> bool {
    !mode.is_empty()
        && !matches!(mode, "default" | "bridge" | "host" | "none")
        && !mode.starts_with("container:")
        && !mode.starts_with("service:")
}

pub fn service_value(c: &ContainerInspectOutput) -> Value {
    let mut svc = serde_json::Map::new();
    svc.insert("image".into(), json!(lit(&c.image)));
    if !c.name.is_empty() {
        svc.insert("container_name".into(), json!(lit(&c.name)));
    }
    if !c.entrypoint.is_empty() {
        svc.insert("entrypoint".into(), json!(compose_args(&c.entrypoint)));
    }
    if !c.command.is_empty() {
        svc.insert("command".into(), json!(compose_args(&c.command)));
    }
    if c.init {
        svc.insert("init".into(), json!(true));
    }
    if !c.user.is_empty() {
        svc.insert("user".into(), json!(lit(&c.user)));
    }
    if !c.working_dir.is_empty() {
        svc.insert(
            "working_dir".into(),
            json!(unless_redacted(&c.working_dir, "working_dir")),
        );
    }
    if !c.env.is_empty() {
        let env: serde_json::Map<String, Value> = c
            .env
            .iter()
            .map(|e| {
                let v = if e.redacted || is_secret(&e.name, &e.value) {
                    env_ref(&e.name)
                } else {
                    lit(&e.value)
                };
                (e.name.clone(), json!(v))
            })
            .collect();
        svc.insert("environment".into(), Value::Object(env));
    }
    let mode = c.network_mode.as_str();
    if matches!(mode, "host" | "none") || mode.starts_with("container:") {
        svc.insert("network_mode".into(), json!(mode));
    } else if c.networks == ["bridge"] {
        svc.insert("network_mode".into(), json!("bridge"));
    } else if !c.networks.is_empty() {
        let mut nets: Vec<&str> = c
            .networks
            .iter()
            .map(|n| if n == "bridge" { "default" } else { n.as_str() })
            .collect();
        nets.sort();
        svc.insert("networks".into(), json!(nets));
    }
    if !c.hostname.is_empty() && !c.id.starts_with(&c.hostname) {
        svc.insert("hostname".into(), json!(lit(&c.hostname)));
    }
    if !c.dns.is_empty() {
        let dns: Vec<String> = c
            .dns
            .iter()
            .enumerate()
            .map(|(i, d)| unless_redacted(d, &format!("dns_{i}")))
            .collect();
        svc.insert("dns".into(), json!(dns));
    }
    if !c.extra_hosts.is_empty() {
        let hosts: Vec<String> = c
            .extra_hosts
            .iter()
            .map(|h| match h.split_once(':') {
                Some((name, addr)) => {
                    format!(
                        "{}:{}",
                        lit(name),
                        unless_redacted(addr, &format!("host_{name}"))
                    )
                }
                None => lit(h),
            })
            .collect();
        svc.insert("extra_hosts".into(), json!(hosts));
    }
    if !c.tmpfs.is_empty() {
        let tmpfs: Vec<String> = c
            .tmpfs
            .iter()
            .map(|(path, opts)| {
                if opts.is_empty() {
                    lit(path)
                } else {
                    format!("{}:{}", lit(path), lit(opts))
                }
            })
            .collect();
        svc.insert("tmpfs".into(), json!(tmpfs));
    }
    if let Some(n) = c.shm_size.filter(|n| *n != DEFAULT_SHM_SIZE) {
        svc.insert("shm_size".into(), json!(n));
    }
    if !c.sysctls.is_empty() {
        svc.insert("sysctls".into(), json!(c.sysctls));
    }
    if !c.ulimits.is_empty() {
        let ulimits: serde_json::Map<String, Value> = c
            .ulimits
            .iter()
            .map(|u| {
                let v = if u.soft == u.hard {
                    json!(u.soft)
                } else {
                    json!({ "soft": u.soft, "hard": u.hard })
                };
                (u.name.clone(), v)
            })
            .collect();
        svc.insert("ulimits".into(), Value::Object(ulimits));
    }
    if !c.security_opt.is_empty() {
        svc.insert("security_opt".into(), json!(c.security_opt));
    }
    if !c.pid_mode.is_empty() {
        svc.insert("pid".into(), json!(c.pid_mode));
    }
    if !matches!(c.ipc_mode.as_str(), "" | "private" | "shareable") {
        svc.insert("ipc".into(), json!(c.ipc_mode));
    }
    if let Some(n) = c.nano_cpus {
        let cpus = format!("{}", n as f64 / 1e9);
        svc.insert("cpus".into(), json!(cpus));
    }
    if let Some(n) = c.memory {
        svc.insert("mem_limit".into(), json!(n));
    }
    if let Some(n) = c.pids_limit {
        svc.insert("pids_limit".into(), json!(n));
    }
    if !c.log_driver.is_empty() && (c.log_driver != "json-file" || !c.log_options.is_empty()) {
        let mut logging = serde_json::Map::new();
        logging.insert("driver".into(), json!(c.log_driver));
        if !c.log_options.is_empty() {
            let opts: serde_json::Map<String, Value> = c
                .log_options
                .iter()
                .map(|(k, v)| {
                    let v = if c.redacted_log_options.contains(k) {
                        env_ref(k)
                    } else {
                        lit(v)
                    };
                    (k.clone(), json!(v))
                })
                .collect();
            logging.insert("options".into(), Value::Object(opts));
        }
        svc.insert("logging".into(), Value::Object(logging));
    }
    if !c.stop_signal.is_empty() {
        svc.insert("stop_signal".into(), json!(c.stop_signal));
    }
    if let Some(s) = c.stop_timeout {
        svc.insert(
            "stop_grace_period".into(),
            json!(duration(s * 1_000_000_000)),
        );
    }
    if !c.ports.is_empty() {
        let ports: Vec<String> = c
            .ports
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let target = p.container_port.trim_end_matches("/tcp");
                let ip = p.host_ip.as_deref().map(|ip| {
                    if ip == REDACTED {
                        let binding = p.host_port.clone().unwrap_or_else(|| i.to_string());
                        env_ref(&format!("host_ip_{}_{binding}", p.container_port))
                    } else if ip.contains(':') && !ip.starts_with('[') {
                        format!("[{ip}]")
                    } else {
                        ip.to_owned()
                    }
                });
                match (ip, &p.host_port) {
                    (Some(ip), Some(hp)) => format!("{ip}:{hp}:{target}"),
                    (Some(ip), None) => format!("{ip}::{target}"),
                    (None, Some(hp)) => format!("{hp}:{target}"),
                    (None, None) => target.to_owned(),
                }
            })
            .collect();
        svc.insert("ports".into(), json!(ports));
    }
    if !c.mounts.is_empty() {
        let vols: Vec<Value> = c
            .mounts
            .iter()
            .map(|m| {
                let source = match (&m.volume_name, m.kind.as_str()) {
                    (Some(v), "volume") if is_anonymous_volume(v) => String::new(),
                    (Some(v), "volume") => lit(v),
                    (_, "volume") => String::new(),
                    _ if m.source == REDACTED => env_ref(&format!("source{}", m.target)),
                    _ => lit(&m.source),
                };
                let mut v = serde_json::Map::new();
                v.insert("type".into(), json!(m.kind));
                if !source.is_empty() {
                    v.insert("source".into(), json!(source));
                }
                v.insert("target".into(), json!(lit(&m.target)));
                if m.read_only {
                    v.insert("read_only".into(), json!(true));
                }
                Value::Object(v)
            })
            .collect();
        svc.insert("volumes".into(), json!(vols));
    }
    let restart = match (
        c.restart_policy.name.as_str(),
        c.restart_policy.maximum_retry_count,
    ) {
        ("", _) | ("no", _) => None,
        ("on-failure", Some(n)) => Some(format!("on-failure:{n}")),
        (name, _) => Some(name.to_owned()),
    };
    if let Some(r) = restart {
        svc.insert("restart".into(), json!(r));
    }
    if c.privileged {
        svc.insert("privileged".into(), json!(true));
    }
    if !c.cap_add.is_empty() {
        svc.insert("cap_add".into(), json!(c.cap_add));
    }
    if !c.cap_drop.is_empty() {
        svc.insert("cap_drop".into(), json!(c.cap_drop));
    }
    if !c.devices.is_empty() {
        let devs: Vec<String> = c
            .devices
            .iter()
            .map(|d| {
                let mut s = format!(
                    "{}:{}",
                    unless_redacted(&d.path_on_host, &format!("device{}", d.path_in_container)),
                    d.path_in_container
                );
                if !d.cgroup_permissions.is_empty() && d.cgroup_permissions != "rwm" {
                    s.push(':');
                    s.push_str(&d.cgroup_permissions);
                }
                s
            })
            .collect();
        svc.insert("devices".into(), json!(devs));
    }
    if !c.device_requests.is_empty() {
        let reqs: Vec<Value> = c
            .device_requests
            .iter()
            .flat_map(|d| {
                let sets: Vec<Vec<String>> = if d.capabilities.is_empty() {
                    vec![Vec::new()]
                } else {
                    d.capabilities.clone()
                };
                sets.into_iter().map(move |caps| (d, caps))
            })
            .map(|(d, caps)| {
                let mut r = serde_json::Map::new();
                if !d.driver.is_empty() {
                    r.insert("driver".into(), json!(d.driver));
                }
                if !d.device_ids.is_empty() {
                    r.insert("device_ids".into(), json!(d.device_ids));
                } else if d.count < 0 {
                    r.insert("count".into(), json!("all"));
                } else {
                    r.insert("count".into(), json!(d.count));
                }
                r.insert("capabilities".into(), json!(caps));
                Value::Object(r)
            })
            .collect();
        svc.insert(
            "deploy".into(),
            json!({ "resources": { "reservations": { "devices": reqs } } }),
        );
    }
    let labels: serde_json::Map<String, Value> = c
        .labels
        .iter()
        .filter(|(k, _)| !k.starts_with(COMPOSE_LABEL_PREFIX))
        .map(|(k, v)| {
            let v = if c.redacted_labels.contains(k) {
                env_ref(k)
            } else {
                lit(v)
            };
            (k.clone(), json!(v))
        })
        .collect();
    if !labels.is_empty() {
        svc.insert("labels".into(), Value::Object(labels));
    }
    if let Some(h) = &c.healthcheck {
        let mut hc = serde_json::Map::new();
        if h.test.first().map(String::as_str) == Some("NONE") {
            hc.insert("disable".into(), json!(true));
        } else {
            hc.insert("test".into(), json!(compose_args(&h.test)));
        }
        for (key, ns) in [
            ("interval", h.interval_ns),
            ("timeout", h.timeout_ns),
            ("start_period", h.start_period_ns),
        ] {
            if let Some(ns) = ns {
                hc.insert(key.into(), json!(duration(ns)));
            }
        }
        if let Some(r) = h.retries {
            hc.insert("retries".into(), json!(r));
        }
        svc.insert("healthcheck".into(), Value::Object(hc));
    }
    Value::Object(svc)
}

fn service_key(c: &ContainerInspectOutput) -> String {
    c.labels
        .get("com.docker.compose.service")
        .cloned()
        .unwrap_or_else(|| c.name.clone())
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => serde_json::to_string(s).unwrap_or_default(),
        other => other.to_string(),
    }
}

fn is_plain_key(k: &str) -> bool {
    let reserved = matches!(
        k.to_ascii_lowercase().as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off" | "y" | "n" | "null" | "~"
    );
    !reserved
        && k.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn emit(v: &Value, indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                let key = if is_plain_key(k) {
                    k.clone()
                } else {
                    scalar(&Value::String(k.clone()))
                };
                match val {
                    Value::Object(m) if !m.is_empty() => {
                        out.push_str(&format!("{pad}{key}:\n"));
                        emit(val, indent + 2, out);
                    }
                    Value::Array(a) if !a.is_empty() => {
                        out.push_str(&format!("{pad}{key}:\n"));
                        emit(val, indent + 2, out);
                    }
                    Value::Object(_) => out.push_str(&format!("{pad}{key}: {{}}\n")),
                    Value::Array(_) => out.push_str(&format!("{pad}{key}: []\n")),
                    _ => out.push_str(&format!("{pad}{key}: {}\n", scalar(val))),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::Object(m) if !m.is_empty() => {
                        let mut inner = String::new();
                        emit(item, indent + 2, &mut inner);
                        let inner = inner.replacen(&" ".repeat(indent + 2), "", 1);
                        out.push_str(&format!("{pad}- {inner}"));
                    }
                    Value::Array(_) | Value::Object(_) => {
                        out.push_str(&format!("{pad}- {}\n", item))
                    }
                    _ => out.push_str(&format!("{pad}- {}\n", scalar(item))),
                }
            }
        }
        _ => out.push_str(&format!("{pad}{}\n", scalar(v))),
    }
}

pub fn compose_yaml(c: &ContainerInspectOutput) -> ContainerComposeOutput {
    let service = service_key(c);
    let mut doc = serde_json::Map::new();
    doc.insert(
        "services".into(),
        json!({ service.clone(): service_value(c) }),
    );
    let external: Vec<&String> = c.networks.iter().filter(|n| is_named_network(n)).collect();
    let mode = c.network_mode.as_str();
    if !external.is_empty() && !matches!(mode, "host" | "none") && !mode.starts_with("container:") {
        let mut nets: serde_json::Map<String, Value> = external
            .iter()
            .map(|n| ((*n).clone(), json!({ "external": true })))
            .collect();
        if c.networks.iter().any(|n| n == "bridge") {
            nets.insert(
                "default".into(),
                json!({ "name": "bridge", "external": true }),
            );
        }
        doc.insert("networks".into(), Value::Object(nets));
    }
    let vols: serde_json::Map<String, Value> = c
        .mounts
        .iter()
        .filter(|m| m.kind == "volume")
        .filter_map(|m| m.volume_name.clone())
        .filter(|v| !is_anonymous_volume(v))
        .map(|v| (v, json!({ "external": true })))
        .collect();
    if !vols.is_empty() {
        doc.insert("volumes".into(), Value::Object(vols));
    }
    let mut yaml = String::new();
    for key in ["services", "networks", "volumes"] {
        if let Some(v) = doc.remove(key) {
            emit(&json!({ key: v }), 0, &mut yaml);
        }
    }
    ContainerComposeOutput { service, yaml }
}

pub async fn inspect(
    docker: &Docker,
    container: &str,
    view: View,
) -> Result<ContainerInspectOutput> {
    let target = crate::container_delete::parse_name(container)?;
    let opts = InspectContainerOptionsBuilder::new().build();
    match docker.inspect_container(&target, Some(opts)).await {
        Ok(c) => {
            let mut out = describe(&c, view, Endpoint::current());
            if !out.image_id.is_empty() {
                match docker.inspect_image(&out.image_id).await {
                    Ok(image) => {
                        out.repo_digests = image.repo_digests.unwrap_or_default();
                        out.repo_digests.sort();
                    }
                    Err(e) => {
                        out.repo_digests_error =
                            Some(format!("inspect image {}: {e}", out.image_id));
                    }
                }
            }
            Ok(out)
        }
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => bail!("no container '{target}'"),
        Err(e) => bail!("inspect container {target}: {e}"),
    }
}

fn client() -> Result<Docker> {
    crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))
}

/// **Inspect a container** by name or id: image, image id and repo digests
/// (`repoDigestsError` when the image lookup fails), command, entrypoint, env
/// names, networks, ports, mounts, restart policy, devices, GPU requests,
/// capabilities, privileged, read-only rootfs, PID/IPC/UTS modes, labels, user,
/// working dir, healthcheck. Every caller gets env names only (each value is
/// `***`, `redacted` marks a secret-looking one) and `***` for every host path
/// (mount and sensitive bind sources, device host paths, working dir), compose project path label, DNS server, `extraHosts` and port host
/// address; log option and label values have credentials scrubbed and IP
/// literals and URL hosts masked. Bind mounts of runtime sockets and
/// sensitive host paths are listed by class in `sensitiveBinds`, each with a
/// `basis`: `resolved` when the symlink-resolved path decided the class (local
/// unix-socket engine only), else `lexical`. The classification is advisory: symlinks resolve at
/// inspect time, not container start, so a repointed link is missed. Callable by plugins through `tool.call`; the unfiltered
/// form is `docker.container_inspect_raw`. Read-only.
#[orca_tool(
    domain = "docker",
    verb = "container_inspect",
    role = "read",
    execute_gated = false,
    tool_callable = true
)]
async fn docker_container_inspect(
    args: DockerContainerInspectArgs,
    _ctx: &ToolCtx,
) -> Result<ContainerInspectOutput> {
    inspect(&client()?, &args.container, View::Names).await
}

/// **Inspect a container, unfiltered**: `docker.container_inspect` with real
/// env values, command, entrypoint, healthcheck test, host paths (mount
/// sources, device host paths, working dir), compose project path labels, DNS
/// servers and `extraHosts` addresses. Still masked: secret-looking label values
/// (listed in `redactedLabels`) and credentials in log option values. Admin
/// only; not callable through `tool.call`. Read-only.
#[orca_tool(
    domain = "docker",
    verb = "container_inspect_raw",
    role = "admin",
    execute_gated = false
)]
async fn docker_container_inspect_raw(
    args: DockerContainerInspectArgs,
    ctx: &ToolCtx,
) -> Result<ContainerInspectOutput> {
    crate::execute::require_admin("docker.container_inspect_raw", ctx)?;
    inspect(&client()?, &args.container, View::Admin).await
}

/// **Render a container as a Compose service** by name or id. Secret-looking
/// env values become `${NAME}` references; bind-mount sources become
/// `${SECRET_SOURCE_…}` references unless an admin calls directly. Read-only.
#[orca_tool(
    domain = "docker",
    verb = "container_compose",
    role = "read",
    execute_gated = false
)]
async fn docker_container_compose(
    args: DockerContainerInspectArgs,
    ctx: &ToolCtx,
) -> Result<ContainerComposeOutput> {
    Ok(compose_yaml(
        &inspect(&client()?, &args.container, View::of(ctx)).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};

    fn engine() -> FakeEngine {
        FakeEngine::routed(vec![
            plex_route(),
            Route::new(
                "GET",
                "/images/sha256:feed/json",
                200,
                json!({
                    "Id": "sha256:feed",
                    "RepoDigests": ["plexinc/pms-docker@sha256:beef", "mirror/pms@sha256:abba"]
                })
                .to_string(),
            ),
        ])
    }

    fn plex_route() -> Route {
        Route::new(
            "GET",
            "/containers/plex/json",
            200,
            json!({
                "Id": "abc123",
                "Name": "/plex",
                "Image": "sha256:feed",
                "Config": {
                    "Image": "plexinc/pms-docker:latest",
                    "Cmd": ["--verbose"],
                    "Entrypoint": ["/init"],
                    "Env": ["TZ=UTC", "PLEX_CLAIM=claim-xyz", "DB_PASSWORD=hunter2", "api_key=k", "COST=$5"],
                    "Labels": { "com.docker.compose.service": "plex", "app": "media" },
                    "User": "1000:1000",
                    "WorkingDir": "/srv",
                    "Healthcheck": {
                        "Test": ["CMD", "curl", "-f", "http://localhost"],
                        "Interval": 30_000_000_000i64,
                        "Timeout": 1_500_000_000i64,
                        "Retries": 3
                    }
                },
                "HostConfig": {
                    "NetworkMode": "media",
                    "PortBindings": { "32400/tcp": [{ "HostIp": "", "HostPort": "32400" }], "1900/udp": [{ "HostIp": "10.0.0.5", "HostPort": "1900" }] },
                    "RestartPolicy": { "Name": "unless-stopped", "MaximumRetryCount": 0 },
                    "DeviceRequests": [{ "Driver": "nvidia", "Count": -1, "Capabilities": [["gpu"]] }],
                    "Devices": [{ "PathOnHost": "/dev/dri", "PathInContainer": "/dev/dri", "CgroupPermissions": "rwm" }],
                    "CapAdd": ["NET_ADMIN"],
                    "CapDrop": ["ALL"],
                    "Privileged": false,
                    "ReadonlyRootfs": true,
                    "UTSMode": "host",
                    "PidMode": "host",
                    "IpcMode": "private",
                    "SecurityOpt": ["no-new-privileges:true"]
                },
                "Mounts": [
                    { "Type": "bind", "Source": "/mnt/media", "Destination": "/media", "RW": false },
                    { "Type": "volume", "Name": "plex_config", "Source": "/var/lib/docker/volumes/plex_config/_data", "Destination": "/config", "RW": true }
                ],
                "NetworkSettings": { "Networks": { "media": {} } }
            })
            .to_string(),
        )
    }

    #[test]
    fn hardening_fields_and_image_digests_are_reported() {
        let out = inspected();
        assert!(out.read_only_rootfs);
        assert_eq!(out.uts_mode, "host");
        assert_eq!(out.pid_mode, "host");
        assert_eq!(out.ipc_mode, "private");
        assert_eq!(out.security_opt, ["no-new-privileges:true"]);
        assert_eq!(out.image_id, "sha256:feed");
        assert_eq!(
            out.repo_digests,
            ["mirror/pms@sha256:abba", "plexinc/pms-docker@sha256:beef"]
        );
    }

    fn inspected() -> ContainerInspectOutput {
        inspected_as(View::Reader)
    }

    fn inspected_as(view: View) -> ContainerInspectOutput {
        let e = engine();
        plugin_toolkit::reactor::block_on(inspect(&e.client(), "plex", view)).unwrap()
    }

    fn with_image_status(status: u16) -> ContainerInspectOutput {
        let e = FakeEngine::routed(vec![
            plex_route(),
            Route::new(
                "GET",
                "/images/sha256:feed/json",
                status,
                json!({ "message": "image lookup failed" }).to_string(),
            ),
        ]);
        plugin_toolkit::reactor::block_on(inspect(&e.client(), "plex", View::Reader)).unwrap()
    }

    #[test]
    fn a_failed_image_lookup_is_reported_not_hidden() {
        for status in [404, 500] {
            let out = with_image_status(status);
            assert!(out.repo_digests.is_empty(), "{status}");
            let err = out.repo_digests_error.as_deref().unwrap_or_default();
            assert!(
                err.starts_with("inspect image sha256:feed: "),
                "{status}: {err}"
            );
            assert!(err.contains("image lookup failed"), "{status}: {err}");
        }
        assert_eq!(inspected().repo_digests_error, None);
        let json = serde_json::to_value(with_image_status(500)).unwrap();
        assert!(json["repoDigestsError"].is_string(), "{json}");
    }

    #[test]
    fn an_admin_direct_call_sees_raw_env_and_mount_sources() {
        let out = inspected_as(View::Admin);
        let by: BTreeMap<_, _> = out.env.iter().map(|e| (e.name.as_str(), e)).collect();
        assert_eq!(by["DB_PASSWORD"].value, "hunter2");
        assert!(!by["DB_PASSWORD"].redacted);
        assert_eq!(out.mounts[0].source, "/mnt/media");
        let y = compose_yaml(&out).yaml;
        assert!(!y.contains("hunter2"), "{y}");
        assert!(y.contains("DB_PASSWORD: \"${DB_PASSWORD}\""), "{y}");
    }

    #[test]
    fn an_admin_sees_command_entrypoint_and_healthcheck_unmasked() {
        let c = serde_json::from_value::<ContainerInspectResponse>(json!({
            "Id": "x",
            "Config": {
                "Cmd": ["--password", "hunter2"],
                "Entrypoint": ["run", "--token=s3cr3t"],
                "Healthcheck": { "Test": ["CMD", "curl", "-u", "admin:hunter2", "http://x"] }
            }
        }))
        .unwrap();
        let admin = describe(&c, View::Admin, Endpoint::Remote);
        assert_eq!(admin.command, ["--password", "hunter2"]);
        assert_eq!(admin.entrypoint, ["run", "--token=s3cr3t"]);
        assert_eq!(
            admin.healthcheck.unwrap().test,
            ["CMD", "curl", "-u", "admin:hunter2", "http://x"]
        );
        let reader = describe(&c, View::Reader, Endpoint::Remote);
        for leak in ["hunter2", "s3cr3t"] {
            assert!(
                !reader.command.iter().any(|a| a.contains(leak)),
                "{reader:?}"
            );
            assert!(
                !reader.entrypoint.iter().any(|a| a.contains(leak)),
                "{reader:?}"
            );
            assert!(
                !reader
                    .healthcheck
                    .as_ref()
                    .unwrap()
                    .test
                    .iter()
                    .any(|a| a.contains(leak)),
                "{reader:?}"
            );
        }
    }

    #[test]
    fn a_reader_sees_no_mount_sources() {
        let out = inspected();
        assert!(
            out.mounts.iter().all(|m| m.source == REDACTED),
            "{:?}",
            out.mounts
        );
        assert_eq!(out.mounts[0].target, "/media");
        let y = compose_yaml(&out).yaml;
        assert!(y.contains("source: \"${SECRET_SOURCE_MEDIA}\""), "{y}");
        assert!(!y.contains("/mnt/media"), "{y}");
    }

    #[test]
    fn the_names_view_hides_values_but_keeps_the_secret_flag() {
        let out = inspected_as(View::Names);
        let names: Vec<_> = out.env.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            ["TZ", "PLEX_CLAIM", "DB_PASSWORD", "api_key", "COST"]
        );
        assert!(out.env.iter().all(|e| e.value == REDACTED));
        let flagged: Vec<_> = out
            .env
            .iter()
            .filter(|e| e.redacted)
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(flagged, ["PLEX_CLAIM", "DB_PASSWORD", "api_key"]);
        assert!(out.mounts.iter().all(|m| m.source == REDACTED));
        assert!(!serde_json::to_string(&out).unwrap().contains("/mnt/media"));
    }

    #[test]
    fn mask_hosts_hides_ip_literals_and_url_authorities() {
        assert_eq!(mask_hosts("tcp://10.0.0.5:514"), "tcp://***");
        assert_eq!(
            mask_hosts("http://10.0.0.9:3100/loki/api/v1/push"),
            "http://***/loki/api/v1/push"
        );
        assert_eq!(mask_hosts("fluentd.lan:24224"), "***:24224");
        assert_eq!(mask_hosts("10.0.0.5:24224"), "***:24224");
        assert_eq!(mask_hosts("[fe80::1]:53"), "***:53");
        assert_eq!(mask_hosts("Host(`a`) && 192.168.1.2"), "Host(`a`) && ***");
        assert_eq!(mask_hosts("app"), "app");
        assert_eq!(mask_hosts("v1.2.3"), "v1.2.3");
    }

    #[test]
    fn mask_hosts_masks_port_triples_keeping_the_ports() {
        assert_eq!(mask_hosts("10.0.0.5:8080:80"), "***:8080:80");
    }

    #[test]
    fn mask_hosts_treats_underscores_as_hostname_chars() {
        assert_eq!(mask_hosts("my_host.lan:514"), "***:514");
    }

    #[test]
    fn mask_hosts_masks_dotless_host_port() {
        assert_eq!(mask_hosts("nas:514"), "***:514");
        assert_eq!(mask_hosts("fluentd:24224"), "***:24224");
        assert_eq!(mask_hosts("nas:http"), "nas:http");
    }

    #[test]
    fn mask_hosts_leaves_routing_rule_names_alone() {
        let rule = "Host(`app.example.com`) && PathPrefix(`/api`)";
        assert_eq!(mask_hosts(rule), rule);
    }

    #[test]
    fn wildcard_host_ips_pass_through_unmasked() {
        let c: ContainerInspectResponse = serde_json::from_value(json!({
            "Id": "x",
            "HostConfig": { "PortBindings": {
                "80/tcp": [{ "HostIp": "0.0.0.0", "HostPort": "80" }],
                "443/tcp": [{ "HostIp": "::", "HostPort": "443" }]
            } }
        }))
        .unwrap();
        let out = describe(&c, View::Reader, Endpoint::Remote);
        let mut ips: Vec<_> = out.ports.iter().map(|p| p.host_ip.as_deref()).collect();
        ips.sort();
        assert_eq!(ips, [Some("0.0.0.0"), Some("::")]);
    }

    #[test]
    fn port_placeholders_are_unique_per_binding() {
        let c: ContainerInspectResponse = serde_json::from_value(json!({
            "Id": "x",
            "HostConfig": { "PortBindings": { "80/tcp": [
                { "HostIp": "10.0.0.5", "HostPort": "8080" },
                { "HostIp": "10.0.0.6", "HostPort": "8081" },
                { "HostIp": "10.0.0.7" }
            ] } }
        }))
        .unwrap();
        let y = compose_yaml(&describe(&c, View::Reader, Endpoint::Remote)).yaml;
        assert!(
            y.contains("\"${SECRET_HOST_IP_80_TCP_8080}:8080:80\""),
            "{y}"
        );
        assert!(
            y.contains("\"${SECRET_HOST_IP_80_TCP_8081}:8081:80\""),
            "{y}"
        );
        assert!(y.contains("\"${SECRET_HOST_IP_80_TCP_2}::80\""), "{y}");
    }

    fn host_bearing() -> ContainerInspectResponse {
        serde_json::from_value(json!({
            "Id": "x",
            "Config": { "Labels": {
                "traefik.http.services.x.loadbalancer.server.url": "http://10.0.0.5:8080",
                "app": "media"
            } },
            "HostConfig": {
                "PortBindings": { "80/tcp": [{ "HostIp": "10.0.0.5", "HostPort": "8080" }] },
                "LogConfig": { "Type": "syslog", "Config": {
                    "syslog-address": "tcp://10.0.0.5:514",
                    "fluentd-address": "10.0.0.6:24224",
                    "gelf-address": "udp://gelf.lan:12201",
                    "loki-url": "http://10.0.0.9:3100/loki/api/v1/push",
                    "tag": "app"
                } }
            }
        }))
        .unwrap()
    }

    #[test]
    fn scrubbed_view_hides_port_host_addresses() {
        let c = host_bearing();
        for view in [View::Reader, View::Names] {
            let out = describe(&c, view, Endpoint::Remote);
            assert_eq!(out.ports[0].host_ip.as_deref(), Some(REDACTED));
            let y = compose_yaml(&out).yaml;
            assert!(
                y.contains("\"${SECRET_HOST_IP_80_TCP_8080}:8080:80\""),
                "{y}"
            );
            assert!(!y.contains("10.0.0.5"), "{y}");
        }
        let admin = describe(&c, View::Admin, Endpoint::Remote);
        assert_eq!(admin.ports[0].host_ip.as_deref(), Some("10.0.0.5"));
        assert!(compose_yaml(&admin).yaml.contains("\"10.0.0.5:8080:80\""));
    }

    #[test]
    fn scrubbed_view_hides_log_option_host_addresses() {
        let c = host_bearing();
        for view in [View::Reader, View::Names] {
            let out = describe(&c, view, Endpoint::Remote);
            assert_eq!(out.log_options["syslog-address"], "tcp://***");
            assert_eq!(out.log_options["fluentd-address"], "***:24224");
            assert_eq!(out.log_options["gelf-address"], "udp://***");
            assert_eq!(out.log_options["loki-url"], "http://***/loki/api/v1/push");
            assert_eq!(out.log_options["tag"], "app");
            let y = compose_yaml(&out).yaml;
            assert!(
                y.contains("syslog-address: \"${SECRET_SYSLOG_ADDRESS}\""),
                "{y}"
            );
            for leak in ["10.0.0.5", "10.0.0.6", "10.0.0.9", "gelf.lan"] {
                assert!(!y.contains(leak), "{view:?} {leak}");
            }
        }
        let admin = describe(&c, View::Admin, Endpoint::Remote);
        assert_eq!(admin.log_options["syslog-address"], "tcp://10.0.0.5:514");
        assert_eq!(admin.log_options["fluentd-address"], "10.0.0.6:24224");
        assert_eq!(admin.log_options["gelf-address"], "udp://gelf.lan:12201");
        assert_eq!(
            admin.log_options["loki-url"],
            "http://10.0.0.9:3100/loki/api/v1/push"
        );
    }

    #[test]
    fn scrubbed_view_hides_label_host_addresses() {
        let c = host_bearing();
        let key = "traefik.http.services.x.loadbalancer.server.url";
        for view in [View::Reader, View::Names] {
            let out = describe(&c, view, Endpoint::Remote);
            assert_eq!(out.labels[key], "http://***");
            assert_eq!(out.labels["app"], "media");
            assert!(!compose_yaml(&out).yaml.contains("10.0.0.5"));
        }
        let admin = describe(&c, View::Admin, Endpoint::Remote);
        assert_eq!(admin.labels[key], "http://10.0.0.5:8080");
    }

    #[test]
    fn compose_path_labels_are_masked_outside_the_admin_view() {
        let mut c = serde_json::from_value::<ContainerInspectResponse>(json!({
            "Id": "x",
            "Config": { "Labels": {
                "com.docker.compose.project": "media",
                "com.docker.compose.service": "plex",
                "com.docker.compose.version": "2.29.0",
                "com.docker.compose.project.working_dir": "/opt/stacks/x",
                "com.docker.compose.project.config_files": "/mnt/secret/x.yml",
                "com.docker.compose.project.environment_file": "/opt/stacks/x/.env"
            } }
        }))
        .unwrap();
        for view in [View::Reader, View::Names] {
            let labels = describe(&c, view, Endpoint::Remote).labels;
            for key in COMPOSE_PATH_LABELS {
                assert_eq!(labels[key], REDACTED, "{view:?} {key}");
            }
            assert_eq!(labels["com.docker.compose.project"], "media");
            assert_eq!(labels["com.docker.compose.service"], "plex");
            assert_eq!(labels["com.docker.compose.version"], "2.29.0");
            let json = serde_json::to_string(&describe(&c, view, Endpoint::Remote)).unwrap();
            for leak in ["/opt/stacks", "/mnt/secret"] {
                assert!(!json.contains(leak), "{view:?} {leak}");
            }
        }
        let admin = describe(&c, View::Admin, Endpoint::Remote).labels;
        assert_eq!(
            admin["com.docker.compose.project.working_dir"],
            "/opt/stacks/x"
        );
        assert_eq!(
            admin["com.docker.compose.project.config_files"],
            "/mnt/secret/x.yml"
        );
        c.config = None;
        assert!(
            describe(&c, View::Names, Endpoint::Remote)
                .labels
                .is_empty()
        );
    }

    #[test]
    fn the_raw_inspect_tool_refuses_a_non_admin_caller() {
        for ctx in crate::test_support::non_admins() {
            let err = plugin_toolkit::reactor::block_on(docker_container_inspect_raw(
                DockerContainerInspectArgs {
                    container: "plex".into(),
                },
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
        }
    }

    #[test]
    fn the_raw_inspect_gate_ranks_roles_instead_of_matching_admin_exactly() {
        use crate::test_support::{caller, test_ctx};
        let gate = |role: &str| {
            crate::execute::require_admin(
                "docker.container_inspect_raw",
                &test_ctx().with_auth(caller(role)),
            )
        };
        gate("admin").unwrap();
        gate("super-admin").unwrap();
        for role in ["read", "superadmin", "root"] {
            crate::test_support::assert_admin_refusal(&gate(role).unwrap_err().to_string());
        }
    }

    #[test]
    fn only_the_scrubbed_inspect_tool_is_callable_through_tool_call() {
        use plugin_toolkit::contract::OrcaToolDef;
        assert_eq!(DockerContainerInspect::NAME, "docker.container_inspect");
        const { assert!(DockerContainerInspect::TOOL_CALLABLE) };
        assert_eq!(
            DockerContainerInspectRaw::NAME,
            "docker.container_inspect_raw"
        );
        const { assert!(!DockerContainerInspectRaw::TOOL_CALLABLE) };
    }

    #[test]
    fn only_a_local_linux_unix_socket_is_a_local_endpoint() {
        let local = if cfg!(target_os = "linux") {
            Endpoint::Local
        } else {
            Endpoint::Remote
        };
        assert_eq!(Endpoint::of(None), local);
        assert_eq!(Endpoint::of(Some("unix:///var/run/docker.sock")), local);
        for remote in [
            "tcp://10.0.0.5:2375",
            "ssh://deploy@build",
            "unix:///home/a/.colima/default/docker.sock",
            "unix:///home/a/.docker/desktop/docker.sock",
        ] {
            assert_eq!(Endpoint::of(Some(remote)), Endpoint::Remote, "{remote}");
        }
    }

    #[test]
    fn symlinked_bind_sources_classify_by_their_real_target() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let sock = dir.join("docker.sock");
        std::fs::write(&sock, "").unwrap();
        let to_sock = dir.join("innocent");
        let to_root = dir.join("rootlink");
        std::os::unix::fs::symlink(&sock, &to_sock).unwrap();
        std::os::unix::fs::symlink("/", &to_root).unwrap();
        assert_eq!(
            classify_bind(to_sock.to_str().unwrap(), Endpoint::Local),
            Some(("runtimeSocket", "resolved"))
        );
        assert_eq!(
            classify_bind(to_root.to_str().unwrap(), Endpoint::Local),
            Some(("sensitivePath", "resolved"))
        );
        assert_eq!(
            classify_bind("/definitely/not/a/real/dir", Endpoint::Local),
            None
        );
        assert_eq!(
            classify_bind(to_sock.to_str().unwrap(), Endpoint::Remote),
            None
        );
        assert_eq!(
            classify_bind(to_root.to_str().unwrap(), Endpoint::Remote),
            None
        );
        assert_eq!(
            classify_bind("/etc/ssh", Endpoint::Remote),
            Some(("sensitivePath", "lexical"))
        );
    }

    #[test]
    fn basis_is_lexical_when_the_lexical_class_alone_decides() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("docker.sock");
        std::fs::write(&sock, "").unwrap();
        let real = std::fs::canonicalize(&sock).unwrap();
        assert_eq!(
            classify_bind(real.to_str().unwrap(), Endpoint::Local),
            Some(("runtimeSocket", "lexical"))
        );
        assert_eq!(
            classify_bind("/", Endpoint::Local),
            Some(("sensitivePath", "lexical"))
        );
        let to_sock = tmp.path().join("etc-link");
        std::os::unix::fs::symlink(&sock, &to_sock).unwrap();
        assert_eq!(
            classify_bind(to_sock.to_str().unwrap(), Endpoint::Local),
            Some(("runtimeSocket", "resolved"))
        );
    }

    #[test]
    fn bind_sources_are_classified_without_exposing_ordinary_paths() {
        for (path, class) in [
            ("/var/run/docker.sock", Some("runtimeSocket")),
            ("/run/user/1000/podman/podman.sock", Some("runtimeSocket")),
            ("/var/run", Some("runtimeSocket")),
            ("/etc/ssh", Some("sensitivePath")),
            ("/", Some("sensitivePath")),
            ("/mnt/media", None),
            ("/home/app", None),
            ("/run/user/1000", Some("runtimeSocket")),
            ("/run/user/1000/pulse", Some("sensitivePath")),
            ("/run/dbus", Some("sensitivePath")),
            ("/etcetera", None),
            ("/srv/app/docker.sock", Some("runtimeSocket")),
            ("/var/lib/containerd/io", Some("sensitivePath")),
            ("/var/lib/kubelet", Some("sensitivePath")),
            ("/var/lib/lxc/101", Some("sensitivePath")),
            ("/usr/local/bin", Some("sensitivePath")),
            ("/home/alice/.ssh", Some("sensitivePath")),
            ("/home/alice/.ssh/id_ed25519", Some("sensitivePath")),
            ("/home/alice/.sshx", None),
            ("/home/alice/data", None),
            ("/etc/pve/nodes", Some("sensitivePath")),
            (
                "/Users/a/.colima/default/docker.sock",
                Some("runtimeSocket"),
            ),
            (
                "/run/host-services/docker.proxy.sock",
                Some("runtimeSocket"),
            ),
            ("/var/run/docker.sock.raw", Some("runtimeSocket")),
            ("/run/k3s/containerd/containerd.sock", Some("runtimeSocket")),
            ("/run/crio/crio.sock", Some("runtimeSocket")),
            ("/srv/app/app.sock", None),
            ("/srv/docker-data", None),
            ("//etc//ssh", Some("sensitivePath")),
            ("/mnt/./media/../../etc", Some("sensitivePath")),
            ("/mnt/media/../../../etc", Some("sensitivePath")),
            ("/mnt/../../mnt", Some("sensitivePath")),
            ("/mnt/media/", None),
            ("/mnt//media/./x", None),
            ("/var//run///docker.sock", Some("runtimeSocket")),
            ("/Users/x/.ssh", Some("sensitivePath")),
            ("/Users/x/.SSH", Some("sensitivePath")),
            ("/HOME/x/.Ssh/id_ed25519", Some("sensitivePath")),
            ("/ETC", Some("sensitivePath")),
            ("/Etc/passwd", Some("sensitivePath")),
            ("/VAR/RUN/Docker.sock", Some("runtimeSocket")),
            ("/home/x/.docker", Some("sensitivePath")),
            ("/Users/x/.docker/config.json", Some("sensitivePath")),
            ("/home/x/.kube/config", Some("sensitivePath")),
            ("/Users/x/.aws", Some("sensitivePath")),
            ("/home/x/.gnupg", Some("sensitivePath")),
            ("/Users/x/.config/gcloud", Some("sensitivePath")),
            ("/home/x/.netrc", Some("sensitivePath")),
            ("/root/.aws", Some("sensitivePath")),
            ("/ROOT/.kube", Some("sensitivePath")),
            ("/private/etc", Some("sensitivePath")),
            ("/private/etc/hosts", Some("sensitivePath")),
            ("/PRIVATE/var/lib/docker", Some("sensitivePath")),
            ("/private/var/lib/docker/volumes", Some("sensitivePath")),
            ("/Users/x/.config/other", None),
            ("/Users/x/.dockerignore", None),
            ("/home/.ssh", None),
            ("/Users/x/code", None),
        ] {
            assert_eq!(
                classify_bind(path, Endpoint::Remote).map(|(c, _)| c),
                class,
                "{path}"
            );
        }
        let mut c = serde_json::from_value::<ContainerInspectResponse>(json!({
            "Id": "x",
            "Mounts": [
                { "Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/s", "RW": true },
                { "Type": "bind", "Source": "/etc", "Destination": "/e", "RW": false },
                { "Type": "bind", "Source": "/mnt/media", "Destination": "/m", "RW": true },
                { "Type": "volume", "Name": "etc", "Source": "/etc", "Destination": "/v", "RW": true }
            ]
        }))
        .unwrap();
        let out = describe(&c, View::Admin, Endpoint::Remote);
        assert_eq!(
            out.sensitive_binds,
            vec![
                SensitiveBind {
                    source: "/etc".into(),
                    class: "sensitivePath".into(),
                    read_only: true,
                    basis: "lexical".into(),
                },
                SensitiveBind {
                    source: "/var/run/docker.sock".into(),
                    class: "runtimeSocket".into(),
                    read_only: false,
                    basis: "lexical".into(),
                },
            ]
        );
        c.mounts = None;
        assert!(
            describe(&c, View::Names, Endpoint::Remote)
                .sensitive_binds
                .is_empty()
        );
    }

    #[test]
    fn the_scrubbed_view_hides_host_paths_credentials_and_addresses() {
        let c = serde_json::from_value::<ContainerInspectResponse>(json!({
            "Id": "x",
            "Config": { "WorkingDir": "/srv/app", "Hostname": "box" },
            "HostConfig": {
                "LogConfig": { "Type": "loki", "Config": {
                    "loki-url": "push to https://user:pass@loki.lan/api",
                    "max-size": "10m"
                } },
                "ExtraHosts": ["db.lan:10.1.2.3"],
                "Dns": ["10.1.2.1"],
                "Tmpfs": { "/host/tmp": "rw" },
                "Sysctls": { "net.core.somaxconn": "1024" },
                "Devices": [{ "PathOnHost": "/dev/dri/renderD128", "PathInContainer": "/dev/dri", "CgroupPermissions": "rwm" }]
            },
            "Mounts": [
                { "Type": "bind", "Source": "/etc", "Destination": "/e", "RW": false }
            ]
        }))
        .unwrap();
        for view in [View::Reader, View::Names] {
            let out = describe(&c, view, Endpoint::Remote);
            let text = serde_json::to_string(&out).unwrap();
            for leak in [
                "/etc",
                "/srv/app",
                "user:pass",
                "10.1.2.",
                "/dev/dri/renderD128",
            ] {
                assert!(!text.contains(leak), "{view:?} leaks {leak}: {text}");
            }
            assert_eq!(out.sensitive_binds[0].source, REDACTED);
            assert_eq!(out.sensitive_binds[0].class, "sensitivePath");
            assert_eq!(out.extra_hosts, vec![format!("db.lan:{REDACTED}")]);
            assert_eq!(out.dns, vec![REDACTED.to_owned()]);
            assert_eq!(out.working_dir, REDACTED);
            assert_eq!(out.devices[0].path_on_host, REDACTED);
            assert_eq!(out.hostname, "box");
            assert_eq!(out.sysctls["net.core.somaxconn"], "1024");
        }
        let admin = describe(&c, View::Admin, Endpoint::Remote);
        assert_eq!(admin.sensitive_binds[0].source, "/etc");
        assert_eq!(admin.extra_hosts, vec!["db.lan:10.1.2.3".to_owned()]);
        assert_eq!(admin.dns, vec!["10.1.2.1".to_owned()]);
        assert_eq!(admin.working_dir, "/srv/app");
        assert_eq!(admin.devices[0].path_on_host, "/dev/dri/renderD128");
        let text = serde_json::to_string(&admin).unwrap();
        assert!(!text.contains("user:pass"), "{text}");
        assert!(admin.redacted_log_options.contains(&"loki-url".to_owned()));
    }

    #[test]
    fn only_an_admin_gets_the_unfiltered_view_for_compose() {
        use crate::test_support::{admin, caller, test_ctx};
        assert_eq!(View::of(&test_ctx()), View::Reader);
        assert_eq!(
            View::of(&test_ctx().with_auth(caller("read"))),
            View::Reader
        );
        assert_eq!(
            View::of(&test_ctx().with_auth(caller("user"))),
            View::Reader
        );
        assert_eq!(View::of(&admin()), View::Admin);
        assert_eq!(
            View::of(&test_ctx().with_auth(caller("super-admin"))),
            View::Admin
        );
        assert_eq!(
            View::of(&test_ctx().with_auth(caller("superadmin"))),
            View::Reader
        );
    }

    #[test]
    fn secret_names_match_case_insensitively() {
        for name in [
            "GITHUB_TOKEN",
            "client_secret",
            "DB_PASSWORD",
            "api_key",
            "PASS",
            "AWS_CREDS",
            "Passphrase",
        ] {
            assert!(is_sensitive_key(name), "{name}");
        }
        for name in ["TZ", "PUID", "HOME", "PATH"] {
            assert!(!is_sensitive_key(name), "{name}");
        }
    }

    #[test]
    fn env_values_of_secret_names_are_redacted() {
        let out = inspected();
        let by: BTreeMap<_, _> = out.env.iter().map(|e| (e.name.as_str(), e)).collect();
        assert_eq!(by["TZ"].value, "UTC");
        assert!(!by["TZ"].redacted);
        assert_eq!(by["DB_PASSWORD"].value, REDACTED);
        assert_eq!(by["api_key"].value, REDACTED);
        assert_eq!(by["PLEX_CLAIM"].value, REDACTED);
        assert!(!out.env.iter().any(|e| e.value == "hunter2"));
        assert_eq!(env_var("NOVALUE", View::Reader).value, "");
    }

    #[test]
    fn secret_values_are_redacted_whatever_the_name() {
        for raw in [
            "DB=/run/secrets/db",
            "CONF=/var/run/secrets/app/creds",
            "DATABASE_URL=postgres://app:hunter2@db:5432/app",
            "UPSTREAM=https://u:p@host/path?x=1",
        ] {
            assert_eq!(env_var(raw, View::Reader).value, REDACTED, "{raw}");
        }
        for raw in [
            "URL=https://host/a@b",
            "HOME=/home/app",
            "DSN=redis://cache:6379",
        ] {
            assert!(!env_var(raw, View::Reader).redacted, "{raw}");
        }
    }

    #[test]
    fn secrets_in_args_labels_and_healthchecks_never_leak() {
        let mut c = inspected();
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let raw = args(&[
            "--password",
            "hunter2",
            "--token=tok1",
            "API_KEY=k2",
            "postgres://a:pw3@db/x",
            "--port",
            "80",
        ]);
        let masked = redact_args(&raw, |_| REDACTED.to_owned());
        for leak in ["hunter2", "tok1", "k2", "pw3"] {
            assert!(
                !masked.iter().any(|a| a.contains(leak)),
                "{leak} in {masked:?}"
            );
        }
        assert_eq!(masked[6], "80");
        for (cmd, leak) in [
            (vec!["CMD-SHELL", "mysqladmin -phunter2 ping"], "hunter2"),
            (vec!["sh", "-c", "redis-cli -a hunter2"], "hunter2"),
            (
                vec!["curl", "-H", "Authorization: Bearer xyz", "http://h/"],
                "xyz",
            ),
        ] {
            let cmd: Vec<String> = cmd.into_iter().map(String::from).collect();
            let masked = redact_args(&cmd, |_| REDACTED.to_owned());
            assert!(
                !masked.iter().any(|a| a.contains(leak)),
                "{leak} in {masked:?}"
            );
        }
        for (cmd, leak) in [
            (vec!["redis-cli", "-a", "hunter2"], "hunter2"),
            (vec!["mysqld", "-phunter2"], "hunter2"),
            (vec!["CMD", "mysqladmin", "-phunter2", "ping"], "hunter2"),
            (vec!["curl", "-u", "user:pass"], "pass"),
            (vec!["--header", "X-Api-Key: k9"], "k9"),
            (vec!["-H", "X-Api-Key: k9"], "k9"),
        ] {
            let cmd: Vec<String> = cmd.into_iter().map(String::from).collect();
            let masked = redact_args(&cmd, |_| REDACTED.to_owned());
            assert!(masked.iter().any(|a| a.contains(REDACTED)), "{masked:?}");
            assert!(
                !masked.iter().any(|a| a.contains(leak)),
                "{leak} in {masked:?}"
            );
        }
        let benign: Vec<String> = ["sh", "-c", "nginx -g  'daemon off;' -p 80"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(redact_args(&benign, |_| REDACTED.to_owned()), benign);
        for (cmd, leaks) in [
            (
                "app --password 'correct horse battery'",
                &["correct", "horse", "battery"][..],
            ),
            ("app --token \"zq1 zq2\"", &["zq1", "zq2"][..]),
            ("app --password=\"zq1 zq2 zq3\"", &["zq1", "zq2", "zq3"][..]),
            (
                "app --password 'unbalanced horse",
                &["unbalanced", "horse"][..],
            ),
            ("app --token=\"zq1 zq2", &["zq1", "zq2"][..]),
        ] {
            let cmd = args(&["sh", "-c", cmd]);
            let masked = redact_args(&cmd, |_| REDACTED.to_owned());
            let words: Vec<&str> = masked[2].split_whitespace().collect();
            assert!(masked[2].contains(REDACTED), "{masked:?}");
            for leak in leaks {
                assert!(
                    !words.iter().any(|w| w.contains(leak)),
                    "{leak} in {masked:?}"
                );
            }
        }
        let benign = args(&["sh", "-c", "nginx -g 'daemon off;'"]);
        assert_eq!(redact_args(&benign, |_| REDACTED.to_owned()), benign);
        c.command = masked;
        c.labels.insert(
            "traefik.http.middlewares.a.basicauth.users".into(),
            REDACTED.into(),
        );
        c.redacted_labels = vec!["traefik.http.middlewares.a.basicauth.users".into()];
        let y = compose_yaml(&c).yaml;
        assert!(
            y.contains("- \"--password\"\n      - \"${SECRET_PASSWORD}\"\n"),
            "{y}"
        );
        assert!(y.contains("- \"--token=${SECRET_TOKEN}\"\n"), "{y}");
        assert!(y.contains("- \"API_KEY=${API_KEY}\"\n"), "{y}");
        assert!(y.contains("- \"${ARG}\"\n"), "{y}");
        assert!(
            y.contains(
                "basicauth.users\": \"${SECRET_TRAEFIK_HTTP_MIDDLEWARES_A_BASICAUTH_USERS}\""
            ) || y.contains(
                "basicauth.users: \"${SECRET_TRAEFIK_HTTP_MIDDLEWARES_A_BASICAUTH_USERS}\""
            ),
            "{y}"
        );
        assert!(!y.contains(REDACTED), "{y}");
    }

    #[test]
    fn secrets_inside_nested_shell_commands_are_redacted() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for cmd in [
            "su redis -c 'redis-cli -a hunter2 ping'",
            "su app -c \"curl -fsu admin:hunter2 http://localhost/health\"",
            "sh -c 'mysqladmin ping -uroot -phunter2'",
            "echo \"$(curl -u \"admin:hunter2\" x)\"",
            "sh -c \"su app -c 'sh -c \\\"sh -c \\\\\\\"app -a hunter2\\\\\\\"\\\"'\"",
        ] {
            let masked = redact_args(&args(&["sh", "-c", cmd]), |_| REDACTED.to_owned());
            assert!(!masked[2].contains("hunter2"), "{masked:?}");
            assert!(masked[2].contains(REDACTED), "{masked:?}");
        }
        let benign = args(&["sh", "-c", "su app -c 'redis-cli ping'"]);
        assert_eq!(redact_args(&benign, |_| REDACTED.to_owned()), benign);
    }

    #[test]
    fn a_secret_flag_ending_a_command_string_masks_the_next_element() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let masked = redact_args(&args(&["app --password", "hunter2"]), |_| {
            REDACTED.to_owned()
        });
        assert_eq!(masked, args(&["app --password", REDACTED]));
    }

    #[test]
    fn value_taking_short_flag_clusters_end_in_a_u_or_h() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let r = |v: &[&str]| redact_args(&args(v), |_| REDACTED.to_owned());
        assert_eq!(
            r(&["curl", "-sH", "Authorization: Bearer tok"])[2],
            REDACTED
        );
        assert_eq!(r(&["redis-cli", "-xa", "hunter2"])[2], REDACTED);
        assert_eq!(r(&["curl", "-fsu", "admin:hunter2"])[2], REDACTED);
        assert_eq!(r(&["curl", "-uadmin:hunter2"])[1], format!("-u{REDACTED}"));
        assert_eq!(r(&["curl", "-Hvalue"])[1], format!("-H{REDACTED}"));
        assert_eq!(r(&["redis-cli", "-ahunter"])[1], format!("-a{REDACTED}"));
        assert_eq!(r(&["redis-cli", "-xahunter"])[1], format!("-xa{REDACTED}"));
        assert_eq!(r(&["curl", "-fsuadmin"])[1], format!("-fsu{REDACTED}"));
        let masked = r(&["sh", "-c", "redis-cli -xahunter ping"]);
        assert!(!masked[2].contains("hunter"), "{masked:?}");
        let masked = r(&["sh", "-c", "curl -sH 'Authorization: Bearer tok' x"]);
        assert!(!masked[2].contains("tok'"), "{masked:?}");
        assert!(!masked[2].contains("Bearer"), "{masked:?}");
        assert_eq!(r(&["redis-cli", "-Xahunter"])[1], format!("-Xa{REDACTED}"));
        assert_eq!(r(&["redis-cli", "-2ahunter"])[1], format!("-2a{REDACTED}"));
        assert_eq!(r(&["curl", "-Kfsuadmin:pw"])[1], format!("-Kfsu{REDACTED}"));
        assert_eq!(r(&["curl", "-KHvalue"])[1], format!("-KH{REDACTED}"));
        let masked = r(&["sh", "-c", "curl -Kfsuadmin:pw x; redis-cli -2ahunter"]);
        assert!(!masked[2].contains("admin:pw"), "{masked:?}");
        assert!(!masked[2].contains("hunter"), "{masked:?}");
        let masked = r(&["x", "-\u{e9}ahunter", "-a\u{e9}\u{79d8}\u{5bc6}"]);
        assert!(
            masked[1].starts_with("-\u{e9}a") && !masked[1].contains("hunter"),
            "{masked:?}"
        );
        assert!(
            masked[2].starts_with("-a") && !masked[2].contains('\u{79d8}'),
            "{masked:?}"
        );
        let benign = args(&["curl", "-fsSL", "-o", "out"]);
        assert_eq!(redact_args(&benign, |_| REDACTED.to_owned()), benign);
        let benign = args(&[
            "x",
            "-o/tmp/out.tar",
            "-c/etc/app.conf",
            "-XX:MaxRAMPercentage=75",
            "-Duser.home=/x",
            "-Dfile.encoding=UTF-8",
        ]);
        assert_eq!(redact_args(&benign, |_| REDACTED.to_owned()), benign);
        assert_eq!(r(&["java", "-Xufoo=bar"])[1], format!("-Xu{REDACTED}"));
        assert_eq!(r(&["curl", "-Kusecret=x"])[1], format!("-Ku{REDACTED}"));
        assert_eq!(r(&["curl", "-ukey=val"])[1], format!("-u{REDACTED}"));
        for prop in ["-Ddb.password=hunter2", "-Dapi.token=abc", "-Dpassword=x"] {
            let masked = r(&["java", prop]);
            let (key, value) = prop.split_once('=').unwrap();
            assert!(
                masked[1].starts_with(key) && !masked[1].ends_with(&format!("={value}")),
                "{masked:?}"
            );
        }
    }

    #[test]
    fn a_nested_trailing_secret_flag_masks_the_next_word() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for cmd in [
            "eval 'curl -su' admin:hunter2",
            "eval 'redis-cli -a' hunter2",
            "eval 'mysql --password' hunter2",
        ] {
            let masked = redact_args(&args(&["sh", "-c", cmd]), |_| REDACTED.to_owned());
            assert!(!masked[2].contains("hunter2"), "{masked:?}");
        }
        let masked = redact_args(&args(&["sh -c 'eval \"redis-cli -a\"'", "hunter2"]), |_| {
            REDACTED.to_owned()
        });
        assert_eq!(masked[1], REDACTED, "{masked:?}");
    }

    #[test]
    fn compose_reproduces_init_anonymous_volumes_and_ipv6_ports() {
        let mut c = inspected();
        c.init = true;
        c.mounts.push(MountInfo {
            kind: "volume".into(),
            source: "/var/lib/docker/volumes/x/_data".into(),
            target: "/cache".into(),
            read_only: false,
            volume_name: Some("a".repeat(64)),
        });
        c.ports = vec![
            PortMapping {
                container_port: "53/udp".into(),
                host_ip: Some("::1".into()),
                host_port: Some("53".into()),
            },
            PortMapping {
                container_port: "80/tcp".into(),
                host_ip: Some("10.0.0.5".into()),
                host_port: None,
            },
        ];
        let y = compose_yaml(&c).yaml;
        assert!(y.contains("    init: true\n"), "{y}");
        assert!(
            y.contains("      - target: \"/cache\"\n        type: \"volume\"\n"),
            "{y}"
        );
        assert!(!y.contains(&"a".repeat(64)), "{y}");
        assert!(y.contains("\"[::1]:53:53/udp\""), "{y}");
        assert!(y.contains("\"10.0.0.5::80\""), "{y}");
        assert!(!y.contains("com.docker.compose"), "{y}");
    }

    #[test]
    fn yaml_quotes_keys_a_parser_would_retype() {
        let mut out = String::new();
        emit(
            &json!({ "on": 1, "8080": 2, "-x": 3, "ok_key": 4 }),
            0,
            &mut out,
        );
        assert!(out.contains("\"on\": 1\n"), "{out}");
        assert!(out.contains("\"8080\": 2\n"), "{out}");
        assert!(out.contains("\"-x\": 3\n"), "{out}");
        assert!(out.contains("ok_key: 4\n"), "{out}");
    }

    #[test]
    fn literal_dollars_are_escaped_everywhere() {
        let mut c = inspected();
        c.command = vec!["echo $HOME".into()];
        c.labels.insert("price".into(), "$5".into());
        let y = compose_yaml(&c).yaml;
        assert!(y.contains("\"echo $$HOME\""), "{y}");
        assert!(y.contains("price: \"$$5\""), "{y}");
    }

    #[test]
    fn inspect_collects_the_runtime_config() {
        let out = inspected();
        assert_eq!(out.name, "plex");
        assert_eq!(out.image, "plexinc/pms-docker:latest");
        assert_eq!(out.entrypoint, vec!["/init"]);
        assert_eq!(out.network_mode, "media");
        assert_eq!(out.networks, vec!["media"]);
        assert_eq!(out.ports.len(), 2);
        assert_eq!(out.ports[0].container_port, "1900/udp");
        assert_eq!(out.ports[0].host_ip.as_deref(), Some(REDACTED));
        assert_eq!(out.ports[1].host_ip, None);
        let admin = inspected_as(View::Admin);
        assert_eq!(admin.ports[0].host_ip.as_deref(), Some("10.0.0.5"));
        assert!(out.mounts[0].read_only);
        assert_eq!(out.mounts[1].volume_name.as_deref(), Some("plex_config"));
        assert_eq!(out.restart_policy.name, "unless-stopped");
        assert_eq!(out.device_requests[0].count, -1);
        assert_eq!(
            out.device_requests[0].capabilities,
            vec![vec!["gpu".to_string()]]
        );
        assert_eq!(out.cap_drop, vec!["ALL"]);
        assert_eq!(out.healthcheck.as_ref().unwrap().retries, Some(3));
    }

    #[test]
    fn compose_uses_env_references_for_secrets() {
        let out = compose_yaml(&inspected());
        assert_eq!(out.service, "plex");
        let y = &out.yaml;
        assert!(y.contains("DB_PASSWORD: \"${DB_PASSWORD}\""), "{y}");
        assert!(y.contains("api_key: \"${api_key}\""), "{y}");
        assert!(y.contains("TZ: \"UTC\""), "{y}");
        assert!(y.contains("COST: \"$$5\""), "{y}");
        assert!(!y.contains("hunter2"), "{y}");
        assert!(!y.contains(REDACTED), "{y}");
    }

    #[test]
    fn compose_renders_the_service_shape() {
        let y = compose_yaml(&inspected_as(View::Admin)).yaml;
        for want in [
            "services:\n  plex:\n    cap_add:\n      - \"NET_ADMIN\"\n",
            "    image: \"plexinc/pms-docker:latest\"\n",
            "    ports:\n      - \"10.0.0.5:1900:1900/udp\"\n      - \"32400:32400\"\n",
            "      - read_only: true\n        source: \"/mnt/media\"\n        target: \"/media\"\n        type: \"bind\"\n",
            "      - source: \"plex_config\"\n        target: \"/config\"\n        type: \"volume\"\n",
            "    restart: \"unless-stopped\"\n",
            "    devices:\n      - \"/dev/dri:/dev/dri\"\n",
            "            - capabilities:\n                - \"gpu\"\n              count: \"all\"\n              driver: \"nvidia\"\n",
            "      interval: \"30s\"\n",
            "      timeout: \"1500ms\"\n",
            "    networks:\n      - \"media\"\n",
            "\nnetworks:\n  media:\n    external: true\nvolumes:\n  plex_config:\n    external: true\n",
        ] {
            assert!(y.contains(want), "missing {want:?} in\n{y}");
        }
    }

    #[test]
    fn host_network_mode_is_emitted_instead_of_networks() {
        let mut c = inspected();
        c.network_mode = "host".into();
        c.networks = vec!["host".into()];
        let y = compose_yaml(&c).yaml;
        assert!(y.contains("network_mode: \"host\""), "{y}");
        assert!(!y.contains("networks"), "{y}");
    }

    fn tuned() -> (ContainerInspectOutput, String) {
        let e = FakeEngine::routed(vec![Route::new(
            "GET",
            "/containers/tuned/json",
            200,
            json!({
                "Id": "f00dfeed",
                "Name": "/tuned",
                "Config": {
                    "Image": "app:1",
                    "Hostname": "apphost",
                    "StopSignal": "SIGINT",
                    "StopTimeout": 30
                },
                "HostConfig": {
                    "NetworkMode": "bridge",
                    "Tmpfs": { "/run": "rw,size=65536k", "/tmp": "" },
                    "ShmSize": 268435456i64,
                    "Sysctls": { "net.core.somaxconn": "1024" },
                    "Ulimits": [
                        { "Name": "nofile", "Soft": 1024, "Hard": 4096 },
                        { "Name": "nproc", "Soft": 512, "Hard": 512 }
                    ],
                    "SecurityOpt": ["no-new-privileges:true"],
                    "ExtraHosts": ["db:10.0.0.9"],
                    "PidMode": "host",
                    "IpcMode": "host",
                    "NanoCpus": 1_500_000_000i64,
                    "Memory": 536870912i64,
                    "PidsLimit": 200,
                    "LogConfig": { "Type": "syslog", "Config": { "tag": "app", "splunk-token": "s3cr3t" } },
                    "Dns": ["10.0.0.1"]
                },
                "NetworkSettings": { "Networks": { "bridge": {}, "media": {} } }
            })
            .to_string(),
        )]);
        let out =
            plugin_toolkit::reactor::block_on(inspect(&e.client(), "tuned", View::Reader)).unwrap();
        let y = compose_yaml(&out).yaml;
        (out, y)
    }

    #[test]
    fn bridge_plus_other_networks_uses_the_default_network() {
        let (out, y) = tuned();
        assert_eq!(out.networks, vec!["bridge", "media"]);
        assert!(
            y.contains("    networks:\n      - \"default\"\n      - \"media\"\n"),
            "{y}"
        );
        assert!(
            y.contains("\nnetworks:\n  default:\n    external: true\n    name: \"bridge\"\n  media:\n    external: true\n"),
            "{y}"
        );
        assert!(!y.contains("network_mode"), "{y}");
    }

    #[test]
    fn bridge_only_uses_network_mode() {
        let mut c = inspected();
        c.network_mode = "bridge".into();
        c.networks = vec!["bridge".into()];
        let y = compose_yaml(&c).yaml;
        assert!(y.contains("    network_mode: \"bridge\"\n"), "{y}");
        assert!(!y.contains("networks"), "{y}");
    }

    #[test]
    fn tmpfs_keeps_its_options() {
        let (out, y) = tuned();
        assert_eq!(out.tmpfs["/run"], "rw,size=65536k");
        assert!(
            y.contains("    tmpfs:\n      - \"/run:rw,size=65536k\"\n      - \"/tmp\"\n"),
            "{y}"
        );
    }

    #[test]
    fn shm_size_is_kept_unless_default() {
        let (out, y) = tuned();
        assert_eq!(out.shm_size, Some(268435456));
        assert!(y.contains("    shm_size: 268435456\n"), "{y}");
        let mut c = out;
        c.shm_size = Some(DEFAULT_SHM_SIZE);
        assert!(!compose_yaml(&c).yaml.contains("shm_size"));
    }

    #[test]
    fn sysctls_are_reproduced() {
        let (out, y) = tuned();
        assert_eq!(out.sysctls["net.core.somaxconn"], "1024");
        assert!(
            y.contains("    sysctls:\n      net.core.somaxconn: \"1024\"\n"),
            "{y}"
        );
    }

    #[test]
    fn ulimits_are_reproduced() {
        let (out, y) = tuned();
        assert_eq!(out.ulimits[0].hard, 4096);
        assert!(y.contains("    ulimits:\n      nofile:\n        hard: 4096\n        soft: 1024\n      nproc: 512\n"), "{y}");
    }

    #[test]
    fn security_opt_is_reproduced() {
        let (out, y) = tuned();
        assert_eq!(out.security_opt, vec!["no-new-privileges:true"]);
        assert!(
            y.contains("    security_opt:\n      - \"no-new-privileges:true\"\n"),
            "{y}"
        );
    }

    #[test]
    fn extra_hosts_are_reproduced() {
        let (out, y) = tuned();
        assert_eq!(out.extra_hosts, vec![format!("db:{REDACTED}")]);
        assert!(
            y.contains("    extra_hosts:\n      - \"db:${host_db}\"\n"),
            "{y}"
        );
    }

    #[test]
    fn pid_and_ipc_modes_are_reproduced() {
        let (out, y) = tuned();
        assert_eq!(
            (out.pid_mode.as_str(), out.ipc_mode.as_str()),
            ("host", "host")
        );
        assert!(y.contains("    pid: \"host\"\n"), "{y}");
        assert!(y.contains("    ipc: \"host\"\n"), "{y}");
        let mut c = out;
        c.ipc_mode = "private".into();
        assert!(!compose_yaml(&c).yaml.contains("ipc:"));
    }

    #[test]
    fn resource_limits_are_reproduced() {
        let (out, y) = tuned();
        assert_eq!(out.nano_cpus, Some(1_500_000_000));
        assert_eq!(out.memory, Some(536870912));
        assert_eq!(out.pids_limit, Some(200));
        assert!(y.contains("    cpus: \"1.5\"\n"), "{y}");
        assert!(y.contains("    mem_limit: 536870912\n"), "{y}");
        assert!(y.contains("    pids_limit: 200\n"), "{y}");
    }

    #[test]
    fn logging_driver_and_options_are_reproduced_with_secrets_redacted() {
        let (out, y) = tuned();
        assert_eq!(out.log_driver, "syslog");
        assert_eq!(out.log_options["splunk-token"], REDACTED);
        assert_eq!(out.redacted_log_options, vec!["splunk-token"]);
        assert!(
            y.contains("    logging:\n      driver: \"syslog\"\n      options:\n        splunk-token: \"${SECRET_SPLUNK_TOKEN}\"\n        tag: \"app\"\n"),
            "{y}"
        );
        assert!(!y.contains("s3cr3t"), "{y}");
    }

    #[test]
    fn stop_signal_and_grace_period_are_reproduced() {
        let (out, y) = tuned();
        assert_eq!(out.stop_signal, "SIGINT");
        assert_eq!(out.stop_timeout, Some(30));
        assert!(y.contains("    stop_signal: \"SIGINT\"\n"), "{y}");
        assert!(y.contains("    stop_grace_period: \"30s\"\n"), "{y}");
    }

    #[test]
    fn hostname_is_reproduced_unless_it_is_the_id() {
        let (out, y) = tuned();
        assert_eq!(out.hostname, "apphost");
        assert!(y.contains("    hostname: \"apphost\"\n"), "{y}");
        let mut c = out;
        c.hostname = "f00dfeed".into();
        assert!(!compose_yaml(&c).yaml.contains("hostname"));
    }

    #[test]
    fn dns_is_reproduced() {
        let (out, y) = tuned();
        assert_eq!(out.dns, vec![REDACTED]);
        assert!(y.contains("    dns:\n      - \"${dns_0}\"\n"), "{y}");
    }

    #[test]
    fn a_missing_container_is_an_error() {
        let e = FakeEngine::routed(vec![]);
        let err = plugin_toolkit::reactor::block_on(inspect(&e.client(), "gone", View::Reader))
            .unwrap_err();
        assert!(err.to_string().contains("no container 'gone'"), "{err}");
    }
}
