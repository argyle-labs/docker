use std::collections::BTreeMap;

use bollard::Docker;
use bollard::models::ContainerInspectResponse;
use bollard::query_parameters::InspectContainerOptionsBuilder;
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{self, Value, json};

const REDACTED: &str = "***";
const SECRET_MARKERS: [&str; 9] = [
    "TOKEN", "SECRET", "PASSWORD", "KEY", "PASS", "CRED", "AUTH", "CLAIM", "PRIVATE",
];
const COMPOSE_LABEL_PREFIX: &str = "com.docker.compose.";
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
    pub command: Vec<String>,
    pub entrypoint: Vec<String>,
    pub env: Vec<EnvVar>,
    pub network_mode: String,
    pub networks: Vec<String>,
    pub ports: Vec<PortMapping>,
    pub mounts: Vec<MountInfo>,
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

pub fn is_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_MARKERS.iter().any(|m| upper.contains(m))
}

pub fn is_secret_value(value: &str) -> bool {
    if value.starts_with('/') && is_secret_name(value) {
        return true;
    }
    let Some((_, rest)) = value.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    authority
        .rsplit_once('@')
        .is_some_and(|(userinfo, _)| userinfo.contains(':'))
}

fn is_secret(name: &str, value: &str) -> bool {
    is_secret_name(name) || is_secret_value(value)
}

fn redact_args(args: &[String], replace: impl Fn(&str) -> String) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut pending: Option<String> = None;
    for arg in args {
        if let Some(flag) = pending.take() {
            out.push(replace(&flag));
            continue;
        }
        if let Some((name, value)) = arg.split_once('=')
            && is_secret(name, value)
        {
            out.push(format!("{name}={}", replace(name)));
        } else if is_secret_value(arg) {
            out.push(replace("ARG"));
        } else {
            if arg.starts_with('-') && is_secret_name(arg) {
                pending = Some(arg.clone());
            }
            out.push(arg.clone());
        }
    }
    out
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

fn is_anonymous_volume(name: &str) -> bool {
    name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn env_var(raw: &str) -> EnvVar {
    let (name, value) = raw.split_once('=').unwrap_or((raw, ""));
    let redacted = is_secret(name, value);
    EnvVar {
        name: name.to_owned(),
        value: if redacted {
            REDACTED.to_owned()
        } else {
            value.to_owned()
        },
        redacted,
    }
}

pub fn describe(c: &ContainerInspectResponse) -> ContainerInspectOutput {
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
                    host_ip: b.host_ip.filter(|s| !s.is_empty()),
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
            } else {
                (k, v)
            }
        })
        .collect();
    redacted_labels.sort();
    let masked = |a: Vec<String>| redact_args(&a, |_| REDACTED.to_owned());
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
        command: masked(config.cmd.unwrap_or_default()),
        entrypoint: masked(config.entrypoint.unwrap_or_default()),
        env: config
            .env
            .unwrap_or_default()
            .iter()
            .map(|e| env_var(e))
            .collect(),
        network_mode: host.network_mode.unwrap_or_default(),
        networks,
        ports,
        mounts: c
            .mounts
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|m| MountInfo {
                kind: m.typ.map(|t| t.to_string()).unwrap_or_default(),
                source: m.source.unwrap_or_default(),
                target: m.destination.unwrap_or_default(),
                read_only: !m.rw.unwrap_or(true),
                volume_name: m.name.filter(|s| !s.is_empty()),
            })
            .collect(),
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
                path_on_host: d.path_on_host.unwrap_or_default(),
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
        working_dir: config.working_dir.unwrap_or_default(),
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
        extra_hosts: host.extra_hosts.unwrap_or_default(),
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
        dns: host.dns.unwrap_or_default(),
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
        svc.insert("working_dir".into(), json!(lit(&c.working_dir)));
    }
    if !c.env.is_empty() {
        let env: serde_json::Map<String, Value> = c
            .env
            .iter()
            .map(|e| {
                let v = if e.redacted {
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
        svc.insert("dns".into(), json!(c.dns));
    }
    if !c.extra_hosts.is_empty() {
        svc.insert("extra_hosts".into(), json!(c.extra_hosts));
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
            .map(|p| {
                let target = p.container_port.trim_end_matches("/tcp");
                let ip = p.host_ip.as_deref().map(|ip| {
                    if ip.contains(':') && !ip.starts_with('[') {
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
                let mut s = format!("{}:{}", d.path_on_host, d.path_in_container);
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

pub async fn inspect(docker: &Docker, container: &str) -> Result<ContainerInspectOutput> {
    let target = crate::container_delete::parse_name(container)?;
    let opts = InspectContainerOptionsBuilder::new().build();
    match docker.inspect_container(&target, Some(opts)).await {
        Ok(c) => {
            let mut out = describe(&c);
            if !out.image_id.is_empty()
                && let Ok(image) = docker.inspect_image(&out.image_id).await
            {
                out.repo_digests = image.repo_digests.unwrap_or_default();
                out.repo_digests.sort();
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

/// **Inspect a container** by name or id: image, command, env (secret-looking
/// values shown as `***`), networks, ports, mounts, restart policy, devices,
/// GPU requests, capabilities, labels, user, working dir, healthcheck.
/// Read-only.
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
    inspect(&client()?, &args.container).await
}

/// **Render a container as a Compose service** by name or id. Secret-looking
/// env values become `${NAME}` references. Read-only.
#[orca_tool(
    domain = "docker",
    verb = "container_compose",
    role = "read",
    execute_gated = false
)]
async fn docker_container_compose(
    args: DockerContainerInspectArgs,
    _ctx: &ToolCtx,
) -> Result<ContainerComposeOutput> {
    Ok(compose_yaml(&inspect(&client()?, &args.container).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};

    fn engine() -> FakeEngine {
        FakeEngine::routed(vec![Route::new(
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
        ), Route::new(
            "GET",
            "/images/sha256:feed/json",
            200,
            json!({
                "Id": "sha256:feed",
                "RepoDigests": ["plexinc/pms-docker@sha256:beef", "mirror/pms@sha256:abba"]
            })
            .to_string(),
        )])
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
        let e = engine();
        plugin_toolkit::reactor::block_on(inspect(&e.client(), "plex")).unwrap()
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
            assert!(is_secret_name(name), "{name}");
        }
        for name in ["TZ", "PUID", "HOME", "PATH"] {
            assert!(!is_secret_name(name), "{name}");
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
        assert_eq!(env_var("NOVALUE").value, "");
    }

    #[test]
    fn secret_values_are_redacted_whatever_the_name() {
        for raw in [
            "DB=/run/secrets/db",
            "CONF=/var/run/secrets/app/creds",
            "DATABASE_URL=postgres://app:hunter2@db:5432/app",
            "UPSTREAM=https://u:p@host/path?x=1",
        ] {
            assert_eq!(env_var(raw).value, REDACTED, "{raw}");
        }
        for raw in [
            "URL=https://host/a@b",
            "HOME=/home/app",
            "DSN=redis://cache:6379",
        ] {
            assert!(!env_var(raw).redacted, "{raw}");
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
        assert_eq!(out.ports[0].host_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(out.ports[1].host_ip, None);
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
        let y = compose_yaml(&inspected()).yaml;
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
        let out = plugin_toolkit::reactor::block_on(inspect(&e.client(), "tuned")).unwrap();
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
        assert_eq!(out.extra_hosts, vec!["db:10.0.0.9"]);
        assert!(
            y.contains("    extra_hosts:\n      - \"db:10.0.0.9\"\n"),
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
        assert_eq!(out.dns, vec!["10.0.0.1"]);
        assert!(y.contains("    dns:\n      - \"10.0.0.1\"\n"), "{y}");
    }

    #[test]
    fn a_missing_container_is_an_error() {
        let e = FakeEngine::routed(vec![]);
        let err = plugin_toolkit::reactor::block_on(inspect(&e.client(), "gone")).unwrap_err();
        assert!(err.to_string().contains("no container 'gone'"), "{err}");
    }
}
