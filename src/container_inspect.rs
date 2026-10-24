use std::collections::BTreeMap;

use bollard::Docker;
use bollard::models::ContainerInspectResponse;
use bollard::query_parameters::InspectContainerOptionsBuilder;
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{self, Value, json};

const REDACTED: &str = "***";
const SECRET_MARKERS: [&str; 6] = ["TOKEN", "SECRET", "PASSWORD", "KEY", "PASS", "CRED"];

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
pub struct ContainerInspectOutput {
    pub id: String,
    pub name: String,
    pub image: String,
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
    pub labels: BTreeMap<String, String>,
    pub user: String,
    pub working_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<HealthcheckInfo>,
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

pub fn env_var(raw: &str) -> EnvVar {
    let (name, value) = raw.split_once('=').unwrap_or((raw, ""));
    let redacted = is_secret_name(name);
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
    ContainerInspectOutput {
        id: c.id.clone().unwrap_or_default(),
        name: c
            .name
            .as_deref()
            .map(|n| n.trim_start_matches('/').to_owned())
            .unwrap_or_default(),
        image: config.image.unwrap_or_default(),
        command: config.cmd.unwrap_or_default(),
        entrypoint: config.entrypoint.unwrap_or_default(),
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
        labels: config.labels.unwrap_or_default().into_iter().collect(),
        user: config.user.unwrap_or_default(),
        working_dir: config.working_dir.unwrap_or_default(),
        healthcheck: config.healthcheck.and_then(|h| {
            let test = h.test.unwrap_or_default();
            (!test.is_empty()).then_some(HealthcheckInfo {
                test,
                interval_ns: h.interval.filter(|n| *n > 0),
                timeout_ns: h.timeout.filter(|n| *n > 0),
                retries: h.retries.filter(|n| *n > 0),
                start_period_ns: h.start_period.filter(|n| *n > 0),
            })
        }),
    }
}

fn duration(ns: i64) -> String {
    let ms = ns / 1_000_000;
    if ms % 1000 == 0 {
        format!("{}s", ms / 1000)
    } else {
        format!("{ms}ms")
    }
}

fn is_named_network(mode: &str) -> bool {
    !mode.is_empty()
        && !matches!(mode, "default" | "bridge" | "host" | "none")
        && !mode.starts_with("container:")
        && !mode.starts_with("service:")
}

pub fn service_value(c: &ContainerInspectOutput) -> Value {
    let mut svc = serde_json::Map::new();
    svc.insert("image".into(), json!(c.image));
    if !c.name.is_empty() {
        svc.insert("container_name".into(), json!(c.name));
    }
    if !c.entrypoint.is_empty() {
        svc.insert("entrypoint".into(), json!(c.entrypoint));
    }
    if !c.command.is_empty() {
        svc.insert("command".into(), json!(c.command));
    }
    if !c.user.is_empty() {
        svc.insert("user".into(), json!(c.user));
    }
    if !c.working_dir.is_empty() {
        svc.insert("working_dir".into(), json!(c.working_dir));
    }
    if !c.env.is_empty() {
        let env: serde_json::Map<String, Value> = c
            .env
            .iter()
            .map(|e| {
                let v = if e.redacted {
                    format!("${{{}}}", e.name)
                } else {
                    e.value.replace('$', "$$")
                };
                (e.name.clone(), json!(v))
            })
            .collect();
        svc.insert("environment".into(), Value::Object(env));
    }
    let mode = c.network_mode.as_str();
    if matches!(mode, "host" | "none") || mode.starts_with("container:") {
        svc.insert("network_mode".into(), json!(mode));
    } else if !c.networks.is_empty() && c.networks != ["bridge"] {
        svc.insert("networks".into(), json!(c.networks));
    }
    if !c.ports.is_empty() {
        let ports: Vec<String> = c
            .ports
            .iter()
            .map(|p| {
                let target = p.container_port.trim_end_matches("/tcp");
                match (&p.host_ip, &p.host_port) {
                    (Some(ip), Some(hp)) => format!("{ip}:{hp}:{target}"),
                    (None, Some(hp)) => format!("{hp}:{target}"),
                    _ => target.to_owned(),
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
                    (Some(v), "volume") => v.clone(),
                    _ => m.source.clone(),
                };
                let mut v = serde_json::Map::new();
                v.insert("type".into(), json!(m.kind));
                if !source.is_empty() {
                    v.insert("source".into(), json!(source));
                }
                v.insert("target".into(), json!(m.target));
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
            .map(|d| {
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
                let caps: Vec<&String> = d.capabilities.iter().flatten().collect();
                r.insert("capabilities".into(), json!(caps));
                Value::Object(r)
            })
            .collect();
        svc.insert(
            "deploy".into(),
            json!({ "resources": { "reservations": { "devices": reqs } } }),
        );
    }
    if !c.labels.is_empty() {
        svc.insert("labels".into(), json!(c.labels));
    }
    if let Some(h) = &c.healthcheck {
        let mut hc = serde_json::Map::new();
        hc.insert("test".into(), json!(h.test));
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

fn emit(v: &Value, indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                let key = if !k.is_empty()
                    && k.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
                {
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
        let nets: serde_json::Map<String, Value> = external
            .iter()
            .map(|n| ((*n).clone(), json!({ "external": true })))
            .collect();
        doc.insert("networks".into(), Value::Object(nets));
    }
    let vols: serde_json::Map<String, Value> = c
        .mounts
        .iter()
        .filter(|m| m.kind == "volume")
        .filter_map(|m| m.volume_name.clone())
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
        Ok(c) => Ok(describe(&c)),
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
    execute_gated = false
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
                    "Privileged": false
                },
                "Mounts": [
                    { "Type": "bind", "Source": "/mnt/media", "Destination": "/media", "RW": false },
                    { "Type": "volume", "Name": "plex_config", "Source": "/var/lib/docker/volumes/plex_config/_data", "Destination": "/config", "RW": true }
                ],
                "NetworkSettings": { "Networks": { "media": {} } }
            })
            .to_string(),
        )])
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
        assert_eq!(by["PLEX_CLAIM"].value, "claim-xyz");
        assert!(!out.env.iter().any(|e| e.value == "hunter2"));
        assert_eq!(env_var("NOVALUE").value, "");
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

    #[test]
    fn a_missing_container_is_an_error() {
        let e = FakeEngine::routed(vec![]);
        let err = plugin_toolkit::reactor::block_on(inspect(&e.client(), "gone")).unwrap_err();
        assert!(err.to_string().contains("no container 'gone'"), "{err}");
    }
}
