//! Docker → TopologyClaim collector.
//!
//! Runs on the local host (the docker socket is the API endpoint). Emits
//! one claim per container with MACs from `NetworkSettings.Networks[*]`.
//! Consumed by `system::topology` and surfaced on `SystemInfoReport.claims`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use plugin_toolkit::anyhow;
use plugin_toolkit::contract::TopologyClaim;
use plugin_toolkit::contract::topology::{ClaimEndpoint, Route};
use plugin_toolkit::serde::Deserialize;
use plugin_toolkit::serde_json;

#[derive(Debug, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
struct InspectEntry {
    #[serde(rename = "NetworkSettings", default)]
    network_settings: NetworkSettings,
    #[serde(rename = "Config", default)]
    config: ConfigEntry,
}

#[derive(Debug, Default, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
struct NetworkSettings {
    #[serde(rename = "Networks", default)]
    networks: BTreeMap<String, NetworkEntry>,
    /// Published-port map: `"8989/tcp" -> [{HostIp, HostPort}]` (or `null` when
    /// the port is exposed but not published to the host).
    #[serde(rename = "Ports", default)]
    ports: BTreeMap<String, Option<Vec<PortBinding>>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
struct NetworkEntry {
    #[serde(rename = "MacAddress", default)]
    mac_address: String,
    #[serde(rename = "IPAddress", default)]
    ip_address: String,
    #[serde(rename = "GlobalIPv6Address", default)]
    global_ipv6_address: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
struct PortBinding {
    #[serde(rename = "HostIp", default)]
    host_ip: String,
    #[serde(rename = "HostPort", default)]
    host_port: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
struct ConfigEntry {
    #[serde(rename = "Image", default)]
    image: String,
    #[serde(rename = "Labels", default)]
    labels: BTreeMap<String, String>,
}

/// One row of `docker network ls --format '{{json .}}'` — the network's name
/// and driver, used to classify container IPs as LAN-reachable or internal.
#[derive(Debug, Default, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
struct NetworkMeta {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Driver", default)]
    driver: String,
}

/// Well-known label a container can set to declare its service role as a cheap
/// hint (the authoritative role still comes from a runtime registration).
const ROLE_LABEL: &str = "orca.role";

/// Compose project name label docker sets on every container it starts from a
/// compose file. Fallback signal for `service_identity` when the working-dir
/// label is absent.
const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";

/// Compose project working-directory label — the strongest `service_identity`
/// signal (`/opt/stacks/<project>`); byte-for-byte the same path dockge manages.
const COMPOSE_WORKING_DIR_LABEL: &str = "com.docker.compose.project.working_dir";

/// Enumerate local containers via the `docker` CLI and build claims.
pub async fn collect_claims() -> anyhow::Result<Vec<TopologyClaim>> {
    // `all = true` so stopped containers still surface as claims (rendered
    // with a "stopped" run-state) instead of vanishing from the topology.
    let summaries = crate::containers::list(true).await?;
    // Network name -> driver, fetched once. Lets `extract_addresses` tell an L2
    // network (macvlan/ipvlan, real LAN IPs) from a bridge network (internal).
    let drivers = network_drivers().await;
    let mut claims = Vec::with_capacity(summaries.len());
    for s in summaries {
        let state = normalize_state(&s.state);
        let inspected = crate::containers::inspect(&s.id).await?;
        let entries: Vec<InspectEntry> = serde_json::from_value(inspected).unwrap_or_default();
        let macs = extract_macs(&entries);
        let first = entries.first();
        let endpoints = first.map(extract_endpoints).unwrap_or_default();
        let routes = first
            .map(|e| extract_addresses(e, &drivers))
            .unwrap_or_default();
        let image = first
            .map(|e| e.config.image.clone())
            .filter(|s| !s.is_empty());
        let labels = first.map(|e| e.config.labels.clone()).unwrap_or_default();
        let service_role = labels.get(ROLE_LABEL).filter(|s| !s.is_empty()).cloned();
        let service_identity = compose_service_identity(&labels);
        let id_short = s.id.chars().take(12).collect::<String>();
        let name = first_name(&s.names);
        claims.push(TopologyClaim {
            kind: "container".to_string(),
            id: id_short,
            name,
            macs,
            provider: "docker".to_string(),
            provider_instance: "local".to_string(),
            // Single-host provider: the reporting peer is the host.
            runs_on: None,
            endpoints,
            routes: routes.into(),
            image,
            labels,
            service_role,
            service_identity,
            state,
            // Left empty: the inventory layer mints the stable uuidv7 identity
            // (docker's hex id is a descriptive field, not an identity).
            uuid: String::new(),
        });
    }
    Ok(claims)
}

/// Derive the host-scoped compose `service_identity` correlation key from a
/// container's compose labels. Docker learns the stack from
/// `com.docker.compose.project.working_dir` (preferred) / `com.docker.compose.project`;
/// both are routed through the core normalizer so docker and dockge — observing
/// the same stack from different angles — emit byte-identical keys and dedup
/// onto one stack node. Returns `None` for containers not started from compose.
fn compose_service_identity(labels: &BTreeMap<String, String>) -> Option<String> {
    let working_dir = labels
        .get(COMPOSE_WORKING_DIR_LABEL)
        .map(String::as_str)
        .filter(|s| !s.is_empty());
    let project = labels
        .get(COMPOSE_PROJECT_LABEL)
        .map(String::as_str)
        .filter(|s| !s.is_empty());
    let host = plugin_toolkit::containers::local_hostname();
    TopologyClaim::normalize_service_identity(host, working_dir, project)
}

/// Map a docker `State` string onto orca's normalized run-state vocabulary.
/// `docker ps` reports `created`/`restarting`/`running`/`removing`/`paused`/
/// `exited`/`dead`; an empty/unknown value yields `None` (Unknown, not down).
fn normalize_state(state: &str) -> Option<String> {
    match state.trim().to_lowercase().as_str() {
        "running" | "restarting" => Some("running".to_string()),
        "paused" => Some("paused".to_string()),
        "created" | "exited" | "dead" | "removing" => Some("stopped".to_string()),
        _ => None,
    }
}

fn extract_macs(entries: &[InspectEntry]) -> Vec<String> {
    let Some(first) = entries.first() else {
        return Vec::new();
    };
    first
        .network_settings
        .networks
        .values()
        .filter(|n| !n.mac_address.is_empty())
        .map(|n| n.mac_address.to_lowercase())
        .collect()
}

/// Build [`ClaimEndpoint`]s from an inspect entry's `NetworkSettings.Ports`.
/// Each key is `"PORT/PROTO"`; the value lists host bindings (or `null` when
/// exposed but unpublished — still surfaced, with no `published_port`).
fn extract_endpoints(entry: &InspectEntry) -> Vec<ClaimEndpoint> {
    let mut out = Vec::new();
    for (spec, bindings) in &entry.network_settings.ports {
        let (port_str, proto) = spec.split_once('/').unwrap_or((spec.as_str(), "tcp"));
        let Ok(port) = port_str.parse::<u16>() else {
            continue;
        };
        match bindings {
            Some(binds) if !binds.is_empty() => {
                for b in binds {
                    out.push(ClaimEndpoint {
                        port,
                        published_port: b.host_port.parse::<u16>().ok(),
                        protocol: proto.to_string(),
                        host_ip: (!b.host_ip.is_empty()).then(|| b.host_ip.clone()),
                    });
                }
            }
            _ => out.push(ClaimEndpoint {
                port,
                published_port: None,
                protocol: proto.to_string(),
                host_ip: None,
            }),
        }
    }
    out.sort_by_key(|e| (e.port, e.published_port));
    out
}

/// True for L2 network drivers (`macvlan`/`ipvlan`) where a container gets a
/// REAL address on the host's LAN subnet. Bridge networks (default or user-
/// defined) are NOT L2 — their container IPs are docker-internal.
fn is_l2_driver(driver: &str) -> bool {
    matches!(driver, "macvlan" | "ipvlan")
}

/// Collect a container's LAN-REACHABLE IPs from `NetworkSettings`.
///
/// A container IP is only reachable from the rest of the network when it sits
/// on an L2 network (macvlan/ipvlan) — it gets a real address on the host's
/// subnet. On BRIDGE networks (default `bridge` or user-defined) the IP is a
/// docker-internal bridge address (e.g. `172.18.0.x`) that is NOT reachable
/// off-host; there, reachability is the HOST's IP + PUBLISHED PORT (surfaced
/// separately as endpoints). So we deliberately DO NOT advertise internal
/// bridge IPs — they misrepresent the container as reachable at an address the
/// operator's LAN can't route (the legacy top-level `IPAddress` is the default
/// bridge and is likewise skipped). Host-network containers expose no IP here.
/// Values are deduped and tagged `lan_v4`/`lan_v6` with `source: "docker"`.
fn extract_addresses(entry: &InspectEntry, drivers: &BTreeMap<String, String>) -> Vec<Route> {
    let mut out: Vec<Route> = Vec::new();
    for (net_name, n) in &entry.network_settings.networks {
        // Unknown driver (network ls unavailable / renamed) → treat as NOT L2,
        // i.e. don't advertise an unverified internal-looking address.
        let driver = drivers.get(net_name).map(String::as_str).unwrap_or("");
        if !is_l2_driver(driver) {
            continue;
        }
        for r in [n.ip_address.as_str(), n.global_ipv6_address.as_str()] {
            if let Some((kind, value)) = classify_ip(r)
                && !out.iter().any(|a| a.value == value)
            {
                out.push(Route {
                    source: Some("docker".to_string()),
                    ..Route::mesh(kind, value, None)
                });
            }
        }
    }
    out
}

/// Map docker network NAME → driver via `docker network ls`. Empty on failure
/// (the collector then advertises no container IPs, which is the safe default —
/// reachability still comes through published-port endpoints).
async fn network_drivers() -> BTreeMap<String, String> {
    let Ok(out) = crate::run(&["network", "ls", "--format", "{{json .}}"], None).await else {
        return BTreeMap::new();
    };
    out.lines()
        .filter_map(|l| serde_json::from_str::<NetworkMeta>(l).ok())
        .filter(|m| !m.name.is_empty())
        .map(|m| (m.name, m.driver))
        .collect()
}

/// Classify one IP literal into its address kind, or `None` for empty /
/// loopback / link-local / unspecified / unparseable.
fn classify_ip(raw: &str) -> Option<(&'static str, String)> {
    let bare = raw.trim();
    if bare.is_empty() {
        return None;
    }
    let ip: IpAddr = bare.parse().ok()?;
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() {
                return None;
            }
            Some(("lan_v4", v4.to_string()))
        }
        IpAddr::V6(v6) => {
            let link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            if v6.is_loopback() || v6.is_unspecified() || link_local {
                return None;
            }
            Some(("lan_v6", v6.to_string()))
        }
    }
}

fn first_name(names: &str) -> String {
    names
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches('/')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Vec<InspectEntry> {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn compose_service_identity_from_working_dir_label() {
        let mut labels = BTreeMap::new();
        labels.insert(
            COMPOSE_WORKING_DIR_LABEL.to_string(),
            "/opt/stacks/jellyfin".to_string(),
        );
        labels.insert(COMPOSE_PROJECT_LABEL.to_string(), "jellyfin".to_string());
        let got = compose_service_identity(&labels).expect("compose labels yield identity");
        // Host-scoped via the same core normalizer; working-dir wins over name.
        let host = plugin_toolkit::containers::local_hostname();
        let expected = TopologyClaim::normalize_service_identity(
            host,
            Some("/opt/stacks/jellyfin"),
            Some("jellyfin"),
        )
        .unwrap();
        assert_eq!(got, expected);
        assert!(got.ends_with("\u{1f}/opt/stacks/jellyfin"));
    }

    #[test]
    fn compose_service_identity_falls_back_to_project_name() {
        let mut labels = BTreeMap::new();
        labels.insert(COMPOSE_PROJECT_LABEL.to_string(), "arr".to_string());
        let got = compose_service_identity(&labels).expect("project label yields identity");
        assert!(got.ends_with("\u{1f}arr"));
    }

    #[test]
    fn compose_service_identity_none_without_compose_labels() {
        // A container not started from compose carries no compose labels.
        let mut labels = BTreeMap::new();
        labels.insert("orca.role".to_string(), "sonarr".to_string());
        assert_eq!(compose_service_identity(&labels), None);
        // Empty label values are treated as absent.
        let mut empties = BTreeMap::new();
        empties.insert(COMPOSE_PROJECT_LABEL.to_string(), String::new());
        empties.insert(COMPOSE_WORKING_DIR_LABEL.to_string(), String::new());
        assert_eq!(compose_service_identity(&empties), None);
    }

    #[test]
    fn extract_macs_pulls_per_network_mac() {
        let entries = parse(
            r#"[{"NetworkSettings":{"Networks":{
                "bridge":{"MacAddress":"02:42:AC:11:00:02"},
                "frontend":{"MacAddress":"02:42:AC:12:00:03"}
            }}}]"#,
        );
        let mut macs = extract_macs(&entries);
        macs.sort();
        assert_eq!(macs, vec!["02:42:ac:11:00:02", "02:42:ac:12:00:03"]);
    }

    #[test]
    fn extract_macs_skips_empty_and_missing() {
        let entries = parse(
            r#"[{"NetworkSettings":{"Networks":{
                "bridge":{"MacAddress":""},
                "none":{}
            }}}]"#,
        );
        assert!(extract_macs(&entries).is_empty());
    }

    #[test]
    fn extract_macs_handles_missing_networksettings() {
        assert!(extract_macs(&parse("[{}]")).is_empty());
        assert!(extract_macs(&parse("[]")).is_empty());
    }

    #[test]
    fn extract_endpoints_parses_published_and_exposed_ports() {
        let entries = parse(
            r#"[{"NetworkSettings":{"Ports":{
                "8989/tcp":[{"HostIp":"0.0.0.0","HostPort":"8989"}],
                "9117/tcp":null
            }},"Config":{"Image":"lscr.io/linuxserver/sonarr","Labels":{"orca.role":"sonarr"}}}]"#,
        );
        let e = &entries[0];
        let eps = extract_endpoints(e);
        assert_eq!(eps.len(), 2);
        let published = eps.iter().find(|x| x.port == 8989).unwrap();
        assert_eq!(published.published_port, Some(8989));
        assert_eq!(published.host_ip.as_deref(), Some("0.0.0.0"));
        let exposed = eps.iter().find(|x| x.port == 9117).unwrap();
        assert_eq!(exposed.published_port, None);
        assert_eq!(e.config.image, "lscr.io/linuxserver/sonarr");
        assert_eq!(
            e.config.labels.get("orca.role").map(String::as_str),
            Some("sonarr")
        );
    }

    fn drivers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(n, d)| (n.to_string(), d.to_string()))
            .collect()
    }

    #[test]
    fn extract_addresses_drops_bridge_internal_ip() {
        // A bridge container's 172.x IP is docker-internal, NOT LAN-reachable —
        // it must NOT be advertised (reachability = host + published port).
        let entries = parse(
            r#"[{"NetworkSettings":{"Networks":{
                "bridge":{"IPAddress":"172.18.0.5","GlobalIPv6Address":""}
            }}}]"#,
        );
        let got = extract_addresses(&entries[0], &drivers(&[("bridge", "bridge")]));
        assert!(got.is_empty(), "bridge-internal IP must not be surfaced");
    }

    #[test]
    fn extract_addresses_keeps_macvlan_lan_ip() {
        // A macvlan container gets a real address on the host's LAN subnet —
        // that IS reachable and must be surfaced.
        let entries = parse(
            r#"[{"NetworkSettings":{"Networks":{
                "lan":{"IPAddress":"10.10.10.42","GlobalIPv6Address":""}
            }}}]"#,
        );
        let got = extract_addresses(&entries[0], &drivers(&[("lan", "macvlan")]));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, "lan_v4");
        assert_eq!(got[0].value, "10.10.10.42");
        assert_eq!(got[0].source.as_deref(), Some("docker"));
    }

    #[test]
    fn extract_addresses_unknown_driver_is_dropped() {
        // Driver not resolvable → treat as non-L2, don't advertise the address.
        let entries =
            parse(r#"[{"NetworkSettings":{"Networks":{"custom":{"IPAddress":"172.20.0.2"}}}}]"#);
        assert!(extract_addresses(&entries[0], &BTreeMap::new()).is_empty());
    }

    #[test]
    fn extract_addresses_host_network_yields_none() {
        // Host-network containers report no per-network IP.
        let entries = parse(r#"[{"NetworkSettings":{"Networks":{"host":{}}}}]"#);
        assert!(extract_addresses(&entries[0], &drivers(&[("host", "host")])).is_empty());
    }

    #[test]
    fn normalize_state_maps_docker_states() {
        assert_eq!(normalize_state("running"), Some("running".into()));
        assert_eq!(normalize_state("Restarting"), Some("running".into()));
        assert_eq!(normalize_state("paused"), Some("paused".into()));
        assert_eq!(normalize_state("exited"), Some("stopped".into()));
        assert_eq!(normalize_state("created"), Some("stopped".into()));
        assert_eq!(normalize_state("dead"), Some("stopped".into()));
        assert_eq!(normalize_state(""), None);
        assert_eq!(normalize_state("weird"), None);
    }

    #[test]
    fn first_name_strips_leading_slash_and_takes_first() {
        assert_eq!(first_name("/foo,bar"), "foo");
        assert_eq!(first_name("foo"), "foo");
        assert_eq!(first_name(""), "");
    }
}
