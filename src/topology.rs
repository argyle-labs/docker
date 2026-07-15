//! Docker → TopologyClaim collector.
//!
//! Runs on the local host (the docker socket is the API endpoint). Emits
//! one claim per container with MACs from `NetworkSettings.Networks[*]`.
//! Consumed by `system::topology` and surfaced on `SystemInfoReport.claims`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use plugin_toolkit::anyhow;
use plugin_toolkit::contract::TopologyClaim;
use plugin_toolkit::contract::topology::{ClaimAddress, ClaimEndpoint};
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
    /// Legacy top-level IP (set for the default bridge; empty under custom
    /// networks, where the per-network `Networks[*].IPAddress` is used).
    #[serde(rename = "IPAddress", default)]
    ip_address: String,
    #[serde(rename = "GlobalIPv6Address", default)]
    global_ipv6_address: String,
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

/// Well-known label a container can set to declare its service role as a cheap
/// hint (the authoritative role still comes from a runtime registration).
const ROLE_LABEL: &str = "orca.role";

/// Enumerate local containers via the `docker` CLI and build claims.
pub async fn collect_claims() -> anyhow::Result<Vec<TopologyClaim>> {
    // `all = true` so stopped containers still surface as claims (rendered
    // with a "stopped" run-state) instead of vanishing from the topology.
    let summaries = crate::containers::list(true).await?;
    let mut claims = Vec::with_capacity(summaries.len());
    for s in summaries {
        let state = normalize_state(&s.state);
        let inspected = crate::containers::inspect(&s.id).await?;
        let entries: Vec<InspectEntry> = serde_json::from_value(inspected).unwrap_or_default();
        let macs = extract_macs(&entries);
        let first = entries.first();
        let endpoints = first.map(extract_endpoints).unwrap_or_default();
        let addresses = first.map(extract_addresses).unwrap_or_default();
        let image = first
            .map(|e| e.config.image.clone())
            .filter(|s| !s.is_empty());
        let labels = first.map(|e| e.config.labels.clone()).unwrap_or_default();
        let service_role = labels.get(ROLE_LABEL).filter(|s| !s.is_empty()).cloned();
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
            addresses,
            image,
            labels,
            service_role,
            state,
            // Left empty: the inventory layer mints the stable uuidv7 identity
            // (docker's hex id is a descriptive field, not an identity).
            uuid: String::new(),
        });
    }
    Ok(claims)
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

/// Collect a container's reachable IPs from `NetworkSettings` — the per-network
/// `IPAddress`/`GlobalIPv6Address` plus the legacy top-level fields as a
/// fallback. Host-network containers expose no IP here (they're reachable at
/// the host's own address + published port), so they yield nothing — a noted
/// gap, not an error. Loopback/link-local/unspecified are dropped; values are
/// deduped and tagged `lan_v4`/`lan_v6` with `source: "docker"`.
fn extract_addresses(entry: &InspectEntry) -> Vec<ClaimAddress> {
    let ns = &entry.network_settings;
    let raw = ns
        .networks
        .values()
        .flat_map(|n| [n.ip_address.clone(), n.global_ipv6_address.clone()])
        .chain([ns.ip_address.clone(), ns.global_ipv6_address.clone()]);
    let mut out: Vec<ClaimAddress> = Vec::new();
    for r in raw {
        if let Some((kind, value)) = classify_ip(&r)
            && !out.iter().any(|a| a.value == value)
        {
            out.push(ClaimAddress {
                kind: kind.to_string(),
                value,
                source: "docker".to_string(),
            });
        }
    }
    out
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

    #[test]
    fn extract_addresses_pulls_bridge_ip_and_filters() {
        let entries = parse(
            r#"[{"NetworkSettings":{"Networks":{
                "bridge":{"IPAddress":"172.18.0.5","GlobalIPv6Address":""},
                "loop":{"IPAddress":"127.0.0.1"}
            }}}]"#,
        );
        let got = extract_addresses(&entries[0]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, "lan_v4");
        assert_eq!(got[0].value, "172.18.0.5");
        assert_eq!(got[0].source, "docker");
    }

    #[test]
    fn extract_addresses_host_network_yields_none() {
        // Host-network containers report no per-network IP.
        let entries = parse(r#"[{"NetworkSettings":{"Networks":{"host":{}}}}]"#);
        assert!(extract_addresses(&entries[0]).is_empty());
    }

    #[test]
    fn extract_addresses_uses_legacy_toplevel_and_ipv6() {
        let entries = parse(
            r#"[{"NetworkSettings":{"IPAddress":"10.0.0.9","GlobalIPv6Address":"fd00::9","Networks":{}}}]"#,
        );
        let got = extract_addresses(&entries[0]);
        assert_eq!(got.len(), 2);
        assert!(
            got.iter()
                .any(|a| a.kind == "lan_v4" && a.value == "10.0.0.9")
        );
        assert!(
            got.iter()
                .any(|a| a.kind == "lan_v6" && a.value == "fd00::9")
        );
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
