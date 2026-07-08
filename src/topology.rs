//! Docker → TopologyClaim collector.
//!
//! Runs on the local host (the docker socket is the API endpoint). Emits
//! one claim per container with MACs from `NetworkSettings.Networks[*]`.
//! Consumed by `system::topology` and surfaced on `SystemInfoReport.claims`.

use std::collections::BTreeMap;

use plugin_toolkit::anyhow;
use plugin_toolkit::contract::TopologyClaim;
use plugin_toolkit::contract::topology::ClaimEndpoint;
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
    let summaries = crate::containers::list(false).await?;
    let mut claims = Vec::with_capacity(summaries.len());
    for s in summaries {
        let inspected = crate::containers::inspect(&s.id).await?;
        let entries: Vec<InspectEntry> = serde_json::from_value(inspected).unwrap_or_default();
        let macs = extract_macs(&entries);
        let first = entries.first();
        let endpoints = first.map(extract_endpoints).unwrap_or_default();
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
            image,
            labels,
            service_role,
        });
    }
    Ok(claims)
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
    fn first_name_strips_leading_slash_and_takes_first() {
        assert_eq!(first_name("/foo,bar"), "foo");
        assert_eq!(first_name("foo"), "foo");
        assert_eq!(first_name(""), "");
    }
}
