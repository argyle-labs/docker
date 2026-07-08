//! Docker → TopologyClaim collector.
//!
//! Runs on the local host (the docker socket is the API endpoint). Emits
//! one claim per container with MACs from `NetworkSettings.Networks[*]`.
//! Consumed by `system::topology` and surfaced on `SystemInfoReport.claims`.

use std::collections::BTreeMap;

use plugin_toolkit::anyhow;
use plugin_toolkit::contract::TopologyClaim;
use plugin_toolkit::serde::Deserialize;
use plugin_toolkit::serde_json;

#[derive(Debug, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
struct InspectEntry {
    #[serde(rename = "NetworkSettings", default)]
    network_settings: NetworkSettings,
}

#[derive(Debug, Default, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
struct NetworkSettings {
    #[serde(rename = "Networks", default)]
    networks: BTreeMap<String, NetworkEntry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
struct NetworkEntry {
    #[serde(rename = "MacAddress", default)]
    mac_address: String,
}

/// Enumerate local containers via the `docker` CLI and build claims.
pub async fn collect_claims() -> anyhow::Result<Vec<TopologyClaim>> {
    let summaries = crate::containers::list(false).await?;
    let mut claims = Vec::with_capacity(summaries.len());
    for s in summaries {
        let inspected = crate::containers::inspect(&s.id).await?;
        let entries: Vec<InspectEntry> = serde_json::from_value(inspected).unwrap_or_default();
        let macs = extract_macs(&entries);
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
    fn first_name_strips_leading_slash_and_takes_first() {
        assert_eq!(first_name("/foo,bar"), "foo");
        assert_eq!(first_name("foo"), "foo");
        assert_eq!(first_name(""), "");
    }
}
