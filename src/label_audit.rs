//! `docker.label_audit` — every container, volume and network on this host
//! without `orca.managed`, grouped by the owner it can be attributed to.
#![allow(clippy::disallowed_types)]

use std::collections::{BTreeMap, HashMap};

use bollard::Docker;
use bollard::models::{ContainerSummary, Network, Volume};
use bollard::query_parameters::{
    ListContainersOptionsBuilder, ListNetworksOptions, ListVolumesOptions,
};
use plugin_toolkit::prelude::*;

use crate::labels;
use crate::prune::COMPOSE_PROJECT_LABEL;

/// Networks the engine creates itself; nothing deploys them.
const BUILTIN_NETWORKS: &[&str] = &["bridge", "host", "none"];

/// Bucket for resources nothing can be attributed to.
pub const UNKNOWN_OWNER: &str = "(unknown)";

/// A resource's owner from its own labels: `orca.stack`, else the compose
/// project.
pub fn label_owner(labels: &HashMap<String, String>) -> Option<String> {
    labels
        .get(labels::STACK)
        .or_else(|| labels.get(COMPOSE_PROJECT_LABEL))
        .filter(|s| !s.is_empty())
        .cloned()
}

/// Volume name → owner of a container (running or stopped) that mounts it.
pub fn mount_owners(containers: &[ContainerSummary]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for c in containers {
        let Some(owner) = c.labels.as_ref().and_then(label_owner) else {
            continue;
        };
        for m in c.mounts.iter().flatten() {
            if let Some(name) = &m.name {
                out.entry(name.clone()).or_insert_with(|| owner.clone());
            }
        }
    }
    out
}

/// A volume's owner: its labels first, else the container that mounts it.
pub fn volume_owner(v: &Volume, mounts: &HashMap<String, String>) -> Option<String> {
    label_owner(&v.labels).or_else(|| mounts.get(&v.name).cloned())
}

/// Unlabeled resources attributed to one owner.
#[orca_struct]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnerGroup {
    /// Compose project or `orca.stack`, or `(unknown)`.
    pub owner: String,
    pub containers: Vec<String>,
    pub volumes: Vec<String>,
    pub networks: Vec<String>,
}

#[orca_struct]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LabelAudit {
    pub groups: Vec<OwnerGroup>,
    /// Unlabeled resources across all groups.
    pub total: usize,
}

fn container_name(c: &ContainerSummary) -> String {
    c.names
        .as_ref()
        .and_then(|n| n.first())
        .map(|n| n.trim_start_matches('/').to_string())
        .or_else(|| c.id.clone())
        .unwrap_or_default()
}

fn group(groups: &mut BTreeMap<String, OwnerGroup>, owner: Option<String>) -> &mut OwnerGroup {
    let owner = owner.unwrap_or_else(|| UNKNOWN_OWNER.to_string());
    groups.entry(owner.clone()).or_insert_with(|| OwnerGroup {
        owner,
        ..Default::default()
    })
}

/// Group every resource without `orca.managed` by owner.
pub fn audit(
    containers: &[ContainerSummary],
    volumes: &[Volume],
    networks: &[Network],
) -> LabelAudit {
    let mounts = mount_owners(containers);
    let mut attached: HashMap<String, String> = HashMap::new();
    for c in containers {
        let Some(owner) = c.labels.as_ref().and_then(label_owner) else {
            continue;
        };
        let nets = c
            .network_settings
            .as_ref()
            .and_then(|n| n.networks.as_ref());
        for (name, ep) in nets.into_iter().flatten() {
            attached
                .entry(name.clone())
                .or_insert_with(|| owner.clone());
            if let Some(id) = &ep.network_id {
                attached.entry(id.clone()).or_insert_with(|| owner.clone());
            }
        }
    }
    let mut groups: BTreeMap<String, OwnerGroup> = BTreeMap::new();
    let mut total = 0;
    for c in containers {
        let labels = c.labels.clone().unwrap_or_default();
        if labels::is_managed(labels.iter()) {
            continue;
        }
        group(&mut groups, label_owner(&labels))
            .containers
            .push(container_name(c));
        total += 1;
    }
    for v in volumes {
        if labels::is_managed(v.labels.iter()) {
            continue;
        }
        group(&mut groups, volume_owner(v, &mounts))
            .volumes
            .push(v.name.clone());
        total += 1;
    }
    for n in networks {
        let name = n.name.clone().unwrap_or_default();
        if BUILTIN_NETWORKS.contains(&name.as_str()) {
            continue;
        }
        let labels = n.labels.clone().unwrap_or_default();
        if labels::is_managed(labels.iter()) {
            continue;
        }
        let owner = label_owner(&labels)
            .or_else(|| attached.get(&name).cloned())
            .or_else(|| n.id.as_ref().and_then(|id| attached.get(id).cloned()));
        group(&mut groups, owner).networks.push(name);
        total += 1;
    }
    let mut groups: Vec<OwnerGroup> = groups.into_values().collect();
    for g in &mut groups {
        g.containers.sort();
        g.volumes.sort();
        g.networks.sort();
    }
    LabelAudit { groups, total }
}

fn engine_err(what: &str, e: bollard::errors::Error) -> plugin_toolkit::anyhow::Error {
    anyhow!("{what}: {e}")
}

/// Read the engine and audit it.
pub async fn collect(docker: &Docker) -> Result<LabelAudit> {
    let containers = docker
        .list_containers(Some(ListContainersOptionsBuilder::new().all(true).build()))
        .await
        .map_err(|e| engine_err("list containers", e))?;
    let volumes = docker
        .list_volumes(None::<ListVolumesOptions>)
        .await
        .map_err(|e| engine_err("list volumes", e))?
        .volumes
        .unwrap_or_default();
    let networks = docker
        .list_networks(None::<ListNetworksOptions>)
        .await
        .map_err(|e| engine_err("list networks", e))?;
    Ok(audit(&containers, &volumes, &networks))
}

#[orca_struct(args)]
pub struct DockerLabelAuditArgs {}

/// **Audit ownership labels**: every container, volume and network on this
/// host without `orca.managed`, grouped by inferred owner (`orca.stack` or
/// the compose project label, else the container that mounts or attaches
/// it). Read-only.
#[orca_tool(
    domain = "docker",
    verb = "label_audit",
    role = "any",
    execute_gated = false
)]
async fn docker_label_audit(_args: DockerLabelAuditArgs, _ctx: &ToolCtx) -> Result<LabelAudit> {
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    collect(docker).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};

    const CONTAINERS: &str = r#"[
      {"Id":"c1","Names":["/media-app-1"],"Labels":{"com.docker.compose.project":"media"},
       "Mounts":[{"Name":"anon1","Destination":"/cache"}],
       "NetworkSettings":{"Networks":{"media_default":{"NetworkID":"n1"}}}},
      {"Id":"c2","Names":["/web-1"],"Labels":{"orca.managed":"true","orca.stack":"web"},
       "Mounts":[{"Name":"anon2","Destination":"/data"}]},
      {"Id":"c3","Names":["/loose"],"Labels":{}}
    ]"#;
    const VOLUMES: &str = r#"{"Volumes":[
      {"Name":"anon1","Driver":"local","Mountpoint":"","Labels":{"com.docker.volume.anonymous":""},"Scope":"local","Options":{}},
      {"Name":"anon2","Driver":"local","Mountpoint":"","Labels":{},"Scope":"local","Options":{}},
      {"Name":"media_db","Driver":"local","Mountpoint":"","Labels":{"com.docker.compose.project":"media"},"Scope":"local","Options":{}},
      {"Name":"web_data","Driver":"local","Mountpoint":"","Labels":{"orca.managed":"true"},"Scope":"local","Options":{}},
      {"Name":"stray","Driver":"local","Mountpoint":"","Labels":{},"Scope":"local","Options":{}}
    ],"Warnings":[]}"#;
    const NETWORKS: &str = r#"[
      {"Id":"n1","Name":"media_default","Labels":{}},
      {"Id":"n0","Name":"bridge","Labels":{}},
      {"Id":"n2","Name":"web_default","Labels":{"orca.managed":"true"}}
    ]"#;

    #[test]
    fn groups_unlabeled_resources_by_label_or_referencing_container() {
        let e = FakeEngine::routed(vec![
            Route::new("GET", "/containers/json", 200, CONTAINERS),
            Route::new("GET", "/volumes", 200, VOLUMES),
            Route::new("GET", "/networks", 200, NETWORKS),
        ]);
        let a = plugin_toolkit::reactor::block_on(collect(&e.client())).unwrap();
        let by = |o: &str| a.groups.iter().find(|g| g.owner == o).unwrap().clone();
        let media = by("media");
        assert_eq!(media.containers, vec!["media-app-1"]);
        assert_eq!(media.volumes, vec!["anon1", "media_db"]);
        assert_eq!(media.networks, vec!["media_default"]);
        // Attributed through a managed container's mount, still unlabeled itself.
        assert_eq!(by("web").volumes, vec!["anon2"]);
        let unknown = by(UNKNOWN_OWNER);
        assert_eq!(unknown.containers, vec!["loose"]);
        assert_eq!(unknown.volumes, vec!["stray"]);
        assert_eq!(a.total, 7);
        assert!(e.paths("DELETE").is_empty() && e.paths("POST").is_empty());
    }
}
