//! orca ownership labels for docker resources. Mirrors the contract in
//! orca#772 exactly; moves to `plugin_toolkit::labels` when that lands.

use std::collections::BTreeMap;

/// `true` on every container, volume, network and image orca creates.
pub const MANAGED: &str = "orca.managed";
/// The plugin that deployed the resource.
pub const OWNER: &str = "orca.owner";
/// The compose project or template name.
pub const STACK: &str = "orca.stack";
/// The compose service or container name (containers, volumes).
pub const SERVICE: &str = "orca.service";
/// The orca unit id, when one exists.
pub const UNIT: &str = "orca.unit";
/// The container path a volume is mounted at.
pub const MOUNT: &str = "orca.mount";

pub const HEAL: &str = "orca.heal";
pub const SKIP: &str = "orca.skip";
pub const UNWEDGE: &str = "orca.unwedge";
pub const ROLE: &str = "orca.role";
pub const ICON_URL: &str = "orca.icon_url";
pub const WEB_UI_URL: &str = "orca.web_ui_url";
pub const UPDATE_AVAILABLE: &str = "orca.update_available";

/// This plugin's `orca.owner` value.
pub const OWNER_DOCKER: &str = "docker";

/// The ownership labels of one resource.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Labels {
    pub owner: String,
    pub stack: String,
    pub service: Option<String>,
    pub unit: Option<String>,
    pub mount: Option<String>,
}

impl Labels {
    pub fn for_(owner: &str, stack: &str, service: Option<&str>, unit: Option<&str>) -> Self {
        Self {
            owner: owner.to_string(),
            stack: stack.to_string(),
            service: service.map(str::to_string),
            unit: unit.map(str::to_string),
            mount: None,
        }
    }

    pub fn with_mount(mut self, path: &str) -> Self {
        self.mount = Some(path.to_string());
        self
    }

    pub fn to_map(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::from([
            (MANAGED.to_string(), "true".to_string()),
            (OWNER.to_string(), self.owner.clone()),
            (STACK.to_string(), self.stack.clone()),
        ]);
        for (key, value) in [
            (SERVICE, &self.service),
            (UNIT, &self.unit),
            (MOUNT, &self.mount),
        ] {
            if let Some(v) = value {
                m.insert(key.to_string(), v.clone());
            }
        }
        m
    }
}

/// Whether `labels` mark the resource as orca-managed.
pub fn is_managed<'a>(mut labels: impl Iterator<Item = (&'a String, &'a String)>) -> bool {
    labels.any(|(k, v)| k == MANAGED && v == "true")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_carry_the_contract_keys_and_omit_unknown_ones() {
        let m = Labels::for_(OWNER_DOCKER, "media", Some("app"), None)
            .with_mount("/data")
            .to_map();
        assert_eq!(m[MANAGED], "true");
        assert_eq!(m[OWNER], "docker");
        assert_eq!(m[STACK], "media");
        assert_eq!(m[SERVICE], "app");
        assert_eq!(m[MOUNT], "/data");
        assert!(!m.contains_key(UNIT));
        assert!(is_managed(m.iter()));
    }
}
