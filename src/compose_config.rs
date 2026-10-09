//! Typed view of `docker compose config --format json`. Compose has already
//! interpolated variables, made bind sources absolute and expanded mounts to
//! long syntax, so this is what the engine will actually be asked to run.

use std::collections::BTreeMap;

use plugin_toolkit::anyhow::{Context, Result};
use plugin_toolkit::serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
pub struct ComposeConfig {
    /// The compose project name, as stamped on `com.docker.compose.project`.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub services: BTreeMap<String, ServiceConfig>,
    /// Top-level named volumes, keyed by the name services refer to.
    #[serde(default)]
    pub volumes: BTreeMap<String, VolumeConfig>,
    /// Networks the project uses, keyed as services refer to them.
    #[serde(default)]
    pub networks: BTreeMap<String, NetworkConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
pub struct NetworkConfig {
    /// The engine-side name (`<project>_<key>` unless set explicitly).
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub external: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
pub struct ServiceConfig {
    #[serde(default)]
    pub restart: Option<String>,
    #[serde(default)]
    pub volumes: Vec<MountConfig>,
    #[serde(default)]
    pub privileged: bool,
    #[serde(default)]
    pub pid: Option<String>,
    #[serde(default)]
    pub network_mode: Option<String>,
    #[serde(default)]
    pub cap_add: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
pub struct MountConfig {
    /// `bind`, `volume`, `tmpfs`, …
    #[serde(rename = "type", default)]
    pub kind: String,
    /// Absent for anonymous volumes and tmpfs.
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub target: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
pub struct VolumeConfig {
    /// The engine-side name (`<project>_<key>` unless set explicitly).
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub external: Option<bool>,
    /// `local` driver options; `o: bind` + `device` binds a host path.
    #[serde(default)]
    pub driver_opts: BTreeMap<String, String>,
}

impl ComposeConfig {
    pub fn parse(raw: &str) -> Result<Self> {
        plugin_toolkit::serde_json::from_str(raw).context("parsing `compose config --format json`")
    }
}

impl MountConfig {
    /// An anonymous volume: type `volume` without a source.
    pub fn is_anonymous(&self) -> bool {
        self.kind == "volume" && self.source.as_deref().is_none_or(str::is_empty)
    }

    /// A named volume: type `volume` with a source.
    pub fn named_volume(&self) -> Option<&str> {
        (self.kind == "volume")
            .then_some(self.source.as_deref())
            .flatten()
            .filter(|s| !s.is_empty())
    }

    pub fn bind_source(&self) -> Option<&str> {
        (self.kind == "bind")
            .then_some(self.source.as_deref())
            .flatten()
            .filter(|s| !s.is_empty())
    }
}

#[cfg(test)]
pub(crate) const FIXTURE: &str = r#"{
  "name": "media",
  "services": {
    "app": {
      "image": "ghcr.io/example/app:1",
      "restart": "on-failure:3",
      "volumes": [
        {"type": "bind", "source": "/mnt/willow/media", "target": "/media", "bind": {"create_host_path": true}},
        {"type": "bind", "source": "/srv/stacks/media/config", "target": "/config"},
        {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"},
        {"type": "volume", "source": "data", "target": "/data", "volume": {}},
        {"type": "volume", "target": "/cache"}
      ]
    },
    "db": {
      "image": "postgres:16",
      "restart": "unless-stopped",
      "volumes": [
        {"type": "volume", "source": "pg", "target": "/var/lib/postgresql/data"},
        {"type": "bind", "source": "/mnt/data/gone", "target": "/import"}
      ]
    },
    "worker": {
      "image": "ghcr.io/example/worker:1"
    }
  },
  "volumes": {
    "data": {"name": "media_data"},
    "pg": {"name": "media_pg"},
    "shared": {"name": "shared", "external": true}
  },
  "networks": {
    "default": {"name": "media_default"},
    "proxy": {"name": "caddy_proxy", "external": true}
  }
}"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_services_mounts_and_volumes() {
        let c = ComposeConfig::parse(FIXTURE).unwrap();
        assert_eq!(c.name, "media");
        let app = &c.services["app"];
        assert_eq!(app.restart.as_deref(), Some("on-failure:3"));
        assert_eq!(app.volumes[0].bind_source(), Some("/mnt/willow/media"));
        assert_eq!(app.volumes[3].named_volume(), Some("data"));
        assert_eq!(app.volumes[4].named_volume(), None, "anonymous");
        assert!(app.volumes[4].is_anonymous() && !app.volumes[3].is_anonymous());
        assert_eq!(c.networks["proxy"].external, Some(true));
        assert!(c.services["worker"].restart.is_none());
        assert_eq!(c.volumes["data"].name.as_deref(), Some("media_data"));
        assert_eq!(c.volumes["shared"].external, Some(true));
    }
}
