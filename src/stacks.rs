//! Managed Compose **stacks** — orca's config-manager view of `docker compose`.
//!
//! A *stack* pairs a unique `name` with a project directory on the host that
//! holds a compose file. orca persists this registry (name → dir/file) in the
//! generic per-plugin KV store, so orca — not the filesystem alone — owns the
//! *set* of managed stacks and can `view` / `edit` / `deploy` each one's compose
//! file over the cli / api / mcp surfaces.
//!
//! The compose file itself stays on disk (it is the user's own file and the
//! canonical input to the `docker compose` CLI); orca reads it for `view`,
//! rewrites it for `edit`, and runs `up` for `deploy`. Keeping disk canonical
//! avoids a stored-copy that could silently drift from what the CLI actually
//! runs.

use std::path::{Path, PathBuf};

use plugin_toolkit::anyhow::{self, Context, Result};
use plugin_toolkit::db;
use plugin_toolkit::serde::{Deserialize, Serialize};
use plugin_toolkit::serde_json;

use crate::Compose;

/// plugin_data owner id — matches the docker runtime registry's plugin id.
const PLUGIN_ID: &str = "docker";
/// Stack rows are namespaced under this key prefix so they never collide with
/// any other docker plugin_data entry.
const KEY_PREFIX: &str = "stack:";
/// Compose filename written when the caller doesn't name one.
pub const DEFAULT_COMPOSE_FILE: &str = "docker-compose.yml";
const ENV_FILE: &str = ".env";

/// A registered managed stack: a name bound to an on-disk compose project.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
pub struct StackRow {
    /// Unique stack name (the natural key).
    pub name: String,
    /// Absolute project directory holding the compose file.
    pub dir: String,
    /// Compose filename within `dir` (default `docker-compose.yml`).
    #[serde(default = "default_compose_file")]
    pub file: String,
    /// Whether orca considers the stack active. Deploy actions ignore disabled
    /// stacks in bulk operations; direct verbs still work.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_compose_file() -> String {
    DEFAULT_COMPOSE_FILE.to_string()
}
fn default_true() -> bool {
    true
}

impl StackRow {
    /// Absolute path to the stack's compose file.
    pub fn compose_path(&self) -> PathBuf {
        Path::new(&self.dir).join(&self.file)
    }

    /// Absolute path to the stack's `.env` file.
    pub fn env_path(&self) -> PathBuf {
        Path::new(&self.dir).join(ENV_FILE)
    }

    /// Read the compose file contents (the `view` operation).
    pub fn read_compose(&self) -> Result<String> {
        let p = self.compose_path();
        std::fs::read_to_string(&p).with_context(|| format!("reading compose file {}", p.display()))
    }

    /// Read the `.env` contents if present. Missing file → `None`.
    pub fn read_env(&self) -> Option<String> {
        std::fs::read_to_string(self.env_path()).ok()
    }

    /// Write compose file contents (the `edit` operation), creating `dir` if
    /// needed.
    pub fn write_compose(&self, yaml: &str) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating stack dir {}", self.dir))?;
        let p = self.compose_path();
        std::fs::write(&p, yaml).with_context(|| format!("writing compose file {}", p.display()))
    }

    /// Write `.env` contents. Empty input is a no-op (leaves any existing file
    /// untouched).
    pub fn write_env(&self, env: &str) -> Result<()> {
        if env.is_empty() {
            return Ok(());
        }
        let p = self.env_path();
        std::fs::write(&p, env).with_context(|| format!("writing env file {}", p.display()))
    }

    /// Open the located [`Compose`] project for lifecycle actions. Errors when
    /// no compose file is present under `dir`.
    pub fn compose(&self) -> Result<Compose, crate::ComposeError> {
        Compose::open(Path::new(&self.dir))
    }
}

fn key(name: &str) -> String {
    format!("{KEY_PREFIX}{name}")
}

/// All registered stacks, ordered by name.
pub fn list() -> Result<Vec<StackRow>> {
    let conn = db::open_default()?;
    let mut out = Vec::new();
    for row in db::plugin_data::list(&conn, PLUGIN_ID)? {
        if !row.key.starts_with(KEY_PREFIX) {
            continue;
        }
        match serde_json::from_str::<StackRow>(&row.value) {
            Ok(s) => out.push(s),
            Err(e) => {
                // A malformed row shouldn't take down the whole listing; skip it.
                plugin_toolkit::tracing::warn!(key = %row.key, error = %e, "skipping unreadable stack row");
            }
        }
    }
    Ok(out)
}

/// Look up a single stack by name.
pub fn get(name: &str) -> Result<Option<StackRow>> {
    let conn = db::open_default()?;
    match db::plugin_data::get(&conn, PLUGIN_ID, &key(name))? {
        Some(r) => Ok(Some(serde_json::from_str(&r.value)?)),
        None => Ok(None),
    }
}

/// Look up a stack, erroring when it isn't registered.
pub fn require(name: &str) -> Result<StackRow> {
    get(name)?.ok_or_else(|| anyhow::anyhow!("no managed stack named '{name}'"))
}

/// Whether a stack with this name is registered.
pub fn exists(name: &str) -> Result<bool> {
    Ok(get(name)?.is_some())
}

/// Insert or replace a stack row (the registry write for create/upsert).
pub fn put(row: &StackRow) -> Result<()> {
    let conn = db::open_default()?;
    let value = serde_json::to_string(row)?;
    db::plugin_data::set(&conn, PLUGIN_ID, &key(&row.name), &value)
}

/// Deregister a stack. Returns whether a row was removed. Does NOT tear down
/// running containers — callers run `down` first when that's intended.
pub fn remove(name: &str) -> Result<bool> {
    let conn = db::open_default()?;
    db::plugin_data::delete(&conn, PLUGIN_ID, &key(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn row(dir: &Path) -> StackRow {
        StackRow {
            name: "web".into(),
            dir: dir.to_string_lossy().into_owned(),
            file: DEFAULT_COMPOSE_FILE.into(),
            enabled: true,
        }
    }

    #[test]
    fn compose_and_env_paths_join_dir() {
        let r = StackRow {
            name: "x".into(),
            dir: "/srv/x".into(),
            file: "compose.yaml".into(),
            enabled: true,
        };
        assert_eq!(r.compose_path(), Path::new("/srv/x/compose.yaml"));
        assert_eq!(r.env_path(), Path::new("/srv/x/.env"));
    }

    #[test]
    fn write_then_read_roundtrips_compose() {
        let dir = tempdir().unwrap();
        let r = row(dir.path());
        r.write_compose("services:\n  web:\n    image: nginx\n")
            .unwrap();
        assert!(r.read_compose().unwrap().contains("nginx"));
    }

    #[test]
    fn write_compose_creates_missing_dir() {
        let base = tempdir().unwrap();
        let nested = base.path().join("a/b/c");
        let r = row(&nested);
        r.write_compose("services: {}").unwrap();
        assert!(nested.join(DEFAULT_COMPOSE_FILE).exists());
    }

    #[test]
    fn read_env_absent_is_none() {
        let dir = tempdir().unwrap();
        assert!(row(dir.path()).read_env().is_none());
    }

    #[test]
    fn write_env_empty_is_noop() {
        let dir = tempdir().unwrap();
        let r = row(dir.path());
        r.write_env("").unwrap();
        assert!(!r.env_path().exists());
    }

    #[test]
    fn write_env_roundtrips() {
        let dir = tempdir().unwrap();
        let r = row(dir.path());
        r.write_env("FOO=bar\n").unwrap();
        assert_eq!(r.read_env().as_deref(), Some("FOO=bar\n"));
    }

    #[test]
    fn stackrow_deserializes_with_defaults() {
        let r: StackRow = serde_json::from_str(r#"{"name":"a","dir":"/srv/a"}"#).unwrap();
        assert_eq!(r.file, DEFAULT_COMPOSE_FILE);
        assert!(r.enabled);
    }
}
