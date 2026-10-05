//! Managed Compose **stacks** — orca's config-manager view of `docker compose`.
//!
//! A *stack* pairs a unique `name` with a project directory on the host that
//! holds a compose file. orca persists this registry (name → dir/file) in the
//! docker-owned `docker.stacks` table — reached through the thin `db_op`
//! capability so the plugin links no rusqlite and opens no second connection —
//! so orca, not the filesystem alone, owns the *set* of managed stacks and can
//! `view` / `edit` / `deploy` each one's compose file over the cli / api / mcp
//! surfaces.
//!
//! The compose file itself stays on disk (it is the user's own file and the
//! canonical input to the `docker compose` CLI); orca reads it for `view`,
//! rewrites it for `edit`, and runs `up` for `deploy`. Keeping disk canonical
//! avoids a stored-copy that could silently drift from what the CLI actually
//! runs.

use std::path::{Path, PathBuf};

use plugin_toolkit::abi::{DbOp, DbRow, DbValue};
use plugin_toolkit::anyhow::{self, Context, Result};
use plugin_toolkit::runtime::{db_op, field_from_row};
use plugin_toolkit::serde::{Deserialize, Serialize};

use crate::Compose;
use crate::compose_config::ComposeConfig;
use crate::policy;

/// The docker-owned stacks table. Declared in the Hello handshake schema (see
/// [`crate::registration::schema_json`]) and applied by the daemon against its
/// single connection, which resolves `(namespace="docker", table="stacks")` to
/// the physical `plug__docker__stacks` table; every op runs through [`db_op`]
/// (the `db.op` capability / host FFI channel), so this plugin never opens its
/// own SQLite connection.
const TABLE: &str = "stacks";

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
    /// Compose policy exceptions an admin granted this stack (see
    /// [`crate::policy`]).
    #[serde(default)]
    pub allow: Vec<String>,
}

fn default_compose_file() -> String {
    DEFAULT_COMPOSE_FILE.to_string()
}
fn default_true() -> bool {
    true
}

impl StackRow {
    /// The stack's compose file: `<dir>/<file>` when it exists, else the
    /// conventional file compose would pick in `dir`, else `<dir>/<file>` (to
    /// be created). Audit, view, edit and every compose call use this one
    /// path.
    pub fn compose_path(&self) -> PathBuf {
        let named = Path::new(&self.dir).join(&self.file);
        if named.is_file() {
            return named;
        }
        Compose::find(Path::new(&self.dir))
            .map(|c| c.file().to_path_buf())
            .unwrap_or(named)
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
    /// needed. See [`StagedWrite`].
    pub fn write_compose(&self, yaml: &str) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating stack dir {}", self.dir))?;
        StagedWrite::new(&self.compose_path(), yaml)?.commit()
    }

    /// Rewrite the compose file for `fix`: refused when the file on disk no
    /// longer hashes to `read_before` (someone edited it since it was read),
    /// or when compose rejects the new content. Nothing is replaced unless
    /// both pass.
    pub async fn write_compose_if_unchanged(&self, yaml: &str, read_before: &str) -> Result<()> {
        let now = self.read_compose()?;
        if content_hash(&now) != content_hash(read_before) {
            anyhow::bail!(
                "compose file {} changed since it was read; re-run the dry run",
                self.compose_path().display()
            );
        }
        let staged = StagedWrite::new(&self.compose_path(), yaml)?;
        validate_compose(&self.dir, staged.temp_path()).await?;
        staged.commit()
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

    /// Write the compose file and/or `.env` for `deploy`, `set` and `edit`:
    /// both are staged, the resolved config they produce is checked against
    /// [`crate::policy`], and nothing is replaced unless it passes. `current`
    /// is the registered stack before this write; settings it already ran
    /// with stay allowed. With no compose file to write or on disk there is
    /// nothing to check.
    pub async fn write_checked(
        &self,
        yaml: Option<&str>,
        env: Option<&str>,
        current: Option<&StackRow>,
        stacks_roots: &[String],
    ) -> Result<()> {
        let env = env.filter(|e| !e.is_empty());
        if yaml.is_some() || env.is_some() {
            std::fs::create_dir_all(&self.dir)
                .with_context(|| format!("creating stack dir {}", self.dir))?;
        }
        let compose_path = self.compose_path();
        let env_path = self.env_path();
        ensure_within(&compose_path, &self.dir)?;
        ensure_within(&env_path, &self.dir)?;
        let compose = yaml
            .map(|y| StagedWrite::new(&compose_path, y))
            .transpose()?;
        let env = env.map(|e| StagedWrite::new(&env_path, e)).transpose()?;
        let file = match &compose {
            Some(staged) => staged.temp_path().to_path_buf(),
            None if compose_path.is_file() => compose_path,
            None => {
                if let Some(staged) = env {
                    staged.commit()?;
                }
                return Ok(());
            }
        };
        let raw = config_json(&self.dir, &file, env.as_ref().map(StagedWrite::temp_path)).await?;
        let new = ComposeConfig::parse(&raw)?;
        let before = match current.map(StackRow::compose) {
            Some(Ok(c)) => c
                .config_json()
                .await
                .ok()
                .and_then(|raw| ComposeConfig::parse(&raw).ok()),
            _ => None,
        };
        let roots = policy::bind_roots(&self.dir, stacks_roots);
        policy::check(
            &new,
            before.as_ref(),
            &self.allow,
            &roots,
            &policy::resolve_host_path,
        )?;
        if let Some(staged) = compose {
            staged.commit()?;
        }
        if let Some(staged) = env {
            staged.commit()?;
        }
        Ok(())
    }

    /// The [`Compose`] project of [`compose_path`](Self::compose_path).
    /// Errors when that file does not exist.
    pub fn compose(&self) -> Result<Compose, crate::ComposeError> {
        Compose::at(&self.compose_path())
            .ok_or_else(|| crate::ComposeError::NoComposeFile(PathBuf::from(&self.dir)))
    }
}

/// `docker compose config -q` over `file` in place of the stack's compose
/// file (with the override compose would load), from `dir`.
async fn validate_compose(dir: &str, file: &Path) -> Result<()> {
    let args = validate_args(dir, file);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    crate::run(&argv, None)
        .await
        .map(|_| ())
        .context("compose rejects the rewritten file; nothing was written")
}

fn validate_args(dir: &str, file: &Path) -> Vec<String> {
    let mut args = project_args(dir, file);
    args.extend(["config".into(), "-q".into()]);
    args
}

/// `compose` with `file` as the project's compose file, plus the override
/// compose would load from `dir`.
fn project_args(dir: &str, file: &Path) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "compose".into(),
        "--project-directory".into(),
        dir.into(),
        "-f".into(),
        file.to_string_lossy().into_owned(),
    ];
    if let Some(o) =
        Compose::find(Path::new(dir)).and_then(|c| c.override_file().map(Path::to_path_buf))
    {
        args.extend(["-f".into(), o.to_string_lossy().into_owned()]);
    }
    args
}

/// The resolved config `compose up` would run with `file` as the compose file
/// and, when given, `env_file` in place of the stack's `.env`.
pub async fn config_json(dir: &str, file: &Path, env_file: Option<&Path>) -> Result<String> {
    let mut args = project_args(dir, file);
    if let Some(env) = env_file {
        args.extend(["--env-file".into(), env.to_string_lossy().into_owned()]);
    }
    args.extend(["config".into(), "--format".into(), "json".into()]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    crate::run(&argv, None)
        .await
        .context("compose rejects the stack's config; nothing was written")
}

/// `dir` resolved, symlinks included, and refused unless it lies strictly
/// inside one of `roots`.
pub fn stack_dir_in_roots(dir: &str, roots: &[String]) -> Result<PathBuf> {
    let resolved = crate::lifecycle::resolve(Path::new(dir))?;
    let inside = roots
        .iter()
        .filter_map(|r| crate::lifecycle::resolve(Path::new(r)).ok())
        .any(|root| resolved.starts_with(&root) && resolved != root);
    if !inside {
        anyhow::bail!(
            "stack dir '{dir}' resolves to '{}', outside the stacks roots ({}); set stacks_root with docker.update to allow another root",
            resolved.display(),
            roots.join(", ")
        );
    }
    Ok(resolved)
}

/// A compose filename: one plain path component.
pub fn check_file_name(file: &str) -> Result<()> {
    let mut parts = Path::new(file).components();
    match (parts.next(), parts.next()) {
        (Some(std::path::Component::Normal(_)), None) => Ok(()),
        _ => anyhow::bail!("compose file '{file}' must be a plain file name inside the stack dir"),
    }
}

/// Refuse `path` when it resolves, through a symlink, outside `dir`.
pub fn ensure_within(path: &Path, dir: &str) -> Result<()> {
    let resolved = crate::lifecycle::resolve(path)?;
    let dir = crate::lifecycle::resolve(Path::new(dir))?;
    if !resolved.starts_with(&dir) {
        anyhow::bail!(
            "'{}' resolves to '{}', outside the stack dir '{}'",
            path.display(),
            resolved.display(),
            dir.display()
        );
    }
    Ok(())
}

/// A file replacement staged next to its target. The target is resolved
/// through symlinks, so a symlinked compose file is rewritten where it lives
/// and stays a symlink. The temp file has a unique name, the original's mode
/// and owner, and is fsynced; [`commit`](Self::commit) keeps the original as
/// `<name>.bak`, renames over it and fsyncs the directory. Dropped without a
/// commit, the temp file is removed and the original is untouched.
pub struct StagedWrite {
    target: PathBuf,
    temp: PathBuf,
    committed: bool,
}

impl StagedWrite {
    pub fn new(path: &Path, contents: &str) -> Result<Self> {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let target = if path.exists() {
            std::fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()))?
        } else {
            path.to_path_buf()
        };
        let dir = target
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{} has no directory", target.display()))?;
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temp = dir.join(format!(
            ".{name}.orca-{}-{nanos}-{seq}.tmp",
            std::process::id()
        ));
        let original = std::fs::metadata(&target).ok();
        let staged = StagedWrite {
            target: target.clone(),
            temp: temp.clone(),
            committed: false,
        };
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .with_context(|| format!("creating {}", temp.display()))?;
        f.write_all(contents.as_bytes())
            .with_context(|| format!("writing {}", temp.display()))?;
        if let Some(meta) = &original {
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(meta.mode() & 0o7777))
                .with_context(|| format!("setting the mode of {}", temp.display()))?;
            // Only root may give a file away; a same-owner chown is a no-op.
            if let Err(e) = std::os::unix::fs::chown(&temp, Some(meta.uid()), Some(meta.gid()))
                && e.kind() != std::io::ErrorKind::PermissionDenied
            {
                return Err(e).with_context(|| format!("setting the owner of {}", temp.display()));
            }
        }
        f.sync_all()
            .with_context(|| format!("syncing {}", temp.display()))?;
        Ok(staged)
    }

    pub fn temp_path(&self) -> &Path {
        &self.temp
    }

    /// [`replace`](Self::replace), keeping the original as `<name>.bak`.
    pub fn commit(self) -> Result<()> {
        if self.target.exists() {
            let mut bak = self.target.clone().into_os_string();
            bak.push(".bak");
            std::fs::copy(&self.target, &bak)
                .with_context(|| format!("keeping a backup at {}", bak.to_string_lossy()))?;
        }
        self.replace()
    }

    /// Rename the temp file over the target and fsync the directory.
    pub fn replace(mut self) -> Result<()> {
        std::fs::rename(&self.temp, &self.target)
            .with_context(|| format!("replacing {}", self.target.display()))?;
        self.committed = true;
        if let Some(dir) = self.target.parent() {
            std::fs::File::open(dir)
                .and_then(|d| d.sync_all())
                .with_context(|| format!("syncing {}", dir.display()))?;
        }
        Ok(())
    }
}

impl Drop for StagedWrite {
    fn drop(&mut self) {
        if !self.committed {
            // Best effort: a leftover temp file is inert.
            let _removed = std::fs::remove_file(&self.temp);
        }
    }
}

fn content_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

fn to_dbrow(row: &StackRow) -> DbRow {
    let mut m = DbRow::new();
    m.insert("name".to_string(), DbValue::Text(row.name.clone()));
    m.insert("dir".to_string(), DbValue::Text(row.dir.clone()));
    m.insert("file".to_string(), DbValue::Text(row.file.clone()));
    m.insert("enabled".to_string(), DbValue::Bool(row.enabled));
    m.insert(
        "allow".to_string(),
        DbValue::Text(plugin_toolkit::serde_json::to_string(&row.allow).unwrap_or_default()),
    );
    m
}

fn from_dbrow(m: &DbRow) -> Result<StackRow> {
    Ok(StackRow {
        name: field_from_row(m, "name")?,
        dir: field_from_row(m, "dir")?,
        file: field_from_row(m, "file")?,
        enabled: field_from_row::<bool>(m, "enabled")?,
        allow: field_from_row::<Option<String>>(m, "allow")?
            .and_then(|raw| plugin_toolkit::serde_json::from_str(&raw).ok())
            .unwrap_or_default(),
    })
}

/// All registered stacks, ordered by name.
pub fn list() -> Result<Vec<StackRow>> {
    let reply = db_op(&DbOp::List {
        namespace: "docker".to_string(),
        table: TABLE.to_string(),
    })?;
    reply.rows.iter().map(from_dbrow).collect()
}

/// Look up a single stack by name.
pub fn get(name: &str) -> Result<Option<StackRow>> {
    let reply = db_op(&DbOp::Get {
        namespace: "docker".to_string(),
        table: TABLE.to_string(),
        key_col: "name".to_string(),
        key: name.to_string(),
    })?;
    match reply.rows.first() {
        Some(r) => Ok(Some(from_dbrow(r)?)),
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
    db_op(&DbOp::Upsert {
        namespace: "docker".to_string(),
        table: TABLE.to_string(),
        row: to_dbrow(row),
    })?;
    Ok(())
}

/// Deregister a stack. Returns whether a row was removed. Does NOT tear down
/// running containers — callers run `down` first when that's intended.
pub fn remove(name: &str) -> Result<bool> {
    let reply = db_op(&DbOp::Delete {
        namespace: "docker".to_string(),
        table: TABLE.to_string(),
        key_col: "name".to_string(),
        key: name.to_string(),
    })?;
    Ok(reply.affected > 0)
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
            allow: Vec::new(),
        }
    }

    #[test]
    fn compose_and_env_paths_join_dir() {
        let r = StackRow {
            name: "x".into(),
            dir: "/srv/x".into(),
            file: "compose.yaml".into(),
            enabled: true,
            allow: Vec::new(),
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
    fn write_compose_keeps_a_backup_and_leaves_no_temp_file() {
        let dir = tempdir().unwrap();
        let r = row(dir.path());
        r.write_compose("services: {}\n").unwrap();
        r.write_compose("services:\n  web: {}\n").unwrap();
        let bak = dir.path().join(format!("{DEFAULT_COMPOSE_FILE}.bak"));
        assert_eq!(std::fs::read_to_string(bak).unwrap(), "services: {}\n");
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!names.iter().any(|n| n.ends_with(".tmp")), "{names:?}");
    }

    #[test]
    fn write_compose_if_unchanged_refuses_a_file_edited_since_it_was_read() {
        let dir = tempdir().unwrap();
        let r = row(dir.path());
        r.write_compose("a: 1\n").unwrap();
        let read = r.read_compose().unwrap();
        std::fs::write(r.compose_path(), "a: 2\n").unwrap();
        let err = plugin_toolkit::reactor::block_on(r.write_compose_if_unchanged("a: 3\n", &read))
            .unwrap_err();
        assert!(
            err.to_string().contains("changed since it was read"),
            "{err}"
        );
        assert_eq!(r.read_compose().unwrap(), "a: 2\n");
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_staged_write_keeps_mode_and_leaves_the_original_until_commit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let p = dir.path().join("compose.yaml");
        std::fs::write(&p, "old\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let a = StagedWrite::new(&p, "new\n").unwrap();
        let b = StagedWrite::new(&p, "other\n").unwrap();
        assert_ne!(a.temp_path(), b.temp_path(), "temp names are unique");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "old\n");
        drop(b);
        a.commit().unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new\n");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert_eq!(
            entries(dir.path()),
            vec!["compose.yaml", "compose.yaml.bak"]
        );
    }

    #[test]
    fn validation_checks_the_temp_file_with_the_stack_override() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("compose.yaml"), "services: {}\n").unwrap();
        std::fs::write(dir.path().join("compose.override.yaml"), "").unwrap();
        let d = dir.path().to_string_lossy().into_owned();
        let tmp = dir.path().join(".compose.yaml.orca-1.tmp");
        let a = validate_args(&d, &tmp);
        assert_eq!(
            a[..5],
            [
                "compose".to_string(),
                "--project-directory".into(),
                d.clone(),
                "-f".into(),
                tmp.to_string_lossy().into_owned()
            ]
        );
        assert!(a[6].ends_with("compose.override.yaml"), "{a:?}");
        assert_eq!(a[7..], ["config".to_string(), "-q".into()]);
    }

    #[test]
    fn an_uncommitted_write_leaves_nothing_behind() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("compose.yaml");
        std::fs::write(&p, "old\n").unwrap();
        drop(StagedWrite::new(&p, "new\n").unwrap());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "old\n");
        assert_eq!(entries(dir.path()), vec!["compose.yaml"]);
    }

    #[test]
    fn a_symlinked_compose_file_is_written_through_and_stays_a_link() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.yaml");
        std::fs::write(&real, "old\n").unwrap();
        let link = dir.path().join("compose.yaml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        StagedWrite::new(&link, "new\n").unwrap().commit().unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "new\n");
    }

    #[test]
    fn compose_path_is_the_named_file_else_the_one_compose_picks() {
        let dir = tempdir().unwrap();
        let mut r = row(dir.path());
        r.file = "prod.yml".into();
        assert!(r.compose_path().ends_with("prod.yml"), "to be created");
        std::fs::write(dir.path().join("compose.yaml"), "services: {}\n").unwrap();
        assert!(r.compose_path().ends_with("compose.yaml"));
        std::fs::write(dir.path().join("prod.yml"), "services: {}\n").unwrap();
        assert!(r.compose_path().ends_with("prod.yml"));
        assert!(r.compose().unwrap().file().ends_with("prod.yml"));
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
        let r: StackRow =
            plugin_toolkit::serde_json::from_str(r#"{"name":"a","dir":"/srv/a"}"#).unwrap();
        assert_eq!(r.file, DEFAULT_COMPOSE_FILE);
        assert!(r.enabled);
    }

    fn s(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn stack_dir_must_resolve_strictly_inside_a_root() {
        let root = tempdir().unwrap();
        let roots = [s(root.path())];
        let inside = root.path().join("web");
        assert_eq!(
            stack_dir_in_roots(&s(&inside), &roots).unwrap(),
            root.path().canonicalize().unwrap().join("web")
        );
        let outside = tempdir().unwrap();
        for bad in [
            s(outside.path()),
            "/etc".to_string(),
            s(root.path()),
            format!("{}/web/../../etc", s(root.path())),
            "relative/web".to_string(),
        ] {
            assert!(stack_dir_in_roots(&bad, &roots).is_err(), "{bad}");
        }
    }

    #[test]
    fn stack_dir_refuses_a_symlink_out_of_the_root() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
        let roots = [s(root.path())];
        for dir in ["escape", "escape/web"] {
            let err = stack_dir_in_roots(&s(&root.path().join(dir)), &roots).unwrap_err();
            assert!(
                err.to_string().contains("outside the stacks roots"),
                "{err}"
            );
        }
    }

    #[test]
    fn compose_file_is_a_plain_name() {
        check_file_name("docker-compose.yml").unwrap();
        for bad in ["../x.yml", "/etc/x.yml", "sub/x.yml", "..", ""] {
            assert!(check_file_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn files_linked_out_of_the_stack_dir_are_refused() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("x.yml"),
            dir.path().join("compose.yaml"),
        )
        .unwrap();
        assert!(ensure_within(&dir.path().join("compose.yaml"), &s(dir.path())).is_err());
        ensure_within(&dir.path().join(".env"), &s(dir.path())).unwrap();
    }
}
