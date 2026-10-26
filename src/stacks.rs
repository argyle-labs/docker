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
use crate::{fsat, policy};

/// The docker-owned stacks table. Declared in the Hello handshake schema (see
/// [`crate::registration::schema_json`]) and applied by the daemon against its
/// single connection, which resolves `(namespace="docker", table="stacks")` to
/// the physical `plug__docker__stacks` table; every op runs through [`db_op`]
/// (the `db.op` capability / host FFI channel), so this plugin never opens its
/// own SQLite connection.
const TABLE: &str = "stacks";

/// Compose filename written when the caller doesn't name one.
pub const DEFAULT_COMPOSE_FILE: &str = "docker-compose.yml";
pub const ENV_FILE: &str = ".env";

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
    /// Compose policy exceptions an admin granted this stack, each bound to
    /// a service and its image (see [`crate::policy`]).
    #[serde(default)]
    pub allow: Vec<policy::Grant>,
    /// Every compose file, absolute, of a discovered project; empty means
    /// `file` in `dir` with the override compose loads next to it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_files: Vec<String>,
    /// The compose project the stack runs as, once known; unset reads as
    /// `name`. `docker.stack_adopt` fills it in for rows without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

fn default_compose_file() -> String {
    DEFAULT_COMPOSE_FILE.to_string()
}
fn default_true() -> bool {
    true
}

impl StackRow {
    pub fn project_name(&self) -> String {
        self.project.clone().unwrap_or_else(|| self.name.clone())
    }

    pub fn open_dir(&self, roots: &[String]) -> Result<StackDir> {
        StackDir::open(&self.dir, roots, false)?
            .ok_or_else(|| anyhow::anyhow!("stack dir {} does not exist", self.dir))
    }

    /// The stack's compose file inside its dir under `roots`: `<file>` when
    /// it exists, else the conventional file compose would pick, else
    /// `<file>` (to be created). Refused when the dir is outside `roots` or
    /// the file is neither a regular file nor a symlink to one in `roots`.
    pub fn compose_path(&self, roots: &[String]) -> Result<PathBuf> {
        let dir = self.open_dir(roots)?;
        let name = self.compose_name(&dir);
        if dir.stat(&name)?.is_some() {
            file_in_roots(&dir, &name, roots)?;
        }
        Ok(dir.path().join(name))
    }

    /// The file name of [`compose_path`](Self::compose_path) inside `dir`.
    pub fn compose_name(&self, dir: &StackDir) -> String {
        if dir.path().join(&self.file).is_file() {
            return self.file.clone();
        }
        Compose::find(dir.path())
            .and_then(|c| {
                c.file()
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| self.file.clone())
    }

    fn listed_compose(&self, roots: &[String]) -> Result<Compose, crate::ComposeError> {
        self.open_dir(roots).map_err(crate::ComposeError::Refused)?;
        let check = |list: &[String]| -> Result<Vec<PathBuf>, crate::ComposeError> {
            list.iter()
                .map(|f| {
                    listed_file(f, roots).map_err(|cause| {
                        crate::ComposeError::Refused(anyhow::anyhow!("{f}: {cause}"))
                    })
                })
                .collect()
        };
        Compose::new(
            check(&self.files)?,
            check(&self.env_files)?,
            Some(self.name.clone()),
        )
        .map(|c| c.with_project_dir(anchored(Path::new(&self.dir))))
        .ok_or_else(|| crate::ComposeError::NoComposeFile(PathBuf::from(&self.dir)))
    }

    pub fn emitted_dir(&self, roots: &[String]) -> Option<String> {
        canonical_in_roots(&self.dir, roots).map(|d| d.to_string_lossy().into_owned())
    }

    /// Absolute path to the stack's `.env` file.
    pub fn env_path(&self) -> PathBuf {
        Path::new(&self.dir).join(ENV_FILE)
    }

    /// Read the compose file contents (the `view` operation).
    pub fn read_compose(&self, roots: &[String]) -> Result<String> {
        let dir = self.open_dir(roots)?;
        self.read_file(&self.compose_name(&dir), roots)
    }

    pub fn read_file(&self, name: &str, roots: &[String]) -> Result<String> {
        let dir = self.open_dir(roots)?;
        let (dir, name) = file_in_roots(&dir, name, roots)?;
        dir.read(&name)
    }

    /// Read the `.env` contents if present. Missing file, a dir outside
    /// `roots`, or a symlink in its place → `None`.
    pub fn read_env(&self, roots: &[String]) -> Option<String> {
        self.open_dir(roots).ok()?.read(ENV_FILE).ok()
    }

    /// `text` with every value the stack's `.env` sets replaced by `***`.
    pub fn redact(&self, text: &str, roots: &[String]) -> String {
        redact(text, &env_values(&self.read_env(roots).unwrap_or_default()))
    }

    /// Write the compose file and/or `.env` for `deploy`, `set` and `edit`:
    /// both are staged in the stack dir (opened under a stacks root without
    /// following symlinks), the resolved config they produce is checked
    /// against [`crate::policy`] with this row's grants, and nothing is
    /// replaced unless it passes. With no compose file to write or on disk
    /// there is nothing to check.
    pub async fn write_checked(
        &self,
        yaml: Option<&str>,
        env: Option<&str>,
        stacks_roots: &[String],
        docker: Option<&bollard::Docker>,
    ) -> Result<()> {
        check_file_name(&self.file)?;
        let env = env.filter(|e| !e.is_empty());
        let Some(dir) = StackDir::open(&self.dir, stacks_roots, yaml.is_some() || env.is_some())?
        else {
            return Ok(());
        };
        let name = self.compose_name(&dir);
        let compose = yaml.map(|y| StagedWrite::new(&dir, &name, y)).transpose()?;
        let env = env
            .map(|e| StagedWrite::new(&dir, ENV_FILE, e))
            .transpose()?;
        let file = match &compose {
            Some(staged) => staged.temp_path(),
            None => match dir.stat(&name)? {
                Some(st) if st.kind == fsat::Kind::File => dir.path().join(&name),
                Some(st)
                    if st.kind == fsat::Kind::Symlink
                        && regular_file_in_roots(&dir.path().join(&name), stacks_roots) =>
                {
                    dir.path().join(&name)
                }
                Some(_) => anyhow::bail!(
                    "compose file '{name}' in {} is not a regular file",
                    dir.path().display()
                ),
                None => {
                    if let Some(staged) = env {
                        staged.commit()?;
                    }
                    return Ok(());
                }
            },
        };
        let env_file = env.as_ref().map(StagedWrite::temp_path);
        let checked =
            self.checked_compose(dir.path(), &name, &file, env_file.as_deref(), stacks_roots)?;
        let raw = resolved_config(dir.path(), &checked)
            .await
            .context("nothing was written")?;
        let cfg = policy::prepare(&raw, dir.path(), &dir)?;
        policy::check_stack(docker, &cfg, &cfg, self, dir.path(), stacks_roots).await?;
        if let Some(staged) = compose {
            staged.commit()?;
        }
        if let Some(staged) = env {
            staged.commit()?;
        }
        Ok(())
    }

    /// The project this row runs from `dir`, with `file` (the compose file
    /// `name`, possibly staged) and `env` (a staged `.env`) in place of the
    /// live ones: exactly what a write will run.
    fn checked_compose(
        &self,
        dir: &Path,
        name: &str,
        file: &Path,
        env: Option<&Path>,
        roots: &[String],
    ) -> Result<Compose> {
        let live_file = entry(&dir.join(name));
        let listed = match self.compose(roots) {
            Ok(c) => c,
            Err(crate::ComposeError::NoComposeFile(_)) if self.files.is_empty() => {
                let mut files = vec![dir.join(name)];
                files.extend(crate::compose::override_in(dir));
                Compose::new(files, Vec::new(), None).context("no compose file")?
            }
            Err(e) => return Err(e.into()),
        };
        if entry(file) != live_file && !listed.files().iter().any(|f| entry(f) == live_file) {
            anyhow::bail!(
                "compose file {} is not one of the files the stack runs",
                live_file.display()
            );
        }
        let live_env = entry(&dir.join(ENV_FILE));
        if env.is_some()
            && !listed.env_files().is_empty()
            && !listed.env_files().iter().any(|e| entry(e) == live_env)
        {
            anyhow::bail!(
                "the stack runs with env files {}, not {}; a .env would not take effect",
                listed
                    .env_files()
                    .iter()
                    .map(|e| e.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                live_env.display()
            );
        }
        let swapped = listed.map_paths(|p| {
            let a = entry(p);
            if a == live_file {
                file.to_path_buf()
            } else if let Some(env) = env.filter(|_| a == live_env) {
                env.to_path_buf()
            } else {
                p.to_path_buf()
            }
        });
        let swapped = match env {
            Some(env) if swapped.env_files().is_empty() => swapped.with_env_file(env.to_path_buf()),
            _ => swapped,
        };
        Ok(if dir.join(crate::compose::ORCA_FILE).is_file() {
            swapped.with_orca(roots)?
        } else {
            swapped
        })
    }

    /// Rewrite the compose file for `fix`: refused when the file on disk no
    /// longer hashes to `read_before` (someone edited it since it was read),
    /// when compose rejects the new content, or when the policy refuses it.
    /// Nothing is replaced unless all pass.
    pub async fn write_compose_if_unchanged(
        &self,
        yaml: &str,
        read_before: &str,
        stacks_roots: &[String],
        docker: Option<&bollard::Docker>,
    ) -> Result<()> {
        let dir = StackDir::open(&self.dir, stacks_roots, false)?
            .ok_or_else(|| anyhow::anyhow!("stack dir {} does not exist", self.dir))?;
        let name = self.compose_name(&dir);
        let now = dir.read(&name)?;
        if content_hash(&now) != content_hash(read_before) {
            anyhow::bail!(
                "compose file {} changed since it was read; re-run the dry run",
                dir.path().join(&name).display()
            );
        }
        let staged = StagedWrite::new(&dir, &name, yaml)?;
        let checked =
            self.checked_compose(dir.path(), &name, &staged.temp_path(), None, stacks_roots)?;
        let raw = resolved_config(dir.path(), &checked)
            .await
            .context("nothing was written")?;
        let cfg = policy::prepare(&raw, dir.path(), &dir)?;
        policy::check_stack(docker, &cfg, &cfg, self, dir.path(), stacks_roots).await?;
        staged.commit()
    }

    /// The [`Compose`] project of [`compose_path`](Self::compose_path).
    /// Errors when that file does not exist.
    pub fn compose(&self, roots: &[String]) -> Result<Compose, crate::ComposeError> {
        if !self.files.is_empty() {
            return self.listed_compose(roots);
        }
        let missing = || crate::ComposeError::NoComposeFile(PathBuf::from(&self.dir));
        let path = self
            .compose_path(roots)
            .map_err(crate::ComposeError::Refused)?;
        let compose = Compose::at(&path).ok_or_else(missing)?;
        if let Some(o) = compose.override_file()
            && !regular_file_in_roots(o, roots)
        {
            return Err(crate::ComposeError::Refused(anyhow::anyhow!(
                "{} is not a regular file inside the stacks roots",
                o.display()
            )));
        }
        Ok(compose)
    }
}

/// One assignment in an env file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvEntry {
    pub key: String,
    /// Unquoted, escapes in double quotes applied.
    pub value: String,
    /// The value names a variable (`$VAR` or `${VAR}`, unquoted or in double
    /// quotes) that compose would expand.
    pub expands: bool,
}

/// Whether `$` at `chars[i]` starts a variable compose would expand.
fn starts_var(chars: &[char], i: usize) -> bool {
    chars
        .get(i + 1)
        .is_some_and(|c| *c == '{' || *c == '_' || c.is_ascii_alphabetic())
}

/// The assignments an env file sets, in file order, read as compose reads
/// them: `KEY=value` or `KEY: value`, an optional `export ` prefix, `#`
/// comments (inline ones after whitespace in unquoted values), single quotes
/// literal, double quotes with `\n`, `\r`, `\t`, `\\`, `\"` and `\$`
/// escapes, and quoted values that span lines.
pub fn parse_env(text: &str) -> Vec<EnvEntry> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut i = 0;
    let mut out = Vec::new();
    let skip_line = |i: &mut usize| {
        while *i < n && chars[*i] != '\n' {
            *i += 1;
        }
    };
    while i < n {
        while i < n && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= n {
            break;
        }
        if chars[i] == '#' {
            skip_line(&mut i);
            continue;
        }
        let rest: String = chars[i..n.min(i + 7)].iter().collect();
        if rest.starts_with("export") && rest[6..].starts_with([' ', '\t']) {
            i += 7;
        }
        let key_start = i;
        while i < n && !matches!(chars[i], '=' | ':' | '\n') {
            i += 1;
        }
        let key: String = chars[key_start..i]
            .iter()
            .collect::<String>()
            .trim()
            .to_string();
        if i >= n || chars[i] == '\n' || key.is_empty() {
            skip_line(&mut i);
            continue;
        }
        i += 1;
        while i < n && matches!(chars[i], ' ' | '\t') {
            i += 1;
        }
        let mut value = String::new();
        let mut expands = false;
        match chars.get(i) {
            Some('\'') => {
                i += 1;
                while i < n && chars[i] != '\'' {
                    value.push(chars[i]);
                    i += 1;
                }
                i += 1;
                skip_line(&mut i);
            }
            Some('"') => {
                i += 1;
                while i < n && chars[i] != '"' {
                    match (chars[i], chars.get(i + 1)) {
                        ('\\', Some(&e)) => {
                            match e {
                                'n' => value.push('\n'),
                                'r' => value.push('\r'),
                                't' => value.push('\t'),
                                '\\' | '"' | '$' => value.push(e),
                                other => {
                                    value.push('\\');
                                    value.push(other);
                                }
                            }
                            i += 2;
                            continue;
                        }
                        ('$', _) if starts_var(&chars, i) => expands = true,
                        _ => {}
                    }
                    value.push(chars[i]);
                    i += 1;
                }
                i += 1;
                skip_line(&mut i);
            }
            _ => {
                let start = i;
                skip_line(&mut i);
                let line = &chars[start..i];
                let end = (0..line.len())
                    .find(|&j| line[j] == '#' && j > 0 && line[j - 1].is_whitespace())
                    .unwrap_or(line.len());
                let line = &line[..end];
                expands = (0..line.len()).any(|j| line[j] == '$' && starts_var(line, j));
                value = line.iter().collect::<String>().trim().to_string();
            }
        }
        out.push(EnvEntry {
            key,
            value,
            expands,
        });
    }
    out
}

/// The `(key, value)` pairs an env text sets (see [`parse_env`]).
pub fn env_pairs(env: &str) -> Vec<(String, String)> {
    parse_env(env)
        .into_iter()
        .map(|e| (e.key, e.value))
        .collect()
}

/// Values shorter than this are left in output: scrubbing every `1` or
/// `yes` would garble it without hiding a secret.
const MIN_REDACTED_LEN: usize = 4;

/// The values an `.env` text sets, as [`redact`] scrubs them.
pub fn env_values(env: &str) -> Vec<String> {
    env_pairs(env).into_iter().map(|(_, v)| v).collect()
}

/// `text` with each of `values`, as written or JSON-escaped, replaced by
/// `***`. Compose interpolates `.env` values into the config it prints and
/// echoes them in its errors.
pub fn redact(text: &str, values: &[String]) -> String {
    let escaped: Vec<String> = values
        .iter()
        .filter_map(|v| {
            let quoted = plugin_toolkit::serde_json::to_string(v).ok()?;
            let inner = &quoted[1..quoted.len() - 1];
            (inner != v).then(|| inner.to_string())
        })
        .collect();
    let mut values: Vec<&str> = values
        .iter()
        .chain(&escaped)
        .map(String::as_str)
        .filter(|v| v.chars().count() >= MIN_REDACTED_LEN)
        .collect();
    // Longest first, so a value inside another does not leave the rest of
    // the longer one showing.
    values.sort_by_key(|v| std::cmp::Reverse(v.len()));
    values.dedup();
    values.iter().fold(text.to_string(), |out, v| {
        out.replace(v, plugin_toolkit::scrub::REDACTED)
    })
}

/// `compose config` of `compose` (its files, env files and project name) as
/// the project in `dir`, with every profile enabled: the one way every verb
/// reads a stack. Env files are left unread, so the policy sees their paths
/// rather than their contents.
pub fn config_args(dir: &Path, compose: &Compose) -> Result<Vec<String>> {
    if let Some(own) = compose.project_dir()
        && anchored(own) != anchored(dir)
    {
        anyhow::bail!(
            "compose project dir {} is not {}",
            own.display(),
            dir.display()
        );
    }
    let mut args: Vec<String> = vec!["compose".into()];
    args.extend(compose.clone().with_project_dir(dir.to_path_buf()).args());
    args.extend(
        [
            "--profile",
            "*",
            "config",
            "--no-env-resolution",
            "--format",
            "json",
        ]
        .map(String::from),
    );
    Ok(args)
}

/// The resolved config of `compose` run as the project in `dir`. Also the
/// validation: compose rejects files it cannot run.
pub async fn resolved_config(dir: &Path, compose: &Compose) -> Result<String> {
    let args = config_args(dir, compose)?;
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    crate::run(&argv)
        .await
        .context("compose rejects the stack's config")
}

/// `(root, dir relative to it)` for `dir` resolved, symlinks included, when it
/// lies strictly inside one of `roots`.
fn locate(dir: &str, roots: &[String]) -> Result<(PathBuf, PathBuf)> {
    let resolved = crate::lifecycle::resolve(Path::new(dir))?;
    for root in roots
        .iter()
        .filter_map(|r| crate::lifecycle::resolve(Path::new(r)).ok())
    {
        if let Ok(rel) = resolved.strip_prefix(&root)
            && rel.components().next().is_some()
        {
            return Ok((root.clone(), rel.to_path_buf()));
        }
    }
    anyhow::bail!(
        "stack dir '{dir}' resolves to '{}', outside the stacks roots ({}); set stacksRoot with docker.update or move the stack",
        resolved.display(),
        roots.join(", ")
    )
}

/// `dir` resolved, symlinks included, and refused unless it lies strictly
/// inside one of `roots`.
pub fn stack_dir_in_roots(dir: &str, roots: &[String]) -> Result<PathBuf> {
    let (root, rel) = locate(dir, roots)?;
    Ok(root.join(rel))
}

/// A compose filename: one plain path component.
pub fn check_file_name(file: &str) -> Result<()> {
    if !fsat::is_single_component(file) {
        anyhow::bail!("compose file '{file}' must be a plain file name inside the stack dir");
    }
    Ok(())
}

fn file_in_roots(dir: &StackDir, name: &str, roots: &[String]) -> Result<(StackDir, String)> {
    let path = dir.path().join(name);
    match dir.stat(name)? {
        Some(st) if st.kind == fsat::Kind::File => Ok((
            StackDir {
                fd: dir.fd.try_clone()?,
                path: dir.path.clone(),
            },
            name.to_string(),
        )),
        Some(st) if st.kind == fsat::Kind::Symlink && regular_file_in_roots(&path, roots) => {
            let real = path.canonicalize()?;
            let (Some(parent), Some(file)) = (real.parent(), real.file_name()) else {
                anyhow::bail!("{} is not a file", real.display());
            };
            Ok((
                StackDir {
                    fd: fsat::open_dir(parent)?,
                    path: parent.to_path_buf(),
                },
                file.to_string_lossy().into_owned(),
            ))
        }
        _ => anyhow::bail!(
            "'{name}' in {} is not a regular file inside the stacks roots",
            dir.path().display()
        ),
    }
}

/// An open stack dir. Opened by walking each component below its stacks root
/// with `O_NOFOLLOW`, so no symlink is crossed on the way; every read and
/// write below goes through the descriptor.
pub struct StackDir {
    fd: std::fs::File,
    path: PathBuf,
}

impl StackDir {
    /// Open `dir` under one of `roots`. With `create`, missing components are
    /// made (0755); without, a missing dir is `None`.
    pub fn open(dir: &str, roots: &[String], create: bool) -> Result<Option<Self>> {
        let (root, rel) = locate(dir, roots)?;
        let names: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        walk(dir, &root, &names, create)
    }

    /// The parent of `dir` (itself a stacks root, or a dir under one) and
    /// `dir`'s own name in it.
    pub fn open_parent(dir: &str, roots: &[String]) -> Result<(Self, String)> {
        let (root, rel) = locate(dir, roots)?;
        let mut names: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let base = names.pop().unwrap_or_default();
        let parent = walk(dir, &root, &names, false)?
            .ok_or_else(|| anyhow::anyhow!("the parent of stack dir {dir} does not exist"))?;
        Ok((parent, base))
    }

    /// `name` in this dir, opened as a dir without following a symlink.
    pub fn child(&self, name: &str) -> Result<Self> {
        let fd = fsat::open_dir_at(&self.fd, name)
            .with_context(|| format!("opening '{name}' in {}", self.path.display()))?;
        Ok(StackDir {
            fd,
            path: self.path.join(name),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn fd(&self) -> &std::fs::File {
        &self.fd
    }

    pub fn stat(&self, name: &str) -> Result<Option<fsat::Stat>> {
        Ok(fsat::stat_at(&self.fd, name)?)
    }

    /// The dir at `rel` below this one (this one for an empty `rel`), crossing
    /// no symlink. `None` when it does not exist.
    pub fn open_rel(&self, rel: &Path) -> Result<Option<StackDir>> {
        let mut dir = StackDir {
            fd: self.fd.try_clone()?,
            path: self.path.clone(),
        };
        for c in rel.components() {
            let name = c.as_os_str().to_string_lossy().into_owned();
            dir = match fsat::open_dir_at(&dir.fd, &name) {
                Ok(fd) => StackDir {
                    fd,
                    path: dir.path.join(&name),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => {
                    return Err(anyhow::anyhow!(e).context(format!(
                        "opening '{name}' in {} (a symlink or not a directory)",
                        dir.path.display()
                    )));
                }
            };
        }
        Ok(Some(dir))
    }

    /// Read the file at `rel` below this dir, crossing no symlink. `None`
    /// when it does not exist.
    pub fn read_rel(&self, rel: &Path) -> Result<Option<String>> {
        let Some(file) = rel.file_name().map(|f| f.to_string_lossy().into_owned()) else {
            anyhow::bail!("no file named in {}", rel.display());
        };
        let Some(dir) = self.open_rel(rel.parent().unwrap_or(Path::new("")))? else {
            return Ok(None);
        };
        match dir.stat(&file)? {
            None => Ok(None),
            Some(_) => dir.read(&file).map(Some),
        }
    }

    /// Read `name`, refusing a symlink.
    pub fn read(&self, name: &str) -> Result<String> {
        use std::io::Read;
        let mut f = fsat::open_at(&self.fd, name, libc::O_RDONLY, 0)
            .with_context(|| format!("reading {name} in {}", self.path.display()))?;
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        Ok(s)
    }
}

/// Open `root`, then each of `names` below it with `O_NOFOLLOW`.
fn walk(dir: &str, root: &Path, names: &[String], create: bool) -> Result<Option<StackDir>> {
    let mut fd =
        fsat::open_dir(root).with_context(|| format!("opening stacks root {}", root.display()))?;
    for name in names {
        fd = match fsat::open_dir_at(&fd, name) {
            Ok(next) => next,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
                fsat::mkdir_at(&fd, name, 0o755)
                    .with_context(|| format!("creating {name} under {}", root.display()))?;
                fsat::open_dir_at(&fd, name)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(anyhow::anyhow!(e).context(format!(
                    "opening '{name}' in {dir} (a symlink or not a directory)"
                )));
            }
        };
    }
    Ok(Some(StackDir {
        fd,
        path: names.iter().fold(root.to_path_buf(), |p, n| p.join(n)),
    }))
}

/// A stack restore extracted into a private dir beside the stack dir and
/// not yet swapped in. Dropped without [`swap`](Self::swap), everything is
/// put back and the staging dir removed.
pub struct StagedRestore {
    parent: StackDir,
    base: String,
    staging: String,
    /// Real paths of the live and staging dirs, read from their descriptors.
    live: PathBuf,
    staged: PathBuf,
    /// Live entries carried into staging, relative to both.
    moved: Vec<PathBuf>,
    done: bool,
}

impl StagedRestore {
    /// Extract the archive open as `archive` (its entries checked from the
    /// headers: no absolute paths, no `..`, no links leading out, no devices)
    /// into a fresh 0700 dir beside `row`'s stack dir, which is opened under
    /// `roots` without following symlinks and created if missing. What the
    /// live dir holds that the archive lacks is carried over, as extracting
    /// over it would have kept it.
    pub fn stage(row: &StackRow, archive: &mut std::fs::File, roots: &[String]) -> Result<Self> {
        let live = StackDir::open(&row.dir, roots, true)?
            .ok_or_else(|| anyhow::anyhow!("stack dir {} could not be created", row.dir))?;
        let (parent, base) = StackDir::open_parent(&row.dir, roots)?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let staging = format!(".{base}.orca-restore-{}-{nanos}", std::process::id());
        fsat::mkdir_at(parent.fd(), &staging, 0o700)
            .with_context(|| format!("creating {staging} in {}", parent.path().display()))?;
        let staged = crate::engine_state::fd_path(parent.child(&staging)?.fd())?;
        let mut s = StagedRestore {
            live: crate::engine_state::fd_path(live.fd())?,
            parent,
            base,
            staging,
            staged,
            moved: Vec::new(),
            done: false,
        };
        if let Err(e) = crate::engine_state::extract_stack(archive, &s.staged) {
            return Err(s.fail(e));
        }
        let mut moved = Vec::new();
        let kept = crate::engine_state::carry_over(&s.live, &s.staged, Path::new(""), &mut moved);
        s.moved = moved;
        if let Err(e) = kept {
            return Err(s.fail(e));
        }
        Ok(s)
    }

    /// The staged dir, as it will be once swapped in.
    pub fn path(&self) -> &Path {
        &self.staged
    }

    /// The staged dir, opened from its parent without following a symlink.
    pub fn dir(&self) -> Result<StackDir> {
        self.parent.child(&self.staging)
    }

    /// The compose files in the staged dir that `row` would run, in `-f`
    /// order, without and then with [`crate::compose::ORCA_FILE`] when the
    /// archive holds one. Empty when it holds no compose file.
    pub fn compose_sets(&self, row: &StackRow, roots: &[String]) -> Result<Vec<Compose>> {
        let env = self.env_file();
        let compose = if row.files.is_empty() {
            let named = self.staged.join(&row.file);
            let Some(c) = Compose::at(&named).or_else(|| Compose::find(&self.staged)) else {
                return Ok(Vec::new());
            };
            c.map_paths(Path::to_path_buf)
        } else {
            let live = anchored(Path::new(&row.dir));
            let staged = row.compose(roots)?.map_paths(|p| {
                let a = anchored(p);
                match a.strip_prefix(&live) {
                    Ok(rest) => self.staged.join(rest),
                    Err(_) => p.to_path_buf(),
                }
            });
            if !staged.file().is_file() {
                return Ok(Vec::new());
            }
            staged
        };
        let compose = match env {
            Some(env) if compose.env_files().is_empty() => compose.with_env_file(env),
            _ => compose,
        };
        let mut sets = vec![compose.clone()];
        if self.staged.join(crate::compose::ORCA_FILE).is_file()
            && let Ok(with) = compose.with_orca(roots)
        {
            sets.push(with);
        }
        Ok(sets)
    }

    pub fn read_env(&self) -> Option<String> {
        self.parent.child(&self.staging).ok()?.read(ENV_FILE).ok()
    }

    /// The staged `.env`, if any.
    pub fn env_file(&self) -> Option<PathBuf> {
        let env = self.staged.join(ENV_FILE);
        env.is_file().then_some(env)
    }

    /// Swap the staged dir in for the live one by two renames in the parent
    /// dir's descriptor. Returns the previous dir when it could not be
    /// removed afterwards.
    pub fn swap(mut self) -> Result<Option<PathBuf>> {
        let aside = format!(".{}.orca-replaced-{}", self.base, std::process::id());
        let fd = self.parent.fd();
        if let Err(e) = fsat::rename_at(fd, &self.base, &aside) {
            let e = anyhow::anyhow!(e).context(format!("moving {} aside", self.live.display()));
            return Err(self.fail(e));
        }
        if let Err(e) = fsat::rename_at(fd, &self.staging, &self.base) {
            let mut e = anyhow::anyhow!(e)
                .context(format!("moving the restore into {}", self.live.display()));
            if let Err(back) = fsat::rename_at(fd, &aside, &self.base) {
                self.done = true;
                e = e.context(format!(
                    "and failed to put the previous dir back from {aside} (kept entries are in {}): {back}",
                    self.staging
                ));
                return Err(e);
            }
            return Err(self.fail(e));
        }
        self.done = true;
        let old = self.live.with_file_name(&aside);
        Ok(std::fs::remove_dir_all(&old).err().map(|_| old))
    }

    /// Undo the staging and return `e`, naming anything that could not be
    /// moved back.
    pub fn fail(&mut self, e: anyhow::Error) -> anyhow::Error {
        self.done = true;
        crate::engine_state::abandon(e, &self.moved, &self.staged, &self.live)
    }
}

impl Drop for StagedRestore {
    fn drop(&mut self) {
        if !self.done {
            // Best effort: `fail` names what it cannot move back.
            let _undone = self.fail(anyhow::anyhow!("restore abandoned"));
        }
    }
}

/// A file replacement staged next to its target in a [`StackDir`]. A target
/// that is a symlink is refused, never written through. The temp file has a
/// unique name, the original's mode and owner, and is fsynced;
/// [`commit`](Self::commit) keeps the original as `<name>.bak`, renames over
/// it and fsyncs the directory. Dropped without a commit, the temp file is
/// removed and the original is untouched.
pub struct StagedWrite<'a> {
    dir: &'a StackDir,
    name: String,
    temp: String,
    committed: bool,
}

fn staging_error(e: std::io::Error, temp: &str, dir: &Path) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let uid = unsafe { libc::geteuid() };
        return anyhow::anyhow!(
            "cannot write in stack dir {}: permission denied for uid {uid}; orca stages {temp} there and renames it into place, so the orca user needs write access to {} (owner or group write)",
            dir.display(),
            dir.display()
        );
    }
    anyhow::Error::new(e).context(format!("creating {temp} in {}", dir.display()))
}

impl<'a> StagedWrite<'a> {
    pub fn new(dir: &'a StackDir, name: &str, contents: &str) -> Result<Self> {
        use std::io::Write;
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let original = dir.stat(name)?;
        if let Some(st) = original
            && st.kind != fsat::Kind::File
        {
            anyhow::bail!(
                "{name} in {} is not a regular file; refusing to replace it",
                dir.path().display()
            );
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temp = format!(".{name}.orca-{}-{nanos}-{seq}.tmp", std::process::id());
        let mut f = fsat::open_at(
            dir.fd(),
            &temp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
        .map_err(|e| staging_error(e, &temp, dir.path()))?;
        let staged = StagedWrite {
            dir,
            name: name.to_string(),
            temp: temp.clone(),
            committed: false,
        };
        f.write_all(contents.as_bytes())
            .with_context(|| format!("writing {temp}"))?;
        if let Some(st) = original {
            fsat::set_mode(&f, st.mode).with_context(|| format!("setting the mode of {temp}"))?;
            fsat::set_owner(&f, st.uid, st.gid)
                .with_context(|| format!("setting the owner of {temp}"))?;
        }
        f.sync_all().with_context(|| format!("syncing {temp}"))?;
        Ok(staged)
    }

    pub fn temp_path(&self) -> PathBuf {
        self.dir.path().join(&self.temp)
    }

    /// [`replace`](Self::replace), keeping the original as `<name>.bak`. A
    /// `.bak` that is not a regular file is refused rather than written
    /// through.
    pub fn commit(self) -> Result<()> {
        use std::io::Write;
        let fd = self.dir.fd();
        if let Some(st) = self.dir.stat(&self.name)?
            && st.kind == fsat::Kind::File
        {
            let bak = format!("{}.bak", self.name);
            match self.dir.stat(&bak)? {
                Some(b) if b.kind == fsat::Kind::File => fsat::unlink_at(fd, &bak)?,
                Some(_) => anyhow::bail!(
                    "{bak} in {} is not a regular file; refusing to replace it",
                    self.dir.path().display()
                ),
                None => {}
            }
            let old = self.dir.read(&self.name)?;
            let mut f = fsat::open_at(
                fd,
                &bak,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
            .with_context(|| format!("keeping a backup at {bak}"))?;
            f.write_all(old.as_bytes())?;
            f.sync_all()?;
        }
        self.replace()
    }

    /// Rename the temp file over the target and fsync the directory.
    pub fn replace(mut self) -> Result<()> {
        fsat::rename_at(self.dir.fd(), &self.temp, &self.name)
            .with_context(|| format!("replacing {} in {}", self.name, self.dir.path().display()))?;
        self.committed = true;
        self.dir
            .fd()
            .sync_all()
            .with_context(|| format!("syncing {}", self.dir.path().display()))?;
        Ok(())
    }
}

impl Drop for StagedWrite<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // Best effort: a leftover temp file is inert.
            let _removed = fsat::unlink_at(self.dir.fd(), &self.temp);
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
    for (key, list) in [("files", &row.files), ("env_files", &row.env_files)] {
        m.insert(
            key.to_string(),
            DbValue::Text(plugin_toolkit::serde_json::to_string(list).unwrap_or_default()),
        );
    }
    if let Some(p) = &row.project {
        m.insert("project".to_string(), DbValue::Text(p.clone()));
    }
    m
}

fn list_from_row(m: &DbRow, key: &str) -> Result<Vec<String>> {
    match field_from_row::<Option<String>>(m, key)? {
        Some(raw) if !raw.is_empty() => plugin_toolkit::serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("stack row `{key}` is not a JSON list: {e}")),
        _ => Ok(Vec::new()),
    }
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
        files: list_from_row(m, "files")?,
        env_files: list_from_row(m, "env_files")?,
        project: field_from_row::<Option<String>>(m, "project")
            .ok()
            .flatten()
            .filter(|p| !p.is_empty()),
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

pub fn allowed_roots() -> Result<Vec<String>> {
    let mut roots = crate::tools::stacks_roots()?;
    for root in crate::tools::discovery_roots()? {
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    Ok(roots)
}

pub const CONFIG_FILES_LABEL: &str = "com.docker.compose.project.config_files";
pub const ENV_FILE_LABEL: &str = "com.docker.compose.project.environment_file";

/// An unregistered compose project its containers' labels describe, every
/// listed file checked to be a regular file inside the roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredProject {
    pub name: String,
    pub dir: PathBuf,
    pub files: Vec<PathBuf>,
    pub env_files: Vec<PathBuf>,
    /// Env files that fail the root or open check: compose verbs refuse the
    /// project, and prune cannot read its refs.
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Discovery {
    Ok(DiscoveredProject),
    /// The project's containers disagree on its dir or files.
    Conflict {
        name: String,
        detail: String,
        dirs: Vec<PathBuf>,
    },
    /// A label is missing, or a path it names is outside the roots, relative,
    /// has `..`, or is not a readable regular file.
    Unreadable {
        name: String,
        dir: PathBuf,
        path: PathBuf,
        cause: String,
        running: bool,
    },
}

impl From<DiscoveredProject> for StackRow {
    fn from(p: DiscoveredProject) -> Self {
        let text = |v: Vec<PathBuf>| -> Vec<String> {
            v.into_iter()
                .map(|f| f.to_string_lossy().into_owned())
                .collect()
        };
        StackRow {
            file: p
                .files
                .first()
                .and_then(|f| f.file_name())
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(default_compose_file),
            name: p.name.clone(),
            dir: p.dir.to_string_lossy().into_owned(),
            enabled: true,
            allow: Vec::new(),
            files: text(p.files),
            env_files: text(p.env_files),
            project: Some(p.name),
        }
    }
}

pub fn discovered_rows(outcomes: Vec<Discovery>) -> Vec<StackRow> {
    outcomes
        .into_iter()
        .filter_map(|o| match o {
            Discovery::Ok(p) => Some(p.into()),
            _ => None,
        })
        .collect()
}

fn label_list(value: Option<&String>) -> Vec<&str> {
    value
        .map(|v| v.split(',').filter(|p| !p.is_empty()).collect())
        .unwrap_or_default()
}

/// `path` when it is absolute, has no `..` and is a regular file inside
/// `roots`, else why not.
fn listed_file(path: &str, roots: &[String]) -> std::result::Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err("not an absolute path");
    }
    if p.components().any(|c| c == std::path::Component::ParentDir) {
        return Err("has `..`");
    }
    let in_roots = p
        .parent()
        .and_then(|d| d.canonicalize().ok())
        .is_some_and(|d| {
            roots
                .iter()
                .filter_map(|r| Path::new(r).canonicalize().ok())
                .any(|r| d.starts_with(r))
        });
    if !in_roots || !regular_file_in_roots(p, roots) {
        return Err("not a regular file inside the stacks roots");
    }
    if std::fs::File::open(p).is_err() {
        return Err("cannot be opened");
    }
    Ok(p.to_path_buf())
}

type LabelSet<'a> = (Option<&'a String>, Option<&'a String>, Option<&'a String>);

fn one_project(
    name: &str,
    (dir, files, envs): LabelSet<'_>,
    running: bool,
    registered: &[StackRow],
    roots: &[String],
) -> Option<Discovery> {
    let raw_dir = PathBuf::from(dir.map(String::as_str).unwrap_or_default());
    let unreadable = |path: &Path, cause: &str| {
        Some(Discovery::Unreadable {
            name: name.to_string(),
            dir: raw_dir.clone(),
            path: path.to_path_buf(),
            cause: cause.to_string(),
            running,
        })
    };
    if !fsat::is_single_component(name) {
        return unreadable(
            Path::new(name),
            "the project name is not a single path component",
        );
    }
    let Some(dir) = dir else {
        return unreadable(Path::new(""), "no working_dir label");
    };
    let Some(real) = canonical_in_roots(dir, roots) else {
        return unreadable(
            Path::new(dir),
            "the working dir is not a directory inside the stacks roots",
        );
    };
    if registered.iter().any(|r| normalized(&r.dir) == real) {
        return None;
    }
    let files = label_list(files);
    if files.is_empty() {
        return unreadable(&real, "no config_files label");
    }
    let mut checked = Vec::new();
    for f in &files {
        match listed_file(f, roots) {
            Ok(p) => checked.push(p),
            Err(cause) => return unreadable(Path::new(f), cause),
        }
    }
    let mut env_files = Vec::new();
    let mut problems = Vec::new();
    for f in label_list(envs) {
        if let Err(cause) = listed_file(f, roots) {
            problems.push(format!("{f}: {cause}"));
        }
        env_files.push(PathBuf::from(f));
    }
    Some(Discovery::Ok(DiscoveredProject {
        name: name.to_string(),
        dir: real,
        files: checked,
        env_files,
        problems,
    }))
}

/// The compose projects `containers` name that are not `registered`, one
/// outcome each.
pub fn from_labels(
    containers: &[bollard::models::ContainerSummary],
    registered: &[StackRow],
    roots: &[String],
) -> Vec<Discovery> {
    from_labels_claimed(containers, registered, &[], roots)
}

/// [`from_labels`], also leaving out the compose projects in `claimed`, the
/// names registered stacks run as.
pub fn from_labels_claimed(
    containers: &[bollard::models::ContainerSummary],
    registered: &[StackRow],
    claimed: &[String],
    roots: &[String],
) -> Vec<Discovery> {
    let mut groups: std::collections::BTreeMap<
        &String,
        (std::collections::BTreeSet<LabelSet<'_>>, bool),
    > = Default::default();
    for c in containers {
        let Some(labels) = c.labels.as_ref() else {
            continue;
        };
        let Some(project) = labels.get(crate::prune::COMPOSE_PROJECT_LABEL) else {
            continue;
        };
        let entry = groups.entry(project).or_default();
        entry.0.insert((
            labels.get(crate::stacks_root_drift::WORKING_DIR_LABEL),
            labels.get(CONFIG_FILES_LABEL),
            labels.get(ENV_FILE_LABEL),
        ));
        entry.1 |= c.state == Some(bollard::models::ContainerSummaryStateEnum::RUNNING);
    }
    groups
        .into_iter()
        .filter(|(name, _)| {
            !registered.iter().any(|r| &r.name == *name) && !claimed.contains(*name)
        })
        .filter_map(|(name, (sets, running))| {
            if sets.len() > 1 {
                let mut dirs: Vec<PathBuf> = sets
                    .iter()
                    .filter_map(|(dir, _, _)| canonical_in_roots(dir.as_ref()?, roots))
                    .collect();
                dirs.sort();
                dirs.dedup();
                return Some(Discovery::Conflict {
                    name: name.clone(),
                    detail: "its containers disagree on the working dir, config files or env files"
                        .to_string(),
                    dirs,
                });
            }
            let set = sets.into_iter().next()?;
            one_project(name, set, running, registered, roots)
        })
        .collect()
}

fn normalized(dir: &str) -> PathBuf {
    Path::new(dir)
        .canonicalize()
        .unwrap_or_else(|_| Path::new(dir).components().collect())
}

fn canonical_in_roots(dir: &str, roots: &[String]) -> Option<PathBuf> {
    let path = Path::new(dir);
    if !path.is_absolute()
        || path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
    {
        return None;
    }
    let real = path.canonicalize().ok().filter(|p| p.is_dir())?;
    crate::tools::validated_roots(roots)
        .iter()
        .any(|r| {
            real.strip_prefix(r)
                .is_ok_and(|rel| rel.components().next().is_some())
        })
        .then_some(real)
}

pub async fn discover(docker: &bollard::Docker) -> Result<Vec<Discovery>> {
    let filters = std::collections::HashMap::from([(
        "label",
        vec![crate::prune::COMPOSE_PROJECT_LABEL.to_string()],
    )]);
    let containers = docker
        .list_containers(Some(
            bollard::query_parameters::ListContainersOptionsBuilder::new()
                .all(true)
                .filters(&filters)
                .build(),
        ))
        .await
        .map_err(|e| anyhow::anyhow!("list compose containers: {e}"))?;
    let registered = list()?;
    let roots = allowed_roots()?;
    let claimed = claimed_projects(&registered);
    Ok(from_labels_claimed(
        &containers,
        &registered,
        &claimed,
        &roots,
    ))
}

/// The compose project each registered row runs as.
pub fn claimed_projects(rows: &[StackRow]) -> Vec<String> {
    rows.iter().map(StackRow::project_name).collect()
}

/// The compose project `row` runs as, resolved by compose from its files.
pub async fn resolve_project(row: &StackRow) -> Result<String> {
    let compose = row
        .compose(&allowed_roots()?)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    compose
        .project_name()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// [`put`] `row` with its compose project resolved; a failed resolution
/// keeps the stored one.
pub async fn store(row: &mut StackRow) -> Result<()> {
    if let Ok(p) = resolve_project(row).await {
        row.project = Some(p);
    }
    put(row)
}

/// [`insert`] `row` with its compose project resolved, as [`store`].
pub async fn store_new(row: &mut StackRow) -> Result<()> {
    if let Ok(p) = resolve_project(row).await {
        row.project = Some(p);
    }
    insert(row)
}

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    plugin_toolkit::schemars::JsonSchema,
)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "camelCase")]
pub struct Backfill {
    /// `<stack>: <old> -> <new>` for each stored project name that changes.
    pub changed: Vec<String>,
    /// `<stack>: <error>` for each stack whose project could not be resolved.
    pub errors: Vec<String>,
}

/// Re-resolve the compose project of every registered row, storing each that
/// changed unless `dry_run`. One row's failure never stops the rest.
pub async fn backfill_projects(dry_run: bool) -> Result<Backfill> {
    let mut out = Backfill::default();
    for mut row in list()? {
        match resolve_project(&row).await {
            Ok(p) if row.project.as_deref() == Some(p.as_str()) => {}
            Ok(p) => {
                out.changed.push(format!(
                    "{}: {} -> {p}",
                    row.name,
                    row.project.as_deref().unwrap_or("(unset)")
                ));
                row.project = Some(p);
                if !dry_run && let Err(e) = put(&row) {
                    out.errors.push(format!("{}: {e:#}", row.name));
                }
            }
            Err(e) => out.errors.push(format!("{}: {e:#}", row.name)),
        }
    }
    Ok(out)
}

pub async fn all(docker: Option<&bollard::Docker>) -> Result<Vec<StackRow>> {
    let mut rows = list()?;
    if let Some(docker) = docker {
        match discover(docker).await {
            Ok(found) => rows.extend(discovered_rows(found)),
            Err(e) => {
                plugin_toolkit::tracing::warn!(error = %e, "docker stacks: compose discovery failed")
            }
        }
    }
    Ok(rows)
}

pub async fn all_here() -> Result<Vec<StackRow>> {
    all(crate::registration::adapter().present_client().as_ref()).await
}

pub async fn find_here(name: &str) -> Result<StackRow> {
    find(
        name,
        crate::registration::adapter().present_client().as_ref(),
    )
    .await
}

pub const DOCKGE_STACKS_ROOT: &str = "/opt/stacks";

pub async fn units(docker: Option<&bollard::Docker>) -> Result<Vec<StackRow>> {
    let registered = list()?;
    let Some(docker) = docker else {
        return Ok(registered);
    };
    let found = match discover(docker).await {
        Ok(found) => discovered_rows(found),
        Err(e) => {
            plugin_toolkit::tracing::warn!(error = %e, "docker stacks: compose discovery failed");
            Vec::new()
        }
    };
    let yield_to_dockge = found.iter().any(under_dockge_root) && dockge_is_local();
    let mut rows = registered;
    rows.extend(
        found
            .into_iter()
            .filter(|r| !(yield_to_dockge && under_dockge_root(r))),
    );
    Ok(rows)
}

fn under_dockge_root(row: &StackRow) -> bool {
    !Path::new(&row.dir)
        .components()
        .any(|c| c == std::path::Component::ParentDir)
        && normalized(&row.dir).parent() == Some(normalized(DOCKGE_STACKS_ROOT).as_path())
}

fn dockge_is_local() -> bool {
    if !plugin_toolkit::tool_call::available() {
        return false;
    }
    match plugin_toolkit::tool_call::call_json("dockge.list", plugin_toolkit::serde_json::json!({}))
    {
        Ok(v) => lists_local_dockge(&v, plugin_toolkit::containers::local_hostname()),
        Err(_) => false,
    }
}

pub fn lists_local_dockge(listed: &plugin_toolkit::serde_json::Value, hostname: &str) -> bool {
    listed
        .get("endpoints")
        .and_then(|e| e.as_array())
        .is_some_and(|eps| {
            eps.iter().any(|e| {
                e.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true)
                    && e.get("base_url")
                        .or_else(|| e.get("baseUrl"))
                        .and_then(|v| v.as_str())
                        .is_some_and(|u| is_local_url(u, hostname))
            })
        })
}

fn is_local_url(url: &str, hostname: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    };
    host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case(hostname)
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub async fn find(name: &str, docker: Option<&bollard::Docker>) -> Result<StackRow> {
    if let Some(row) = get(name)? {
        return Ok(row);
    }
    if let Some(docker) = docker
        && let Some(row) = discovered(docker, name).await
    {
        return Ok(row);
    }
    Err(anyhow::anyhow!("no managed stack named '{name}'"))
}

async fn discovered(docker: &bollard::Docker, name: &str) -> Option<StackRow> {
    match discover(docker).await {
        Ok(found) => discovered_rows(found).into_iter().find(|r| r.name == name),
        Err(e) => {
            plugin_toolkit::tracing::warn!(error = %e, "docker stacks: compose discovery failed");
            None
        }
    }
}

/// `row` with `source`'s listed files and env files when both name the same
/// dir, so no write drops a discovered project's files.
pub fn carry_listed(row: &mut StackRow, source: Option<&StackRow>, roots: &[String]) {
    let dir = anchored(Path::new(&row.dir));
    let in_roots = roots
        .iter()
        .map(|r| anchored(Path::new(r)))
        .any(|r| dir.starts_with(&r) && dir != r);
    if let Some(s) = source
        && in_roots
        && anchored(Path::new(&s.dir)) == dir
    {
        row.files = s.files.clone();
        row.env_files = s.env_files.clone();
    }
}

/// The row a deploy or normalize payload names, keeping `source`'s listed
/// files.
pub fn payload_row(
    name: &str,
    dir: &Path,
    file: String,
    allow: Vec<policy::Grant>,
    source: Option<&StackRow>,
    roots: &[String],
) -> StackRow {
    let mut row = StackRow {
        name: name.to_string(),
        dir: dir.to_string_lossy().into_owned(),
        file,
        enabled: true,
        allow,
        files: Vec::new(),
        env_files: Vec::new(),
        project: None,
    };
    carry_listed(&mut row, source, roots);
    row
}

/// `path` with its parent [`anchored`] and its last component kept as is, so a
/// symlink is compared by where it sits, not where it points.
fn entry(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => anchored(parent).join(name),
        _ => anchored(path),
    }
}

/// `path` with its nearest existing ancestor canonicalized, so a dir not yet
/// created compares equal through a symlinked root. `..` is kept lexically.
fn anchored(path: &Path) -> PathBuf {
    let lexical: PathBuf = path.components().collect();
    let mut base = lexical.as_path();
    let mut rest = Vec::new();
    loop {
        if let Ok(real) = base.canonicalize() {
            return rest.iter().rev().fold(real, |p, c| p.join(c));
        }
        match (base.parent(), base.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                base = parent;
            }
            _ => return lexical,
        }
    }
}

/// The registered row named `name`, else the discovered project.
pub async fn listed_source(name: &str) -> Option<StackRow> {
    match get(name) {
        Ok(Some(row)) => Some(row),
        _ => discovered_here(name).await,
    }
}

/// The discovered project named `name` on the local engine, if any.
pub async fn discovered_here(name: &str) -> Option<StackRow> {
    let docker = crate::registration::adapter().present_client()?;
    discovered(&docker, name).await
}

/// What [`require_registered`] does with a discovered, unregistered project.
/// Only `docker.stack_adopt` registers one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adoption {
    Refuse,
    /// Return the discovered row unregistered, for a dry run.
    Preview,
}

impl Adoption {
    pub fn for_call(dry_run: bool) -> Self {
        if dry_run {
            Adoption::Preview
        } else {
            Adoption::Refuse
        }
    }
}

/// The registered stack `name`, or the discovered project of that name as
/// `adoption` says.
pub async fn require_registered(
    name: &str,
    docker: Option<&bollard::Docker>,
    adoption: Adoption,
) -> Result<StackRow> {
    if let Some(row) = get(name)? {
        return Ok(row);
    }
    if let Some(docker) = docker
        && let Some(row) = discovered(docker, name).await
    {
        return match adoption {
            Adoption::Refuse => Err(anyhow::anyhow!(
                "stack '{name}' is a discovered compose project, not a registered one; adopt it with docker.stack_adopt first"
            )),
            Adoption::Preview => Ok(row),
        };
    }
    Err(anyhow::anyhow!("no managed stack named '{name}'"))
}

/// Fails when `name` is not registered but a discovered compose project
/// carries it: a deploy would take that project over without adoption.
pub async fn require_not_discovered(name: &str, docker: Option<&bollard::Docker>) -> Result<()> {
    if get(name)?.is_none()
        && let Some(docker) = docker
        && discovered(docker, name).await.is_some()
    {
        anyhow::bail!(
            "stack '{name}' is a discovered compose project, not a registered one; adopt it with docker.stack_adopt before deploying over it"
        );
    }
    Ok(())
}

pub async fn require_registered_here(name: &str, adoption: Adoption) -> Result<StackRow> {
    require_registered(
        name,
        crate::registration::adapter().present_client().as_ref(),
        adoption,
    )
    .await
}

/// Whether `path` is a regular file, or a symlink resolving to one inside
/// one of `roots`.
pub fn regular_file_in_roots(path: &Path, roots: &[String]) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if meta.is_file() {
        return true;
    }
    if !meta.file_type().is_symlink() {
        return false;
    }
    let Ok(real) = path.canonicalize() else {
        return false;
    };
    real.is_file()
        && roots
            .iter()
            .filter_map(|r| Path::new(r).canonicalize().ok())
            .any(|r| real.starts_with(r))
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

/// Register a stack, failing when the name is already registered.
pub fn insert(row: &StackRow) -> Result<()> {
    db_op(&DbOp::Insert {
        namespace: "docker".to_string(),
        table: TABLE.to_string(),
        row: to_dbrow(row),
    })?;
    Ok(())
}

/// Refuse `dir` (resolved) for stack `name` when it is, is inside or
/// contains another registered stack's dir, or nests with a bind any
/// registered stack is granted: either stack's policy would then judge the
/// other's files as its own.
pub fn check_dir_free(name: &str, dir: &Path) -> Result<()> {
    let resolve =
        |p: &str| crate::lifecycle::resolve(Path::new(p)).unwrap_or_else(|_| PathBuf::from(p));
    let nests = |p: &Path| dir.starts_with(p) || p.starts_with(dir);
    for row in list()?.into_iter().filter(|r| r.name != name) {
        let other = resolve(&row.dir);
        if nests(&other) {
            anyhow::bail!(
                "stack dir {} overlaps stack '{}' at {}",
                dir.display(),
                row.name,
                other.display()
            );
        }
        for bind in row
            .allow
            .iter()
            .filter_map(|g| g.allow.strip_prefix(policy::ALLOW_BIND))
        {
            let bind = resolve(bind);
            if nests(&bind) {
                anyhow::bail!(
                    "stack dir {} overlaps {}, a bind granted to stack '{}'",
                    dir.display(),
                    bind.display(),
                    row.name
                );
            }
        }
    }
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
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    fn s(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn insert_fails_on_a_registered_name_and_keeps_the_row() {
        crate::test_support::with_db(|| {
            let row = |dir: &str| StackRow {
                name: "web".into(),
                dir: dir.into(),
                file: DEFAULT_COMPOSE_FILE.into(),
                enabled: true,
                allow: Vec::new(),
                files: Vec::new(),
                env_files: Vec::new(),
                project: None,
            };
            insert(&row("/opt/stacks/web")).unwrap();
            assert!(insert(&row("/opt/stacks/elsewhere")).is_err());
            assert_eq!(require("web").unwrap().dir, "/opt/stacks/web");
        });
    }

    #[test]
    fn a_multi_file_project_is_discovered_with_every_file_and_env_file() {
        let r = Roots::new(&["web"]);
        std::fs::write(PathBuf::from(r.path("web/extra.yaml")), "services: {}\n").unwrap();
        std::fs::write(PathBuf::from(r.path("web/.env")), "A=1\n").unwrap();
        std::fs::write(PathBuf::from(r.path("web/more.env")), "B=2\n").unwrap();
        let files = format!(
            "{},{}",
            r.path("web/compose.yaml"),
            r.path("web/extra.yaml")
        );
        let envs = format!("{},{}", r.path("web/.env"), r.path("web/more.env"));
        let containers: Vec<bollard::models::ContainerSummary> =
            plugin_toolkit::serde_json::from_value(plugin_toolkit::serde_json::json!([{
                "Id": "c1",
                "State": "running",
                "Labels": {
                    "com.docker.compose.project": "web",
                    "com.docker.compose.project.working_dir": r.path("web"),
                    "com.docker.compose.project.config_files": files,
                    "com.docker.compose.project.environment_file": envs,
                }
            }]))
            .unwrap();
        let rows = discovered_rows(from_labels(&containers, &[], &r.roots));
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].files,
            vec![r.path("web/compose.yaml"), r.path("web/extra.yaml")]
        );
        assert_eq!(
            rows[0].env_files,
            vec![r.path("web/.env"), r.path("web/more.env")]
        );
        let compose = rows[0].compose(&r.roots).unwrap();
        let args = compose.args();
        let has = |pair: [&str; 2]| args.windows(2).any(|w| w == pair);
        assert!(has(["-p", "web"]), "{args:?}");
        assert!(has(["-f", &r.path("web/extra.yaml")]), "{args:?}");
        assert!(has(["--env-file", &r.path("web/more.env")]), "{args:?}");
        assert_eq!(
            args.iter().filter(|a| *a == "-f").count(),
            2,
            "no auto-loaded override beyond the listed files: {args:?}"
        );
    }

    #[test]
    fn disagreeing_labels_and_unreadable_files_are_typed_outcomes() {
        let r = Roots::new(&["a", "b", "c"]);
        let containers = summaries(&[
            ("dup", &r.path("a"), &r.path("a/compose.yaml")),
            ("dup", &r.path("b"), &r.path("b/compose.yaml")),
            ("gone", &r.path("c"), &r.path("c/missing.yaml")),
        ]);
        let outcomes = from_labels(&containers, &[], &r.roots);
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, Discovery::Conflict { name, .. } if name == "dup")),
            "{outcomes:?}"
        );
        assert!(
            outcomes.iter().any(|o| matches!(
                o,
                Discovery::Unreadable { name, path, .. }
                    if name == "gone" && path.ends_with("c/missing.yaml")
            )),
            "{outcomes:?}"
        );
    }

    #[test]
    fn a_listed_file_outside_the_roots_or_with_dot_dot_is_unreadable() {
        let r = Roots::new(&["web"]);
        for extra in [
            "/etc/passwd".to_string(),
            r.path("web/../web/compose.yaml"),
            "rel.yaml".to_string(),
        ] {
            let files = format!("{},{extra}", r.path("web/compose.yaml"));
            let containers = summaries(&[("web", &r.path("web"), &files)]);
            let outcomes = from_labels(&containers, &[], &r.roots);
            assert!(
                matches!(&outcomes[..], [Discovery::Unreadable { .. }]),
                "{extra}: {outcomes:?}"
            );
        }
    }

    fn labelled_only(project: &str, labels: plugin_toolkit::serde_json::Value) -> Vec<Discovery> {
        let mut labels = labels;
        labels["com.docker.compose.project"] = project.into();
        let containers: Vec<bollard::models::ContainerSummary> =
            plugin_toolkit::serde_json::from_value(
                plugin_toolkit::serde_json::json!([{"Id": "c1", "Labels": labels}]),
            )
            .unwrap();
        let r = Roots::new(&[]);
        from_labels(&containers, &[], &r.roots)
    }

    #[test]
    fn a_project_without_a_working_dir_is_unreadable() {
        let outcomes = labelled_only(
            "web",
            plugin_toolkit::serde_json::json!({"com.docker.compose.project.config_files": "/x/compose.yaml"}),
        );
        assert!(
            matches!(&outcomes[..], [Discovery::Unreadable { cause, .. }] if cause == "no working_dir label"),
            "{outcomes:?}"
        );
    }

    #[test]
    fn a_project_without_config_files_is_unreadable() {
        let r = Roots::new(&["web"]);
        let containers: Vec<bollard::models::ContainerSummary> =
            plugin_toolkit::serde_json::from_value(plugin_toolkit::serde_json::json!([{
                "Id": "c1",
                "Labels": {
                    "com.docker.compose.project": "web",
                    "com.docker.compose.project.working_dir": r.path("web"),
                }
            }]))
            .unwrap();
        let outcomes = from_labels(&containers, &[], &r.roots);
        assert!(
            matches!(&outcomes[..], [Discovery::Unreadable { cause, .. }] if cause == "no config_files label"),
            "{outcomes:?}"
        );
    }

    #[test]
    fn mismatched_labels_on_one_projects_containers_are_a_conflict() {
        let r = Roots::new(&["web"]);
        std::fs::write(PathBuf::from(r.path("web/other.yaml")), "services: {}\n").unwrap();
        let containers = summaries(&[
            ("web", &r.path("web"), &r.path("web/compose.yaml")),
            ("web", &r.path("web"), &r.path("web/other.yaml")),
        ]);
        let outcomes = from_labels(&containers, &[], &r.roots);
        assert!(
            matches!(&outcomes[..], [Discovery::Conflict { name, .. }] if name == "web"),
            "{outcomes:?}"
        );
    }

    #[test]
    fn a_discovered_project_in_a_registered_dir_yields_no_outcome() {
        let r = Roots::new(&["web"]);
        let containers = summaries(&[("other", &r.path("web"), &r.path("web/compose.yaml"))]);
        let registered = [StackRow {
            name: "web".into(),
            dir: r.path("web"),
            file: DEFAULT_COMPOSE_FILE.into(),
            enabled: true,
            allow: Vec::new(),
            files: Vec::new(),
            env_files: Vec::new(),
            project: None,
        }];
        assert!(from_labels(&containers, &registered, &r.roots).is_empty());
    }

    fn with_env(r: &Roots, env: &str) -> Vec<Discovery> {
        let containers: Vec<bollard::models::ContainerSummary> =
            plugin_toolkit::serde_json::from_value(plugin_toolkit::serde_json::json!([{
                "Id": "c1",
                "State": "running",
                "Labels": {
                    "com.docker.compose.project": "web",
                    "com.docker.compose.project.working_dir": r.path("web"),
                    "com.docker.compose.project.config_files": r.path("web/compose.yaml"),
                    "com.docker.compose.project.environment_file": env,
                }
            }]))
            .unwrap();
        from_labels(&containers, &[], &r.roots)
    }

    #[test]
    fn an_env_file_outside_the_roots_keeps_the_project_and_refuses_compose() {
        let r = Roots::new(&["web"]);
        let outside = tempdir().unwrap();
        let env = outside.path().join(".env");
        std::fs::write(&env, "A=1\n").unwrap();
        let outcomes = with_env(&r, &env.to_string_lossy());
        let [Discovery::Ok(p)] = &outcomes[..] else {
            panic!("{outcomes:?}");
        };
        assert_eq!(p.env_files, vec![env.clone()]);
        assert_eq!(p.problems.len(), 1, "{p:?}");
        assert!(p.problems[0].contains(".env"), "{p:?}");
        let row: StackRow = p.clone().into();
        let err = row.compose(&r.roots).unwrap_err().to_string();
        assert!(err.contains(".env"), "{err}");
    }

    #[test]
    fn an_unreadable_env_file_keeps_the_project_with_a_problem() {
        use std::os::unix::fs::PermissionsExt;
        let r = Roots::new(&["web"]);
        let env = PathBuf::from(r.path("web/.env"));
        std::fs::write(&env, "A=1\n").unwrap();
        std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&env).is_ok() {
            return;
        }
        let outcomes = with_env(&r, &r.path("web/.env"));
        let [Discovery::Ok(p)] = &outcomes[..] else {
            panic!("{outcomes:?}");
        };
        assert!(p.problems[0].contains("cannot be opened"), "{p:?}");
    }

    #[test]
    fn the_deploy_gate_reads_a_discovered_row_like_every_verb() {
        let r = Roots::new(&["web"]);
        std::fs::write(PathBuf::from(r.path("web/extra.yaml")), "services: {}\n").unwrap();
        std::fs::write(PathBuf::from(r.path("web/.env")), "A=1\n").unwrap();
        let row = StackRow {
            name: "web".into(),
            dir: r.path("web"),
            file: "compose.yaml".into(),
            enabled: true,
            allow: Vec::new(),
            files: vec![r.path("web/compose.yaml"), r.path("web/extra.yaml")],
            env_files: vec![r.path("web/.env")],
            project: None,
        };
        let compose = row.compose(&r.roots).unwrap();
        let args = config_args(Path::new(&row.dir), &compose).unwrap();
        let has = |pair: [&str; 2]| args.windows(2).any(|w| w == pair);
        assert!(has(["--project-directory", &r.path("web")]), "{args:?}");
        assert!(has(["-p", "web"]), "{args:?}");
        assert!(has(["-f", &r.path("web/extra.yaml")]), "{args:?}");
        assert!(has(["--env-file", &r.path("web/.env")]), "{args:?}");
        assert!(has(["--profile", "*"]), "{args:?}");
        assert_eq!(&args[..1], ["compose"]);
    }

    fn listed_web(r: &Roots, files: &[&str]) -> StackRow {
        StackRow {
            name: "web".into(),
            dir: r.path("web"),
            file: "compose.yaml".into(),
            enabled: true,
            allow: Vec::new(),
            files: files.iter().map(|f| r.path(f)).collect(),
            env_files: Vec::new(),
            project: None,
        }
    }

    #[test]
    fn a_staged_write_over_a_symlinked_compose_file_of_a_listed_stack_is_refused() {
        let r = Roots::new(&["web"]);
        let dir = PathBuf::from(r.path("web"));
        std::fs::rename(dir.join("compose.yaml"), dir.join("real.yaml")).unwrap();
        symlink(dir.join("real.yaml"), dir.join("compose.yaml")).unwrap();
        let row = listed_web(&r, &["web/real.yaml"]);
        let err = plugin_toolkit::reactor::block_on(row.write_checked(
            Some("services: {}\n"),
            None,
            &r.roots,
            None,
        ))
        .unwrap_err();
        assert!(format!("{err:#}").contains("not a regular file"), "{err:#}");
        assert!(
            std::fs::symlink_metadata(dir.join("compose.yaml"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn the_unlisted_check_runs_what_compose_runs_including_the_orca_file() {
        let r = Roots::new(&["web"]);
        let dir = PathBuf::from(r.path("web"));
        std::fs::write(dir.join(crate::compose::ORCA_FILE), "services: {}\n").unwrap();
        let row = listed_web(&r, &[]);
        let staged = dir.join(".compose.yaml.staged");
        std::fs::write(&staged, "services: {}\n").unwrap();
        let checked = row
            .checked_compose(&dir, "compose.yaml", &staged, None, &r.roots)
            .unwrap();
        assert_eq!(
            checked.files(),
            vec![
                staged.as_path(),
                dir.join(crate::compose::ORCA_FILE).as_path()
            ]
        );
    }

    #[test]
    fn a_listed_stack_runs_and_is_checked_from_its_own_project_dir() {
        let r = Roots::new(&["web", "shared"]);
        let row = listed_web(&r, &["shared/compose.yaml", "web/compose.yaml"]);
        let compose = row.compose(&r.roots).unwrap();
        let args = compose.args();
        assert!(
            args.windows(2)
                .any(|w| w == ["--project-directory", &r.path("web")]),
            "{args:?}"
        );
        let checked = config_args(Path::new(&r.path("web")), &compose).unwrap();
        assert!(config_args(Path::new(&r.path("shared")), &compose).is_err());
        assert_eq!(
            checked
                .iter()
                .filter(|a| *a == "--project-directory")
                .count(),
            1,
            "{checked:?}"
        );
    }

    #[test]
    fn corrupt_listed_files_are_an_error() {
        let mut m = DbRow::new();
        m.insert("files".into(), DbValue::Text("not json".into()));
        assert!(list_from_row(&m, "files").is_err());
        m.insert("files".into(), DbValue::Text(r#"["/a"]"#.into()));
        assert_eq!(list_from_row(&m, "files").unwrap(), vec!["/a"]);
        assert!(list_from_row(&DbRow::new(), "files").unwrap().is_empty());
    }

    #[test]
    fn carrying_compares_through_symlinks_for_missing_dirs_and_checks_the_roots() {
        let r = Roots::new(&["web"]);
        let alias = tempdir().unwrap();
        let link = alias.path().join("stacks");
        symlink(&r.roots[0], &link).unwrap();
        let source = StackRow {
            name: "new".into(),
            dir: r.path("new"),
            file: "compose.yaml".into(),
            enabled: true,
            allow: Vec::new(),
            files: vec![r.path("new/compose.yaml")],
            env_files: Vec::new(),
            project: None,
        };
        let mut row = StackRow {
            dir: link.join("new").to_string_lossy().into_owned(),
            files: Vec::new(),
            ..source.clone()
        };
        carry_listed(&mut row, Some(&source), &r.roots);
        assert_eq!(row.files, source.files);
        let outside = StackRow {
            dir: "/etc".into(),
            ..source.clone()
        };
        let mut at_etc = StackRow {
            dir: "/etc".into(),
            files: Vec::new(),
            ..source.clone()
        };
        carry_listed(&mut at_etc, Some(&outside), &r.roots);
        assert!(at_etc.files.is_empty());
    }

    #[test]
    fn normalizing_a_discovered_multi_file_stack_keeps_its_files() {
        let r = Roots::new(&["web"]);
        std::fs::write(PathBuf::from(r.path("web/extra.yaml")), "services: {}\n").unwrap();
        let discovered = StackRow {
            name: "web".into(),
            dir: r.path("web"),
            file: "compose.yaml".into(),
            enabled: true,
            allow: Vec::new(),
            files: vec![r.path("web/compose.yaml"), r.path("web/extra.yaml")],
            env_files: Vec::new(),
            project: None,
        };
        let dir = PathBuf::from(format!("{}/./web", r.roots[0]));
        let row = payload_row(
            "web",
            &dir,
            "compose.yaml".into(),
            Vec::new(),
            Some(&discovered),
            &r.roots,
        );
        assert_eq!(row.files, discovered.files);
        let compose = row.compose(&r.roots).unwrap();
        assert_eq!(compose.files().len(), 2);
        let other = StackRow {
            dir: "/opt/stacks/other".into(),
            ..discovered.clone()
        };
        let row = payload_row(
            "web",
            &dir,
            "compose.yaml".into(),
            Vec::new(),
            Some(&other),
            &r.roots,
        );
        assert!(row.files.is_empty());
    }

    #[test]
    fn listed_files_survive_the_db_round_trip() {
        crate::test_support::with_db(|| {
            let row = StackRow {
                name: "web".into(),
                dir: "/opt/stacks/web".into(),
                file: "compose.yaml".into(),
                enabled: true,
                allow: Vec::new(),
                files: vec![
                    "/opt/stacks/web/compose.yaml".into(),
                    "/opt/stacks/web/x.yaml".into(),
                ],
                env_files: vec!["/opt/stacks/web/.env".into()],
                project: None,
            };
            put(&row).unwrap();
            let back = require("web").unwrap();
            assert_eq!(back.files, row.files);
            assert_eq!(back.env_files, row.env_files);
        });
    }

    #[test]
    fn a_registered_stack_is_read_with_the_project_name_deploy_resolves() {
        let r = Roots::new(&["web"]);
        let row = StackRow {
            name: "registered-name".into(),
            dir: r.path("web"),
            file: DEFAULT_COMPOSE_FILE.into(),
            enabled: true,
            allow: Vec::new(),
            files: Vec::new(),
            env_files: Vec::new(),
            project: None,
        };
        let args = row.compose(&r.roots).unwrap().args();
        assert!(
            !args.iter().any(|a| a == "-p" || a == "--env-file"),
            "{args:?}"
        );
        assert_eq!(args, vec!["-f".to_string(), r.path("web/compose.yaml")]);
    }

    fn compose_container(project: &str, dir: &str, files: &str) -> String {
        format!(
            r#"{{"Id":"{project}","Labels":{{"com.docker.compose.project":"{project}","com.docker.compose.project.working_dir":"{dir}","com.docker.compose.project.config_files":"{files}"}}}}"#
        )
    }

    fn summaries(entries: &[(&str, &str, &str)]) -> Vec<bollard::models::ContainerSummary> {
        let body = entries
            .iter()
            .map(|(p, d, f)| compose_container(p, d, f))
            .collect::<Vec<_>>()
            .join(",");
        plugin_toolkit::serde_json::from_str(&format!("[{body}]")).unwrap()
    }

    struct Roots {
        _root: tempfile::TempDir,
        roots: Vec<String>,
    }

    impl Roots {
        fn new(stacks: &[&str]) -> Self {
            let root = tempdir().unwrap();
            let roots = vec![s(&root.path().canonicalize().unwrap())];
            for name in stacks {
                let dir = PathBuf::from(&roots[0]).join(name);
                std::fs::create_dir(&dir).unwrap();
                std::fs::write(dir.join("compose.yaml"), "services: {}\n").unwrap();
            }
            Roots { _root: root, roots }
        }

        fn path(&self, rel: &str) -> String {
            format!("{}/{rel}", self.roots[0])
        }
    }

    #[test]
    fn compose_projects_are_discovered_from_container_labels() {
        let r = Roots::new(&["komga", "ntfy", "web"]);
        let containers = summaries(&[
            ("komga", &r.path("komga"), &r.path("komga/compose.yaml")),
            ("komga", &r.path("komga"), &r.path("komga/compose.yaml")),
            ("ntfy", &r.path("ntfy"), &r.path("ntfy/compose.yaml")),
            ("web", &r.path("web"), &r.path("web/compose.yaml")),
        ]);
        let registered = [StackRow {
            name: "web".into(),
            dir: r.path("web"),
            file: DEFAULT_COMPOSE_FILE.into(),
            enabled: true,
            allow: Vec::new(),
            files: Vec::new(),
            env_files: Vec::new(),
            project: None,
        }];
        let rows = discovered_rows(from_labels(&containers, &registered, &r.roots));
        let got: Vec<(String, String, String)> = rows
            .into_iter()
            .map(|row| (row.name, row.dir, row.file))
            .collect();
        assert_eq!(
            got,
            [
                ("komga".into(), r.path("komga"), "compose.yaml".into()),
                ("ntfy".into(), r.path("ntfy"), "compose.yaml".into()),
            ]
        );
    }

    #[test]
    fn labels_pointing_outside_the_roots_discover_and_read_nothing() {
        let r = Roots::new(&["web"]);
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join("compose.yaml"), "services: {}\n").unwrap();
        std::fs::write(outside.path().join(".env"), "TOKEN=abcd\n").unwrap();
        symlink(outside.path(), PathBuf::from(&r.roots[0]).join("escape")).unwrap();
        let ssh = format!("{}/.ssh", std::env::var("HOME").unwrap());
        let cases = [
            ("/etc".to_string(), "/etc/passwd".to_string()),
            (
                "/opt/stacks/../../etc".to_string(),
                "/opt/stacks/../../etc/passwd".to_string(),
            ),
            (r.path("web/../../../etc"), "/etc/passwd".to_string()),
            (r.path("escape"), r.path("escape/compose.yaml")),
            (ssh.clone(), format!("{ssh}/config")),
        ];
        for (dir, file) in &cases {
            let containers = summaries(&[("evil", dir, file)]);
            assert!(
                discovered_rows(from_labels(&containers, &[], &r.roots)).is_empty(),
                "{dir}"
            );
            let row = StackRow {
                name: "evil".into(),
                dir: dir.clone(),
                file: Path::new(file)
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                enabled: true,
                allow: Vec::new(),
                files: Vec::new(),
                env_files: Vec::new(),
                project: None,
            };
            assert!(row.read_compose(&r.roots).is_err(), "{dir}");
            assert!(row.compose_path(&r.roots).is_err(), "{dir}");
            assert!(row.compose(&r.roots).is_err(), "{dir}");
            assert!(row.read_env(&r.roots).is_none(), "{dir}");
            assert_eq!(row.redact("TOKEN=abcd", &r.roots), "TOKEN=abcd", "{dir}");
        }
    }

    #[test]
    fn discovered_dirs_are_canonical_and_dot_dot_is_refused() {
        let r = Roots::new(&["web"]);
        let canonical = r.path("web");
        for dir in [
            format!("{}/./web", r.roots[0]),
            format!("{}//web", r.roots[0]),
            format!("{}/web/", r.roots[0]),
        ] {
            let containers = summaries(&[("web", &dir, &format!("{dir}/compose.yaml"))]);
            let rows = discovered_rows(from_labels(&containers, &[], &r.roots));
            assert_eq!(rows.len(), 1, "{dir}");
            assert_eq!(rows[0].dir, canonical, "{dir}");
        }
        let dotted = format!("{}/web/../web", r.roots[0]);
        let containers = summaries(&[("web", &dotted, &r.path("web/compose.yaml"))]);
        assert!(discovered_rows(from_labels(&containers, &[], &r.roots)).is_empty());
    }

    #[test]
    fn a_registered_dir_matches_its_discovered_project_after_normalizing() {
        let r = Roots::new(&["web"]);
        let containers = summaries(&[("other", &r.path("web"), &r.path("web/compose.yaml"))]);
        for dir in [
            format!("{}/./web", r.roots[0]),
            format!("{}//web", r.roots[0]),
            format!("{}/web/", r.roots[0]),
        ] {
            let registered = [StackRow {
                name: "web".into(),
                dir: dir.clone(),
                file: DEFAULT_COMPOSE_FILE.into(),
                enabled: true,
                allow: Vec::new(),
                files: Vec::new(),
                env_files: Vec::new(),
                project: None,
            }];
            assert!(
                discovered_rows(from_labels(&containers, &registered, &r.roots)).is_empty(),
                "{dir}"
            );
        }
    }

    #[test]
    fn a_project_name_seen_with_two_dirs_is_not_discovered() {
        let r = Roots::new(&["a", "b", "c"]);
        let containers = summaries(&[
            ("dup", &r.path("a"), &r.path("a/compose.yaml")),
            ("dup", &r.path("b"), &r.path("b/compose.yaml")),
            ("c", &r.path("c"), &r.path("c/compose.yaml")),
        ]);
        let names: Vec<String> = discovered_rows(from_labels(&containers, &[], &r.roots))
            .into_iter()
            .map(|row| row.name)
            .collect();
        assert_eq!(names, ["c"]);
        let containers = summaries(&[
            ("dup", &r.path("a"), &r.path("a/compose.yaml")),
            ("dup", "/etc", "/etc/passwd"),
        ]);
        assert!(discovered_rows(from_labels(&containers, &[], &r.roots)).is_empty());
        std::fs::write(PathBuf::from(r.path("a/other.yaml")), "services: {}\n").unwrap();
        let containers = summaries(&[
            ("dup", &r.path("a"), &r.path("a/compose.yaml")),
            ("dup", &r.path("a"), &r.path("a/other.yaml")),
        ]);
        assert!(discovered_rows(from_labels(&containers, &[], &r.roots)).is_empty());
    }

    #[test]
    fn config_files_never_fall_back_to_the_default() {
        let r = Roots::new(&["web"]);
        std::fs::write(PathBuf::from(r.path("web/override.yaml")), "services: {}\n").unwrap();
        let multi = format!(
            "{},{}",
            r.path("web/compose.yaml"),
            r.path("web/override.yaml")
        );
        let containers = summaries(&[("web", &r.path("web"), &multi)]);
        let rows = discovered_rows(from_labels(&containers, &[], &r.roots));
        assert_eq!(rows.len(), 1);
        for files in [
            "/etc/passwd",
            "/elsewhere/ntfy.yml",
            &r.path("web/missing.yaml"),
            "",
        ] {
            let containers = summaries(&[("web", &r.path("web"), files)]);
            assert!(
                discovered_rows(from_labels(&containers, &[], &r.roots)).is_empty(),
                "{files}"
            );
        }
    }

    #[test]
    fn only_a_canonical_in_root_dir_is_emitted() {
        let r = Roots::new(&["web"]);
        let outside = tempdir().unwrap();
        symlink(outside.path(), PathBuf::from(&r.roots[0]).join("escape")).unwrap();
        let at = |dir: String| StackRow {
            name: "x".into(),
            dir,
            file: DEFAULT_COMPOSE_FILE.into(),
            enabled: true,
            allow: Vec::new(),
            files: Vec::new(),
            env_files: Vec::new(),
            project: None,
        };
        let web = Some(r.path("web"));
        assert_eq!(at(r.path("web")).emitted_dir(&r.roots), web);
        assert_eq!(
            at(format!("{}/./web", r.roots[0])).emitted_dir(&r.roots),
            web
        );
        assert_eq!(
            at(format!("{}//web", r.roots[0])).emitted_dir(&r.roots),
            web
        );
        assert_eq!(
            at(format!("{}/web/../web", r.roots[0])).emitted_dir(&r.roots),
            None
        );
        assert_eq!(at(r.path("escape")).emitted_dir(&r.roots), None);
        assert_eq!(at("/etc".into()).emitted_dir(&r.roots), None);
        assert_eq!(at(r.roots[0].clone()).emitted_dir(&r.roots), None);
    }

    #[test]
    fn a_stack_file_name_with_a_path_is_never_read() {
        let r = Roots::new(&["web", "other"]);
        let row = StackRow {
            name: "web".into(),
            dir: r.path("web"),
            file: "../other/compose.yaml".into(),
            enabled: true,
            allow: Vec::new(),
            files: Vec::new(),
            env_files: Vec::new(),
            project: None,
        };
        assert!(row.compose_path(&r.roots).is_err());
        assert!(row.read_file("../other/compose.yaml", &r.roots).is_err());
    }

    #[test]
    fn dockge_root_membership_compares_normalized_paths() {
        let at = |dir: &str| StackRow {
            name: "x".into(),
            dir: dir.into(),
            file: DEFAULT_COMPOSE_FILE.into(),
            enabled: true,
            allow: Vec::new(),
            files: Vec::new(),
            env_files: Vec::new(),
            project: None,
        };
        assert!(under_dockge_root(&at("/opt/stacks/x")));
        assert!(under_dockge_root(&at("/opt/stacks/./x")));
        assert!(under_dockge_root(&at("/opt//stacks/x")));
        assert!(under_dockge_root(&at("/opt/stacks/x/")));
        assert!(!under_dockge_root(&at("/opt/stacks/x/../../etc")));
        assert!(!under_dockge_root(&at("/opt/stacks/../x")));
    }

    fn discovered_engine(project: &str, dir: &str) -> crate::test_engine::FakeEngine {
        use crate::test_engine::{FakeEngine, Route};
        FakeEngine::routed(vec![Route::new(
            "GET",
            "/containers/json",
            200,
            format!(
                "[{}]",
                compose_container(project, dir, &format!("{dir}/compose.yaml"))
            ),
        )])
    }

    fn register_root(root: &str, discovery_roots: &[String]) {
        let args = crate::tools::DockerCreateArgs {
            name: "local".into(),
            socket_path: None,
            host: None,
            url: None,
            stacks_root: Some(root.into()),
            data_roots: Vec::new(),
            discovery_roots: discovery_roots.to_vec(),
            registries: Vec::new(),
            routes: Vec::new(),
            dry_run: false,
        };
        plugin_toolkit::reactor::block_on(crate::tools::docker_create(
            args,
            &crate::test_support::admin(),
        ))
        .unwrap();
    }

    #[test]
    fn an_admin_discovery_root_admits_projects_outside_the_stacks_roots() {
        crate::test_support::with_db(|| {
            let stacks = Roots::new(&[]);
            let extra = Roots::new(&["legacy"]);
            let e = discovered_engine("legacy", &extra.path("legacy"));
            let docker = e.client();
            register_root(&stacks.roots[0], &[]);
            assert!(
                plugin_toolkit::reactor::block_on(all(Some(&docker)))
                    .unwrap()
                    .is_empty()
            );
            let args: crate::tools::DockerUpdateArgs =
                plugin_toolkit::serde_json::from_value(plugin_toolkit::serde_json::json!({
                    "name": "local",
                    "discoveryRoots": extra.roots,
                }))
                .unwrap();
            plugin_toolkit::reactor::block_on(crate::tools::docker_update(
                args,
                &crate::test_support::admin(),
            ))
            .unwrap();
            let rows = plugin_toolkit::reactor::block_on(all(Some(&docker))).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].dir, extra.path("legacy"));
            assert_eq!(
                rows[0].read_compose(&allowed_roots().unwrap()).unwrap(),
                "services: {}\n"
            );
            let row = plugin_toolkit::reactor::block_on(require_registered(
                "legacy",
                Some(&docker),
                Adoption::Preview,
            ))
            .unwrap();
            assert_eq!(row.dir, extra.path("legacy"));
        });
    }

    #[test]
    fn a_discovered_project_outside_the_roots_is_never_found() {
        crate::test_support::with_db(|| {
            let e = discovered_engine("x", "/etc/x");
            let docker = e.client();
            let err = plugin_toolkit::reactor::block_on(find("x", Some(&docker)))
                .unwrap_err()
                .to_string();
            assert!(err.contains("no managed stack"), "{err}");
            assert!(
                plugin_toolkit::reactor::block_on(all(Some(&docker)))
                    .unwrap()
                    .is_empty()
            );
        });
    }

    #[test]
    fn backfill_reports_each_failure_and_plans_on_a_dry_run() {
        crate::test_support::with_db(|| {
            let r = Roots::new(&["web"]);
            register_root(&r.roots[0], &[]);
            let web = StackRow {
                name: "web".into(),
                dir: r.path("web"),
                file: "compose.yaml".into(),
                enabled: true,
                allow: Vec::new(),
                files: vec![r.path("web/compose.yaml")],
                env_files: Vec::new(),
                project: None,
            };
            let gone = StackRow {
                name: "gone".into(),
                dir: r.path("gone"),
                files: Vec::new(),
                ..web.clone()
            };
            put(&web).unwrap();
            put(&gone).unwrap();
            let mut claimed = claimed_projects(&list().unwrap());
            claimed.sort();
            assert_eq!(claimed, ["gone", "web"]);
            let plan = plugin_toolkit::reactor::block_on(backfill_projects(true)).unwrap();
            assert!(
                plan.errors.iter().any(|e| e.starts_with("gone: ")),
                "{plan:?}"
            );
            assert!(
                require("web").unwrap().project.is_none(),
                "a dry run stores nothing"
            );
            if crate::test_support::have_compose() {
                assert_eq!(plan.changed, ["web: (unset) -> web"]);
                let done = plugin_toolkit::reactor::block_on(backfill_projects(false)).unwrap();
                assert_eq!(done.changed, plan.changed);
                assert_eq!(require("web").unwrap().project.as_deref(), Some("web"));
                let again = plugin_toolkit::reactor::block_on(backfill_projects(false)).unwrap();
                assert!(again.changed.is_empty());
            }
            let renamed = StackRow {
                project: Some("webapp".into()),
                ..web
            };
            assert_eq!(claimed_projects(&[renamed]), ["webapp"]);
        });
    }

    #[test]
    fn a_row_stored_before_the_project_column_reads_as_unset() {
        let mut legacy = to_dbrow(&StackRow {
            name: "web".into(),
            dir: "/opt/stacks/web".into(),
            file: "compose.yaml".into(),
            enabled: true,
            allow: Vec::new(),
            files: Vec::new(),
            env_files: Vec::new(),
            project: None,
        });
        legacy.remove("project");
        let row = from_dbrow(&legacy).unwrap();
        assert_eq!(row.project, None);
        assert_eq!(row.project_name(), "web");
        let schema: plugin_toolkit::serde_json::Value =
            plugin_toolkit::serde_json::from_str(&crate::registration::schema_json()).unwrap();
        let project = schema["tables"][0]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "project")
            .unwrap();
        assert_eq!(project["sql_type"], "TEXT");
        assert!(
            project.get("not_null").is_none(),
            "core adds a nullable column to existing tables with ADD COLUMN"
        );
    }

    #[test]
    fn deploying_over_a_discovered_project_needs_adoption_first() {
        crate::test_support::with_db(|| {
            let r = Roots::new(&["immich", "fresh"]);
            register_root(&r.roots[0], &[]);
            let e = discovered_engine("immich", &r.path("immich"));
            let docker = e.client();
            let err =
                plugin_toolkit::reactor::block_on(require_not_discovered("immich", Some(&docker)))
                    .unwrap_err()
                    .to_string();
            assert!(err.contains("docker.stack_adopt"), "{err}");
            plugin_toolkit::reactor::block_on(require_not_discovered("fresh", Some(&docker)))
                .unwrap();
            plugin_toolkit::reactor::block_on(require_not_discovered("immich", None)).unwrap();
            put(&StackRow {
                name: "immich".into(),
                dir: r.path("immich"),
                file: "compose.yaml".into(),
                enabled: true,
                allow: Vec::new(),
                files: Vec::new(),
                env_files: Vec::new(),
                project: None,
            })
            .unwrap();
            plugin_toolkit::reactor::block_on(require_not_discovered("immich", Some(&docker)))
                .unwrap();
        });
    }

    #[test]
    fn changing_a_discovered_project_never_adopts_it() {
        crate::test_support::with_db(|| {
            let r = Roots::new(&["immich"]);
            register_root(&r.roots[0], &[]);
            let e = discovered_engine("immich", &r.path("immich"));
            let docker = e.client();
            let err = plugin_toolkit::reactor::block_on(require_registered(
                "immich",
                Some(&docker),
                Adoption::for_call(false),
            ))
            .unwrap_err()
            .to_string();
            assert!(err.contains("docker.stack_adopt"), "{err}");
            assert!(get("immich").unwrap().is_none());
            let preview = plugin_toolkit::reactor::block_on(require_registered(
                "immich",
                Some(&docker),
                Adoption::for_call(true),
            ))
            .unwrap();
            assert_eq!(preview.dir, r.path("immich"));
            assert!(get("immich").unwrap().is_none(), "a dry run adopts nothing");
            let err = plugin_toolkit::reactor::block_on(require_registered(
                "absent",
                Some(&docker),
                Adoption::Preview,
            ))
            .unwrap_err()
            .to_string();
            assert!(err.contains("no managed stack"), "{err}");
        });
    }

    #[test]
    fn a_symlinked_working_dir_cannot_escape_the_stacks_root() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        symlink(outside.path(), root.path().join("web")).unwrap();
        let roots = vec![s(&root.path().canonicalize().unwrap())];
        let dir = PathBuf::from(&roots[0]).join("web");
        assert!(StackDir::open(&s(&dir), &roots, true).is_err());
    }

    #[test]
    fn a_project_a_registered_stack_runs_as_is_not_discovered_again() {
        let r = Roots::new(&["web", "elsewhere"]);
        let containers = summaries(&[(
            "webapp",
            &r.path("elsewhere"),
            &r.path("elsewhere/compose.yaml"),
        )]);
        let registered = vec![StackRow {
            name: "web".into(),
            dir: r.path("web"),
            file: "compose.yaml".into(),
            enabled: true,
            allow: Vec::new(),
            files: Vec::new(),
            env_files: Vec::new(),
            project: None,
        }];
        assert_eq!(from_labels(&containers, &registered, &r.roots).len(), 1);
        assert!(
            from_labels_claimed(&containers, &registered, &["webapp".into()], &r.roots).is_empty()
        );
    }

    #[test]
    fn a_multi_component_project_name_is_not_discovered() {
        let r = Roots::new(&["a", "b", "ok"]);
        let containers = summaries(&[
            ("../etc", &r.path("a"), &r.path("a/compose.yaml")),
            ("a/b", &r.path("b"), &r.path("b/compose.yaml")),
            ("ok", &r.path("ok"), &r.path("ok/compose.yaml")),
        ]);
        let names: Vec<String> = discovered_rows(from_labels(&containers, &[], &r.roots))
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(names, ["ok"]);
    }

    #[test]
    fn a_symlink_counts_as_a_regular_file_only_inside_a_root() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let roots = vec![s(root.path())];
        let shared = root.path().join("shared.yaml");
        std::fs::write(&shared, "services: {}\n").unwrap();
        let evil = outside.path().join("evil.yaml");
        std::fs::write(&evil, "services: {}\n").unwrap();
        let inside = root.path().join("in.yaml");
        let escape = root.path().join("out.yaml");
        let dangling = root.path().join("gone.yaml");
        let to_dir = root.path().join("dir.yaml");
        symlink(&shared, &inside).unwrap();
        symlink(&evil, &escape).unwrap();
        symlink(root.path().join("missing"), &dangling).unwrap();
        symlink(outside.path(), &to_dir).unwrap();
        assert!(regular_file_in_roots(&shared, &roots));
        assert!(regular_file_in_roots(&inside, &roots));
        assert!(!regular_file_in_roots(&escape, &roots));
        assert!(!regular_file_in_roots(&dangling, &roots));
        assert!(!regular_file_in_roots(&to_dir, &roots));
        assert!(!regular_file_in_roots(&root.path().join("none"), &roots));
    }

    #[test]
    fn a_denied_staging_write_names_the_dir_and_the_grant() {
        let err = staging_error(
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            ".x.tmp",
            Path::new("/opt/halvor/compose"),
        )
        .to_string();
        assert!(
            err.contains("/opt/halvor/compose") && err.contains("needs write access"),
            "{err}"
        );
        let err = staging_error(
            std::io::Error::from(std::io::ErrorKind::NotFound),
            ".x.tmp",
            Path::new("/d"),
        );
        assert!(
            format!("{err:#}").contains("creating .x.tmp in /d"),
            "{err:#}"
        );
    }

    #[test]
    fn a_local_dockge_endpoint_is_recognised() {
        use plugin_toolkit::serde_json::json;
        let listed = |url: &str, enabled: bool| json!({"endpoints": [{"name": "d", "base_url": url, "enabled": enabled}]});
        assert!(lists_local_dockge(
            &listed("http://localhost:5001", true),
            "freyr"
        ));
        assert!(lists_local_dockge(
            &listed("http://127.0.0.1:5001/", true),
            "freyr"
        ));
        assert!(lists_local_dockge(
            &listed("http://[::1]:5001", true),
            "freyr"
        ));
        assert!(lists_local_dockge(
            &listed("http://FREYR:5001", true),
            "freyr"
        ));
        assert!(!lists_local_dockge(
            &listed("http://localhost:5001", false),
            "freyr"
        ));
        assert!(!lists_local_dockge(
            &listed("http://baldur:5001", true),
            "freyr"
        ));
        assert!(!lists_local_dockge(
            &listed("http://10.0.0.5:5001", true),
            "freyr"
        ));
        assert!(!lists_local_dockge(&json!({"endpoints": []}), "freyr"));
    }

    #[test]
    fn units_keep_dockge_root_projects_without_a_local_dockge() {
        use crate::test_engine::{FakeEngine, Route};
        crate::test_support::with_db(|| {
            let r = Roots::new(&["arr", "ntfy"]);
            register_root(&r.roots[0], &[]);
            let e = FakeEngine::routed(vec![Route::new(
                "GET",
                "/containers/json",
                200,
                format!(
                    "[{},{}]",
                    compose_container("arr", &r.path("arr"), &r.path("arr/compose.yaml")),
                    compose_container("ntfy", &r.path("ntfy"), &r.path("ntfy/compose.yaml"))
                ),
            )]);
            let docker = e.client();
            let names: Vec<String> = plugin_toolkit::reactor::block_on(units(Some(&docker)))
                .unwrap()
                .into_iter()
                .map(|r| r.name)
                .collect();
            assert_eq!(names, ["arr", "ntfy"]);
        });
    }

    /// A stacks root with the stack `web` in it, the dir created.
    struct Fixture {
        root: tempfile::TempDir,
        roots: Vec<String>,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempdir().unwrap();
            let roots = vec![s(&root.path().canonicalize().unwrap())];
            std::fs::create_dir(root.path().join("web")).unwrap();
            Fixture { root, roots }
        }

        fn dir(&self) -> PathBuf {
            PathBuf::from(&self.roots[0]).join("web")
        }

        fn open(&self) -> StackDir {
            StackDir::open(&s(&self.dir()), &self.roots, false)
                .unwrap()
                .unwrap()
        }

        fn row(&self) -> StackRow {
            row(&self.dir())
        }
    }

    /// A client whose engine is gone, so every image lookup fails.
    fn no_engine() -> bollard::Docker {
        crate::test_engine::FakeEngine::routed(Vec::new()).client()
    }

    fn row(dir: &Path) -> StackRow {
        StackRow {
            name: "web".into(),
            dir: dir.to_string_lossy().into_owned(),
            file: DEFAULT_COMPOSE_FILE.into(),
            enabled: true,
            allow: Vec::new(),
            files: Vec::new(),
            env_files: Vec::new(),
            project: None,
        }
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
    fn compose_and_env_paths_join_dir() {
        let f = Fixture::new();
        let mut r = f.row();
        r.file = "compose.yaml".into();
        assert_eq!(
            r.compose_path(&f.roots).unwrap(),
            f.dir().join("compose.yaml")
        );
        assert_eq!(r.env_path(), f.dir().join(".env"));
    }

    #[test]
    fn a_staged_write_keeps_mode_and_a_backup_and_leaves_the_original_until_commit() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        let p = f.dir().join("compose.yaml");
        std::fs::write(&p, "old\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let dir = f.open();
        let a = StagedWrite::new(&dir, "compose.yaml", "new\n").unwrap();
        let b = StagedWrite::new(&dir, "compose.yaml", "other\n").unwrap();
        assert_ne!(a.temp_path(), b.temp_path(), "temp names are unique");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "old\n");
        drop(b);
        a.commit().unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new\n");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert_eq!(entries(&f.dir()), vec!["compose.yaml", "compose.yaml.bak"]);
        StagedWrite::new(&dir, "compose.yaml", "newer\n")
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(f.dir().join("compose.yaml.bak")).unwrap(),
            "new\n",
            "a regular .bak is replaced"
        );
    }

    #[test]
    fn an_uncommitted_write_leaves_nothing_behind() {
        let f = Fixture::new();
        let p = f.dir().join("compose.yaml");
        std::fs::write(&p, "old\n").unwrap();
        drop(StagedWrite::new(&f.open(), "compose.yaml", "new\n").unwrap());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "old\n");
        assert_eq!(entries(&f.dir()), vec!["compose.yaml"]);
    }

    #[test]
    fn a_bak_symlink_is_refused_not_written_through() {
        let f = Fixture::new();
        let outside = tempdir().unwrap();
        let victim = outside.path().join("authorized_keys");
        std::fs::write(&victim, "keep\n").unwrap();
        std::fs::write(f.dir().join("compose.yaml"), "old\n").unwrap();
        symlink(&victim, f.dir().join("compose.yaml.bak")).unwrap();
        let dir = f.open();
        let err = StagedWrite::new(&dir, "compose.yaml", "new\n")
            .unwrap()
            .commit()
            .unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep\n");
        assert_eq!(
            std::fs::read_to_string(f.dir().join("compose.yaml")).unwrap(),
            "old\n"
        );
    }

    #[test]
    fn a_symlinked_compose_file_is_refused_not_written_through() {
        let f = Fixture::new();
        let outside = tempdir().unwrap();
        let real = outside.path().join("real.yaml");
        std::fs::write(&real, "old\n").unwrap();
        symlink(&real, f.dir().join("compose.yaml")).unwrap();
        assert!(StagedWrite::new(&f.open(), "compose.yaml", "new\n").is_err());
        assert!(f.open().read("compose.yaml").is_err());
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "old\n");
    }

    #[test]
    fn a_stack_dir_swapped_for_a_symlink_is_refused() {
        let f = Fixture::new();
        let outside = tempdir().unwrap();
        let held = f.open();
        std::fs::remove_dir(f.dir()).unwrap();
        symlink(outside.path(), f.dir()).unwrap();
        let err = StackDir::open(&s(&f.dir()), &f.roots, true).err().unwrap();
        assert!(
            err.to_string().contains("outside the stacks roots"),
            "{err}"
        );
        // A descriptor opened before the swap still names the old dir, so a
        // write through it never lands in the link's target.
        assert!(StagedWrite::new(&held, "compose.yaml", "x\n").is_err());
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
        let inner = f.root.path().join("inner");
        std::fs::create_dir(&inner).unwrap();
        symlink(&inner, f.root.path().join("linked")).unwrap();
        let resolved = s(&PathBuf::from(&f.roots[0]).join("linked/web"));
        let opened = StackDir::open(&resolved, &f.roots, true).unwrap().unwrap();
        assert!(
            opened
                .path()
                .starts_with(PathBuf::from(&f.roots[0]).join("inner"))
        );
    }

    #[test]
    fn write_compose_if_unchanged_refuses_a_file_edited_since_it_was_read() {
        let f = Fixture::new();
        let r = f.row();
        std::fs::write(r.compose_path(&f.roots).unwrap(), "a: 2\n").unwrap();
        let err = plugin_toolkit::reactor::block_on(r.write_compose_if_unchanged(
            "a: 3\n",
            "a: 1\n",
            &f.roots,
            Some(&no_engine()),
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("changed since it was read"),
            "{err}"
        );
        assert_eq!(r.read_compose(&f.roots).unwrap(), "a: 2\n");
    }

    #[test]
    fn writes_refuse_a_stack_outside_the_roots() {
        let f = Fixture::new();
        let elsewhere = tempdir().unwrap();
        let r = row(elsewhere.path());
        let err = plugin_toolkit::reactor::block_on(r.write_checked(
            Some("services: {}\n"),
            None,
            &f.roots,
            Some(&no_engine()),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("set stacksRoot"), "{err}");
        let err = plugin_toolkit::reactor::block_on(r.write_compose_if_unchanged(
            "x",
            "",
            &f.roots,
            Some(&no_engine()),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("set stacksRoot"), "{err}");
        assert_eq!(std::fs::read_dir(elsewhere.path()).unwrap().count(), 0);
    }

    #[test]
    fn config_runs_every_profile_over_exactly_the_given_files() {
        let files = [
            PathBuf::from("/s/web/compose.yaml"),
            PathBuf::from("/s/web/compose.orca.yaml"),
        ];
        let compose =
            Compose::new(files.to_vec(), vec![PathBuf::from("/s/web/.env.tmp")], None).unwrap();
        let a = config_args(Path::new("/s/web"), &compose).unwrap();
        assert_eq!(
            a,
            [
                "compose",
                "--project-directory",
                "/s/web",
                "--env-file",
                "/s/web/.env.tmp",
                "-f",
                "/s/web/compose.yaml",
                "-f",
                "/s/web/compose.orca.yaml",
                "--profile",
                "*",
                "config",
                "--no-env-resolution",
                "--format",
                "json"
            ]
        );
    }

    #[test]
    fn compose_path_is_the_named_file_else_the_one_compose_picks() {
        let f = Fixture::new();
        let mut r = f.row();
        r.file = "prod.yml".into();
        let path = |r: &StackRow| r.compose_path(&f.roots).unwrap();
        assert!(path(&r).ends_with("prod.yml"), "to be created");
        std::fs::write(f.dir().join("compose.yaml"), "services: {}\n").unwrap();
        assert!(path(&r).ends_with("compose.yaml"));
        std::fs::write(f.dir().join("prod.yml"), "services: {}\n").unwrap();
        assert!(path(&r).ends_with("prod.yml"));
        assert!(r.compose(&f.roots).unwrap().file().ends_with("prod.yml"));
    }

    #[test]
    fn stack_dir_open_creates_missing_dirs_only_when_asked() {
        let f = Fixture::new();
        let nested = s(&PathBuf::from(&f.roots[0]).join("a/b/c"));
        assert!(StackDir::open(&nested, &f.roots, false).unwrap().is_none());
        StackDir::open(&nested, &f.roots, true).unwrap().unwrap();
        assert!(Path::new(&nested).is_dir());
    }

    #[test]
    fn read_env_absent_is_none() {
        let f = Fixture::new();
        assert!(f.row().read_env(&f.roots).is_none());
    }

    #[test]
    fn read_env_refuses_a_symlink() {
        let f = Fixture::new();
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join("secrets"), "TOKEN=abcd\n").unwrap();
        symlink(outside.path().join("secrets"), f.dir().join(".env")).unwrap();
        assert!(f.row().read_env(&f.roots).is_none());
    }

    #[test]
    fn env_values_are_unquoted_and_scrubbed_longest_first() {
        let env = "# c\nDB_PASSWORD=hunter2pw\nexport TOKEN = 'tok en'\nQ=\"quoted val\"\nC=plain # note\nN=1\nLONG=hunter2pw-extended\nbad line\n";
        assert_eq!(
            env_pairs(env),
            [
                ("DB_PASSWORD", "hunter2pw"),
                ("TOKEN", "tok en"),
                ("Q", "quoted val"),
                ("C", "plain"),
                ("N", "1"),
                ("LONG", "hunter2pw-extended"),
            ]
            .map(|(k, v)| (k.to_string(), v.to_string()))
        );
        let out = redact(
            "volume hunter2pw-extended, pw hunter2pw, tok en, quoted val, plain, 1 replica",
            &env_values(env),
        );
        assert_eq!(out, "volume ***, pw ***, ***, ***, ***, 1 replica");
    }

    fn entries_of(text: &str) -> Vec<(String, String, bool)> {
        parse_env(text)
            .into_iter()
            .map(|e| (e.key, e.value, e.expands))
            .collect()
    }

    fn entry(k: &str, v: &str, expands: bool) -> (String, String, bool) {
        (k.to_string(), v.to_string(), expands)
    }

    #[test]
    fn env_files_parse_keys_comments_and_export_as_compose_does() {
        let text = "# top\n  export A=1\nexport\tB=2\nC: 3\nexporter=4\nno pair here\n=empty key\nD=a#b # comment\nE=\r\n";
        assert_eq!(
            entries_of(text),
            [
                entry("A", "1", false),
                entry("B", "2", false),
                entry("C", "3", false),
                entry("exporter", "4", false),
                entry("D", "a#b", false),
                entry("E", "", false),
            ]
        );
    }

    #[test]
    fn single_quotes_are_literal_and_may_span_lines() {
        let text = "A='x\\ny $B ${C} # not a comment'\nM='one\ntwo' # after\nN=1\n";
        assert_eq!(
            entries_of(text),
            [
                entry("A", "x\\ny $B ${C} # not a comment", false),
                entry("M", "one\ntwo", false),
                entry("N", "1", false),
            ]
        );
    }

    #[test]
    fn double_quotes_take_escapes_and_may_span_lines() {
        let text = "A=\"l1\\nl2\\t\\\"q\\\" back\\\\slash \\$LIT \\x\" # c\nM=\"one\ntwo\"\nN=1\n";
        assert_eq!(
            entries_of(text),
            [
                entry("A", "l1\nl2\t\"q\" back\\slash $LIT \\x", false),
                entry("M", "one\ntwo", false),
                entry("N", "1", false),
            ]
        );
    }

    #[test]
    fn variables_compose_would_expand_are_flagged() {
        let text =
            "A=$HOME\nB=${HOME}/x\nC=\"pre ${X}\"\nD='${X}'\nE=\"\\${X}\"\nF=cost $5\nG=a$\n";
        let flags: Vec<(String, bool)> = parse_env(text)
            .into_iter()
            .map(|e| (e.key, e.expands))
            .collect();
        assert_eq!(
            flags,
            [
                ("A", true),
                ("B", true),
                ("C", true),
                ("D", false),
                ("E", false),
                ("F", false),
                ("G", false),
            ]
            .map(|(k, f)| (k.to_string(), f))
        );
    }

    #[test]
    fn json_escaped_env_values_are_scrubbed_too() {
        let values = env_values("PW='pa\"ss\\word'\n");
        assert_eq!(values, [r#"pa"ss\word"#]);
        let json = plugin_toolkit::serde_json::json!({"error": "bad pa\"ss\\word"}).to_string();
        assert_eq!(redact(&json, &values), r#"{"error":"bad ***"}"#);
    }

    #[test]
    fn stackrow_deserializes_with_defaults() {
        let r: StackRow =
            plugin_toolkit::serde_json::from_str(r#"{"name":"a","dir":"/srv/a"}"#).unwrap();
        assert_eq!(r.file, DEFAULT_COMPOSE_FILE);
        assert!(r.enabled && r.allow.is_empty());
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
        symlink(outside.path(), root.path().join("escape")).unwrap();
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

    // ── restore staging ─────────────────────────────────────────────────────

    enum Kind {
        File(&'static str),
        Dir,
        Symlink(&'static str),
        Hardlink(&'static str),
        Char,
    }

    /// An archive built header by header, so names and link targets are
    /// exactly as given.
    fn archive(dir: &Path, entries: &[(&str, Kind)]) -> std::fs::File {
        let path = dir.join("stack.tar.gz");
        let gz = flate2::write::GzEncoder::new(
            std::fs::File::create(&path).unwrap(),
            flate2::Compression::default(),
        );
        let mut builder = tar::Builder::new(gz);
        for (name, kind) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            // Unpacking as root reads ownership; empty numeric fields fail to parse.
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(0);
            h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            let body: &[u8] = match kind {
                Kind::File(b) => {
                    h.set_entry_type(tar::EntryType::Regular);
                    b.as_bytes()
                }
                Kind::Dir => {
                    h.set_mode(0o755);
                    h.set_entry_type(tar::EntryType::Directory);
                    b""
                }
                Kind::Symlink(t) | Kind::Hardlink(t) => {
                    h.set_entry_type(if matches!(kind, Kind::Symlink(_)) {
                        tar::EntryType::Symlink
                    } else {
                        tar::EntryType::Link
                    });
                    h.as_old_mut().linkname[..t.len()].copy_from_slice(t.as_bytes());
                    b""
                }
                Kind::Char => {
                    h.set_entry_type(tar::EntryType::Char);
                    b""
                }
            };
            h.set_size(body.len() as u64);
            h.set_cksum();
            builder.append(&h, body).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
        std::fs::File::open(path).unwrap()
    }

    #[test]
    fn a_staged_restore_swaps_in_and_keeps_what_the_archive_lacks() {
        let f = Fixture::new();
        std::fs::write(f.dir().join("compose.yaml"), "old\n").unwrap();
        std::fs::write(f.dir().join("notes"), "kept\n").unwrap();
        let src = tempdir().unwrap();
        let mut file = archive(
            src.path(),
            &[
                ("./", Kind::Dir),
                ("./compose.yaml", Kind::File("new\n")),
                ("./.env", Kind::File("A=1\n")),
                ("./data/", Kind::Dir),
                ("./data/link", Kind::Symlink("../compose.yaml")),
            ],
        );
        let staged = StagedRestore::stage(&f.row(), &mut file, &f.roots);
        let err = staged.err().unwrap().to_string();
        assert!(err.contains("outside"), "a '..' link is refused: {err}");
        let mut file = archive(
            src.path(),
            &[
                ("./", Kind::Dir),
                ("./compose.yaml", Kind::File("new\n")),
                ("./.env", Kind::File("A=1\n")),
                ("./data/", Kind::Dir),
                ("./data/link", Kind::Symlink("x")),
            ],
        );
        let staged = StagedRestore::stage(&f.row(), &mut file, &f.roots).unwrap();
        assert_eq!(staged.env_file(), Some(staged.path().join(".env")));
        let sets = staged.compose_sets(&f.row(), &f.roots).unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].files(), vec![staged.path().join("compose.yaml")]);
        assert_eq!(sets[0].env_files(), [staged.path().join(".env")]);
        assert_eq!(staged.swap().unwrap(), None);
        assert_eq!(
            std::fs::read_to_string(f.dir().join("compose.yaml")).unwrap(),
            "new\n"
        );
        assert_eq!(
            std::fs::read_to_string(f.dir().join("notes")).unwrap(),
            "kept\n"
        );
        assert_eq!(entries(Path::new(&f.roots[0])), vec!["web"]);
    }

    #[test]
    fn an_abandoned_restore_leaves_the_stack_dir_as_it_was() {
        let f = Fixture::new();
        std::fs::write(f.dir().join("compose.yaml"), "old\n").unwrap();
        std::fs::write(f.dir().join("notes"), "kept\n").unwrap();
        let src = tempdir().unwrap();
        let mut file = archive(src.path(), &[("compose.yaml", Kind::File("new\n"))]);
        let staged = StagedRestore::stage(&f.row(), &mut file, &f.roots).unwrap();
        assert!(!f.dir().join("notes").exists(), "carried into staging");
        drop(staged);
        assert_eq!(entries(&f.dir()), vec!["compose.yaml", "notes"]);
        assert_eq!(
            std::fs::read_to_string(f.dir().join("compose.yaml")).unwrap(),
            "old\n"
        );
        assert_eq!(entries(Path::new(&f.roots[0])), vec!["web"]);
    }

    #[test]
    fn restore_refuses_escaping_and_device_entries_from_their_headers() {
        let f = Fixture::new();
        std::fs::write(f.dir().join("compose.yaml"), "old\n").unwrap();
        let src = tempdir().unwrap();
        for (name, kind) in [
            ("/etc/cron.d/x", Kind::File("x")),
            ("../escape", Kind::File("x")),
            ("data/../../escape", Kind::File("x")),
            ("link", Kind::Symlink("/etc")),
            ("link", Kind::Symlink("../../etc")),
            ("hard", Kind::Hardlink("/etc/shadow")),
            ("tty", Kind::Char),
        ] {
            let mut file = archive(
                src.path(),
                &[("compose.yaml", Kind::File("new\n")), (name, kind)],
            );
            assert!(crate::engine_state::validate(&mut file).is_err(), "{name}");
            assert!(
                StagedRestore::stage(&f.row(), &mut file, &f.roots).is_err(),
                "{name}"
            );
            assert_eq!(entries(&f.dir()), vec!["compose.yaml"], "{name}");
            assert_eq!(entries(Path::new(&f.roots[0])), vec!["web"], "{name}");
        }
        assert_eq!(
            std::fs::read_to_string(f.dir().join("compose.yaml")).unwrap(),
            "old\n"
        );
    }

    #[test]
    fn restore_refuses_a_stack_outside_the_roots_or_swapped_for_a_link() {
        let f = Fixture::new();
        let src = tempdir().unwrap();
        let elsewhere = tempdir().unwrap();
        let mut file = archive(src.path(), &[("compose.yaml", Kind::File("x"))]);
        let err = StagedRestore::stage(&row(elsewhere.path()), &mut file, &f.roots)
            .err()
            .unwrap();
        assert!(err.to_string().contains("set stacksRoot"), "{err}");
        std::fs::remove_dir(f.dir()).unwrap();
        symlink(elsewhere.path(), f.dir()).unwrap();
        assert!(StagedRestore::stage(&f.row(), &mut file, &f.roots).is_err());
        assert_eq!(std::fs::read_dir(elsewhere.path()).unwrap().count(), 0);
    }
}
