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
        Path::new(&self.dir).join(self.compose_name())
    }

    /// The file name of [`compose_path`](Self::compose_path) inside `dir`.
    pub fn compose_name(&self) -> String {
        if Path::new(&self.dir).join(&self.file).is_file() {
            return self.file.clone();
        }
        Compose::find(Path::new(&self.dir))
            .and_then(|c| {
                c.file()
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| self.file.clone())
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

    /// Read the `.env` contents if present. Missing file, or a symlink in
    /// its place → `None`.
    pub fn read_env(&self) -> Option<String> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.env_path())
            .ok()?;
        let mut s = String::new();
        f.read_to_string(&mut s).ok()?;
        Some(s)
    }

    /// `text` with every value the stack's `.env` sets replaced by `***`.
    pub fn redact(&self, text: &str) -> String {
        redact(text, &env_values(&self.read_env().unwrap_or_default()))
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
        let name = self.compose_name();
        let compose = yaml.map(|y| StagedWrite::new(&dir, &name, y)).transpose()?;
        let env = env
            .map(|e| StagedWrite::new(&dir, ENV_FILE, e))
            .transpose()?;
        let file = match &compose {
            Some(staged) => staged.temp_path(),
            None => match dir.stat(&name)? {
                Some(st) if st.kind == fsat::Kind::File => dir.path().join(&name),
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
        let raw = config_json(dir.path(), &file, env_file.as_deref()).await?;
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
        let name = self.compose_name();
        let now = dir.read(&name)?;
        if content_hash(&now) != content_hash(read_before) {
            anyhow::bail!(
                "compose file {} changed since it was read; re-run the dry run",
                self.compose_path().display()
            );
        }
        let staged = StagedWrite::new(&dir, &name, yaml)?;
        let raw = config_json(dir.path(), &staged.temp_path(), None).await?;
        let cfg = policy::prepare(&raw, dir.path(), &dir)?;
        policy::check_stack(docker, &cfg, &cfg, self, dir.path(), stacks_roots).await?;
        staged.commit()
    }

    /// The [`Compose`] project of [`compose_path`](Self::compose_path).
    /// Errors when that file does not exist.
    pub fn compose(&self) -> Result<Compose, crate::ComposeError> {
        Compose::at(&self.compose_path())
            .ok_or_else(|| crate::ComposeError::NoComposeFile(PathBuf::from(&self.dir)))
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
        out.replace(v, plugin_toolkit::scrub::REDACTED_TEXT)
    })
}

/// `compose config` over exactly `files`, as the project in `dir`, with
/// every profile enabled. Env files are left unread, so the policy sees their
/// paths rather than their contents.
fn config_args(dir: &Path, files: &[PathBuf], env_file: Option<&Path>) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "compose".into(),
        "--project-directory".into(),
        dir.to_string_lossy().into_owned(),
    ];
    for f in files {
        args.extend(["-f".into(), f.to_string_lossy().into_owned()]);
    }
    if let Some(env) = env_file {
        args.extend(["--env-file".into(), env.to_string_lossy().into_owned()]);
    }
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
    args
}

/// The resolved config of exactly `files` run as the project in `dir`, with
/// `env_file` in place of the dir's `.env` when given. Also the validation:
/// compose rejects files it cannot run.
pub async fn resolved_config(
    dir: &Path,
    files: &[PathBuf],
    env_file: Option<&Path>,
) -> Result<String> {
    let args = config_args(dir, files, env_file);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    crate::run(&argv, None)
        .await
        .context("compose rejects the stack's config")
}

/// The resolved config `compose up` would run with `file` in place of the
/// stack's compose file, plus the override compose would load from `dir`.
pub async fn config_json(dir: &Path, file: &Path, env_file: Option<&Path>) -> Result<String> {
    let mut files = vec![file.to_path_buf()];
    files.extend(crate::compose::override_in(dir));
    resolved_config(dir, &files, env_file)
        .await
        .context("nothing was written")
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
    pub fn compose_sets(&self, row: &StackRow) -> Vec<Vec<PathBuf>> {
        let named = self.staged.join(&row.file);
        let Some(compose) = Compose::at(&named).or_else(|| Compose::find(&self.staged)) else {
            return Vec::new();
        };
        let plain: Vec<PathBuf> = compose.files().into_iter().map(Path::to_path_buf).collect();
        let mut sets = vec![plain];
        if self.staged.join(crate::compose::ORCA_FILE).is_file() {
            sets.push(
                compose
                    .with_orca()
                    .files()
                    .into_iter()
                    .map(Path::to_path_buf)
                    .collect(),
            );
        }
        sets
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
        .with_context(|| format!("creating {temp} in {}", dir.path().display()))?;
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
            };
            insert(&row("/opt/stacks/web")).unwrap();
            assert!(insert(&row("/opt/stacks/elsewhere")).is_err());
            assert_eq!(require("web").unwrap().dir, "/opt/stacks/web");
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
        std::fs::write(r.compose_path(), "a: 2\n").unwrap();
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
        assert_eq!(r.read_compose().unwrap(), "a: 2\n");
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
        let a = config_args(
            Path::new("/s/web"),
            &files,
            Some(Path::new("/s/web/.env.tmp")),
        );
        assert_eq!(
            a,
            [
                "compose",
                "--project-directory",
                "/s/web",
                "-f",
                "/s/web/compose.yaml",
                "-f",
                "/s/web/compose.orca.yaml",
                "--env-file",
                "/s/web/.env.tmp",
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
    fn stack_dir_open_creates_missing_dirs_only_when_asked() {
        let f = Fixture::new();
        let nested = s(&PathBuf::from(&f.roots[0]).join("a/b/c"));
        assert!(StackDir::open(&nested, &f.roots, false).unwrap().is_none());
        StackDir::open(&nested, &f.roots, true).unwrap().unwrap();
        assert!(Path::new(&nested).is_dir());
    }

    #[test]
    fn read_env_absent_is_none() {
        let dir = tempdir().unwrap();
        assert!(row(dir.path()).read_env().is_none());
    }

    #[test]
    fn read_env_refuses_a_symlink() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join("secrets"), "TOKEN=abcd\n").unwrap();
        symlink(outside.path().join("secrets"), dir.path().join(".env")).unwrap();
        assert!(row(dir.path()).read_env().is_none());
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
        assert_eq!(
            staged.compose_sets(&f.row()),
            vec![vec![staged.path().join("compose.yaml")]]
        );
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
