//! `docker.stack_bindings` and `docker.stack_relocate`: a stack's bind mounts
//! judged against its dir, and moving the stack dir to another root on the
//! same host.

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use plugin_toolkit::prelude::*;

use crate::compose_config::ComposeConfig;
use crate::fsat;
use crate::stack_health::StackHealth;
use crate::stacks::{self, StackDir, StackRow};

const TOOL: &str = "docker.stack_relocate";

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackBinding {
    pub service: String,
    pub source: String,
    pub target: String,
    pub read_only: bool,
    pub inside_stack_dir: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackBindings {
    pub stack: String,
    pub dir: String,
    pub bindings: Vec<StackBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Every bind mount of `cfg`, each judged inside or outside any of `dirs`
/// (one stack dir in its written and resolved forms).
pub fn classify(cfg: &ComposeConfig, dirs: &[PathBuf]) -> Vec<StackBinding> {
    let mut out = Vec::new();
    for (service, svc) in &cfg.services {
        for m in &svc.volumes {
            let Some(source) = m.bind_source() else {
                continue;
            };
            out.push(StackBinding {
                service: service.clone(),
                source: source.to_owned(),
                target: m.target.clone(),
                read_only: m.read_only,
                inside_stack_dir: dirs.iter().any(|d| Path::new(source).starts_with(d)),
            });
        }
    }
    out
}

fn dir_forms(row: &StackRow) -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from(&row.dir)];
    if let Ok(resolved) = crate::lifecycle::resolve(Path::new(&row.dir))
        && !dirs.contains(&resolved)
    {
        dirs.push(resolved);
    }
    dirs
}

fn user_files(row: &StackRow) -> Result<Vec<PathBuf>> {
    Ok(row
        .compose(&crate::stacks::allowed_roots()?)?
        .without_orca()
        .files()
        .into_iter()
        .map(Path::to_path_buf)
        .collect())
}

async fn config_at(dir: &Path, files: &[PathBuf]) -> Result<ComposeConfig> {
    ComposeConfig::parse(&stacks::resolved_config(dir, files, None).await?)
}

pub async fn bindings_of(row: &StackRow) -> Result<Vec<StackBinding>> {
    let cfg = config_at(Path::new(&row.dir), &user_files(row)?).await?;
    Ok(classify(&cfg, &dir_forms(row)))
}

#[orca_struct(args)]
pub struct DockerStackBindingsArgs {
    /// One stack; omitted, every registered stack.
    #[arg(long)]
    #[serde(default)]
    pub stack: Option<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackBindingsOutput {
    pub stacks: Vec<StackBindings>,
}

/// **List each stack's bind mounts** and whether each lies inside the
/// stack's own dir (moves with it) or outside (stays put). Read-only.
#[orca_tool(domain = "docker", verb = "stack_bindings", role = "read")]
async fn docker_stack_bindings(
    args: DockerStackBindingsArgs,
    _ctx: &ToolCtx,
) -> Result<StackBindingsOutput> {
    let rows = match &args.stack {
        Some(name) => vec![stacks::find_here(name).await?],
        None => stacks::all_here().await?,
    };
    let roots = stacks::allowed_roots()?;
    let mut out = Vec::new();
    for row in rows {
        let (bindings, error) = match bindings_of(&row).await {
            Ok(b) => (b, None),
            Err(e) => (Vec::new(), Some(row.redact(&format!("{e:#}"), &roots))),
        };
        out.push(StackBindings {
            dir: row.emitted_dir(&roots).unwrap_or_default(),
            stack: row.name,
            bindings,
            error,
        });
    }
    Ok(StackBindingsOutput { stacks: out })
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewrite {
    pub file: String,
    pub line: usize,
    pub before: String,
    pub after: String,
}

fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-')
}

/// Byte offsets of `needle` in `line` standing as a whole path or a path
/// prefix (followed by `/`), not part of a longer name.
fn occurrences(line: &str, needle: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = line[from..].find(needle).map(|i| i + from) {
        let before = line[..i].chars().next_back();
        let after = line[i + needle.len()..].chars().next();
        if before.is_none_or(|c| !is_path_char(c))
            && after.is_none_or(|c| c == '/' || !is_path_char(c))
        {
            out.push(i);
        }
        from = i + needle.len();
    }
    out
}

/// Each line of `text` naming any of `old` as an absolute path, with that
/// path replaced by `new`.
pub fn rewrites(file: &str, text: &str, old: &[String], new: &str) -> Vec<Rewrite> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let mut after = line.to_owned();
        for o in old {
            let mut hits = occurrences(&after, o);
            hits.reverse();
            for i in hits {
                after.replace_range(i..i + o.len(), new);
            }
        }
        if after != line {
            out.push(Rewrite {
                file: file.to_owned(),
                line: n + 1,
                before: line.to_owned(),
                after,
            });
        }
    }
    out
}

fn apply_rewrites(text: &str, rewrites: &[Rewrite]) -> String {
    let mut out: Vec<String> = text.lines().map(str::to_owned).collect();
    for r in rewrites {
        if let Some(l) = out.get_mut(r.line - 1) {
            l.clone_from(&r.after);
        }
    }
    let mut joined = out.join("\n");
    if text.ends_with('\n') {
        joined.push('\n');
    }
    joined
}

/// Refuse absolute references into the old dir unless they are being
/// rewritten, and rewrites of a stack whose grants are bound to its
/// current definitions.
pub fn check_rewrites(found: &[Rewrite], rewrite: bool, granted: bool) -> Result<()> {
    if found.is_empty() {
        return Ok(());
    }
    let lines = found
        .iter()
        .map(|r| format!("{}:{}: {}", r.file, r.line, r.before.trim()))
        .collect::<Vec<_>>()
        .join("; ");
    if !rewrite {
        bail!(
            "absolute paths point inside the stack dir ({lines}); pass rewrite to repoint them at the new dir"
        );
    }
    if granted {
        bail!(
            "the stack has grants bound to its service definitions, which the rewrite would change ({lines}); revoke them, relocate, then re-grant"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    kind: fsat::Kind,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    content: String,
}

/// Every entry below `root` by relative path, symlinks not followed: kind,
/// mode, owner, and a file's sha256 or a link's target.
pub fn snapshot(root: &Path) -> Result<BTreeMap<PathBuf, Entry>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        for item in std::fs::read_dir(root.join(&rel))
            .with_context(|| format!("reading {}", root.join(&rel).display()))?
        {
            let item = item?;
            let rel = rel.join(item.file_name());
            let path = root.join(&rel);
            let meta = std::fs::symlink_metadata(&path)?;
            let ft = meta.file_type();
            let (kind, content) = if ft.is_symlink() {
                (
                    fsat::Kind::Symlink,
                    std::fs::read_link(&path)?.to_string_lossy().into_owned(),
                )
            } else if ft.is_dir() {
                stack.push(rel.clone());
                (fsat::Kind::Dir, String::new())
            } else if ft.is_file() {
                (fsat::Kind::File, plugin_toolkit::hash::sha256_file(&path)?)
            } else {
                bail!(
                    "{} is not a file, dir or symlink; refusing to copy it",
                    path.display()
                );
            };
            out.insert(
                rel,
                Entry {
                    kind,
                    mode: meta.mode() & 0o7777,
                    uid: meta.uid(),
                    gid: meta.gid(),
                    size: if kind == fsat::Kind::File {
                        meta.len()
                    } else {
                        0
                    },
                    content,
                },
            );
        }
    }
    Ok(out)
}

pub fn totals(snap: &BTreeMap<PathBuf, Entry>) -> (u64, u64) {
    snap.values()
        .filter(|e| e.kind == fsat::Kind::File)
        .fold((0, 0), |(n, b), e| (n + 1, b + e.size))
}

fn chown(path: &Path, e: &Entry) -> Result<()> {
    std::os::unix::fs::lchown(path, Some(e.uid), Some(e.gid))
        .with_context(|| format!("preserving owner {}:{} of {}", e.uid, e.gid, path.display()))
}

/// Copy the entries of `snap` from `src` into the fresh dir `dst`, keeping
/// mode and owner; dirs get theirs after their contents are written.
pub fn copy_tree(src: &Path, dst: &Path, snap: &BTreeMap<PathBuf, Entry>) -> Result<()> {
    let root = std::fs::symlink_metadata(src)?;
    std::fs::create_dir(dst).with_context(|| format!("creating {}", dst.display()))?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o700))?;
    for (rel, e) in snap {
        let (from, to) = (src.join(rel), dst.join(rel));
        match e.kind {
            fsat::Kind::Dir => {
                std::fs::create_dir(&to)?;
                std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o700))?;
            }
            fsat::Kind::File => {
                std::fs::copy(&from, &to).with_context(|| format!("copying {}", from.display()))?;
                chown(&to, e)?;
                std::fs::set_permissions(&to, std::fs::Permissions::from_mode(e.mode))?;
            }
            fsat::Kind::Symlink => {
                std::os::unix::fs::symlink(&e.content, &to)?;
                chown(&to, e)?;
            }
            fsat::Kind::Other => bail!("{} cannot be copied", from.display()),
        }
    }
    for (rel, e) in snap.iter().rev().filter(|(_, e)| e.kind == fsat::Kind::Dir) {
        let to = dst.join(rel);
        chown(&to, e)?;
        std::fs::set_permissions(&to, std::fs::Permissions::from_mode(e.mode))?;
    }
    std::os::unix::fs::lchown(dst, Some(root.uid()), Some(root.gid()))
        .with_context(|| format!("preserving the owner of {}", dst.display()))?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(root.mode() & 0o7777))?;
    Ok(())
}

/// The copy at `dst` matches `snap` entry for entry: same paths, kinds,
/// modes, owners, sizes and sha256s.
pub fn verify(dst: &Path, snap: &BTreeMap<PathBuf, Entry>) -> Result<()> {
    let copy = snapshot(dst)?;
    if copy.len() != snap.len() {
        bail!(
            "copy at {} has {} entries, the source {}",
            dst.display(),
            copy.len(),
            snap.len()
        );
    }
    for (rel, e) in snap {
        match copy.get(rel) {
            Some(c) if c == e => {}
            Some(_) => bail!(
                "{} differs from the source after the copy",
                dst.join(rel).display()
            ),
            None => bail!("{} is missing from the copy", dst.join(rel).display()),
        }
    }
    Ok(())
}

#[orca_struct(args)]
pub struct DockerStackRelocateArgs {
    #[arg(long)]
    pub stack: String,
    /// Absolute stacks root to move the stack under; it lands at
    /// `<newRoot>/<stack>`.
    #[arg(long)]
    #[serde(rename = "newRoot", alias = "new_root")]
    pub new_root: String,
    /// Repoint absolute paths into the old stack dir at the new one.
    #[arg(long)]
    #[serde(default)]
    pub rewrite: bool,
    /// Return the plan and change nothing. Omitted, applies.
    #[arg(long)]
    #[serde(default, rename = "dryRun", alias = "dry_run")]
    pub dry_run: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RelocateOutput {
    pub executed: bool,
    pub stack: String,
    /// Kept after the move; delete it once the stack is confirmed healthy.
    pub old_dir: String,
    pub new_dir: String,
    pub bindings: Vec<StackBinding>,
    pub rewrites: Vec<Rewrite>,
    pub file_count: u64,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<StackHealth>,
}

struct Plan {
    row: StackRow,
    old_dir: PathBuf,
    new_dir: PathBuf,
    snap: BTreeMap<PathBuf, Entry>,
    old_forms: Vec<String>,
    found: Vec<Rewrite>,
    out: RelocateOutput,
}

async fn plan(args: &DockerStackRelocateArgs) -> Result<Plan> {
    let row = stacks::require_registered_here(&args.stack).await?;
    if !fsat::is_single_component(&row.name) {
        bail!("stack name '{}' is not a plain dir name", row.name);
    }
    crate::tools::validate_stacks_root(&args.new_root)?;
    let roots = crate::tools::stacks_roots()?;
    let old_dir = stacks::stack_dir_in_roots(&row.dir, &roots)?;
    let new_root = crate::lifecycle::resolve(Path::new(&args.new_root))?;
    if !new_root.is_dir() {
        bail!(
            "new root {} is not an existing directory",
            new_root.display()
        );
    }
    let new_dir = new_root.join(&row.name);
    stacks::stack_dir_in_roots(&new_dir.to_string_lossy(), &roots)?;
    if std::fs::symlink_metadata(&new_dir).is_ok() {
        bail!("{} already exists", new_dir.display());
    }
    if new_dir.starts_with(&old_dir) || old_dir.starts_with(&new_dir) {
        bail!("{} and {} overlap", old_dir.display(), new_dir.display());
    }
    stacks::check_dir_free(&row.name, &new_dir)?;
    let forms = dir_forms(&row);
    let cfg = config_at(Path::new(&row.dir), &user_files(&row)?).await?;
    let bindings = classify(&cfg, &forms);
    let old_forms: Vec<String> = forms
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let new_str = new_dir.to_string_lossy().into_owned();
    let mut found = Vec::new();
    let mut names: Vec<String> = user_files(&row)?
        .iter()
        .filter_map(|f| f.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    if row.read_env(&roots).is_some() {
        names.push(stacks::ENV_FILE.to_owned());
    }
    let dir = StackDir::open(&row.dir, &roots, false)?
        .ok_or_else(|| anyhow!("stack dir {} does not exist", row.dir))?;
    for name in &names {
        found.extend(rewrites(name, &dir.read(name)?, &old_forms, &new_str));
    }
    check_rewrites(&found, args.rewrite, !row.allow.is_empty())?;
    let snap = snapshot(&old_dir)?;
    let (file_count, bytes) = totals(&snap);
    let out = RelocateOutput {
        executed: false,
        stack: row.name.clone(),
        old_dir: old_dir.to_string_lossy().into_owned(),
        new_dir: new_str,
        bindings,
        rewrites: found
            .iter()
            .map(|r| Rewrite {
                before: row.redact(&r.before, &roots),
                after: row.redact(&r.after, &roots),
                ..r.clone()
            })
            .collect(),
        file_count,
        bytes,
        health: None,
    };
    Ok(Plan {
        row,
        old_dir,
        new_dir,
        snap,
        old_forms,
        found,
        out,
    })
}

/// Copy, verify, rewrite and check the new dir; on any failure the copy is
/// removed.
async fn stage(p: &Plan) -> Result<()> {
    let staged = async {
        copy_tree(&p.old_dir, &p.new_dir, &p.snap)?;
        verify(&p.new_dir, &p.snap)?;
        let roots = crate::tools::stacks_roots()?;
        let dir = StackDir::open(&p.new_dir.to_string_lossy(), &roots, false)?
            .ok_or_else(|| anyhow!("{} vanished", p.new_dir.display()))?;
        let mut by_file: BTreeMap<&str, Vec<Rewrite>> = BTreeMap::new();
        for r in &p.found {
            by_file.entry(r.file.as_str()).or_default().push(r.clone());
        }
        for (name, rs) in by_file {
            let text = apply_rewrites(&dir.read(name)?, &rs);
            stacks::StagedWrite::new(&dir, name, &text)?.replace()?;
        }
        let moved = StackRow {
            dir: p.new_dir.to_string_lossy().into_owned(),
            ..p.row.clone()
        };
        let cfg = config_at(&p.new_dir, &user_files(&moved)?).await?;
        let olds: Vec<PathBuf> = p.old_forms.iter().map(PathBuf::from).collect();
        if let Some(b) = classify(&cfg, &olds).iter().find(|b| b.inside_stack_dir) {
            bail!(
                "service '{}' still binds {} in the old dir after the rewrite",
                b.service,
                b.source
            );
        }
        Ok(())
    }
    .await;
    if let Err(e) = staged {
        let cleanup = match std::fs::remove_dir_all(&p.new_dir) {
            Ok(()) => String::new(),
            Err(r) if r.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(r) => format!(
                "; removing the partial copy {} failed: {r}",
                p.new_dir.display()
            ),
        };
        return Err(e.context(format!("staging the copy failed{cleanup}")));
    }
    Ok(())
}

async fn bring_back(row: &StackRow) -> String {
    match crate::ownership::up(row, &[]).await {
        Ok(_) => "; the stack is back up at its old dir".to_owned(),
        Err(e) => format!("; bringing it back up at its old dir failed: {e:#}"),
    }
}

async fn relocate(args: &DockerStackRelocateArgs) -> Result<RelocateOutput> {
    let p = plan(args).await?;
    if args.dry_run {
        return Ok(p.out);
    }
    let new_str = p.new_dir.to_string_lossy().into_owned();
    p.row
        .compose(&crate::stacks::allowed_roots()?)?
        .run_action("down", None, None)
        .await
        .map_err(|e| anyhow!("compose down at {}: {e}", p.row.dir))?;
    if let Err(e) = stage(&p).await {
        let back = bring_back(&p.row).await;
        return Err(e.context(format!("relocate refused; nothing moved{back}")));
    }
    let moved = StackRow {
        dir: new_str.clone(),
        ..p.row.clone()
    };
    stacks::put(&moved)?;
    if let Err(e) = crate::ownership::up(&moved, &[]).await {
        let restored = match stacks::put(&p.row) {
            Ok(()) => bring_back(&p.row).await,
            Err(r) => format!("; restoring the registry row failed: {r:#}"),
        };
        return Err(e.context(format!(
            "compose up at {new_str} failed; the copy is kept there{restored}"
        )));
    }
    let docker = &crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    let health =
        crate::stack_health::wait(docker, &p.row.name, crate::stack_health::timeout(Some(10)))
            .await?;
    Ok(RelocateOutput {
        executed: true,
        health: Some(health),
        ..p.out
    })
}

/// **Move a stack to another root on this host**: takes the stack down,
/// copies its dir (bind data inside it included) to `<newRoot>/<stack>`
/// keeping modes and owners, verifies every file's sha256, repoints the
/// registry, brings it up there and waits for health (re-poll
/// `docker.stack_wait_healthy` while `ready` is false). Absolute paths into
/// the old dir are refused unless `rewrite`. The old dir is kept and
/// returned for later deletion. `dryRun` returns the binds, rewrites, file
/// count and bytes.
#[orca_tool(
    domain = "docker",
    verb = "stack_relocate",
    role = "admin",
    execute_gated = false,
    dry_run_aware = true
)]
async fn docker_stack_relocate(
    args: DockerStackRelocateArgs,
    ctx: &ToolCtx,
) -> Result<RelocateOutput> {
    let args = DockerStackRelocateArgs {
        dry_run: args.dry_run || ctx.dry_run(),
        ..args
    };
    crate::execute::require_admin(TOOL, ctx)?;
    relocate(&args).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn binds_are_judged_inside_or_outside_the_stack_dir() {
        let cfg = ComposeConfig::parse(crate::compose_config::FIXTURE).unwrap();
        let b = classify(&cfg, &[PathBuf::from("/srv/stacks/media")]);
        let inside: Vec<_> = b
            .iter()
            .filter(|b| b.inside_stack_dir)
            .map(|b| b.source.as_str())
            .collect();
        assert_eq!(inside, ["/srv/stacks/media/config"]);
        assert_eq!(b.len(), 4, "named and anonymous volumes are not binds");
        assert!(
            b.iter()
                .all(|b| !b.service.is_empty() && !b.target.is_empty())
        );
        let sibling = classify(&cfg, &[PathBuf::from("/srv/stacks/med")]);
        assert!(sibling.iter().all(|b| !b.inside_stack_dir));
    }

    #[test]
    fn rewrites_touch_only_whole_paths_into_the_old_dir() {
        let text = "services:\n  a:\n    volumes:\n      - /opt/stacks/web/data:/data\n      - /opt/stacks/web2/x:/x\n      - ./rel:/rel\n      - \"/opt/stacks/web\":/root\n      - /x/opt/stacks/web/y:/y\n";
        let r = rewrites(
            "compose.yaml",
            text,
            &["/opt/stacks/web".into()],
            "/srv/stacks/web",
        );
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].line, 4);
        assert_eq!(r[0].after, "      - /srv/stacks/web/data:/data");
        assert_eq!(r[1].after, "      - \"/srv/stacks/web\":/root");
        let applied = apply_rewrites(text, &r);
        assert!(applied.contains("/srv/stacks/web/data") && applied.contains("/opt/stacks/web2/x"));
        assert!(applied.ends_with('\n'));
    }

    #[test]
    fn every_written_form_of_the_old_dir_is_rewritten() {
        let r = rewrites(
            "x",
            "A=/data/web:/real/web/b\n",
            &["/data/web".into(), "/real/web".into()],
            "/n/web",
        );
        assert_eq!(r[0].after, "A=/n/web:/n/web/b");
    }

    #[test]
    fn absolute_refs_need_rewrite_and_no_grants() {
        let r = rewrites("c", "- /o/s:/s\n", &["/o/s".into()], "/n/s");
        assert!(check_rewrites(&[], false, true).is_ok());
        let err = check_rewrites(&r, false, false).unwrap_err().to_string();
        assert!(err.contains("pass rewrite") && err.contains("c:1"), "{err}");
        assert!(
            check_rewrites(&r, true, true)
                .unwrap_err()
                .to_string()
                .contains("grants")
        );
        assert!(check_rewrites(&r, true, false).is_ok());
    }

    fn tree() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("web");
        std::fs::create_dir_all(src.join("data/sub")).unwrap();
        std::fs::write(src.join("compose.yaml"), "services: {}\n").unwrap();
        std::fs::write(src.join("data/sub/db"), vec![7u8; 100_000]).unwrap();
        std::fs::set_permissions(
            src.join("data/sub/db"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        std::fs::set_permissions(src.join("data"), std::fs::Permissions::from_mode(0o750)).unwrap();
        symlink("sub/db", src.join("data/link")).unwrap();
        d
    }

    #[test]
    fn a_copy_keeps_modes_links_and_hashes_and_verifies() {
        let d = tree();
        let (src, dst) = (d.path().join("web"), d.path().join("moved"));
        let snap = snapshot(&src).unwrap();
        assert_eq!(totals(&snap), (2, 100_000 + 13));
        copy_tree(&src, &dst, &snap).unwrap();
        verify(&dst, &snap).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().mode() & 0o7777;
        assert_eq!(mode(&dst.join("data/sub/db")), 0o640);
        assert_eq!(mode(&dst.join("data")), 0o750);
        assert_eq!(mode(&dst), mode(&src));
        assert_eq!(
            std::fs::read_link(dst.join("data/link")).unwrap(),
            Path::new("sub/db")
        );
        assert!(src.join("compose.yaml").exists(), "the source is kept");
    }

    #[test]
    fn verify_catches_a_changed_missing_or_extra_file() {
        let d = tree();
        let (src, dst) = (d.path().join("web"), d.path().join("moved"));
        let snap = snapshot(&src).unwrap();
        copy_tree(&src, &dst, &snap).unwrap();
        std::fs::write(dst.join("data/sub/db"), vec![8u8; 100_000]).unwrap();
        std::fs::set_permissions(
            dst.join("data/sub/db"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(
            verify(&dst, &snap)
                .unwrap_err()
                .to_string()
                .contains("differs")
        );
        std::fs::remove_file(dst.join("data/sub/db")).unwrap();
        std::fs::write(dst.join("extra"), "x").unwrap();
        assert!(verify(&dst, &snap).is_err());
    }

    #[test]
    fn a_copy_refuses_an_existing_destination() {
        let d = tree();
        let src = d.path().join("web");
        let snap = snapshot(&src).unwrap();
        std::fs::create_dir(d.path().join("taken")).unwrap();
        assert!(copy_tree(&src, &d.path().join("taken"), &snap).is_err());
    }

    #[test]
    fn special_files_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let _l = std::os::unix::net::UnixListener::bind(d.path().join("sock")).unwrap();
        assert!(
            snapshot(d.path())
                .unwrap_err()
                .to_string()
                .contains("refusing")
        );
    }

    #[test]
    fn args_accept_camel_and_snake_new_root() {
        use plugin_toolkit::serde_json::{self, json};
        for key in ["newRoot", "new_root"] {
            let a: DockerStackRelocateArgs =
                serde_json::from_value(json!({ "stack": "s", key: "/srv/stacks", "dryRun": true }))
                    .unwrap();
            assert_eq!(a.new_root, "/srv/stacks");
            assert!(a.dry_run && !a.rewrite);
        }
    }

    #[test]
    fn plan_refuses_unknown_stacks_and_bad_roots_before_touching_anything() {
        crate::test_support::with_db(|| {
            let args = |stack: &str, root: &str| DockerStackRelocateArgs {
                stack: stack.into(),
                new_root: root.into(),
                rewrite: false,
                dry_run: true,
            };
            let run = |a| plugin_toolkit::reactor::block_on(relocate(&a));
            assert!(
                run(args("ghost", "/srv/stacks"))
                    .unwrap_err()
                    .to_string()
                    .contains("no managed stack")
            );
            stacks::put(&StackRow {
                name: "web".into(),
                dir: "/opt/stacks/web".into(),
                file: stacks::DEFAULT_COMPOSE_FILE.into(),
                enabled: true,
                allow: Vec::new(),
                files: Vec::new(),
                env_files: Vec::new(),
            })
            .unwrap();
            for bad in ["relative", "/srv/../etc", "/"] {
                assert!(run(args("web", bad)).is_err(), "{bad}");
            }
        });
    }

    #[test]
    fn refuses_a_non_admin_caller() {
        for ctx in crate::test_support::non_admins() {
            let err = plugin_toolkit::reactor::block_on(docker_stack_relocate(
                DockerStackRelocateArgs {
                    stack: "web".into(),
                    new_root: "/srv/stacks".into(),
                    rewrite: false,
                    dry_run: true,
                },
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
        }
    }
}
