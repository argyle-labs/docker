//! The engine-state archive behind `docker.backup` / `docker.restore`.
//!
//! Both directions run in-process over one open file: restore checks every
//! entry from the same reader it extracts from, so neither a swapped path nor
//! a crafted listing can slip an entry past the check.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use plugin_toolkit::prelude::*;
use tar::{Archive, Builder, Entry, EntryType};

/// Comma-separated backup roots, set on the daemon.
pub const BACKUP_ROOTS_ENV: &str = "ORCA_DOCKER_BACKUP_ROOTS";
const DEFAULT_BACKUP_ROOT: &str = "/mnt/backups";

/// Lima's VM ssh keypair. Lima generates a missing pair on start, and the
/// guest re-applies the current public key each boot (the cidata instance-id
/// changes on every start, so cloud-init re-runs its user setup), so a
/// restored host needs neither.
pub const EXCLUDED: &[&str] = &["_lima/_config/user", "_lima/_config/user.pub"];

/// Roots a backup may be written to or restored from: the daemon's
/// [`BACKUP_ROOTS_ENV`], else `/mnt/backups`.
pub fn backup_roots() -> Vec<String> {
    let from_env: Vec<String> = std::env::var(BACKUP_ROOTS_ENV)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| s.starts_with('/'))
        .map(str::to_string)
        .collect();
    if from_env.is_empty() {
        vec![DEFAULT_BACKUP_ROOT.to_string()]
    } else {
        from_env
    }
}

/// Absolute, or climbing out with `..`: either could land outside the dir an
/// archive is extracted into.
fn leaves_root(p: &Path) -> bool {
    p.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    })
}

/// What a backup of `state` holds, as paths relative to it, and what it
/// leaves out with the reason.
pub fn members(state: &Path) -> Result<(Vec<PathBuf>, Vec<String>)> {
    let mut members = Vec::new();
    let mut excluded = Vec::new();
    walk(state, Path::new(""), &mut members, &mut excluded)?;
    Ok((members, excluded))
}

fn walk(
    root: &Path,
    rel: &Path,
    members: &mut Vec<PathBuf>,
    excluded: &mut Vec<String>,
) -> Result<()> {
    let dir = root.join(rel);
    let mut names: Vec<_> = fs::read_dir(&dir)
        .with_context(|| format!("failed to read '{}'", dir.display()))?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<_>>()?;
    names.sort();
    for name in names {
        let member = rel.join(&name);
        let shown = member.to_string_lossy().into_owned();
        if EXCLUDED.contains(&shown.as_str()) {
            excluded.push(format!("{shown}: lima's VM ssh key, regenerated on start"));
            continue;
        }
        let kind = fs::symlink_metadata(root.join(&member))?.file_type();
        if kind.is_dir() {
            members.push(member.clone());
            walk(root, &member, members, excluded)?;
        } else if kind.is_file() {
            members.push(member);
        } else if kind.is_symlink() {
            let target = fs::read_link(root.join(&member))?;
            if leaves_root(&target) {
                excluded.push(format!(
                    "{shown}: links to '{}', which restore refuses",
                    target.display()
                ));
            } else {
                members.push(member);
            }
        } else {
            excluded.push(format!("{shown}: not a file, directory or link"));
        }
    }
    Ok(())
}

/// Write `state` to `docker-engine-state-<stamp>.tar.gz` in `dest`, mode 0600
/// since it can hold VM credentials. Built under a temporary name and renamed
/// into place, so a failed run never leaves a truncated archive behind.
pub fn pack(state: &Path, dest: &Path, stamp: &str) -> Result<(PathBuf, Vec<String>)> {
    let (members, excluded) = members(state)?;
    let name = format!("docker-engine-state-{stamp}.tar.gz");
    let archive = dest.join(&name);
    if archive.symlink_metadata().is_ok() {
        bail!("archive '{}' already exists", archive.display());
    }
    let partial = dest.join(format!(".{name}.partial"));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&partial)
        .with_context(|| format!("failed to create '{}'", partial.display()))?;
    let written = (|| -> Result<()> {
        let mut builder = Builder::new(GzEncoder::new(file, Compression::default()));
        builder.follow_symlinks(false);
        for m in &members {
            builder.append_path_with_name(state.join(m), m)?;
        }
        builder.into_inner()?.finish()?.sync_all()?;
        Ok(())
    })();
    if let Err(e) = written.and_then(|()| Ok(fs::rename(&partial, &archive)?)) {
        let _removed = fs::remove_file(&partial);
        return Err(e.context(format!("failed to write '{}'", archive.display())));
    }
    Ok((archive, excluded))
}

/// Whether `entry` is extracted: refuses any entry that could land outside the
/// extraction dir or is not a file, directory or link. A relative link target
/// without `..` can only descend, so chains of such links stay inside too; a
/// check that allowed `..` would not, since `a -> .` then `b -> a/..`
/// resolves above the root.
fn admit<R: Read>(entry: &Entry<'_, R>) -> Result<bool> {
    let path = entry.path()?;
    if leaves_root(&path) {
        bail!(
            "archive entry '{}' would extract outside the state dir",
            path.display()
        );
    }
    match entry.header().entry_type() {
        EntryType::Regular | EntryType::Directory => Ok(true),
        EntryType::Symlink | EntryType::Link => {
            let Some(target) = entry.link_name()? else {
                bail!("archive link '{}' has no target", path.display());
            };
            if leaves_root(&target) {
                bail!(
                    "archive entry '{}' links to '{}', outside the state dir",
                    path.display(),
                    target.display()
                );
            }
            Ok(true)
        }
        // Archive-wide metadata, not a member.
        EntryType::XGlobalHeader => Ok(false),
        other => bail!(
            "archive entry '{}' is {other:?}, not a file, directory or link",
            path.display()
        ),
    }
}

fn archive(file: &mut File) -> Result<Archive<GzDecoder<&mut File>>> {
    file.seek(SeekFrom::Start(0))?;
    let mut archive = Archive::new(GzDecoder::new(file));
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);
    archive.set_unpack_xattrs(false);
    Ok(archive)
}

/// Check every entry of the archive open as `file`.
pub fn validate(file: &mut File) -> Result<()> {
    for entry in archive(file)?.entries()? {
        admit(&entry?)?;
    }
    Ok(())
}

/// Extract the archive open as `file` into `state`, checking each entry again
/// as it is read: [`validate`] keeps a bad archive from half-restoring, this
/// keeps the extraction safe even if the file changed in between.
/// `unpack_in` also refuses to write through a symlink that leaves `state`.
/// Permissions drop setuid/setgid/sticky; ownership is never restored.
pub fn unpack(file: &mut File, state: &Path) -> Result<()> {
    for entry in archive(file)?.entries()? {
        let mut entry = entry?;
        if !admit(&entry)? {
            continue;
        }
        let path = entry.path()?.into_owned();
        if !entry.unpack_in(state)? {
            bail!(
                "archive entry '{}' was refused by the extractor",
                path.display()
            );
        }
    }
    Ok(())
}

/// Symlinks already under `state` that resolve outside it. Extraction would
/// write through them, so restore refuses while any exist.
pub fn outward_links(state: &Path) -> Result<Vec<String>> {
    if state.symlink_metadata().is_err() {
        return Ok(Vec::new());
    }
    let root = state.canonicalize()?;
    let mut out = Vec::new();
    find_outward(&root, &root, &mut out)?;
    Ok(out)
}

fn find_outward(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let kind = fs::symlink_metadata(&path)?.file_type();
        if kind.is_dir() {
            find_outward(root, &path, out)?;
        } else if kind.is_symlink() && escapes(&path, root)? {
            out.push(path.to_string_lossy().into_owned());
        }
    }
    Ok(())
}

fn escapes(link: &Path, root: &Path) -> Result<bool> {
    if let Ok(resolved) = link.canonicalize() {
        return Ok(!resolved.starts_with(root));
    }
    // Dangling: judge where it would point once its target is created.
    let target = fs::read_link(link)?;
    let joined = match link.parent() {
        Some(parent) if target.is_relative() => parent.join(&target),
        _ => target,
    };
    let mut lexical = PathBuf::new();
    for c in joined.components() {
        match c {
            Component::ParentDir => {
                lexical.pop();
            }
            Component::CurDir => {}
            c => lexical.push(c),
        }
    }
    Ok(!lexical.starts_with(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn tree() -> tempfile::TempDir {
        let state = tempfile::tempdir().unwrap();
        let s = state.path();
        fs::create_dir_all(s.join("_lima/_config")).unwrap();
        fs::create_dir_all(s.join("default")).unwrap();
        fs::write(s.join("_lima/_config/user"), b"PRIVATE").unwrap();
        fs::write(s.join("_lima/_config/user.pub"), b"PUBLIC").unwrap();
        fs::write(s.join("default/colima.yaml"), b"cpu: 2").unwrap();
        symlink("colima.yaml", s.join("default/current")).unwrap();
        symlink(s.join("default"), s.join("absolute")).unwrap();
        state
    }

    #[test]
    fn pack_writes_0600_and_leaves_out_the_key_and_absolute_links() {
        let state = tree();
        let dest = tempfile::tempdir().unwrap();
        let (archive, excluded) = pack(state.path(), dest.path(), "stamp").unwrap();
        let mode = fs::metadata(&archive).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(
            !dest
                .path()
                .join(".docker-engine-state-stamp.tar.gz.partial")
                .exists()
        );
        assert_eq!(excluded.len(), 3, "{excluded:?}");

        let mut names = Vec::new();
        let mut ar = Archive::new(GzDecoder::new(File::open(&archive).unwrap()));
        for e in ar.entries().unwrap() {
            names.push(e.unwrap().path().unwrap().to_string_lossy().into_owned());
        }
        assert!(names.contains(&"default/colima.yaml".to_string()));
        assert!(names.contains(&"default/current".to_string()));
        assert!(
            !names
                .iter()
                .any(|n| n.ends_with("user") || n.ends_with("user.pub"))
        );
        assert!(!names.contains(&"absolute".to_string()));
    }

    #[test]
    fn pack_refuses_to_overwrite_an_archive() {
        let state = tree();
        let dest = tempfile::tempdir().unwrap();
        pack(state.path(), dest.path(), "stamp").unwrap();
        let err = pack(state.path(), dest.path(), "stamp").unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }

    #[test]
    fn pack_then_unpack_round_trips() {
        let state = tree();
        let dest = tempfile::tempdir().unwrap();
        let (archive, _) = pack(state.path(), dest.path(), "stamp").unwrap();
        let target = tempfile::tempdir().unwrap();
        let mut file = File::open(archive).unwrap();
        validate(&mut file).unwrap();
        unpack(&mut file, target.path()).unwrap();
        let t = target.path();
        assert_eq!(fs::read(t.join("default/current")).unwrap(), b"cpu: 2");
        assert!(!t.join("_lima/_config/user").exists());
    }

    #[test]
    fn unpack_drops_setuid() {
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("a.tar.gz");
        let mut builder = Builder::new(GzEncoder::new(
            File::create(&path).unwrap(),
            Compression::default(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_size(1);
        header.set_mode(0o4755);
        header.set_cksum();
        builder.append_data(&mut header, "suid", &b"x"[..]).unwrap();
        builder.into_inner().unwrap().finish().unwrap();
        let target = tempfile::tempdir().unwrap();
        unpack(&mut File::open(&path).unwrap(), target.path()).unwrap();
        let mode = fs::metadata(target.path().join("suid"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7000, 0);
    }

    #[test]
    fn outward_links_finds_links_leaving_the_state_dir() {
        let state = tree();
        let outside = tempfile::tempdir().unwrap();
        assert!(outward_links(state.path()).unwrap().is_empty());
        symlink(outside.path(), state.path().join("default/out")).unwrap();
        symlink("../../gone", state.path().join("default/dangling")).unwrap();
        let mut found = outward_links(state.path()).unwrap();
        found.sort();
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].ends_with("default/dangling") && found[1].ends_with("default/out"));
        assert!(
            outward_links(&state.path().join("missing"))
                .unwrap()
                .is_empty()
        );
    }
}
