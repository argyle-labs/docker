//! The engine-state archive behind `docker.backup` / `docker.restore`.
//!
//! Both directions run in-process over one open file: restore checks every
//! entry from the same reader it extracts from, so neither a swapped path nor
//! a crafted listing can slip an entry past the check.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
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

/// Lima's disk dir: colima's persistent data disk, holding the VM's container
/// images and volumes.
const DISKS_DIR: &str = "_lima/_disks";
/// Per-instance VM disks under `_lima/<instance>/` (`disk` links to
/// `diffdisk`).
const INSTANCE_DISKS: &[&str] = &["basedisk", "diffdisk", "disk"];
const IMAGE_EXTENSIONS: &[&str] = &["iso", "img", "qcow2", "raw"];

/// Backups are config only: VM and disk images are left out. `rel` is
/// relative to the colima root, whatever subdir is being backed up.
fn is_vm_image(rel: &Path) -> bool {
    if rel.starts_with(DISKS_DIR) {
        return true;
    }
    let parts: Vec<_> = rel.components().map(|c| c.as_os_str()).collect();
    if let [lima, _, name] = parts.as_slice()
        && *lima == "_lima"
        && name.to_str().is_some_and(|n| INSTANCE_DISKS.contains(&n))
    {
        return true;
    }
    rel.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| IMAGE_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

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
/// leaves out with the reason. Exclusions match paths relative to `root`
/// (the resolved `$HOME/.colima`), so backing up a subdir of it cannot pick up
/// the key or the disks.
pub fn members(state: &Path, root: &Path) -> Result<(Vec<PathBuf>, Vec<String>)> {
    let scope = state
        .strip_prefix(root)
        .with_context(|| format!("'{}' is not inside '{}'", state.display(), root.display()))?;
    let mut members = Vec::new();
    let mut excluded = Vec::new();
    walk(state, scope, Path::new(""), &mut members, &mut excluded)?;
    Ok((members, excluded))
}

fn walk(
    root: &Path,
    scope: &Path,
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
        let in_root = scope.join(&member);
        let shown = member.to_string_lossy().into_owned();
        if EXCLUDED.iter().any(|e| in_root == Path::new(e)) {
            excluded.push(format!("{shown}: lima's VM ssh key, regenerated on start"));
            continue;
        }
        if is_vm_image(&in_root) {
            excluded.push(format!(
                "{shown}: VM or disk image; backups are config only"
            ));
            continue;
        }
        let kind = fs::symlink_metadata(root.join(&member))?.file_type();
        if kind.is_dir() {
            members.push(member.clone());
            walk(root, scope, &member, members, excluded)?;
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
pub fn pack(state: &Path, root: &Path, dest: &Path, stamp: &str) -> Result<(PathBuf, Vec<String>)> {
    let (members, excluded) = members(state, root)?;
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

/// Ceilings on what one archive may expand to, so a gzip bomb fails the
/// check instead of filling the disk.
#[derive(Clone, Copy)]
pub struct Limits {
    pub bytes: u64,
    pub entries: usize,
}

pub const LIMITS: Limits = Limits {
    bytes: 4 << 30,
    entries: 100_000,
};

/// A reader that errors once more than `limit` bytes have come through.
struct Capped<R> {
    inner: R,
    left: u64,
    limit: u64,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.left = self.left.checked_sub(n as u64).ok_or_else(|| {
            io::Error::other(format!(
                "archive expands past {} bytes; refusing it",
                self.limit
            ))
        })?;
        Ok(n)
    }
}

/// How entries land on disk.
#[derive(Clone, Copy)]
struct Unpack {
    /// Mode bits cleared from every entry.
    mask: u32,
    /// Restore the archive's owners.
    owners: bool,
}

/// Engine state is the owner's alone.
const ENGINE: Unpack = Unpack {
    mask: 0o077,
    owners: false,
};

fn archive(
    file: &mut File,
    limits: Limits,
    unpack: Unpack,
) -> Result<Archive<Capped<GzDecoder<&mut File>>>> {
    file.seek(SeekFrom::Start(0))?;
    let mut archive = Archive::new(Capped {
        inner: GzDecoder::new(file),
        left: limits.bytes,
        limit: limits.bytes,
    });
    // Without preserved permissions the setuid, setgid and sticky bits are
    // dropped.
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(unpack.owners);
    archive.set_unpack_xattrs(false);
    // Without it the archive's mode bits land verbatim (an explicit chmod
    // that bypasses the umask), so a 0777 entry would be world-writable.
    archive.set_mask(unpack.mask);
    Ok(archive)
}

fn count(seen: &mut usize, limits: Limits) -> Result<()> {
    *seen += 1;
    if *seen > limits.entries {
        bail!(
            "archive has more than {} entries; refusing it",
            limits.entries
        );
    }
    Ok(())
}

/// Check every entry of the archive open as `file`.
pub fn validate(file: &mut File) -> Result<()> {
    validate_within(file, LIMITS)
}

fn validate_within(file: &mut File, limits: Limits) -> Result<()> {
    let mut seen = 0;
    for entry in archive(file, limits, ENGINE)?.entries()? {
        count(&mut seen, limits)?;
        admit(&entry?)?;
    }
    Ok(())
}

/// Extract `file` into `dir`, checking each entry again as it is read:
/// [`validate`] keeps a bad archive from getting this far, this keeps the
/// extraction safe even if the file changed in between. `unpack_in` also
/// refuses to write through a symlink that leaves `dir`. Mode bits are masked
/// to owner-only with no setuid/setgid/sticky; ownership is never restored.
fn extract(file: &mut File, dir: &Path, limits: Limits, unpack: Unpack) -> Result<()> {
    let mut seen = 0;
    for entry in archive(file, limits, unpack)?.entries()? {
        count(&mut seen, limits)?;
        let mut entry = entry?;
        if !admit(&entry)? {
            continue;
        }
        let path = entry.path()?.into_owned();
        if !entry.unpack_in(dir)? {
            bail!(
                "archive entry '{}' was refused by the extractor",
                path.display()
            );
        }
    }
    Ok(())
}

/// Extract a stack archive into `dir`, checking every entry as
/// [`extract`] does. Modes are kept but for the setuid, setgid and sticky
/// bits; owners are kept when running as root, as `tar` would.
pub(crate) fn extract_stack(file: &mut File, dir: &Path) -> Result<()> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    extract(
        file,
        dir,
        LIMITS,
        Unpack {
            mask: 0,
            owners: root,
        },
    )
}

/// Restore the archive open as `file` into `state` without ever leaving it
/// half-restored. The archive is extracted into a fresh sibling dir; whatever
/// the old `state` holds that the archive does not (the VM disks a
/// config-only backup leaves out) is moved across, as extracting over it
/// would have kept it; then the dirs are swapped by rename. Any failure
/// before the swap completes puts everything back. Returns the old dir when
/// it could not be removed afterwards.
pub fn restore_into(file: &mut File, state: &Path) -> Result<Option<PathBuf>> {
    restore_within(file, state, LIMITS)
}

fn restore_within(file: &mut File, state: &Path, limits: Limits) -> Result<Option<PathBuf>> {
    let (Some(parent), Some(name)) = (state.parent(), state.file_name()) else {
        bail!("state dir '{}' has no parent", state.display());
    };
    let name = name.to_string_lossy();
    let pid = std::process::id();
    let staging = parent.join(format!(".{name}.restore-{pid}"));
    DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .with_context(|| format!("failed to create '{}'", staging.display()))?;
    let discard = |e: plugin_toolkit::anyhow::Error| {
        let _removed = fs::remove_dir_all(&staging);
        e
    };
    extract(file, &staging, limits, ENGINE).map_err(discard)?;
    if state.symlink_metadata().is_err() {
        fs::rename(&staging, state)
            .with_context(|| format!("failed to move the restore into '{}'", state.display()))
            .map_err(discard)?;
        return Ok(None);
    }
    let mut moved = Vec::new();
    if let Err(e) = carry_over(state, &staging, Path::new(""), &mut moved) {
        return Err(abandon(e, &moved, &staging, state));
    }
    let aside = parent.join(format!(".{name}.old-{pid}"));
    if let Err(e) = fs::rename(state, &aside) {
        let e = anyhow!(e).context(format!("failed to move '{}' aside", state.display()));
        return Err(abandon(e, &moved, &staging, state));
    }
    if let Err(e) = fs::rename(&staging, state) {
        let mut e = anyhow!(e).context(format!(
            "failed to move the restore into '{}'",
            state.display()
        ));
        if let Err(back) = fs::rename(&aside, state) {
            e = e.context(format!(
                "and failed to put the previous state back from '{}' (kept entries are in '{}'): {back}",
                aside.display(),
                staging.display()
            ));
            return Err(e);
        }
        return Err(abandon(e, &moved, &staging, state));
    }
    Ok(fs::remove_dir_all(&aside).err().map(|_| aside))
}

/// Move everything under `old` that has no counterpart under `new` across,
/// recording each move relative to the roots. A path that is a directory on
/// one side and not on the other is refused: either way the swap would drop
/// the old subtree.
pub(crate) fn carry_over(
    old: &Path,
    new: &Path,
    rel: &Path,
    moved: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut names: Vec<_> = fs::read_dir(old.join(rel))?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<io::Result<_>>()?;
    names.sort();
    for name in names {
        let r = rel.join(name);
        let (from, to) = (old.join(&r), new.join(&r));
        match to.symlink_metadata() {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::rename(&from, &to)
                    .with_context(|| format!("failed to keep '{}'", from.display()))?;
                moved.push(r);
            }
            Err(e) => return Err(e.into()),
            Ok(m) => match (m.is_dir(), fs::symlink_metadata(&from)?.is_dir()) {
                (true, true) => carry_over(old, new, &r, moved)?,
                // The archive's file wins, as it would extracting over it.
                (false, false) => {}
                (in_archive, _) => bail!(
                    "'{}' is a {} in the archive but a {} in the state dir; refusing to replace it",
                    r.display(),
                    if in_archive {
                        "directory"
                    } else {
                        "non-directory"
                    },
                    if in_archive {
                        "non-directory"
                    } else {
                        "directory"
                    },
                ),
            },
        }
    }
    Ok(())
}

/// Undo a failed swap: move carried-over entries back from `staging` to
/// `state`, newest first, and remove `staging` only if every one made it back;
/// otherwise keep it and name it, since it still holds them.
pub(crate) fn abandon(
    e: plugin_toolkit::anyhow::Error,
    moved: &[PathBuf],
    staging: &Path,
    state: &Path,
) -> plugin_toolkit::anyhow::Error {
    let stuck: Vec<String> = moved
        .iter()
        .rev()
        .filter(|r| fs::rename(staging.join(r), state.join(r)).is_err())
        .map(|r| r.to_string_lossy().into_owned())
        .collect();
    if stuck.is_empty() {
        let _removed = fs::remove_dir_all(staging);
        return e;
    }
    e.context(format!(
        "and could not move back into '{}': {}; they remain in '{}'",
        state.display(),
        stuck.join(", "),
        staging.display()
    ))
}

/// The path the open `file` actually refers to, from the descriptor itself.
#[cfg(target_os = "macos")]
pub fn fd_path(file: &File) -> Result<PathBuf> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes at most PATH_MAX bytes into `buf`, which is
    // exactly that long and outlives the call.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc == -1 {
        return Err(io::Error::last_os_error().into());
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..len])))
}

/// The path the open `file` actually refers to, from the descriptor itself.
#[cfg(target_os = "linux")]
pub fn fd_path(file: &File) -> Result<PathBuf> {
    use std::os::fd::AsRawFd;
    Ok(fs::read_link(format!(
        "/proc/self/fd/{}",
        file.as_raw_fd()
    ))?)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn fd_path(_file: &File) -> Result<PathBuf> {
    bail!("cannot read an open file's path on this platform")
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
        let (archive, excluded) = pack(state.path(), state.path(), dest.path(), "stamp").unwrap();
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
    fn vm_and_disk_images_are_left_out() {
        for p in [
            "_lima/_disks",
            "_lima/colima/basedisk",
            "_lima/colima/diffdisk",
            "_lima/colima/disk",
            "_lima/colima/cidata.iso",
            "default/vm.qcow2",
            "x.IMG",
        ] {
            assert!(is_vm_image(Path::new(p)), "{p}");
        }
        for p in [
            "_lima/colima/colima.yaml",
            "_lima/colima/vz-efi",
            "_lima/_config/networks.yaml",
            "default/disk",
            "_lima/_disks.yaml",
        ] {
            assert!(!is_vm_image(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn pack_leaves_out_lima_disks() {
        let state = tree();
        let s = state.path();
        fs::create_dir_all(s.join("_lima/_disks/colima")).unwrap();
        fs::create_dir_all(s.join("_lima/colima")).unwrap();
        fs::write(s.join("_lima/_disks/colima/datadisk"), b"disk").unwrap();
        fs::write(s.join("_lima/colima/diffdisk"), b"disk").unwrap();
        fs::write(s.join("_lima/colima/lima.yaml"), b"cfg").unwrap();
        let (members, excluded) = members(s, s).unwrap();
        assert!(members.contains(&PathBuf::from("_lima/colima/lima.yaml")));
        assert!(
            !members
                .iter()
                .any(|m| m.starts_with("_lima/_disks") || m.ends_with("diffdisk"))
        );
        assert!(excluded.iter().any(|e| e.starts_with("_lima/_disks:")));
        assert!(
            excluded
                .iter()
                .any(|e| e.starts_with("_lima/colima/diffdisk:"))
        );
    }

    #[test]
    fn pack_refuses_to_overwrite_an_archive() {
        let state = tree();
        let dest = tempfile::tempdir().unwrap();
        pack(state.path(), state.path(), dest.path(), "stamp").unwrap();
        let err = pack(state.path(), state.path(), dest.path(), "stamp").unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }

    #[test]
    fn a_subdir_backup_still_leaves_out_the_key_and_disks() {
        let state = tree();
        let s = state.path();
        fs::create_dir_all(s.join("_lima/_disks/colima")).unwrap();
        fs::write(s.join("_lima/_disks/colima/datadisk"), b"disk").unwrap();
        fs::write(s.join("_lima/_config/networks.yaml"), b"cfg").unwrap();
        let (members, excluded) = members(&s.join("_lima"), s).unwrap();
        assert_eq!(
            members,
            [
                PathBuf::from("_config"),
                PathBuf::from("_config/networks.yaml")
            ]
        );
        assert_eq!(excluded.len(), 3, "{excluded:?}");
        let (disks, _) = super::members(&s.join("_lima/_disks"), s).unwrap();
        assert!(disks.is_empty(), "{disks:?}");
    }

    /// A `.tar.gz` of `entries` as `(name, mode, body)`; a `None` body is a
    /// directory.
    fn built(dir: &Path, entries: &[(&str, u32, Option<&[u8]>)]) -> PathBuf {
        let path = dir.join("built.tar.gz");
        let mut builder = Builder::new(GzEncoder::new(
            File::create(&path).unwrap(),
            Compression::default(),
        ));
        for (name, mode, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_mode(*mode);
            match body {
                Some(b) => {
                    h.set_entry_type(EntryType::Regular);
                    h.set_size(b.len() as u64);
                    h.set_cksum();
                    builder.append_data(&mut h, name, *b).unwrap();
                }
                None => {
                    h.set_entry_type(EntryType::Directory);
                    h.set_size(0);
                    h.set_cksum();
                    builder.append_data(&mut h, name, io::empty()).unwrap();
                }
            }
        }
        builder.into_inner().unwrap().finish().unwrap();
        path
    }

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn pack_then_restore_round_trips() {
        let state = tree();
        let dest = tempfile::tempdir().unwrap();
        let (archive, _) = pack(state.path(), state.path(), dest.path(), "stamp").unwrap();
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join(".colima");
        let mut file = File::open(archive).unwrap();
        validate(&mut file).unwrap();
        assert_eq!(restore_into(&mut file, &target).unwrap(), None);
        assert_eq!(fs::read(target.join("default/current")).unwrap(), b"cpu: 2");
        assert!(!target.join("_lima/_config/user").exists());
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 1);
    }

    #[test]
    fn restore_masks_modes_to_the_owner() {
        let work = tempfile::tempdir().unwrap();
        let archive = built(
            work.path(),
            &[
                ("open", 0o777, None),
                ("open/shared", 0o666, Some(b"x")),
                ("suid", 0o4755, Some(b"x")),
            ],
        );
        let target = work.path().join("state");
        restore_into(&mut File::open(&archive).unwrap(), &target).unwrap();
        assert_eq!(mode(&target.join("open")) & 0o077, 0);
        assert_eq!(mode(&target.join("open/shared")) & 0o077, 0);
        assert_eq!(mode(&target.join("suid")) & 0o7077, 0);
    }

    #[test]
    fn restore_replaces_config_and_keeps_what_the_archive_lacks() {
        let work = tempfile::tempdir().unwrap();
        let state = work.path().join("state");
        fs::create_dir_all(state.join("_lima/_disks/colima")).unwrap();
        fs::create_dir_all(state.join("default")).unwrap();
        fs::write(state.join("_lima/_disks/colima/datadisk"), b"disk").unwrap();
        fs::write(state.join("default/colima.yaml"), b"old").unwrap();
        fs::write(state.join("default/extra"), b"kept").unwrap();
        let archive = built(
            work.path(),
            &[
                ("default", 0o755, None),
                ("default/colima.yaml", 0o644, Some(b"new")),
            ],
        );
        assert_eq!(
            restore_into(&mut File::open(&archive).unwrap(), &state).unwrap(),
            None
        );
        assert_eq!(fs::read(state.join("default/colima.yaml")).unwrap(), b"new");
        assert_eq!(fs::read(state.join("default/extra")).unwrap(), b"kept");
        assert_eq!(
            fs::read(state.join("_lima/_disks/colima/datadisk")).unwrap(),
            b"disk"
        );
        let left: Vec<_> = fs::read_dir(work.path()).unwrap().collect();
        assert_eq!(left.len(), 2, "staging or the old dir was left behind");
    }

    #[test]
    fn a_failing_restore_leaves_the_state_dir_untouched() {
        let work = tempfile::tempdir().unwrap();
        let state = work.path().join("state");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("colima.yaml"), b"old").unwrap();
        let big = vec![b'x'; 64 * 1024];
        let archive = built(
            work.path(),
            &[
                ("colima.yaml", 0o644, Some(b"new")),
                ("big", 0o644, Some(&big)),
            ],
        );
        let limits = Limits {
            bytes: 16 * 1024,
            entries: 10,
        };
        let err = restore_within(&mut File::open(&archive).unwrap(), &state, limits).unwrap_err();
        assert!(format!("{err:#}").contains("expands past"), "{err:#}");
        assert_eq!(fs::read(state.join("colima.yaml")).unwrap(), b"old");
        assert_eq!(fs::read_dir(&state).unwrap().count(), 1);
        let left: Vec<_> = fs::read_dir(work.path()).unwrap().collect();
        assert_eq!(left.len(), 2, "staging was left behind");
    }

    #[test]
    fn restore_refuses_a_file_over_a_directory_and_keeps_the_old_state() {
        let work = tempfile::tempdir().unwrap();
        let state = work.path().join("state");
        fs::create_dir_all(state.join("_lima/_disks/colima")).unwrap();
        fs::write(state.join("_lima/_disks/colima/datadisk"), b"disk").unwrap();
        fs::write(state.join("a-kept"), b"kept").unwrap();
        let archive = built(work.path(), &[("_lima", 0o644, Some(b"file"))]);
        let err = restore_into(&mut File::open(&archive).unwrap(), &state).unwrap_err();
        assert!(
            err.to_string()
                .contains("'_lima' is a non-directory in the archive"),
            "{err:#}"
        );
        assert_eq!(
            fs::read(state.join("_lima/_disks/colima/datadisk")).unwrap(),
            b"disk"
        );
        assert_eq!(fs::read(state.join("a-kept")).unwrap(), b"kept");
        assert_eq!(fs::read_dir(work.path()).unwrap().count(), 2);
    }

    #[test]
    fn restore_refuses_a_directory_over_a_file() {
        let work = tempfile::tempdir().unwrap();
        let state = work.path().join("state");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("colima.yaml"), b"old").unwrap();
        let archive = built(work.path(), &[("colima.yaml", 0o755, None)]);
        let err = restore_into(&mut File::open(&archive).unwrap(), &state).unwrap_err();
        assert!(
            err.to_string().contains("is a directory in the archive"),
            "{err:#}"
        );
        assert_eq!(fs::read(state.join("colima.yaml")).unwrap(), b"old");
    }

    #[test]
    fn abandon_keeps_staging_when_an_entry_cannot_move_back() {
        let work = tempfile::tempdir().unwrap();
        let (staging, state) = (work.path().join("staging"), work.path().join("state"));
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("back"), b"b").unwrap();
        fs::write(staging.join("stuck"), b"s").unwrap();
        // A non-empty directory where `stuck` must return blocks the rename.
        fs::create_dir_all(state.join("stuck/occupied")).unwrap();
        let moved = [PathBuf::from("back"), PathBuf::from("stuck")];
        let err = abandon(anyhow!("boom"), &moved, &staging, &state);
        let msg = format!("{err:#}");
        assert!(msg.contains("stuck") && msg.contains("remain in"), "{msg}");
        assert_eq!(fs::read(state.join("back")).unwrap(), b"b");
        assert_eq!(fs::read(staging.join("stuck")).unwrap(), b"s");

        fs::remove_dir_all(state.join("stuck")).unwrap();
        abandon(anyhow!("boom"), &[PathBuf::from("stuck")], &staging, &state);
        assert_eq!(fs::read(state.join("stuck")).unwrap(), b"s");
        assert!(!staging.exists());
    }

    #[test]
    fn validate_caps_bytes_and_entries() {
        let work = tempfile::tempdir().unwrap();
        let big = vec![0u8; 1 << 20];
        let archive = built(
            work.path(),
            &[("a", 0o644, Some(&big)), ("b", 0o644, Some(b"x"))],
        );
        let mut file = File::open(&archive).unwrap();
        validate(&mut file).unwrap();
        let bytes = Limits {
            bytes: 64 * 1024,
            entries: 10,
        };
        let err = validate_within(&mut file, bytes).unwrap_err();
        assert!(format!("{err:#}").contains("expands past"), "{err:#}");
        let entries = Limits {
            bytes: 1 << 30,
            entries: 1,
        };
        let err = validate_within(&mut file, entries).unwrap_err();
        assert!(err.to_string().contains("more than 1 entries"), "{err}");
    }

    #[test]
    fn fd_path_names_the_opened_file() {
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("f");
        fs::write(&path, b"x").unwrap();
        let file = File::open(&path).unwrap();
        assert_eq!(fd_path(&file).unwrap(), path.canonicalize().unwrap());
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
