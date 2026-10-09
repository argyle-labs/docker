//! Descriptor-relative file operations for stack dirs.
//!
//! Every name is one path component resolved against an open directory with
//! `O_NOFOLLOW`, so a symlink planted at a name (or swapped in for a directory
//! between a check and a write) fails the call instead of redirecting it.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy)]
pub struct Stat {
    pub kind: Kind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Whether `name` is exactly one normal path component.
pub fn is_single_component(name: &str) -> bool {
    let mut parts = Path::new(name).components();
    matches!(
        (parts.next(), parts.next()),
        (Some(Component::Normal(_)), None)
    ) && !name.contains('/')
}

fn cname(name: &str) -> io::Result<CString> {
    if !is_single_component(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("'{name}' is not a single path component"),
        ));
    }
    CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn check(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// Open the directory at `path`, refusing a symlink as its last component.
pub fn open_dir(path: &Path) -> io::Result<File> {
    let p = cpath(path)?;
    // SAFETY: `p` is a valid NUL-terminated path for the call's duration; a
    // returned descriptor is owned by the new `File`.
    let fd = check(unsafe {
        libc::open(
            p.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    // SAFETY: `fd` was just opened and is owned by nothing else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Open `name` under `dir` with `flags`, never following a symlink at it.
// `mode_t` is u16 on macOS and u32 on Linux.
#[allow(clippy::unnecessary_cast)]
pub fn open_at(dir: &File, name: &str, flags: libc::c_int, mode: libc::mode_t) -> io::Result<File> {
    let n = cname(name)?;
    // SAFETY: `dir` is an open descriptor and `n` a valid C string for the
    // call; a returned descriptor is owned by the new `File`.
    let fd = check(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            n.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    })?;
    // SAFETY: `fd` was just opened and is owned by nothing else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub fn open_dir_at(dir: &File, name: &str) -> io::Result<File> {
    open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
}

pub fn mkdir_at(dir: &File, name: &str, mode: libc::mode_t) -> io::Result<()> {
    let n = cname(name)?;
    // SAFETY: valid descriptor and C string for the call's duration.
    check(unsafe { libc::mkdirat(dir.as_raw_fd(), n.as_ptr(), mode) }).map(|_| ())
}

pub fn rename_at(dir: &File, from: &str, to: &str) -> io::Result<()> {
    let (f, t) = (cname(from)?, cname(to)?);
    // SAFETY: valid descriptor and C strings for the call's duration.
    check(unsafe { libc::renameat(dir.as_raw_fd(), f.as_ptr(), dir.as_raw_fd(), t.as_ptr()) })
        .map(|_| ())
}

pub fn unlink_at(dir: &File, name: &str) -> io::Result<()> {
    let n = cname(name)?;
    // SAFETY: valid descriptor and C string for the call's duration.
    check(unsafe { libc::unlinkat(dir.as_raw_fd(), n.as_ptr(), 0) }).map(|_| ())
}

// `st_mode` is u16 on macOS and u32 on Linux.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn to_stat(st: &libc::stat) -> Stat {
    let mode = st.st_mode as u32;
    let kind = match mode & (libc::S_IFMT as u32) {
        m if m == libc::S_IFREG as u32 => Kind::File,
        m if m == libc::S_IFDIR as u32 => Kind::Dir,
        m if m == libc::S_IFLNK as u32 => Kind::Symlink,
        _ => Kind::Other,
    };
    Stat {
        kind,
        mode: mode & 0o7777,
        uid: st.st_uid,
        gid: st.st_gid,
    }
}

/// `name` under `dir` without following a symlink, or `None` when absent.
pub fn stat_at(dir: &File, name: &str) -> io::Result<Option<Stat>> {
    let n = cname(name)?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid descriptor and C string; `st` is written by a successful
    // call before it is read.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            n.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == -1 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(e)
        };
    }
    // SAFETY: fstatat succeeded, so `st` is initialized.
    let st = unsafe { st.assume_init() };
    Ok(Some(to_stat(&st)))
}

// `mode_t` is u16 on macOS and u32 on Linux.
#[allow(clippy::unnecessary_cast)]
pub fn set_mode(file: &File, mode: u32) -> io::Result<()> {
    // SAFETY: valid descriptor for the call's duration.
    check(unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) }).map(|_| ())
}

/// Give `file` to `uid:gid`. Only root may give a file away; a same-owner
/// chown is a no-op, so a permission error is ignored.
pub fn set_owner(file: &File, uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: valid descriptor for the call's duration.
    match check(unsafe { libc::fchown(file.as_raw_fd(), uid, gid) }) {
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        other => other.map(|_| ()),
    }
}

/// A fresh 0700 dir under the system temp dir, removed with its contents on
/// drop. Only its owner can write in it, and the temp dir's sticky bit keeps
/// anyone else from renaming it away.
pub struct PrivateDir {
    path: PathBuf,
    fd: File,
}

impl PrivateDir {
    pub fn new(prefix: &str) -> io::Result<Self> {
        let template = std::env::temp_dir().join(format!("{prefix}XXXXXX"));
        let mut buf = cpath(&template)?.into_bytes_with_nul();
        // SAFETY: `buf` is a writable NUL-terminated template; mkdtemp
        // rewrites the trailing Xs in place.
        if unsafe { libc::mkdtemp(buf.as_mut_ptr().cast()) }.is_null() {
            return Err(io::Error::last_os_error());
        }
        buf.pop();
        let path = PathBuf::from(std::ffi::OsString::from_vec(buf));
        let fd = open_dir(&path)?;
        Ok(PrivateDir { path, fd })
    }

    /// Create `name` (0600) in the dir with `contents`; its path.
    pub fn write(&self, name: &str, contents: &[u8]) -> io::Result<PathBuf> {
        use std::io::Write;
        let mut f = open_at(
            &self.fd,
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        f.write_all(contents)?;
        Ok(self.path.join(name))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        // Best effort: a leftover dir is private to its owner.
        let _removed = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn names_must_be_one_component() {
        for ok in ["a", "compose.yaml", ".env"] {
            assert!(is_single_component(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "/a", "a/"] {
            assert!(!is_single_component(bad), "{bad}");
        }
    }

    #[test]
    fn symlinks_are_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("f"), b"x").unwrap();
        symlink(outside.path().join("f"), dir.path().join("link")).unwrap();
        symlink(outside.path(), dir.path().join("dlink")).unwrap();
        let d = open_dir(dir.path()).unwrap();
        assert!(open_at(&d, "link", libc::O_RDONLY, 0).is_err());
        assert!(open_dir_at(&d, "dlink").is_err());
        assert_eq!(stat_at(&d, "link").unwrap().unwrap().kind, Kind::Symlink);
        assert!(stat_at(&d, "missing").unwrap().is_none());
        assert!(open_dir(&dir.path().join("dlink")).is_err());
    }

    #[test]
    fn a_private_dir_is_owner_only_and_removed_on_drop() {
        use std::os::unix::fs::PermissionsExt;
        let d = PrivateDir::new("orca-test-").unwrap();
        let mode = std::fs::metadata(d.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let f = d.write("c.json", b"{}").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"{}");
        assert!(d.write("c.json", b"x").is_err(), "never overwrites");
        let path = d.path().to_path_buf();
        drop(d);
        assert!(!path.exists());
    }
}
