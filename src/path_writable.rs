//! `docker.path_writable` — whether the plugin's own user can create files in
//! a directory, proven by creating and removing a temp file there.

use std::path::Path;

use plugin_toolkit::prelude::*;

#[orca_struct(args)]
pub struct DockerPathWritableArgs {
    /// Absolute directory to probe.
    #[arg(long)]
    pub path: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathWritableOutput {
    pub path: String,
    pub writable: bool,
    pub uid: u32,
    pub gid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn probe(path: &str) -> Result<PathWritableOutput> {
    let dir = Path::new(path);
    if !dir.is_absolute() {
        bail!("'{path}' is not an absolute path");
    }
    let meta = std::fs::symlink_metadata(dir).with_context(|| format!("stat {path}"))?;
    if !meta.is_dir() {
        bail!("'{path}' is not a directory");
    }
    let error = tempfile::Builder::new()
        .prefix(".orca-probe-")
        .tempfile_in(dir)
        .and_then(|f| f.close())
        .err()
        .map(|e| e.to_string());
    Ok(PathWritableOutput {
        path: path.to_owned(),
        writable: error.is_none(),
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        error,
    })
}

/// **Can orca write here**: creates and removes a temp file in `path` as the
/// plugin's user and reports whether that worked, with the uid/gid tried.
#[orca_tool(domain = "docker", verb = "path_writable", role = "read")]
async fn docker_path_writable(
    args: DockerPathWritableArgs,
    _ctx: &ToolCtx,
) -> Result<PathWritableOutput> {
    probe(&args.path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_writable_dir_is_reported_and_left_clean() {
        let dir = tempfile::tempdir().unwrap();
        let out = probe(dir.path().to_str().unwrap()).unwrap();
        assert!(out.writable, "{out:?}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_read_only_dir_is_not_writable() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let out = probe(dir.path().to_str().unwrap()).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!out.writable);
        assert!(out.error.is_some());
    }

    #[test]
    fn relative_missing_and_non_dir_paths_are_refused() {
        assert!(probe("rel/dir").is_err());
        assert!(probe("/definitely/not/here").is_err());
        let f = tempfile::NamedTempFile::new().unwrap();
        assert!(probe(f.path().to_str().unwrap()).is_err());
    }
}
