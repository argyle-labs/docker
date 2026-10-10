//! The host's init system and its service config files, read and edited
//! through files only (never a subprocess).
#![allow(clippy::disallowed_types)]

use std::io::Write;
use std::path::Path;

use plugin_toolkit::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Init {
    OpenRc,
    Systemd,
    Other,
}

impl Init {
    pub fn as_str(self) -> &'static str {
        match self {
            Init::OpenRc => "openrc",
            Init::Systemd => "systemd",
            Init::Other => "other",
        }
    }
}

/// The init running under `root`, by the runtime dirs each creates at boot.
/// systemd is checked first: an installed `openrc-run` binary alone does not
/// mean OpenRC is PID 1.
pub fn detect(root: &Path) -> Init {
    if root.join("run/systemd/system").is_dir() {
        Init::Systemd
    } else if root.join("run/openrc").is_dir() {
        Init::OpenRc
    } else {
        Init::Other
    }
}

/// `KEY=value` with `"…"`, `'…'` or no quotes, as OpenRC's conf.d files are
/// sourced by sh.
fn value_of<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let v = line
        .trim_start()
        .strip_prefix(key)?
        .strip_prefix('=')?
        .trim_end();
    Some(
        v.strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(v),
    )
}

/// `conf` with `key` set to `value`, edited in place: the first assignment is
/// replaced, later ones dropped, and a missing one appended. In place keeps
/// edits by different tools stable in either order.
pub fn set_var(conf: &str, key: &str, value: &str) -> String {
    let mut out = Vec::new();
    let mut set = false;
    for line in conf.lines() {
        if value_of(line, key).is_some() {
            if !set {
                out.push(format!("{key}=\"{value}\""));
                set = true;
            }
        } else {
            out.push(line.to_owned());
        }
    }
    if !set {
        out.push(format!("{key}=\"{value}\""));
    }
    out.join("\n") + "\n"
}

/// `conf` with `word` among the space-separated words of `key`, others kept.
pub fn add_word(conf: &str, key: &str, word: &str) -> String {
    let mut words: Vec<&str> = conf
        .lines()
        .find_map(|l| value_of(l, key))
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    if words.contains(&word) && conf.lines().filter(|l| value_of(l, key).is_some()).count() == 1 {
        return conf.to_owned();
    }
    if !words.contains(&word) {
        words.push(word);
    }
    set_var(conf, key, &words.join(" "))
}

/// Replace `path` with `content` via a temp file in the same dir and a
/// rename, so a crash never leaves it half-written.
pub fn write_atomic(path: &Path, content: &str, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("'{}' has no parent", path.display()))?;
    std::fs::create_dir_all(dir)?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = dir.join(format!(".{name}.orca-{}", std::process::id()));
    let result = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _removed = std::fs::remove_file(&tmp);
    }
    result.with_context(|| format!("failed to write '{}'", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_wins_over_an_installed_openrc() {
        let t = tempfile::tempdir().unwrap();
        assert_eq!(detect(t.path()), Init::Other);
        std::fs::create_dir_all(t.path().join("run/openrc")).unwrap();
        assert_eq!(detect(t.path()), Init::OpenRc);
        std::fs::create_dir_all(t.path().join("run/systemd/system")).unwrap();
        assert_eq!(detect(t.path()), Init::Systemd);
    }

    #[test]
    fn set_var_edits_in_place_and_drops_duplicates() {
        assert_eq!(set_var("", "A", "1"), "A=\"1\"\n");
        let conf = "# c\nA='0'\nB=x\nA=2\n";
        assert_eq!(set_var(conf, "A", "1"), "# c\nA=\"1\"\nB=x\n");
        assert_eq!(set_var("AB=1\n", "A", "1"), "AB=1\nA=\"1\"\n");
    }

    #[test]
    fn add_word_keeps_other_words_and_quoting_variants() {
        assert_eq!(
            add_word("rc_use='localmount'\n", "rc_use", "netmount"),
            "rc_use=\"localmount netmount\"\n"
        );
        assert_eq!(
            add_word("rc_use=netmount\n", "rc_use", "netmount"),
            "rc_use=netmount\n"
        );
        assert_eq!(add_word("", "rc_use", "netmount"), "rc_use=\"netmount\"\n");
    }

    #[test]
    fn edits_by_two_tools_are_stable_in_either_order() {
        let ulimit = |c: &str| set_var(c, "DOCKER_ULIMIT", "-n 524288");
        let net = |c: &str| add_word(&add_word(c, "rc_use", "netmount"), "rc_after", "netmount");
        let base = "DOCKER_OPTS=\"\"\n";
        let ab = net(&ulimit(base));
        let ba = ulimit(&net(base));
        for c in [&ab, &ba] {
            assert_eq!(&ulimit(c), c);
            assert_eq!(&net(c), c);
        }
    }

    #[test]
    fn write_atomic_replaces_and_sets_mode() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("etc/conf.d/docker");
        write_atomic(&p, "a\n", 0o644).unwrap();
        write_atomic(&p, "b\n", 0o755).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "b\n");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(std::fs::read_dir(p.parent().unwrap()).unwrap().count(), 1);
    }
}
