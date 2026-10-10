//! Pins `scripts/restore.sh`: staged swap, size/entry caps, outward-symlink
//! refusal, and an untouched state dir on any failure.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.sh")
}

/// Build `archive.tar.gz` under `root` from `files` (relative path, contents).
fn archive(root: &Path, files: &[(&str, &str)]) -> PathBuf {
    let src = root.join("src");
    for (rel, body) in files {
        let p = src.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }
    let out = root.join("archive.tar.gz");
    let ok = Command::new("tar")
        .arg("-czf")
        .arg(&out)
        .arg("-C")
        .arg(&src)
        .arg(".")
        .status()
        .unwrap()
        .success();
    assert!(ok);
    out
}

fn restore(archive: &Path, state: &Path, env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("bash");
    cmd.arg(script()).arg(archive).arg(state);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

fn leftovers(parent: &Path) -> Vec<String> {
    fs::read_dir(parent)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".restore-") || n.contains(".old-"))
        .collect()
}

#[test]
fn restores_into_a_fresh_state_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let a = archive(tmp.path(), &[("colima.yaml", "new"), ("sub/x", "1")]);
    let state = tmp.path().join("state");
    let out = restore(&a, &state, &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read_to_string(state.join("colima.yaml")).unwrap(),
        "new"
    );
    assert_eq!(fs::read_to_string(state.join("sub/x")).unwrap(), "1");
    assert!(leftovers(tmp.path()).is_empty());
}

#[test]
fn replaces_archived_entries_and_carries_over_the_rest() {
    let tmp = tempfile::tempdir().unwrap();
    let a = archive(tmp.path(), &[("colima.yaml", "new"), ("sub/x", "1")]);
    let state = tmp.path().join("state");
    fs::create_dir_all(state.join("sub")).unwrap();
    fs::create_dir_all(state.join("_lima/_disks")).unwrap();
    fs::write(state.join("colima.yaml"), "old").unwrap();
    fs::write(state.join("sub/kept"), "k").unwrap();
    fs::write(state.join(".hidden"), "h").unwrap();
    fs::write(state.join("_lima/_disks/disk"), "d").unwrap();
    let out = restore(&a, &state, &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read_to_string(state.join("colima.yaml")).unwrap(),
        "new"
    );
    assert_eq!(fs::read_to_string(state.join("sub/kept")).unwrap(), "k");
    assert_eq!(fs::read_to_string(state.join(".hidden")).unwrap(), "h");
    assert_eq!(
        fs::read_to_string(state.join("_lima/_disks/disk")).unwrap(),
        "d"
    );
    assert!(leftovers(tmp.path()).is_empty());
}

#[test]
fn a_type_conflict_fails_and_puts_carried_entries_back() {
    let tmp = tempfile::tempdir().unwrap();
    // "a" sorts before "z", so "a" is carried over before "z" conflicts.
    let a = archive(tmp.path(), &[("z", "file in archive")]);
    let state = tmp.path().join("state");
    fs::create_dir_all(state.join("z")).unwrap();
    fs::write(state.join("a"), "carried").unwrap();
    let out = restore(&a, &state, &[]);
    assert!(!out.status.success());
    assert_eq!(fs::read_to_string(state.join("a")).unwrap(), "carried");
    assert!(state.join("z").is_dir());
    assert!(leftovers(tmp.path()).is_empty());
}

#[test]
fn refuses_an_archive_over_the_byte_cap() {
    let tmp = tempfile::tempdir().unwrap();
    let a = archive(tmp.path(), &[("big", &"x".repeat(64 * 1024))]);
    let state = tmp.path().join("state");
    let out = restore(&a, &state, &[("RESTORE_MAX_BYTES", "4096")]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("expands past"));
    assert!(!state.exists());
    assert!(leftovers(tmp.path()).is_empty());
}

#[test]
fn refuses_an_archive_over_the_entry_cap() {
    let tmp = tempfile::tempdir().unwrap();
    let a = archive(tmp.path(), &[("a", ""), ("b", ""), ("c", "")]);
    let state = tmp.path().join("state");
    let out = restore(&a, &state, &[("RESTORE_MAX_ENTRIES", "2")]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("entries"));
    assert!(!state.exists());
}

#[test]
fn refuses_a_state_dir_holding_an_outward_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let a = archive(tmp.path(), &[("colima.yaml", "new")]);
    let state = tmp.path().join("state");
    fs::create_dir_all(&state).unwrap();
    fs::write(state.join("colima.yaml"), "old").unwrap();
    std::os::unix::fs::symlink("/etc", state.join("escape")).unwrap();
    let out = restore(&a, &state, &[]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("leaves the state dir"));
    assert_eq!(
        fs::read_to_string(state.join("colima.yaml")).unwrap(),
        "old"
    );
    assert!(leftovers(tmp.path()).is_empty());
}

#[test]
fn refuses_an_archive_carrying_an_outward_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    std::os::unix::fs::symlink("/etc", src.join("escape")).unwrap();
    let a = archive(tmp.path(), &[("colima.yaml", "new")]);
    let state = tmp.path().join("state");
    fs::create_dir_all(&state).unwrap();
    fs::write(state.join("colima.yaml"), "old").unwrap();
    let out = restore(&a, &state, &[]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("leaves the state dir"));
    assert_eq!(
        fs::read_to_string(state.join("colima.yaml")).unwrap(),
        "old"
    );
    assert!(leftovers(tmp.path()).is_empty());
}

#[test]
fn keeps_an_absolute_symlink_inside_the_state_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let a = archive(&root, &[("colima.yaml", "new")]);
    let state = root.join("state");
    fs::create_dir_all(state.join("d")).unwrap();
    std::os::unix::fs::symlink(state.join("d"), state.join("abs")).unwrap();
    let out = restore(&a, &state, &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read_link(state.join("abs")).unwrap(), state.join("d"));
}

#[test]
fn a_stale_aside_dir_is_neither_reused_nor_touched() {
    let tmp = tempfile::tempdir().unwrap();
    let a = archive(tmp.path(), &[("colima.yaml", "new")]);
    let state = tmp.path().join("state");
    fs::create_dir_all(&state).unwrap();
    let stale = tmp.path().join(".state.old-1");
    fs::create_dir_all(&stale).unwrap();
    fs::write(stale.join("keep"), "x").unwrap();
    let out = restore(&a, &state, &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read_to_string(stale.join("keep")).unwrap(), "x");
    assert_eq!(leftovers(tmp.path()), [".state.old-1"]);
}

#[test]
fn a_failed_swap_puts_the_previous_state_back() {
    let tmp = tempfile::tempdir().unwrap();
    let a = archive(tmp.path(), &[("colima.yaml", "new")]);
    let state = tmp.path().join("state");
    fs::create_dir_all(&state).unwrap();
    fs::write(state.join("colima.yaml"), "old").unwrap();
    fs::write(state.join("kept"), "k").unwrap();
    // An exported bash function shadows `mv` for the staging → state rename only.
    let fail = r#"() { case "$1" in *.restore-*/state) return 1;; esac; command mv "$@"; }"#;
    let out = restore(&a, &state, &[("BASH_FUNC_mv%%", fail)]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("previous state put back"));
    assert_eq!(
        fs::read_to_string(state.join("colima.yaml")).unwrap(),
        "old"
    );
    assert_eq!(fs::read_to_string(state.join("kept")).unwrap(), "k");
    assert!(leftovers(tmp.path()).is_empty());
}

#[test]
fn keeps_an_inward_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let a = archive(tmp.path(), &[("colima.yaml", "new")]);
    let state = tmp.path().join("state");
    fs::create_dir_all(state.join("d")).unwrap();
    std::os::unix::fs::symlink("d", state.join("link")).unwrap();
    let out = restore(&a, &state, &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read_link(state.join("link")).unwrap(), Path::new("d"));
}
