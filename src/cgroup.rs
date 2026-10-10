//! cgroup v2 controller delegation for docker hosts inside an LXC.
//!
//! cgroup v2 refuses to enable controllers on a cgroup that holds processes.
//! In an LXC, init and the gettys sit in the CT's root cgroup, so memory/cpu
//! are never delegated and `docker run --memory` fails. The assessment reads
//! only files (never a subprocess), relative to a root so tests can fake it.
#![allow(clippy::disallowed_types)]

use std::path::Path;

use plugin_toolkit::prelude::*;

const PROBE_TOOL: &str = "docker.host_probe";
const CGROUP: &str = "sys/fs/cgroup";
/// In the daemon's `Warnings` when the memory controller is not delegated.
const SWAP_WARNING: &str = "No swap limit support";
/// What the probe container gets and must read back from `memory.max`.
const PROBE_MEMORY: u64 = 64 << 20;
const PROBE_IMAGE: &str = "debian:stable-slim";
/// Covers pulling the probe image on a slow link; a wedged engine fails it.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CgroupAssessment {
    pub in_lxc: bool,
    pub cgroup_v2: bool,
    /// `openrc`, `systemd` or `other`.
    pub init: String,
    /// Processes in the root cgroup; any blocks delegation.
    pub root_procs: usize,
    pub controllers: Vec<String>,
    pub delegated: Vec<String>,
    /// Available controllers not yet in `cgroup.subtree_control`.
    pub missing: Vec<String>,
    /// Hard `RLIMIT_NOFILE` of this process, the ceiling for docker's ulimit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nofile_hard: Option<u64>,
    pub needs_delegation: bool,
}

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel)).ok()
}

fn words(s: Option<String>) -> Vec<String> {
    s.unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// `/proc/1/environ` is root-only; `/run/systemd/container` covers the rest.
fn in_lxc(root: &Path) -> bool {
    let environ = std::fs::read(root.join("proc/1/environ")).unwrap_or_default();
    environ.split(|b| *b == 0).any(|kv| kv == b"container=lxc")
        || read(root, "run/systemd/container").is_some_and(|s| s.trim() == "lxc")
}

/// The hard "Max open files" limit from a `/proc/<pid>/limits` table.
pub(crate) fn nofile_hard(limits: &str) -> Option<u64> {
    let line = limits.lines().find(|l| l.starts_with("Max open files"))?;
    let hard = line["Max open files".len()..].split_whitespace().nth(1)?;
    hard.parse().ok()
}

pub fn assess(root: &Path) -> CgroupAssessment {
    let cg = root.join(CGROUP);
    let cgroup_v2 = cg.join("cgroup.subtree_control").exists();
    let controllers = words(read(&cg, "cgroup.controllers"));
    let delegated = words(read(&cg, "cgroup.subtree_control"));
    let missing: Vec<String> = controllers
        .iter()
        .filter(|c| !delegated.contains(c))
        .cloned()
        .collect();
    let root_procs = read(&cg, "cgroup.procs")
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count();
    let in_lxc = in_lxc(root);
    CgroupAssessment {
        in_lxc,
        cgroup_v2,
        init: crate::init::detect(root).as_str().to_owned(),
        root_procs,
        needs_delegation: in_lxc && cgroup_v2 && !missing.is_empty(),
        controllers,
        delegated,
        missing,
        nofile_hard: read(root, "proc/self/limits")
            .as_deref()
            .and_then(nofile_hard),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.host_probe — is the engine able to enforce container limits?
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
pub struct DockerHostProbeArgs {
    /// Also pull `debian:stable-slim` if absent and create and run a
    /// throwaway container with memory/cpu limits, reading its memory limit
    /// back. Omitted, only files and `docker info` are read.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerHostProbeOutput {
    pub healthy: bool,
    pub cgroup: CgroupAssessment,
    /// `docker info` warned about swap limits (`None`: docker unreachable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap_limit_warning: Option<bool>,
    /// `memory.max` read inside the limited container (execute only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_readback: Option<String>,
    /// Why the limited container did not run (execute only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_error: Option<String>,
    pub problems: Vec<String>,
}

/// Problems found, given the assessment and docker's answers.
pub(crate) fn problems(
    a: &CgroupAssessment,
    swap_warning: Option<bool>,
    readback: Option<std::result::Result<&str, &str>>,
) -> Vec<String> {
    let mut out = Vec::new();
    if a.needs_delegation {
        out.push(format!(
            "controllers not delegated: {} ({} process(es) in the root cgroup)",
            a.missing.join(" "),
            a.root_procs
        ));
    }
    match swap_warning {
        Some(true) => out.push(format!("docker info: {SWAP_WARNING}")),
        None => out.push("docker info failed: engine unreachable".into()),
        Some(false) => {}
    }
    match readback {
        Some(Ok(got)) if got.trim() != PROBE_MEMORY.to_string() => out.push(format!(
            "limited container read memory.max '{}', expected {PROBE_MEMORY}",
            got.trim()
        )),
        Some(Err(why)) => out.push(format!("limited container did not run: {why}")),
        _ => {}
    }
    out
}

/// stdout of a docker CLI call, or why it failed (exit status and stderr).
async fn docker_stdout(args: &[&str]) -> std::result::Result<String, String> {
    let out = crate::clean_command(crate::resolve_docker_bin())
        .await
        .args(args)
        .output()
        .await
        .map_err(|e| format!("failed to run docker: {e}"))?;
    if !out.status.success {
        return Err(format!(
            "exit {:?}: {}",
            out.status.code,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// **Probe whether this docker host can enforce container limits**: cgroup v2
/// delegation inside an LXC, and `docker info`'s swap-limit warning. With
/// `execute`, also pulls a small image if absent and creates and runs a
/// throwaway limited container, reading its memory limit back. Without it,
/// only reads; use as a health check.
#[orca_tool(
    domain = "docker",
    verb = "host_probe",
    local_only = true,
    role = "admin",
    execute_gated = false
)]
async fn docker_host_probe(
    args: DockerHostProbeArgs,
    ctx: &ToolCtx,
) -> Result<DockerHostProbeOutput> {
    crate::execute::require_admin(PROBE_TOOL, ctx)?;
    let cgroup = assess(Path::new("/"));
    let swap_limit_warning = docker_stdout(&["info", "--format", "{{json .Warnings}}"])
        .await
        .ok()
        .map(|w| w.contains(SWAP_WARNING));
    let readback = if args.execute {
        let memory = format!("--memory={PROBE_MEMORY}");
        let swap = format!("--memory-swap={}", PROBE_MEMORY + (32 << 20));
        let run = [
            "run",
            "--rm",
            &memory,
            &swap,
            "--cpus=1",
            PROBE_IMAGE,
            "cat",
            "/sys/fs/cgroup/memory.max",
        ];
        Some(
            plugin_toolkit::time::timeout(PROBE_TIMEOUT, docker_stdout(&run))
                .await
                .unwrap_or_else(|| Err(format!("timed out after {}s", PROBE_TIMEOUT.as_secs()))),
        )
    } else {
        None
    };
    let problems = problems(
        &cgroup,
        swap_limit_warning,
        readback
            .as_ref()
            .map(|r| r.as_deref().map_err(String::as_str)),
    );
    let (memory_readback, probe_error) = match readback {
        Some(Ok(v)) => (Some(v), None),
        Some(Err(e)) => (None, Some(e)),
        None => (None, None),
    };
    Ok(DockerHostProbeOutput {
        healthy: problems.is_empty(),
        cgroup,
        swap_limit_warning,
        memory_readback,
        probe_error,
        problems,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;

    /// A fake root: an LXC on cgroup v2 with `procs` in the root cgroup.
    pub(crate) fn fake_lxc(delegated: &str, procs: &str) -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        let cg = t.path().join(CGROUP);
        fs::create_dir_all(&cg).unwrap();
        fs::write(cg.join("cgroup.controllers"), "cpuset cpu io memory pids\n").unwrap();
        fs::write(cg.join("cgroup.subtree_control"), delegated).unwrap();
        fs::write(cg.join("cgroup.procs"), procs).unwrap();
        fs::create_dir_all(t.path().join("proc/1")).unwrap();
        fs::write(
            t.path().join("proc/1/environ"),
            b"PATH=/bin\0container=lxc\0",
        )
        .unwrap();
        fs::create_dir_all(t.path().join("run/openrc")).unwrap();
        t
    }

    #[test]
    fn an_undelegated_lxc_needs_delegation() {
        let t = fake_lxc("", "1\n42\n");
        let a = assess(t.path());
        assert!(a.in_lxc && a.cgroup_v2);
        assert_eq!(a.init, "openrc");
        assert_eq!(a.root_procs, 2);
        assert_eq!(a.missing, ["cpuset", "cpu", "io", "memory", "pids"]);
        assert!(a.needs_delegation);
    }

    #[test]
    fn a_delegated_lxc_is_fine() {
        let t = fake_lxc("cpuset cpu io memory pids\n", "");
        let a = assess(t.path());
        assert!(a.missing.is_empty());
        assert!(!a.needs_delegation);
    }

    #[test]
    fn outside_an_lxc_nothing_is_needed() {
        let t = fake_lxc("", "1\n");
        fs::write(t.path().join("proc/1/environ"), b"PATH=/bin\0").unwrap();
        assert!(!assess(t.path()).needs_delegation);
        fs::create_dir_all(t.path().join("run/systemd")).unwrap();
        fs::write(t.path().join("run/systemd/container"), "lxc\n").unwrap();
        assert!(
            assess(t.path()).in_lxc,
            "systemd's marker also identifies an LXC"
        );
    }

    #[test]
    fn cgroup_v1_is_not_assessed_as_v2() {
        let t = tempfile::tempdir().unwrap();
        let a = assess(t.path());
        assert!(!a.cgroup_v2 && !a.needs_delegation);
        assert_eq!(a.init, "other");
    }

    #[test]
    fn reads_the_hard_nofile_limit() {
        let limits = "Limit                     Soft Limit           Hard Limit           Units\n\
                      Max processes             63432                63432                processes\n\
                      Max open files            1024                 524288               files\n";
        assert_eq!(nofile_hard(limits), Some(524288));
        assert_eq!(nofile_hard("Max open files  1024  unlimited  files"), None);
    }

    #[test]
    fn problems_cover_delegation_warning_and_readback() {
        let t = fake_lxc("", "1\n");
        let bad = assess(t.path());
        let p = problems(&bad, Some(true), Some(Ok("max\n")));
        assert_eq!(p.len(), 3, "{p:?}");
        let good = assess(fake_lxc("cpuset cpu io memory pids", "").path());
        assert!(problems(&good, Some(false), Some(Ok("67108864\n"))).is_empty());
        assert!(problems(&good, Some(false), None).is_empty());
        assert_eq!(problems(&good, None, None).len(), 1);
        let failed = problems(&good, Some(false), Some(Err("exit Some(125): no image")));
        assert!(failed[0].contains("did not run"), "{failed:?}");
    }
}
