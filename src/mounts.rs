//! Network-backed bind mounts that a container captured before the host
//! mounted them.
//!
//! With default (`rprivate`) propagation, a container started before its
//! network share is mounted keeps the empty local mountpoint forever. Host
//! and container views are compared through `/proc/<pid>/mountinfo`, file
//! reads only.
#![allow(clippy::disallowed_types)]

use std::path::{Component, Path};

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::execute;
use crate::init::Init;

const CHECK_TOOL: &str = "docker.mount_check";
const NETWORK_FS: &[&str] = &[
    "cifs",
    "smb3",
    "smbfs",
    "nfs",
    "nfs4",
    "ceph",
    "glusterfs",
    "fuse.sshfs",
    "fuse.rclone",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// `major:minor` of the filesystem.
    pub dev: String,
    /// Path within the filesystem that is mounted here.
    pub root: String,
    pub point: String,
    pub fstype: String,
}

pub fn is_network(fstype: &str) -> bool {
    NETWORK_FS.contains(&fstype)
}

/// mountinfo escapes space, tab, newline and backslash as octal.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('\\') {
        out.push_str(&rest[..i]);
        let code = rest
            .get(i + 1..i + 4)
            .and_then(|o| u8::from_str_radix(o, 8).ok());
        match code {
            Some(b) => {
                out.push(b as char);
                rest = &rest[i + 4..];
            }
            None => {
                out.push('\\');
                rest = &rest[i + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Mount point and filesystem type of each `/proc/<pid>/mountinfo` line.
pub fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let (head, tail) = line.split_once(" - ")?;
            let mut f = head.split(' ').skip(2);
            let (dev, root, point) = (f.next()?, f.next()?, f.next()?);
            let fstype = tail.split(' ').next()?;
            Some(Mount {
                dev: dev.to_owned(),
                root: unescape(root),
                point: unescape(point),
                fstype: fstype.to_owned(),
            })
        })
        .collect()
}

/// The mount `path` lives on: the deepest mount point that is a component
/// prefix of it; the last one listed wins for stacked mounts.
pub fn mount_at<'a>(path: &str, mounts: &'a [Mount]) -> Option<&'a Mount> {
    let path = Path::new(path);
    let mut best: Option<&Mount> = None;
    for m in mounts {
        if path.starts_with(&m.point) {
            let depth = Path::new(&m.point)
                .components()
                .filter(|c| matches!(c, Component::Normal(_)))
                .count();
            let best_depth = best.map_or(0, |b| {
                Path::new(&b.point)
                    .components()
                    .filter(|c| matches!(c, Component::Normal(_)))
                    .count()
            });
            if best.is_none() || depth >= best_depth {
                best = Some(m);
            }
        }
    }
    best
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    pub source: String,
    pub destination: String,
    pub propagation: String,
}

/// Bind mounts from one `docker inspect` object.
pub fn binds(inspect: &Value) -> Vec<Bind> {
    inspect["Mounts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["Type"] == "bind")
        .filter_map(|m| {
            Some(Bind {
                source: m["Source"].as_str()?.to_owned(),
                destination: m["Destination"].as_str()?.to_owned(),
                propagation: m["Propagation"].as_str().unwrap_or("rprivate").to_owned(),
            })
        })
        .collect()
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindFinding {
    pub source: String,
    pub destination: String,
    /// Filesystem type behind `source` on the host.
    pub host_fs: String,
    /// Filesystem type the container sees at `destination`.
    pub container_fs: String,
    pub propagation: String,
    /// The container sees local disk where the host has the network share.
    pub stale: bool,
}

/// Every bind whose host source is on a network filesystem, judged against
/// the container's own mount table.
pub fn judge(binds: &[Bind], host: &[Mount], container: &[Mount]) -> Vec<BindFinding> {
    binds
        .iter()
        .filter_map(|b| {
            let h = mount_at(&b.source, host)?;
            if !is_network(&h.fstype) {
                return None;
            }
            let c = mount_at(&b.destination, container);
            Some(BindFinding {
                source: b.source.clone(),
                destination: b.destination.clone(),
                stale: !c.is_some_and(|c| sees(b, h, c)),
                host_fs: h.fstype.clone(),
                container_fs: c.map_or_else(String::new, |m| m.fstype.clone()),
                propagation: b.propagation.clone(),
            })
        })
        .collect()
}

/// Whether container mount `c` shows the host filesystem `h` holding `b`'s
/// source: same device, and, when `c` is the bind itself, the same path in it.
fn sees(b: &Bind, h: &Mount, c: &Mount) -> bool {
    if c.dev != h.dev {
        return false;
    }
    if c.point != b.destination {
        return true;
    }
    let rel = Path::new(&b.source)
        .strip_prefix(&h.point)
        .unwrap_or(Path::new(""));
    Path::new(&h.root).join(rel) == Path::new(&c.root)
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.mount_check — find and restart containers holding a stale mount
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
pub struct DockerMountCheckArgs {
    /// Return the plan and change nothing. Omitted, applies.
    #[arg(long)]
    #[serde(default, rename = "dryRun", alias = "dry_run")]
    pub dry_run: bool,
    /// `container:<name>` items from the dry run (when executing).
    /// Comma-separated on the CLI.
    #[arg(long, value_delimiter = ',')]
    #[serde(default)]
    pub items: Vec<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone)]
pub struct ContainerMounts {
    pub container: String,
    pub binds: Vec<BindFinding>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerMountCheckOutput {
    /// true: nothing was changed.
    pub dry_run: bool,
    /// Running containers with network-backed binds.
    pub containers: Vec<ContainerMounts>,
    /// `container:<name>` for each container with a stale bind.
    pub items: Vec<String>,
    /// Running containers whose mount table could not be read (docker in a
    /// VM, or the daemon lacks permission).
    pub unreadable: Vec<String>,
    pub restarted: Vec<String>,
    /// `<container>: <error>` for each restart that failed.
    pub failed: Vec<String>,
    /// Confirmed items no longer stale, left alone.
    pub dropped: Vec<String>,
}

/// Stale-bind restart targets.
pub fn stale_items(containers: &[ContainerMounts]) -> Vec<String> {
    containers
        .iter()
        .filter(|c| c.binds.iter().any(|b| b.stale))
        .map(|c| format!("container:{}", c.container))
        .collect()
}

/// dockerd resolves bind sources in its own mount namespace; its pid file
/// names it. Without the pid file, this daemon's namespace stands in, which
/// differs only when dockerd runs in a namespace of its own.
const DOCKERD_PID: &str = "/var/run/docker.pid";

/// The mount table bind sources are resolved against, and whether it is
/// dockerd's own: only then does this daemon share dockerd's pid namespace,
/// so a container's pid names the same process here.
#[derive(Debug)]
pub struct HostTable {
    pub mounts: Vec<Mount>,
    pub dockerd_ns: bool,
}

/// File reads under `/proc`, faked in tests.
pub trait Proc {
    fn read(&self, path: &str) -> std::io::Result<String>;
    fn readlink(&self, path: &str) -> std::io::Result<String>;
}

pub struct HostProc;

impl Proc for HostProc {
    fn read(&self, path: &str) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn readlink(&self, path: &str) -> std::io::Result<String> {
        std::fs::read_link(path).map(|t| t.to_string_lossy().into_owned())
    }
}

/// The pid in dockerd's pid file, if that process is dockerd and shares this
/// daemon's pid namespace; a stale pid file can name any process.
fn dockerd_pid(proc: &impl Proc) -> Option<u32> {
    let pid: u32 = proc.read(DOCKERD_PID).ok()?.trim().parse().ok()?;
    let comm = proc.read(&format!("/proc/{pid}/comm")).ok()?;
    let ours = proc.readlink("/proc/self/ns/pid").ok()?;
    let theirs = proc.readlink(&format!("/proc/{pid}/ns/pid")).ok()?;
    (comm.trim() == "dockerd" && ours == theirs).then_some(pid)
}

/// Unreadable is an error: an empty table would judge every bind fine.
pub fn host_mounts(proc: &impl Proc) -> Result<HostTable> {
    let from_pid =
        dockerd_pid(proc).and_then(|pid| proc.read(&format!("/proc/{pid}/mountinfo")).ok());
    let dockerd_ns = from_pid.is_some();
    let text = match from_pid {
        Some(t) => t,
        None => proc
            .read("/proc/self/mountinfo")
            .context("cannot read the host mount table")?,
    };
    let mounts = parse_mountinfo(&text);
    if mounts.is_empty() {
        bail!("the host mount table is empty or unparseable");
    }
    Ok(HostTable { mounts, dockerd_ns })
}

/// A container's binds and its init pid (0 when stopped).
struct Scanned {
    name: String,
    binds: Vec<Bind>,
    pid: i64,
}

/// Containers with bind mounts; ones removed mid-scan are skipped.
async fn scan(all: bool) -> Result<Vec<Scanned>> {
    let mut out = Vec::new();
    for c in crate::containers::list(all).await? {
        let name = c.names.split(',').next().unwrap_or_default().to_owned();
        let Ok(inspect) = crate::containers::inspect(&name).await else {
            continue;
        };
        let obj = &inspect[0];
        let binds = binds(obj);
        if !binds.is_empty() {
            out.push(Scanned {
                name,
                binds,
                pid: obj["State"]["Pid"].as_i64().unwrap_or(0),
            });
        }
    }
    Ok(out)
}

/// What [`check`] found: stale-bind findings, containers whose mount table
/// cannot be read, and those whose read failed, which may have exited.
#[derive(Debug, Default)]
struct Checked {
    /// With the pid whose mount table was read.
    found: Vec<(ContainerMounts, i64)>,
    unreadable: Vec<String>,
    failed: Vec<String>,
}

/// Judge each running container against `host`. Outside dockerd's pid
/// namespace a container pid may name an unrelated process here, so nothing
/// is read and every container is unreadable.
fn check(scanned: Vec<Scanned>, host: &HostTable, proc: &impl Proc) -> Checked {
    let mut out = Checked::default();
    for s in scanned.into_iter().filter(|s| s.pid > 0) {
        if !host.dockerd_ns {
            out.unreadable.push(s.name);
            continue;
        }
        let Ok(text) = proc.read(&format!("/proc/{}/mountinfo", s.pid)) else {
            out.failed.push(s.name);
            continue;
        };
        let binds = judge(&s.binds, &host.mounts, &parse_mountinfo(&text));
        if !binds.is_empty() {
            out.found.push((
                ContainerMounts {
                    container: s.name,
                    binds,
                },
                s.pid,
            ));
        }
    }
    out
}

/// The container's current init pid; 0 when stopped or gone.
async fn current_pid(name: &str) -> i64 {
    crate::containers::inspect(name)
        .await
        .ok()
        .filter(|v| v[0]["State"]["Running"].as_bool() == Some(true))
        .and_then(|v| v[0]["State"]["Pid"].as_i64())
        .unwrap_or(0)
}

/// `(restart, dropped)`: the confirmed items still stale, and the rest.
pub fn select(
    tool: &str,
    confirmed: &[String],
    stale: &[String],
) -> Result<(Vec<String>, Vec<String>)> {
    execute::require_confirmed(tool, confirmed, stale)?;
    Ok(execute::intersect(confirmed, stale))
}

/// **Find containers holding a stale network mount**: a bind whose host
/// source is on a network share (cifs/nfs/…) while the container sees local
/// disk there, because it started before the share was mounted. With the dry run's `items`, restarts those still stale. Run after
/// boot as a backstop to `docker.mount_gate`.
#[orca_tool(
    domain = "docker",
    verb = "mount_check",
    local_only = true,
    role = "admin",
    execute_gated = false
)]
async fn docker_mount_check(
    args: DockerMountCheckArgs,
    ctx: &ToolCtx,
) -> Result<DockerMountCheckOutput> {
    execute::require_admin(CHECK_TOOL, ctx)?;
    let host = host_mounts(&HostProc)?;
    let checked = check(scan(false).await?, &host, &HostProc);
    // A pid that changed while its table was read may have named another
    // process by then; that finding is dropped.
    let mut containers = Vec::new();
    for (c, pid) in checked.found {
        if current_pid(&c.container).await == pid {
            containers.push(c);
        }
    }
    let mut unreadable = checked.unreadable;
    for name in checked.failed {
        if current_pid(&name).await > 0 {
            unreadable.push(name);
        }
    }
    let items = stale_items(&containers);
    let mut out = DockerMountCheckOutput {
        dry_run: args.dry_run,
        containers,
        items,
        unreadable,
        restarted: Vec::new(),
        failed: Vec::new(),
        dropped: Vec::new(),
    };
    if args.dry_run {
        return Ok(out);
    }
    let (act, dropped) = select(CHECK_TOOL, &args.items, &out.items)?;
    out.dropped = dropped;
    for item in act {
        let name = item.trim_start_matches("container:");
        match crate::containers::restart(name).await {
            Ok(_) => out.restarted.push(name.to_owned()),
            Err(e) => out.failed.push(format!("{name}: {e}")),
        }
    }
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.mount_gate — start dockerd after the shares its binds use
// ═══════════════════════════════════════════════════════════════════════════

const GATE_TOOL: &str = "docker.mount_gate";
const DROP_IN: &str = "etc/systemd/system/docker.service.d/orca-mounts.conf";
const OPENRC_CONF: &str = "etc/conf.d/docker";
/// `/bin` is `/usr/bin` on merged-usr hosts and holds systemctl on the rest.
const SYSTEMCTL: &str = "/bin/systemctl";
/// Said in every plan: the ordering is soft by design.
const FAILURE_MODE: &str = "ordering is soft: if a share is not mounted when dockerd starts (slow or failed mount), dockerd still starts and containers binding it may capture the empty mountpoint; docker.mount_check restarts those once the share is up";

/// Network mount points on the host that any bind's source lives on.
/// A mount point holding a control character (mountinfo escapes newlines as
/// `\012`) could end a line of the drop-in and inject a setting.
pub fn is_safe_point(point: &str) -> bool {
    !point.chars().any(char::is_control)
}

pub fn share_points<'a>(binds: impl IntoIterator<Item = &'a Bind>, host: &[Mount]) -> Vec<String> {
    let mut points: Vec<String> = binds
        .into_iter()
        .filter_map(|b| mount_at(&b.source, host))
        .filter(|m| is_network(&m.fstype))
        .map(|m| m.point.clone())
        .collect();
    points.sort();
    points.dedup();
    points
}

/// A path as one word of a systemd unit setting: quoted, with `\`, `"` and
/// the specifier character `%` escaped.
fn systemd_word(path: &str) -> String {
    let escaped = path
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!("\"{escaped}\"")
}

/// systemd's unit name for the mount at `path` (`systemd-escape --path
/// --suffix=mount`), with `%` doubled for use inside a unit file.
fn mount_unit(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    let mut out = String::new();
    for (i, b) in trimmed.bytes().enumerate() {
        match b {
            b'/' => out.push('-'),
            b'.' if i == 0 => out.push_str("\\x2e"),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.' => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    if out.is_empty() {
        out.push('-');
    }
    format!("{out}.mount").replace('%', "%%")
}

/// The drop-in ordering docker.service after `points`, without requiring
/// them.
pub fn drop_in(points: &[String]) -> String {
    let units: Vec<String> = points.iter().map(|p| mount_unit(p)).collect();
    let words: Vec<String> = points.iter().map(|p| systemd_word(p)).collect();
    format!(
        "# Written by orca docker.mount_gate: start dockerd after the network\n\
         # shares its containers bind. Soft: a share that fails to mount does\n\
         # not keep dockerd down.\n\
         [Unit]\nWants=remote-fs.target\nAfter=remote-fs.target {}\nWantsMountsFor={}\n",
        units.join(" "),
        words.join(" ")
    )
}

/// Records which settings the gate added `netmount` to, so removal never
/// takes out one an operator put there.
const NETMOUNT_MARKER: &str = "# orca docker.mount_gate added netmount to:";
const NETMOUNT_KEYS: [&str; 2] = ["rc_use", "rc_after"];

/// The words of `key`'s first assignment in `conf`.
fn words_of(conf: &str, key: &str) -> Vec<String> {
    conf.lines()
        .find_map(|l| crate::init::assignment(l, key))
        .map(|(v, _)| v.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// The keys the marker says the gate added `netmount` to.
fn marked_keys(conf: &str) -> Vec<String> {
    conf.lines()
        .find_map(|l| l.strip_prefix(NETMOUNT_MARKER))
        .map(|k| k.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// `conf` without the marker line.
fn unmarked(conf: &str) -> String {
    let kept: Vec<&str> = conf
        .lines()
        .filter(|l| !l.starts_with(NETMOUNT_MARKER))
        .collect();
    if kept.is_empty() {
        String::new()
    } else {
        kept.join("\n") + "\n"
    }
}

/// `conf` using and ordering after `netmount`, without needing it. Each key
/// the gate adds the word to is recorded in the marker; a key that already
/// had it is the operator's and is not recorded.
pub fn with_netmount(conf: &str) -> String {
    let mut keys = marked_keys(conf);
    let mut c = unmarked(conf);
    for key in NETMOUNT_KEYS {
        if !words_of(&c, key).iter().any(|w| w == "netmount") {
            c = crate::init::add_word(&c, key, "netmount");
            keys.push(key.to_owned());
        }
    }
    if keys.is_empty() {
        return c;
    }
    keys.sort();
    keys.dedup();
    let marked = format!("{c}{NETMOUNT_MARKER} {}\n", keys.join(" "));
    // Unchanged input stays byte-identical, so the gate sees nothing to do.
    if unmarked(&marked) == unmarked(conf) && marked_keys(conf) == keys {
        conf.to_owned()
    } else {
        marked
    }
}

/// `conf` without `word` in `key`; a setting left empty is dropped. Other
/// lines stay where they are.
pub fn remove_word(conf: &str, key: &str, word: &str) -> String {
    let mut out = Vec::new();
    for line in conf.lines() {
        let Some((value, trailer)) = crate::init::assignment(line, key) else {
            out.push(line.to_owned());
            continue;
        };
        let words: Vec<&str> = value.split_whitespace().filter(|w| *w != word).collect();
        if words.len() == value.split_whitespace().count() {
            out.push(line.to_owned());
        } else if !words.is_empty() {
            out.push(format!(
                "{key}=\"{}\"{}",
                words.join(" "),
                trailer.trim_end()
            ));
        } else if !trailer.trim().is_empty() {
            out.push(trailer.trim().to_owned());
        }
    }
    if out.is_empty() {
        String::new()
    } else {
        out.join("\n") + "\n"
    }
}

/// `conf` without the `netmount` the gate added; an operator's stays.
pub fn without_netmount(conf: &str) -> String {
    let mut c = unmarked(conf);
    for key in marked_keys(conf) {
        c = remove_word(&c, &key, "netmount");
    }
    c
}

/// `container: source -> destination` binds that would not pick up a late
/// mount on their own.
pub fn propagation_advice(scanned: &[(String, Vec<Bind>)], host: &[Mount]) -> Vec<String> {
    scanned
        .iter()
        .flat_map(|(c, binds)| binds.iter().map(move |b| (c, b)))
        .filter(|(_, b)| mount_at(&b.source, host).is_some_and(|m| is_network(&m.fstype)))
        .filter(|(_, b)| {
            !matches!(
                b.propagation.as_str(),
                "rslave" | "rshared" | "slave" | "shared"
            )
        })
        .map(|(c, b)| {
            format!(
                "{c}: {} -> {} uses {}; add `:rslave` to the bind so a late mount propagates in",
                b.source, b.destination, b.propagation
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateChange {
    Write {
        rel: &'static str,
        content: String,
    },
    /// A drop-in left from shares no container binds any more.
    Remove {
        rel: &'static str,
    },
}

/// The change `init` needs under `root` to gate dockerd on `points`, or
/// `None` when the files already say so.
pub fn gate_change(root: &Path, init: Init, points: &[String]) -> Option<GateChange> {
    let current = |rel: &str| std::fs::read_to_string(root.join(rel)).ok();
    match init {
        Init::Systemd if points.is_empty() => current(DROP_IN)
            .is_some()
            .then_some(GateChange::Remove { rel: DROP_IN }),
        Init::Systemd => {
            let content = drop_in(points);
            (current(DROP_IN).as_deref() != Some(content.as_str())).then_some(GateChange::Write {
                rel: DROP_IN,
                content,
            })
        }
        Init::OpenRc if points.is_empty() => {
            let now = current(OPENRC_CONF)?;
            let content = without_netmount(&now);
            (content != now).then_some(GateChange::Write {
                rel: OPENRC_CONF,
                content,
            })
        }
        Init::OpenRc => {
            let now = current(OPENRC_CONF).unwrap_or_default();
            let content = with_netmount(&now);
            (content != now).then_some(GateChange::Write {
                rel: OPENRC_CONF,
                content,
            })
        }
        Init::Other => None,
    }
}

pub fn apply_gate(root: &Path, change: &GateChange) -> Result<()> {
    match change {
        GateChange::Write { rel, content } => {
            crate::init::write_atomic(&root.join(rel), content, 0o644)
        }
        GateChange::Remove { rel } => std::fs::remove_file(root.join(rel))
            .with_context(|| format!("failed to remove '/{rel}'")),
    }
}

#[orca_struct(args)]
pub struct DockerMountGateArgs {
    /// Write the gate. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerMountGateOutput {
    pub dry_run: bool,
    /// `openrc`, `systemd` or `other`.
    pub init: String,
    /// Network mount points containers (running or stopped) bind from.
    pub shares: Vec<String>,
    /// Shares left out of the gate: their mount point holds a control
    /// character. Shown escaped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<String>,
    /// `write` or `remove`, when a change is due.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<String>,
    /// File changed (or to change), absolute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// What happens when a share is not mounted in time.
    pub failure_mode: String,
    /// Binds on private propagation; compose files are left to their owner.
    pub advice: Vec<String>,
}

/// **Order dockerd after the network shares its containers bind.** systemd:
/// a `docker.service` drop-in with `After=` each share's mount unit and
/// `remote-fs.target` and `WantsMountsFor=` each share, then `systemctl
/// daemon-reload`; a drop-in no share needs any more is removed. OpenRC:
/// `netmount` added to `rc_use` and `rc_after` in `/etc/conf.d/docker`, and
/// removed again once no share needs it.
/// Soft ordering: a share that fails to mount never keeps dockerd down.
/// Never restarts dockerd; the order applies from the next boot. Without
/// `execute`, returns the plan.
#[orca_tool(
    domain = "docker",
    verb = "mount_gate",
    local_only = true,
    role = "admin",
    execute_gated = false
)]
async fn docker_mount_gate(
    args: DockerMountGateArgs,
    ctx: &ToolCtx,
) -> Result<DockerMountGateOutput> {
    execute::require_admin(GATE_TOOL, ctx)?;
    execute::guard(GATE_TOOL, args.execute, ctx)?;
    let root = Path::new("/");
    let host = host_mounts(&HostProc)?;
    let scanned: Vec<(String, Vec<Bind>)> = scan(true)
        .await?
        .into_iter()
        .map(|s| (s.name, s.binds))
        .collect();
    let (shares, rejected): (Vec<String>, Vec<String>) =
        share_points(scanned.iter().flat_map(|(_, b)| b), &host.mounts)
            .into_iter()
            .partition(|p| is_safe_point(p));
    let init = crate::init::detect(root);
    let change = gate_change(root, init, &shares);
    if args.execute
        && let Some(c) = &change
    {
        apply_gate(root, c)?;
        if init == Init::Systemd {
            let out = plugin_toolkit::process::Command::new(SYSTEMCTL)
                .arg("daemon-reload")
                .output()
                .await
                .context("failed to spawn systemctl")?;
            if !out.status.success {
                bail!(
                    "systemctl daemon-reload failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
        }
    }
    let (kind, path, content) = match change {
        Some(GateChange::Write { rel, content }) => (Some("write"), Some(rel), Some(content)),
        Some(GateChange::Remove { rel }) => (Some("remove"), Some(rel), None),
        None => (None, None, None),
    };
    Ok(DockerMountGateOutput {
        dry_run: !args.execute,
        init: init.as_str().to_owned(),
        change: kind.map(str::to_owned),
        path: path.map(|r| format!("/{r}")),
        content,
        failure_mode: FAILURE_MODE.to_owned(),
        advice: propagation_advice(&scanned, &host.mounts),
        rejected: rejected
            .iter()
            .map(|p| p.escape_debug().to_string())
            .collect(),
        shares,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json::json;

    const HOST: &str = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
95 22 0:50 / /mnt/data rw,relatime shared:60 - cifs //willow/data rw
96 22 0:51 / /mnt/my\\040share rw - nfs4 nas:/x rw
98 22 0:52 / /mnt/back\\134slash rw - nfs4 nas:/y rw
97 22 8:1 /srv /srv rw - ext4 /dev/sda1 rw
";

    #[test]
    fn parses_mount_points_and_types() {
        let m = parse_mountinfo(HOST);
        assert_eq!(m.len(), 5);
        assert_eq!(
            m[1],
            Mount {
                dev: "0:50".into(),
                root: "/".into(),
                point: "/mnt/data".into(),
                fstype: "cifs".into()
            }
        );
        assert_eq!(m[2].point, "/mnt/my share");
        assert_eq!(m[3].point, "/mnt/back\\slash");
    }

    #[test]
    fn mount_at_takes_the_deepest_component_prefix() {
        let m = parse_mountinfo(HOST);
        assert_eq!(mount_at("/mnt/data/media", &m).unwrap().fstype, "cifs");
        assert_eq!(mount_at("/mnt/database", &m).unwrap().fstype, "ext4");
        assert_eq!(mount_at("/mnt/data", &m).unwrap().fstype, "cifs");
    }

    fn inspect() -> Value {
        json!({"Mounts": [
            {"Type": "bind", "Source": "/mnt/data/media", "Destination": "/data/media", "Propagation": "rprivate"},
            {"Type": "bind", "Source": "/srv/config", "Destination": "/config", "Propagation": "rprivate"},
            {"Type": "volume", "Name": "v", "Source": "/var/lib/docker/volumes/v/_data", "Destination": "/v"}
        ]})
    }

    #[test]
    fn a_container_seeing_local_disk_under_a_share_is_stale() {
        let container = "\
500 400 0:60 / / rw - overlay overlay rw
501 500 8:1 /mnt/data/media /data/media rw - ext4 /dev/sda1 rw
502 500 8:1 /srv/config /config rw - ext4 /dev/sda1 rw
";
        let f = judge(
            &binds(&inspect()),
            &parse_mountinfo(HOST),
            &parse_mountinfo(container),
        );
        assert_eq!(f.len(), 1, "only the network-backed bind is judged");
        assert!(f[0].stale);
        assert_eq!(
            (f[0].host_fs.as_str(), f[0].container_fs.as_str()),
            ("cifs", "ext4")
        );
        let items = stale_items(&[ContainerMounts {
            container: "sonarr".into(),
            binds: f,
        }]);
        assert_eq!(items, ["container:sonarr"]);
    }

    #[test]
    fn a_container_seeing_the_share_is_fine() {
        let container = "\
500 400 0:60 / / rw - overlay overlay rw
501 500 0:50 /media /data/media rw - cifs //willow/data rw
";
        let f = judge(
            &binds(&inspect()),
            &parse_mountinfo(HOST),
            &parse_mountinfo(container),
        );
        assert!(!f[0].stale);
        assert!(
            stale_items(&[ContainerMounts {
                container: "sonarr".into(),
                binds: f
            }])
            .is_empty()
        );
    }

    #[test]
    fn binds_default_to_rprivate_and_skip_volumes() {
        let mut v = inspect();
        v["Mounts"][0]
            .as_object_mut()
            .unwrap()
            .remove("Propagation");
        let b = binds(&v);
        assert_eq!(b.len(), 2);
        assert_eq!(b[0].propagation, "rprivate");
    }

    #[test]
    fn the_same_fstype_on_another_device_or_path_is_stale() {
        let other_share = "501 500 0:77 /media /data/media rw - cifs //other/data rw\n";
        let wrong_path = "501 500 0:50 /tv /data/media rw - cifs //willow/data rw\n";
        for container in [other_share, wrong_path] {
            let f = judge(
                &binds(&inspect()),
                &parse_mountinfo(HOST),
                &parse_mountinfo(container),
            );
            assert!(f[0].stale, "{container}");
        }
    }

    /// A fake `/proc`: unlisted paths are absent.
    #[derive(Default)]
    struct FakeProc {
        files: std::collections::HashMap<String, String>,
        links: std::collections::HashMap<String, String>,
    }

    impl FakeProc {
        fn file(mut self, p: &str, body: &str) -> Self {
            self.files.insert(p.into(), body.into());
            self
        }

        fn link(mut self, p: &str, target: &str) -> Self {
            self.links.insert(p.into(), target.into());
            self
        }

        /// dockerd as pid 42 in this daemon's pid namespace.
        fn dockerd() -> Self {
            FakeProc::default()
                .file(DOCKERD_PID, "42\n")
                .file("/proc/42/comm", "dockerd\n")
                .file("/proc/42/mountinfo", HOST)
                .file(
                    "/proc/self/mountinfo",
                    "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
                )
                .link("/proc/self/ns/pid", "pid:[4026531836]")
                .link("/proc/42/ns/pid", "pid:[4026531836]")
        }
    }

    impl Proc for FakeProc {
        fn read(&self, p: &str) -> std::io::Result<String> {
            self.files
                .get(p)
                .cloned()
                .ok_or_else(|| std::io::ErrorKind::NotFound.into())
        }

        fn readlink(&self, p: &str) -> std::io::Result<String> {
            self.links
                .get(p)
                .cloned()
                .ok_or_else(|| std::io::ErrorKind::NotFound.into())
        }
    }

    #[test]
    fn an_unreadable_host_table_is_an_error_not_empty() {
        assert!(host_mounts(&FakeProc::default()).is_err());
        assert!(host_mounts(&FakeProc::default().file("/proc/self/mountinfo", "")).is_err());
    }

    #[test]
    fn the_host_table_is_dockerds_only_when_the_pid_is_dockerd_in_our_namespace() {
        let t = host_mounts(&FakeProc::dockerd()).unwrap();
        assert_eq!(t.mounts.len(), 5);
        assert!(t.dockerd_ns);

        let stale_pidfile = FakeProc::dockerd().file("/proc/42/comm", "bash\n");
        let t = host_mounts(&stale_pidfile).unwrap();
        assert!(
            !t.dockerd_ns,
            "a pid file naming another process is not trusted"
        );
        assert_eq!(t.mounts.len(), 1, "falls back to this daemon's table");

        let other_ns = FakeProc::dockerd().link("/proc/42/ns/pid", "pid:[4026532001]");
        assert!(!host_mounts(&other_ns).unwrap().dockerd_ns);

        let mut no_ns = FakeProc::dockerd();
        no_ns.links.remove("/proc/self/ns/pid");
        assert!(!host_mounts(&no_ns).unwrap().dockerd_ns);
    }

    fn scanned() -> Vec<Scanned> {
        vec![
            Scanned {
                name: "gone".into(),
                binds: binds(&inspect()),
                pid: i64::from(u32::MAX),
            },
            Scanned {
                name: "stopped".into(),
                binds: binds(&inspect()),
                pid: 0,
            },
            Scanned {
                name: "sonarr".into(),
                binds: binds(&inspect()),
                pid: 7,
            },
        ]
    }

    #[test]
    fn unreadable_and_stopped_containers_are_not_judged() {
        let proc = FakeProc::default().file(
            "/proc/7/mountinfo",
            "501 500 8:1 /x /data/media rw - ext4 /dev/sda1 rw\n",
        );
        let dockerd = HostTable {
            mounts: parse_mountinfo(HOST),
            dockerd_ns: true,
        };
        let c = check(scanned(), &dockerd, &proc);
        let found: Vec<ContainerMounts> = c.found.iter().map(|(m, _)| m.clone()).collect();
        assert_eq!(stale_items(&found), ["container:sonarr"]);
        assert_eq!(c.found[0].1, 7, "the pid read is kept for the re-check");
        assert_eq!(
            c.failed,
            ["gone"],
            "a failed read is re-inspected, not dropped"
        );
        assert!(c.unreadable.is_empty());
    }

    #[test]
    fn outside_dockerds_pid_namespace_nothing_is_read() {
        struct Panics;
        impl Proc for Panics {
            fn read(&self, p: &str) -> std::io::Result<String> {
                panic!("read {p}")
            }
            fn readlink(&self, p: &str) -> std::io::Result<String> {
                panic!("readlink {p}")
            }
        }
        let foreign = HostTable {
            mounts: parse_mountinfo(HOST),
            dockerd_ns: false,
        };
        let c = check(scanned(), &foreign, &Panics);
        assert!(c.found.is_empty() && c.failed.is_empty());
        assert_eq!(
            c.unreadable,
            ["gone", "sonarr"],
            "stopped containers are not listed"
        );
    }

    #[test]
    fn execute_restarts_only_confirmed_items_still_stale() {
        let stale = vec!["container:a".to_string(), "container:b".to_string()];
        assert!(
            select(CHECK_TOOL, &[], &stale).is_err(),
            "execute needs the dry run's items"
        );
        let (act, dropped) = select(
            CHECK_TOOL,
            &["container:b".into(), "container:gone".into()],
            &stale,
        )
        .unwrap();
        assert_eq!(act, ["container:b"]);
        assert_eq!(dropped, ["container:gone"]);
        assert_eq!(select(CHECK_TOOL, &[], &[]).unwrap(), (vec![], vec![]));
    }

    fn bind(source: &str, propagation: &str) -> Bind {
        Bind {
            source: source.into(),
            destination: "/data".into(),
            propagation: propagation.into(),
        }
    }

    #[test]
    fn share_points_are_the_network_mounts_sources_live_on() {
        let host = parse_mountinfo(HOST);
        let b = [
            bind("/mnt/data/media", "rprivate"),
            bind("/mnt/data/tv", "rslave"),
            bind("/mnt/my share/x", "rslave"),
            bind("/srv/x", "rprivate"),
        ];
        assert_eq!(share_points(&b, &host), ["/mnt/data", "/mnt/my share"]);
    }

    #[test]
    fn drop_in_orders_softly_and_escapes() {
        let d = drop_in(&[
            "/mnt/data".into(),
            "/mnt/my share".into(),
            "/mnt/100%".into(),
        ]);
        assert!(
            d.contains("WantsMountsFor=\"/mnt/data\" \"/mnt/my share\" \"/mnt/100%%\"\n"),
            "{d}"
        );
        assert!(
            d.contains(
                "After=remote-fs.target mnt-data.mount mnt-my\\x20share.mount mnt-100\\x25.mount\n"
            ),
            "{d}"
        );
        assert!(!d.contains("Requires"), "never a hard requirement");
    }

    #[test]
    fn mount_units_match_systemd_escape() {
        assert_eq!(mount_unit("/mnt/data"), "mnt-data.mount");
        assert_eq!(mount_unit("/mnt/a-b"), "mnt-a\\x2db.mount");
        assert_eq!(mount_unit("/"), "-.mount");
    }

    #[test]
    fn netmount_is_soft_added_once_and_other_words_kept() {
        let once = with_netmount("DOCKER_OPTS=\"\"\nrc_use='localmount'\n");
        assert_eq!(
            once,
            "DOCKER_OPTS=\"\"\nrc_use=\"localmount netmount\"\nrc_after=\"netmount\"\n\
             # orca docker.mount_gate added netmount to: rc_after rc_use\n"
        );
        assert_eq!(with_netmount(&once), once);
        assert!(!once.contains("rc_need"));
    }

    #[test]
    fn only_the_netmount_the_gate_added_is_removed() {
        let added = with_netmount("A=1\n");
        assert_eq!(without_netmount(&added), "A=1\n");

        let operator = "A=1\nrc_use=\"localmount netmount\"\nB=2\n";
        let gated = with_netmount(operator);
        assert!(gated.ends_with("added netmount to: rc_after\n"), "{gated}");
        assert_eq!(
            without_netmount(&gated),
            operator,
            "the operator's rc_use stays"
        );

        let hand = "rc_use=\"netmount\"\nrc_after=\"netmount\"\n";
        assert_eq!(with_netmount(hand), hand, "nothing added, nothing marked");
        assert_eq!(
            without_netmount(hand),
            hand,
            "unmarked netmount is never removed"
        );
    }

    #[test]
    fn control_characters_never_reach_the_drop_in() {
        assert!(is_safe_point("/mnt/my share"));
        assert!(!is_safe_point("/mnt/x\n[Service]\nExecStartPre=/bin/sh"));
        let host = parse_mountinfo("95 22 0:50 / /mnt/x\\012ExecStart=evil rw - cifs //w/d rw\n");
        let points = share_points(&[bind("/mnt/x\nExecStart=evil/a", "rslave")], &host);
        assert_eq!(points.len(), 1);
        assert!(
            !is_safe_point(&points[0]),
            "mountinfo's \\012 unescapes to a newline"
        );
    }

    #[test]
    fn remove_word_keeps_trailing_comments() {
        assert_eq!(
            remove_word(
                "rc_use=\"localmount netmount\" # boot order\n",
                "rc_use",
                "netmount"
            ),
            "rc_use=\"localmount\" # boot order\n"
        );
        assert_eq!(
            remove_word("rc_after=netmount # orca\n", "rc_after", "netmount"),
            "# orca\n"
        );
    }

    #[test]
    fn advice_names_only_private_network_binds() {
        let host = parse_mountinfo(HOST);
        let scanned = vec![(
            "sonarr".to_string(),
            vec![
                bind("/mnt/data/a", "rprivate"),
                bind("/mnt/data/b", "rslave"),
                bind("/srv/c", "rprivate"),
            ],
        )];
        let a = propagation_advice(&scanned, &host);
        assert_eq!(a.len(), 1);
        assert!(a[0].contains("/mnt/data/a") && a[0].contains(":rslave"));
    }

    #[test]
    fn gate_changes_are_idempotent_and_a_stale_drop_in_is_removed() {
        let t = tempfile::tempdir().unwrap();
        let points = vec!["/mnt/data".to_string()];
        assert!(gate_change(t.path(), Init::Systemd, &[]).is_none());
        assert!(gate_change(t.path(), Init::Other, &points).is_none());
        for init in [Init::Systemd, Init::OpenRc] {
            let c = gate_change(t.path(), init, &points).unwrap();
            apply_gate(t.path(), &c).unwrap();
            assert!(gate_change(t.path(), init, &points).is_none(), "{init:?}");
        }
        let remove = gate_change(t.path(), Init::Systemd, &[]).unwrap();
        assert_eq!(remove, GateChange::Remove { rel: DROP_IN });
        apply_gate(t.path(), &remove).unwrap();
        assert!(!t.path().join(DROP_IN).exists());
        let unwind = gate_change(t.path(), Init::OpenRc, &[]).unwrap();
        apply_gate(t.path(), &unwind).unwrap();
        assert_eq!(
            std::fs::read_to_string(t.path().join(OPENRC_CONF)).unwrap(),
            ""
        );
        assert!(gate_change(t.path(), Init::OpenRc, &[]).is_none());
    }
}
