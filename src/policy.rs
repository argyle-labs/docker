//! Compose content policy for managed stacks, checked before a compose file
//! is written (`deploy`, `set`, `edit`, `fix`, `restore`) and before compose
//! runs it (`up`, the lifecycle actions, `host_update`).
//!
//! `deploy` is a unit create, which reaches the plugin without a caller
//! identity (orca#788), so the plugin cannot require admin on every stack
//! verb. The policy is an allowlist over the resolved config (`compose
//! config`, every profile enabled): a key it does not know is refused, and
//! every setting that reaches the host (privileged, host or shared
//! namespaces, extra capabilities, devices, binds outside the stack dir,
//! other projects' volumes and networks, the host network) needs a grant.
//! Grants are recorded by an admin through `docker.stack_allow`, either one
//! by one or by approving what the stack runs now; approving an unregistered
//! compose project registers it with its grants. Each is bound to a digest
//! of its service's whole resolved definition (env files included) and to
//! its image's registry content digest, so any change to the service or to
//! what its image tag holds voids its grants until an admin approves again.
//!
//! A few things are refused outright, with no grant: a path with a `..`
//! component or that cannot be resolved, a bind that contains the stack dir,
//! its parent, a stacks root, a backup root or another stack's dir, a bind
//! inside another stack's dir or of one of the stack's own compose or `.env`
//! files, binds that nest inside one another, an env file, build context or
//! Dockerfile outside the stack dir, a grant on a service that builds its
//! image, and keys the policy does not know.
//!
//! [`gate`] returns the exact config it checked, and compose runs from that
//! ([`Checked`]), so a compose file changed after the check is never used.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{self, Value};

use crate::compose::{self, Compose};
use crate::stacks::{self, StackDir, StackRow};
use crate::{engine_state, execute, fsat};

pub const ALLOW_PRIVILEGED: &str = "privileged";
pub const ALLOW_PID_HOST: &str = "pid:host";
/// `pid: container:<x>` or `service:<x>`: another container's namespace.
pub const ALLOW_PID_SHARED: &str = "pid:shared";
pub const ALLOW_IPC_HOST: &str = "ipc:host";
pub const ALLOW_IPC_SHARED: &str = "ipc:shared";
pub const ALLOW_NETWORK_HOST: &str = "network_mode:host";
pub const ALLOW_NETWORK_SHARED: &str = "network_mode:shared";
pub const ALLOW_USERNS_HOST: &str = "userns_mode:host";
pub const ALLOW_CGROUP_HOST: &str = "cgroup:host";
pub const ALLOW_SECURITY_OPT: &str = "security_opt";
/// `devices`, `gpus` and device reservations under `deploy`.
pub const ALLOW_DEVICES: &str = "devices";
pub const ALLOW_VOLUMES_FROM: &str = "volumes_from";
/// Prefix of a capability grant: `cap_add:SYS_ADMIN`.
pub const ALLOW_CAP: &str = "cap_add:";
/// Prefix of a per-path bind grant: `bind:/var/run/docker.sock`. Secret and
/// config `file:` sources are bind mounts too and use the same grant.
pub const ALLOW_BIND: &str = "bind:";
/// Prefix of a grant for a volume the project does not own, external or
/// named outside the project: `external_volume:<engine name>`.
pub const ALLOW_EXTERNAL_VOLUME: &str = "external_volume:";
/// Prefix of a grant for a network the project does not own, external or
/// named outside the project: `network:<engine name>`.
pub const ALLOW_NETWORK: &str = "network:";
/// Prefix of a network driver grant: `network_driver:macvlan`.
pub const ALLOW_NETWORK_DRIVER: &str = "network_driver:";

const FIXED_GRANTS: &[&str] = &[
    ALLOW_PRIVILEGED,
    ALLOW_PID_HOST,
    ALLOW_PID_SHARED,
    ALLOW_IPC_HOST,
    ALLOW_IPC_SHARED,
    ALLOW_NETWORK_HOST,
    ALLOW_NETWORK_SHARED,
    ALLOW_USERNS_HOST,
    ALLOW_CGROUP_HOST,
    ALLOW_SECURITY_OPT,
    ALLOW_DEVICES,
    ALLOW_VOLUMES_FROM,
];

const ALLOW_TOOL: &str = "docker.stack_allow";
/// Prefix of the `after` item an adoption adds: `adopt:<dir>/<file>`.
const ADOPT_ITEM: &str = "adopt:";

/// Capabilities a service may add without a grant: Docker's default set,
/// which every container already holds, so adding one is a no-op, plus
/// `NET_ADMIN`, which acts on the container's own network namespace (the
/// host's needs the `network_mode:host` grant).
const SAFE_CAPS: &[&str] = &[
    "AUDIT_WRITE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "MKNOD",
    "NET_BIND_SERVICE",
    "NET_RAW",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
    "NET_ADMIN",
];

/// Service keys with no host reach of their own.
const PLAIN_SERVICE_KEYS: &[&str] = &[
    "annotations",
    "attach",
    "cap_drop",
    "command",
    "container_name",
    "cpu_count",
    "cpu_percent",
    "cpu_period",
    "cpu_quota",
    "cpu_shares",
    "cpus",
    "cpuset",
    "depends_on",
    "dns",
    "dns_opt",
    "dns_search",
    "domainname",
    "entrypoint",
    "environment",
    "expose",
    "external_links",
    "extra_hosts",
    "group_add",
    "healthcheck",
    "hostname",
    "image",
    "init",
    "labels",
    "links",
    "logging",
    "mac_address",
    "mem_limit",
    "mem_reservation",
    "mem_swappiness",
    "memswap_limit",
    "oom_score_adj",
    "pids_limit",
    "platform",
    "ports",
    "profiles",
    "pull_policy",
    "read_only",
    "restart",
    "scale",
    "shm_size",
    "stdin_open",
    "stop_grace_period",
    "stop_signal",
    "sysctls",
    "tmpfs",
    "tty",
    "ulimits",
    "user",
    "working_dir",
];

/// Service keys the checks below judge.
const CHECKED_SERVICE_KEYS: &[&str] = &[
    "build",
    "cap_add",
    "cgroup",
    "configs",
    "deploy",
    "devices",
    "env_file",
    "gpus",
    "ipc",
    "network_mode",
    "networks",
    "pid",
    "privileged",
    "secrets",
    "security_opt",
    "userns_mode",
    "volumes",
    "volumes_from",
];

const TOP_KEYS: &[&str] = &[
    "name", "services", "networks", "volumes", "secrets", "configs",
];
const NETWORK_KEYS: &[&str] = &[
    "name",
    "driver",
    "driver_opts",
    "external",
    "attachable",
    "enable_ipv4",
    "enable_ipv6",
    "ipam",
    "internal",
    "labels",
];
/// Network drivers that need no grant. `host` needs the host network grant;
/// `macvlan` and `ipvlan` put the container on the host's LAN and need a
/// driver grant; any other is refused.
const PLAIN_NETWORK_DRIVERS: &[&str] = &["", "bridge", "overlay"];
const GRANTED_NETWORK_DRIVERS: &[&str] = &["macvlan", "ipvlan"];
/// `network_mode` values that join no named network.
const PLAIN_NETWORK_MODES: &[&str] = &["", "bridge", "default", "none"];
const VOLUME_KEYS: &[&str] = &["name", "driver", "driver_opts", "external", "labels"];
const SECRET_KEYS: &[&str] = &[
    "name",
    "file",
    "environment",
    "content",
    "external",
    "labels",
];
const BUILD_KEYS: &[&str] = &[
    "context",
    "dockerfile",
    "dockerfile_inline",
    "args",
    "target",
    "labels",
    "tags",
    "platforms",
    "pull",
    "no_cache",
    "shm_size",
    "network",
    "extra_hosts",
];
/// `local` volume mount types that do not take a host path as `device`.
const REMOTE_VOLUME_TYPES: &[&str] = &["nfs", "nfs4", "cifs", "tmpfs"];
const DIGEST_PREFIX: &str = "sha256:";

fn is_digest(d: &str) -> bool {
    d.strip_prefix(DIGEST_PREFIX)
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// One exception an admin recorded: `allow` for `service` while it runs
/// `image` with registry content `image_digest` and its resolved definition
/// hashes to `definition`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct Grant {
    pub service: String,
    /// The service's `image` as compose resolves it.
    pub image: String,
    /// `sha256:<hex>` of the service's definition (see [`digests`]).
    pub definition: String,
    /// The image's registry content digest(s), `sha256:<hex>[,...]` (see
    /// [`ImagePin`]).
    pub image_digest: String,
    pub allow: String,
}

impl std::fmt::Display for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}|{}|{}|{}|{}",
            self.service, self.image, self.definition, self.image_digest, self.allow
        )
    }
}

impl std::str::FromStr for Grant {
    type Err = plugin_toolkit::anyhow::Error;

    /// `<service>|<image>|<definition>|<image digest>|<grant>`. None of the
    /// first four can hold a `|`; the grant may.
    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.splitn(5, '|');
        let (Some(service), Some(image), Some(definition), Some(image_digest), Some(allow)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            bail!("grant '{s}' must be '<service>|<image>|<definition>|<image digest>|<grant>'");
        };
        if service.is_empty() || image.is_empty() {
            bail!("grant '{s}' names no service or no image");
        }
        if !is_digest(definition) || !image_digest.split(',').all(is_digest) {
            bail!(
                "grant '{s}' needs the definition and image digests ({DIGEST_PREFIX}<hex>) from the dry run"
            );
        }
        validate_grant(allow)?;
        Ok(Grant {
            service: service.to_string(),
            image: image.to_string(),
            definition: definition.to_string(),
            image_digest: image_digest.to_string(),
            allow: allow.to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    /// Empty for a project-level setting no service uses.
    pub service: String,
    pub image: String,
    /// The service's definition digest; empty with no service.
    pub definition: String,
    /// The image's registry content digest; empty when it has none.
    pub image_digest: String,
    /// The grant that admits it; `None` when nothing can.
    pub allow: Option<String>,
    pub detail: String,
}

impl Violation {
    fn grant(&self) -> Option<Grant> {
        self.allow.as_ref().map(|allow| Grant {
            service: self.service.clone(),
            image: self.image.clone(),
            definition: self.definition.clone(),
            image_digest: self.image_digest.clone(),
            allow: allow.clone(),
        })
    }
}

/// An image's registry identity, from `docker image inspect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePin {
    /// The content digests of its `RepoDigests`, sorted and joined by `,`.
    pub digest: String,
    /// One of its `RepoDigests` (`repo@sha256:...`), which compose runs so
    /// a tag retagged after the check is never used.
    pub reference: String,
}

/// What each service's grants are bound to.
#[derive(Debug, Default)]
pub struct Pins {
    /// [`digests`] of the user's own files.
    pub definitions: BTreeMap<String, String>,
    /// Each service's image, where it has a registry digest. A built or
    /// unpulled image has none and cannot hold a grant.
    pub images: BTreeMap<String, ImagePin>,
}

pub type Resolver<'a> = &'a dyn Fn(&Path) -> Result<PathBuf>;

/// The host paths the policy judges sources against, all resolved.
pub struct Roots {
    stack_dir: PathBuf,
    /// A source that is or contains one of these is refused outright.
    protected: Vec<PathBuf>,
    /// Other registered stacks' dirs: a source inside one is refused.
    other_dirs: Vec<PathBuf>,
    /// Other registered stacks' granted bind paths: a source may equal one,
    /// never nest with one.
    other_binds: Vec<PathBuf>,
    /// File names in the stack dir that orca reads or writes, never bindable.
    own_files: BTreeSet<String>,
    /// The daemon's home and docker config dirs: no bind may be, contain or
    /// sit inside one.
    daemon_dirs: Vec<PathBuf>,
    /// The stack being judged.
    stack: String,
    /// Every image a granted service of any registered stack runs.
    granted_images: Vec<GrantedImage>,
    /// Writable bind sources of the host's containers, and each container's
    /// name: compose builds before it recreates or removes any of them.
    container_binds: Vec<(PathBuf, String)>,
}

/// An image a granted service runs: `stack`'s `service` holds a grant while
/// running `image` (normalized, see [`norm_image`]).
#[derive(Debug, Clone)]
pub struct GrantedImage {
    pub image: String,
    pub stack: String,
    pub service: String,
}

impl Roots {
    pub fn new(
        stack_dir: &Path,
        stacks_roots: &[String],
        backup_roots: &[String],
        resolve: Resolver<'_>,
    ) -> Result<Roots> {
        let stack_dir = resolve(stack_dir)?;
        let mut protected = vec![stack_dir.clone()];
        protected.extend(stack_dir.parent().map(Path::to_path_buf));
        protected.extend(stacks_roots.iter().map(|r| configured(r, resolve)));
        protected.extend(backup_roots.iter().map(|r| configured(r, resolve)));
        let mut own_files = BTreeSet::new();
        for name in compose::COMPOSE_FILES
            .iter()
            .chain(compose::OVERRIDE_FILES)
            .chain(&[compose::ORCA_FILE, stacks::ENV_FILE])
        {
            own_files.insert(name.to_string());
            own_files.insert(format!("{name}.bak"));
        }
        Ok(Roots {
            stack_dir,
            protected,
            other_dirs: Vec::new(),
            other_binds: Vec::new(),
            own_files,
            daemon_dirs: Vec::new(),
            stack: String::new(),
            granted_images: Vec::new(),
            container_binds: Vec::new(),
        })
    }

    /// With the daemon's home and docker config dirs.
    pub fn with_daemon_dirs(mut self, dirs: &[String], resolve: Resolver<'_>) -> Self {
        self.daemon_dirs = dirs.iter().map(|d| configured(d, resolve)).collect();
        self
    }

    /// Judging stack `stack`, against the images granted services of every
    /// registered stack run.
    pub fn with_granted_images(mut self, stack: &str, images: Vec<GrantedImage>) -> Self {
        self.stack = stack.to_string();
        self.granted_images = images;
        self
    }

    /// With the other registered stacks' `dirs` and granted bind paths.
    pub fn with_others(mut self, dirs: &[String], binds: &[String], resolve: Resolver<'_>) -> Self {
        let dirs: Vec<PathBuf> = dirs.iter().map(|d| configured(d, resolve)).collect();
        self.protected.extend(dirs.iter().cloned());
        self.other_dirs = dirs;
        self.other_binds = binds.iter().map(|b| configured(b, resolve)).collect();
        self
    }

    /// With the writable bind `sources` of existing containers, each with
    /// its container's name.
    pub fn with_container_binds(
        mut self,
        sources: &[(String, String)],
        resolve: Resolver<'_>,
    ) -> Self {
        self.container_binds = sources
            .iter()
            .map(|(s, c)| (configured(s, resolve), c.clone()))
            .collect();
        self
    }

    /// With the stack's own compose file name, when it is not a conventional
    /// one.
    pub fn with_compose_file(mut self, file: &str) -> Self {
        self.own_files.insert(file.to_string());
        self.own_files.insert(format!("{file}.bak"));
        self
    }
}

/// An admin-configured path, absolute without `..`: one that cannot be
/// resolved is still judged as written.
fn configured(r: &str, resolve: Resolver<'_>) -> PathBuf {
    resolve(Path::new(r)).unwrap_or_else(|_| PathBuf::from(r))
}

enum Judgment {
    Ok,
    Grant(String),
    Refuse(String),
}

fn has_dotdot(raw: &str) -> bool {
    raw.split('/').any(|seg| seg == "..")
}

/// `raw` as an absolute host path with symlinks resolved, or why it is
/// refused. A path that cannot be resolved is refused, never judged as
/// written.
fn host_path(raw: &str, resolve: Resolver<'_>) -> std::result::Result<PathBuf, String> {
    if has_dotdot(raw) {
        return Err(format!("'{raw}' has a '..' component"));
    }
    if !Path::new(raw).is_absolute() {
        return Err(format!("'{raw}' is not an absolute path"));
    }
    resolve(Path::new(raw)).map_err(|e| format!("'{raw}' cannot be resolved: {e}"))
}

/// Whether `raw` resolves inside the stack dir (`or_equal`: or is it).
fn in_stack_dir(raw: &str, roots: &Roots, or_equal: bool, resolve: Resolver<'_>) -> bool {
    stack_path(raw, roots, or_equal, resolve).is_some()
}

/// `raw` resolved, when it lies inside the stack dir (`or_equal`: or is it).
/// compose prints a literal `$` as `$$`.
fn stack_path(raw: &str, roots: &Roots, or_equal: bool, resolve: Resolver<'_>) -> Option<PathBuf> {
    host_path(&raw.replace("$$", "$"), resolve)
        .ok()
        .filter(|p| p.starts_with(&roots.stack_dir) && (or_equal || *p != roots.stack_dir))
}

/// A bind source: free strictly inside the stack dir, but for orca's own
/// files there; a grant anywhere else. Sources are resolved now and docker
/// resolves them again at mount time, so a writable parent could redirect a
/// bind: data roots are not exempt, and [`Collector::nesting`] refuses binds
/// that nest.
fn judge_source(p: &Path, raw: &str, roots: &Roots) -> Judgment {
    if let Some(r) = roots.protected.iter().find(|r| r.starts_with(p)) {
        return Judgment::Refuse(format!(
            "'{raw}' contains {}, the stack dir, its parent, a stacks root, a backup root or another stack's dir",
            r.display()
        ));
    }
    if let Some(d) = roots
        .daemon_dirs
        .iter()
        .find(|d| p.starts_with(d) || d.starts_with(p))
    {
        return Judgment::Refuse(format!(
            "'{raw}' reaches {}, the daemon's home or docker config",
            d.display()
        ));
    }
    if let Some(d) = roots.other_dirs.iter().find(|d| p.starts_with(d)) {
        return Judgment::Refuse(format!(
            "'{raw}' is inside another stack's dir {}",
            d.display()
        ));
    }
    if p.parent() == Some(roots.stack_dir.as_path())
        && p.file_name()
            .is_some_and(|n| roots.own_files.contains(&*n.to_string_lossy()))
    {
        return Judgment::Refuse(format!(
            "'{raw}' is one of the stack's own compose or .env files"
        ));
    }
    if p.starts_with(&roots.stack_dir) {
        return Judgment::Ok;
    }
    Judgment::Grant(format!("{ALLOW_BIND}{}", p.display()))
}

fn norm_cap(cap: &str) -> String {
    let cap = cap.trim().to_ascii_uppercase();
    cap.strip_prefix("CAP_").unwrap_or(&cap).to_string()
}

fn str_of(v: Option<&Value>) -> &str {
    v.and_then(Value::as_str).unwrap_or("")
}

fn non_empty(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

fn keys_outside<'a>(obj: &'a Value, known: &[&[&str]]) -> Vec<&'a str> {
    obj.as_object()
        .map(|o| {
            o.keys()
                .map(String::as_str)
                .filter(|k| !k.starts_with("x-") && !known.iter().any(|set| set.contains(k)))
                .collect()
        })
        .unwrap_or_default()
}

/// A namespace key: values in `ok` pass, `host` needs the `host` grant,
/// `container:`/`service:` the `shared` one (refused without one), and
/// anything else is refused.
struct Mode {
    key: &'static str,
    ok: &'static [&'static str],
    host: &'static str,
    shared: Option<&'static str>,
}

const MODES: &[Mode] = &[
    Mode {
        key: "pid",
        ok: &[],
        host: ALLOW_PID_HOST,
        shared: Some(ALLOW_PID_SHARED),
    },
    Mode {
        key: "ipc",
        ok: &["private", "shareable", "none"],
        host: ALLOW_IPC_HOST,
        shared: Some(ALLOW_IPC_SHARED),
    },
    Mode {
        key: "userns_mode",
        ok: &[],
        host: ALLOW_USERNS_HOST,
        shared: None,
    },
    Mode {
        key: "cgroup",
        ok: &["private"],
        host: ALLOW_CGROUP_HOST,
        shared: None,
    },
    Mode {
        key: "network_mode",
        ok: PLAIN_NETWORK_MODES,
        host: ALLOW_NETWORK_HOST,
        shared: Some(ALLOW_NETWORK_SHARED),
    },
];

fn namespace(value: &str, mode: &Mode) -> Judgment {
    if value.is_empty() || mode.ok.contains(&value) {
        return Judgment::Ok;
    }
    if value == "host" {
        return Judgment::Grant(mode.host.to_string());
    }
    if (value.starts_with("container:") || value.starts_with("service:"))
        && let Some(g) = mode.shared
    {
        return Judgment::Grant(g.to_string());
    }
    Judgment::Refuse(format!("{}: {value} is not supported", mode.key))
}

/// What compose builds from when `build` names no Dockerfile.
const DEFAULT_DOCKERFILE: &str = "Dockerfile";

struct Collector<'a> {
    out: BTreeSet<Violation>,
    /// Each service's image, for messages.
    images: &'a BTreeMap<String, String>,
    pins: &'a Pins,
    /// Every resolved bind source and the services that use it.
    binds: Vec<(PathBuf, Vec<String>)>,
    /// Every resolved build context and Dockerfile, with what it is and the
    /// service that builds from it.
    builds: Vec<(PathBuf, String, String)>,
    /// The project's own prefix for volume and network names.
    prefix: String,
}

impl Collector<'_> {
    /// Record `judgment` for every service in `users` (or for the project
    /// when none uses the setting).
    fn push(&mut self, users: &[&str], judgment: Judgment, detail: &str) {
        let allow = match judgment {
            Judgment::Ok => return,
            Judgment::Grant(g) => Some(g),
            Judgment::Refuse(why) => {
                return self.add(users, None, format!("{detail}: {why}"));
            }
        };
        self.add(users, allow, detail.to_string());
    }

    /// Judge the bind source `raw` and remember it for [`nesting`](Self::nesting).
    fn bind(
        &mut self,
        users: &[&str],
        raw: &str,
        detail: &str,
        roots: &Roots,
        resolve: Resolver<'_>,
    ) {
        // compose prints a literal `$` as `$$`; the mount uses the literal.
        match host_path(&raw.replace("$$", "$"), resolve) {
            Ok(p) => {
                let judgment = judge_source(&p, raw, roots);
                self.binds
                    .push((p, users.iter().map(|u| u.to_string()).collect()));
                self.push(users, judgment, detail);
            }
            Err(why) => self.push(users, Judgment::Refuse(why), detail),
        }
    }

    /// Refuse a bind that contains another bind of this stack, or nests with
    /// one another stack holds a grant for: a container that can write the
    /// outer one could swap a symlink in for the inner one before it is
    /// mounted again. Equal sources are fine: a mount root cannot be replaced
    /// from inside.
    fn nesting(&mut self, roots: &Roots) {
        let binds = std::mem::take(&mut self.binds);
        // A build reads its context and Dockerfile from the host: if a
        // container can write a bind that holds either, or one inside the
        // context, it can swap in a symlink and the next build reads host
        // files into the image.
        for (b, what, svc) in std::mem::take(&mut self.builds) {
            let nests = |p: &PathBuf| b.starts_with(p) || p.starts_with(&b);
            let hit = binds
                .iter()
                .map(|(p, _)| (p, "a bind of this stack".to_string()))
                .chain(
                    roots
                        .other_binds
                        .iter()
                        .map(|o| (o, "a bind another stack holds a grant for".into())),
                )
                .chain(
                    roots
                        .container_binds
                        .iter()
                        .map(|(p, c)| (p, format!("a writable bind of container {c}"))),
                )
                .find(|(p, _)| nests(p));
            if let Some((p, whose)) = hit {
                self.push(
                    &[svc.as_str()],
                    Judgment::Refuse(format!("it nests with {}, {whose}", p.display())),
                    &format!("build {what} {}", b.display()),
                );
            }
        }
        for (p, users) in &binds {
            let users: Vec<&str> = users.iter().map(String::as_str).collect();
            if let Some((q, _)) = binds.iter().find(|(q, _)| q != p && q.starts_with(p)) {
                self.push(
                    &users,
                    Judgment::Refuse(format!(
                        "it contains {}, another bind of this stack",
                        q.display()
                    )),
                    &format!("bind {}", p.display()),
                );
            }
            if let Some(o) = roots
                .other_binds
                .iter()
                .find(|o| *o != p && (o.starts_with(p) || p.starts_with(o)))
            {
                self.push(
                    &users,
                    Judgment::Refuse(format!(
                        "it nests with {}, a bind another stack holds a grant for",
                        o.display()
                    )),
                    &format!("bind {}", p.display()),
                );
            }
        }
    }

    fn add(&mut self, users: &[&str], allow: Option<String>, detail: String) {
        if users.is_empty() {
            // A grant is per service, so a setting no service uses cannot
            // get one.
            let detail = match allow {
                Some(_) => format!("{detail} (declared but used by no service; remove it)"),
                None => detail,
            };
            self.out.insert(Violation {
                service: String::new(),
                image: String::new(),
                definition: String::new(),
                image_digest: String::new(),
                allow: None,
                detail,
            });
            return;
        }
        for svc in users {
            self.out.insert(Violation {
                service: svc.to_string(),
                image: self.images.get(*svc).cloned().unwrap_or_default(),
                definition: self.pins.definitions.get(*svc).cloned().unwrap_or_default(),
                image_digest: self
                    .pins
                    .images
                    .get(*svc)
                    .map(|p| p.digest.clone())
                    .unwrap_or_default(),
                allow: allow.clone(),
                detail: detail.clone(),
            });
        }
    }
}

/// Services whose `field` refers to top-level entry `name`.
fn users_of<'a>(cfg: &'a Value, field: &str, name: &str) -> Vec<&'a str> {
    let Some(services) = cfg.get("services").and_then(Value::as_object) else {
        return Vec::new();
    };
    services
        .iter()
        .filter(|(_, s)| match s.get(field) {
            Some(Value::Object(m)) => m.contains_key(name),
            Some(Value::Array(a)) => a.iter().any(|e| match e {
                Value::String(n) => n == name,
                other => str_of(other.get("source")) == name,
            }),
            _ => false,
        })
        .map(|(k, _)| k.as_str())
        .collect()
}

/// `v` serialized with object keys sorted at every level, so the digest does
/// not depend on key order.
fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                canonical(&o[k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(e, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// Each service's definition digest over the user's own compose files'
/// resolved config: the service with every key, the project name, and the
/// top-level volumes, networks, secrets and configs it refers to.
pub fn digests(cfg: &Value) -> BTreeMap<String, String> {
    let Some(services) = cfg.get("services").and_then(Value::as_object) else {
        return BTreeMap::new();
    };
    services
        .iter()
        .map(|(name, svc)| {
            let mut refs = serde_json::Map::new();
            for kind in ["volumes", "networks", "secrets", "configs"] {
                let used: serde_json::Map<String, Value> = cfg
                    .get(kind)
                    .and_then(Value::as_object)
                    .into_iter()
                    .flatten()
                    .filter(|(key, _)| users_of(cfg, kind, key).contains(&name.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                refs.insert(kind.to_string(), Value::Object(used));
            }
            let mut text = String::new();
            canonical(
                &serde_json::json!({
                    "project": cfg.get("name"),
                    "service": svc,
                    "refs": refs,
                }),
                &mut text,
            );
            let hex = plugin_toolkit::hash::sha256_hex(text.as_bytes());
            (name.clone(), format!("{DIGEST_PREFIX}{hex}"))
        })
        .collect()
}

/// Every setting in the resolved config `cfg` that needs a grant or is
/// refused outright, with grants bound to `pins`. A grantable setting of a
/// service that builds its image, or whose image has no registry digest, is
/// refused: nothing pins what that image holds.
pub fn violations(
    cfg: &Value,
    pins: &Pins,
    roots: &Roots,
    resolve: Resolver<'_>,
) -> Vec<Violation> {
    let builders: BTreeSet<&str> = cfg
        .get("services")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(_, s)| non_empty(s.get("build")))
        .map(|(k, _)| k.as_str())
        .collect();
    raw_violations(cfg, pins, roots, resolve)
        .into_iter()
        .map(|mut v| {
            if v.allow.is_some() {
                let why = if builders.contains(v.service.as_str()) {
                    Some("a service that builds its image cannot hold a grant")
                } else if !pins.images.contains_key(&v.service) {
                    Some(
                        "its image has no registry digest (built locally or not pulled), so it cannot hold a grant",
                    )
                } else {
                    None
                };
                if let Some(why) = why {
                    v.allow = None;
                    v.detail = format!("{} ({why})", v.detail);
                }
            }
            v
        })
        .collect()
}

/// The services with a setting a grant could admit, whose images
/// [`image_pins`] must look up.
pub fn needing_grants(cfg: &Value, roots: &Roots, resolve: Resolver<'_>) -> BTreeSet<String> {
    raw_violations(cfg, &Pins::default(), roots, resolve)
        .into_iter()
        .filter(|v| v.allow.is_some() && !v.service.is_empty())
        .map(|v| v.service)
        .collect()
}

fn raw_violations(
    cfg: &Value,
    pins: &Pins,
    roots: &Roots,
    resolve: Resolver<'_>,
) -> Vec<Violation> {
    let all = cfg.get("services").and_then(Value::as_object);
    let images: BTreeMap<String, String> = all
        .into_iter()
        .flatten()
        .map(|(k, s)| (k.clone(), str_of(s.get("image")).to_string()))
        .collect();
    let mut c = Collector {
        out: BTreeSet::new(),
        images: &images,
        pins,
        binds: Vec::new(),
        builds: Vec::new(),
        prefix: format!("{}_", str_of(cfg.get("name"))),
    };
    for key in keys_outside(cfg, &[TOP_KEYS]) {
        c.push(
            &[],
            Judgment::Refuse("not supported".into()),
            &format!("top-level key '{key}'"),
        );
    }
    project_entries(cfg, &mut c, roots, resolve);
    for (name, svc) in all.into_iter().flatten() {
        service(name, svc, &mut c, roots, resolve);
    }
    c.nesting(roots);
    c.out.into_iter().collect()
}

fn project_entries(cfg: &Value, c: &mut Collector<'_>, roots: &Roots, resolve: Resolver<'_>) {
    let section = |key: &str| {
        cfg.get(key)
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
    };
    for (key, net) in section("networks") {
        let users = users_of(cfg, "networks", key);
        network(key, net, &users, c);
    }
    for (key, vol) in section("volumes") {
        let users = users_of(cfg, "volumes", key);
        volume(key, vol, &users, c, roots, resolve);
    }
    for kind in ["secrets", "configs"] {
        for (key, entry) in section(kind) {
            let users = users_of(cfg, kind, key);
            for k in keys_outside(entry, &[SECRET_KEYS]) {
                c.push(
                    &users,
                    Judgment::Refuse("not supported".into()),
                    &format!("{kind} {key}: key '{k}'"),
                );
            }
            if let Some(file) = entry.get("file").and_then(Value::as_str) {
                c.bind(
                    &users,
                    file,
                    &format!("{kind} {key} mounts host file {file}"),
                    roots,
                    resolve,
                );
            }
        }
    }
}

fn network(key: &str, net: &Value, users: &[&str], c: &mut Collector<'_>) {
    for k in keys_outside(net, &[NETWORK_KEYS]) {
        c.push(
            users,
            Judgment::Refuse("not supported".into()),
            &format!("network {key}: key '{k}'"),
        );
    }
    let name = net.get("name").and_then(Value::as_str).unwrap_or(key);
    let driver = str_of(net.get("driver"));
    if name == "host" || driver == "host" {
        c.push(
            users,
            Judgment::Grant(ALLOW_NETWORK_HOST.into()),
            &format!("network {key} is the host network"),
        );
        return;
    }
    let external = net.get("external").and_then(Value::as_bool) == Some(true);
    if external || !name.starts_with(&c.prefix) {
        let prefix = c.prefix.clone();
        c.push(
            users,
            Judgment::Grant(format!("{ALLOW_NETWORK}{name}")),
            &format!(
                "network {key} joins {name}, {}",
                if external {
                    "an external network".to_string()
                } else {
                    format!("named outside the project's '{prefix}' prefix")
                }
            ),
        );
    }
    if GRANTED_NETWORK_DRIVERS.contains(&driver) {
        c.push(
            users,
            Judgment::Grant(format!("{ALLOW_NETWORK_DRIVER}{driver}")),
            &format!("network {key} uses the {driver} driver"),
        );
    } else if !PLAIN_NETWORK_DRIVERS.contains(&driver) {
        c.push(
            users,
            Judgment::Refuse(format!("driver '{driver}' is not supported")),
            &format!("network {key}"),
        );
    }
}

fn volume(
    key: &str,
    vol: &Value,
    users: &[&str],
    c: &mut Collector<'_>,
    roots: &Roots,
    resolve: Resolver<'_>,
) {
    for k in keys_outside(vol, &[VOLUME_KEYS]) {
        c.push(
            users,
            Judgment::Refuse("not supported".into()),
            &format!("volume {key}: key '{k}'"),
        );
    }
    let name = vol.get("name").and_then(Value::as_str).unwrap_or(key);
    if vol.get("external").and_then(Value::as_bool) == Some(true) {
        c.push(
            users,
            Judgment::Grant(format!("{ALLOW_EXTERNAL_VOLUME}{name}")),
            &format!("volume {key} is the external volume {name}"),
        );
    } else if !name.starts_with(&c.prefix) {
        let prefix = c.prefix.clone();
        c.push(
            users,
            Judgment::Grant(format!("{ALLOW_EXTERNAL_VOLUME}{name}")),
            &format!("volume {key} is {name}, named outside the project's '{prefix}' prefix"),
        );
    }
    let driver = str_of(vol.get("driver"));
    if !driver.is_empty() && driver != "local" {
        c.push(
            users,
            Judgment::Refuse(format!("driver '{driver}' is not supported")),
            &format!("volume {key}"),
        );
    }
    let opts = vol.get("driver_opts");
    let device = str_of(opts.and_then(|o| o.get("device")));
    if device.is_empty() {
        return;
    }
    let kind = str_of(opts.and_then(|o| o.get("type")));
    if mounts_device_as_bind(str_of(opts.and_then(|o| o.get("o")))) {
        c.bind(
            users,
            device,
            &format!("volume {key} binds host path {device}"),
            roots,
            resolve,
        );
    } else if !REMOTE_VOLUME_TYPES.contains(&kind) {
        c.push(
            users,
            Judgment::Refuse(format!(
                "mount type '{kind}' of device {device} is not supported"
            )),
            &format!("volume {key}"),
        );
    }
}

fn service(name: &str, svc: &Value, c: &mut Collector<'_>, roots: &Roots, resolve: Resolver<'_>) {
    let me = [name];
    for key in keys_outside(svc, &[PLAIN_SERVICE_KEYS, CHECKED_SERVICE_KEYS]) {
        c.push(
            &me,
            Judgment::Refuse("not supported".into()),
            &format!("key '{key}'"),
        );
    }
    if svc.get("privileged").and_then(Value::as_bool) == Some(true) {
        c.push(
            &me,
            Judgment::Grant(ALLOW_PRIVILEGED.into()),
            "privileged: true",
        );
    }
    for mode in MODES {
        let value = str_of(svc.get(mode.key));
        // Any other network_mode joins the network it names directly.
        if mode.key == "network_mode"
            && !PLAIN_NETWORK_MODES.contains(&value)
            && value != "host"
            && !value.starts_with("container:")
            && !value.starts_with("service:")
        {
            if !value.starts_with(&c.prefix) {
                c.push(
                    &me,
                    Judgment::Grant(format!("{ALLOW_NETWORK}{value}")),
                    &format!("network_mode: {value} joins a network outside the project"),
                );
            }
            continue;
        }
        c.push(
            &me,
            namespace(value, mode),
            &format!("{}: {value}", mode.key),
        );
    }
    for opt in svc
        .get("security_opt")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let opt = opt.as_str().unwrap_or("");
        let nnp = opt.replace('=', ":");
        if nnp != "no-new-privileges" && nnp != "no-new-privileges:true" {
            c.push(
                &me,
                Judgment::Grant(ALLOW_SECURITY_OPT.into()),
                &format!("security_opt: {opt}"),
            );
        }
    }
    for cap in svc
        .get("cap_add")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let cap = norm_cap(cap.as_str().unwrap_or(""));
        if !SAFE_CAPS.contains(&cap.as_str()) {
            c.push(
                &me,
                Judgment::Grant(format!("{ALLOW_CAP}{cap}")),
                &format!("cap_add: {cap}"),
            );
        }
    }
    let reserved = svc
        .pointer("/deploy/resources/reservations/devices")
        .filter(|d| non_empty(Some(d)));
    for (key, v) in [
        ("devices", svc.get("devices")),
        ("gpus", svc.get("gpus")),
        ("deploy.resources.reservations.devices", reserved),
    ] {
        if non_empty(v) {
            c.push(
                &me,
                Judgment::Grant(ALLOW_DEVICES.into()),
                &format!("{key} passes host devices"),
            );
        }
    }
    if non_empty(svc.get("volumes_from")) {
        c.push(
            &me,
            Judgment::Grant(ALLOW_VOLUMES_FROM.into()),
            "volumes_from mounts another container's volumes",
        );
    }
    for m in svc
        .get("volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let source = str_of(m.get("source"));
        let target = str_of(m.get("target"));
        match str_of(m.get("type")) {
            "bind" => c.bind(
                &me,
                source,
                &format!("binds host path {source} into {target}"),
                roots,
                resolve,
            ),
            "volume" | "tmpfs" | "image" => {}
            other => c.push(
                &me,
                Judgment::Refuse(format!("mount type '{other}' is not supported")),
                &format!("mount {target}"),
            ),
        }
    }
    for f in svc
        .get("env_file")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let path = f.as_str().unwrap_or_else(|| str_of(f.get("path")));
        if !in_stack_dir(path, roots, false, resolve) {
            c.push(
                &me,
                Judgment::Refuse("only files inside the stack dir are allowed".into()),
                &format!("env_file {path}"),
            );
        }
    }
    image_names(name, svc, c, roots);
    if let Some(build) = svc.get("build") {
        build_section(build, &me, c, roots, resolve);
    }
}

/// `image` in one spelling: no `docker.io/` or `library/` prefix, and
/// `:latest` when it names no tag or digest.
pub fn norm_image(image: &str) -> String {
    let i = image
        .strip_prefix("docker.io/")
        .or_else(|| image.strip_prefix("index.docker.io/"))
        .unwrap_or(image);
    let i = i.strip_prefix("library/").unwrap_or(i);
    let last = i.rsplit('/').next().unwrap_or(i);
    if last.contains(':') || i.contains('@') {
        i.to_string()
    } else {
        format!("{i}:latest")
    }
}

/// Refuse a build that would tag an image a granted service runs, and any
/// other stack naming one: building or pulling it under that name would
/// change what the granted service runs.
fn image_names(name: &str, svc: &Value, c: &mut Collector<'_>, roots: &Roots) {
    let builds = non_empty(svc.get("build"));
    let named: Vec<String> = std::iter::once(str_of(svc.get("image")))
        .chain(
            svc.pointer("/build/tags")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|t| t.as_str().unwrap_or("")),
        )
        .filter(|n| !n.is_empty())
        .map(norm_image)
        .collect();
    for n in named {
        let why = roots
            .granted_images
            .iter()
            .filter(|g| g.image == n)
            .find_map(|g| {
                if builds {
                    Some(format!(
                        "a build would tag {n}, which granted service {}/{} runs",
                        g.stack, g.service
                    ))
                } else if g.stack != roots.stack {
                    Some(format!(
                        "{n} is the image granted service {}/{} runs",
                        g.stack, g.service
                    ))
                } else {
                    None
                }
            });
        if let Some(why) = why {
            c.push(&[name], Judgment::Refuse(why), &format!("image {n}"));
        }
    }
}

fn build_section(
    build: &Value,
    me: &[&str],
    c: &mut Collector<'_>,
    roots: &Roots,
    resolve: Resolver<'_>,
) {
    for k in keys_outside(build, &[BUILD_KEYS]) {
        c.push(
            me,
            Judgment::Refuse("not supported".into()),
            &format!("build key '{k}'"),
        );
    }
    let context = str_of(build.get("context"));
    let Some(context_path) = stack_path(context, roots, true, resolve) else {
        c.push(
            me,
            Judgment::Refuse("only the stack dir or a path inside it is allowed".into()),
            &format!("build context {context}"),
        );
        return;
    };
    c.builds
        .push((context_path, "context".into(), me[0].to_string()));
    let dockerfile = match str_of(build.get("dockerfile")) {
        "" if build.get("dockerfile_inline").is_none() => DEFAULT_DOCKERFILE,
        d => d,
    };
    if !dockerfile.is_empty() {
        let full = if Path::new(dockerfile).is_absolute() {
            dockerfile.to_string()
        } else {
            format!("{}/{dockerfile}", context.trim_end_matches('/'))
        };
        match stack_path(&full, roots, false, resolve) {
            Some(p) => c.builds.push((p, "dockerfile".into(), me[0].to_string())),
            None => c.push(
                me,
                Judgment::Refuse("only a file inside the stack dir is allowed".into()),
                &format!("build dockerfile {dockerfile}"),
            ),
        }
    }
    let network = str_of(build.get("network"));
    if !matches!(network, "" | "default" | "bridge" | "none") {
        c.push(
            me,
            Judgment::Refuse("only default, bridge or none is allowed".into()),
            &format!("build network {network}"),
        );
    }
}

/// Whether `grant` admits `allow` for `v`'s service, definition and image.
/// Bind grants match by resolved path, so a grant written through a symlink
/// still matches.
fn admits(g: &Grant, v: &Violation, allow: &str, resolve: Resolver<'_>) -> bool {
    if g.service != v.service
        || v.definition.is_empty()
        || g.definition != v.definition
        || v.image_digest.is_empty()
        || g.image_digest != v.image_digest
    {
        return false;
    }
    if g.allow == allow {
        return true;
    }
    match (
        g.allow.strip_prefix(ALLOW_BIND),
        allow.strip_prefix(ALLOW_BIND),
    ) {
        (Some(granted), Some(wanted)) => {
            host_path(granted, resolve).is_ok_and(|p| p == Path::new(wanted))
        }
        _ => false,
    }
}

/// Refuse `cfg` unless every violation is granted to its service,
/// definition and image.
pub fn check(
    cfg: &Value,
    pins: &Pins,
    grants: &[Grant],
    roots: &Roots,
    resolve: Resolver<'_>,
) -> Result<()> {
    let refused: Vec<Violation> = violations(cfg, pins, roots, resolve)
        .into_iter()
        .filter(|v| match &v.allow {
            Some(allow) => !grants.iter().any(|g| admits(g, v, allow, resolve)),
            None => true,
        })
        .collect();
    if refused.is_empty() {
        return Ok(());
    }
    let lines: Vec<String> = refused
        .iter()
        .map(|v| {
            let who = if v.service.is_empty() {
                "project".to_string()
            } else {
                format!("{} ({})", v.service, v.image)
            };
            let upstream = grants.iter().any(|g| {
                g.service == v.service
                    && g.definition == v.definition
                    && g.image_digest != v.image_digest
            });
            match v.grant() {
                Some(_) if upstream => format!(
                    "{who}: {} (image changed upstream; re-approve with {ALLOW_TOOL} approveCurrent)",
                    v.detail
                ),
                Some(g) => format!("{who}: {} (grant '{g}')", v.detail),
                None => format!("{who}: {} (cannot be granted)", v.detail),
            }
        })
        .collect();
    bail!(
        "compose policy refuses this stack: {}; an admin can grant what is grantable with {ALLOW_TOOL}",
        lines.join("; ")
    )
}

fn parse(raw: &str) -> Result<Value> {
    serde_json::from_str(raw).context("parsing `compose config --format json`")
}

/// `raw`, the resolved config of the stack dir `base`, with each service's
/// env files read into its `environment` and `env_file` dropped, so the
/// definition digest covers them and compose runs exactly what was checked.
/// The files must lie inside `base` and are read from `dir` (the stack dir,
/// or a restore's staging dir) without following symlinks. As in compose,
/// `environment` wins over env files and later files over earlier ones.
pub fn prepare(raw: &str, base: &Path, dir: &StackDir) -> Result<Value> {
    let mut cfg = parse(raw)?;
    let Some(services) = cfg.get_mut("services").and_then(Value::as_object_mut) else {
        return Ok(cfg);
    };
    for (name, svc) in services.iter_mut() {
        let Some(svc) = svc.as_object_mut() else {
            continue;
        };
        if let Some(build) = svc.get("build") {
            build_paths_unlinked(name, build, base, dir)?;
        }
        let Some(files) = svc.remove("env_file") else {
            continue;
        };
        let mut env = serde_json::Map::new();
        for f in files.as_array().into_iter().flatten() {
            let path = f
                .as_str()
                .unwrap_or_else(|| str_of(f.get("path")))
                .replace("$$", "$");
            let path = path.as_str();
            let required = f.get("required").and_then(Value::as_bool).unwrap_or(true);
            let rel = Path::new(path)
                .strip_prefix(base)
                .ok()
                .filter(|r| {
                    r.components().next().is_some()
                        && r.components().all(|c| matches!(c, Component::Normal(_)))
                })
                .ok_or_else(|| {
                    anyhow!("service {name}: env_file {path} is not inside the stack dir")
                })?;
            let text = match dir.read_rel(rel)? {
                Some(text) => text,
                None if !required => continue,
                None => bail!("service {name}: env_file {path} does not exist"),
            };
            for e in stacks::parse_env(&text) {
                if e.expands {
                    bail!(
                        "service {name}: env_file {path} sets {} from a variable (`$VAR` or `${{VAR}}`), which orca does not expand; put the value in single quotes or escape the `$` as `\\$` in double quotes",
                        e.key
                    );
                }
                // Escaped as compose prints `environment`, so a rerun reads
                // it back verbatim.
                env.insert(e.key, Value::String(e.value.replace('$', "$$")));
            }
        }
        if let Some(Value::Object(own)) = svc.get("environment") {
            env.extend(own.clone());
        }
        svc.insert("environment".into(), Value::Object(env));
    }
    Ok(cfg)
}

/// Refuse a build context or Dockerfile reached through a symlink: each is
/// opened component by component from the stack dir without following one.
/// A path not lexically inside `base` is refused too, as the policy judges
/// paths canonicalised and would accept an alias (`/proc/self/root/...`)
/// this walk never opens.
fn build_paths_unlinked(name: &str, build: &Value, base: &Path, dir: &StackDir) -> Result<()> {
    let inside = |p: &Path| {
        p.strip_prefix(base)
            .ok()
            .filter(|r| r.components().all(|c| matches!(c, Component::Normal(_))))
            .map(Path::to_path_buf)
    };
    let context = str_of(build.get("context")).replace("$$", "$");
    let rel = inside(Path::new(&context)).ok_or_else(|| {
        anyhow!("service {name}: build context {context} is not inside the stack dir")
    })?;
    dir.open_rel(&rel)
        .with_context(|| format!("service {name}: build context {context}"))?
        .ok_or_else(|| anyhow!("service {name}: build context {context} does not exist"))?;
    if build.get("dockerfile_inline").is_some() {
        return Ok(());
    }
    let dockerfile = match str_of(build.get("dockerfile")) {
        "" => DEFAULT_DOCKERFILE.to_string(),
        d => d.replace("$$", "$"),
    };
    // Joined to the context as written, not `dir`'s path: on restore `dir`
    // is the staging dir and `base` the live one.
    let full = Path::new(&context).join(&dockerfile);
    let rel = inside(&full)
        .filter(|r| r.components().next().is_some())
        .ok_or_else(|| {
            anyhow!("service {name}: build dockerfile {dockerfile} is not inside the stack dir")
        })?;
    dir.read_rel(&rel)
        .with_context(|| format!("service {name}: build dockerfile {dockerfile}"))?
        .ok_or_else(|| {
            anyhow!(
                "service {name}: the build needs a Dockerfile at {} and there is none; add that file",
                full.display()
            )
        })?;
    Ok(())
}

/// Whether a `local` volume's mount options `o` bind its `device`, a host
/// path.
fn mounts_device_as_bind(o: &str) -> bool {
    o.split(',').any(|o| matches!(o.trim(), "bind" | "rbind"))
}

/// The writable bind sources of every container on the host, running or
/// stopped, with its name, when `cfg` builds an image: its binds, its
/// volumes' sources and the devices of `local` volumes that bind one. Any
/// of them can swap a symlink into a build path it nests with, whoever owns
/// it. None without an engine, which leaves nothing to build with.
async fn container_binds(
    docker: Option<&bollard::Docker>,
    cfg: &Value,
) -> Result<Vec<(String, String)>> {
    let builds = cfg
        .get("services")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .any(|(_, s)| non_empty(s.get("build")));
    let Some(docker) = docker.filter(|_| builds) else {
        return Ok(Vec::new());
    };
    let containers = docker
        .list_containers(Some(
            bollard::query_parameters::ListContainersOptionsBuilder::new()
                .all(true)
                .build(),
        ))
        .await
        .map_err(|e| anyhow!("listing containers to check build paths against: {e}"))?;
    let mut devices: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut out = Vec::new();
    for c in &containers {
        let name = c
            .names
            .iter()
            .flatten()
            .next()
            .map(|n| n.trim_start_matches('/').to_string())
            .or_else(|| c.id.clone())
            .unwrap_or_default();
        for m in c.mounts.iter().flatten().filter(|m| m.rw != Some(false)) {
            // A volume's own source counts too: a driver plugin can mount a
            // host path there, whatever it reports as its driver.
            if matches!(m.typ.as_deref(), Some("bind" | "volume")) {
                out.extend(m.source.clone().map(|s| (s, name.clone())));
            }
            let device = match (m.typ.as_deref(), &m.name) {
                (Some("volume"), Some(vol)) => {
                    if !devices.contains_key(vol) {
                        let v = docker.inspect_volume(vol).await.map_err(|e| {
                            anyhow!("inspecting volume {vol} to check build paths against: {e}")
                        })?;
                        let device = (v.driver == "local"
                            && mounts_device_as_bind(
                                v.options.get("o").map(String::as_str).unwrap_or_default(),
                            ))
                        .then(|| v.options.get("device").cloned())
                        .flatten();
                        devices.insert(vol.clone(), device);
                    }
                    devices[vol].clone()
                }
                _ => None,
            };
            out.extend(device.map(|s| (s, name.clone())));
        }
    }
    Ok(out)
}

/// The registry identity of each of `services`' images, where it has one.
/// With no engine, none has one.
pub async fn image_pins(
    docker: Option<&bollard::Docker>,
    cfg: &Value,
    services: &BTreeSet<String>,
) -> BTreeMap<String, ImagePin> {
    let mut pins = BTreeMap::new();
    let Some(docker) = docker else {
        return pins;
    };
    for name in services {
        let image = str_of(cfg.pointer(&format!("/services/{name}/image"))).to_string();
        if image.is_empty() {
            continue;
        }
        // An image the engine cannot inspect has no digest to bind to.
        let Ok(info) = docker.inspect_image(&image).await else {
            continue;
        };
        let mut refs = info.repo_digests.unwrap_or_default();
        refs.sort();
        let mut digests: Vec<&str> = refs
            .iter()
            .filter_map(|r| r.split_once('@').map(|(_, d)| d))
            .filter(|d| is_digest(d))
            .collect();
        digests.sort();
        digests.dedup();
        let Some(reference) = refs.iter().find(|r| r.contains('@')) else {
            continue;
        };
        pins.insert(
            name.clone(),
            ImagePin {
                digest: digests.join(","),
                reference: reference.clone(),
            },
        );
    }
    pins
}

/// Every image a granted service of a registered stack runs, `row`'s own
/// grants as they are now included.
fn granted_images(row: &StackRow, others: &[StackRow]) -> Vec<GrantedImage> {
    others
        .iter()
        .chain(std::iter::once(row))
        .flat_map(|r| {
            r.allow.iter().map(|g| GrantedImage {
                image: norm_image(&g.image),
                stack: r.name.clone(),
                service: g.service.clone(),
            })
        })
        .collect()
}

/// The daemon's home, `$DOCKER_CONFIG` and `~/.docker`. A home of `/` (a
/// service with no real home) is left out: it would refuse every bind.
fn daemon_dirs() -> Vec<String> {
    let below_root = |d: &String| Path::new(d).is_absolute() && Path::new(d).parent().is_some();
    let home = std::env::var("HOME").ok().filter(below_root);
    home.iter()
        .flat_map(|h| [h.clone(), format!("{}/.docker", h.trim_end_matches('/'))])
        .chain(std::env::var("DOCKER_CONFIG").ok().filter(below_root))
        .collect()
}

/// The roots `row`, whose dir is `stack_dir`, is judged against, with every
/// other registered stack's dir, bind grants and granted images.
fn live_roots(row: &StackRow, stack_dir: &Path, stacks_roots: &[String]) -> Result<Roots> {
    let others: Vec<StackRow> = stacks::list()?
        .into_iter()
        .filter(|r| r.name != row.name)
        .collect();
    let dirs: Vec<String> = others.iter().map(|r| r.dir.clone()).collect();
    let binds: Vec<String> = others
        .iter()
        .flat_map(|r| &r.allow)
        .filter_map(|g| g.allow.strip_prefix(ALLOW_BIND).map(String::from))
        .collect();
    let resolve = &crate::lifecycle::resolve;
    Ok(Roots::new(
        stack_dir,
        stacks_roots,
        &engine_state::backup_roots(),
        resolve,
    )?
    .with_others(&dirs, &binds, resolve)
    .with_compose_file(&row.file)
    .with_daemon_dirs(&daemon_dirs(), resolve)
    .with_granted_images(&row.name, granted_images(row, &others)))
}

/// Check `cfg`, the [`prepare`]d config of `row` whose dir is `stack_dir`,
/// against the row's grants. `user_cfg` is that of the user's own files
/// (without [`compose::ORCA_FILE`]), which definition digests come from.
/// Returns what the grants were bound to.
pub async fn check_stack(
    docker: Option<&bollard::Docker>,
    cfg: &Value,
    user_cfg: &Value,
    row: &StackRow,
    stack_dir: &Path,
    stacks_roots: &[String],
) -> Result<Pins> {
    let resolve = &crate::lifecycle::resolve;
    let roots = live_roots(row, stack_dir, stacks_roots)?
        .with_container_binds(&container_binds(docker, cfg).await?, resolve);
    let pins = Pins {
        definitions: digests(user_cfg),
        images: image_pins(docker, cfg, &needing_grants(cfg, &roots, resolve)).await,
    };
    check(cfg, &pins, &row.allow, &roots, resolve)?;
    Ok(pins)
}

/// The stack dir, opened under a stacks root, and the [`prepare`]d config of
/// exactly `compose`'s files and of the user's own files among them.
async fn resolved(
    row: &StackRow,
    compose: &Compose,
) -> Result<(StackDir, Vec<String>, Value, Value)> {
    let roots = crate::tools::stacks_roots()?;
    let dir = StackDir::open(&row.dir, &roots, false)?
        .ok_or_else(|| anyhow!("stack dir {} does not exist", row.dir))?;
    let files =
        |c: &Compose| -> Vec<PathBuf> { c.files().into_iter().map(Path::to_path_buf).collect() };
    let raw = stacks::resolved_config(dir.path(), &files(compose), None).await?;
    let cfg = prepare(&raw, dir.path(), &dir)?;
    let user = compose.without_orca();
    let user_cfg = if user.files() == compose.files() {
        cfg.clone()
    } else {
        let raw = stacks::resolved_config(dir.path(), &files(&user), None).await?;
        prepare(&raw, dir.path(), &dir)?
    };
    Ok((dir, roots, cfg, user_cfg))
}

/// The config [`gate`] checked, which compose runs from.
#[derive(Debug)]
pub struct Checked {
    dir: PathBuf,
    project: String,
    config: String,
}

impl Checked {
    pub async fn up(&self, services: &[&str]) -> Result<String> {
        self.run(&[&["up", "-d"], services].concat()).await
    }

    /// `up --no-start`.
    pub async fn create(&self, services: &[&str]) -> Result<String> {
        self.run(&[&["up", "--no-start"], services].concat()).await
    }

    pub async fn build(&self) -> Result<String> {
        self.run(&["build", "--no-cache"]).await
    }

    pub async fn pull(&self) -> Result<String> {
        self.run(&["pull", "-q"]).await
    }

    /// `compose <sub>` over the checked config, written into a fresh 0700
    /// dir no one else can write. The config is already interpolated, so
    /// the stack's `.env` is not read again.
    pub async fn run(&self, sub: &[&str]) -> Result<String> {
        let tmp = fsat::PrivateDir::new("orca-compose-")?;
        let file = tmp.write("config.json", self.config.as_bytes())?;
        let args = checked_args(&self.project, &self.dir, &file, sub);
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        crate::run(&argv, None).await
    }
}

fn checked_args(project: &str, dir: &Path, file: &Path, sub: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = [
        "compose",
        "-p",
        project,
        "--project-directory",
        &dir.to_string_lossy(),
        "--env-file",
        "/dev/null",
        "-f",
        &file.to_string_lossy(),
    ]
    .map(String::from)
    .to_vec();
    args.extend(sub.iter().map(|s| s.to_string()));
    args
}

/// `cfg` as compose runs it: each service holding a grant runs its image by
/// registry digest, so a tag moved after the check is never used.
fn run_config(mut cfg: Value, grants: &[Grant], pins: &Pins) -> Value {
    for (name, pin) in &pins.images {
        if grants.iter().any(|g| &g.service == name)
            && let Some(svc) = cfg.pointer_mut(&format!("/services/{name}"))
        {
            svc["image"] = Value::String(pin.reference.clone());
        }
    }
    cfg
}

/// Refuse to run `compose` for `row` unless its stack dir is inside a stacks
/// root and the config of exactly `compose`'s files passes [`check_stack`].
/// Returns that config to run compose from.
pub async fn gate(
    docker: Option<&bollard::Docker>,
    row: &StackRow,
    compose: &Compose,
) -> Result<Checked> {
    let (dir, roots, cfg, user_cfg) = resolved(row, compose).await?;
    let pins = check_stack(docker, &cfg, &user_cfg, row, dir.path(), &roots).await?;
    let project = str_of(cfg.get("name")).to_string();
    if project.is_empty() {
        bail!(
            "compose config for stack '{}' has no project name",
            row.name
        );
    }
    Ok(Checked {
        dir: dir.path().to_path_buf(),
        project,
        config: run_config(cfg, &row.allow, &pins).to_string(),
    })
}

/// What `row` runs now that needs a grant, for an admin to approve. Fails on
/// anything no grant can admit.
async fn current_grants(docker: Option<&bollard::Docker>, row: &StackRow) -> Result<Vec<Grant>> {
    let compose = row.compose()?;
    let compose = if Path::new(&row.dir).join(compose::ORCA_FILE).is_file() {
        compose.with_orca()
    } else {
        compose
    };
    let (dir, roots, cfg, user_cfg) = resolved(row, &compose).await?;
    let roots = live_roots(row, dir.path(), &roots)?;
    let resolve = &crate::lifecycle::resolve;
    let pins = Pins {
        definitions: digests(&user_cfg),
        images: image_pins(docker, &cfg, &needing_grants(&cfg, &roots, resolve)).await,
    };
    let found = violations(&cfg, &pins, &roots, resolve);
    let refused: Vec<String> = found
        .iter()
        .filter(|v| v.allow.is_none())
        .map(|v| v.detail.clone())
        .collect();
    if !refused.is_empty() {
        bail!(
            "stack '{}' has settings no grant can admit: {}",
            row.name,
            refused.join("; ")
        );
    }
    Ok(found.iter().filter_map(Violation::grant).collect())
}

/// A grant string `docker.stack_allow` accepts.
fn validate_grant(grant: &str) -> Result<()> {
    if FIXED_GRANTS.contains(&grant) {
        return Ok(());
    }
    if let Some(cap) = grant.strip_prefix(ALLOW_CAP) {
        if cap.is_empty() || !cap.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
            bail!("grant '{grant}' needs an upper-case capability name");
        }
        return Ok(());
    }
    for prefix in [ALLOW_EXTERNAL_VOLUME, ALLOW_NETWORK] {
        if let Some(name) = grant.strip_prefix(prefix) {
            if name.is_empty() || name.contains('/') {
                bail!("grant '{grant}' needs an engine name");
            }
            return Ok(());
        }
    }
    if let Some(driver) = grant.strip_prefix(ALLOW_NETWORK_DRIVER) {
        if !GRANTED_NETWORK_DRIVERS.contains(&driver) {
            bail!(
                "grant '{grant}' needs one of the drivers {}",
                GRANTED_NETWORK_DRIVERS.join(", ")
            );
        }
        return Ok(());
    }
    let Some(path) = grant.strip_prefix(ALLOW_BIND) else {
        bail!(
            "unknown grant '{grant}'; expected one of {}, {ALLOW_CAP}<CAP>, {ALLOW_EXTERNAL_VOLUME}<name>, {ALLOW_NETWORK}<name>, {ALLOW_NETWORK_DRIVER}<driver> or {ALLOW_BIND}<absolute path>",
            FIXED_GRANTS.join(", ")
        );
    };
    let p = Path::new(path);
    if !p.is_absolute() || has_dotdot(path) || p.components().any(|c| c == Component::ParentDir) {
        bail!("grant '{grant}' needs an absolute path without '..'");
    }
    if p.parent().is_none() {
        bail!("binding '/' cannot be granted");
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// docker.stack_allow — grant a stack policy exceptions
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
pub struct DockerStackAllowArgs {
    /// Stack name. An unregistered one is adopted: registered at `dir` with
    /// its grants in one write, which needs `approve_current`.
    #[arg(long)]
    pub name: String,
    /// The stack dir, inside a stacks root. Required to adopt; for a
    /// registered stack it must match, so a stack cannot be moved here.
    #[arg(long)]
    #[serde(default)]
    pub dir: Option<String>,
    /// The compose file name in `dir`, which must exist (default
    /// `docker-compose.yml`). For a registered stack it must match.
    #[arg(long)]
    #[serde(default)]
    pub file: Option<String>,
    /// The full grant set, replacing the current one, each
    /// `<service>|<definition>|<grant>`, the definition digest as the
    /// policy refusal or an `approve_current` dry run shows it. A grant is
    /// `privileged`, `pid:host`, `pid:shared`, `ipc:host`, `ipc:shared`,
    /// `network_mode:host`, `network_mode:shared`, `userns_mode:host`,
    /// `cgroup:host`, `security_opt`, `devices`, `volumes_from`,
    /// `cap_add:<CAP>`, `external_volume:<name>`, `network:<name>`,
    /// `network_driver:macvlan|ipvlan` or `bind:<absolute host path>`.
    /// Repeatable; empty clears every grant.
    #[arg(long = "allow")]
    #[serde(default)]
    pub allow: Vec<String>,
    /// Add a grant for everything the stack's compose files on disk use now
    /// that needs one, each bound to its service's current definition.
    #[arg(long)]
    #[serde(default)]
    pub approve_current: bool,
    /// With `approve_current`, execute needs the dry run's `after` list
    /// echoed here, and is refused when the grants would differ from it.
    #[arg(long = "item")]
    #[serde(default)]
    pub items: Vec<String>,
    /// Record the grants. Omitted, returns them and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct DockerStackAllowOutput {
    /// `true`: nothing was written.
    pub dry_run: bool,
    pub name: String,
    /// `true`: the stack was not registered and is (or would be) registered
    /// by this call.
    pub adopted: bool,
    pub before: Vec<String>,
    pub after: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// [MUTATES STATE] Set the compose policy grants of a managed stack, each
/// bound to a service and its resolved definition, or adopt an existing
/// compose project as a stack together with its grants. Never starts or
/// changes containers.
/// Without `execute`, returns the grants and changes nothing.
#[orca_tool(
    domain = "docker",
    verb = "stack_allow",
    role = "admin",
    execute_gated = false
)]
async fn docker_stack_allow(
    args: DockerStackAllowArgs,
    ctx: &ToolCtx,
) -> Result<DockerStackAllowOutput> {
    execute::require_admin(ALLOW_TOOL, ctx)?;
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    stack_allow(args, docker).await
}

/// [`docker_stack_allow`] past the admin check, looking images up on
/// `docker`.
async fn stack_allow(
    args: DockerStackAllowArgs,
    docker: &bollard::Docker,
) -> Result<DockerStackAllowOutput> {
    let mut after = args
        .allow
        .iter()
        .map(|g| g.parse::<Grant>())
        .collect::<Result<Vec<_>>>()?;
    let (mut row, adopted) = match stacks::get(&args.name)? {
        Some(row) => {
            refuse_move(&row, &args)?;
            (row, false)
        }
        None => (adoptable(&args)?, true),
    };
    if args.approve_current {
        after.extend(current_grants(Some(docker), &row).await?);
    }
    after.sort();
    after.dedup();
    let show = |g: &[Grant]| g.iter().map(Grant::to_string).collect::<Vec<_>>();
    let before = show(&row.allow);
    let mut planned = show(&after);
    // Confirming the adopted path too stops an execute from registering a
    // dir no dry run showed, even when it needs no grant.
    if adopted {
        planned.push(adopt_item(&row));
    }
    if !args.execute {
        let how = if adopted {
            format!(
                "re-invoke {ALLOW_TOOL} with `execute: true`, the same `dir` and `file`, and `items` set to `after`"
            )
        } else if args.approve_current {
            format!("re-invoke {ALLOW_TOOL} with `execute: true` and `items` set to `after`")
        } else {
            format!("re-invoke {ALLOW_TOOL} with `execute: true`")
        };
        return Ok(DockerStackAllowOutput {
            dry_run: true,
            name: args.name,
            adopted,
            before,
            after: planned,
            how_to_execute: Some(how),
        });
    }
    if args.approve_current {
        execute::require_confirmed(ALLOW_TOOL, &args.items, &planned)?;
        let mut confirmed = args.items.clone();
        confirmed.sort();
        confirmed.dedup();
        let mut sorted = planned.clone();
        sorted.sort();
        if confirmed != sorted {
            bail!(
                "{ALLOW_TOOL}: the grants to record differ from the confirmed items (the stack changed since the dry run?); re-run the dry run"
            );
        }
    }
    row.allow = after;
    if adopted {
        // Insert, not put: a stack registered under this name since the
        // lookup fails the write instead of being overwritten.
        stacks::insert(&row)?;
    } else {
        stacks::put(&row)?;
    }
    Ok(DockerStackAllowOutput {
        dry_run: false,
        name: args.name,
        adopted,
        before,
        after: planned,
        how_to_execute: None,
    })
}

/// The `after` item naming the compose file an adoption registers.
fn adopt_item(row: &StackRow) -> String {
    format!(
        "{ADOPT_ITEM}{}",
        Path::new(&row.dir).join(&row.file).display()
    )
}

/// Refuse a `dir` or `file` that differs from registered `row`'s.
fn refuse_move(row: &StackRow, args: &DockerStackAllowArgs) -> Result<()> {
    let resolve = |p: &str| crate::lifecycle::resolve(Path::new(p)).ok();
    if let Some(dir) = &args.dir
        && dir != &row.dir
        && resolve(dir).is_none_or(|d| resolve(&row.dir) != Some(d))
    {
        bail!(
            "{ALLOW_TOOL}: stack '{}' is registered at {}, not {dir}; it cannot be moved here",
            row.name,
            row.dir
        );
    }
    if let Some(file) = &args.file
        && file != &row.file
    {
        bail!(
            "{ALLOW_TOOL}: stack '{}' is registered with compose file {}, not {file}",
            row.name,
            row.file
        );
    }
    Ok(())
}

/// The row adopting `args.name` would register: enabled, no grants yet, at
/// `args.dir` inside a stacks root, its compose file a regular file there.
fn adoptable(args: &DockerStackAllowArgs) -> Result<StackRow> {
    if !args.approve_current {
        bail!(
            "{ALLOW_TOOL}: stack '{}' is not registered; adopting it needs `approve_current`",
            args.name
        );
    }
    let Some(dir) = &args.dir else {
        bail!(
            "{ALLOW_TOOL}: stack '{}' is not registered; adopting it needs `dir`",
            args.name
        );
    };
    let file = args
        .file
        .clone()
        .unwrap_or_else(|| stacks::DEFAULT_COMPOSE_FILE.to_string());
    stacks::check_file_name(&file)?;
    let dir = stacks::stack_dir_in_roots(dir, &crate::tools::stacks_roots()?)?;
    stacks::check_dir_free(&args.name, &dir)?;
    let path = dir.join(&file);
    if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
        bail!(
            "{ALLOW_TOOL}: compose file {} is not a regular file",
            path.display()
        );
    }
    // compose reads these by path, following symlinks out of the stack dir.
    for name in compose::OVERRIDE_FILES.iter().chain(&[compose::ORCA_FILE]) {
        let p = dir.join(name);
        if std::fs::symlink_metadata(&p).is_ok_and(|m| !m.is_file()) {
            bail!("{ALLOW_TOOL}: {} is not a regular file", p.display());
        }
    }
    Ok(StackRow {
        name: args.name.clone(),
        dir: dir.to_string_lossy().into_owned(),
        file,
        enabled: true,
        allow: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::contract::OrcaToolDef;
    use plugin_toolkit::serde_json::json;

    /// Lexical resolution: no filesystem, `..` refused as the real one does.
    fn lexical(p: &Path) -> Result<PathBuf> {
        if !p.is_absolute() || p.components().any(|c| c == Component::ParentDir) {
            bail!("'{}' cannot be resolved", p.display());
        }
        Ok(p.components().collect())
    }

    const STACK: &str = "/opt/stacks/web";

    fn roots() -> Roots {
        Roots::new(
            Path::new(STACK),
            &["/opt/stacks".to_string()],
            &["/mnt/backups".to_string()],
            &lexical,
        )
        .unwrap()
    }

    fn cfg_with(extra: Value) -> Value {
        let mut cfg = json!({"name": "web", "services": {"app": {"image": "x:1"}}});
        for (k, v) in extra.as_object().unwrap() {
            cfg[k] = v.clone();
        }
        cfg
    }

    fn service(extra: Value) -> Value {
        let mut svc = json!({"image": "x:1"});
        for (k, v) in extra.as_object().unwrap() {
            svc[k] = v.clone();
        }
        json!({"name": "web", "services": {"app": svc}})
    }

    fn bind(source: &str) -> Value {
        service(json!({"volumes": [{"type": "bind", "source": source, "target": "/x"}]}))
    }

    const IMAGE_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// `c`'s definitions, with every service's image pulled from a registry.
    fn pins(c: &Value) -> Pins {
        Pins {
            definitions: digests(c),
            images: c["services"]
                .as_object()
                .unwrap()
                .iter()
                .filter_map(|(k, s)| {
                    let image = s["image"].as_str()?;
                    Some((
                        k.clone(),
                        ImagePin {
                            digest: IMAGE_DIGEST.into(),
                            reference: format!("{image}@{IMAGE_DIGEST}"),
                        },
                    ))
                })
                .collect(),
        }
    }

    /// The grant of `allow` to `svc` as it is in `c`.
    fn grant_of(c: &Value, svc: &str, allow: &str) -> String {
        let image = c["services"][svc]["image"].as_str().unwrap_or("none");
        format!("{svc}|{image}|{}|{IMAGE_DIGEST}|{allow}", digests(c)[svc])
    }

    fn grant_for(c: &Value, allow: &str) -> String {
        grant_of(c, "app", allow)
    }

    fn check_with(c: &Value, allow: &[&str], roots: &Roots) -> Result<()> {
        let g: Vec<Grant> = allow
            .iter()
            .map(|a| grant_for(c, a).parse().unwrap())
            .collect();
        check(c, &pins(c), &g, roots, &lexical)
    }

    fn grants(c: &Value, allow: &[&str]) -> Result<()> {
        check_with(c, allow, &roots())
    }

    fn refused(c: &Value) -> String {
        grants(c, &[]).unwrap_err().to_string()
    }

    fn ungrantable(c: &Value) -> String {
        let err = refused(c);
        assert!(err.contains("cannot be granted"), "{err}");
        err
    }

    fn found(c: &Value) -> Vec<Violation> {
        violations(c, &pins(c), &roots(), &lexical)
    }

    #[test]
    fn clean_config_passes() {
        let c = json!({
            "name": "web",
            "services": {"app": {
                "image": "x:1",
                "network_mode": "bridge",
                "cap_add": ["NET_ADMIN", "CAP_CHOWN"],
                "security_opt": ["no-new-privileges:true"],
                "ipc": "private",
                "x-note": 1,
                "environment": {"A": "1"},
                "env_file": [{"path": "/opt/stacks/web/app.env"}],
                "networks": {"default": null},
                "volumes": [
                    {"type": "bind", "source": "/opt/stacks/web/config", "target": "/config"},
                    {"type": "bind", "source": "/opt/stacks/web/config.yml", "target": "/c.yml"},
                    {"type": "volume", "source": "db", "target": "/db"},
                    {"type": "tmpfs", "target": "/tmp"}
                ],
                "secrets": [{"source": "token", "target": "/run/secrets/token"}]
            }},
            "volumes": {"db": {"name": "web_db"}},
            "networks": {"default": {"name": "web_default", "ipam": {}}},
            "secrets": {"token": {"name": "web_token", "file": "/opt/stacks/web/token"}}
        });
        assert!(found(&c).is_empty(), "{:?}", found(&c));
    }

    #[test]
    fn dotdot_sources_are_refused_in_every_form() {
        for src in [
            "/mnt/../",
            "/mnt/data/../../etc",
            "/opt/appdata/..",
            "/opt/stacks/web/../../../",
        ] {
            let err = ungrantable(&bind(src));
            assert!(err.contains("'..'"), "{src}: {err}");
        }
        let vol = cfg_with(json!({
            "services": {"app": {"image": "x:1", "volumes": [{"type": "volume", "source": "v", "target": "/v"}]}},
            "volumes": {"v": {"name": "web_v", "driver_opts": {"type": "none", "o": "bind", "device": "/mnt/data/../../"}}}
        }));
        assert!(ungrantable(&vol).contains("'..'"));
        let secret = cfg_with(json!({
            "services": {"app": {"image": "x:1", "secrets": [{"source": "s"}]}},
            "secrets": {"s": {"file": "/opt/stacks/web/../../../etc/shadow"}}
        }));
        assert!(ungrantable(&secret).contains("'..'"));
    }

    #[test]
    fn an_unresolvable_source_is_refused_not_judged_as_written() {
        let failing = |_: &Path| -> Result<PathBuf> { bail!("permission denied") };
        let c = bind("/mnt/data/x");
        let err = check(&c, &pins(&c), &[], &roots(), &failing)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cannot be resolved") && err.contains("cannot be granted"),
            "{err}"
        );
    }

    #[test]
    fn prefix_checks_compare_components() {
        for src in [
            "/mnt/database",
            "/opt/appdata-other/x",
            "/opt/stacks/webapp/x",
        ] {
            let c = bind(src);
            let err = refused(&c);
            assert!(
                err.contains(&format!(
                    "grant '{}'",
                    grant_for(&c, &format!("bind:{src}"))
                )),
                "{src}: {err}"
            );
        }
    }

    #[test]
    fn binds_containing_the_stack_or_a_root_are_refused_outright() {
        for src in ["/", "/opt", "/opt/stacks", STACK, "/mnt", "/mnt/backups"] {
            let err = ungrantable(&bind(src));
            assert!(err.contains("contains"), "{src}: {err}");
        }
        assert!(grants(&bind("/opt/stacks"), &["bind:/opt/stacks"]).is_err());
    }

    #[test]
    fn every_bind_outside_the_stack_dir_needs_a_grant_data_roots_included() {
        for src in [
            "/etc",
            "/var/run/docker.sock",
            "/root/.ssh",
            "/mnt/data/media",
            "/opt/appdata/web",
            "/opt/stacks/other/data",
            "/mnt/backups/web",
        ] {
            let c = bind(src);
            let err = refused(&c);
            assert!(
                err.contains(&format!(
                    "grant '{}'",
                    grant_for(&c, &format!("bind:{src}"))
                )),
                "{src}: {err}"
            );
            grants(&c, &[&format!("bind:{src}")]).unwrap();
        }
    }

    #[test]
    fn binds_that_nest_within_the_stack_are_refused_even_granted() {
        let two = |a: &str, b: &str| {
            json!({"name": "web", "services": {
                "app": {"image": "x:1", "volumes": [{"type": "bind", "source": a, "target": "/a"}]},
                "db": {"image": "y:1", "volumes": [{"type": "bind", "source": b, "target": "/b"}]}
            }})
        };
        let inside = two("/opt/stacks/web/data", "/opt/stacks/web/data/db");
        let err = ungrantable(&inside);
        assert!(err.contains("another bind of this stack"), "{err}");
        let granted = two("/srv/x", "/srv/x/y");
        let g: Vec<Grant> = [("app", "bind:/srv/x"), ("db", "bind:/srv/x/y")]
            .iter()
            .map(|(svc, a)| grant_of(&granted, svc, a).parse().unwrap())
            .collect();
        let err = check(&granted, &pins(&granted), &g, &roots(), &lexical)
            .unwrap_err()
            .to_string();
        assert!(err.contains("contains /srv/x/y"), "{err}");
        let shared = two("/opt/stacks/web/media", "/opt/stacks/web/media");
        assert!(found(&shared).is_empty(), "equal sources are fine");
    }

    #[test]
    fn binds_into_another_stack_or_nesting_its_grants_are_refused() {
        let others = || {
            roots().with_others(
                &["/opt/stacks/other".to_string()],
                &["/srv/media".to_string()],
                &lexical,
            )
        };
        for src in [
            "/opt/stacks/other/data",
            "/opt/stacks/other",
            "/srv",
            "/srv/media/tv",
        ] {
            let c = bind(src);
            let err = check_with(&c, &[&format!("bind:{src}")], &others())
                .unwrap_err()
                .to_string();
            assert!(err.contains("cannot be granted"), "{src}: {err}");
        }
        check_with(&bind("/srv/media"), &["bind:/srv/media"], &others()).unwrap();
    }

    #[test]
    fn the_stacks_own_compose_and_env_files_cannot_be_bound() {
        for name in [
            "compose.yaml",
            "docker-compose.yml",
            "compose.override.yaml",
            "compose.orca.yaml",
            ".env",
            ".env.bak",
            "compose.yaml.bak",
        ] {
            let err = ungrantable(&bind(&format!("{STACK}/{name}")));
            assert!(err.contains("own compose or .env"), "{name}: {err}");
        }
        let custom = roots().with_compose_file("prod.yml");
        let c = bind(&format!("{STACK}/prod.yml"));
        assert!(check(&c, &pins(&c), &[], &custom, &lexical).is_err());
        assert!(found(&bind(&format!("{STACK}/sub/compose.yaml"))).is_empty());
    }

    #[test]
    fn a_bind_through_a_symlink_out_of_a_root_is_judged_where_it_lands() {
        let dir = tempfile::tempdir().unwrap();
        let stack = dir.path().join("stacks/web");
        std::fs::create_dir_all(&stack).unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), stack.join("escape")).unwrap();
        let resolve = &crate::lifecycle::resolve;
        let roots = Roots::new(&stack, &[], &[], resolve).unwrap();
        let src = stack.join("escape/data").to_string_lossy().into_owned();
        let c = bind(&src);
        let found = violations(&c, &pins(&c), &roots, resolve);
        assert_eq!(found.len(), 1, "{found:?}");
        let inside = bind(&stack.join("data").to_string_lossy());
        assert!(violations(&inside, &pins(&inside), &roots, resolve).is_empty());
    }

    #[test]
    fn unknown_keys_are_refused() {
        for (key, value) in [
            ("uts", json!("host")),
            ("runtime", json!("runc")),
            ("cgroup_parent", json!("/")),
            ("device_cgroup_rules", json!(["a *:* rwm"])),
            ("use_api_socket", json!(true)),
            ("post_start", json!([{"command": "id", "privileged": true}])),
            ("provider", json!({"type": "x"})),
            ("storage_opt", json!({"size": "1G"})),
            ("label_file", json!(["/etc/shadow"])),
        ] {
            let err = ungrantable(&service(json!({key: value})));
            assert!(err.contains(&format!("key '{key}'")), "{key}: {err}");
        }
        let err = ungrantable(&cfg_with(json!({"models": {"m": {}}})));
        assert!(err.contains("top-level key 'models'"), "{err}");
        let err = ungrantable(&service(
            json!({"build": {"context": STACK, "ssh": ["default"]}}),
        ));
        assert!(err.contains("build key 'ssh'"), "{err}");
    }

    #[test]
    fn host_reaching_settings_each_need_their_grant() {
        for (extra, grant) in [
            (json!({"privileged": true}), ALLOW_PRIVILEGED.to_string()),
            (json!({"pid": "host"}), ALLOW_PID_HOST.into()),
            (json!({"pid": "container:db"}), ALLOW_PID_SHARED.into()),
            (json!({"pid": "service:db"}), ALLOW_PID_SHARED.into()),
            (json!({"ipc": "host"}), ALLOW_IPC_HOST.into()),
            (json!({"ipc": "container:db"}), ALLOW_IPC_SHARED.into()),
            (json!({"network_mode": "host"}), ALLOW_NETWORK_HOST.into()),
            (
                json!({"network_mode": "container:vpn"}),
                ALLOW_NETWORK_SHARED.into(),
            ),
            (
                json!({"network_mode": "service:vpn"}),
                ALLOW_NETWORK_SHARED.into(),
            ),
            (json!({"userns_mode": "host"}), ALLOW_USERNS_HOST.into()),
            (json!({"cgroup": "host"}), ALLOW_CGROUP_HOST.into()),
            (
                json!({"security_opt": ["apparmor=unconfined"]}),
                ALLOW_SECURITY_OPT.into(),
            ),
            (
                json!({"security_opt": ["seccomp:unconfined"]}),
                ALLOW_SECURITY_OPT.into(),
            ),
            (
                json!({"devices": [{"source": "/dev/sda", "target": "/dev/sda"}]}),
                ALLOW_DEVICES.into(),
            ),
            (
                json!({"gpus": [{"driver": "nvidia", "count": -1}]}),
                ALLOW_DEVICES.into(),
            ),
            (
                json!({"deploy": {"resources": {"reservations": {"devices": [{"capabilities": ["gpu"]}]}}}}),
                ALLOW_DEVICES.into(),
            ),
            (json!({"volumes_from": ["db"]}), ALLOW_VOLUMES_FROM.into()),
            (
                json!({"cap_add": ["SYS_ADMIN"]}),
                "cap_add:SYS_ADMIN".into(),
            ),
            (
                json!({"cap_add": ["cap_sys_ptrace"]}),
                "cap_add:SYS_PTRACE".into(),
            ),
            (json!({"cap_add": ["ALL"]}), "cap_add:ALL".into()),
            (
                json!({"cap_add": ["SYS_MODULE"]}),
                "cap_add:SYS_MODULE".into(),
            ),
        ] {
            let c = service(extra.clone());
            let err = refused(&c);
            assert!(
                err.contains(&format!("grant '{}'", grant_for(&c, &grant))),
                "{extra}: {err}"
            );
            grants(&c, &[&grant]).unwrap();
        }
    }

    #[test]
    fn unknown_namespace_values_are_refused() {
        for extra in [
            json!({"pid": "private"}),
            json!({"userns_mode": "keep-id"}),
            json!({"cgroup": "other"}),
        ] {
            ungrantable(&service(extra));
        }
    }

    #[test]
    fn an_external_host_network_needs_the_host_network_grant() {
        let c = cfg_with(json!({
            "services": {"app": {"image": "x:1", "networks": {"hn": null}}},
            "networks": {"hn": {"name": "host", "external": true}}
        }));
        let err = refused(&c);
        assert!(err.contains("network hn is the host network"), "{err}");
        assert!(err.contains(&grant_for(&c, "network_mode:host")), "{err}");
        grants(&c, &["network_mode:host"]).unwrap();
    }

    #[test]
    fn networks_and_volumes_the_project_does_not_own_need_a_grant() {
        let net = |net: Value| {
            cfg_with(json!({
                "services": {"app": {"image": "x:1", "networks": {"n": null}}},
                "networks": {"n": net}
            }))
        };
        let vol = |name: &str| {
            cfg_with(json!({
                "services": {"app": {"image": "x:1", "volumes": [{"type": "volume", "source": "v", "target": "/v"}]}},
                "volumes": {"v": {"name": name}}
            }))
        };
        for (c, grant) in [
            (
                service(json!({"network_mode": "proxy_net"})),
                "network:proxy_net",
            ),
            (
                net(json!({"name": "proxy", "external": true})),
                "network:proxy",
            ),
            (
                net(json!({"name": "web_proxy", "external": true})),
                "network:web_proxy",
            ),
            (net(json!({"name": "shared"})), "network:shared"),
            (
                net(json!({"name": "web_lan", "driver": "macvlan"})),
                "network_driver:macvlan",
            ),
            (
                net(json!({"name": "web_lan", "driver": "ipvlan"})),
                "network_driver:ipvlan",
            ),
            (vol("other_data"), "external_volume:other_data"),
        ] {
            let err = refused(&c);
            assert!(err.contains(&grant_for(&c, grant)), "{grant}: {err}");
            grants(&c, &[grant]).unwrap();
        }
        assert!(found(&service(json!({"network_mode": "web_backend"}))).is_empty());
        assert!(found(&net(json!({"name": "web_n", "driver": "bridge"}))).is_empty());
        assert!(found(&vol("web_v")).is_empty());
        ungrantable(&net(json!({"name": "web_n", "driver": "weird"})));
    }

    #[test]
    fn secret_and_config_files_are_judged_as_binds() {
        for kind in ["secrets", "configs"] {
            let c = cfg_with(json!({
                "services": {"app": {"image": "x:1", kind: [{"source": "s"}]}},
                kind: {"s": {"file": "/etc/shadow"}}
            }));
            let err = refused(&c);
            assert!(
                err.contains(&grant_for(&c, "bind:/etc/shadow")),
                "{kind}: {err}"
            );
        }
        let unused = cfg_with(json!({"secrets": {"s": {"file": "/etc/shadow"}}}));
        assert!(ungrantable(&unused).contains("used by no service"));
    }

    #[test]
    fn env_files_build_contexts_and_dockerfiles_stay_in_the_stack_dir() {
        for extra in [
            json!({"env_file": [{"path": "/etc/shadow"}]}),
            json!({"env_file": ["/opt/stacks/other/.env"]}),
            json!({"build": {"context": "/"}}),
            json!({"build": {"context": "/opt/stacks"}}),
            json!({"build": {"context": "https://example.com/repo.git"}}),
            json!({"build": {"context": STACK, "dockerfile": "/etc/Dockerfile"}}),
            json!({"build": {"context": STACK, "dockerfile": "../other/Dockerfile"}}),
            json!({"build": {"context": STACK, "network": "host"}}),
        ] {
            ungrantable(&service(extra));
        }
    }

    #[test]
    fn external_and_device_volumes() {
        let ext = cfg_with(json!({
            "services": {"app": {"image": "x:1", "volumes": [{"type": "volume", "source": "v", "target": "/v"}]}},
            "volumes": {"v": {"name": "other_data", "external": true}}
        }));
        let err = refused(&ext);
        assert!(
            err.contains(&grant_for(&ext, "external_volume:other_data")),
            "{err}"
        );
        grants(&ext, &["external_volume:other_data"]).unwrap();
        for opts in [
            json!({"type": "none", "o": "bind", "device": "/"}),
            json!({"type": "ext4", "device": "/dev/sda1"}),
        ] {
            let c = cfg_with(json!({
                "services": {"app": {"image": "x:1", "volumes": [{"type": "volume", "source": "v", "target": "/v"}]}},
                "volumes": {"v": {"name": "web_v", "driver_opts": opts}}
            }));
            ungrantable(&c);
        }
        let nfs = cfg_with(json!({
            "services": {"app": {"image": "x:1", "volumes": [{"type": "volume", "source": "v", "target": "/v"}]}},
            "volumes": {"v": {"name": "web_v", "driver_opts": {"type": "nfs", "o": "addr=10.0.0.2", "device": ":/export"}}}
        }));
        grants(&nfs, &[]).unwrap();
    }

    #[test]
    fn a_grant_is_void_once_anything_in_its_service_changes() {
        let c = service(json!({"privileged": true, "command": ["sleep", "inf"]}));
        let g: Grant = grant_for(&c, "privileged").parse().unwrap();
        check(&c, &pins(&c), std::slice::from_ref(&g), &roots(), &lexical).unwrap();
        let changed = [
            service(json!({"privileged": true, "command": ["sh", "-c", "evil"]})),
            service(json!({"privileged": true, "command": ["sleep", "inf"], "entrypoint": ["sh"]})),
            service(
                json!({"privileged": true, "command": ["sleep", "inf"], "environment": {"LD_PRELOAD": "/x"}}),
            ),
            service(json!({"privileged": true, "command": ["sleep", "inf"], "user": "0"})),
            service(
                json!({"privileged": true, "command": ["sleep", "inf"], "working_dir": "/tmp"}),
            ),
            service(json!({"privileged": true, "command": ["sleep", "inf"], "image": "evil:1"})),
            json!({"name": "other", "services": {"app": {"image": "x:1", "privileged": true, "command": ["sleep", "inf"]}}}),
        ];
        for c in changed {
            let err = check(&c, &pins(&c), std::slice::from_ref(&g), &roots(), &lexical)
                .unwrap_err()
                .to_string();
            assert!(err.contains("privileged: true"), "{c}: {err}");
        }
        let vol = |opts: Value| {
            cfg_with(json!({
                "services": {"app": {"image": "x:1", "privileged": true, "volumes": [{"type": "volume", "source": "v", "target": "/v"}]}},
                "volumes": {"v": {"name": "web_v", "driver_opts": opts}}
            }))
        };
        let before = vol(json!({"type": "nfs", "device": ":/a"}));
        let after = vol(json!({"type": "nfs", "device": ":/b"}));
        assert_ne!(
            digests(&before)["app"],
            digests(&after)["app"],
            "a referenced top-level entry is part of the definition"
        );
        let moved = json!({"name": "web", "services": {"other": {"image": "x:1", "privileged": true, "command": ["sleep", "inf"]}}});
        assert!(check(&moved, &pins(&moved), &[g], &roots(), &lexical).is_err());
    }

    #[test]
    fn digests_ignore_key_order() {
        let a: Value =
            serde_json::from_str(r#"{"name":"web","services":{"app":{"image":"x:1","user":"1"}}}"#)
                .unwrap();
        let b: Value =
            serde_json::from_str(r#"{"services":{"app":{"user":"1","image":"x:1"}},"name":"web"}"#)
                .unwrap();
        assert_eq!(digests(&a), digests(&b));
    }

    #[test]
    fn a_service_that_builds_cannot_hold_a_grant() {
        for c in [
            service(json!({"privileged": true, "build": {"context": STACK}})),
            json!({"name": "web", "services": {"app": {"privileged": true, "build": {"context": STACK, "dockerfile_inline": "FROM x"}}}}),
        ] {
            let err = grants(&c, &["privileged"]).unwrap_err().to_string();
            assert!(
                err.contains("builds its image") && err.contains("cannot be granted"),
                "{err}"
            );
        }
        assert!(found(&service(json!({"build": {"context": STACK}}))).is_empty());
    }

    #[test]
    fn grant_strings_are_validated() {
        let d = format!("sha256:{}", "a".repeat(64));
        let pre = format!("app|x:1|{d}|{IMAGE_DIGEST}");
        for allow in [
            "privileged",
            "pid:shared",
            "cap_add:SYS_ADMIN",
            "bind:/var/run/docker.sock",
            "external_volume:shared",
            "network:proxy",
            "network_driver:macvlan",
        ] {
            format!("{pre}|{allow}").parse::<Grant>().unwrap();
        }
        format!("app|x:1|{d}|{IMAGE_DIGEST},{d}|privileged")
            .parse::<Grant>()
            .unwrap();
        for bad in [
            "privileged".to_string(),
            "app|x".to_string(),
            format!("|x:1|{d}|{IMAGE_DIGEST}|privileged"),
            format!("app||{d}|{IMAGE_DIGEST}|privileged"),
            format!("app|x:1|{d}|privileged"),
            format!("app|x:1|{d}||privileged"),
            format!("app|x:1|x:1|{IMAGE_DIGEST}|privileged"),
            format!(
                "app|x:1|sha256:{}|{IMAGE_DIGEST}|privileged",
                "a".repeat(63)
            ),
            format!("{pre}|root"),
            format!("{pre}|bind:/"),
            format!("{pre}|bind:relative"),
            format!("{pre}|bind:/mnt/../etc"),
            format!("{pre}|cap_add:"),
            format!("{pre}|cap_add:sys admin"),
            format!("{pre}|pid:container"),
            format!("{pre}|network:"),
            format!("{pre}|network_driver:bridge"),
        ] {
            assert!(bad.parse::<Grant>().is_err(), "{bad}");
        }
    }

    /// A registered runtime whose stacks root is `root`, and the stack `web`
    /// in it with `yaml` on disk.
    fn registered(root: &Path, yaml: &str) -> StackRow {
        let dir = unregistered(root, yaml);
        let row = StackRow {
            name: "web".into(),
            dir: dir.to_string_lossy().into_owned(),
            file: "compose.yaml".into(),
            enabled: true,
            allow: Vec::new(),
        };
        stacks::put(&row).unwrap();
        row
    }

    /// A registered runtime whose stacks root is `root`, and the dir `web`
    /// in it with `yaml` on disk as `compose.yaml`, registered as no stack.
    fn unregistered(root: &Path, yaml: &str) -> PathBuf {
        let args = crate::tools::DockerCreateArgs {
            name: "local".into(),
            socket_path: None,
            host: None,
            url: None,
            stacks_root: Some(root.to_string_lossy().into_owned()),
            routes: Vec::new(),
            execute: true,
        };
        plugin_toolkit::reactor::block_on(crate::tools::docker_create(
            args,
            &crate::test_support::admin(),
        ))
        .unwrap();
        let dir = root.join("web");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("compose.yaml"), yaml).unwrap();
        dir
    }

    fn allow(
        docker: &bollard::Docker,
        approve_current: bool,
        items: Vec<String>,
        execute: bool,
    ) -> Result<DockerStackAllowOutput> {
        let args = DockerStackAllowArgs {
            name: "web".into(),
            dir: None,
            file: None,
            allow: Vec::new(),
            approve_current,
            items,
            execute,
        };
        plugin_toolkit::reactor::block_on(stack_allow(args, docker))
    }

    /// An engine that knows `x:1` with `repo_digests`.
    fn engine(repo_digests: &[&str]) -> crate::test_engine::FakeEngine {
        let body = json!({"Id": "sha256:1", "RepoDigests": repo_digests}).to_string();
        crate::test_engine::FakeEngine::routed(vec![
            crate::test_engine::Route::new("GET", "/images/x:1/json", 200, body.clone()),
            crate::test_engine::Route::new("GET", "/images/x%3A1/json", 200, body),
        ])
    }

    const PULLED: &str = "registry.example/x@sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const REPUSHED: &str = "registry.example/x@sha256:2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn real_compose_config_feeds_profiles_env_files_and_dotdot_binds_to_the_policy() {
        if !crate::test_support::have_compose() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let fake = engine(&[]);
        let docker = fake.client();
        crate::test_support::with_db(|| {
            let row = registered(&root, "services:\n  app:\n    image: x:1\n");
            let roots = crate::tools::stacks_roots().unwrap();
            for (yaml, want) in [
                (
                    "services:\n  app:\n    image: x:1\n  debug:\n    image: y:1\n    profiles: [debug]\n    privileged: true\n",
                    "debug (y:1): privileged: true",
                ),
                (
                    "services:\n  app:\n    image: x:1\n    volumes: [\"/mnt/../:/host\"]\n",
                    "'..'",
                ),
                (
                    "services:\n  app:\n    image: x:1\n    env_file: [/etc/hosts]\n",
                    "env_file /etc/hosts",
                ),
                (
                    "services:\n  app:\n    image: x:1\n    volumes: [\"./compose.yaml:/c.yaml\"]\n",
                    "own compose or .env",
                ),
            ] {
                let err = plugin_toolkit::reactor::block_on(row.write_checked(
                    Some(yaml),
                    None,
                    &roots,
                    Some(&docker),
                ))
                .unwrap_err();
                assert!(format!("{err:#}").contains(want), "{yaml}: {err:#}");
            }
            assert_eq!(
                std::fs::read_to_string(root.join("web/compose.yaml")).unwrap(),
                "services:\n  app:\n    image: x:1\n",
                "nothing refused was written"
            );
        });
    }

    #[test]
    fn on_disk_settings_run_only_once_approved_and_only_while_unchanged() {
        if !crate::test_support::have_compose() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let pulled = engine(&[PULLED]);
        let docker = pulled.client();
        crate::test_support::with_db(|| {
            let host = "services:\n  app:\n    image: x:1\n    network_mode: host\n";
            let row = registered(&root, host);
            let compose = row.compose().unwrap();
            let err =
                plugin_toolkit::reactor::block_on(gate(Some(&docker), &row, &compose)).unwrap_err();
            assert!(err.to_string().contains("|network_mode:host'"), "{err}");

            let plan = allow(&docker, true, Vec::new(), false).unwrap();
            assert_eq!(plan.after.len(), 1);
            assert!(
                plan.after[0].starts_with("app|x:1|sha256:")
                    && plan.after[0].ends_with("|sha256:1111111111111111111111111111111111111111111111111111111111111111|network_mode:host"),
                "{:?}",
                plan.after
            );
            let err = allow(&docker, true, Vec::new(), true)
                .unwrap_err()
                .to_string();
            assert!(err.contains("needs the items from the dry run"), "{err}");
            let wrong = vec![plan.after[0].replace("network_mode:host", "privileged")];
            let err = allow(&docker, true, wrong, true).unwrap_err().to_string();
            assert!(err.contains("differ from the confirmed items"), "{err}");
            assert!(stacks::require("web").unwrap().allow.is_empty());
            allow(&docker, true, plan.after.clone(), true).unwrap();
            let row = stacks::require("web").unwrap();
            let checked =
                plugin_toolkit::reactor::block_on(gate(Some(&docker), &row, &compose)).unwrap();
            assert!(
                checked.config.contains(PULLED),
                "a granted service runs its image by digest: {}",
                checked.config
            );

            let roots = crate::tools::stacks_roots().unwrap();
            for changed in [
                host.replace("x:1", "evil:1"),
                format!("{host}    command: [sh, -c, evil]\n"),
            ] {
                let err = plugin_toolkit::reactor::block_on(row.write_checked(
                    Some(&changed),
                    None,
                    &roots,
                    Some(&docker),
                ))
                .unwrap_err();
                assert!(err.to_string().contains("network_mode: host"), "{err}");
            }

            let repushed = engine(&[REPUSHED]);
            let err =
                plugin_toolkit::reactor::block_on(gate(Some(&repushed.client()), &row, &compose))
                    .unwrap_err();
            assert!(
                err.to_string().contains("image changed upstream")
                    && err.to_string().contains("approveCurrent"),
                "{err}"
            );
            let built = engine(&[]);
            let built = built.client();
            let err =
                plugin_toolkit::reactor::block_on(gate(Some(&built), &row, &compose)).unwrap_err();
            assert!(err.to_string().contains("no registry digest"), "{err}");
            let err = allow(&built, true, Vec::new(), false)
                .unwrap_err()
                .to_string();
            assert!(err.contains("no registry digest"), "{err}");
        });
    }

    /// Adopting `web` at `dir` by approving what it runs now.
    fn adopt(
        docker: &bollard::Docker,
        dir: Option<&Path>,
        items: Vec<String>,
        execute: bool,
    ) -> Result<DockerStackAllowOutput> {
        let args = DockerStackAllowArgs {
            name: "web".into(),
            dir: dir.map(|d| d.to_string_lossy().into_owned()),
            file: Some("compose.yaml".into()),
            allow: Vec::new(),
            approve_current: true,
            items,
            execute,
        };
        plugin_toolkit::reactor::block_on(stack_allow(args, docker))
    }

    #[test]
    fn approving_an_unregistered_stack_registers_it_with_its_grants_on_execute() {
        if !crate::test_support::have_compose() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let pulled = engine(&[PULLED]);
        let docker = pulled.client();
        crate::test_support::with_db(|| {
            let dir = unregistered(
                &root,
                "services:\n  app:\n    image: x:1\n    network_mode: host\n    volumes: [\"/srv/media:/media\"]\n",
            );
            let plan = adopt(&docker, Some(&dir), Vec::new(), false).unwrap();
            assert!(plan.dry_run && plan.adopted && plan.before.is_empty());
            let adopt_item = format!("adopt:{}", dir.join("compose.yaml").display());
            assert_eq!(plan.after.len(), 3, "{:?}", plan.after);
            assert!(
                plan.after.iter().any(|g| g.ends_with("|bind:/srv/media"))
                    && plan.after.iter().any(|g| g.ends_with("|network_mode:host"))
                    && plan.after.contains(&adopt_item),
                "{:?}",
                plan.after
            );
            assert!(
                stacks::get("web").unwrap().is_none(),
                "a dry run writes nothing"
            );

            let err = adopt(&docker, Some(&dir), Vec::new(), true)
                .unwrap_err()
                .to_string();
            assert!(err.contains("needs the items from the dry run"), "{err}");
            assert!(stacks::get("web").unwrap().is_none());

            let done = adopt(&docker, Some(&dir), plan.after.clone(), true).unwrap();
            assert!(!done.dry_run && done.adopted);
            let row = stacks::require("web").unwrap();
            assert_eq!(row.dir, dir.to_string_lossy());
            assert_eq!(row.file, "compose.yaml");
            assert!(row.enabled);
            let grants: Vec<String> = plan
                .after
                .iter()
                .filter(|i| **i != adopt_item)
                .cloned()
                .collect();
            assert_eq!(
                row.allow.iter().map(Grant::to_string).collect::<Vec<_>>(),
                grants
            );
            let compose = row.compose().unwrap();
            plugin_toolkit::reactor::block_on(gate(Some(&docker), &row, &compose)).unwrap();

            let again = adopt(&docker, Some(&dir), Vec::new(), false).unwrap();
            assert!(!again.adopted, "a registered stack is not adopted again");
        });
    }

    #[test]
    fn adopting_confirms_the_dir_and_file_even_with_no_grants() {
        if !crate::test_support::have_compose() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let fake = engine(&[PULLED]);
        let docker = fake.client();
        crate::test_support::with_db(|| {
            let dir = unregistered(&root, "services:\n  app:\n    image: x:1\n");
            let other = root.join("other");
            std::fs::create_dir(&other).unwrap();
            std::fs::write(
                other.join("compose.yaml"),
                "services:\n  app:\n    image: x:1\n",
            )
            .unwrap();
            let plan = adopt(&docker, Some(&dir), Vec::new(), false).unwrap();
            assert_eq!(
                plan.after,
                [format!("adopt:{}", dir.join("compose.yaml").display())]
            );
            let err = adopt(&docker, Some(&dir), Vec::new(), true)
                .unwrap_err()
                .to_string();
            assert!(err.contains("needs the items from the dry run"), "{err}");
            let err = adopt(&docker, Some(&other), plan.after.clone(), true)
                .unwrap_err()
                .to_string();
            assert!(err.contains("differ from the confirmed items"), "{err}");
            assert!(stacks::get("web").unwrap().is_none());
            adopt(&docker, Some(&dir), plan.after, true).unwrap();
            assert_eq!(stacks::require("web").unwrap().dir, dir.to_string_lossy());
        });
    }

    #[test]
    fn adopting_refuses_a_dir_overlapping_another_stack_or_its_bind_grants() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let fake = engine(&[]);
        let docker = fake.client();
        crate::test_support::with_db(|| {
            unregistered(&root, "services: {}\n");
            for dir in crate::test_support::overlapping_dirs(&root) {
                let args = DockerStackAllowArgs {
                    name: "other".into(),
                    dir: Some(dir.to_string_lossy().into_owned()),
                    file: Some("compose.yaml".into()),
                    allow: Vec::new(),
                    approve_current: true,
                    items: Vec::new(),
                    execute: false,
                };
                let err = plugin_toolkit::reactor::block_on(stack_allow(args, &docker))
                    .unwrap_err()
                    .to_string();
                assert!(err.contains("overlaps"), "{}: {err}", dir.display());
            }
            assert!(stacks::get("other").unwrap().is_none());
        });
    }

    #[test]
    fn adopting_refuses_a_symlinked_override_or_orca_file() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("evil.yaml");
        std::fs::write(&target, "services: {}\n").unwrap();
        let fake = engine(&[]);
        let docker = fake.client();
        crate::test_support::with_db(|| {
            let dir = unregistered(&root, "services: {}\n");
            for name in ["compose.override.yaml", compose::ORCA_FILE] {
                let link = dir.join(name);
                std::os::unix::fs::symlink(&target, &link).unwrap();
                let err = adopt(&docker, Some(&dir), Vec::new(), false)
                    .unwrap_err()
                    .to_string();
                assert!(
                    err.contains(&format!("{} is not a regular file", link.display())),
                    "{err}"
                );
                std::fs::remove_file(&link).unwrap();
            }
            assert!(stacks::get("web").unwrap().is_none());
        });
    }

    #[test]
    fn an_unregistered_stack_no_grant_can_admit_is_not_adopted() {
        if !crate::test_support::have_compose() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let fake = engine(&[PULLED]);
        let docker = fake.client();
        crate::test_support::with_db(|| {
            let dir = unregistered(
                &root,
                "services:\n  app:\n    image: x:1\n    volumes: [\"./compose.yaml:/c.yaml\"]\n",
            );
            for execute in [false, true] {
                let err = adopt(&docker, Some(&dir), Vec::new(), execute)
                    .unwrap_err()
                    .to_string();
                assert!(err.contains("no grant can admit"), "{err}");
            }
            assert!(stacks::get("web").unwrap().is_none());
        });
    }

    #[test]
    fn adopting_needs_approve_current_a_dir_in_a_stacks_root_and_its_compose_file() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside = outside.path().canonicalize().unwrap();
        std::fs::write(outside.join("compose.yaml"), "services: {}\n").unwrap();
        let fake = engine(&[]);
        let docker = fake.client();
        crate::test_support::with_db(|| {
            let dir = unregistered(&root, "services:\n  app:\n    image: x:1\n");
            let err = adopt(&docker, None, Vec::new(), false)
                .unwrap_err()
                .to_string();
            assert!(err.contains("needs `dir`"), "{err}");
            let err = adopt(&docker, Some(&outside), Vec::new(), false)
                .unwrap_err()
                .to_string();
            assert!(err.contains("outside the stacks roots"), "{err}");
            let empty = root.join("empty");
            std::fs::create_dir(&empty).unwrap();
            let err = adopt(&docker, Some(&empty), Vec::new(), false)
                .unwrap_err()
                .to_string();
            assert!(err.contains("is not a regular file"), "{err}");
            let args = DockerStackAllowArgs {
                name: "web".into(),
                dir: Some(dir.to_string_lossy().into_owned()),
                file: Some("compose.yaml".into()),
                allow: Vec::new(),
                approve_current: false,
                items: Vec::new(),
                execute: true,
            };
            let err = plugin_toolkit::reactor::block_on(stack_allow(args, &docker))
                .unwrap_err()
                .to_string();
            assert!(err.contains("needs `approve_current`"), "{err}");
            assert!(stacks::list().unwrap().is_empty());
        });
    }

    #[test]
    fn stack_allow_cannot_move_a_registered_stack() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let fake = engine(&[]);
        let docker = fake.client();
        crate::test_support::with_db(|| {
            let row = registered(&root, "services:\n  app:\n    image: x:1\n");
            let other = root.join("other");
            std::fs::create_dir(&other).unwrap();
            std::fs::write(other.join("compose.yaml"), "services: {}\n").unwrap();
            let call = |dir: &str, file: &str| {
                let args = DockerStackAllowArgs {
                    name: "web".into(),
                    dir: Some(dir.into()),
                    file: Some(file.into()),
                    allow: Vec::new(),
                    approve_current: false,
                    items: Vec::new(),
                    execute: true,
                };
                plugin_toolkit::reactor::block_on(stack_allow(args, &docker))
            };
            let err = call(&other.to_string_lossy(), "compose.yaml")
                .unwrap_err()
                .to_string();
            assert!(err.contains("cannot be moved here"), "{err}");
            let err = call(&row.dir, "docker-compose.yml")
                .unwrap_err()
                .to_string();
            assert!(err.contains("registered with compose file"), "{err}");
            let row_now = stacks::require("web").unwrap();
            assert_eq!(row_now.dir, row.dir);
            assert_eq!(row_now.file, row.file);
            let same = call(&format!("{}/", row.dir), "compose.yaml").unwrap();
            assert!(!same.adopted);
        });
    }

    #[test]
    fn compose_runs_the_config_that_was_checked_not_the_file_on_disk_now() {
        if !crate::test_support::have_compose() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let fake = engine(&[]);
        let docker = fake.client();
        crate::test_support::with_db(|| {
            let row = registered(&root, "services:\n  app:\n    image: x:1\n");
            std::fs::write(root.join("web/.env"), "IMG=y:2\n").unwrap();
            let compose = row.compose().unwrap();
            let checked =
                plugin_toolkit::reactor::block_on(gate(Some(&docker), &row, &compose)).unwrap();
            std::fs::write(
                root.join("web/compose.yaml"),
                "services:\n  app:\n    image: ${IMG}\n    privileged: true\n",
            )
            .unwrap();
            let ran =
                plugin_toolkit::reactor::block_on(checked.run(&["config", "--format", "json"]))
                    .unwrap();
            let cfg: Value = serde_json::from_str(&ran).unwrap();
            assert_eq!(cfg["services"]["app"]["image"], "x:1", "{ran}");
            assert!(cfg["services"]["app"].get("privileged").is_none(), "{ran}");
            assert_eq!(cfg["name"], "web");
        });
    }

    #[test]
    fn literal_dollars_stay_literal_through_the_checked_run() {
        if !crate::test_support::have_compose() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let fake = engine(&[]);
        let docker = fake.client();
        crate::test_support::with_db(|| {
            let row = registered(
                &root,
                "services:\n  app:\n    image: x:1\n    command: [echo, \"a$$b\"]\n    labels:\n      l: \"c$$d\"\n    environment:\n      E: \"e$$f\"\n    volumes: [\"./d$$x:/x\"]\n",
            );
            let compose = row.compose().unwrap();
            let (_, _, cfg, _) =
                plugin_toolkit::reactor::block_on(resolved(&row, &compose)).unwrap();
            let checked =
                plugin_toolkit::reactor::block_on(gate(Some(&docker), &row, &compose)).unwrap();
            let ran =
                plugin_toolkit::reactor::block_on(checked.run(&["config", "--format", "json"]))
                    .unwrap();
            let ran: Value = serde_json::from_str(&ran).unwrap();
            for (path, want) in [
                ("/services/app/command/1", "a$$b"),
                ("/services/app/labels/l", "c$$d"),
                ("/services/app/environment/E", "e$$f"),
            ] {
                assert_eq!(ran.pointer(path), cfg.pointer(path), "{path}");
                assert_eq!(
                    ran.pointer(path).and_then(Value::as_str),
                    Some(want),
                    "{path}"
                );
            }
            let source = |c: &Value| c.pointer("/services/app/volumes/0/source").cloned();
            assert_eq!(source(&ran), source(&cfg));
            assert!(source(&ran).unwrap().as_str().unwrap().ends_with("/d$$x"));
        });
    }

    #[test]
    fn a_build_cannot_read_through_a_bind_or_a_grant() {
        let stack = |svcs: Value| json!({"name": "web", "services": svcs});
        let binder = |src: &str| json!({"image": "x:1", "volumes": [{"type": "bind", "source": src, "target": "/d"}]});
        for (cfg, want) in [
            (
                stack(json!({
                    "a": binder("/opt/stacks/web/data"),
                    "b": {"image": "y:1", "build": {"context": "/opt/stacks/web/data/src"}}
                })),
                "build context /opt/stacks/web/data/src",
            ),
            (
                stack(json!({
                    "a": binder("/opt/stacks/web/config"),
                    "b": {"image": "y:1", "build": {"context": STACK}}
                })),
                "build context /opt/stacks/web",
            ),
            (
                stack(json!({
                    "a": binder("/opt/stacks/web/df"),
                    "b": {"image": "y:1", "build": {"context": "/opt/stacks/web/src", "dockerfile": "/opt/stacks/web/df/Dockerfile"}}
                })),
                "build dockerfile /opt/stacks/web/df/Dockerfile",
            ),
            (
                stack(json!({
                    "a": binder("/opt/stacks/web/a$b"),
                    "b": {"image": "y:1", "build": {"context": "/opt/stacks/web/a$$b"}}
                })),
                "build context /opt/stacks/web/a$b",
            ),
        ] {
            let err = ungrantable(&cfg);
            assert!(
                err.contains(want) && err.contains("a bind of this stack"),
                "{err}"
            );
        }
        let granted = roots().with_others(&[], &["/opt/stacks/web/shared".to_string()], &lexical);
        let c = stack(
            json!({"b": {"image": "y:1", "build": {"context": "/opt/stacks/web/shared/src"}}}),
        );
        let err = check(&c, &pins(&c), &[], &granted, &lexical)
            .unwrap_err()
            .to_string();
        assert!(err.contains("another stack holds a grant for"), "{err}");
        let apart = stack(json!({
            "a": binder("/opt/stacks/web/data"),
            "b": {"image": "y:1", "build": {"context": "/opt/stacks/web/src"}}
        }));
        assert!(found(&apart).is_empty(), "{:?}", found(&apart));
    }

    #[test]
    fn build_paths_unescape_dollars() {
        let roots = Roots::new(Path::new("/opt/stacks/w$b"), &[], &[], &lexical).unwrap();
        let c = json!({"name": "web", "services": {"b": {"image": "y:1", "build": {
            "context": "/opt/stacks/w$$b", "dockerfile": "Dockerfile"
        }}}});
        assert!(violations(&c, &pins(&c), &roots, &lexical).is_empty());
    }

    #[test]
    fn prepare_opens_build_paths_without_following_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let web = root.join("web");
        std::fs::create_dir_all(web.join("src")).unwrap();
        std::fs::write(web.join("src/Dockerfile"), "FROM x\n").unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("Dockerfile"), "FROM x\n").unwrap();
        std::os::unix::fs::symlink(outside.path(), web.join("ctx")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("Dockerfile"), web.join("src/Linked"))
            .unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        let dir = StackDir::open(&web.to_string_lossy(), &roots, false)
            .unwrap()
            .unwrap();
        let raw = |context: &str, dockerfile: &str| {
            json!({"name": "web", "services": {"b": {"image": "y:1", "build": {
                "context": format!("{}/{context}", web.display()), "dockerfile": dockerfile
            }}}})
            .to_string()
        };
        prepare(&raw("src", "Dockerfile"), &web, &dir).unwrap();
        assert!(prepare(&raw("ctx", "Dockerfile"), &web, &dir).is_err());
        assert!(prepare(&raw("src", "Linked"), &web, &dir).is_err());
        std::fs::create_dir(web.join("a$b")).unwrap();
        std::fs::write(web.join("a$b/Dockerfile"), "FROM x\n").unwrap();
        prepare(&raw("a$$b", "Dockerfile"), &web, &dir).unwrap();
    }

    #[test]
    fn prepare_refuses_build_paths_reached_through_an_alias_of_the_stack_dir() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let web = root.join("web");
        std::fs::create_dir_all(web.join("src")).unwrap();
        std::fs::write(web.join("src/Dockerfile"), "FROM x\n").unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let alias = elsewhere.path().join("alias");
        std::os::unix::fs::symlink(&web, &alias).unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        let dir = StackDir::open(&web.to_string_lossy(), &roots, false)
            .unwrap()
            .unwrap();
        let raw = |context: &Path, dockerfile: &Path| {
            json!({"name": "web", "services": {"b": {"image": "y:1", "build": {
                "context": context, "dockerfile": dockerfile
            }}}})
            .to_string()
        };
        prepare(
            &raw(&web.join("src"), &web.join("src/Dockerfile")),
            &web,
            &dir,
        )
        .unwrap();
        let err = prepare(
            &raw(&alias.join("src"), Path::new("Dockerfile")),
            &web,
            &dir,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not inside the stack dir"), "{err}");
        let err = prepare(
            &raw(&web.join("src"), &alias.join("src/Dockerfile")),
            &web,
            &dir,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not inside the stack dir"), "{err}");
    }

    #[test]
    fn prepare_unescapes_dollars_in_dockerfiles_and_refuses_a_missing_one() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let web = root.join("web");
        std::fs::create_dir_all(web.join("src")).unwrap();
        std::fs::write(web.join("src/ok$x"), "FROM x\n").unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("Dockerfile"), "FROM x\n").unwrap();
        std::os::unix::fs::symlink(outside.path().join("Dockerfile"), web.join("src/a$b")).unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        let dir = StackDir::open(&web.to_string_lossy(), &roots, false)
            .unwrap()
            .unwrap();
        let raw = |dockerfile: &str| {
            json!({"name": "web", "services": {"b": {"image": "y:1", "build": {
                "context": web.join("src"), "dockerfile": dockerfile
            }}}})
            .to_string()
        };
        prepare(&raw("ok$$x"), &web, &dir).unwrap();
        assert!(prepare(&raw("a$$b"), &web, &dir).is_err());
        let err = prepare(&raw("Missing"), &web, &dir)
            .unwrap_err()
            .to_string();
        let want = format!(
            "needs a Dockerfile at {}",
            web.join("src/Missing").display()
        );
        assert!(err.contains(&want), "{err}");
    }

    #[test]
    fn prepare_unescapes_dollars_in_env_file_paths() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let web = root.join("web");
        std::fs::create_dir_all(&web).unwrap();
        std::fs::write(web.join("e$v.env"), "A=1\n").unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        let dir = StackDir::open(&web.to_string_lossy(), &roots, false)
            .unwrap()
            .unwrap();
        let raw = json!({"name": "web", "services": {"app": {
            "image": "x:1", "env_file": [format!("{}/e$$v.env", web.display())]
        }}})
        .to_string();
        let cfg = prepare(&raw, &web, &dir).unwrap();
        assert_eq!(cfg["services"]["app"]["environment"]["A"], "1");
    }

    /// Gate a stack whose `b` builds from `web/proj/src` against an engine
    /// answering `routes`; `routes` gets the path of `web/proj`.
    fn gate_build_over_proj(
        routes: impl FnOnce(&str) -> Vec<crate::test_engine::Route>,
    ) -> Option<Result<Checked>> {
        if !crate::test_support::have_compose() {
            return None;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let (gated, _) = crate::test_support::with_db(|| {
            let row = registered(
                &root,
                "services:\n  b:\n    image: y:1\n    build: ./proj/src\n",
            );
            std::fs::create_dir_all(root.join("web/proj/src")).unwrap();
            std::fs::write(root.join("web/proj/src/Dockerfile"), "FROM x\n").unwrap();
            let compose = row.compose().unwrap();
            let fake = crate::test_engine::FakeEngine::routed(routes(
                &root.join("web/proj").to_string_lossy(),
            ));
            let docker = fake.client();
            plugin_toolkit::reactor::block_on(gate(Some(&docker), &row, &compose))
        });
        Some(gated)
    }

    fn containers_route(mounts: Value) -> crate::test_engine::Route {
        let body = json!([{"Id": "abc", "Names": ["/web-a-1"], "Mounts": mounts}]);
        crate::test_engine::Route::new("GET", "/containers/json", 200, body.to_string())
    }

    #[test]
    fn a_build_cannot_read_through_a_writable_bind_an_existing_container_holds() {
        let Some(gated) = gate_build_over_proj(|proj| {
            vec![containers_route(
                json!([{"Type": "bind", "Source": proj, "Destination": "/p", "RW": true}]),
            )]
        }) else {
            return;
        };
        let err = gated.unwrap_err().to_string();
        assert!(
            err.contains("a writable bind of container web-a-1"),
            "{err}"
        );
        gate_build_over_proj(|proj| {
            vec![containers_route(
                json!([{"Type": "bind", "Source": proj, "Destination": "/p", "RW": false}]),
            )]
        })
        .unwrap()
        .unwrap();
    }

    #[test]
    fn a_build_cannot_read_through_a_volume_an_existing_container_holds_that_binds() {
        let volume = |name: &str, options: Value| {
            crate::test_engine::Route::new(
                "GET",
                format!("/volumes/{name}"),
                200,
                json!({"Name": name, "Driver": "local", "Mountpoint": "/var/lib/docker/volumes/x/_data",
                    "Labels": {}, "Scope": "local", "Options": options})
                .to_string(),
            )
        };
        let mount = |name: &str| {
            json!([{"Type": "volume", "Name": name, "Source": "/var/lib/docker/volumes/x/_data",
                "Destination": "/v", "Driver": "local", "RW": true}])
        };
        let Some(gated) = gate_build_over_proj(|proj| {
            vec![
                containers_route(mount("bound")),
                volume(
                    "bound",
                    json!({"type": "none", "o": "rw,rbind", "device": proj}),
                ),
            ]
        }) else {
            return;
        };
        let err = gated.unwrap_err().to_string();
        assert!(
            err.contains("a writable bind of container web-a-1"),
            "{err}"
        );
        gate_build_over_proj(|_| {
            vec![containers_route(mount("plain")), volume("plain", json!({}))]
        })
        .unwrap()
        .unwrap();
        let err = gate_build_over_proj(|_| vec![containers_route(mount("gone"))])
            .unwrap()
            .unwrap_err()
            .to_string();
        assert!(err.contains("inspecting volume gone"), "{err}");
    }

    #[test]
    fn a_build_cannot_read_through_a_volume_a_driver_plugin_mounts_from_a_host_path() {
        let held = |driver: &'static str, source: String| {
            let mount = json!([{"Type": "volume", "Name": "v", "Source": source,
                "Destination": "/v", "Driver": driver, "RW": true}]);
            let volume = json!({"Name": "v", "Driver": driver, "Mountpoint": source,
                "Labels": {}, "Scope": "local", "Options": {}});
            vec![
                containers_route(mount),
                crate::test_engine::Route::new("GET", "/volumes/v", 200, volume.to_string()),
            ]
        };
        let Some(gated) = gate_build_over_proj(|proj| held("local-persist", proj.to_string()))
        else {
            return;
        };
        let err = gated.unwrap_err().to_string();
        assert!(
            err.contains("a writable bind of container web-a-1"),
            "{err}"
        );
        gate_build_over_proj(|_| held("local", "/var/lib/docker/volumes/v/_data".into()))
            .unwrap()
            .unwrap();
    }

    #[test]
    fn a_build_is_refused_when_the_containers_cannot_be_listed() {
        let Some(gated) = gate_build_over_proj(|_| {
            vec![crate::test_engine::Route::new(
                "GET",
                "/containers/json",
                500,
                r#"{"message":"boom"}"#,
            )]
        }) else {
            return;
        };
        let err = gated.unwrap_err().to_string();
        assert!(err.contains("listing containers"), "{err}");
    }

    #[test]
    fn a_build_without_a_dockerfile_key_uses_and_checks_the_default() {
        let outside = |p: &Path| -> Result<PathBuf> {
            if p == Path::new("/opt/stacks/web/src/Dockerfile") {
                return Ok(PathBuf::from("/etc/Dockerfile"));
            }
            lexical(p)
        };
        for build in [
            json!({"context": "/opt/stacks/web/src"}),
            json!({"context": "/opt/stacks/web/src", "dockerfile": ""}),
        ] {
            let c = json!({"name": "web", "services": {"b": {"image": "y:1", "build": build}}});
            let found = violations(&c, &pins(&c), &roots(), &outside);
            assert!(
                found
                    .iter()
                    .any(|v| v.detail.starts_with("build dockerfile Dockerfile")),
                "{found:?}"
            );
        }
        let c = json!({"name": "web", "services": {"b": {"image": "y:1", "build": {
            "context": "/opt/stacks/web/src", "dockerfile_inline": "FROM x"
        }}}});
        assert!(violations(&c, &pins(&c), &roots(), &outside).is_empty());

        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let web = root.join("web");
        std::fs::create_dir_all(web.join("src")).unwrap();
        std::fs::create_dir_all(web.join("bare")).unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(elsewhere.path().join("Dockerfile"), "FROM x\n").unwrap();
        std::os::unix::fs::symlink(
            elsewhere.path().join("Dockerfile"),
            web.join("src/Dockerfile"),
        )
        .unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        let dir = StackDir::open(&web.to_string_lossy(), &roots, false)
            .unwrap()
            .unwrap();
        let raw = |build: Value| {
            json!({"name": "web", "services": {"b": {"image": "y:1", "build": build}}}).to_string()
        };
        let src = web.join("src");
        assert!(prepare(&raw(json!({"context": src})), &web, &dir).is_err());
        assert!(prepare(&raw(json!({"context": src, "dockerfile": ""})), &web, &dir).is_err());
        prepare(
            &raw(json!({"context": src, "dockerfile_inline": "FROM x"})),
            &web,
            &dir,
        )
        .unwrap();
        let err = prepare(&raw(json!({"context": web.join("bare")})), &web, &dir)
            .unwrap_err()
            .to_string();
        let want = format!(
            "service b: the build needs a Dockerfile at {}",
            web.join("bare/Dockerfile").display()
        );
        assert!(err.contains(&want), "{err}");
    }

    #[test]
    fn prepare_reads_a_restores_dockerfile_from_the_staging_dir() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let live = root.join("web");
        let staged = root.join(".web.staged");
        std::fs::create_dir_all(live.join("src")).unwrap();
        std::fs::create_dir_all(staged.join("src")).unwrap();
        std::fs::write(staged.join("src/Dockerfile"), "FROM x\n").unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        let dir = StackDir::open(&staged.to_string_lossy(), &roots, false)
            .unwrap()
            .unwrap();
        let raw = json!({"name": "web", "services": {"b": {"image": "y:1", "build": {
            "context": live.join("src"), "dockerfile": "Dockerfile"
        }}}})
        .to_string();
        prepare(&raw, &live, &dir).unwrap();
    }

    #[test]
    fn a_bind_source_is_judged_as_the_literal_path_compose_mounts() {
        let c = bind("/srv/a$$b");
        let err = refused(&c);
        assert!(err.contains("|bind:/srv/a$b'"), "{err}");
        grants(&c, &["bind:/srv/a$b"]).unwrap();
    }

    #[test]
    fn env_files_are_read_into_the_checked_config_and_its_digest() {
        if !crate::test_support::have_compose() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let fake = engine(&[]);
        let docker = fake.client();
        crate::test_support::with_db(|| {
            let row = registered(
                &root,
                "services:\n  app:\n    image: x:1\n    env_file: [app.env]\n    environment:\n      B: own\n",
            );
            std::fs::write(root.join("web/app.env"), "A='pa$s'\nB=file\n").unwrap();
            let compose = row.compose().unwrap();
            let (dir, _, cfg, _) =
                plugin_toolkit::reactor::block_on(resolved(&row, &compose)).unwrap();
            let app = &cfg["services"]["app"];
            assert!(app.get("env_file").is_none(), "{app}");
            assert_eq!(app["environment"]["A"], "pa$$s");
            assert_eq!(app["environment"]["B"], "own", "environment wins");
            let before = digests(&cfg)["app"].clone();

            let checked =
                plugin_toolkit::reactor::block_on(gate(Some(&docker), &row, &compose)).unwrap();
            std::fs::write(root.join("web/app.env"), "A=changed\nB=file\n").unwrap();
            let ran =
                plugin_toolkit::reactor::block_on(checked.run(&["config", "--format", "json"]))
                    .unwrap();
            assert!(ran.contains("pa$$s") && !ran.contains("changed"), "{ran}");
            let (_, _, cfg, _) =
                plugin_toolkit::reactor::block_on(resolved(&row, &compose)).unwrap();
            assert_ne!(
                digests(&cfg)["app"],
                before,
                "the digest covers env file contents"
            );

            let outside = tempfile::tempdir().unwrap();
            std::fs::write(outside.path().join("secrets"), "S=x\n").unwrap();
            std::fs::remove_file(root.join("web/app.env")).unwrap();
            std::os::unix::fs::symlink(outside.path().join("secrets"), root.join("web/app.env"))
                .unwrap();
            let raw = format!(
                r#"{{"name":"web","services":{{"app":{{"image":"x:1","env_file":[{{"path":"{}/app.env"}}]}}}}}}"#,
                dir.path().display()
            );
            assert!(
                prepare(&raw, dir.path(), &dir).is_err(),
                "a symlink is not followed"
            );
            std::fs::remove_file(root.join("web/app.env")).unwrap();
            std::fs::write(root.join("web/app.env"), "OK='${HOME}'\nBAD=${HOME}/x\n").unwrap();
            let raw = format!(
                r#"{{"name":"web","services":{{"app":{{"image":"x:1","env_file":[{{"path":"{}/app.env"}}]}}}}}}"#,
                dir.path().display()
            );
            let err = prepare(&raw, dir.path(), &dir).unwrap_err().to_string();
            assert!(err.contains("sets BAD from a variable"), "{err}");
            let raw =
                r#"{"name":"web","services":{"app":{"image":"x:1","env_file":["/etc/hosts"]}}}"#;
            let err = prepare(raw, dir.path(), &dir).unwrap_err().to_string();
            assert!(err.contains("not inside the stack dir"), "{err}");
        });
    }

    #[test]
    fn images_granted_services_run_cannot_be_named_elsewhere_or_built() {
        let held = || {
            roots().with_granted_images(
                "web",
                vec![
                    GrantedImage {
                        image: norm_image("x:1"),
                        stack: "web".into(),
                        service: "app".into(),
                    },
                    GrantedImage {
                        image: norm_image("docker.io/library/ha"),
                        stack: "home".into(),
                        service: "ha".into(),
                    },
                ],
            )
        };
        let refused_in = |c: Value| {
            check(&c, &pins(&c), &[], &held(), &lexical)
                .unwrap_err()
                .to_string()
        };
        let ok = |c: Value| {
            assert!(
                violations(&c, &pins(&c), &held(), &lexical).is_empty(),
                "{c}"
            )
        };
        let err = refused_in(json!({"name": "web", "services": {"app": {"image": "ha"}}}));
        assert!(err.contains("granted service home/ha"), "{err}");
        let err = refused_in(json!({"name": "web", "services": {"b": {
            "image": "y:1", "build": {"context": STACK, "tags": ["x:1"]}
        }}}));
        assert!(err.contains("a build would tag x:1"), "{err}");
        let err = refused_in(json!({"name": "web", "services": {"b": {
            "image": "x:1", "build": {"context": STACK}
        }}}));
        assert!(err.contains("a build would tag x:1"), "{err}");
        ok(
            json!({"name": "web", "services": {"app": {"image": "x:1"}, "worker": {"image": "x:1"}}}),
        );
        ok(
            json!({"name": "web", "services": {"b": {"image": "y:1", "build": {"context": STACK}}}}),
        );
        assert_eq!(norm_image("docker.io/library/ha"), "ha:latest");
        assert_eq!(norm_image("ghcr.io/a/b:2"), "ghcr.io/a/b:2");
        assert_eq!(norm_image("localhost:5000/b"), "localhost:5000/b:latest");
    }

    #[test]
    fn the_daemons_home_and_docker_config_cannot_be_bound_even_granted() {
        let daemon = || {
            roots().with_daemon_dirs(
                &[
                    "/root".to_string(),
                    "/root/.docker".to_string(),
                    "/etc/docker-cli".to_string(),
                ],
                &lexical,
            )
        };
        for src in [
            "/root",
            "/root/.docker/config.json",
            "/root/.ssh",
            "/etc/docker-cli",
            "/etc",
        ] {
            let c = bind(src);
            let err = check_with(&c, &[&format!("bind:{src}")], &daemon())
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("daemon's home or docker config"),
                "{src}: {err}"
            );
        }
        check_with(&bind("/srv/data"), &["bind:/srv/data"], &daemon()).unwrap();
    }

    #[test]
    fn checked_runs_name_no_user_file_and_read_no_env_file() {
        let a = checked_args(
            "web",
            Path::new("/s/web"),
            Path::new("/tmp/orca-compose-x/config.json"),
            &["up", "-d"],
        );
        assert_eq!(
            a,
            [
                "compose",
                "-p",
                "web",
                "--project-directory",
                "/s/web",
                "--env-file",
                "/dev/null",
                "-f",
                "/tmp/orca-compose-x/config.json",
                "up",
                "-d"
            ]
        );
    }

    #[test]
    fn stack_allow_is_admin_only_on_the_dry_run_and_execute() {
        fn admin_self_gated<T: OrcaToolDef>() {
            assert_eq!(T::REQUIRED_ROLE, "admin");
            assert!(!T::EXECUTE_GATED);
        }
        admin_self_gated::<DockerStackAllow>();
        for ctx in crate::test_support::non_admins() {
            for (execute, dir) in [false, true].into_iter().flat_map(|e| {
                [None, Some("/opt/stacks/web".to_string())]
                    .into_iter()
                    .map(move |d| (e, d))
            }) {
                let args = DockerStackAllowArgs {
                    name: "web".into(),
                    approve_current: dir.is_some(),
                    dir,
                    file: None,
                    allow: vec![format!(
                        "app|x:1|sha256:{}|{IMAGE_DIGEST}|privileged",
                        "a".repeat(64)
                    )],
                    items: Vec::new(),
                    execute,
                };
                let err = plugin_toolkit::reactor::block_on(docker_stack_allow(args, &ctx))
                    .unwrap_err()
                    .to_string();
                crate::test_support::assert_admin_refusal(&err);
            }
        }
    }
}
