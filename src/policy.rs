//! Compose content policy for managed stacks, checked before a compose file
//! is written (`deploy`, `set`, `edit`, `fix`, `restore`) and before compose
//! runs it (`up`, the lifecycle actions, `host_update`).
//!
//! `deploy` is a unit create, which reaches the plugin without a caller
//! identity (orca#788), so the plugin cannot require admin on every stack
//! verb. The policy is an allowlist over the resolved config (`compose
//! config`, every profile enabled): a key it does not know is refused, and
//! every setting that reaches the host (privileged, host or shared
//! namespaces, extra capabilities, devices, binds outside the data roots,
//! external volumes, the host network) needs a grant. Grants are
//! recorded per `(service, image)` by an admin through `docker.stack_allow`,
//! either one by one or by approving what the stack runs now; swapping a
//! service's image drops its grants.
//!
//! A few things are refused outright, with no grant: a path with a `..`
//! component or that cannot be resolved, a bind that contains the stack dir,
//! its parent, a stacks root or a backup root, an env file, build context or
//! Dockerfile outside the stack dir, and keys the policy does not know.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{self, Value};

use crate::compose::Compose;
use crate::stacks::{self, StackDir, StackRow};
use crate::{engine_state, execute, lint};

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
/// Prefix of an external volume grant: `external_volume:<engine name>`.
pub const ALLOW_EXTERNAL_VOLUME: &str = "external_volume:";

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

/// One exception an admin recorded: `allow` for `service` while it runs
/// `image`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct Grant {
    pub service: String,
    /// The service's `image` as compose resolves it; empty for a service
    /// that only builds.
    pub image: String,
    pub allow: String,
}

impl std::fmt::Display for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}|{}|{}", self.service, self.image, self.allow)
    }
}

impl std::str::FromStr for Grant {
    type Err = plugin_toolkit::anyhow::Error;

    /// `<service>|<image>|<grant>`. Neither service names nor image
    /// references can hold a `|`; the grant may.
    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.splitn(3, '|');
        let (Some(service), Some(image), Some(allow)) = (parts.next(), parts.next(), parts.next())
        else {
            bail!("grant '{s}' must be '<service>|<image>|<grant>'");
        };
        if service.is_empty() {
            bail!("grant '{s}' names no service");
        }
        validate_grant(allow)?;
        Ok(Grant {
            service: service.to_string(),
            image: image.to_string(),
            allow: allow.to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    /// Empty for a project-level setting no service uses.
    pub service: String,
    pub image: String,
    /// The grant that admits it; `None` when nothing can.
    pub allow: Option<String>,
    pub detail: String,
}

impl Violation {
    fn grant(&self) -> Option<Grant> {
        self.allow.as_ref().map(|allow| Grant {
            service: self.service.clone(),
            image: self.image.clone(),
            allow: allow.clone(),
        })
    }
}

pub type Resolver<'a> = &'a dyn Fn(&Path) -> Result<PathBuf>;

/// The host paths the policy judges sources against, all resolved.
pub struct Roots {
    stack_dir: PathBuf,
    /// Configured data roots: binds inside them need no grant.
    data: Vec<PathBuf>,
    /// A source that is or contains one of these is refused outright.
    protected: Vec<PathBuf>,
    /// A source inside one of these needs a grant, data root or not.
    backups: Vec<PathBuf>,
}

impl Roots {
    pub fn new(
        stack_dir: &Path,
        stacks_roots: &[String],
        backup_roots: &[String],
        data_roots: &[String],
        resolve: Resolver<'_>,
    ) -> Result<Roots> {
        let stack_dir = resolve(stack_dir)?;
        // Admin-configured, absolute without `..`: an unresolvable one is
        // still judged as written.
        let configured = |r: &String| resolve(Path::new(r)).unwrap_or_else(|_| PathBuf::from(r));
        let backups: Vec<PathBuf> = backup_roots.iter().map(configured).collect();
        let mut protected = vec![stack_dir.clone()];
        protected.extend(stack_dir.parent().map(Path::to_path_buf));
        protected.extend(stacks_roots.iter().map(configured));
        protected.extend(backups.iter().cloned());
        Ok(Roots {
            data: data_roots.iter().map(configured).collect(),
            stack_dir,
            protected,
            backups,
        })
    }
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
    host_path(raw, resolve)
        .is_ok_and(|p| p.starts_with(&roots.stack_dir) && (or_equal || p != roots.stack_dir))
}

fn judge_source(raw: &str, roots: &Roots, resolve: Resolver<'_>) -> Judgment {
    let p = match host_path(raw, resolve) {
        Ok(p) => p,
        Err(why) => return Judgment::Refuse(why),
    };
    if let Some(r) = roots.protected.iter().find(|r| r.starts_with(&p)) {
        return Judgment::Refuse(format!(
            "'{raw}' contains {}, the stack dir, its parent, a stacks root or a backup root",
            r.display()
        ));
    }
    let grant = Judgment::Grant(format!("{ALLOW_BIND}{}", p.display()));
    if roots.backups.iter().any(|b| p.starts_with(b)) {
        return grant;
    }
    if p.starts_with(&roots.stack_dir) || roots.data.iter().any(|d| p.starts_with(d)) {
        return Judgment::Ok;
    }
    grant
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
        ok: &[],
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

struct Collector<'a> {
    out: BTreeSet<Violation>,
    services: &'a BTreeMap<String, String>,
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
                allow: None,
                detail,
            });
            return;
        }
        for svc in users {
            self.out.insert(Violation {
                service: svc.to_string(),
                image: self.services.get(*svc).cloned().unwrap_or_default(),
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

/// Every setting in the resolved config `cfg` that needs a grant or is
/// refused outright.
pub fn violations(cfg: &Value, roots: &Roots, resolve: Resolver<'_>) -> Vec<Violation> {
    let services: BTreeMap<String, String> = cfg
        .get("services")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, s)| (k.clone(), str_of(s.get("image")).to_string()))
                .collect()
        })
        .unwrap_or_default();
    let mut c = Collector {
        out: BTreeSet::new(),
        services: &services,
    };
    for key in keys_outside(cfg, &[TOP_KEYS]) {
        c.push(
            &[],
            Judgment::Refuse("not supported".into()),
            &format!("top-level key '{key}'"),
        );
    }
    project_entries(cfg, &mut c, roots, resolve);
    if let Some(all) = cfg.get("services").and_then(Value::as_object) {
        for (name, svc) in all {
            service(name, svc, &mut c, roots, resolve);
        }
    }
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
        for k in keys_outside(net, &[NETWORK_KEYS]) {
            c.push(
                &users,
                Judgment::Refuse("not supported".into()),
                &format!("network {key}: key '{k}'"),
            );
        }
        if str_of(net.get("name")) == "host" || str_of(net.get("driver")) == "host" {
            c.push(
                &users,
                Judgment::Grant(ALLOW_NETWORK_HOST.into()),
                &format!("network {key} is the host network"),
            );
        }
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
                c.push(
                    &users,
                    judge_source(file, roots, resolve),
                    &format!("{kind} {key} mounts host file {file}"),
                );
            }
        }
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
    if vol.get("external").and_then(Value::as_bool) == Some(true) {
        let name = vol.get("name").and_then(Value::as_str).unwrap_or(key);
        c.push(
            users,
            Judgment::Grant(format!("{ALLOW_EXTERNAL_VOLUME}{name}")),
            &format!("volume {key} is the external volume {name}"),
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
    let binds = str_of(opts.and_then(|o| o.get("o")))
        .split(',')
        .any(|o| matches!(o.trim(), "bind" | "rbind"));
    if binds {
        c.push(
            users,
            judge_source(device, roots, resolve),
            &format!("volume {key} binds host path {device}"),
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
        // Any other network_mode names a network, which `networks` judges.
        if mode.key == "network_mode"
            && !value.is_empty()
            && value != "host"
            && !value.starts_with("container:")
            && !value.starts_with("service:")
        {
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
            "bind" => c.push(
                &me,
                judge_source(source, roots, resolve),
                &format!("binds host path {source} into {target}"),
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
    if let Some(build) = svc.get("build") {
        build_section(build, &me, c, roots, resolve);
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
    if !in_stack_dir(context, roots, true, resolve) {
        c.push(
            me,
            Judgment::Refuse("only the stack dir or a path inside it is allowed".into()),
            &format!("build context {context}"),
        );
        return;
    }
    let dockerfile = str_of(build.get("dockerfile"));
    if !dockerfile.is_empty() {
        let full = if Path::new(dockerfile).is_absolute() {
            dockerfile.to_string()
        } else {
            format!("{}/{dockerfile}", context.trim_end_matches('/'))
        };
        if !in_stack_dir(&full, roots, false, resolve) {
            c.push(
                me,
                Judgment::Refuse("only a file inside the stack dir is allowed".into()),
                &format!("build dockerfile {dockerfile}"),
            );
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

/// Whether `grant` admits `allow` for `v`'s service and image. Bind grants
/// match by resolved path, so a grant written through a symlink still
/// matches.
fn admits(g: &Grant, v: &Violation, allow: &str, resolve: Resolver<'_>) -> bool {
    if g.service != v.service || g.image != v.image {
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

/// Refuse `cfg` unless every violation is granted to its service and image.
pub fn check(cfg: &Value, grants: &[Grant], roots: &Roots, resolve: Resolver<'_>) -> Result<()> {
    let refused: Vec<Violation> = violations(cfg, roots, resolve)
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
            match v.grant() {
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

fn live_roots(stack_dir: &Path, stacks_roots: &[String]) -> Result<Roots> {
    Roots::new(
        stack_dir,
        stacks_roots,
        &engine_state::backup_roots(),
        &lint::managed_roots(None),
        &crate::lifecycle::resolve,
    )
}

/// Check the resolved config `raw` of `row`, whose dir is `stack_dir`,
/// against the row's grants, the configured data roots and the backup roots.
pub fn check_stack(
    raw: &str,
    row: &StackRow,
    stack_dir: &Path,
    stacks_roots: &[String],
) -> Result<()> {
    let roots = live_roots(stack_dir, stacks_roots)?;
    check(&parse(raw)?, &row.allow, &roots, &crate::lifecycle::resolve)
}

/// The stack dir, opened under a stacks root, and the resolved config of
/// exactly `compose`'s files.
async fn resolved(row: &StackRow, compose: &Compose) -> Result<(StackDir, Vec<String>, String)> {
    let roots = crate::tools::stacks_roots()?;
    let dir = StackDir::open(&row.dir, &roots, false)?
        .ok_or_else(|| anyhow!("stack dir {} does not exist", row.dir))?;
    let files: Vec<PathBuf> = compose.files().into_iter().map(Path::to_path_buf).collect();
    let raw = stacks::resolved_config(dir.path(), &files, None).await?;
    Ok((dir, roots, raw))
}

/// Refuse to run `compose` for `row` unless its stack dir is inside a stacks
/// root and the config of exactly `compose`'s files passes [`check_stack`].
pub async fn gate(row: &StackRow, compose: &Compose) -> Result<()> {
    let (dir, roots, raw) = resolved(row, compose).await?;
    check_stack(&raw, row, dir.path(), &roots)
}

/// What `row` runs now that needs a grant, for an admin to approve. Fails on
/// anything no grant can admit.
async fn current_grants(row: &StackRow) -> Result<Vec<Grant>> {
    let compose = row.compose()?;
    let compose = if Path::new(&row.dir)
        .join(crate::compose::ORCA_FILE)
        .is_file()
    {
        compose.with_orca()
    } else {
        compose
    };
    let (dir, roots, raw) = resolved(row, &compose).await?;
    let found = violations(
        &parse(&raw)?,
        &live_roots(dir.path(), &roots)?,
        &crate::lifecycle::resolve,
    );
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
    if let Some(name) = grant.strip_prefix(ALLOW_EXTERNAL_VOLUME) {
        if name.is_empty() || name.contains('/') {
            bail!("grant '{grant}' needs a volume name");
        }
        return Ok(());
    }
    let Some(path) = grant.strip_prefix(ALLOW_BIND) else {
        bail!(
            "unknown grant '{grant}'; expected one of {}, {ALLOW_CAP}<CAP>, {ALLOW_EXTERNAL_VOLUME}<name> or {ALLOW_BIND}<absolute path>",
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
    /// Registered stack name.
    #[arg(long)]
    pub name: String,
    /// The full grant set, replacing the current one, each
    /// `<service>|<image>|<grant>`. A grant is `privileged`, `pid:host`,
    /// `pid:shared`, `ipc:host`, `ipc:shared`, `network_mode:host`,
    /// `network_mode:shared`, `userns_mode:host`, `cgroup:host`,
    /// `security_opt`, `devices`, `volumes_from`, `cap_add:<CAP>`,
    /// `external_volume:<name>` or `bind:<absolute host path>`. Repeatable;
    /// empty clears every grant.
    #[arg(long = "allow")]
    #[serde(default)]
    pub allow: Vec<String>,
    /// Add a grant for everything the stack's compose files on disk use now
    /// that needs one, each bound to its service's current image.
    #[arg(long)]
    #[serde(default)]
    pub approve_current: bool,
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
    pub before: Vec<String>,
    pub after: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// [MUTATES STATE] Set the compose policy grants of a managed stack, each
/// bound to a service and the image it runs. Without `execute`, returns the
/// grants and changes nothing.
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
    let mut after = args
        .allow
        .iter()
        .map(|g| g.parse::<Grant>())
        .collect::<Result<Vec<_>>>()?;
    let mut row = stacks::require(&args.name)?;
    if args.approve_current {
        after.extend(current_grants(&row).await?);
    }
    after.sort();
    after.dedup();
    let show = |g: &[Grant]| g.iter().map(Grant::to_string).collect::<Vec<_>>();
    let before = show(&row.allow);
    if !args.execute {
        return Ok(DockerStackAllowOutput {
            dry_run: true,
            name: args.name,
            before,
            after: show(&after),
            how_to_execute: Some(format!("re-invoke {ALLOW_TOOL} with `execute: true`")),
        });
    }
    row.allow = after;
    stacks::put(&row)?;
    Ok(DockerStackAllowOutput {
        dry_run: false,
        name: args.name,
        before,
        after: show(&row.allow),
        how_to_execute: None,
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
            &["/opt/appdata".to_string(), "/mnt/data".to_string()],
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

    fn grants(c: &Value, allow: &[&str]) -> Result<()> {
        let g: Vec<Grant> = allow.iter().map(|a| a.parse().unwrap()).collect();
        check(c, &g, &roots(), &lexical)
    }

    fn refused(c: &Value) -> String {
        grants(c, &[]).unwrap_err().to_string()
    }

    fn ungrantable(c: &Value) -> String {
        let err = refused(c);
        assert!(err.contains("cannot be granted"), "{err}");
        err
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
                "build": {"context": "/opt/stacks/web", "dockerfile": "Dockerfile"},
                "networks": {"default": null},
                "volumes": [
                    {"type": "bind", "source": "/opt/stacks/web/config", "target": "/config"},
                    {"type": "bind", "source": "/mnt/data/media", "target": "/media"},
                    {"type": "bind", "source": "/opt/appdata/web", "target": "/data"},
                    {"type": "volume", "source": "db", "target": "/db"},
                    {"type": "tmpfs", "target": "/tmp"}
                ],
                "secrets": [{"source": "token", "target": "/run/secrets/token"}]
            }},
            "volumes": {"db": {"name": "web_db"}},
            "networks": {"default": {"name": "web_default", "ipam": {}}},
            "secrets": {"token": {"name": "web_token", "file": "/opt/stacks/web/token"}}
        });
        assert!(
            violations(&c, &roots(), &lexical).is_empty(),
            "{:?}",
            violations(&c, &roots(), &lexical)
        );
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
            "volumes": {"v": {"driver_opts": {"type": "none", "o": "bind", "device": "/mnt/data/../../"}}}
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
        let err = check(&bind("/mnt/data/x"), &[], &roots(), &failing)
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
            let err = refused(&bind(src));
            assert!(
                err.contains(&format!("grant 'app|x:1|bind:{src}'")),
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
        assert!(grants(&bind("/opt/stacks"), &["app|x:1|bind:/opt/stacks"]).is_err());
    }

    #[test]
    fn binds_outside_the_data_roots_need_a_grant() {
        for src in [
            "/etc",
            "/var/run/docker.sock",
            "/root/.ssh",
            "/mnt/willow/media",
            "/opt/stacks/other/data",
            "/mnt/backups/web",
        ] {
            let err = refused(&bind(src));
            assert!(
                err.contains(&format!("grant 'app|x:1|bind:{src}'")),
                "{src}: {err}"
            );
        }
        grants(
            &bind("/mnt/backups/web"),
            &["app|x:1|bind:/mnt/backups/web"],
        )
        .unwrap();
    }

    #[test]
    fn a_bind_through_a_symlink_out_of_a_root_is_judged_where_it_lands() {
        let dir = tempfile::tempdir().unwrap();
        let stack = dir.path().join("stacks/web");
        std::fs::create_dir_all(&stack).unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), stack.join("escape")).unwrap();
        let resolve = &crate::lifecycle::resolve;
        let roots = Roots::new(&stack, &[], &[], &[], resolve).unwrap();
        let src = stack.join("escape/data").to_string_lossy().into_owned();
        let found = violations(&bind(&src), &roots, resolve);
        assert_eq!(found.len(), 1, "{found:?}");
        let inside = stack.join("data").to_string_lossy().into_owned();
        assert!(violations(&bind(&inside), &roots, resolve).is_empty());
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
                err.contains(&format!("grant 'app|x:1|{grant}'")),
                "{extra}: {err}"
            );
            grants(&c, &[&format!("app|x:1|{grant}")]).unwrap();
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
        assert!(err.contains("grant 'app|x:1|network_mode:host'"), "{err}");
        grants(&c, &["app|x:1|network_mode:host"]).unwrap();
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
                err.contains("grant 'app|x:1|bind:/etc/shadow'"),
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
            err.contains("grant 'app|x:1|external_volume:other_data'"),
            "{err}"
        );
        grants(&ext, &["app|x:1|external_volume:other_data"]).unwrap();
        for opts in [
            json!({"type": "none", "o": "bind", "device": "/"}),
            json!({"type": "ext4", "device": "/dev/sda1"}),
        ] {
            let c = cfg_with(json!({
                "services": {"app": {"image": "x:1", "volumes": [{"type": "volume", "source": "v", "target": "/v"}]}},
                "volumes": {"v": {"driver_opts": opts}}
            }));
            ungrantable(&c);
        }
        let nfs = cfg_with(json!({
            "services": {"app": {"image": "x:1", "volumes": [{"type": "volume", "source": "v", "target": "/v"}]}},
            "volumes": {"v": {"driver_opts": {"type": "nfs", "o": "addr=10.0.0.2", "device": ":/export"}}}
        }));
        grants(&nfs, &[]).unwrap();
    }

    #[test]
    fn grants_bind_to_service_and_image() {
        let c = service(json!({"privileged": true}));
        grants(&c, &["app|x:1|privileged"]).unwrap();
        let swapped =
            json!({"name": "web", "services": {"app": {"image": "evil:1", "privileged": true}}});
        let err = grants(&swapped, &["app|x:1|privileged"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("grant 'app|evil:1|privileged'"), "{err}");
        let moved =
            json!({"name": "web", "services": {"other": {"image": "x:1", "privileged": true}}});
        assert!(grants(&moved, &["app|x:1|privileged"]).is_err());
    }

    #[test]
    fn grant_strings_are_validated() {
        for ok in [
            "app|x:1|privileged",
            "app|ghcr.io/a/b:2|pid:shared",
            "app||cap_add:SYS_ADMIN",
            "app|x|bind:/var/run/docker.sock",
            "app|x|external_volume:shared",
        ] {
            ok.parse::<Grant>().unwrap();
        }
        for bad in [
            "privileged",
            "app|x",
            "|x|privileged",
            "app|x|root",
            "app|x|bind:/",
            "app|x|bind:relative",
            "app|x|bind:/mnt/../etc",
            "app|x|cap_add:",
            "app|x|cap_add:sys admin",
            "app|x|pid:container",
        ] {
            assert!(bad.parse::<Grant>().is_err(), "{bad}");
        }
    }

    /// A registered runtime whose stacks root is `root`, and the stack `web`
    /// in it with `yaml` on disk.
    fn registered(root: &Path, yaml: &str) -> StackRow {
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

    #[test]
    fn real_compose_config_feeds_profiles_env_files_and_dotdot_binds_to_the_policy() {
        if !crate::test_support::have_compose() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
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
            ] {
                let err =
                    plugin_toolkit::reactor::block_on(row.write_checked(Some(yaml), None, &roots))
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
    fn on_disk_settings_run_only_once_approved_and_only_for_their_image() {
        if !crate::test_support::have_compose() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        crate::test_support::with_db(|| {
            let host = "services:\n  app:\n    image: x:1\n    network_mode: host\n";
            let row = registered(&root, host);
            let compose = row.compose().unwrap();
            let err = plugin_toolkit::reactor::block_on(gate(&row, &compose)).unwrap_err();
            assert!(
                err.to_string()
                    .contains("grant 'app|x:1|network_mode:host'"),
                "{err}"
            );

            let args = DockerStackAllowArgs {
                name: "web".into(),
                allow: Vec::new(),
                approve_current: true,
                execute: true,
            };
            let out = plugin_toolkit::reactor::block_on(docker_stack_allow(
                args,
                &crate::test_support::admin(),
            ))
            .unwrap();
            assert_eq!(out.after, ["app|x:1|network_mode:host"]);
            let row = stacks::require("web").unwrap();
            plugin_toolkit::reactor::block_on(gate(&row, &compose)).unwrap();

            let roots = crate::tools::stacks_roots().unwrap();
            let swapped = host.replace("x:1", "evil:1");
            let err =
                plugin_toolkit::reactor::block_on(row.write_checked(Some(&swapped), None, &roots))
                    .unwrap_err();
            assert!(
                err.to_string().contains("app (evil:1): network_mode: host"),
                "{err}"
            );
            std::fs::write(root.join("web/compose.yaml"), &swapped).unwrap();
            assert!(plugin_toolkit::reactor::block_on(gate(&row, &compose)).is_err());
        });
    }

    #[test]
    fn stack_allow_is_admin_only_on_the_dry_run_and_execute() {
        fn admin_self_gated<T: OrcaToolDef>() {
            assert_eq!(T::REQUIRED_ROLE, "admin");
            assert!(!T::EXECUTE_GATED);
        }
        admin_self_gated::<DockerStackAllow>();
        for ctx in crate::test_support::non_admins() {
            for execute in [false, true] {
                let args = DockerStackAllowArgs {
                    name: "web".into(),
                    allow: vec!["app|x|privileged".into()],
                    approve_current: false,
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
