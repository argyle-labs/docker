//! Compose content policy for managed stacks, checked before `deploy`, `set`
//! and `edit` write a compose file.
//!
//! The stack unit verbs reach the plugin without a caller identity, so the
//! plugin cannot require admin on them. This refuses the settings that turn a
//! compose file into host root (privileged, host pid/network, `SYS_ADMIN`,
//! binds outside the data roots) unless the stack already ran with them or an
//! admin granted them through `docker.stack_allow`.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use plugin_toolkit::prelude::*;

use crate::compose_config::ComposeConfig;
use crate::lint::{self, under};
use crate::{execute, stacks};

pub const ALLOW_PRIVILEGED: &str = "privileged";
pub const ALLOW_PID_HOST: &str = "pid:host";
pub const ALLOW_NETWORK_HOST: &str = "network_mode:host";
pub const ALLOW_SYS_ADMIN: &str = "cap_add:SYS_ADMIN";
/// Prefix of a per-path bind grant: `bind:/var/run/docker.sock`.
pub const ALLOW_BIND: &str = "bind:";

const ALLOW_TOOL: &str = "docker.stack_allow";

/// Host paths a bind may come from without a grant, besides the stack's own
/// dir and the stacks roots.
const DATA_ROOT: &str = "/opt/appdata";
const MNT: &str = "/mnt/";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    pub service: String,
    /// The grant that admits it.
    pub allow: String,
    pub detail: String,
}

/// Roots binds may come from: the stack dir, the stacks roots and the lint's
/// managed roots.
pub fn bind_roots(stack_dir: &str, stacks_roots: &[String]) -> Vec<String> {
    let mut roots = vec![stack_dir.to_string(), DATA_ROOT.to_string()];
    roots.extend(stacks_roots.iter().cloned());
    roots.extend(lint::managed_roots(None));
    roots
}

/// `path` with symlinks resolved, so a bind through a link is judged where it
/// lands. Unresolvable paths are judged as written.
pub fn resolve_host_path(path: &str) -> String {
    crate::lifecycle::resolve(Path::new(path))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

fn bind_allowed(source: &str, roots: &[String], resolve: &dyn Fn(&str) -> String) -> bool {
    let source = resolve(source);
    if source.starts_with(MNT) && source.len() > MNT.len() {
        return true;
    }
    roots.iter().any(|r| under(&source, &resolve(r)))
}

fn cap_is_admin(cap: &str) -> bool {
    let cap = cap.trim().to_ascii_uppercase();
    let cap = cap.strip_prefix("CAP_").unwrap_or(&cap);
    cap == "SYS_ADMIN" || cap == "ALL"
}

/// Every setting in `cfg` that needs a grant.
pub fn violations(
    cfg: &ComposeConfig,
    roots: &[String],
    resolve: &dyn Fn(&str) -> String,
) -> Vec<Violation> {
    let mut out = BTreeSet::new();
    let mut push = |service: &str, allow: String, detail: String| {
        out.insert(Violation {
            service: service.to_string(),
            allow,
            detail,
        });
    };
    for (svc, s) in &cfg.services {
        if s.privileged {
            push(svc, ALLOW_PRIVILEGED.into(), "privileged: true".into());
        }
        if s.pid.as_deref() == Some("host") {
            push(svc, ALLOW_PID_HOST.into(), "pid: host".into());
        }
        if s.network_mode.as_deref() == Some("host") {
            push(svc, ALLOW_NETWORK_HOST.into(), "network_mode: host".into());
        }
        if let Some(cap) = s.cap_add.iter().find(|c| cap_is_admin(c)) {
            push(svc, ALLOW_SYS_ADMIN.into(), format!("cap_add: {cap}"));
        }
        for m in &s.volumes {
            if let Some(src) = m.bind_source()
                && !bind_allowed(src, roots, resolve)
            {
                push(
                    svc,
                    format!("{ALLOW_BIND}{src}"),
                    format!("binds host path {src} into {}", m.target),
                );
            }
        }
    }
    for (key, v) in &cfg.volumes {
        let binds = v.driver_opts.get("o").is_some_and(|o| {
            o.split(',')
                .any(|opt| opt.trim() == "bind" || opt.trim() == "rbind")
        });
        if let Some(device) = v.driver_opts.get("device")
            && binds
            && !bind_allowed(device, roots, resolve)
        {
            push(
                &format!("volume {key}"),
                format!("{ALLOW_BIND}{device}"),
                format!("volume {key} binds host path {device}"),
            );
        }
    }
    out.into_iter().collect()
}

/// Refuse `new` unless every violation is granted in `allow` or was already
/// in `current`, the stack's config before this write, for the same service.
pub fn check(
    new: &ComposeConfig,
    current: Option<&ComposeConfig>,
    allow: &[String],
    roots: &[String],
    resolve: &dyn Fn(&str) -> String,
) -> Result<()> {
    let existing: BTreeSet<(String, String)> = current
        .map(|c| violations(c, roots, resolve))
        .unwrap_or_default()
        .into_iter()
        .map(|v| (v.service, v.allow))
        .collect();
    let refused: Vec<Violation> = violations(new, roots, resolve)
        .into_iter()
        .filter(|v| !allow.contains(&v.allow))
        .filter(|v| !existing.contains(&(v.service.clone(), v.allow.clone())))
        .collect();
    if refused.is_empty() {
        return Ok(());
    }
    let lines: Vec<String> = refused
        .iter()
        .map(|v| format!("{}: {} (grant '{}')", v.service, v.detail, v.allow))
        .collect();
    bail!(
        "compose policy refuses this stack: {}; an admin can grant these with {ALLOW_TOOL}",
        lines.join("; ")
    )
}

/// A grant `docker.stack_allow` accepts.
fn validate_grant(grant: &str) -> Result<()> {
    if [
        ALLOW_PRIVILEGED,
        ALLOW_PID_HOST,
        ALLOW_NETWORK_HOST,
        ALLOW_SYS_ADMIN,
    ]
    .contains(&grant)
    {
        return Ok(());
    }
    let Some(path) = grant.strip_prefix(ALLOW_BIND) else {
        bail!(
            "unknown grant '{grant}'; expected {ALLOW_PRIVILEGED}, {ALLOW_PID_HOST}, {ALLOW_NETWORK_HOST}, {ALLOW_SYS_ADMIN} or {ALLOW_BIND}<absolute path>"
        );
    };
    let p = Path::new(path);
    if !p.is_absolute() || p.components().any(|c| c == Component::ParentDir) {
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
    /// The full grant set, replacing the current one: `privileged`,
    /// `pid:host`, `network_mode:host`, `cap_add:SYS_ADMIN` or
    /// `bind:<absolute host path>`. Repeatable; empty clears every grant.
    #[arg(long = "allow")]
    #[serde(default)]
    pub allow: Vec<String>,
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

/// [MUTATES STATE] Set the compose policy grants of a managed stack: the
/// privileged, host-namespace, `SYS_ADMIN` and bind-path settings its compose
/// file may use. Without `execute`, returns the grants and changes nothing.
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
    for grant in &args.allow {
        validate_grant(grant)?;
    }
    let mut after = args.allow.clone();
    after.sort();
    after.dedup();
    let mut row = stacks::require(&args.name)?;
    let before = row.allow.clone();
    if !args.execute {
        return Ok(DockerStackAllowOutput {
            dry_run: true,
            name: args.name,
            before,
            after,
            how_to_execute: Some(format!("re-invoke {ALLOW_TOOL} with `execute: true`")),
        });
    }
    row.allow = after.clone();
    stacks::put(&row)?;
    Ok(DockerStackAllowOutput {
        dry_run: false,
        name: args.name,
        before,
        after,
        how_to_execute: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::contract::OrcaToolDef;
    use plugin_toolkit::serde_json::json;

    fn cfg(v: plugin_toolkit::serde_json::Value) -> ComposeConfig {
        ComposeConfig::parse(&v.to_string()).unwrap()
    }

    fn id(p: &str) -> String {
        p.to_string()
    }

    fn roots() -> Vec<String> {
        bind_roots("/opt/stacks/web", &["/opt/stacks".to_string()])
    }

    fn service(extra: plugin_toolkit::serde_json::Value) -> ComposeConfig {
        let mut svc = json!({"image": "x"});
        for (k, v) in extra.as_object().unwrap() {
            svc[k] = v.clone();
        }
        cfg(json!({"name": "web", "services": {"app": svc}}))
    }

    fn bind(source: &str) -> ComposeConfig {
        service(json!({"volumes": [{"type": "bind", "source": source, "target": "/x"}]}))
    }

    fn refused(c: &ComposeConfig) -> String {
        check(c, None, &[], &roots(), &id).unwrap_err().to_string()
    }

    #[test]
    fn clean_config_passes() {
        let c = cfg(json!({
            "name": "web",
            "services": {"app": {
                "image": "x",
                "network_mode": "bridge",
                "cap_add": ["NET_ADMIN"],
                "volumes": [
                    {"type": "bind", "source": "/opt/stacks/web/config", "target": "/config"},
                    {"type": "bind", "source": "/opt/stacks/other/shared", "target": "/shared"},
                    {"type": "bind", "source": "/mnt/willow/media", "target": "/media"},
                    {"type": "bind", "source": "/opt/appdata/web", "target": "/data"},
                    {"type": "volume", "source": "db", "target": "/db"}
                ]
            }},
            "volumes": {"db": {"name": "web_db"}}
        }));
        assert!(violations(&c, &roots(), &id).is_empty());
        check(&c, None, &[], &roots(), &id).unwrap();
    }

    #[test]
    fn refuses_privileged() {
        let err = refused(&service(json!({"privileged": true})));
        assert!(
            err.contains("privileged: true") && err.contains("grant 'privileged'"),
            "{err}"
        );
    }

    #[test]
    fn refuses_host_pid() {
        let err = refused(&service(json!({"pid": "host"})));
        assert!(err.contains("pid: host"), "{err}");
    }

    #[test]
    fn refuses_host_network() {
        let err = refused(&service(json!({"network_mode": "host"})));
        assert!(err.contains("network_mode: host"), "{err}");
    }

    #[test]
    fn refuses_sys_admin_in_any_spelling() {
        for cap in ["SYS_ADMIN", "CAP_SYS_ADMIN", "sys_admin", "ALL"] {
            let err = refused(&service(json!({"cap_add": [cap]})));
            assert!(err.contains(ALLOW_SYS_ADMIN), "{cap}: {err}");
        }
    }

    #[test]
    fn refuses_binding_root() {
        let err = refused(&bind("/"));
        assert!(err.contains("binds host path / "), "{err}");
    }

    #[test]
    fn refuses_binds_outside_the_data_roots() {
        for src in ["/etc", "/var/run/docker.sock", "/root/.ssh", "/mnt", "/opt"] {
            let err = refused(&bind(src));
            assert!(err.contains(&format!("grant 'bind:{src}'")), "{src}: {err}");
        }
    }

    #[test]
    fn refuses_a_bind_through_a_symlink_out_of_a_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("stacks");
        std::fs::create_dir_all(&root).unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("escape")).unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        let src = root.join("escape/data").to_string_lossy().into_owned();
        assert!(!violations(&bind(&src), &roots, &resolve_host_path).is_empty());
        let inside = root.join("web/data").to_string_lossy().into_owned();
        assert!(violations(&bind(&inside), &roots, &resolve_host_path).is_empty());
    }

    #[test]
    fn refuses_a_local_volume_binding_a_host_path() {
        let c = cfg(json!({
            "name": "web",
            "services": {"app": {"image": "x"}},
            "volumes": {"root": {"driver_opts": {"type": "none", "o": "bind", "device": "/"}}}
        }));
        let err = refused(&c);
        assert!(err.contains("volume root binds host path /"), "{err}");
    }

    #[test]
    fn a_grant_admits_its_setting_only() {
        let c = service(json!({
            "network_mode": "host",
            "volumes": [{"type": "bind", "source": "/var/run/docker.sock", "target": "/s"}]
        }));
        let allow = vec![ALLOW_NETWORK_HOST.to_string()];
        let err = check(&c, None, &allow, &roots(), &id)
            .unwrap_err()
            .to_string();
        assert!(
            !err.contains("network_mode") && err.contains("docker.sock"),
            "{err}"
        );
        let allow = vec![
            ALLOW_NETWORK_HOST.to_string(),
            "bind:/var/run/docker.sock".to_string(),
        ];
        check(&c, None, &allow, &roots(), &id).unwrap();
    }

    #[test]
    fn settings_the_stack_already_ran_with_stay_allowed_for_that_service() {
        let current = service(json!({"network_mode": "host"}));
        check(&current, Some(&current), &[], &roots(), &id).unwrap();
        let moved = cfg(json!({
            "name": "web",
            "services": {"app": {"image": "x"}, "other": {"image": "y", "network_mode": "host"}}
        }));
        let err = check(&moved, Some(&current), &[], &roots(), &id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("other: network_mode: host"), "{err}");
        let escalated = service(json!({"network_mode": "host", "privileged": true}));
        let err = check(&escalated, Some(&current), &[], &roots(), &id)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("privileged") && !err.contains("network_mode"),
            "{err}"
        );
    }

    #[test]
    fn grants_are_validated() {
        for ok in [
            "privileged",
            "pid:host",
            "network_mode:host",
            "cap_add:SYS_ADMIN",
            "bind:/var/run/docker.sock",
        ] {
            validate_grant(ok).unwrap();
        }
        for bad in [
            "root",
            "bind:/",
            "bind:relative",
            "bind:/mnt/../etc",
            "pid:container",
        ] {
            assert!(validate_grant(bad).is_err(), "{bad}");
        }
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
                    allow: vec![ALLOW_PRIVILEGED.into()],
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
