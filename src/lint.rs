//! Compose lint for managed stacks: `stack detail query.kind=audit` and the
//! stack `fix` action.
//!
//! The audit reads the resolved config (`compose config --format json`), so it
//! judges what the engine will run. Fixes are line edits to the compose file
//! on disk, so comments and layout survive; a finding whose value is not
//! written literally in the file (interpolated, relative) is reported as not
//! auto-fixable rather than guessed at.

use std::path::{Component, Path, PathBuf};

use plugin_toolkit::schemars::JsonSchema;
use plugin_toolkit::serde::{Deserialize, Serialize};

use crate::compose_config::ComposeConfig;

/// Managed mount roots when neither the call nor the daemon names any.
pub const DEFAULT_MANAGED_ROOTS: &[&str] = &[
    "/mnt/data",
    "/mnt/backups",
    "/mnt/downloads",
    "/opt/appdata",
];

/// Comma-separated override of [`DEFAULT_MANAGED_ROOTS`], set on the daemon.
pub const MANAGED_ROOTS_ENV: &str = "ORCA_DOCKER_MANAGED_ROOTS";

/// Host paths that are bound for the host's own sake (sockets, devices,
/// timezone), not as app data, so they are never "outside managed mounts".
const SYSTEM_PREFIXES: &[&str] = &[
    "/var/run",
    "/run",
    "/etc",
    "/dev",
    "/sys",
    "/proc",
    "/lib/modules",
    "/usr",
    "/tmp",
];

pub const PROPOSED_RESTART: &str = "unless-stopped";

/// Roots in force: the call's, else the daemon's env, else the defaults.
pub fn managed_roots(requested: Option<&[String]>) -> Vec<String> {
    if let Some(r) = requested.filter(|r| !r.is_empty()) {
        return r.to_vec();
    }
    let from_env: Vec<String> = std::env::var(MANAGED_ROOTS_ENV)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| s.starts_with('/'))
        .map(str::to_string)
        .collect();
    if !from_env.is_empty() {
        return from_env;
    }
    DEFAULT_MANAGED_ROOTS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// `restart` is `no`, unset, or `on-failure[:N]`, which gives up for good
    /// after N failures (a transient DNS outage is enough).
    Restart,
    /// The bind source does not exist on the host.
    BindMissing,
    /// The bind source exists but sits outside every managed mount root.
    BindUnmanaged,
    /// Data on a named volume, outside the stack's bind-mounted paths.
    NamedVolume,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct Finding {
    /// Stable id: `restart:<svc>`, `bind:<svc>:<source>`, `volume:<svc>:<name>`.
    /// The `fix` action takes these back.
    pub id: String,
    pub kind: FindingKind,
    pub service: String,
    pub detail: String,
    pub current: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed: Option<String>,
    /// Whether `fix` can rewrite it.
    pub fixable: bool,
}

/// Whether `path` is `root` or below it, by whole components. A path with a
/// `..` component is never under anything: it could climb back out.
pub(crate) fn under(path: &str, root: &str) -> bool {
    let p = Path::new(path);
    !p.components().any(|c| c == Component::ParentDir) && p.starts_with(root)
}

/// Whether `candidate` is, contains or sits inside one of `bound`.
pub fn is_taken(candidate: &Path, bound: &[String]) -> bool {
    let c = candidate.to_string_lossy();
    bound.iter().any(|b| under(&c, b) || under(b, &c))
}

/// The same tail of `source` under a managed root, if it exists there:
/// `/mnt/willow/media` → `/mnt/data/media`. Longest matching tail wins. A
/// one-component tail (`config`, `data`) matches unrelated directories, so it
/// counts only when a component of it is the stack or service name
/// (`names`). A candidate some container already binds (`taken`) is
/// another app's data and is never proposed.
pub fn propose_equivalent(
    source: &str,
    roots: &[String],
    names: &[&str],
    exists: &dyn Fn(&Path) -> bool,
    taken: &dyn Fn(&Path) -> bool,
) -> Option<String> {
    let parts: Vec<&str> = source.split('/').filter(|p| !p.is_empty()).collect();
    for skip in 1..parts.len() {
        let tail_parts = &parts[skip..];
        let named = tail_parts.iter().any(|p| {
            names
                .iter()
                .any(|n| !n.is_empty() && p.eq_ignore_ascii_case(n))
        });
        if tail_parts.len() < 2 && !named {
            continue;
        }
        let tail = tail_parts.join("/");
        for root in roots {
            let candidate = PathBuf::from(root).join(&tail);
            let candidate = candidate.to_string_lossy();
            let path = Path::new(candidate.as_ref());
            if candidate != source && exists(path) && !taken(path) {
                return Some(candidate.into_owned());
            }
        }
    }
    None
}

/// Lint one stack's resolved config. `stack_dir` holds the stack's own
/// config binds, which are backed up with the stack and never "unmanaged".
/// `taken` says whether some container already binds a path.
pub fn audit(
    cfg: &ComposeConfig,
    stack_dir: &str,
    roots: &[String],
    exists: &dyn Fn(&Path) -> bool,
    taken: &dyn Fn(&Path) -> bool,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (svc, s) in &cfg.services {
        let names = [cfg.name.as_str(), svc.as_str()];
        let restart = s.restart.as_deref().unwrap_or("");
        if restart.is_empty() || restart == "no" || restart.starts_with("on-failure") {
            let current = if restart.is_empty() {
                "unset (never restarts)".to_string()
            } else {
                restart.to_string()
            };
            out.push(Finding {
                id: format!("restart:{svc}"),
                kind: FindingKind::Restart,
                service: svc.clone(),
                detail: format!(
                    "restart policy '{current}' leaves the service down after a crash or a transient outage"
                ),
                current,
                proposed: Some(PROPOSED_RESTART.to_string()),
                fixable: true,
            });
        }
        for m in &s.volumes {
            if let Some(src) = m.bind_source() {
                if SYSTEM_PREFIXES.iter().any(|p| under(src, p)) {
                    continue;
                }
                let managed = roots.iter().any(|r| under(src, r));
                let own = under(src, stack_dir);
                let (kind, detail, proposed) = if !exists(Path::new(src)) {
                    // A missing path under a managed root is a mount that is
                    // down, not a path to move elsewhere.
                    let proposed = (!managed)
                        .then(|| propose_equivalent(src, roots, &names, exists, taken))
                        .flatten();
                    (
                        FindingKind::BindMissing,
                        format!("bind source {src} for {} does not exist", m.target),
                        proposed,
                    )
                } else if !managed && !own {
                    (
                        FindingKind::BindUnmanaged,
                        format!(
                            "bind source {src} for {} is outside the managed mounts ({})",
                            m.target,
                            roots.join(", ")
                        ),
                        propose_equivalent(src, roots, &names, exists, taken),
                    )
                } else {
                    continue;
                };
                // The id pins the proposal: a confirmed id never applies a
                // different path than the one the dry run showed.
                let id = match &proposed {
                    Some(new) => format!("bind:{svc}:{src}->{new}"),
                    None => format!("bind:{svc}:{src}"),
                };
                out.push(Finding {
                    id,
                    kind,
                    service: svc.clone(),
                    detail,
                    current: src.to_string(),
                    fixable: proposed.is_some(),
                    proposed,
                });
            } else if let Some(vol) = m.named_volume() {
                let engine_name = cfg
                    .volumes
                    .get(vol)
                    .and_then(|v| v.name.clone())
                    .unwrap_or_else(|| vol.to_string());
                out.push(Finding {
                    id: format!("volume:{svc}:{vol}"),
                    kind: FindingKind::NamedVolume,
                    service: svc.clone(),
                    detail: format!(
                        "named volume '{engine_name}' holds data at {}; it is not under the stack dir or a managed mount",
                        m.target
                    ),
                    current: engine_name,
                    proposed: None,
                    fixable: false,
                });
            }
        }
    }
    out
}

// ── fix: line edits to the compose file ─────────────────────────────────────

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn is_content(line: &str) -> bool {
    let t = line.trim();
    !t.is_empty() && !t.starts_with('#')
}

/// `(header, end_exclusive, child_indent)` of `svc`'s block under the
/// top-level `services:` key.
fn service_block(lines: &[String], svc: &str) -> Option<(usize, usize, usize)> {
    let start = lines
        .iter()
        .position(|l| l.trim_end() == "services:" || l.starts_with("services: #"))?;
    let mut svc_indent = None;
    let mut header = None;
    for (i, l) in lines.iter().enumerate().skip(start + 1) {
        if !is_content(l) {
            continue;
        }
        let ind = indent_of(l);
        if ind == 0 {
            break;
        }
        let level = *svc_indent.get_or_insert(ind);
        if ind != level {
            continue;
        }
        let key = l.trim().split(':').next().unwrap_or_default();
        if key.trim_matches(|c| c == '"' || c == '\'') == svc {
            header = Some(i);
            break;
        }
    }
    let header = header?;
    let level = svc_indent?;
    let end = lines
        .iter()
        .enumerate()
        .skip(header + 1)
        .find(|(_, l)| is_content(l) && indent_of(l) <= level)
        .map(|(i, _)| i)
        .unwrap_or(lines.len());
    let child = lines[header + 1..end]
        .iter()
        .find(|l| is_content(l))
        .map(|l| indent_of(l))
        .unwrap_or(level + 2);
    Some((header, end, child))
}

/// [`service_block`] for an edit: refused when the service is written in
/// flow style (`app: {image: x}`), which line edits would turn into invalid
/// YAML.
fn block_service(lines: &[String], svc: &str) -> Result<(usize, usize, usize), String> {
    let (header, end, child) = service_block(lines, svc)
        .ok_or_else(|| format!("service '{svc}' not found in the file"))?;
    let rest = lines[header]
        .split_once(':')
        .map(|(_, r)| r.split('#').next().unwrap_or_default().trim())
        .unwrap_or_default();
    if !rest.is_empty() {
        return Err(format!(
            "service '{svc}' is written in flow style; fix by hand"
        ));
    }
    Ok((header, end, child))
}

fn fix_restart(lines: &mut Vec<String>, svc: &str) -> Result<(), String> {
    let (header, end, child) = block_service(lines, svc)?;
    let pad = " ".repeat(child);
    let new = format!("{pad}restart: {PROPOSED_RESTART}");
    match (header + 1..end)
        .find(|&i| indent_of(&lines[i]) == child && lines[i].trim_start().starts_with("restart:"))
    {
        Some(i) => lines[i] = new,
        None => lines.insert(header + 1, new),
    }
    Ok(())
}

/// Replace `old` where it stands as a whole path: it must start the text or
/// follow a space, quote, `-` or `=`, and the next char must end it, so
/// `/mnt/a` matches neither inside `/mnt/ab` nor inside `/x/mnt/a`.
fn replace_path(text: &str, old: &str, new: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut prev: Option<char> = None;
    let mut hit = false;
    while let Some(pos) = rest.find(old) {
        let before = rest[..pos].chars().next_back().or(prev);
        let starts = matches!(before, None | Some(' ' | '"' | '\'' | '-' | '='));
        let after = rest[pos + old.len()..].chars().next();
        let ends = matches!(after, None | Some(':' | '"' | '\'' | ' ' | ',' | ']'));
        out.push_str(&rest[..pos]);
        out.push_str(if starts && ends { new } else { old });
        hit |= starts && ends;
        prev = old.chars().next_back();
        rest = &rest[pos + old.len()..];
    }
    out.push_str(rest);
    hit.then_some(out)
}

/// `(start, end)` of the lines of a `volumes:` list directly under a block
/// whose keys sit at `child` indent. List items may sit at the key's indent.
fn volumes_block(lines: &[String], from: usize, to: usize, child: usize) -> Option<(usize, usize)> {
    let key = (from..to).find(|&i| {
        indent_of(&lines[i]) == child && lines[i].trim_start().trim_end() == "volumes:"
    })?;
    let end = (key + 1..to)
        .find(|&i| {
            let l = &lines[i];
            is_content(l)
                && (indent_of(l) < child
                    || (indent_of(l) == child && !l.trim_start().starts_with('-')))
        })
        .unwrap_or(to);
    Some((key + 1, end))
}

/// Rewrite the source of one volume entry line when it is `old`: short
/// syntax (`- /src:/dst[:ro]`, optionally quoted) or a long-syntax
/// `source:` key. Targets, options and every other key are left alone.
fn rewrite_volume_source(line: &str, old: &str, new: &str) -> Option<String> {
    let body_at = line.len() - line.trim_start().len();
    let mut body = &line[body_at..];
    let mut offset = body_at;
    if let Some(rest) = body.strip_prefix("- ") {
        offset += 2 + (rest.len() - rest.trim_start().len());
        body = rest.trim_start();
    }
    if let Some(v) = body.strip_prefix("source:") {
        let value_at = offset + "source:".len() + (v.len() - v.trim_start().len());
        let value = line[value_at..].trim_end();
        let bare = value.trim_matches(|c| c == '"' || c == '\'');
        if bare != old {
            return None;
        }
        let rewritten = replace_path(value, old, new)?;
        return Some(format!("{}{rewritten}", &line[..value_at]));
    }
    if offset == body_at || body.contains(": ") {
        return None;
    }
    let unquoted = body.trim_start_matches(['"', '\'']);
    let src_end = unquoted.find(':').unwrap_or(unquoted.len());
    if &unquoted[..src_end] != old {
        return None;
    }
    let src_at = offset + (body.len() - unquoted.len());
    let segment = &line[src_at..src_at + src_end];
    let rewritten = replace_path(segment, old, new)?;
    Some(format!(
        "{}{rewritten}{}",
        &line[..src_at],
        &line[src_at + src_end..]
    ))
}

fn fix_bind(lines: &mut [String], svc: &str, old: &str, new: &str) -> Result<(), String> {
    let (header, end, child) = block_service(lines, svc)?;
    let not_literal = || {
        format!(
            "{old} is not written literally in service '{svc}' volumes (interpolated or relative); fix by hand"
        )
    };
    let (from, to) = volumes_block(lines, header + 1, end, child).ok_or_else(not_literal)?;
    let mut hit = false;
    for line in &mut lines[from..to] {
        if let Some(rewritten) = rewrite_volume_source(line, old, new) {
            *line = rewritten;
            hit = true;
        }
    }
    if hit { Ok(()) } else { Err(not_literal()) }
}

/// Whether the override file sets what `f` would fix: compose applies the
/// override last, so an edit to the compose file would not take effect.
fn set_in_override(lines: &[String], f: &Finding) -> bool {
    let Some((header, end, child)) = service_block(lines, &f.service) else {
        return false;
    };
    match f.kind {
        FindingKind::Restart => (header + 1..end).any(|i| {
            indent_of(&lines[i]) == child && lines[i].trim_start().starts_with("restart:")
        }),
        FindingKind::BindMissing | FindingKind::BindUnmanaged => {
            volumes_block(lines, header + 1, end, child).is_some_and(|(from, to)| {
                lines[from..to]
                    .iter()
                    .any(|l| rewrite_volume_source(l, &f.current, "").is_some())
            })
        }
        FindingKind::NamedVolume => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct NotFixed {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct FixOutcome {
    pub yaml: String,
    pub applied: Vec<String>,
    pub not_fixed: Vec<NotFixed>,
}

/// Apply the fixes for `ids` to `yaml`. Findings that cannot be applied, or
/// whose value the override file (`override_yaml`, when there is one) sets,
/// are reported in `not_fixed`; the rest of the file is untouched.
pub fn apply_fixes(
    yaml: &str,
    override_yaml: Option<&str>,
    findings: &[Finding],
    ids: &[String],
) -> FixOutcome {
    let mut lines: Vec<String> = yaml.lines().map(str::to_string).collect();
    let override_lines: Vec<String> = override_yaml
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    let mut outcome = FixOutcome::default();
    for id in ids {
        let Some(f) = findings.iter().find(|f| &f.id == id) else {
            continue;
        };
        let result = match (f.kind, f.proposed.as_deref()) {
            (_, _) if !f.fixable => Err("not auto-fixable".to_string()),
            (_, _) if set_in_override(&override_lines, f) => Err(
                "the override file sets this value and compose applies it last; fix it there"
                    .to_string(),
            ),
            (FindingKind::Restart, _) => fix_restart(&mut lines, &f.service),
            (FindingKind::BindMissing | FindingKind::BindUnmanaged, Some(new)) => {
                fix_bind(&mut lines, &f.service, &f.current, new)
            }
            _ => Err("not auto-fixable".to_string()),
        };
        match result {
            Ok(()) => outcome.applied.push(id.clone()),
            Err(reason) => outcome.not_fixed.push(NotFixed {
                id: id.clone(),
                reason,
            }),
        }
    }
    let mut out = lines.join("\n");
    if yaml.ends_with('\n') {
        out.push('\n');
    }
    outcome.yaml = out;
    outcome
}

/// A unified-style line diff (`-`/`+` with up to two lines of context).
pub fn diff(old: &str, new: &str) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let (n, m) = (a.len(), b.len());
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut ops: Vec<(char, &str)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            ops.push((' ', a[i]));
            i += 1;
            j += 1;
        } else if i < n && (j == m || lcs[i + 1][j] >= lcs[i][j + 1]) {
            ops.push(('-', a[i]));
            i += 1;
        } else {
            ops.push(('+', b[j]));
            j += 1;
        }
    }
    const CONTEXT: usize = 2;
    let changed: Vec<usize> = (0..ops.len()).filter(|&k| ops[k].0 != ' ').collect();
    let mut out = String::new();
    let mut last: Option<usize> = None;
    for (k, (op, line)) in ops.iter().enumerate() {
        let near = changed
            .iter()
            .any(|&c| k + CONTEXT >= c && k <= c + CONTEXT);
        if !near {
            continue;
        }
        if last.is_some_and(|l| k > l + 1) {
            out.push_str("@@\n");
        }
        out.push(*op);
        out.push_str(line);
        out.push('\n');
        last = Some(k);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose_config::FIXTURE;
    use std::collections::HashSet;

    fn roots() -> Vec<String> {
        DEFAULT_MANAGED_ROOTS
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn fs(present: &[&str]) -> impl Fn(&Path) -> bool {
        let set: HashSet<String> = present.iter().map(|s| s.to_string()).collect();
        move |p: &Path| set.contains(p.to_string_lossy().as_ref())
    }

    fn findings(present: &[&str]) -> Vec<Finding> {
        let cfg = ComposeConfig::parse(FIXTURE).unwrap();
        audit(&cfg, "/srv/stacks/media", &roots(), &fs(present), &|_| {
            false
        })
    }

    fn ids(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.id.as_str()).collect()
    }

    #[test]
    fn audit_flags_restart_binds_and_named_volumes() {
        let f = findings(&[
            "/mnt/willow/media",
            "/mnt/data/media",
            "/srv/stacks/media/config",
        ]);
        assert_eq!(
            ids(&f),
            vec![
                "restart:app",
                "bind:app:/mnt/willow/media->/mnt/data/media",
                "volume:app:data",
                "volume:db:pg",
                "bind:db:/mnt/data/gone",
                "restart:worker",
            ]
        );
        let app_restart = &f[0];
        assert_eq!(app_restart.current, "on-failure:3");
        assert_eq!(app_restart.proposed.as_deref(), Some("unless-stopped"));
        assert_eq!(f[5].current, "unset (never restarts)");
    }

    #[test]
    fn unmanaged_bind_proposes_the_managed_equivalent() {
        let f = findings(&["/mnt/willow/media", "/mnt/data/media"]);
        let bind = f
            .iter()
            .find(|f| f.id == "bind:app:/mnt/willow/media->/mnt/data/media")
            .unwrap();
        assert_eq!(bind.kind, FindingKind::BindUnmanaged);
        assert_eq!(bind.proposed.as_deref(), Some("/mnt/data/media"));
        assert!(bind.fixable);
    }

    #[test]
    fn missing_bind_outside_roots_is_flagged_with_a_proposal() {
        let f = findings(&["/mnt/data/media"]);
        let bind = f
            .iter()
            .find(|f| f.id == "bind:app:/mnt/willow/media->/mnt/data/media")
            .unwrap();
        assert_eq!(bind.kind, FindingKind::BindMissing);
        assert_eq!(bind.proposed.as_deref(), Some("/mnt/data/media"));
    }

    #[test]
    fn missing_bind_under_a_managed_root_gets_no_proposal() {
        let f = findings(&[]);
        let gone = f.iter().find(|f| f.id == "bind:db:/mnt/data/gone").unwrap();
        assert_eq!(gone.kind, FindingKind::BindMissing);
        assert!(gone.proposed.is_none() && !gone.fixable);
    }

    #[test]
    fn system_binds_and_stack_dir_binds_are_not_flagged() {
        let f = findings(&["/srv/stacks/media/config"]);
        assert!(!f.iter().any(|f| f.current.starts_with("/var/run")));
        assert!(!f.iter().any(|f| f.current.starts_with("/srv/stacks/media")));
    }

    #[test]
    fn named_volume_reports_the_engine_name_and_is_not_fixable() {
        let f = findings(&[]);
        let v = f.iter().find(|f| f.id == "volume:app:data").unwrap();
        assert_eq!(v.current, "media_data");
        assert!(!v.fixable);
    }

    #[test]
    fn under_compares_whole_components_and_refuses_dotdot() {
        assert!(under("/mnt/data", "/mnt/data"));
        assert!(under("/mnt/data/x", "/mnt/data/"));
        assert!(!under("/mnt/database", "/mnt/data"));
        assert!(!under("/mnt/data/../../etc", "/mnt/data"));
        assert!(!under("/mnt/../", "/mnt"));
    }

    #[test]
    fn managed_roots_prefers_the_call_then_defaults() {
        let call = vec!["/mnt/pool".to_string()];
        assert_eq!(managed_roots(Some(&call)), call);
        if std::env::var(MANAGED_ROOTS_ENV).is_err() {
            assert_eq!(managed_roots(None), roots());
        }
    }

    const YAML: &str = "\
# media stack
services:
  app:
    image: ghcr.io/example/app:1
    restart: on-failure:3   # gave up after a DNS blip
    volumes:
      - /mnt/willow/media:/media
      - /mnt/willow/media2:/other
      - data:/data
  worker:
    image: ghcr.io/example/worker:1
volumes:
  data:
";

    fn yaml_findings() -> Vec<Finding> {
        findings(&["/mnt/willow/media", "/mnt/data/media"])
    }

    #[test]
    fn fix_rewrites_restart_and_bind_and_leaves_the_rest() {
        let f = yaml_findings();
        let wanted = vec![
            "restart:app".to_string(),
            "bind:app:/mnt/willow/media->/mnt/data/media".to_string(),
            "restart:worker".to_string(),
        ];
        let out = apply_fixes(YAML, None, &f, &wanted);
        assert_eq!(out.applied, wanted);
        assert!(out.not_fixed.is_empty(), "{:?}", out.not_fixed);
        assert_eq!(
            out.yaml,
            "\
# media stack
services:
  app:
    image: ghcr.io/example/app:1
    restart: unless-stopped
    volumes:
      - /mnt/data/media:/media
      - /mnt/willow/media2:/other
      - data:/data
  worker:
    restart: unless-stopped
    image: ghcr.io/example/worker:1
volumes:
  data:
"
        );
    }

    #[test]
    fn fix_only_touches_the_requested_ids() {
        let f = yaml_findings();
        let out = apply_fixes(YAML, None, &f, &["restart:worker".to_string()]);
        assert!(out.yaml.contains("restart: on-failure:3"));
        assert!(out.yaml.contains("/mnt/willow/media:/media"));
    }

    #[test]
    fn unfixable_and_non_literal_findings_are_reported() {
        let f = yaml_findings();
        let interpolated = "services:\n  app:\n    volumes:\n      - ${MEDIA}:/media\n";
        let out = apply_fixes(
            interpolated,
            None,
            &f,
            &[
                "bind:app:/mnt/willow/media->/mnt/data/media".to_string(),
                "volume:app:data".to_string(),
            ],
        );
        assert!(out.applied.is_empty());
        assert_eq!(out.not_fixed.len(), 2);
        assert!(out.not_fixed[0].reason.contains("not written literally"));
        assert_eq!(out.yaml, interpolated);
    }

    #[test]
    fn replace_path_needs_a_left_boundary() {
        assert_eq!(
            replace_path("/mnt/a", "/mnt/a", "/x").as_deref(),
            Some("/x")
        );
        assert_eq!(
            replace_path("\"/mnt/a\"", "/mnt/a", "/x").as_deref(),
            Some("\"/x\"")
        );
        assert_eq!(replace_path("/srv/mnt/a:/a", "/mnt/a", "/x"), None);
        assert_eq!(replace_path("/mnt/ab", "/mnt/a", "/x"), None);
        assert_eq!(replace_path("/mnt/a/sub", "/mnt/a", "/x"), None);
    }

    fn bind_finding(svc: &str, current: &str, proposed: &str) -> Finding {
        Finding {
            id: format!("bind:{svc}:{current}->{proposed}"),
            kind: FindingKind::BindUnmanaged,
            service: svc.into(),
            detail: String::new(),
            current: current.into(),
            proposed: Some(proposed.into()),
            fixable: true,
        }
    }

    #[test]
    fn bind_fix_edits_only_the_matching_volume_source() {
        let yaml = "\
services:
  app:
    image: x
    command: [\"--dir\", \"/mnt/willow/media\"]
    environment:
      - MEDIA=/mnt/willow/media
    labels:
      path: /mnt/willow/media
    volumes:
      - /mnt/willow/media:/mnt/willow/media:ro
      - type: bind
        source: \"/mnt/willow/media\"
        target: /mirror
      - /mnt/willow/media2:/other
";
        let f = bind_finding("app", "/mnt/willow/media", "/mnt/data/media");
        let out = apply_fixes(
            yaml,
            None,
            &[f],
            &["bind:app:/mnt/willow/media->/mnt/data/media".to_string()],
        );
        assert!(out.not_fixed.is_empty(), "{:?}", out.not_fixed);
        assert_eq!(
            out.yaml,
            "\
services:
  app:
    image: x
    command: [\"--dir\", \"/mnt/willow/media\"]
    environment:
      - MEDIA=/mnt/willow/media
    labels:
      path: /mnt/willow/media
    volumes:
      - /mnt/data/media:/mnt/willow/media:ro
      - type: bind
        source: \"/mnt/data/media\"
        target: /mirror
      - /mnt/willow/media2:/other
"
        );
    }

    #[test]
    fn a_bind_only_outside_volumes_is_not_fixed() {
        let yaml = "services:\n  app:\n    environment:\n      - MEDIA=/mnt/willow/media\n";
        let f = bind_finding("app", "/mnt/willow/media", "/mnt/data/media");
        let out = apply_fixes(
            yaml,
            None,
            &[f],
            &["bind:app:/mnt/willow/media->/mnt/data/media".to_string()],
        );
        assert!(out.applied.is_empty());
        assert_eq!(out.yaml, yaml);
    }

    #[test]
    fn a_one_component_tail_needs_the_stack_or_service_name() {
        let roots = vec!["/mnt/data".to_string()];
        let there = fs(&["/mnt/data/config", "/mnt/data/sonarr", "/mnt/data/tv/shows"]);
        let none = |_: &Path| false;
        assert_eq!(
            propose_equivalent(
                "/mnt/willow/config",
                &roots,
                &["media", "app"],
                &there,
                &none
            ),
            None
        );
        assert_eq!(
            propose_equivalent(
                "/mnt/willow/sonarr",
                &roots,
                &["arr", "sonarr"],
                &there,
                &none
            )
            .as_deref(),
            Some("/mnt/data/sonarr")
        );
        assert_eq!(
            propose_equivalent("/mnt/willow/tv/shows", &roots, &[], &there, &none).as_deref(),
            Some("/mnt/data/tv/shows")
        );
        // A name merely contained in a component is not the stack's.
        assert_eq!(
            propose_equivalent("/mnt/willow/sonarr", &roots, &["arr"], &there, &none),
            None
        );
    }

    #[test]
    fn a_path_another_container_binds_is_never_proposed() {
        let roots = vec!["/mnt/data".to_string()];
        let there = fs(&["/mnt/data/tv/shows"]);
        let bound = vec!["/mnt/data/tv".to_string()];
        assert_eq!(
            propose_equivalent("/mnt/willow/tv/shows", &roots, &[], &there, &|p| {
                is_taken(p, &bound)
            }),
            None
        );
        assert!(is_taken(
            Path::new("/mnt/data/tv"),
            &["/mnt/data/tv/shows".into()]
        ));
        assert!(!is_taken(Path::new("/mnt/data/tvx"), &bound));
    }

    #[test]
    fn a_flow_style_service_is_not_edited() {
        let yaml = "services:\n  app: {image: x, restart: \"no\"}\n";
        let f = Finding {
            id: "restart:app".into(),
            kind: FindingKind::Restart,
            service: "app".into(),
            detail: String::new(),
            current: "no".into(),
            proposed: Some(PROPOSED_RESTART.into()),
            fixable: true,
        };
        let out = apply_fixes(yaml, None, &[f], &["restart:app".to_string()]);
        assert!(out.applied.is_empty());
        assert!(
            out.not_fixed[0].reason.contains("flow style"),
            "{:?}",
            out.not_fixed
        );
        assert_eq!(out.yaml, yaml);
    }

    #[test]
    fn a_bind_fix_leaves_devices_alone() {
        let yaml = "services:\n  app:\n    devices:\n      - /mnt/willow/media:/dev/x\n    volumes:\n      - /mnt/willow/media:/media\n";
        let f = bind_finding("app", "/mnt/willow/media", "/mnt/data/media");
        let id = f.id.clone();
        let out = apply_fixes(yaml, None, &[f], &[id]);
        assert!(out.not_fixed.is_empty(), "{:?}", out.not_fixed);
        assert!(
            out.yaml.contains("      - /mnt/willow/media:/dev/x\n"),
            "{}",
            out.yaml
        );
        assert!(
            out.yaml.contains("      - /mnt/data/media:/media\n"),
            "{}",
            out.yaml
        );
    }

    #[test]
    fn a_bind_id_pins_the_proposed_path() {
        let f = findings(&["/mnt/willow/media", "/mnt/data/media"]);
        assert!(
            f.iter()
                .any(|f| f.id == "bind:app:/mnt/willow/media->/mnt/data/media"),
            "{:?}",
            ids(&f)
        );
    }

    #[test]
    fn a_value_the_override_sets_is_not_fixed() {
        let f = yaml_findings();
        let override_yaml = "services:\n  app:\n    restart: on-failure:3\n    volumes:\n      - /mnt/willow/media:/media\n";
        let wanted = vec![
            "restart:app".to_string(),
            "bind:app:/mnt/willow/media->/mnt/data/media".to_string(),
            "restart:worker".to_string(),
        ];
        let out = apply_fixes(YAML, Some(override_yaml), &f, &wanted);
        assert_eq!(out.applied, vec!["restart:worker"]);
        assert_eq!(out.not_fixed.len(), 2);
        assert!(out.not_fixed.iter().all(|n| n.reason.contains("override")));
        assert!(out.yaml.contains("restart: on-failure:3"));
    }

    #[test]
    fn diff_shows_removed_and_added_lines() {
        let d = diff("a\nb\nc\n", "a\nB\nc\n");
        assert_eq!(d, " a\n-b\n+B\n c\n");
        assert_eq!(diff("same\n", "same\n"), "");
    }
}
