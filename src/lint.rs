//! Compose lint for managed stacks: `stack detail query.kind=audit` and the
//! stack `fix` action.
//!
//! The audit reads the resolved config (`compose config --format json`), so it
//! judges what the engine will run. Fixes are line edits to the compose file
//! on disk, so comments and layout survive; a finding whose value is not
//! written literally in the file (interpolated, relative) is reported as not
//! auto-fixable rather than guessed at.

use std::path::{Path, PathBuf};

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

fn under(path: &str, root: &str) -> bool {
    let root = root.trim_end_matches('/');
    path == root || path.starts_with(&format!("{root}/"))
}

/// The same tail of `source` under a managed root, if it exists there:
/// `/mnt/willow/media` → `/mnt/data/media`. Longest matching tail wins.
pub fn propose_equivalent(
    source: &str,
    roots: &[String],
    exists: &dyn Fn(&Path) -> bool,
) -> Option<String> {
    let parts: Vec<&str> = source.split('/').filter(|p| !p.is_empty()).collect();
    for skip in 1..parts.len() {
        let tail = parts[skip..].join("/");
        for root in roots {
            let candidate = PathBuf::from(root).join(&tail);
            let candidate = candidate.to_string_lossy();
            if candidate != source && exists(Path::new(candidate.as_ref())) {
                return Some(candidate.into_owned());
            }
        }
    }
    None
}

/// Lint one stack's resolved config. `stack_dir` holds the stack's own
/// config binds, which are backed up with the stack and never "unmanaged".
pub fn audit(
    cfg: &ComposeConfig,
    stack_dir: &str,
    roots: &[String],
    exists: &dyn Fn(&Path) -> bool,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (svc, s) in &cfg.services {
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
                        .then(|| propose_equivalent(src, roots, exists))
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
                        propose_equivalent(src, roots, exists),
                    )
                } else {
                    continue;
                };
                out.push(Finding {
                    id: format!("bind:{svc}:{src}"),
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

fn fix_restart(lines: &mut Vec<String>, svc: &str) -> Result<(), String> {
    let (header, end, child) = service_block(lines, svc)
        .ok_or_else(|| format!("service '{svc}' not found in the file"))?;
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

/// Replace `old` where it stands as a whole path: the next char must end it,
/// so `/mnt/a` does not match inside `/mnt/ab`.
fn replace_path(line: &str, old: &str, new: &str) -> Option<String> {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    let mut hit = false;
    while let Some(pos) = rest.find(old) {
        let after = rest[pos + old.len()..].chars().next();
        let ends = matches!(after, None | Some(':' | '"' | '\'' | ' ' | ',' | ']' | '/'));
        out.push_str(&rest[..pos]);
        out.push_str(if ends && after != Some('/') { new } else { old });
        hit |= ends && after != Some('/');
        rest = &rest[pos + old.len()..];
    }
    out.push_str(rest);
    hit.then_some(out)
}

fn fix_bind(lines: &mut [String], svc: &str, old: &str, new: &str) -> Result<(), String> {
    let (header, end, _) = service_block(lines, svc)
        .ok_or_else(|| format!("service '{svc}' not found in the file"))?;
    let mut hit = false;
    for line in &mut lines[header + 1..end] {
        if let Some(rewritten) = replace_path(line, old, new) {
            *line = rewritten;
            hit = true;
        }
    }
    if hit {
        Ok(())
    } else {
        Err(format!(
            "{old} is not written literally in service '{svc}' (interpolated or relative); fix by hand"
        ))
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

/// Apply the fixes for `ids` to `yaml`. Findings that cannot be applied are
/// reported in `not_fixed`; the rest of the file is untouched.
pub fn apply_fixes(yaml: &str, findings: &[Finding], ids: &[String]) -> FixOutcome {
    let mut lines: Vec<String> = yaml.lines().map(str::to_string).collect();
    let mut outcome = FixOutcome::default();
    for id in ids {
        let Some(f) = findings.iter().find(|f| &f.id == id) else {
            continue;
        };
        let result = match (f.kind, f.proposed.as_deref()) {
            (_, _) if !f.fixable => Err("not auto-fixable".to_string()),
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
        audit(&cfg, "/srv/stacks/media", &roots(), &fs(present))
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
                "bind:app:/mnt/willow/media",
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
            .find(|f| f.id == "bind:app:/mnt/willow/media")
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
            .find(|f| f.id == "bind:app:/mnt/willow/media")
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
            "bind:app:/mnt/willow/media".to_string(),
            "restart:worker".to_string(),
        ];
        let out = apply_fixes(YAML, &f, &wanted);
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
        let out = apply_fixes(YAML, &f, &["restart:worker".to_string()]);
        assert!(out.yaml.contains("restart: on-failure:3"));
        assert!(out.yaml.contains("/mnt/willow/media:/media"));
    }

    #[test]
    fn unfixable_and_non_literal_findings_are_reported() {
        let f = yaml_findings();
        let interpolated = "services:\n  app:\n    volumes:\n      - ${MEDIA}:/media\n";
        let out = apply_fixes(
            interpolated,
            &f,
            &[
                "bind:app:/mnt/willow/media".to_string(),
                "volume:app:data".to_string(),
            ],
        );
        assert!(out.applied.is_empty());
        assert_eq!(out.not_fixed.len(), 2);
        assert!(out.not_fixed[0].reason.contains("not written literally"));
        assert_eq!(out.yaml, interpolated);
    }

    #[test]
    fn diff_shows_removed_and_added_lines() {
        let d = diff("a\nb\nc\n", "a\nB\nc\n");
        assert_eq!(d, " a\n-b\n+B\n c\n");
        assert_eq!(diff("same\n", "same\n"), "");
    }
}
