//! The admin gate and `dry_run` opt-in shared by this plugin's mutating tools.
//!
//! Mutating tools set `execute_gated = false` and own their `dry_run` flag, so
//! the dry run can list the exact items a call would touch. Opting out of the
//! central gate also opts out of the role check orca runs inside it, so every
//! mutating tool calls [`require_admin`], dry run included.

use std::collections::BTreeSet;

use plugin_toolkit::contract::CallerIdentity;
use plugin_toolkit::prelude::*;

/// Fail closed: applying changes needs an identified admin caller.
pub fn authorize_execute(tool: &str, caller: Option<&CallerIdentity>) -> Result<()> {
    check_admin(&format!("{tool}: execute"), caller)
}

/// Admin for the dry run too, on tools whose plan alone probes host paths or
/// decompresses caller-chosen input.
pub fn require_admin(tool: &str, ctx: &ToolCtx) -> Result<()> {
    check_admin(tool, ctx.caller().as_ref())
}

/// Admin for `subject`, failing closed: no caller is refused.
pub fn require_caller_admin(subject: &str, caller: Option<&CallerIdentity>) -> Result<()> {
    check_admin(subject, caller)
}

fn check_admin(subject: &str, caller: Option<&CallerIdentity>) -> Result<()> {
    match caller {
        Some(c) if c.role == "admin" => Ok(()),
        Some(c) => bail!(
            "{subject} requires role 'admin'; caller '{}' has '{}'",
            c.username,
            c.role
        ),
        None => bail!(
            "{subject} refused: the call carries no caller identity, so admin cannot be verified"
        ),
    }
}

/// Split the operator's confirmed plan against what is valid right now:
/// `(act_on, dropped)`. Only items in both are acted on; confirmed items that
/// are no longer valid are reported, never acted on.
pub fn intersect(confirmed: &[String], current: &[String]) -> (Vec<String>, Vec<String>) {
    let now: BTreeSet<&str> = current.iter().map(String::as_str).collect();
    let mut seen = BTreeSet::new();
    let mut act = Vec::new();
    let mut dropped = Vec::new();
    for item in confirmed {
        if !seen.insert(item.as_str()) {
            continue;
        }
        if now.contains(item.as_str()) {
            act.push(item.clone());
        } else {
            dropped.push(item.clone());
        }
    }
    (act, dropped)
}

/// An execute call must echo the plan it confirms. An empty confirmation is
/// only accepted when there is nothing to do anyway.
pub fn require_confirmed(tool: &str, confirmed: &[String], current: &[String]) -> Result<()> {
    if confirmed.is_empty() && !current.is_empty() {
        bail!(
            "{tool}: execute needs the items from the dry run; re-run with `dryRun` and pass its items"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(role: &str) -> CallerIdentity {
        CallerIdentity {
            user_id: "u".into(),
            username: "op".into(),
            role: role.into(),
            can_mutate: true,
        }
    }

    #[test]
    fn execute_needs_an_admin_caller() {
        assert!(authorize_execute("t", Some(&caller("admin"))).is_ok());
        let err = authorize_execute("t", Some(&caller("user"))).unwrap_err();
        assert!(err.to_string().contains("requires role 'admin'"), "{err}");
        let err = authorize_execute("t", None).unwrap_err();
        assert!(err.to_string().contains("no caller identity"), "{err}");
    }

    #[test]
    fn require_caller_admin_fails_closed() {
        assert!(require_caller_admin("t", Some(&caller("admin"))).is_ok());
        let err = require_caller_admin("t", None).unwrap_err();
        assert!(err.to_string().contains("no caller identity"), "{err}");
        for role in ["member", "user"] {
            let err = require_caller_admin("t", Some(&caller(role))).unwrap_err();
            assert!(err.to_string().contains("requires role 'admin'"), "{err}");
        }
    }

    #[test]
    fn intersect_acts_only_on_confirmed_items_still_valid() {
        let confirmed = vec!["a".to_string(), "b".to_string(), "a".to_string()];
        let current = vec!["b".to_string(), "c".to_string()];
        let (act, dropped) = intersect(&confirmed, &current);
        assert_eq!(act, vec!["b"]);
        assert_eq!(dropped, vec!["a"]);
    }

    #[test]
    fn empty_confirmation_is_refused_unless_nothing_to_do() {
        assert!(require_confirmed("t", &[], &["x".to_string()]).is_err());
        assert!(require_confirmed("t", &[], &[]).is_ok());
        assert!(require_confirmed("t", &["x".to_string()], &[]).is_ok());
    }
}
