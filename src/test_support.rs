//! Test helpers shared by the admin-gated tools: callers, a bare `ToolCtx`,
//! and an in-memory `db.op` capability sink.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use plugin_toolkit::abi::{DbOp, DbReply, DbRow, DbValue};
use plugin_toolkit::contract::{CallerIdentity, ToolCtx};

pub fn caller(role: &str) -> CallerIdentity {
    CallerIdentity {
        user_id: "u".into(),
        username: "op".into(),
        role: role.into(),
        can_mutate: true,
    }
}

pub fn test_ctx() -> ToolCtx {
    use plugin_toolkit::contract::config::{Config, Model, Ports};
    use std::sync::Arc;
    ToolCtx::new(Arc::new(Config {
        anthropic_api_key: None,
        lmstudio_url: String::new(),
        ollama_url: String::new(),
        default_model: Model::LMStudio {
            id: String::new(),
            url: String::new(),
        },
        app_dir: std::env::temp_dir(),
        memory_root: std::env::temp_dir(),
        db_path: std::env::temp_dir().join("orca-test.db"),
        ports: Ports::default(),
    }))
}

pub fn admin() -> ToolCtx {
    test_ctx().with_auth(caller("admin"))
}

/// No caller, a `user`, and a `member` that can mutate: the callers orca's
/// central gate lets through.
pub fn non_admins() -> Vec<ToolCtx> {
    vec![
        test_ctx(),
        test_ctx().with_auth(caller("user")),
        test_ctx().with_auth(caller("member")),
    ]
}

pub fn assert_admin_refusal(err: &str) {
    assert!(
        err.contains("requires role 'admin'") || err.contains("no caller identity"),
        "{err}"
    );
}

/// Whether the docker CLI with compose is here; tests that run the real
/// `compose config` are skipped without it.
pub fn have_compose() -> bool {
    let ok = std::process::Command::new(crate::resolve_docker_bin())
        .args(["compose", "version"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("skipped: no docker compose CLI");
    }
    ok
}

type Tables = BTreeMap<(String, String), Vec<DbRow>>;

fn text(row: &DbRow, col: &str) -> Option<String> {
    match row.get(col) {
        Some(DbValue::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

fn apply(tables: &mut Tables, op: DbOp) -> Result<DbReply, String> {
    let mut reply = DbReply::default();
    match op {
        DbOp::List { namespace, table } => {
            reply.rows = tables.get(&(namespace, table)).cloned().unwrap_or_default();
        }
        DbOp::Get {
            namespace,
            table,
            key_col,
            key,
        } => {
            reply.rows = tables
                .get(&(namespace, table))
                .into_iter()
                .flatten()
                .filter(|r| text(r, &key_col).as_deref() == Some(key.as_str()))
                .cloned()
                .collect();
        }
        DbOp::Insert {
            namespace,
            table,
            row,
        } => {
            let rows = tables.entry((namespace, table)).or_default();
            let name = text(&row, "name");
            if name.is_some() && rows.iter().any(|r| text(r, "name") == name) {
                return Err("UNIQUE constraint failed: name".into());
            }
            rows.push(row);
            reply.affected = 1;
        }
        DbOp::Upsert {
            namespace,
            table,
            row,
        } => {
            let rows = tables.entry((namespace, table)).or_default();
            rows.retain(|r| text(r, "name") != text(&row, "name"));
            rows.push(row);
            reply.affected = 1;
        }
        DbOp::Update {
            namespace,
            table,
            key_col,
            row,
        } => {
            for r in tables.entry((namespace, table)).or_default() {
                if text(r, &key_col) == text(&row, &key_col) {
                    r.extend(row.clone());
                    reply.affected += 1;
                }
            }
        }
        DbOp::Delete {
            namespace,
            table,
            key_col,
            key,
        } => {
            let rows = tables.entry((namespace, table)).or_default();
            let before = rows.len();
            rows.retain(|r| text(r, &key_col).as_deref() != Some(key.as_str()));
            reply.affected = (before - rows.len()) as u64;
        }
    }
    Ok(reply)
}

/// Under `root`, an already registered stacks root: the stack `web` at
/// `group/web`, granted a bind of `shared/data`, and a dir with a compose
/// file for each way another stack's dir can overlap them.
pub fn overlapping_dirs(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let web = root.join("group/web");
    let bind = format!(
        "app|x:1|sha256:{}|sha256:{}|bind:{}",
        "a".repeat(64),
        "b".repeat(64),
        root.join("shared/data").display()
    );
    crate::stacks::put(&crate::stacks::StackRow {
        name: "web".into(),
        dir: web.to_string_lossy().into_owned(),
        file: "compose.yaml".into(),
        enabled: true,
        allow: vec![bind.parse().unwrap()],
    })
    .unwrap();
    let dirs = [
        web.clone(),
        web.join("sub"),
        root.join("group"),
        root.join("shared/data/app"),
        root.join("shared"),
    ];
    for d in &dirs {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join("compose.yaml"), "services: {}\n").unwrap();
    }
    dirs.to_vec()
}

/// Run `body` against a fresh in-memory database, returning its result and
/// the tables it left behind.
pub fn with_db<R>(body: impl FnOnce() -> R) -> (R, Tables) {
    let tables: Rc<RefCell<Tables>> = Rc::default();
    let sink_tables = Rc::clone(&tables);
    let sink: plugin_toolkit::capsink::CapSink = Box::new(move |cap, op_json| {
        if cap != "db.op" {
            return Err(format!("unexpected capability {cap}"));
        }
        let op: DbOp = plugin_toolkit::serde_json::from_str(op_json).map_err(|e| e.to_string())?;
        let reply = apply(&mut sink_tables.borrow_mut(), op)?;
        plugin_toolkit::serde_json::to_string(&reply).map_err(|e| e.to_string())
    });
    let out = plugin_toolkit::capsink::with_cap_sink(sink, body);
    let left = tables.borrow().clone();
    (out, left)
}
