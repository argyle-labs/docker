//! Docker [`UnitProvider`] — exposes containers as units on the five-verb surface.
//!
//! Each running/stopped Docker container is a `container` kind unit. Verbs map:
//! - [`Verb::List`]   → list containers (with optional search filter)
//! - [`Verb::Detail`] → inspect one container; `query.kind = "logs"` → tail logs
//! - [`Verb::Update`] → action `start` / `stop` / `restart`
//! - [`Verb::Create`] → action `exec` (creates a new process in the container)
//! - [`Verb::Delete`] → not supported (containers are managed by Compose / CLI)

use plugin_toolkit::anyhow::{self, Result};
use plugin_toolkit::containers::{AdapterError, Container, ListFilter, LogTail, RuntimeAdapter};
use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::unit::{
    ActionDecl, ActionOutcome, CreateArgs, DeleteArgs, DetailArgs, ItemOutcome, ItemsOutcome,
    KindDeclaration, ListArgs, UnitDescriptor, UnitId, UnitProvider, UpdateArgs, Verb, VerbArgs,
    VerbDecl, VerbOutcome,
};
use plugin_toolkit::schemars::{JsonSchema, schema_for};
use plugin_toolkit::serde::{Deserialize, Serialize};
use plugin_toolkit::serde_json;

use crate::runtime_adapter::DockerAdapter;

const KIND: &str = "container";

pub struct DockerUnitProvider {
    adapter: &'static DockerAdapter,
    hostname: String,
}

impl DockerUnitProvider {
    pub fn new(adapter: &'static DockerAdapter) -> Self {
        let hostname = plugin_toolkit::containers::local_hostname();
        Self {
            adapter,
            hostname: hostname.to_string(),
        }
    }

    fn unit_id(&self, c: &Container) -> UnitId {
        UnitId {
            manager: format!("docker@{}", self.hostname),
            kind: KIND.into(),
            id: c.id.clone(),
            name: c.name.clone(),
        }
    }

    fn container_payload(c: &Container) -> String {
        serde_json::to_string(c).unwrap_or_default()
    }

    async fn do_list(&self, _args: ListArgs) -> Result<VerbOutcome> {
        // ListFilter has no name field; search is applied client-side by orca.
        let filter = ListFilter {
            all: true,
            labels: vec![],
        };
        let containers = self.adapter.list(&filter).await.map_err(adapter_err)?;
        let items = containers
            .into_iter()
            .map(|c| ItemOutcome::new(self.unit_id(&c), Self::container_payload(&c)))
            .collect::<Vec<_>>();
        let total = items.len() as u64;
        Ok(VerbOutcome::Items(ItemsOutcome {
            items,
            total: Some(total),
        }))
    }

    async fn do_detail(&self, args: DetailArgs) -> Result<VerbOutcome> {
        let id = &args.id.id;
        if args.query.kind.as_deref() == Some("logs") {
            let tail = args.query.limit.unwrap_or(100);
            let logs = self
                .adapter
                .logs(id, LogTail(tail))
                .await
                .map_err(adapter_err)?;
            return Ok(VerbOutcome::Item(ItemOutcome::new(
                args.id,
                serde_json::to_string(&logs).unwrap_or_default(),
            )));
        }
        let c = self.adapter.inspect(id).await.map_err(adapter_err)?;
        Ok(VerbOutcome::Item(ItemOutcome::new(
            self.unit_id(&c),
            Self::container_payload(&c),
        )))
    }

    async fn do_update(&self, args: UpdateArgs) -> Result<VerbOutcome> {
        let id = &args.id.id;
        match args.action.as_str() {
            "start" => {
                self.adapter.start(id).await.map_err(adapter_err)?;
                Ok(VerbOutcome::Action(ActionOutcome {
                    changed: true,
                    message: format!("started {id}"),
                }))
            }
            "stop" => {
                self.adapter.stop(id).await.map_err(adapter_err)?;
                Ok(VerbOutcome::Action(ActionOutcome {
                    changed: true,
                    message: format!("stopped {id}"),
                }))
            }
            "restart" => {
                self.adapter.restart(id).await.map_err(adapter_err)?;
                Ok(VerbOutcome::Action(ActionOutcome {
                    changed: true,
                    message: format!("restarted {id}"),
                }))
            }
            other => Err(anyhow::anyhow!("unknown container update action: {other}")),
        }
    }

    async fn do_create(&self, args: CreateArgs) -> Result<VerbOutcome> {
        match args.action.as_str() {
            "exec" => {
                let raw = args.payload.unwrap_or_default();
                let exec: ExecPayload =
                    serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("exec payload: {e}"))?;
                let result = self
                    .adapter
                    .exec(&exec.id, &exec.cmd, exec.stdin)
                    .await
                    .map_err(adapter_err)?;
                Ok(VerbOutcome::Item(ItemOutcome::new(
                    UnitId {
                        manager: format!("docker@{}", self.hostname),
                        kind: "exec".into(),
                        id: exec.id.clone(),
                        name: format!("exec:{}", exec.id),
                    },
                    serde_json::to_string(&result).unwrap_or_default(),
                )))
            }
            other => Err(anyhow::anyhow!("unknown container create action: {other}")),
        }
    }

    fn do_delete(&self, _args: DeleteArgs) -> Result<VerbOutcome> {
        Err(anyhow::anyhow!(
            "container delete is managed by Compose/CLI; use the docker.delete tool"
        ))
    }
}

/// Typed payload for `Create { action: "exec" }`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct ExecPayload {
    /// Container name or ID.
    pub id: String,
    /// Command and arguments to run inside the container.
    pub cmd: Vec<String>,
    /// Optional stdin to pipe into the process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
}

/// Typed response for `Create { action: "exec" }`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct ExecResponse {
    pub exit_code: i64,
    pub stdout: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

fn adapter_err(e: AdapterError) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

impl UnitProvider for DockerUnitProvider {
    fn name(&self) -> &str {
        "docker"
    }

    fn declarations(&self) -> Vec<KindDeclaration> {
        vec![KindDeclaration {
            kind: KIND.into(),
            verbs: vec![
                VerbDecl::list(),
                VerbDecl::detail(),
                VerbDecl {
                    verb: Verb::Update,
                    query_schema: None,
                    actions: vec![
                        ActionDecl {
                            action: "start".into(),
                            payload_schema: None,
                            response_schema: None,
                        },
                        ActionDecl {
                            action: "stop".into(),
                            payload_schema: None,
                            response_schema: None,
                        },
                        ActionDecl {
                            action: "restart".into(),
                            payload_schema: None,
                            response_schema: None,
                        },
                    ],
                },
                VerbDecl {
                    verb: Verb::Create,
                    query_schema: None,
                    actions: vec![ActionDecl {
                        action: "exec".into(),
                        payload_schema: Some(schema_for!(ExecPayload)),
                        response_schema: Some(schema_for!(ExecResponse)),
                    }],
                },
            ],
        }]
    }

    fn units(&self) -> BoxFuture<'_, Result<Vec<UnitDescriptor>>> {
        Box::pin(async move {
            let containers = self
                .adapter
                .list(&ListFilter::default())
                .await
                .map_err(adapter_err)?;
            Ok(containers
                .into_iter()
                .map(|c| UnitDescriptor {
                    id: self.unit_id(&c),
                    verbs: vec![Verb::List, Verb::Detail, Verb::Update, Verb::Create],
                    parent: None,
                })
                .collect())
        })
    }

    fn invoke(&self, args: VerbArgs) -> BoxFuture<'_, Result<VerbOutcome>> {
        Box::pin(async move {
            match args {
                VerbArgs::List(a) => self.do_list(a).await,
                VerbArgs::Detail(a) => self.do_detail(a).await,
                VerbArgs::Update(a) => self.do_update(a).await,
                VerbArgs::Create(a) => self.do_create(a).await,
                VerbArgs::Delete(a) => self.do_delete(a),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Result<ExecPayload, anyhow::Error> {
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("exec payload: {e}"))
    }

    #[test]
    fn exec_payload_happy_path() {
        let p = parse(r#"{"id":"web","cmd":["ls","-la"],"stdin":"hello"}"#).unwrap();
        assert_eq!(p.id, "web");
        assert_eq!(p.cmd, vec!["ls", "-la"]);
        assert_eq!(p.stdin.as_deref(), Some("hello"));
    }

    #[test]
    fn exec_payload_stdin_optional() {
        let p = parse(r#"{"id":"db","cmd":["psql","-c","\\l"]}"#).unwrap();
        assert_eq!(p.id, "db");
        assert_eq!(p.cmd, vec!["psql", "-c", "\\l"]);
        assert!(p.stdin.is_none());
    }

    #[test]
    fn exec_payload_missing_id() {
        let err = parse(r#"{"cmd":["ls"]}"#).unwrap_err();
        assert!(
            err.to_string().contains("id"),
            "expected id error, got: {err}"
        );
    }

    #[test]
    fn exec_payload_missing_cmd() {
        let err = parse(r#"{"id":"web"}"#).unwrap_err();
        assert!(
            err.to_string().contains("cmd"),
            "expected cmd error, got: {err}"
        );
    }

    #[test]
    fn exec_payload_bad_json() {
        let err = parse("not json at all").unwrap_err();
        assert!(err.to_string().contains("exec payload"), "got: {err}");
    }

    #[test]
    fn exec_payload_cmd_wrong_type() {
        let err = parse(r#"{"id":"web","cmd":"ls"}"#).unwrap_err();
        assert!(
            err.to_string().contains("sequence") || err.to_string().contains("cmd"),
            "expected sequence/cmd type error, got: {err}"
        );
    }

    #[test]
    fn declarations_exec_action_has_typed_schemas() {
        let provider = DockerUnitProvider {
            adapter: {
                static A: std::sync::OnceLock<DockerAdapter> = std::sync::OnceLock::new();
                A.get_or_init(DockerAdapter::new)
            },
            hostname: "test".into(),
        };
        let decls = provider.declarations();
        let container = decls.iter().find(|d| d.kind == "container").unwrap();
        let create_decl = container
            .verbs
            .iter()
            .find(|v| v.verb == Verb::Create)
            .unwrap();
        let exec = create_decl
            .actions
            .iter()
            .find(|a| a.action == "exec")
            .unwrap();
        assert!(
            exec.payload_schema.is_some(),
            "exec must declare payload schema"
        );
        assert!(
            exec.response_schema.is_some(),
            "exec must declare response schema"
        );
        let schema_json = serde_json::to_string(exec.payload_schema.as_ref().unwrap()).unwrap();
        assert!(
            schema_json.contains("cmd"),
            "schema must reference cmd field"
        );
        assert!(schema_json.contains("id"), "schema must reference id field");
    }
}
