//! Docker [`UnitProvider`] — exposes containers as units on the five-verb surface.
//!
//! Each running/stopped Docker container is a `container` kind unit. Verbs map:
//! - [`Verb::List`]   → list containers (with optional search filter)
//! - [`Verb::Detail`] → inspect one container; `query.kind = "logs"` → tail logs
//! - [`Verb::Update`] → action `start` / `stop` / `restart`
//! - [`Verb::Create`] → action `exec` (creates a new process in the container)
//! - [`Verb::Delete`] → not supported (containers are managed by Compose / CLI)

use plugin_toolkit::anyhow::{self, Result};
use plugin_toolkit::containers::{
    AdapterError, Container, ListFilter, LogTail, RuntimeAdapter,
};
use plugin_toolkit::contract::unit::{
    ActionDecl, ActionOutcome, CreateArgs, DeleteArgs, DetailArgs, ItemOutcome, ItemsOutcome,
    KindDeclaration, ListArgs, UnitDescriptor, UnitId, UpdateArgs, VerbArgs, VerbDecl,
    VerbOutcome, Verb, UnitProvider,
};
use plugin_toolkit::contract::BoxFuture;
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
        Self { adapter, hostname: hostname.to_string() }
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

    async fn do_list(&self, args: ListArgs) -> Result<VerbOutcome> {
        // ListFilter has no name field; search is applied client-side by orca.
        let filter = ListFilter { all: true, labels: vec![] };
        let containers = self
            .adapter
            .list(&filter)
            .await
            .map_err(adapter_err)?;
        let items = containers
            .into_iter()
            .map(|c| ItemOutcome {
                id: self.unit_id(&c),
                payload: Self::container_payload(&c),
            })
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
            return Ok(VerbOutcome::Item(ItemOutcome {
                id: args.id,
                payload: serde_json::to_string(&logs).unwrap_or_default(),
            }));
        }
        let c = self.adapter.inspect(id).await.map_err(adapter_err)?;
        Ok(VerbOutcome::Item(ItemOutcome {
            id: self.unit_id(&c),
            payload: Self::container_payload(&c),
        }))
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
                let payload = args.payload.unwrap_or_default();
                let exec = ExecPayload::from_json(&payload)?;
                let result = self
                    .adapter
                    .exec(&exec.id, &exec.cmd, exec.stdin)
                    .await
                    .map_err(adapter_err)?;
                Ok(VerbOutcome::Item(ItemOutcome {
                    id: UnitId {
                        manager: format!("docker@{}", self.hostname),
                        kind: "exec".into(),
                        id: exec.id.clone(),
                        name: format!("exec:{}", exec.id),
                    },
                    payload: serde_json::to_string(&result).unwrap_or_default(),
                }))
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

/// Payload for `Create { action: "exec" }`.
struct ExecPayload {
    id: String,
    cmd: Vec<String>,
    stdin: Option<String>,
}

impl ExecPayload {
    fn from_json(s: &str) -> Result<Self, anyhow::Error> {
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|e| anyhow::anyhow!("exec payload: {e}"))?;
        Ok(Self {
            id: v["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("exec payload missing 'id'"))?
                .to_string(),
            cmd: v["cmd"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("exec payload missing 'cmd'"))?
                .iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect(),
            stdin: v["stdin"].as_str().map(str::to_string),
        })
    }
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
                        payload_schema: None,
                        response_schema: None,
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
