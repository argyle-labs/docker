//! Docker [`UnitProvider`] — exposes two kinds on the five-verb surface:
//! Docker `container`s and managed Compose `stack`s.
//!
//! **`container` kind** — each running/stopped Docker container. Verbs map:
//! - [`Verb::List`]   → list containers (with optional search filter)
//! - [`Verb::Detail`] → inspect one container; `query.kind = "logs"` → tail logs
//! - [`Verb::Update`] → action `start` / `stop` / `restart`
//! - [`Verb::Create`] → action `exec` (creates a new process in the container)
//! - [`Verb::Delete`] → not supported (containers are managed by Compose / CLI)
//!
//! **`stack` kind** — a managed `docker compose` project (see [`crate::stacks`]).
//! This is orca's config-manager surface for compose: view / edit / deploy a
//! compose file of your own over cli / api / mcp. Verbs map (mirrors the dockge
//! plugin's `stack` kind so orca sees one unified stack surface):
//! - [`Verb::List`]   → registered stacks + per-service status
//! - [`Verb::Detail`] → **view**: compose YAML + `.env` + status; `query.kind =
//!   "logs"` → tail logs
//! - [`Verb::Update`] → **edit** (action `edit`, rewrite YAML/env, no deploy) or
//!   lifecycle (`up` / `down` / `start` / `stop` / `restart` / `build` / `pull`)
//! - [`Verb::Create`] → action `deploy`: register + write + `up` (add-only)
//! - [`Verb::Upsert`] → action `set`: register-or-replace, then deploy
//! - [`Verb::Delete`] → deregister the stack (leaves containers running)

use plugin_toolkit::anyhow::{self, Result};
use plugin_toolkit::containers::{AdapterError, Container, ListFilter, LogTail, RuntimeAdapter};
use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::unit::{
    ActionDecl, ActionOutcome, CreateArgs, DeleteArgs, DetailArgs, ItemOutcome, ItemsOutcome,
    KindDeclaration, ListArgs, UnitDescriptor, UnitId, UnitProvider, UpdateArgs, UpsertArgs, Verb,
    VerbArgs, VerbDecl, VerbOutcome,
};
use plugin_toolkit::schemars::{JsonSchema, schema_for};
use plugin_toolkit::serde::{Deserialize, Serialize};
use plugin_toolkit::serde_json;

use crate::runtime_adapter::DockerAdapter;
use crate::stacks::{self, StackRow};

const KIND: &str = "container";
const STACK_KIND: &str = "stack";

/// Compose lifecycle actions accepted on a `stack`'s [`Verb::Update`]. `edit` is
/// handled separately (it carries a payload); these are argument-free actions
/// forwarded to `docker compose <action>`.
const STACK_LIFECYCLE: &[&str] = &["up", "down", "start", "stop", "restart", "build", "pull"];

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

    fn stack_unit_id(&self, row: &StackRow) -> UnitId {
        UnitId {
            manager: format!("docker@{}", self.hostname),
            kind: STACK_KIND.into(),
            id: row.name.clone(),
            name: row.name.clone(),
        }
    }

    /// Per-service runtime status for a stack. Absent/unparseable compose file
    /// yields an empty list rather than an error, so a registered-but-not-yet-
    /// written stack still lists.
    async fn stack_services(row: &StackRow) -> Vec<StackService> {
        let Ok(compose) = row.compose() else {
            return Vec::new();
        };
        compose
            .services()
            .await
            .map(|svcs| svcs.into_iter().map(StackService::from).collect())
            .unwrap_or_default()
    }

    async fn do_list(&self, args: ListArgs) -> Result<VerbOutcome> {
        let want = args.query.kind.as_deref();
        let mut items = Vec::new();

        if want.is_none() || want == Some(KIND) {
            // ListFilter has no name field; search is applied client-side by orca.
            let filter = ListFilter {
                all: true,
                labels: vec![],
            };
            let containers = self.adapter.list(&filter).await.map_err(adapter_err)?;
            items.extend(
                containers
                    .into_iter()
                    .map(|c| ItemOutcome::new(self.unit_id(&c), Self::container_payload(&c))),
            );
        }

        if want.is_none() || want == Some(STACK_KIND) {
            for row in stacks::list()? {
                let services = Self::stack_services(&row).await;
                let summary = StackSummary {
                    name: row.name.clone(),
                    dir: row.dir.clone(),
                    file: row.file.clone(),
                    enabled: row.enabled,
                    services,
                };
                items.push(ItemOutcome::new(
                    self.stack_unit_id(&row),
                    serde_json::to_string(&summary).unwrap_or_default(),
                ));
            }
        }

        let total = items.len() as u64;
        Ok(VerbOutcome::Items(ItemsOutcome {
            items,
            total: Some(total),
        }))
    }

    // ── stack kind ────────────────────────────────────────────────────────────

    /// **view** — compose YAML + `.env` + per-service status. `query.kind =
    /// "logs"` tails the project's compose logs instead.
    async fn stack_detail(&self, args: DetailArgs) -> Result<VerbOutcome> {
        let row = stacks::require(&args.id.id)?;
        if args.query.kind.as_deref() == Some("logs") {
            let tail = args.query.limit.unwrap_or(200);
            let logs = row
                .compose()
                .map_err(anyhow::Error::from)?
                .logs(&[], tail)
                .await
                .map_err(anyhow::Error::from)?;
            return Ok(VerbOutcome::Item(ItemOutcome::new(
                args.id,
                serde_json::to_string(&StackLogs { logs }).unwrap_or_default(),
            )));
        }
        let detail = StackDetail {
            compose_yaml: row.read_compose().unwrap_or_default(),
            compose_env: row.read_env(),
            services: Self::stack_services(&row).await,
            name: row.name.clone(),
            dir: row.dir.clone(),
            file: row.file.clone(),
            enabled: row.enabled,
        };
        Ok(VerbOutcome::Item(ItemOutcome::new(
            self.stack_unit_id(&row),
            serde_json::to_string(&detail).unwrap_or_default(),
        )))
    }

    /// **edit** (rewrite YAML/env, no deploy) or a compose lifecycle action.
    async fn stack_update(&self, args: UpdateArgs) -> Result<VerbOutcome> {
        let row = stacks::require(&args.id.id)?;
        match args.action.as_str() {
            "edit" => {
                let raw = args
                    .payload
                    .ok_or_else(|| anyhow::anyhow!("stack edit requires a payload"))?;
                let p: StackEditPayload =
                    serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("edit payload: {e}"))?;
                if p.compose_yaml.is_none() && p.compose_env.is_none() {
                    return Err(anyhow::anyhow!(
                        "edit payload must set compose_yaml and/or compose_env"
                    ));
                }
                if let Some(yaml) = &p.compose_yaml {
                    row.write_compose(yaml)?;
                }
                if let Some(env) = &p.compose_env {
                    row.write_env(env)?;
                }
                Ok(VerbOutcome::Action(ActionOutcome {
                    changed: true,
                    message: format!("edited stack '{}'", row.name),
                }))
            }
            action if STACK_LIFECYCLE.contains(&action) => {
                let out = row
                    .compose()
                    .map_err(anyhow::Error::from)?
                    .run_action(action, None, None)
                    .await
                    .map_err(anyhow::Error::from)?;
                Ok(VerbOutcome::Action(ActionOutcome {
                    changed: true,
                    message: format!("stack '{}' {action}: {}", row.name, out.trim()),
                }))
            }
            other => Err(anyhow::anyhow!("unknown stack update action: {other}")),
        }
    }

    /// Shared create/upsert path: register the stack, (optionally) write its
    /// compose/env files, then deploy. `add_only` rejects an existing name.
    async fn stack_deploy(&self, payload: Option<String>, add_only: bool) -> Result<VerbOutcome> {
        let raw = payload.ok_or_else(|| anyhow::anyhow!("deploy requires a payload"))?;
        let p: StackDeployPayload =
            serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("deploy payload: {e}"))?;
        let existed = stacks::exists(&p.name)?;
        if add_only && existed {
            return Err(anyhow::anyhow!(
                "stack '{}' already exists; use upsert (action=set) to redeploy",
                p.name
            ));
        }
        let row = StackRow {
            name: p.name.clone(),
            dir: p.dir.clone(),
            file: p
                .file
                .clone()
                .unwrap_or_else(|| stacks::DEFAULT_COMPOSE_FILE.to_string()),
            enabled: true,
        };
        if let Some(yaml) = &p.compose_yaml {
            row.write_compose(yaml)?;
        }
        if let Some(env) = &p.compose_env {
            row.write_env(env)?;
        }
        stacks::put(&row)?;
        if p.deploy {
            row.compose()
                .map_err(anyhow::Error::from)?
                .up(&[])
                .await
                .map_err(anyhow::Error::from)?;
        }
        Ok(VerbOutcome::Item(ItemOutcome::new(
            self.stack_unit_id(&row),
            serde_json::to_string(&StackDeployResult {
                name: row.name.clone(),
                created: !existed,
                deployed: p.deploy,
            })
            .unwrap_or_default(),
        )))
    }

    async fn do_detail(&self, args: DetailArgs) -> Result<VerbOutcome> {
        if args.id.kind == STACK_KIND {
            return self.stack_detail(args).await;
        }
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
        if args.id.kind == STACK_KIND {
            return self.stack_update(args).await;
        }
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
            "deploy" => self.stack_deploy(args.payload, true).await,
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

    fn do_delete(&self, args: DeleteArgs) -> Result<VerbOutcome> {
        if args.id.kind == STACK_KIND {
            if !stacks::remove(&args.id.id)? {
                return Err(anyhow::anyhow!("no managed stack named '{}'", args.id.id));
            }
            return Ok(VerbOutcome::Action(ActionOutcome {
                changed: true,
                message: format!(
                    "deregistered stack '{}' (containers left running; run action=down first to tear down)",
                    args.id.id
                ),
            }));
        }
        Err(anyhow::anyhow!(
            "container delete is managed by Compose/CLI; use the docker.delete tool"
        ))
    }

    async fn do_upsert(&self, args: UpsertArgs) -> Result<VerbOutcome> {
        if args.id.kind == STACK_KIND {
            return match args.action.as_str() {
                "set" => self.stack_deploy(args.payload, false).await,
                other => Err(anyhow::anyhow!("unknown stack upsert action: {other}")),
            };
        }
        Err(anyhow::anyhow!(
            "containers are not provisioned by the docker plugin (Compose/dockge owns creation); upsert is unsupported for the container kind"
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

// ── stack payloads & views ────────────────────────────────────────────────────

/// One service's declaration + runtime status within a stack.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackService {
    pub name: String,
    pub state: String,
    pub running: bool,
    pub health: String,
    pub ports: Vec<String>,
}

impl From<crate::ServiceSummary> for StackService {
    fn from(s: crate::ServiceSummary) -> Self {
        StackService {
            name: s.name,
            state: s.state,
            running: s.running,
            health: s.health,
            ports: s.ports,
        }
    }
}

/// `List` row for a `stack` unit — registry entry + per-service status.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackSummary {
    pub name: String,
    pub dir: String,
    pub file: String,
    pub enabled: bool,
    pub services: Vec<StackService>,
}

/// `Detail` (view) payload — the compose file contents plus status.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackDetail {
    pub name: String,
    pub dir: String,
    pub file: String,
    pub enabled: bool,
    /// Full compose file contents (empty if the file isn't on disk yet).
    pub compose_yaml: String,
    /// `.env` contents when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compose_env: Option<String>,
    pub services: Vec<StackService>,
}

/// `Detail` payload when `query.kind = "logs"`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackLogs {
    pub logs: String,
}

/// Payload for `Update{action:"edit"}` — rewrite the compose file and/or `.env`
/// without deploying. At least one field must be set.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackEditPayload {
    /// New compose file contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_yaml: Option<String>,
    /// New `.env` contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_env: Option<String>,
}

/// Payload for `Create{action:"deploy"}` and `Upsert{action:"set"}` — register
/// a stack, optionally (re)write its files, then deploy.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackDeployPayload {
    /// Unique stack name.
    pub name: String,
    /// Project directory on the host holding the compose file.
    pub dir: String,
    /// Compose filename within `dir` (default `docker-compose.yml`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Compose file contents to write. Omit to register/redeploy an existing
    /// on-disk file unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_yaml: Option<String>,
    /// Optional `.env` contents to write alongside.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_env: Option<String>,
    /// Run `docker compose up -d` after writing (default `true`).
    #[serde(default = "default_deploy")]
    pub deploy: bool,
}

fn default_deploy() -> bool {
    true
}

/// Response for a deploy/upsert.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackDeployResult {
    pub name: String,
    /// Whether the stack was newly registered (vs. replacing an existing one).
    pub created: bool,
    /// Whether `docker compose up -d` was run.
    pub deployed: bool,
}

/// The `stack` [`KindDeclaration`]: view (Detail), edit + lifecycle (Update),
/// deploy (Create), set (Upsert), deregister (Delete).
fn stack_declaration() -> KindDeclaration {
    let mut update_actions = vec![ActionDecl {
        action: "edit".into(),
        payload_schema: Some(schema_for!(StackEditPayload)),
        response_schema: None,
    }];
    update_actions.extend(STACK_LIFECYCLE.iter().map(|a| ActionDecl {
        action: (*a).into(),
        payload_schema: None,
        response_schema: None,
    }));

    KindDeclaration {
        kind: STACK_KIND.into(),
        verbs: vec![
            VerbDecl::list(),
            VerbDecl::detail(),
            VerbDecl {
                verb: Verb::Update,
                query_schema: None,
                actions: update_actions,
            },
            VerbDecl {
                verb: Verb::Create,
                query_schema: None,
                actions: vec![ActionDecl {
                    action: "deploy".into(),
                    payload_schema: Some(schema_for!(StackDeployPayload)),
                    response_schema: Some(schema_for!(StackDeployResult)),
                }],
            },
            VerbDecl {
                verb: Verb::Upsert,
                query_schema: None,
                actions: vec![ActionDecl {
                    action: "set".into(),
                    payload_schema: Some(schema_for!(StackDeployPayload)),
                    response_schema: Some(schema_for!(StackDeployResult)),
                }],
            },
            VerbDecl {
                verb: Verb::Delete,
                query_schema: None,
                actions: vec![],
            },
        ],
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
        vec![
            KindDeclaration {
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
            },
            stack_declaration(),
        ]
    }

    fn units(&self) -> BoxFuture<'_, Result<Vec<UnitDescriptor>>> {
        Box::pin(async move {
            let containers = self
                .adapter
                .list(&ListFilter::default())
                .await
                .map_err(adapter_err)?;
            let mut units: Vec<UnitDescriptor> = containers
                .into_iter()
                .map(|c| UnitDescriptor {
                    id: self.unit_id(&c),
                    verbs: vec![Verb::List, Verb::Detail, Verb::Update, Verb::Create],
                    parent: None,
                })
                .collect();
            for row in stacks::list()? {
                units.push(UnitDescriptor {
                    id: self.stack_unit_id(&row),
                    verbs: vec![
                        Verb::List,
                        Verb::Detail,
                        Verb::Update,
                        Verb::Create,
                        Verb::Upsert,
                        Verb::Delete,
                    ],
                    parent: None,
                });
            }
            Ok(units)
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
                VerbArgs::Upsert(a) => self.do_upsert(a).await,
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

    // ── stack kind ────────────────────────────────────────────────────────────

    #[test]
    fn deploy_payload_defaults_deploy_true_and_no_file() {
        let p: StackDeployPayload =
            serde_json::from_str(r#"{"name":"web","dir":"/srv/web"}"#).unwrap();
        assert_eq!(p.name, "web");
        assert!(p.deploy, "deploy defaults to true");
        assert!(p.file.is_none());
        assert!(p.compose_yaml.is_none(), "yaml omitted = import existing");
    }

    #[test]
    fn deploy_payload_respects_explicit_deploy_false() {
        let p: StackDeployPayload = serde_json::from_str(
            r#"{"name":"web","dir":"/srv/web","compose_yaml":"services: {}","deploy":false}"#,
        )
        .unwrap();
        assert!(!p.deploy);
        assert_eq!(p.compose_yaml.as_deref(), Some("services: {}"));
    }

    #[test]
    fn edit_payload_allows_partial_fields() {
        let p: StackEditPayload =
            serde_json::from_str(r#"{"compose_yaml":"services: {}"}"#).unwrap();
        assert!(p.compose_yaml.is_some());
        assert!(p.compose_env.is_none());
    }

    #[test]
    fn stack_declaration_advertises_typed_actions() {
        let d = stack_declaration();
        assert_eq!(d.kind, STACK_KIND);

        let update = d.verbs.iter().find(|v| v.verb == Verb::Update).unwrap();
        let edit = update.actions.iter().find(|a| a.action == "edit").unwrap();
        assert!(edit.payload_schema.is_some(), "edit must declare a payload");
        for lifecycle in STACK_LIFECYCLE {
            assert!(
                update.actions.iter().any(|a| &a.action == lifecycle),
                "missing lifecycle action {lifecycle}"
            );
        }

        let create = d.verbs.iter().find(|v| v.verb == Verb::Create).unwrap();
        let deploy = create
            .actions
            .iter()
            .find(|a| a.action == "deploy")
            .unwrap();
        assert!(deploy.payload_schema.is_some());
        assert!(deploy.response_schema.is_some());

        let upsert = d.verbs.iter().find(|v| v.verb == Verb::Upsert).unwrap();
        assert!(upsert.actions.iter().any(|a| a.action == "set"));

        assert!(d.verbs.iter().any(|v| v.verb == Verb::Delete));
    }

    #[test]
    fn declarations_expose_both_container_and_stack_kinds() {
        let provider = DockerUnitProvider {
            adapter: {
                static A: std::sync::OnceLock<DockerAdapter> = std::sync::OnceLock::new();
                A.get_or_init(DockerAdapter::new)
            },
            hostname: "test".into(),
        };
        let kinds: Vec<_> = provider
            .declarations()
            .into_iter()
            .map(|d| d.kind)
            .collect();
        assert!(kinds.iter().any(|k| k == "container"));
        assert!(kinds.iter().any(|k| k == STACK_KIND));
    }
}
