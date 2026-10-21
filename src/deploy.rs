use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::anyhow;
use plugin_toolkit::async_trait::async_trait;
use plugin_toolkit::backend_def::deploy_backend_def;
use plugin_toolkit::contract::unit::{UnitId, UpdateArgs, VerbOutcome};
use plugin_toolkit::deploy_target::{
    AdoptRequest, DeployCapability, DeployError, DeployOutcome, DeployTarget, MountKind, Runtime,
    TargetKind, TargetStatus, WorkloadSpec, dispatch_op,
};
use plugin_toolkit::serde_json::{self, Map, Value, json};

use crate::registration::unit_provider;
use crate::stacks;
use crate::unit_provider::{DockerUnitProvider, StackDeployPayload, stack_remove};

const INVOKE_PREFIX: &str = "docker.__deploy";

pub struct DockerDeployTarget {
    host: String,
    root: String,
}

impl DockerDeployTarget {
    pub fn new(host: impl Into<String>, root: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            root: root.into(),
        }
    }

    fn local() -> anyhow::Result<Self> {
        let root = crate::tools::stacks_roots()?
            .into_iter()
            .next()
            .unwrap_or_else(|| crate::tools::DEFAULT_STACKS_ROOT.to_string());
        Ok(Self::new(
            plugin_toolkit::containers::local_hostname().to_string(),
            root,
        ))
    }

    fn payload(&self, spec: &WorkloadSpec) -> Result<StackDeployPayload, DeployError> {
        Ok(StackDeployPayload {
            name: spec.name.clone(),
            dir: format!("{}/{}", self.root.trim_end_matches('/'), spec.name),
            file: None,
            compose_yaml: Some(compose_yaml(spec)?),
            compose_env: None,
            deploy: true,
        })
    }

    async fn lifecycle(&self, workload: &str, action: &str) -> Result<DeployOutcome, DeployError> {
        require(workload)?;
        let args = UpdateArgs {
            id: UnitId {
                manager: format!("docker@{}", self.host),
                kind: "stack".into(),
                id: workload.to_string(),
                name: workload.to_string(),
            },
            action: action.to_string(),
            payload: None,
            caller: None,
        };
        let out = provider().stack_update(args).await.map_err(other)?;
        Ok(outcome(workload, action, out))
    }
}

fn provider() -> DockerUnitProvider {
    unit_provider()
}

fn other(e: impl std::fmt::Display) -> DeployError {
    DeployError::Other(e.to_string())
}

fn require(workload: &str) -> Result<stacks::StackRow, DeployError> {
    stacks::get(workload)
        .map_err(other)?
        .ok_or_else(|| DeployError::NotFound(format!("no docker stack '{workload}'")))
}

fn outcome(workload: &str, state: &str, out: VerbOutcome) -> DeployOutcome {
    let detail = match out {
        VerbOutcome::Action(a) => Some(a.message),
        _ => None,
    };
    DeployOutcome {
        workload: workload.to_string(),
        id: Some(workload.to_string()),
        state: Some(state.to_string()),
        detail,
    }
}

pub fn compose_yaml(spec: &WorkloadSpec) -> Result<String, DeployError> {
    if spec.name.is_empty() {
        return Err(other("docker deploy requires spec.name"));
    }
    let image = spec
        .image
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| other("docker deploy requires spec.image"))?;
    let mut svc = Map::new();
    svc.insert("image".into(), json!(image));
    svc.insert("restart".into(), json!("unless-stopped"));
    svc.insert("cap_drop".into(), json!(["ALL"]));
    svc.insert("security_opt".into(), json!(["no-new-privileges:true"]));
    if !spec.env.is_empty() {
        let env: Map<String, Value> = spec
            .env
            .iter()
            .map(|e| (e.key.clone(), json!(e.value)))
            .collect();
        svc.insert("environment".into(), Value::Object(env));
    }
    if !spec.ports.is_empty() {
        svc.insert("ports".into(), json!(spec.ports));
    }
    if !spec.mounts.is_empty() {
        let mut volumes = Vec::new();
        for m in &spec.mounts {
            volumes.push(match m.kind {
                MountKind::Bind => {
                    if m.source.is_empty() {
                        return Err(other(format!("bind mount '{}' has no source", m.target)));
                    }
                    json!({"type": "bind", "source": m.source, "target": m.target, "read_only": m.read_only})
                }
                MountKind::Tmpfs => {
                    let mut v = json!({"type": "tmpfs", "target": m.target});
                    if let Some(size) = &m.size {
                        v["tmpfs"] = json!({"size": size});
                    }
                    v
                }
            });
        }
        svc.insert("volumes".into(), Value::Array(volumes));
    }
    let doc = json!({"services": {spec.name.clone(): Value::Object(svc)}});
    serde_json::to_string_pretty(&doc).map_err(other)
}

#[async_trait]
impl DeployTarget for DockerDeployTarget {
    fn host(&self) -> &str {
        &self.host
    }
    fn runtime(&self) -> Runtime {
        Runtime::Docker
    }
    fn kind(&self) -> TargetKind {
        TargetKind::Compose
    }
    fn capabilities(&self) -> Vec<DeployCapability> {
        vec![
            DeployCapability::Launch,
            DeployCapability::Stop,
            DeployCapability::Restart,
            DeployCapability::Provision,
            DeployCapability::Destroy,
            DeployCapability::Adopt,
            DeployCapability::Status,
        ]
    }
    fn endpoint(&self) -> String {
        format!("docker:compose@{}:{}", self.host, self.root)
    }

    async fn launch(&self, spec: &WorkloadSpec) -> Result<DeployOutcome, DeployError> {
        let raw = serde_json::to_string(&self.payload(spec)?).map_err(other)?;
        let out = provider()
            .stack_deploy(Some(raw), false)
            .await
            .map_err(other)?;
        let detail = match out {
            VerbOutcome::Item(i) => Some(i.payload),
            _ => None,
        };
        Ok(DeployOutcome {
            workload: spec.name.clone(),
            id: Some(spec.name.clone()),
            state: Some("running".into()),
            detail,
        })
    }

    async fn provision(&self, spec: &WorkloadSpec) -> Result<DeployOutcome, DeployError> {
        self.launch(spec).await
    }

    async fn stop(&self, workload: &str) -> Result<DeployOutcome, DeployError> {
        self.lifecycle(workload, "stop").await
    }

    async fn restart(&self, workload: &str) -> Result<DeployOutcome, DeployError> {
        self.lifecycle(workload, "restart").await
    }

    async fn destroy(&self, workload: &str) -> Result<DeployOutcome, DeployError> {
        let row = require(workload)?;
        let out = stack_remove(&row).await.map_err(other)?;
        Ok(outcome(workload, "destroyed", out))
    }

    async fn adopt(&self, req: &AdoptRequest) -> Result<DeployOutcome, DeployError> {
        let row = stacks::get(&req.native_id).map_err(other)?.ok_or_else(|| {
            DeployError::NotFound(format!("no docker stack '{}' to adopt", req.native_id))
        })?;
        Ok(DeployOutcome {
            workload: req.name.clone().unwrap_or_else(|| row.name.clone()),
            id: Some(row.name.clone()),
            state: Some("adopted".into()),
            detail: Some(format!("stack '{}' at {}", row.name, row.dir)),
        })
    }

    async fn status(&self, workload: &str) -> Result<TargetStatus, DeployError> {
        let Some(row) = stacks::get(workload).map_err(other)? else {
            return Ok(TargetStatus {
                workload: workload.to_string(),
                id: None,
                exists: false,
                state: "absent".into(),
                detail: None,
            });
        };
        let services = DockerUnitProvider::stack_services(&row).await;
        let state = if services.is_empty() {
            "stopped"
        } else if services.iter().all(|s| s.running) {
            "running"
        } else if services.iter().any(|s| s.running) {
            "degraded"
        } else {
            "stopped"
        };
        Ok(TargetStatus {
            workload: workload.to_string(),
            id: Some(row.name.clone()),
            exists: true,
            state: state.into(),
            detail: Some(format!("{} service(s) at {}", services.len(), row.dir)),
        })
    }
}

pub fn backend_defs() -> Vec<BackendDef> {
    match DockerDeployTarget::local() {
        Ok(t) => vec![deploy_backend_def(&t, INVOKE_PREFIX)],
        Err(e) => {
            plugin_toolkit::tracing::warn!(error = %e, "docker deploy: target unavailable; none advertised");
            Vec::new()
        }
    }
}

pub fn dispatch(name: &str, args: Value) -> Option<Result<Value, Value>> {
    let op = name
        .strip_prefix(INVOKE_PREFIX)
        .and_then(|s| s.strip_prefix('.'))?;
    let target = match DockerDeployTarget::local() {
        Ok(t) => t,
        Err(e) => return Some(Err(Value::String(e.to_string()))),
    };
    Some(plugin_toolkit::reactor::block_on(dispatch_op(
        &target, op, args,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::deploy_target::{EnvVar, Mount};

    fn spec() -> WorkloadSpec {
        WorkloadSpec {
            name: "web".into(),
            image: Some("nginx:1".into()),
            env: vec![EnvVar {
                key: "A".into(),
                value: "1".into(),
            }],
            mounts: vec![
                Mount {
                    kind: MountKind::Bind,
                    source: "/opt/stacks/web/data".into(),
                    target: "/data".into(),
                    read_only: true,
                    size: None,
                },
                Mount {
                    kind: MountKind::Tmpfs,
                    source: String::new(),
                    target: "/run".into(),
                    read_only: false,
                    size: Some("64m".into()),
                },
            ],
            ports: vec!["8080:80".into()],
        }
    }

    fn service(spec: &WorkloadSpec) -> Value {
        let doc: Value = serde_json::from_str(&compose_yaml(spec).unwrap()).unwrap();
        doc["services"][&spec.name].clone()
    }

    #[test]
    fn maps_spec_to_least_privilege_service() {
        let svc = service(&spec());
        assert_eq!(svc["image"], "nginx:1");
        assert_eq!(svc["cap_drop"], json!(["ALL"]));
        assert_eq!(svc["security_opt"], json!(["no-new-privileges:true"]));
        assert_eq!(svc["environment"], json!({"A": "1"}));
        assert_eq!(svc["ports"], json!(["8080:80"]));
        assert_eq!(
            svc["volumes"],
            json!([
                {"type": "bind", "source": "/opt/stacks/web/data", "target": "/data", "read_only": true},
                {"type": "tmpfs", "target": "/run", "tmpfs": {"size": "64m"}}
            ])
        );
    }

    #[test]
    fn omits_empty_sections() {
        let svc = service(&WorkloadSpec {
            name: "web".into(),
            image: Some("nginx:1".into()),
            ..Default::default()
        });
        for key in ["environment", "ports", "volumes"] {
            assert!(svc.get(key).is_none(), "{key} present");
        }
    }

    #[test]
    fn rejects_missing_image_and_sourceless_bind() {
        let mut s = spec();
        s.image = None;
        assert!(compose_yaml(&s).is_err());
        let mut s = spec();
        s.mounts[0].source.clear();
        assert!(compose_yaml(&s).is_err());
    }

    #[test]
    fn payload_places_stack_under_root() {
        let t = DockerDeployTarget::new("host-a", "/opt/stacks/");
        let p = t.payload(&spec()).unwrap();
        assert_eq!(p.dir, "/opt/stacks/web");
        assert!(p.deploy);
        assert!(p.compose_yaml.is_some());
    }

    #[test]
    fn backend_def_shape() {
        let t = DockerDeployTarget::new("host-a", "/opt/stacks");
        let def = deploy_backend_def(&t, INVOKE_PREFIX);
        assert_eq!(def.domain, "deploy_target");
        assert_eq!(def.name, "host-a");
        assert_eq!(def.runtime, "docker");
        assert_eq!(def.kind, "compose");
        assert_eq!(def.endpoint, "docker:compose@host-a:/opt/stacks");
        assert_eq!(def.invoke_prefix, "docker.__deploy");
        for cap in ["launch", "stop", "restart", "destroy", "adopt", "status"] {
            assert!(def.capabilities.iter().any(|c| c == cap), "{cap}");
        }
    }

    #[test]
    fn dispatch_ignores_foreign_prefix() {
        assert!(dispatch("proxmox.__deploy.x.launch", json!({})).is_none());
    }
}
