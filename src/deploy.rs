use std::path::{Component, Path, PathBuf};

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

const DENIED: &[&str] = &[
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/run",
    "/var/run",
    "/var/lib/docker",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/opt",
    "/var/spool",
    "/var/lib/containerd",
    "/var/lib/containers",
    "/var/lib/lxc",
    "/var/lib/libvirt",
    "/var/lib/orca",
];

const DENIED_SEGMENTS: &[&[&str]] = &[
    &[".ssh"],
    &[".gnupg"],
    &[".orca"],
    &["Library", "Keychains"],
];

pub struct DockerDeployTarget {
    host: String,
    root: String,
    data_roots: Vec<String>,
}

impl DockerDeployTarget {
    pub fn new(host: impl Into<String>, root: impl Into<String>) -> Self {
        let root = root.into();
        Self {
            host: host.into(),
            data_roots: vec![root.clone()],
            root,
        }
    }

    pub fn with_data_roots(mut self, roots: Vec<String>) -> Self {
        if !roots.is_empty() {
            self.data_roots = roots;
        }
        self
    }

    fn local() -> anyhow::Result<Self> {
        let root = pick_root(&crate::tools::stacks_roots()?)?;
        let mut roots = Vec::new();
        for rt in crate::tools::runtimes()? {
            let rt_root = rt
                .stacks_root
                .as_deref()
                .unwrap_or(crate::tools::DEFAULT_STACKS_ROOT);
            if rt_root == root {
                for r in rt.data_roots {
                    if !roots.contains(&r) {
                        roots.push(r);
                    }
                }
            }
        }
        Ok(Self::new(
            plugin_toolkit::containers::local_hostname().to_string(),
            root,
        )
        .with_data_roots(roots))
    }

    fn payload(&self, spec: &WorkloadSpec) -> Result<StackDeployPayload, DeployError> {
        Ok(StackDeployPayload {
            name: spec.name.clone(),
            dir: format!("{}/{}", self.root.trim_end_matches('/'), spec.name),
            file: None,
            compose_yaml: Some(compose_json(spec)?),
            compose_env: None,
            deploy: true,
        })
    }

    async fn observed(
        &self,
        workload: &str,
        detail: Option<String>,
    ) -> Result<DeployOutcome, DeployError> {
        let status = self.status(workload).await?;
        Ok(DeployOutcome {
            workload: workload.to_string(),
            id: status.id,
            state: Some(status.state),
            detail: detail.or(status.detail),
        })
    }

    async fn lifecycle(&self, workload: &str, action: &str) -> Result<DeployOutcome, DeployError> {
        check_name(workload)?;
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
        self.observed(workload, message(out)).await
    }
}

fn provider() -> DockerUnitProvider {
    unit_provider()
}

fn other(e: impl std::fmt::Display) -> DeployError {
    DeployError::Other(e.to_string())
}

pub fn pick_root(roots: &[String]) -> Result<String, DeployError> {
    match roots {
        [root] => Ok(root.clone()),
        [] => Ok(crate::tools::DEFAULT_STACKS_ROOT.to_string()),
        _ => Err(other(format!(
            "ambiguous stacks roots {roots:?}; configure a single stacks_root for the deploy target"
        ))),
    }
}

fn check_name(name: &str) -> Result<(), DeployError> {
    if !crate::fsat::is_single_component(name) {
        return Err(other(format!(
            "workload name '{name}' must be a single path component"
        )));
    }
    Ok(())
}

pub fn summarize(services: Result<Vec<bool>, String>) -> (&'static str, String) {
    match services {
        Err(e) => ("broken", e),
        Ok(running) => {
            let up = running.iter().filter(|r| **r).count();
            let state = if running.is_empty() || up == 0 {
                "stopped"
            } else if up == running.len() {
                "running"
            } else {
                "degraded"
            };
            (state, format!("{up}/{} service(s) running", running.len()))
        }
    }
}

fn is_named_volume(source: &str) -> bool {
    source
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        && source
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn orca_home() -> Option<PathBuf> {
    std::env::var_os("ORCA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".orca")))
}

fn resolved(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn denied(path: &Path, orca_home: Option<&Path>) -> bool {
    if path.parent().is_none() {
        return true;
    }
    let mut deny: Vec<PathBuf> = DENIED.iter().map(PathBuf::from).collect();
    deny.extend(orca_home.map(Path::to_path_buf));
    let deny_hit = deny
        .iter()
        .flat_map(|d| [d.clone(), resolved(d)])
        .any(|d| path.starts_with(&d));
    let segments: Vec<&std::ffi::OsStr> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();
    deny_hit
        || DENIED_SEGMENTS.iter().any(|pat| {
            segments
                .windows(pat.len())
                .any(|w| w.iter().zip(pat.iter()).all(|(a, b)| *a == *b))
        })
}

pub fn check_mounts(
    spec: &WorkloadSpec,
    data_roots: &[String],
    orca_home: Option<&Path>,
) -> Result<(), DeployError> {
    let roots: Vec<PathBuf> = data_roots
        .iter()
        .filter_map(|r| std::fs::canonicalize(r).ok())
        .collect();
    for m in &spec.mounts {
        if !matches!(m.kind, MountKind::Bind) || is_named_volume(&m.source) {
            continue;
        }
        let source = Path::new(&m.source);
        if !source.is_absolute() {
            return Err(other(format!(
                "bind mount source '{}' must be an absolute path",
                m.source
            )));
        }
        let real = std::fs::canonicalize(source).map_err(|e| {
            other(format!(
                "bind mount source '{}' is unavailable: {e}",
                m.source
            ))
        })?;
        if !roots.iter().any(|r| real.starts_with(r)) {
            return Err(other(format!(
                "bind mount source '{}' is outside the allowed data roots {data_roots:?}",
                m.source
            )));
        }
        if denied(&real, orca_home) {
            return Err(other(format!(
                "bind mount source '{}' resolves to protected path '{}'",
                m.source,
                real.display()
            )));
        }
    }
    Ok(())
}

fn require(workload: &str) -> Result<stacks::StackRow, DeployError> {
    stacks::get(workload)
        .map_err(other)?
        .ok_or_else(|| DeployError::NotFound(format!("no docker stack '{workload}'")))
}

fn message(out: VerbOutcome) -> Option<String> {
    match out {
        VerbOutcome::Action(a) => Some(a.message),
        _ => None,
    }
}

pub fn compose_json(spec: &WorkloadSpec) -> Result<String, DeployError> {
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
                    if is_named_volume(&m.source) {
                        json!({"type": "volume", "source": m.source, "target": m.target, "read_only": m.read_only})
                    } else {
                        json!({"type": "bind", "source": m.source, "target": m.target, "read_only": m.read_only, "bind": {"create_host_path": false}})
                    }
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
        check_name(&spec.name)?;
        check_mounts(spec, &self.data_roots, orca_home().as_deref())?;
        let raw = serde_json::to_string(&self.payload(spec)?).map_err(other)?;
        provider()
            .stack_deploy(Some(raw), true)
            .await
            .map_err(other)?;
        self.observed(&spec.name, None).await
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
        check_name(workload)?;
        let row = require(workload)?;
        let out = stack_remove(&row).await.map_err(other)?;
        Ok(DeployOutcome {
            workload: workload.to_string(),
            id: None,
            state: Some("absent".into()),
            detail: message(out),
        })
    }

    async fn adopt(&self, req: &AdoptRequest) -> Result<DeployOutcome, DeployError> {
        check_name(&req.native_id)?;
        if req.name.as_deref().is_some_and(|n| n != req.native_id) {
            return Err(other(
                "docker stacks are tracked by their stack name; adopt does not rename",
            ));
        }
        require(&req.native_id)?;
        self.observed(&req.native_id, None).await
    }

    async fn status(&self, workload: &str) -> Result<TargetStatus, DeployError> {
        check_name(workload)?;
        let Some(row) = stacks::get(workload).map_err(other)? else {
            return Ok(TargetStatus {
                workload: workload.to_string(),
                id: None,
                exists: false,
                state: "absent".into(),
                detail: None,
            });
        };
        let services = match row.compose() {
            Ok(c) => c
                .services()
                .await
                .map(|svcs| svcs.into_iter().map(|s| s.running).collect())
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        let (state, detail) = summarize(services);
        Ok(TargetStatus {
            workload: workload.to_string(),
            id: Some(row.name.clone()),
            exists: true,
            state: state.into(),
            detail: Some(format!("{detail} at {}", row.dir)),
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
        let doc: Value = serde_json::from_str(&compose_json(spec).unwrap()).unwrap();
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
                {"type": "bind", "source": "/opt/stacks/web/data", "target": "/data", "read_only": true, "bind": {"create_host_path": false}},
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
        assert!(compose_json(&s).is_err());
        let mut s = spec();
        s.mounts[0].source.clear();
        assert!(compose_json(&s).is_err());
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

    fn run(op: &str, args: Value) -> Result<Value, Value> {
        crate::test_support::with_db(|| dispatch(&format!("{INVOKE_PREFIX}.{op}"), args).unwrap()).0
    }

    fn err_text(r: Result<Value, Value>) -> String {
        r.expect_err("op should fail").to_string()
    }

    #[test]
    fn launch_refuses_non_component_names() {
        for name in ["../x", "a/b", "..", ""] {
            let mut s = spec();
            s.name = name.into();
            let err = err_text(run("launch", json!({"spec": s})));
            assert!(err.contains("single path component"), "{name}: {err}");
            let err = err_text(run("provision", json!({"spec": s})));
            assert!(err.contains("single path component"), "{name}: {err}");
        }
    }

    #[test]
    fn workload_ops_refuse_non_component_names() {
        for op in ["stop", "restart", "destroy", "status"] {
            for name in ["../x", "a/b"] {
                let err = err_text(run(op, json!({"workload": name})));
                assert!(err.contains("single path component"), "{op} {name}: {err}");
            }
        }
    }

    #[test]
    fn unknown_stack_is_not_found_per_op() {
        for op in ["stop", "restart", "destroy"] {
            let err = err_text(run(op, json!({"workload": "ghost"})));
            assert!(err.contains("no docker stack 'ghost'"), "{op}: {err}");
        }
        let err = err_text(run("adopt", json!({"req": {"native_id": "ghost"}})));
        assert!(err.contains("no docker stack 'ghost'"), "{err}");
    }

    #[test]
    fn status_of_unknown_stack_is_absent() {
        let out = run("status", json!({"workload": "ghost"})).unwrap();
        assert_eq!(out["exists"], false);
        assert_eq!(out["state"], "absent");
    }

    #[test]
    fn adopt_refuses_rename() {
        let err = err_text(run(
            "adopt",
            json!({"req": {"native_id": "web", "name": "other"}}),
        ));
        assert!(err.contains("does not rename"), "{err}");
    }

    #[test]
    fn unknown_op_is_refused() {
        let err = err_text(run("teleport", json!({})));
        assert!(err.contains("no operation 'teleport'"), "{err}");
    }

    #[test]
    fn summarize_maps_every_state() {
        assert_eq!(
            summarize(Err("bad yaml".into())),
            ("broken", "bad yaml".into())
        );
        assert_eq!(summarize(Ok(vec![])).0, "stopped");
        assert_eq!(summarize(Ok(vec![false, false])).0, "stopped");
        assert_eq!(summarize(Ok(vec![true, true])).0, "running");
        assert_eq!(
            summarize(Ok(vec![true, false])),
            ("degraded", "1/2 service(s) running".into())
        );
    }

    #[test]
    fn pick_root_refuses_ambiguity() {
        assert_eq!(pick_root(&[]).unwrap(), crate::tools::DEFAULT_STACKS_ROOT);
        assert_eq!(pick_root(&["/srv/stacks".into()]).unwrap(), "/srv/stacks");
        let err = pick_root(&["/a".into(), "/b".into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("ambiguous stacks roots"), "{err}");
    }

    fn bind(source: &str) -> WorkloadSpec {
        WorkloadSpec {
            name: "web".into(),
            image: Some("nginx:1".into()),
            mounts: vec![Mount {
                kind: MountKind::Bind,
                source: source.into(),
                target: "/data".into(),
                read_only: false,
                size: None,
            }],
            ..Default::default()
        }
    }

    fn root_dir() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        (dir, root)
    }

    #[test]
    fn symlink_inside_root_to_etc_is_refused() {
        let (dir, root) = root_dir();
        let link = dir.path().join("etc");
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        let err = check_mounts(&bind(&link.to_string_lossy()), &[root], None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("outside the allowed data roots"), "{err}");
    }

    #[test]
    fn path_outside_roots_is_refused() {
        let (_dir, root) = root_dir();
        let (other_dir, _) = root_dir();
        let err = check_mounts(&bind(&other_dir.path().to_string_lossy()), &[root], None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("outside the allowed data roots"), "{err}");
    }

    #[test]
    fn deny_set_applies_even_under_slash_root() {
        let (dir, _) = root_dir();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir(&ssh).unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let roots = ["/".to_string()];
        for src in [
            "/".to_string(),
            "/etc".to_string(),
            "/usr".to_string(),
            ssh.to_string_lossy().into_owned(),
            home.to_string_lossy().into_owned(),
        ] {
            let err = check_mounts(&bind(&src), &roots, Some(&home))
                .unwrap_err()
                .to_string();
            assert!(err.contains("protected path"), "{src}: {err}");
        }
    }

    #[test]
    fn missing_and_relative_sources_are_refused() {
        let (dir, root) = root_dir();
        let missing = dir.path().join("nope");
        let err = check_mounts(
            &bind(&missing.to_string_lossy()),
            std::slice::from_ref(&root),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unavailable"), "{err}");
        let err = check_mounts(&bind("./data"), &[root], None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("absolute path"), "{err}");
    }

    #[test]
    fn allowed_path_and_named_volume_pass() {
        let (dir, root) = root_dir();
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        check_mounts(
            &bind(&data.to_string_lossy()),
            std::slice::from_ref(&root),
            None,
        )
        .unwrap();
        check_mounts(&bind("pgdata"), &[root], None).unwrap();
    }

    #[test]
    fn named_volume_is_emitted_as_volume() {
        let svc = service(&bind("pgdata"));
        assert_eq!(
            svc["volumes"],
            json!([{"type": "volume", "source": "pgdata", "target": "/data", "read_only": false}])
        );
    }

    #[test]
    fn data_roots_default_to_stack_root() {
        let t = DockerDeployTarget::new("host-a", "/opt/stacks");
        assert_eq!(t.data_roots, ["/opt/stacks"]);
        let t = t.with_data_roots(vec!["/srv/data".into()]);
        assert_eq!(t.data_roots, ["/srv/data"]);
    }

    #[test]
    fn dispatch_ignores_foreign_prefix() {
        assert!(dispatch("proxmox.__deploy.x.launch", json!({})).is_none());
    }
}
