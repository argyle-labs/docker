#![allow(clippy::disallowed_types)]

use bollard::Docker;
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{Map, Value};

use crate::lint::{block_service, indent_of, is_content};
use crate::policy::{self, Grant};
use crate::stacks::{self, StackRow};

pub const ICON_LABEL: &str = "net.unraid.docker.icon";
pub const WEBUI_LABEL: &str = "net.unraid.docker.webui";
const CONTAINER_NAME: &str = "container_name";
const ICON_BASE: &str = "https://gitea.scottkey.me/argyle-labs";
const ICON_PATH: &str = "raw/branch/main/assets/icon-256.png";
const ALIASES: &[(&str, &str)] = &[
    ("act_runner", "gitea"),
    ("gitea-runner", "gitea"),
    ("proxmox-backup-server", "pbs"),
    ("faster-whisper", "whisper-ai"),
    ("wyoming-whisper", "whisper-ai"),
    ("whisper", "whisper-ai"),
];
const ARCH_SUFFIXES: &[&str] = &["-linux-amd64", "-linux-arm64", "-amd64", "-arm64"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct Change {
    pub service: String,
    pub key: String,
    pub value: String,
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}={}", self.service, self.key, self.value)
    }
}

pub struct Plan {
    pub before: String,
    pub after: String,
    pub changes: Vec<Change>,
    cfg: Value,
}

fn str_at<'a>(svc: &'a Value, key: &str) -> Option<&'a str> {
    svc.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn has_label(svc: &Value, key: &str) -> bool {
    match svc.get("labels") {
        Some(Value::Object(m)) => m.contains_key(key),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .any(|l| l.split('=').next() == Some(key)),
        _ => false,
    }
}

fn first_port(svc: &Value) -> Option<u64> {
    svc.get("ports")?.as_array()?.iter().find_map(|p| match p {
        Value::Object(m) => m
            .get("published")
            .filter(|v| !v.is_null())
            .and(m.get("target"))
            .and_then(|t| t.as_u64().or_else(|| t.as_str()?.parse().ok())),
        Value::String(s) => {
            let target = s.rsplit(':').next()?.split('/').next()?;
            s.contains(':').then(|| target.parse().ok()).flatten()
        }
        _ => None,
    })
}

pub fn candidates(stack: &str, service: &str, image: Option<&str>) -> Vec<String> {
    let from_image = image.map(|i| {
        let i = i.split('@').next().unwrap_or(i);
        let last = i.rsplit('/').next().unwrap_or(i);
        let name = last.split(':').next().unwrap_or(last);
        ARCH_SUFFIXES
            .iter()
            .find_map(|s| name.strip_suffix(s))
            .unwrap_or(name)
            .to_string()
    });
    let mut out: Vec<String> = Vec::new();
    for c in from_image
        .into_iter()
        .chain([service.to_string(), stack.to_string()])
    {
        let c = ALIASES
            .iter()
            .find(|(from, _)| *from == c)
            .map_or(c.clone(), |(_, to)| (*to).to_string());
        if !c.is_empty() && !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

pub fn icon_url(app: &str) -> String {
    format!("{ICON_BASE}/{app}/{ICON_PATH}")
}

fn exists(url: &str) -> bool {
    let req = plugin_toolkit::abi::HttpRequest {
        method: "HEAD".into(),
        url: url.into(),
        headers: Vec::new(),
        body: Vec::new(),
        timeout_ms: Some(5_000),
        insecure: false,
        max_body_bytes: Some(0),
        body_b64: true,
        follow_redirects: None,
    };
    plugin_toolkit::capsink::http_request(&req).is_ok_and(|r| r.status == 200)
}

pub fn icon_for(candidates: &[String]) -> Option<String> {
    candidates.iter().map(|c| icon_url(c)).find(|u| exists(u))
}

pub fn is_unraid() -> bool {
    crate::daemon_config::detect(std::path::Path::new("/")) == crate::daemon_config::Host::Unraid
}

pub fn plan(
    stack: &str,
    cfg: &Value,
    unraid: bool,
    icon: &dyn Fn(&[String]) -> Option<String>,
) -> Vec<Change> {
    let Some(services) = cfg.get("services").and_then(Value::as_object) else {
        return Vec::new();
    };
    let single = services.len() == 1;
    let mut out = Vec::new();
    for (name, svc) in services {
        let change = |key: &str, value: String| Change {
            service: name.clone(),
            key: key.to_string(),
            value,
        };
        if str_at(svc, CONTAINER_NAME).is_none() {
            let value = if single { stack } else { name };
            out.push(change(CONTAINER_NAME, value.to_string()));
        }
        if !unraid {
            continue;
        }
        if !has_label(svc, ICON_LABEL)
            && let Some(url) = icon(&candidates(stack, name, str_at(svc, "image")))
        {
            out.push(change(ICON_LABEL, url));
        }
        if !has_label(svc, WEBUI_LABEL)
            && let Some(port) = first_port(svc)
        {
            out.push(change(WEBUI_LABEL, format!("http://[IP]:[PORT:{port}]/")));
        }
    }
    out
}

fn quoted(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

fn set_label(lines: &mut Vec<String>, c: &Change) -> Result<()> {
    let (header, end, child) = block_service(lines, &c.service).map_err(|e| anyhow!(e))?;
    let pad = " ".repeat(child);
    let at = (header + 1..end)
        .find(|&i| indent_of(&lines[i]) == child && lines[i].trim_start().starts_with("labels:"));
    let Some(at) = at else {
        lines.insert(header + 1, format!("{pad}labels:"));
        lines.insert(
            header + 2,
            format!("{pad}  {}: {}", c.key, quoted(&c.value)),
        );
        return Ok(());
    };
    let rest = lines[at]
        .trim_start()
        .trim_start_matches("labels:")
        .split('#')
        .next()
        .unwrap_or_default()
        .trim();
    if !rest.is_empty() {
        bail!(
            "service '{}' writes its labels in flow style; set {} by hand",
            c.service,
            c.key
        );
    }
    let next = lines[at + 1..end].iter().find(|l| is_content(l));
    let (inner, list) = match next {
        Some(l) if indent_of(l) > child => (indent_of(l), l.trim_start().starts_with('-')),
        _ => (child + 2, false),
    };
    let pad = " ".repeat(inner);
    let line = if list {
        format!("{pad}- {}", quoted(&format!("{}={}", c.key, c.value)))
    } else {
        format!("{pad}{}: {}", c.key, quoted(&c.value))
    };
    lines.insert(at + 1, line);
    Ok(())
}

pub fn apply(yaml: &str, changes: &[Change]) -> Result<String> {
    let mut lines: Vec<String> = yaml.lines().map(str::to_string).collect();
    for c in changes {
        if c.key == CONTAINER_NAME {
            let (header, _, child) = block_service(&lines, &c.service).map_err(|e| anyhow!(e))?;
            lines.insert(
                header + 1,
                format!(
                    "{}{CONTAINER_NAME}: {}",
                    " ".repeat(child),
                    quoted(&c.value)
                ),
            );
        } else {
            set_label(&mut lines, c)?;
        }
    }
    let mut out = lines.join("\n");
    if yaml.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

pub fn rebind(allow: &mut [Grant], before: &Value, changes: &[Change]) {
    let mut after = before.clone();
    for c in changes {
        let Some(svc) = after.pointer_mut(&format!("/services/{}", c.service)) else {
            continue;
        };
        if c.key == CONTAINER_NAME {
            svc[CONTAINER_NAME] = Value::String(c.value.clone());
        } else {
            if !svc.get("labels").is_some_and(Value::is_object) {
                svc["labels"] = Value::Object(Map::new());
            }
            svc["labels"][&c.key] = Value::String(c.value.clone());
        }
    }
    let (old, new) = (policy::digests(before), policy::digests(&after));
    for g in allow.iter_mut() {
        if old.get(&g.service) == Some(&g.definition)
            && let Some(d) = new.get(&g.service)
        {
            g.definition = d.clone();
        }
    }
}

pub async fn collisions(docker: &Docker, project: &str, changes: &[Change]) -> Result<()> {
    for c in changes.iter().filter(|c| c.key == CONTAINER_NAME) {
        match docker.inspect_container(&c.value, None).await {
            Ok(info) => {
                let owner = info
                    .config
                    .as_ref()
                    .and_then(|c| c.labels.as_ref())
                    .and_then(|l| l.get(crate::prune::COMPOSE_PROJECT_LABEL));
                if owner.map(String::as_str) != Some(project) {
                    bail!(
                        "container name '{}' for service '{}' is already used on this host outside stack project '{project}'; set container_name in the compose file",
                        c.value,
                        c.service
                    );
                }
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(e) => bail!("check container name '{}': {e}", c.value),
        }
    }
    Ok(())
}

pub async fn plan_stack(row: &StackRow) -> Result<Plan> {
    let cfg = policy::user_cfg(row).await?;
    let before = row.read_compose()?;
    let changes = plan(&row.name, &cfg, is_unraid(), &icon_for);
    let after = apply(&before, &changes)?;
    Ok(Plan {
        before,
        after,
        changes,
        cfg,
    })
}

pub async fn write(row: &mut StackRow, plan: &Plan, docker: Option<&Docker>) -> Result<()> {
    if plan.changes.is_empty() {
        return Ok(());
    }
    if let Some(docker) = docker {
        let project = plan
            .cfg
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(&row.name)
            .to_string();
        collisions(docker, &project, &plan.changes).await?;
    }
    let mut allow = row.allow.clone();
    rebind(&mut allow, &plan.cfg, &plan.changes);
    let rebound = StackRow {
        allow,
        ..row.clone()
    };
    rebound
        .write_compose_if_unchanged(
            &plan.after,
            &plan.before,
            &crate::tools::stacks_roots()?,
            docker,
        )
        .await?;
    *row = rebound;
    if stacks::get(&row.name)?.is_some() {
        stacks::put(row)?;
    }
    Ok(())
}

pub async fn normalize(row: &mut StackRow, docker: Option<&Docker>) -> Result<Vec<Change>> {
    let plan = plan_stack(row).await?;
    write(row, &plan, docker).await?;
    Ok(plan.changes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json::json;

    fn no_icon(_: &[String]) -> Option<String> {
        None
    }

    #[test]
    fn every_service_without_a_name_gets_one() {
        let cfg = json!({"services": {
            "app": {"image": "x:1"},
            "db": {"image": "postgres:16", "container_name": "pg"}
        }});
        let changes = plan("web", &cfg, false, &no_icon);
        assert_eq!(
            changes,
            [Change {
                service: "app".into(),
                key: CONTAINER_NAME.into(),
                value: "app".into()
            }]
        );
    }

    #[test]
    fn a_single_service_stack_is_named_after_the_stack() {
        let cfg = json!({"services": {"server": {"image": "dxflrs/garage:v1"}}});
        let changes = plan("garage", &cfg, false, &no_icon);
        assert_eq!(changes[0].value, "garage");
    }

    #[test]
    fn unraid_adds_icon_and_webui_only_when_absent() {
        let cfg = json!({"services": {
            "zot": {"image": "ghcr.io/project-zot/zot-linux-amd64:v2", "container_name": "zot",
                    "ports": [{"target": 5000, "published": "5000", "protocol": "tcp"}]},
            "set": {"image": "x:1", "container_name": "set",
                    "labels": {ICON_LABEL: "a", WEBUI_LABEL: "b"},
                    "ports": [{"target": 80, "published": "8080"}]}
        }});
        let icon = |c: &[String]| (c[0] == "zot").then(|| icon_url(&c[0]));
        let changes = plan("registry", &cfg, true, &icon);
        let shown: Vec<String> = changes.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown,
            [
                format!("zot: {ICON_LABEL}={}", icon_url("zot")),
                format!("zot: {WEBUI_LABEL}=http://[IP]:[PORT:5000]/"),
            ]
        );
        assert!(plan("registry", &cfg, false, &icon).is_empty());
    }

    #[test]
    fn icon_candidates_map_images_and_aliases() {
        assert_eq!(
            candidates("ci", "runner", Some("gitea/act_runner:latest")),
            ["gitea", "runner", "ci"]
        );
        assert_eq!(
            candidates("ollama", "ollama", Some("ollama/ollama@sha256:ab")),
            ["ollama"]
        );
        assert_eq!(
            candidates("s", "pbs", Some("ayufan/proxmox-backup-server:latest")),
            ["pbs", "s"]
        );
        assert_eq!(
            icon_url("garage"),
            "https://gitea.scottkey.me/argyle-labs/garage/raw/branch/main/assets/icon-256.png"
        );
    }

    #[test]
    fn icon_lookup_outside_orca_finds_nothing() {
        assert_eq!(icon_for(&["garage".into()]), None);
    }

    #[test]
    fn apply_inserts_names_and_labels_in_both_label_styles() {
        let yaml = "services:\n  app:\n    image: x:1\n    labels:\n      a: b\n  db:\n    image: y:1\n    labels:\n      - c=d\n  web:\n    image: z:1\n";
        let ch = |service: &str, key: &str, value: &str| Change {
            service: service.into(),
            key: key.into(),
            value: value.into(),
        };
        let out = apply(
            yaml,
            &[
                ch("app", CONTAINER_NAME, "app"),
                ch("app", ICON_LABEL, "i"),
                ch("db", WEBUI_LABEL, "w"),
                ch("web", ICON_LABEL, "j"),
            ],
        )
        .unwrap();
        assert_eq!(
            out,
            format!(
                "services:\n  app:\n    container_name: \"app\"\n    image: x:1\n    labels:\n      {ICON_LABEL}: \"i\"\n      a: b\n  db:\n    image: y:1\n    labels:\n      - \"{WEBUI_LABEL}=w\"\n      - c=d\n  web:\n    labels:\n      {ICON_LABEL}: \"j\"\n    image: z:1\n"
            )
        );
        let flow = "services:\n  app:\n    labels: {a: b}\n";
        assert!(apply(flow, &[ch("app", ICON_LABEL, "i")]).is_err());
    }

    #[test]
    fn rebind_moves_only_grants_bound_to_the_current_definition() {
        let cfg = json!({"name": "web", "services": {"app": {"image": "x:1", "privileged": true}}});
        let old = policy::digests(&cfg)["app"].clone();
        let grant = |definition: &str| Grant {
            service: "app".into(),
            image: "x:1".into(),
            definition: definition.into(),
            image_digest: "sha256:a".into(),
            allow: "privileged".into(),
        };
        let mut allow = vec![grant(&old), grant("sha256:stale")];
        let changes = [Change {
            service: "app".into(),
            key: CONTAINER_NAME.into(),
            value: "app".into(),
        }];
        rebind(&mut allow, &cfg, &changes);
        assert_ne!(allow[0].definition, old);
        assert_eq!(allow[1].definition, "sha256:stale");
        let mut expected = cfg.clone();
        expected["services"]["app"][CONTAINER_NAME] = json!("app");
        assert_eq!(allow[0].definition, policy::digests(&expected)["app"]);
    }

    #[test]
    fn a_name_taken_outside_the_stack_is_refused() {
        use crate::test_engine::{FakeEngine, Route};
        let engine = FakeEngine::routed(vec![
            Route::new(
                "GET",
                "/containers/app/json",
                200,
                json!({"Id": "c1", "Config": {"Labels": {"com.docker.compose.project": "other"}}})
                    .to_string(),
            ),
            Route::new(
                "GET",
                "/containers/mine/json",
                200,
                json!({"Id": "c2", "Config": {"Labels": {"com.docker.compose.project": "web"}}})
                    .to_string(),
            ),
        ]);
        let docker = engine.client();
        let ch = |value: &str| Change {
            service: "s".into(),
            key: CONTAINER_NAME.into(),
            value: value.into(),
        };
        let run = |c: Change| plugin_toolkit::reactor::block_on(collisions(&docker, "web", &[c]));
        let err = run(ch("app")).unwrap_err().to_string();
        assert!(err.contains("already used on this host"), "{err}");
        run(ch("mine")).unwrap();
        run(ch("free")).unwrap();
    }
}
