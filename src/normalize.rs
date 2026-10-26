#![allow(clippy::disallowed_types)]

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

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
const PROBE_ATTEMPTS: usize = 3;
const PROBE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(200);
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
    pub warnings: Vec<String>,
    cfg: Value,
}

impl Plan {
    pub fn report(&self) -> Vec<String> {
        self.changes
            .iter()
            .map(ToString::to_string)
            .chain(self.warnings.iter().map(|w| format!("warning: {w}")))
            .collect()
    }
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

fn many(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Number(n)) => n.as_u64().is_none_or(|n| n > 1),
        Some(Value::String(s)) => s.trim().parse::<u64>().map_or(true, |n| n > 1),
        Some(_) => true,
    }
}

fn replicated(svc: &Value) -> bool {
    many(svc.get("scale")) || many(svc.pointer("/deploy/replicas"))
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

fn valid_app(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
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
        if valid_app(&c) && !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

pub fn icon_url(app: &str) -> String {
    format!("{ICON_BASE}/{app}/{ICON_PATH}")
}

fn probe(url: &str) -> Option<bool> {
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
        connect_timeout_ms: Some(2_000),
        retry: Some(false),
    };
    for attempt in 0..PROBE_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(PROBE_BACKOFF * u32::try_from(attempt).unwrap_or(1));
        }
        match plugin_toolkit::capsink::http_request(&req) {
            Ok(r) if r.status < 500 => return Some((200..300).contains(&r.status)),
            Err(e) if e.to_string().contains("capability unavailable") => return None,
            _ => {}
        }
    }
    None
}

fn icon_cache() -> &'static Mutex<HashMap<String, bool>> {
    static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

fn has_icon(app: &str, probe: &dyn Fn(&str) -> Option<bool>) -> bool {
    if let Some(hit) = icon_cache().lock().ok().and_then(|c| c.get(app).copied()) {
        return hit;
    }
    let Some(found) = probe(&icon_url(app)) else {
        return false;
    };
    if let Ok(mut c) = icon_cache().lock() {
        c.insert(app.to_string(), found);
    }
    found
}

pub fn icon_for(candidates: &[String]) -> Option<String> {
    candidates
        .iter()
        .find(|c| has_icon(c, &probe))
        .map(|c| icon_url(c))
}

pub fn is_unraid() -> bool {
    crate::daemon_config::detect(std::path::Path::new("/")) == crate::daemon_config::Host::Unraid
}

pub fn plan(
    stack: &str,
    cfg: &Value,
    naming: bool,
    unraid: bool,
    icon: &dyn Fn(&[String]) -> Option<String>,
) -> (Vec<Change>, Vec<String>) {
    let Some(services) = cfg.get("services").and_then(Value::as_object) else {
        return (Vec::new(), Vec::new());
    };
    let single = services.len() == 1;
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for (name, svc) in services {
        let change = |key: &str, value: String| Change {
            service: name.clone(),
            key: key.to_string(),
            value,
        };
        if str_at(svc, CONTAINER_NAME).is_none() {
            if !naming {
                warnings.push(format!(
                    "{name}: container_name not set: no engine connection to check the name is free"
                ));
            } else if replicated(svc) {
                warnings.push(format!(
                    "{name}: container_name not set: the service runs replicas"
                ));
            } else {
                let value = if single { stack } else { name };
                out.push(change(CONTAINER_NAME, value.to_string()));
            }
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
    (out, warnings)
}

fn quoted(v: &str) -> Result<String> {
    if v.chars().any(char::is_control) {
        bail!("value holds a control character");
    }
    Ok(format!(
        "\"{}\"",
        v.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn set_name(lines: &mut Vec<String>, c: &Change) -> Result<()> {
    let (header, end, child) = block_service(lines, &c.service).map_err(|e| anyhow!(e))?;
    let line = format!(
        "{}{CONTAINER_NAME}: {}",
        " ".repeat(child),
        quoted(&c.value)?
    );
    match (header + 1..end).find(|&i| {
        indent_of(&lines[i]) == child
            && lines[i]
                .trim_start()
                .starts_with(&format!("{CONTAINER_NAME}:"))
    }) {
        Some(i) => lines[i] = line,
        None => lines.insert(header + 1, line),
    }
    Ok(())
}

fn set_label(lines: &mut Vec<String>, c: &Change) -> Result<()> {
    let (header, end, child) = block_service(lines, &c.service).map_err(|e| anyhow!(e))?;
    let pad = " ".repeat(child);
    let at = (header + 1..end)
        .find(|&i| indent_of(&lines[i]) == child && lines[i].trim_start().starts_with("labels:"));
    let Some(at) = at else {
        let line = format!("{pad}  {}: {}", c.key, quoted(&c.value)?);
        lines.insert(header + 1, format!("{pad}labels:"));
        lines.insert(header + 2, line);
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
        bail!("labels are written in flow style");
    }
    let next = lines[at + 1..end].iter().find(|l| is_content(l));
    let (inner, list) = match next {
        Some(l) if indent_of(l) > child => (indent_of(l), l.trim_start().starts_with('-')),
        _ => (child + 2, false),
    };
    let pad = " ".repeat(inner);
    let line = if list {
        format!("{pad}- {}", quoted(&format!("{}={}", c.key, c.value))?)
    } else {
        format!("{pad}{}: {}", c.key, quoted(&c.value)?)
    };
    lines.insert(at + 1, line);
    Ok(())
}

pub fn apply(yaml: &str, changes: &[Change]) -> (String, Vec<Change>, Vec<String>) {
    let mut lines: Vec<String> = yaml.lines().map(str::to_string).collect();
    let mut applied = Vec::new();
    let mut warnings = Vec::new();
    for c in changes {
        let mut next = lines.clone();
        let done = if c.key == CONTAINER_NAME {
            set_name(&mut next, c)
        } else {
            set_label(&mut next, c)
        };
        match done {
            Ok(()) => {
                lines = next;
                applied.push(c.clone());
            }
            Err(e) => warnings.push(format!("{}: {} skipped: {e}", c.service, c.key)),
        }
    }
    let mut out = lines.join("\n");
    if yaml.ends_with('\n') {
        out.push('\n');
    }
    (out, applied, warnings)
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

pub async fn collision(docker: &Docker, project: &str, name: &str) -> Option<String> {
    match docker.inspect_container(name, None).await {
        Ok(info) => {
            let owner = info
                .config
                .as_ref()
                .and_then(|c| c.labels.as_ref())
                .and_then(|l| l.get(crate::prune::COMPOSE_PROJECT_LABEL));
            (owner.map(String::as_str) != Some(project)).then(|| {
                format!("container name '{name}' is already used on this host outside stack project '{project}'; set container_name in the compose file")
            })
        }
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => None,
        Err(e) => Some(format!("check container name '{name}': {e}")),
    }
}

async fn plan_text(name: &str, before: String, cfg: Value, docker: Option<&Docker>) -> Plan {
    let (planned, mut warnings) = plan(name, &cfg, docker.is_some(), is_unraid(), &icon_for);
    let project = cfg
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(name)
        .to_string();
    let mut free = Vec::new();
    for c in planned {
        if c.key == CONTAINER_NAME
            && let Some(docker) = docker
            && let Some(why) = collision(docker, &project, &c.value).await
        {
            warnings.push(format!("{}: {why}", c.service));
            continue;
        }
        free.push(c);
    }
    let (after, changes, skipped) = apply(&before, &free);
    warnings.extend(skipped);
    Plan {
        before,
        after,
        changes,
        warnings,
        cfg,
    }
}

pub async fn plan_stack(row: &StackRow, docker: Option<&Docker>) -> Result<Plan> {
    let cfg = policy::user_cfg(row).await?;
    let before = row.read_compose(&crate::stacks::allowed_roots()?)?;
    Ok(plan_text(&row.name, before, cfg, docker).await)
}

pub async fn plan_inline(
    name: &str,
    dir: &std::path::Path,
    yaml: &str,
    docker: Option<&Docker>,
) -> Result<Plan> {
    let tmp = crate::fsat::PrivateDir::new("orca-normalize-")?;
    let file = tmp.write("compose.yaml", yaml.as_bytes())?;
    let project_dir = if dir.is_dir() { dir } else { tmp.path() };
    let compose = crate::compose::Compose::new(vec![file], Vec::new(), None)
        .ok_or_else(|| plugin_toolkit::anyhow::anyhow!("no compose file"))?;
    let raw = stacks::resolved_config(project_dir, &compose).await?;
    let cfg: Value = plugin_toolkit::serde_json::from_str(&raw)?;
    Ok(plan_text(name, yaml.to_string(), cfg, docker).await)
}

pub async fn write(row: &mut StackRow, plan: &Plan, docker: Option<&Docker>) -> Result<()> {
    if plan.changes.is_empty() {
        return Ok(());
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

pub async fn normalize(row: &mut StackRow, docker: Option<&Docker>) -> Vec<String> {
    let plan = match plan_stack(row, docker).await {
        Ok(p) => p,
        Err(e) => return vec![format!("warning: normalize skipped: {e:#}")],
    };
    match write(row, &plan, docker).await {
        Ok(()) => plan.report(),
        Err(e) => vec![format!("warning: normalize not written: {e:#}")],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json::json;

    fn no_icon(_: &[String]) -> Option<String> {
        None
    }

    fn ch(service: &str, key: &str, value: &str) -> Change {
        Change {
            service: service.into(),
            key: key.into(),
            value: value.into(),
        }
    }

    #[test]
    fn every_service_without_a_name_gets_one() {
        let cfg = json!({"services": {
            "app": {"image": "x:1"},
            "db": {"image": "postgres:16", "container_name": "pg"}
        }});
        let (changes, warnings) = plan("web", &cfg, true, false, &no_icon);
        assert_eq!(changes, [ch("app", CONTAINER_NAME, "app")]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn a_single_service_stack_is_named_after_the_stack() {
        let cfg = json!({"services": {"server": {"image": "dxflrs/garage:v1"}}});
        let (changes, _) = plan("garage", &cfg, true, false, &no_icon);
        assert_eq!(changes[0].value, "garage");
    }

    #[test]
    fn replicated_services_get_no_name() {
        let cfg = json!({"services": {
            "a": {"image": "x:1", "scale": 2},
            "b": {"image": "x:1", "deploy": {"replicas": 3}},
            "c": {"image": "x:1", "deploy": {"replicas": "${N}"}},
            "d": {"image": "x:1", "deploy": {"replicas": "1"}, "scale": 1}
        }});
        let (changes, warnings) = plan("web", &cfg, true, false, &no_icon);
        assert_eq!(changes, [ch("d", CONTAINER_NAME, "d")]);
        assert_eq!(warnings.len(), 3, "{warnings:?}");
        assert!(
            warnings.iter().all(|w| w.contains("replicas")),
            "{warnings:?}"
        );
    }

    #[test]
    fn without_an_engine_no_name_is_added() {
        let cfg = json!({"services": {"app": {"image": "x:1"}}});
        let (changes, warnings) = plan("web", &cfg, false, false, &no_icon);
        assert!(changes.is_empty());
        assert!(warnings[0].contains("no engine connection"), "{warnings:?}");
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
        let (changes, _) = plan("registry", &cfg, true, true, &icon);
        let shown: Vec<String> = changes.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown,
            [
                format!("zot: {ICON_LABEL}={}", icon_url("zot")),
                format!("zot: {WEBUI_LABEL}=http://[IP]:[PORT:5000]/"),
            ]
        );
        assert!(plan("registry", &cfg, true, false, &icon).0.is_empty());
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
            candidates("My Stack", "a..b", Some("x/Bad$Name:1")),
            Vec::<String>::new()
        );
        assert_eq!(
            icon_url("garage"),
            "https://gitea.scottkey.me/argyle-labs/garage/raw/branch/main/assets/icon-256.png"
        );
    }

    #[test]
    fn icon_probes_are_cached_per_app() {
        let calls = std::cell::Cell::new(0);
        let probe = |_: &str| {
            calls.set(calls.get() + 1);
            Some(true)
        };
        assert!(has_icon("cache-test-app", &probe));
        assert!(has_icon("cache-test-app", &probe));
        assert_eq!(calls.get(), 1);
        let gave_up = |_: &str| {
            calls.set(calls.get() + 1);
            None
        };
        assert!(!has_icon("cache-test-unreachable", &gave_up));
        assert!(!has_icon("cache-test-unreachable", &gave_up));
        assert_eq!(calls.get(), 3, "a give-up is not cached");
        assert!(has_icon("cache-test-unreachable", &probe));
    }

    #[test]
    fn icon_lookup_outside_orca_finds_nothing() {
        assert_eq!(icon_for(&["no-sink-app".into()]), None);
    }

    #[test]
    fn apply_inserts_names_and_labels_in_both_label_styles() {
        let yaml = "services:\n  app:\n    image: x:1\n    labels:\n      a: b\n  db:\n    image: y:1\n    labels:\n      - c=d\n  web:\n    image: z:1\n";
        let (out, applied, warnings) = apply(
            yaml,
            &[
                ch("app", CONTAINER_NAME, "app"),
                ch("app", ICON_LABEL, "i"),
                ch("db", WEBUI_LABEL, "w"),
                ch("web", ICON_LABEL, "j"),
            ],
        );
        assert_eq!(applied.len(), 4);
        assert!(warnings.is_empty());
        assert_eq!(
            out,
            format!(
                "services:\n  app:\n    container_name: \"app\"\n    image: x:1\n    labels:\n      {ICON_LABEL}: \"i\"\n      a: b\n  db:\n    image: y:1\n    labels:\n      - \"{WEBUI_LABEL}=w\"\n      - c=d\n  web:\n    labels:\n      {ICON_LABEL}: \"j\"\n    image: z:1\n"
            )
        );
    }

    #[test]
    fn an_empty_container_name_is_replaced_not_duplicated() {
        let yaml = "services:\n  app:\n    image: x:1\n    container_name: \"\"\n";
        let (out, _, _) = apply(yaml, &[ch("app", CONTAINER_NAME, "app")]);
        assert_eq!(
            out,
            "services:\n  app:\n    image: x:1\n    container_name: \"app\"\n"
        );
    }

    #[test]
    fn services_the_file_text_cannot_take_are_skipped_with_a_warning() {
        let yaml = "x-base: &base\n  image: x:1\nservices:\n  anchored: *base\n  merged:\n    <<: *base\n  child:\n    extends:\n      service: merged\n  flow:\n    image: y:1\n    labels: {a: b}\n";
        let (out, applied, warnings) = apply(
            yaml,
            &[
                ch("anchored", CONTAINER_NAME, "anchored"),
                ch("merged", CONTAINER_NAME, "merged"),
                ch("child", CONTAINER_NAME, "child"),
                ch("included", CONTAINER_NAME, "included"),
                ch("flow", ICON_LABEL, "i"),
                ch("merged", ICON_LABEL, "bad\nvalue"),
            ],
        );
        let names: Vec<&str> = applied.iter().map(|c| c.service.as_str()).collect();
        assert_eq!(names, ["merged", "child"]);
        assert_eq!(warnings.len(), 4, "{warnings:?}");
        for skipped in ["anchored", "included", "flow", "control character"] {
            assert!(
                warnings.iter().any(|w| w.contains(skipped)),
                "{skipped}: {warnings:?}"
            );
        }
        assert!(out.contains("  anchored: *base\n"));
        assert!(out.contains("  merged:\n    container_name: \"merged\"\n    <<: *base\n"));
        assert!(out.contains("  child:\n    container_name: \"child\"\n    extends:\n"));
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
        rebind(&mut allow, &cfg, &[ch("app", CONTAINER_NAME, "app")]);
        assert_ne!(allow[0].definition, old);
        assert_eq!(allow[1].definition, "sha256:stale");
        let mut expected = cfg.clone();
        expected["services"]["app"][CONTAINER_NAME] = json!("app");
        assert_eq!(allow[0].definition, policy::digests(&expected)["app"]);
    }

    #[test]
    fn a_name_taken_outside_the_stack_is_reported() {
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
        let run = |name: &str| plugin_toolkit::reactor::block_on(collision(&docker, "web", name));
        assert!(run("app").unwrap().contains("already used on this host"));
        assert_eq!(run("mine"), None);
        assert_eq!(run("free"), None);
    }
}
