//! `docker.host_update` — update a docker host in one verb: OS packages, then
//! every running stack (`compose pull -q` + `up -d --remove-orphans`), then a
//! prune of dangling images.
//!
//! The pre-update backup gate runs first and a failed gate aborts. Core has no
//! guard API a plugin can call yet (orca#767), so [`backup_gate`] is the seam:
//! it reports `Unavailable` today and execute refuses unless the caller passes
//! `skip_backup_gate`.
//!
//! Dry run by default. The plan's change targets are `host:packages`,
//! `stack:<name>` and `image:<id>` (images dangling now). Execute takes those
//! targets back and acts only on the ones still valid. Images the update
//! itself leaves dangling (the ones the pulls replaced) are pruned too. They
//! cannot be listed in advance, and the confirmed stacks produce them.
#![allow(clippy::disallowed_types)]

use std::collections::{HashMap, HashSet};

use bollard::Docker;
use bollard::query_parameters::ListContainersOptionsBuilder;
use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::prelude::*;
use plugin_toolkit::process::Command;

use crate::execute;
use crate::prune::{self, COMPOSE_PROJECT_LABEL, PruneApplied, Skipped};
use crate::stacks::{self, StackRow};

const TOOL: &str = "docker.host_update";
const PACKAGES_TARGET: &str = "host:packages";
const OS_RELEASE: &str = "/etc/os-release";

/// The OS package manager this verb drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgManager {
    Apk,
    Apt,
}

impl PkgManager {
    /// From `/etc/os-release` contents: Alpine is apk, Debian and its
    /// derivatives (`ID` or `ID_LIKE`) are apt. Anything else is unsupported.
    pub fn detect(os_release: &str) -> Option<Self> {
        let field = |key: &str| {
            os_release.lines().find_map(|l| {
                l.strip_prefix(key)
                    .and_then(|v| v.strip_prefix('='))
                    .map(|v| v.trim_matches('"').to_ascii_lowercase())
            })
        };
        let id = field("ID").unwrap_or_default();
        let like = field("ID_LIKE").unwrap_or_default();
        if id == "alpine" {
            return Some(PkgManager::Apk);
        }
        let debian = ["debian", "ubuntu"];
        if debian.contains(&id.as_str()) || like.split_whitespace().any(|l| debian.contains(&l)) {
            return Some(PkgManager::Apt);
        }
        None
    }

    /// The commands run in order; any failure aborts the update.
    pub fn commands(self) -> Vec<Vec<&'static str>> {
        match self {
            PkgManager::Apk => vec![vec!["apk", "update"], vec!["apk", "upgrade"]],
            PkgManager::Apt => vec![
                vec!["apt-get", "update"],
                // Keep the host's edited config files rather than prompting.
                vec![
                    "apt-get",
                    "-y",
                    "-o",
                    "Dpkg::Options::=--force-confold",
                    "upgrade",
                ],
            ],
        }
    }
}

/// What the pre-update backup gate reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateStatus {
    Passed(String),
    Failed(String),
    /// There is no gate to run.
    Unavailable(String),
}

/// The pre-update backup gate. Core exposes no guard API to plugins yet.
pub async fn backup_gate() -> GateStatus {
    GateStatus::Unavailable(
        "the pre-update backup gate needs orca#767 (core guard wiring), which has not landed"
            .to_string(),
    )
}

/// Whether the update may proceed past the gate.
pub fn check_gate(status: &GateStatus, skip: bool) -> Result<String> {
    match status {
        GateStatus::Passed(msg) => Ok(msg.clone()),
        GateStatus::Failed(why) => bail!("{TOOL}: backup gate failed, update aborted: {why}"),
        GateStatus::Unavailable(_) if skip => {
            Ok("backup gate skipped by skip_backup_gate".to_string())
        }
        GateStatus::Unavailable(why) => {
            bail!("{TOOL}: {why}; back up by other means and pass skip_backup_gate to proceed")
        }
    }
}

/// Pull and up one stack. A seam so the per-stack loop is testable without a
/// docker CLI.
pub trait StackRunner: Send + Sync {
    fn pull<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<String>>;
    fn up<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<String>>;
}

struct ComposeRunner;

impl StackRunner for ComposeRunner {
    fn pull<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { Ok(row.compose()?.pull(&[]).await?) })
    }
    fn up<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { Ok(row.compose()?.up(&[]).await?) })
    }
}

/// One step's outcome.
#[orca_struct]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    pub ok: bool,
    pub output: String,
}

impl StepReport {
    fn from_result(r: Result<String>) -> Self {
        match r {
            Ok(out) => Self {
                ok: true,
                output: out.trim().to_string(),
            },
            Err(e) => Self {
                ok: false,
                output: e.to_string(),
            },
        }
    }
}

/// Per-stack outcome. `up` is absent when the pull failed.
#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone)]
pub struct StackReport {
    pub stack: String,
    pub pull: StepReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up: Option<StepReport>,
}

/// Pull then up each stack. A failed stack does not stop the others.
pub async fn update_stacks(runner: &dyn StackRunner, rows: &[StackRow]) -> Vec<StackReport> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let pull = StepReport::from_result(runner.pull(row).await);
        let up = if pull.ok {
            Some(StepReport::from_result(runner.up(row).await))
        } else {
            None
        };
        out.push(StackReport {
            stack: row.name.clone(),
            pull,
            up,
        });
    }
    out
}

/// The record of an executed host update.
#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone)]
pub struct HostUpdateApplied {
    /// Always `false`: changes were applied.
    pub dry_run: bool,
    pub backup_gate: String,
    /// Absent when `host:packages` was not confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packages: Option<Vec<StepReport>>,
    pub stacks: Vec<StackReport>,
    /// Confirmed targets that were no longer valid.
    pub skipped: Vec<Skipped>,
    pub prune: PruneApplied,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(untagged)]
pub enum HostUpdateChange {
    Plan(ExecutionPlan),
    Applied(HostUpdateApplied),
}

/// Enabled stacks with at least one running service.
async fn running_stacks() -> Result<Vec<StackRow>> {
    let mut out = Vec::new();
    for row in stacks::list()?.into_iter().filter(|r| r.enabled) {
        let Ok(compose) = row.compose() else { continue };
        let running = compose
            .services()
            .await
            .map(|s| s.iter().any(|s| s.running))
            .unwrap_or(false);
        if running {
            out.push(row);
        }
    }
    Ok(out)
}

fn stack_target(name: &str) -> String {
    format!("stack:{name}")
}

/// Build the dry-run plan.
pub fn plan<A: Serialize>(
    args: &A,
    pkg: Option<PkgManager>,
    gate: &GateStatus,
    running: &[StackRow],
    dangling: &[prune::Candidate],
) -> Result<ExecutionPlan> {
    let inputs = plugin_toolkit::serde_json::to_value(args)?;
    let mut changes = Vec::new();
    let gate_detail = match gate {
        GateStatus::Passed(m) => format!("passes: {m}"),
        GateStatus::Failed(m) => format!("fails, so execute will abort: {m}"),
        GateStatus::Unavailable(m) => format!("{m}; execute needs skip_backup_gate"),
    };
    changes.push(PlannedChange::new("backup-gate", "run").with_detail(gate_detail));
    match pkg {
        Some(p) => {
            let cmds: Vec<String> = p.commands().iter().map(|c| c.join(" ")).collect();
            changes.push(
                PlannedChange::new(PACKAGES_TARGET, "upgrade").with_detail(cmds.join(" && ")),
            );
        }
        None => changes.push(
            PlannedChange::new("host:packages-unsupported", "skip")
                .with_detail("no apk or apt on this host; packages are not upgraded"),
        ),
    }
    for row in running {
        changes.push(
            PlannedChange::new(stack_target(&row.name), "pull+up")
                .with_detail("compose pull -q && compose up -d --remove-orphans"),
        );
    }
    for c in dangling {
        changes.push(PlannedChange::new(&c.key, "remove").with_detail(&c.detail));
    }
    let summary = format!(
        "update host: packages{}, {} running stack(s), prune {} dangling image(s) plus any the pulls replace",
        if pkg.is_some() { "" } else { " (unsupported)" },
        running.len(),
        dangling.len()
    );
    let mut p = ExecutionPlan::generic(TOOL, inputs.into()).detailed(summary, changes);
    p.how_to_execute = format!(
        "re-invoke {TOOL} with `execute: true` and `items` set to the change targets to apply (host:packages, stack:*, image:*)"
    );
    Ok(p)
}

async fn project_of(row: &StackRow) -> Result<String> {
    Ok(row.compose()?.project_name().await?)
}

/// Image ids used by a compose project's containers, running or stopped.
async fn project_images(docker: &Docker, project: &str) -> Result<HashSet<String>> {
    let filters = HashMap::from([("label", vec![format!("{COMPOSE_PROJECT_LABEL}={project}")])]);
    let containers = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::new()
                .all(true)
                .filters(&filters)
                .build(),
        ))
        .await
        .map_err(|e| anyhow!("list containers of {project}: {e}"))?;
    Ok(containers.into_iter().filter_map(|c| c.image_id).collect())
}

/// Image keys to prune after the update: confirmed images, plus images the
/// updated stacks used before and are dangling now.
pub fn prune_keys(
    confirmed_images: &[String],
    replaced: &HashSet<String>,
    dangling_now: &[prune::Candidate],
) -> Vec<String> {
    let mut keys: Vec<String> = confirmed_images.to_vec();
    for c in dangling_now {
        if replaced.contains(&c.id) && !keys.contains(&c.key) {
            keys.push(c.key.clone());
        }
    }
    keys
}

async fn run_packages(pkg: PkgManager) -> Result<Vec<StepReport>> {
    let mut out = Vec::new();
    for cmd in pkg.commands() {
        let output = Command::new(cmd[0])
            .args(&cmd[1..])
            .env("DEBIAN_FRONTEND", "noninteractive")
            .output()
            .await
            .with_context(|| format!("spawn {}", cmd.join(" ")))?;
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !output.status.success {
            bail!(
                "{TOOL}: `{}` failed, update aborted before touching stacks: {}",
                cmd.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        out.push(StepReport {
            ok: true,
            output: text,
        });
    }
    Ok(out)
}

#[orca_struct(args)]
pub struct DockerHostUpdateArgs {
    /// Proceed without the pre-update backup gate. Needed until core exposes
    /// the gate (orca#767); back up by other means first.
    #[arg(long)]
    #[serde(default)]
    pub skip_backup_gate: bool,
    /// The plan's change targets to apply (execute only). Comma-separated on
    /// the CLI.
    #[arg(long, value_delimiter = ',')]
    #[serde(default)]
    pub items: Vec<String>,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// **Update this docker host**: upgrade OS packages (apk/apt), then
/// `compose pull -q` + `up -d --remove-orphans` for every running stack, then
/// prune dangling images. The pre-update backup gate runs first; a failed gate
/// aborts. Without `execute`, returns the plan and changes nothing.
#[orca_tool(
    domain = "docker",
    verb = "host_update",
    role = "admin",
    execute_gated = false
)]
async fn docker_host_update(args: DockerHostUpdateArgs, ctx: &ToolCtx) -> Result<HostUpdateChange> {
    execute::guard(TOOL, args.execute, ctx)?;
    let pkg = std::fs::read_to_string(OS_RELEASE)
        .ok()
        .and_then(|s| PkgManager::detect(&s));
    let gate = backup_gate().await;
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;

    if !args.execute {
        let running = running_stacks().await?;
        let dangling = prune::dangling_images(docker).await?;
        return Ok(HostUpdateChange::Plan(plan(
            &args, pkg, &gate, &running, &dangling,
        )?));
    }

    let backup_gate = check_gate(&gate, args.skip_backup_gate)?;

    let running = running_stacks().await?;
    let mut current: Vec<String> = running.iter().map(|r| stack_target(&r.name)).collect();
    if pkg.is_some() {
        current.push(PACKAGES_TARGET.to_string());
    }
    let confirmed_images: Vec<String> = args
        .items
        .iter()
        .filter(|i| i.starts_with("image:"))
        .cloned()
        .collect();
    let others: Vec<String> = args
        .items
        .iter()
        .filter(|i| !i.starts_with("image:"))
        .cloned()
        .collect();
    execute::require_confirmed(TOOL, &args.items, &current)?;
    let (act, dropped) = execute::intersect(&others, &current);
    let skipped = dropped
        .into_iter()
        .map(|item| Skipped {
            item,
            reason: "no longer valid on this host".into(),
        })
        .collect();

    let packages = match pkg {
        Some(p) if act.iter().any(|a| a == PACKAGES_TARGET) => Some(run_packages(p).await?),
        _ => None,
    };

    let rows: Vec<StackRow> = running
        .into_iter()
        .filter(|r| act.contains(&stack_target(&r.name)))
        .collect();
    let mut replaced = HashSet::new();
    for row in &rows {
        if let Ok(project) = project_of(row).await {
            replaced.extend(project_images(docker, &project).await.unwrap_or_default());
        }
    }
    let stacks = update_stacks(&ComposeRunner, &rows).await;

    let dangling_now = prune::dangling_images(docker).await?;
    let keys = prune_keys(&confirmed_images, &replaced, &dangling_now);
    let prune = if keys.is_empty() {
        PruneApplied::default()
    } else {
        // `keys` are images only; the default scope also withholds networks.
        prune::apply(docker, prune::Scope::default(), &keys).await?
    };

    Ok(HostUpdateChange::Applied(HostUpdateApplied {
        dry_run: false,
        backup_gate,
        packages,
        stacks,
        skipped,
        prune,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn detects_apk_and_apt_hosts() {
        assert_eq!(
            PkgManager::detect("NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\n"),
            Some(PkgManager::Apk)
        );
        assert_eq!(PkgManager::detect("ID=debian\n"), Some(PkgManager::Apt));
        assert_eq!(
            PkgManager::detect("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n"),
            Some(PkgManager::Apt)
        );
        assert_eq!(PkgManager::detect("ID=fedora\n"), None);
        // `ID_LIKE` must not be read as `ID`.
        assert_eq!(PkgManager::detect("ID_LIKE=alpine\nID=other\n"), None);
    }

    #[test]
    fn package_commands_are_noninteractive_upgrades() {
        assert_eq!(
            PkgManager::Apk.commands(),
            vec![vec!["apk", "update"], vec!["apk", "upgrade"]]
        );
        let apt = PkgManager::Apt.commands();
        assert_eq!(apt[0], vec!["apt-get", "update"]);
        assert!(apt[1].contains(&"-y") && apt[1].last() == Some(&"upgrade"));
    }

    #[test]
    fn unavailable_gate_blocks_unless_skipped() {
        let gate = plugin_toolkit::reactor::block_on(backup_gate());
        let err = check_gate(&gate, false).unwrap_err();
        assert!(err.to_string().contains("orca#767"), "{err}");
        assert!(check_gate(&gate, true).is_ok());
    }

    #[test]
    fn failed_gate_aborts_even_when_skip_is_set() {
        let gate = GateStatus::Failed("pbs unreachable".into());
        let err = check_gate(&gate, true).unwrap_err();
        assert!(err.to_string().contains("aborted"), "{err}");
    }

    fn row(name: &str) -> StackRow {
        StackRow {
            name: name.into(),
            dir: format!("/srv/{name}"),
            file: "docker-compose.yml".into(),
            enabled: true,
        }
    }

    struct FakeRunner {
        fail_pull: &'static str,
        calls: Mutex<Vec<String>>,
    }

    impl StackRunner for FakeRunner {
        fn pull<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<String>> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("pull {}", row.name));
            let fail = row.name == self.fail_pull;
            Box::pin(async move {
                if fail {
                    bail!("pull access denied")
                }
                Ok("pulled".to_string())
            })
        }
        fn up<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<String>> {
            self.calls.lock().unwrap().push(format!("up {}", row.name));
            Box::pin(async { Ok("started".to_string()) })
        }
    }

    #[test]
    fn a_failed_pull_skips_that_stack_up_and_continues() {
        let runner = FakeRunner {
            fail_pull: "b",
            calls: Mutex::new(Vec::new()),
        };
        let reports = plugin_toolkit::reactor::block_on(update_stacks(
            &runner,
            &[row("a"), row("b"), row("c")],
        ));
        assert_eq!(
            *runner.calls.lock().unwrap(),
            vec!["pull a", "up a", "pull b", "pull c", "up c"]
        );
        assert!(reports[0].pull.ok && reports[0].up.as_ref().unwrap().ok);
        assert!(!reports[1].pull.ok && reports[1].up.is_none());
        assert!(reports[1].pull.output.contains("denied"));
        assert!(reports[2].up.as_ref().unwrap().ok);
    }

    fn candidate(id: &str) -> prune::Candidate {
        prune::Candidate {
            key: format!("image:{id}"),
            kind: prune::ResourceKind::Image,
            id: id.into(),
            detail: String::new(),
        }
    }

    #[test]
    fn prune_takes_confirmed_images_plus_ones_the_update_replaced() {
        let replaced: HashSet<String> = ["sha256:old".to_string()].into();
        let dangling = [candidate("sha256:old"), candidate("sha256:unrelated")];
        let keys = prune_keys(&["image:sha256:planned".to_string()], &replaced, &dangling);
        assert_eq!(keys, vec!["image:sha256:planned", "image:sha256:old"]);
    }

    #[test]
    fn plan_lists_gate_packages_stacks_and_images() {
        let gate = plugin_toolkit::reactor::block_on(backup_gate());
        let p = plan(
            &plugin_toolkit::serde_json::json!({}),
            Some(PkgManager::Apk),
            &gate,
            &[row("media")],
            &[candidate("sha256:dead")],
        )
        .unwrap();
        assert!(p.dry_run && p.detailed);
        let targets: Vec<_> = p.changes.iter().map(|c| c.target.as_str()).collect();
        assert_eq!(
            targets,
            vec![
                "backup-gate",
                "host:packages",
                "stack:media",
                "image:sha256:dead"
            ]
        );
        assert!(p.changes[0].detail.as_deref().unwrap().contains("orca#767"));
    }

    #[test]
    fn plan_on_an_unsupported_host_says_packages_are_skipped() {
        let gate = GateStatus::Passed("ok".into());
        let p = plan(
            &plugin_toolkit::serde_json::json!({}),
            None,
            &gate,
            &[],
            &[],
        )
        .unwrap();
        assert!(
            p.changes
                .iter()
                .any(|c| c.target == "host:packages-unsupported")
        );
        assert!(!p.changes.iter().any(|c| c.target == PACKAGES_TARGET));
    }
}
