//! `docker.host_update` — update a docker host in one verb: OS packages, then
//! every running stack (`compose pull -q` + `up -d`), then a prune of
//! dangling images.
//!
//! The pre-update backup gate runs first and a failed gate aborts. Core has no
//! guard API a plugin can call yet (orca#767), so [`backup_gate`] is the seam:
//! it reports `Unavailable` today and execute refuses unless the caller passes
//! `skip_backup_gate`.
//!
//! Dry run by default. The plan's change targets are `package:<name>` (each
//! upgradable package, from the current package index), `stack:<name>`,
//! `orphan:<stack>/<container>` (containers of services the compose files no
//! longer declare) and `image:<id>` (images dangling now). Execute takes those
//! targets back and acts only on the ones still valid. A stack's orphans are
//! removed (`up --remove-orphans`) only when every current orphan of that
//! stack was confirmed. Images the update itself leaves dangling (the ones the
//! pulls replaced) are pruned too. They cannot be listed in advance, and the
//! confirmed stacks produce them.
#![allow(clippy::disallowed_types)]

use std::collections::{BTreeMap, HashSet};

use bollard::Docker;
use bollard::models::ContainerSummary;
use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::prelude::*;
use plugin_toolkit::process::Command;

use crate::execute;
use crate::ownership::{COMPOSE_ONEOFF_LABEL, COMPOSE_SERVICE_LABEL, project_containers};
use crate::prune::{self, PruneApplied, Skipped};
use crate::stacks::{self, StackRow};

const TOOL: &str = "docker.host_update";
const OS_RELEASE: &str = "/etc/os-release";

/// The OS package manager this verb drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgManager {
    Apk,
    Apt,
}

/// One upgradable package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    /// The package manager's line for it (versions).
    pub detail: String,
}

impl Package {
    fn target(&self) -> String {
        format!("package:{}", self.name)
    }

    /// Upgrading the engine restarts every container on the host.
    pub fn is_engine(&self) -> bool {
        let n = self.name.as_str();
        n == "docker"
            || n == "docker.io"
            || n.starts_with("docker-")
            || n.starts_with("containerd")
            || n.starts_with("moby-")
    }
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

    /// Read-only listing of upgradable packages against the current index.
    pub fn list_command(self) -> Vec<&'static str> {
        match self {
            PkgManager::Apk => vec!["apk", "version", "-l", "<"],
            PkgManager::Apt => vec!["apt", "list", "--upgradable"],
        }
    }

    /// Parse [`list_command`](Self::list_command) output.
    pub fn parse_upgradable(self, out: &str) -> Vec<Package> {
        out.lines()
            .filter_map(|line| {
                let line = line.trim();
                let name = match self {
                    // `docker-ce/bookworm 5:27.3.1-1 amd64 [upgradable from: …]`
                    PkgManager::Apt => line.split_once('/')?.0,
                    // `musl-1.2.5-r0   < 1.2.5-r1`: the name is all but the
                    // trailing `-<version>-r<n>`.
                    PkgManager::Apk => {
                        let (installed, _) = line.split_once(" <")?;
                        let mut parts = installed.trim().rsplitn(3, '-');
                        let (_rel, _ver) = (parts.next()?, parts.next()?);
                        parts.next()?
                    }
                };
                (!name.is_empty() && !name.contains(char::is_whitespace)).then(|| Package {
                    name: name.to_string(),
                    detail: line.to_string(),
                })
            })
            .collect()
    }

    /// The commands that upgrade exactly `names`, run in order; any failure
    /// aborts the update.
    pub fn commands(self, names: &[String]) -> Vec<Vec<String>> {
        let owned = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        match self {
            PkgManager::Apk => {
                let mut upgrade = owned(&["apk", "upgrade"]);
                upgrade.extend(names.iter().cloned());
                vec![owned(&["apk", "update"]), upgrade]
            }
            PkgManager::Apt => {
                // Keep the host's edited config files rather than prompting.
                let mut upgrade = owned(&[
                    "apt-get",
                    "-y",
                    "-o",
                    "Dpkg::Options::=--force-confold",
                    "install",
                    "--only-upgrade",
                    "--no-remove",
                ]);
                upgrade.extend(names.iter().cloned());
                vec![owned(&["apt-get", "update"]), upgrade]
            }
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

/// A container of the project whose service the compose files do not
/// declare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Orphan {
    pub name: String,
    pub id: String,
}

/// Pull, orphan lookup, orphan removal and up for one stack. A seam so the
/// per-stack loop is testable without a docker CLI.
pub trait StackRunner: Send + Sync {
    fn pull<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<String>>;
    fn orphans<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<Vec<Orphan>>>;
    fn remove<'a>(&'a self, orphan: &'a Orphan) -> BoxFuture<'a, Result<()>>;
    fn up<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<String>>;
}

struct ComposeRunner<'d> {
    docker: &'d Docker,
}

impl StackRunner for ComposeRunner<'_> {
    fn pull<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { Ok(row.compose()?.pull(&[]).await?) })
    }
    fn orphans<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<Vec<Orphan>>> {
        Box::pin(async move { stack_orphans(self.docker, &row.compose()?).await })
    }
    fn remove<'a>(&'a self, orphan: &'a Orphan) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.docker
                .stop_container(
                    &orphan.id,
                    None::<bollard::query_parameters::StopContainerOptions>,
                )
                .await
                .or_else(|e| match e {
                    bollard::errors::Error::DockerResponseServerError {
                        status_code: 304, ..
                    } => Ok(()),
                    e => Err(e),
                })
                .map_err(|e| anyhow!("stop {}: {e}", orphan.name))?;
            self.docker
                .remove_container(
                    &orphan.id,
                    None::<bollard::query_parameters::RemoveContainerOptions>,
                )
                .await
                .map_err(|e| anyhow!("remove {}: {e}", orphan.name))
        })
    }
    fn up<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { crate::ownership::up(row, &[]).await })
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
    /// [`from_result`](Self::from_result) with `row`'s `.env` values
    /// scrubbed: compose echoes them in its errors.
    fn redacted(r: Result<String>, row: &StackRow) -> Self {
        let mut report = Self::from_result(r);
        report.output = row.redact(&report.output);
        report
    }

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
    /// Orphan containers removed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orphans_removed: Vec<String>,
    /// Confirmed orphans not removed, and why.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orphans_skipped: Vec<Skipped>,
}

/// A stack to update and the orphan containers confirmed for removal.
#[derive(Debug, Clone)]
pub struct StackJob {
    pub row: StackRow,
    pub remove_orphans: Vec<String>,
}

/// Pull, remove the confirmed orphans, then up each stack. Orphans are
/// looked up again right before removal and removed by id, so only a
/// confirmed container that is still an orphan goes. A failed stack does not
/// stop the others.
pub async fn update_stacks(runner: &dyn StackRunner, jobs: &[StackJob]) -> Vec<StackReport> {
    let mut out = Vec::with_capacity(jobs.len());
    for job in jobs {
        let mut report = StackReport {
            stack: job.row.name.clone(),
            pull: StepReport::redacted(runner.pull(&job.row).await, &job.row),
            up: None,
            orphans_removed: Vec::new(),
            orphans_skipped: Vec::new(),
        };
        if !report.pull.ok {
            out.push(report);
            continue;
        }
        if !job.remove_orphans.is_empty() {
            match runner.orphans(&job.row).await {
                Ok(now) => {
                    for name in &job.remove_orphans {
                        let item = orphan_target(&job.row.name, name);
                        let Some(o) = now.iter().find(|o| &o.name == name) else {
                            report.orphans_skipped.push(Skipped {
                                item,
                                reason: "no longer an orphan".into(),
                            });
                            continue;
                        };
                        match runner.remove(o).await {
                            Ok(()) => report.orphans_removed.push(name.clone()),
                            Err(e) => report.orphans_skipped.push(Skipped {
                                item,
                                reason: e.to_string(),
                            }),
                        }
                    }
                }
                Err(e) => report
                    .orphans_skipped
                    .extend(job.remove_orphans.iter().map(|n| Skipped {
                        item: orphan_target(&job.row.name, n),
                        reason: format!("orphans could not be listed again: {e}"),
                    })),
            }
        }
        report.up = Some(StepReport::redacted(runner.up(&job.row).await, &job.row));
        out.push(report);
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
    /// Absent when no package was confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packages: Option<Vec<StepReport>>,
    pub stacks: Vec<StackReport>,
    /// Confirmed targets that were not acted on, and stacks whose compose
    /// could not be read.
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

/// What the host looks like now: everything the plan lists and execute
/// intersects against.
#[derive(Debug, Clone)]
pub struct HostState {
    /// `Err` when the package listing failed.
    pub packages: std::result::Result<Vec<Package>, String>,
    pub running: Vec<StackRow>,
    /// Orphan containers per running stack.
    pub orphans: BTreeMap<String, Vec<Orphan>>,
    /// Enabled stacks whose compose could not be read.
    pub unreadable: Vec<Skipped>,
}

impl HostState {
    /// Every target execute may act on, except images.
    pub fn targets(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .packages
            .as_ref()
            .map(|p| p.iter().map(Package::target).collect())
            .unwrap_or_default();
        out.extend(self.running.iter().map(|r| stack_target(&r.name)));
        for (stack, orphans) in &self.orphans {
            out.extend(orphans.iter().map(|o| orphan_target(stack, &o.name)));
        }
        out
    }
}

/// Containers of `project` (`containers` is already filtered to it) whose
/// service is not among `services`, as compose judges orphans: `services`
/// includes profile-gated ones, and a container without a service label is
/// an orphan. `compose run` one-offs are not orphans: `up --remove-orphans`
/// leaves them (measured, compose 2.31).
pub fn orphans(containers: &[ContainerSummary], services: &[String]) -> Vec<Orphan> {
    let mut out: Vec<Orphan> = containers
        .iter()
        .filter_map(|c| {
            let labels = c.labels.clone().unwrap_or_default();
            if labels.get(COMPOSE_ONEOFF_LABEL).map(String::as_str) == Some("True") {
                return None;
            }
            if labels
                .get(COMPOSE_SERVICE_LABEL)
                .is_some_and(|s| services.contains(s))
            {
                return None;
            }
            let id = c.id.clone()?;
            let name = c
                .names
                .as_ref()
                .and_then(|n| n.first())
                .map(|n| n.trim_start_matches('/').to_string())
                .unwrap_or_else(|| id.clone());
            Some(Orphan { name, id })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The stack's orphans now.
async fn stack_orphans(docker: &Docker, compose: &crate::Compose) -> Result<Vec<Orphan>> {
    let services = compose.all_service_names().await?;
    let project = compose.project_name().await?;
    Ok(orphans(
        &project_containers(docker, &project).await?,
        &services,
    ))
}

async fn list_packages(pkg: Option<PkgManager>) -> std::result::Result<Vec<Package>, String> {
    let Some(p) = pkg else { return Ok(Vec::new()) };
    let cmd = p.list_command();
    let out = Command::new(cmd[0])
        .args(&cmd[1..])
        .output()
        .await
        .map_err(|e| format!("spawn {}: {e}", cmd.join(" ")))?;
    if !out.status.success {
        return Err(format!(
            "`{}` failed: {}",
            cmd.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(p.parse_upgradable(&String::from_utf8_lossy(&out.stdout)))
}

fn unreadable(row: &StackRow, why: impl std::fmt::Display) -> Skipped {
    Skipped {
        item: stack_target(&row.name),
        reason: format!("compose could not be read: {why}"),
    }
}

/// Read the host: upgradable packages, enabled stacks with a running service
/// and their orphans. A stack whose compose cannot be read is reported, not
/// dropped.
async fn host_state(docker: &Docker, pkg: Option<PkgManager>) -> Result<HostState> {
    let mut state = HostState {
        packages: list_packages(pkg).await,
        running: Vec::new(),
        orphans: BTreeMap::new(),
        unreadable: Vec::new(),
    };
    for row in stacks::list()?.into_iter().filter(|r| r.enabled) {
        let compose = match row.compose() {
            Ok(c) => c,
            Err(e) => {
                state.unreadable.push(unreadable(&row, e));
                continue;
            }
        };
        let services = match compose.services().await {
            Ok(s) => s,
            Err(e) => {
                state.unreadable.push(unreadable(&row, e));
                continue;
            }
        };
        if !services.iter().any(|s| s.running) {
            continue;
        }
        let found = match stack_orphans(docker, &compose).await {
            Ok(o) => o,
            Err(e) => {
                state.unreadable.push(unreadable(&row, e));
                continue;
            }
        };
        if !found.is_empty() {
            state.orphans.insert(row.name.clone(), found);
        }
        state.running.push(row);
    }
    Ok(state)
}

fn stack_target(name: &str) -> String {
    format!("stack:{name}")
}

fn orphan_target(stack: &str, container: &str) -> String {
    format!("orphan:{stack}/{container}")
}

/// Build the dry-run plan.
pub fn plan<A: Serialize>(
    args: &A,
    pkg: Option<PkgManager>,
    gate: &GateStatus,
    state: &HostState,
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
    let mut engine = 0;
    match (pkg, &state.packages) {
        (None, _) => changes.push(
            PlannedChange::new("host:packages-unsupported", "skip")
                .with_detail("no apk or apt on this host; packages are not upgraded"),
        ),
        (Some(_), Err(why)) => changes
            .push(PlannedChange::new("host:packages-unreadable", "skip").with_detail(why.as_str())),
        (Some(_), Ok(packages)) => {
            for p in packages {
                let detail = if p.is_engine() {
                    engine += 1;
                    format!(
                        "{}; ENGINE package: upgrading it restarts every container on this host",
                        p.detail
                    )
                } else {
                    p.detail.clone()
                };
                changes.push(PlannedChange::new(p.target(), "upgrade").with_detail(detail));
            }
        }
    }
    for row in &state.running {
        changes.push(
            PlannedChange::new(stack_target(&row.name), "pull+up")
                .with_detail("compose pull -q && compose up -d"),
        );
        for o in state.orphans.get(&row.name).into_iter().flatten() {
            changes.push(
                PlannedChange::new(orphan_target(&row.name, &o.name), "remove").with_detail(
                    "container of a service the compose files do not declare; removed by id before up, if it is still an orphan then",
                ),
            );
        }
    }
    for s in &state.unreadable {
        changes
            .push(PlannedChange::new(format!("skipped:{}", s.item), "skip").with_detail(&s.reason));
    }
    for c in dangling {
        changes.push(PlannedChange::new(&c.key, "remove").with_detail(&c.detail));
    }
    let package_count = state.packages.as_ref().map(Vec::len).unwrap_or(0);
    let summary = format!(
        "update host: {}, {} running stack(s), {} orphan container(s), {} unreadable stack(s) skipped, prune {} dangling image(s) plus any the pulls replace",
        match pkg {
            Some(_) if engine > 0 =>
                format!("{package_count} package(s) ({engine} engine: restarts every container)"),
            Some(_) => format!("{package_count} package(s)"),
            None => "packages unsupported".to_string(),
        },
        state.running.len(),
        state.orphans.values().map(Vec::len).sum::<usize>(),
        state.unreadable.len(),
        dangling.len()
    );
    let mut p = ExecutionPlan::generic(TOOL, inputs.into()).detailed(summary, changes);
    p.how_to_execute = format!(
        "re-invoke {TOOL} with `execute: true` and `items` set to the change targets to apply (package:*, stack:*, orphan:*, image:*)"
    );
    Ok(p)
}

async fn project_of(row: &StackRow) -> Result<String> {
    Ok(row.compose()?.project_name().await?)
}

/// Image ids used by a compose project's containers, running or stopped.
async fn project_images(docker: &Docker, project: &str) -> Result<HashSet<String>> {
    Ok(project_containers(docker, project)
        .await?
        .into_iter()
        .filter_map(|c| c.image_id)
        .collect())
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

/// The stacks to update, each with its confirmed orphans. Orphans confirmed
/// without their stack are not removed.
pub fn stack_jobs(state: &HostState, act: &[String]) -> (Vec<StackJob>, Vec<Skipped>) {
    let mut jobs = Vec::new();
    let mut skipped = Vec::new();
    for row in &state.running {
        let confirmed: Vec<String> = state
            .orphans
            .get(&row.name)
            .into_iter()
            .flatten()
            .map(|o| o.name.clone())
            .filter(|n| act.contains(&orphan_target(&row.name, n)))
            .collect();
        if !act.contains(&stack_target(&row.name)) {
            skipped.extend(confirmed.iter().map(|n| Skipped {
                item: orphan_target(&row.name, n),
                reason: "its stack was not confirmed".into(),
            }));
            continue;
        }
        jobs.push(StackJob {
            row: row.clone(),
            remove_orphans: confirmed,
        });
    }
    (jobs, skipped)
}

/// What an execute acts on: the confirmed targets still valid now.
#[derive(Debug, Clone)]
pub struct Selection {
    pub packages: Vec<String>,
    pub jobs: Vec<StackJob>,
    pub images: Vec<String>,
    pub skipped: Vec<Skipped>,
}

/// Intersect the confirmed `items` with `state`. Images are handled by the
/// prune, which re-checks them itself.
pub fn select(state: &HostState, items: &[String]) -> Result<Selection> {
    let current = state.targets();
    let images: Vec<String> = items
        .iter()
        .filter(|i| i.starts_with("image:"))
        .cloned()
        .collect();
    let others: Vec<String> = items
        .iter()
        .filter(|i| !i.starts_with("image:"))
        .cloned()
        .collect();
    execute::require_confirmed(TOOL, items, &current)?;
    let (act, dropped) = execute::intersect(&others, &current);
    let mut skipped: Vec<Skipped> = dropped
        .into_iter()
        .map(|item| Skipped {
            item,
            reason: "no longer valid on this host".into(),
        })
        .collect();
    skipped.extend(state.unreadable.iter().cloned());
    let packages = act
        .iter()
        .filter_map(|a| a.strip_prefix("package:"))
        .map(str::to_string)
        .collect();
    let (jobs, kept) = stack_jobs(state, &act);
    skipped.extend(kept);
    Ok(Selection {
        packages,
        jobs,
        images,
        skipped,
    })
}

async fn run_packages(pkg: PkgManager, names: &[String]) -> Result<Vec<StepReport>> {
    let mut out = Vec::new();
    for cmd in pkg.commands(names) {
        let output = Command::new(&cmd[0])
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

/// **Update this docker host**: upgrade the confirmed OS packages (apk/apt),
/// then `compose pull -q` + `up -d` for every confirmed running stack
/// (removing its confirmed orphans by id first), then prune dangling
/// images. The pre-update backup gate runs first; a failed gate aborts.
/// Without `execute`, returns the plan and changes nothing.
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
        let state = host_state(docker, pkg).await?;
        let dangling = prune::dangling_images(docker).await?;
        return Ok(HostUpdateChange::Plan(plan(
            &args, pkg, &gate, &state, &dangling,
        )?));
    }

    let backup_gate = check_gate(&gate, args.skip_backup_gate)?;

    let state = host_state(docker, pkg).await?;
    let Selection {
        packages: names,
        jobs,
        images: confirmed_images,
        skipped,
    } = select(&state, &args.items)?;
    let packages = match pkg {
        Some(p) if !names.is_empty() => Some(run_packages(p, &names).await?),
        _ => None,
    };

    let mut replaced = HashSet::new();
    for job in &jobs {
        if let Ok(project) = project_of(&job.row).await {
            replaced.extend(project_images(docker, &project).await.unwrap_or_default());
        }
    }
    let stacks = update_stacks(&ComposeRunner { docker }, &jobs).await;

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
    fn package_commands_upgrade_only_the_confirmed_names() {
        let names = vec!["musl".to_string(), "docker".to_string()];
        assert_eq!(
            PkgManager::Apk.commands(&names),
            vec![
                vec!["apk", "update"],
                vec!["apk", "upgrade", "musl", "docker"]
            ]
        );
        let apt = PkgManager::Apt.commands(&["curl".to_string()]);
        assert_eq!(apt[0], vec!["apt-get", "update"]);
        assert!(apt[1].contains(&"-y".to_string()));
        assert!(apt[1].ends_with(&[
            "install".into(),
            "--only-upgrade".into(),
            "--no-remove".into(),
            "curl".into()
        ]));
    }

    #[test]
    fn parses_upgradable_packages_and_flags_the_engine() {
        let apt = PkgManager::Apt.parse_upgradable(
            "Listing... Done\ncurl/stable 7.88.1-10+deb12u8 amd64 [upgradable from: 7.88.1-10+deb12u7]\ndocker-ce/bookworm 5:27.3.1-1~debian.12~bookworm amd64 [upgradable from: 5:27.3.0-1]\ncontainerd.io/bookworm 1.7.22-1 amd64 [upgradable from: 1.7.21-1]\n",
        );
        let names: Vec<_> = apt.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["curl", "docker-ce", "containerd.io"]);
        assert!(!apt[0].is_engine() && apt[1].is_engine() && apt[2].is_engine());
        for engine in ["docker.io", "moby-engine", "moby-containerd"] {
            assert!(
                Package {
                    name: engine.into(),
                    detail: String::new()
                }
                .is_engine(),
                "{engine}"
            );
        }
        let apk = PkgManager::Apk.parse_upgradable(
            "Installed:                                Available:\nmusl-1.2.5-r0                           < 1.2.5-r1\npy3-foo-bar-2.0.1-r3                    < 2.0.2-r0\ndocker-27.3.1-r0                        < 27.3.1-r1\n",
        );
        let names: Vec<_> = apk.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["musl", "py3-foo-bar", "docker"]);
        assert!(apk[2].is_engine());
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
            allow: Vec::new(),
        }
    }

    struct FakeRunner {
        fail_pull: &'static str,
        /// Orphans each stack has when looked up again before up.
        now: Vec<(&'static str, &'static str)>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeRunner {
        fn log(&self, s: String) {
            self.calls.lock().unwrap().push(s);
        }
    }

    impl StackRunner for FakeRunner {
        fn pull<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<String>> {
            self.log(format!("pull {}", row.name));
            let fail = row.name == self.fail_pull;
            Box::pin(async move {
                if fail {
                    bail!("pull access denied")
                }
                Ok("pulled".to_string())
            })
        }
        fn orphans<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<Vec<Orphan>>> {
            self.log(format!("orphans {}", row.name));
            let now = self
                .now
                .iter()
                .filter(|(s, _)| *s == row.name)
                .map(|(_, n)| Orphan {
                    name: n.to_string(),
                    id: format!("id-{n}"),
                })
                .collect();
            Box::pin(async move { Ok(now) })
        }
        fn remove<'a>(&'a self, orphan: &'a Orphan) -> BoxFuture<'a, Result<()>> {
            self.log(format!("remove {}", orphan.id));
            Box::pin(async { Ok(()) })
        }
        fn up<'a>(&'a self, row: &'a StackRow) -> BoxFuture<'a, Result<String>> {
            self.log(format!("up {}", row.name));
            Box::pin(async { Ok("started".to_string()) })
        }
    }

    #[test]
    fn a_failed_pull_skips_that_stack_up_and_continues() {
        let runner = FakeRunner {
            fail_pull: "b",
            now: vec![("c", "c-old-1"), ("c", "c-unconfirmed-1")],
            calls: Mutex::new(Vec::new()),
        };
        let job = |n: &str, orphans: &[&str]| StackJob {
            row: row(n),
            remove_orphans: orphans.iter().map(|o| o.to_string()).collect(),
        };
        let reports = plugin_toolkit::reactor::block_on(update_stacks(
            &runner,
            &[
                job("a", &[]),
                job("b", &["b-old-1"]),
                job("c", &["c-old-1"]),
            ],
        ));
        assert_eq!(
            *runner.calls.lock().unwrap(),
            vec![
                "pull a",
                "up a",
                "pull b",
                "pull c",
                "orphans c",
                "remove id-c-old-1",
                "up c"
            ]
        );
        assert!(reports[1].orphans_removed.is_empty(), "b never came up");
        assert_eq!(reports[2].orphans_removed, vec!["c-old-1"]);
        assert!(reports[0].pull.ok && reports[0].up.as_ref().unwrap().ok);
        assert!(!reports[1].pull.ok && reports[1].up.is_none());
        assert!(reports[1].pull.output.contains("denied"));
        assert!(reports[2].up.as_ref().unwrap().ok);
    }

    #[test]
    fn a_confirmed_orphan_that_is_no_longer_one_is_kept() {
        // Between the plan and the up, the stack's file declared its service again.
        let runner = FakeRunner {
            fail_pull: "",
            now: vec![],
            calls: Mutex::new(Vec::new()),
        };
        let reports = plugin_toolkit::reactor::block_on(update_stacks(
            &runner,
            &[StackJob {
                row: row("media"),
                remove_orphans: vec!["media-old-1".into()],
            }],
        ));
        assert!(reports[0].orphans_removed.is_empty());
        assert_eq!(
            reports[0].orphans_skipped[0].item,
            "orphan:media/media-old-1"
        );
        assert!(
            !runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.starts_with("remove"))
        );
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

    fn pkg(name: &str) -> Package {
        Package {
            name: name.into(),
            detail: format!("{name} 1 < 2"),
        }
    }

    fn state() -> HostState {
        HostState {
            packages: Ok(vec![pkg("curl"), pkg("docker-ce")]),
            running: vec![row("media"), row("web")],
            orphans: BTreeMap::from([(
                "media".to_string(),
                vec![
                    Orphan {
                        name: "media-old-1".into(),
                        id: "o1".into(),
                    },
                    Orphan {
                        name: "media-older-1".into(),
                        id: "o2".into(),
                    },
                ],
            )]),
            unreadable: vec![Skipped {
                item: "stack:broken".into(),
                reason: "compose could not be read: no compose file".into(),
            }],
        }
    }

    #[test]
    fn plan_lists_gate_packages_stacks_orphans_unreadable_and_images() {
        let gate = plugin_toolkit::reactor::block_on(backup_gate());
        let p = plan(
            &plugin_toolkit::serde_json::json!({}),
            Some(PkgManager::Apt),
            &gate,
            &state(),
            &[candidate("sha256:dead")],
        )
        .unwrap();
        assert!(p.dry_run && p.detailed);
        let targets: Vec<_> = p.changes.iter().map(|c| c.target.as_str()).collect();
        assert_eq!(
            targets,
            vec![
                "backup-gate",
                "package:curl",
                "package:docker-ce",
                "stack:media",
                "orphan:media/media-old-1",
                "orphan:media/media-older-1",
                "stack:web",
                "skipped:stack:broken",
                "image:sha256:dead"
            ]
        );
        assert!(p.changes[0].detail.as_deref().unwrap().contains("orca#767"));
        assert!(p.changes[2].detail.as_deref().unwrap().contains("ENGINE"));
        assert!(!p.changes[1].detail.as_deref().unwrap().contains("ENGINE"));
        assert!(p.summary.contains("1 engine"), "{}", p.summary);
        assert!(!p.changes[3].detail.as_deref().unwrap().contains("orphans"));
    }

    #[test]
    fn plan_on_an_unsupported_host_says_packages_are_skipped() {
        let gate = GateStatus::Passed("ok".into());
        let mut st = state();
        st.packages = Ok(Vec::new());
        let p = plan(
            &plugin_toolkit::serde_json::json!({}),
            None,
            &gate,
            &st,
            &[],
        )
        .unwrap();
        assert!(
            p.changes
                .iter()
                .any(|c| c.target == "host:packages-unsupported")
        );
        assert!(!p.changes.iter().any(|c| c.target.starts_with("package:")));
    }

    #[test]
    fn targets_cover_packages_stacks_and_orphans_but_not_unreadable_stacks() {
        let t = state().targets();
        assert!(t.contains(&"package:docker-ce".to_string()));
        assert!(t.contains(&"orphan:media/media-old-1".to_string()));
        assert!(!t.iter().any(|x| x.contains("broken")));
    }

    #[test]
    fn select_acts_only_on_confirmed_targets_still_valid() {
        let st = state();
        let sel = select(
            &st,
            &[
                "package:docker-ce".to_string(),
                "package:gone".to_string(),
                "stack:media".to_string(),
                "orphan:media/media-old-1".to_string(),
                "orphan:web/not-an-orphan".to_string(),
                "image:sha256:dead".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(sel.packages, vec!["docker-ce"], "curl was not confirmed");
        assert_eq!(sel.jobs.len(), 1, "web was not confirmed");
        assert_eq!(sel.jobs[0].row.name, "media");
        assert_eq!(sel.jobs[0].remove_orphans, vec!["media-old-1"]);
        assert_eq!(sel.images, vec!["image:sha256:dead"]);
        let skipped: Vec<_> = sel.skipped.iter().map(|s| s.item.as_str()).collect();
        assert!(skipped.contains(&"package:gone"));
        assert!(skipped.contains(&"orphan:web/not-an-orphan"));
        assert!(
            skipped.contains(&"stack:broken"),
            "unreadable stacks are reported"
        );
        assert!(select(&st, &[]).is_err(), "execute needs the plan's items");
    }

    #[test]
    fn orphans_confirmed_without_their_stack_are_not_removed() {
        let st = state();
        let (jobs, skipped) = stack_jobs(
            &st,
            &[
                "orphan:media/media-old-1".to_string(),
                "orphan:media/media-older-1".to_string(),
            ],
        );
        assert!(jobs.is_empty());
        assert_eq!(skipped.len(), 2);
        assert!(skipped[0].reason.contains("stack was not confirmed"));
    }

    fn summary(name: &str, service: Option<&str>, oneoff: bool) -> ContainerSummary {
        let service = service
            .map(|s| format!(r#""{COMPOSE_SERVICE_LABEL}":"{s}","#))
            .unwrap_or_default();
        plugin_toolkit::serde_json::from_str(&format!(
            r#"{{"Id":"{name}","Names":["/{name}"],"Labels":{{{service}"{COMPOSE_ONEOFF_LABEL}":"{}"}}}}"#,
            if oneoff { "True" } else { "False" }
        ))
        .unwrap()
    }

    #[test]
    fn orphans_are_undeclared_services_but_never_compose_run_one_offs() {
        let containers = [
            summary("media-app-1", Some("app"), false),
            summary("media-debug-1", Some("debug"), false),
            summary("media-old-1", Some("old"), false),
            summary("media-unlabeled", None, false),
            summary("media_app_run_1", Some("old"), true),
        ];
        // `debug` is profile-gated: still a declared service.
        let names: Vec<_> = orphans(&containers, &["app".to_string(), "debug".to_string()])
            .into_iter()
            .map(|o| o.name)
            .collect();
        assert_eq!(names, vec!["media-old-1", "media-unlabeled"]);
    }
}
