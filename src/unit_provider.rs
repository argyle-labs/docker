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
//!   "logs"` → tail logs; `query.kind = "audit"` → lint findings (see
//!   [`crate::lint`]); `query.kind = "coverage"` → named-volume backup
//!   coverage (see [`crate::volume_coverage`])
//! - [`Verb::Update`] → **edit** (action `edit`, rewrite YAML/env, no deploy),
//!   **fix** (rewrite lint findings, dry run by default), **volume_policy**
//!   (declare how a named volume is backed up), **label_volumes** (convert
//!   anonymous volumes into labeled named ones, see [`crate::ownership`]), or
//!   lifecycle (`up` regenerates `compose.orca.yaml` first; `up` /
//!   `down` / `start` / `stop` / `restart` / `build` / `pull`)
//! - [`Verb::Create`] → action `deploy`: register + write + `up` (add-only)
//! - [`Verb::Upsert`] → action `set`: register-or-replace, then deploy
//! - [`Verb::Delete`] → deregister the stack (leaves containers running)

use plugin_toolkit::anyhow::{self, Result};
use plugin_toolkit::containers::{AdapterError, Container, ListFilter, LogTail, RuntimeAdapter};
use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::backup::{BackupRef, BackupSpec, BackupStrategy, RestorePayload};
use plugin_toolkit::contract::plan::PlannedChange;
use plugin_toolkit::contract::unit::{
    ACTION_BACKUP, ACTION_RESTORE, ActionDecl, ActionOutcome, CreateArgs, DeleteArgs, DetailArgs,
    ItemOutcome, ItemsOutcome, KindDeclaration, ListArgs, UnitDescriptor, UnitId, UnitProvider,
    UpdateArgs, UpsertArgs, Verb, VerbArgs, VerbDecl, VerbOutcome,
};
use plugin_toolkit::schemars::{JsonSchema, schema_for};
use plugin_toolkit::serde::{Deserialize, Serialize};
use plugin_toolkit::serde_json;

use crate::compose::ORCA_FILE;
use crate::compose_config::ComposeConfig;
use crate::engine_state;
use crate::lint::{self, Finding, NotFixed};
use crate::ownership::{self, Migrated, Migrator};
use crate::policy;
use crate::runtime_adapter::DockerAdapter;
use crate::stacks::{self, StackRow, StagedRestore};
use crate::volume_coverage::{self, Strategy, VolumePolicy};

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
        if args.query.kind.as_deref() == Some("coverage") {
            let (project, volumes) = self.stack_volumes(&row).await?;
            let policies = volume_coverage::policies(&row.name)?;
            let raw = ownership::refresh(&row)
                .await?
                .config_json()
                .await
                .map_err(anyhow::Error::from)?;
            let cfg = ComposeConfig::parse(&raw)?;
            let docker = self.adapter.client().map_err(adapter_err)?;
            let containers = ownership::project_containers(docker, &project).await?;
            let engine = ownership::engine_volumes(docker).await?;
            let report = volume_coverage::coverage(&row.name, &project, volumes, &policies)
                .with_ownership(ownership::anonymous_volumes(&cfg, &containers), &engine);
            return Ok(VerbOutcome::Item(ItemOutcome::new(
                self.stack_unit_id(&row),
                serde_json::to_string(&report).unwrap_or_default(),
            )));
        }
        if args.query.kind.as_deref() == Some("audit") {
            let q: AuditQuery = match args.query.extra.as_deref() {
                Some(raw) => {
                    serde_json::from_str(raw).map_err(|e| anyhow::anyhow!("audit query: {e}"))?
                }
                None => AuditQuery::default(),
            };
            let roots = lint::managed_roots(q.managed_roots.as_deref());
            let findings = stack_findings(&row, &roots).await?;
            return Ok(VerbOutcome::Item(ItemOutcome::new(
                self.stack_unit_id(&row),
                serde_json::to_string(&StackAudit {
                    name: row.name.clone(),
                    managed_roots: roots,
                    findings,
                })
                .unwrap_or_default(),
            )));
        }
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
            env_keys: env_keys(row.read_env().as_deref().unwrap_or("")),
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
                row.write_checked(
                    p.compose_yaml.as_deref(),
                    p.compose_env.as_deref(),
                    &crate::tools::stacks_roots()?,
                )
                .await?;
                // A stale orca override naming a removed service breaks every
                // compose command, so regenerate the one that exists.
                let mut message = format!("edited stack '{}'", row.name);
                if std::path::Path::new(&row.dir).join(ORCA_FILE).exists()
                    && let Err(e) = ownership::refresh(&row).await
                {
                    message.push_str(&format!("; {ORCA_FILE} not regenerated: {e}"));
                }
                Ok(VerbOutcome::Action(ActionOutcome {
                    changed: true,
                    message,
                }))
            }
            "fix" => self.stack_fix(&args.id, &row, args.payload).await,
            "volume_policy" => self.stack_volume_policy(&args.id, &row, args.payload).await,
            ACTION_BACKUP => self.do_stack_backup(&args.id, &row, args.payload).await,
            ACTION_RESTORE => self.do_stack_restore(&args.id, &row, args.payload).await,
            "label_volumes" => self.stack_label_volumes(&args.id, &row, args.payload).await,
            "up" => {
                let out = ownership::up(&row, &[]).await?;
                Ok(VerbOutcome::Action(ActionOutcome {
                    changed: true,
                    message: format!("stack '{}' up: {}", row.name, out.trim()),
                }))
            }
            action if STACK_LIFECYCLE.contains(&action) => {
                let compose = row.compose().map_err(anyhow::Error::from)?;
                // Only stopping and removing containers needs no check.
                if !matches!(action, "down" | "stop") {
                    policy::gate(&row, &compose).await?;
                }
                let out = compose
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

    /// **fix** — rewrite the fixable lint findings in the compose file through
    /// the edit path. Dry run by default: returns the changes and the diff.
    /// Execute applies only the confirmed `items` that still apply cleanly to
    /// the file as it is now. Does not deploy; run `up` afterwards.
    async fn stack_fix(
        &self,
        id: &UnitId,
        row: &StackRow,
        payload: Option<String>,
    ) -> Result<VerbOutcome> {
        let p: StackFixPayload = match payload {
            Some(raw) => {
                serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("fix payload: {e}"))?
            }
            None => StackFixPayload::default(),
        };
        let roots = lint::managed_roots(None);
        let findings = stack_findings(row, &roots).await?;
        let yaml = row.read_compose()?;
        let override_yaml = row
            .compose()
            .map_err(anyhow::Error::from)?
            .override_file()
            .map(std::fs::read_to_string)
            .transpose()?;
        let (result, new_yaml) = fix_result(&yaml, override_yaml.as_deref(), &findings, &p)?;
        if let Some(new_yaml) = new_yaml {
            row.write_compose_if_unchanged(&new_yaml, &yaml, &crate::tools::stacks_roots()?)
                .await?;
        }
        Ok(VerbOutcome::Item(ItemOutcome::new(
            id.clone(),
            serde_json::to_string(&result).unwrap_or_default(),
        )))
    }

    /// The stack's compose project name and its named volumes, from the
    /// resolved config and the engine.
    async fn stack_volumes(
        &self,
        row: &StackRow,
    ) -> Result<(String, Vec<volume_coverage::StackVolume>)> {
        // Converted volumes are declared only in the orca file.
        let raw = ownership::refresh(row)
            .await?
            .config_json()
            .await
            .map_err(anyhow::Error::from)?;
        let cfg = ComposeConfig::parse(&raw)?;
        let docker = self.adapter.client().map_err(adapter_err)?;
        let engine = volume_coverage::engine_volumes(docker, &cfg.name).await?;
        let mut volumes = volume_coverage::detect(&cfg, &engine);
        volume_coverage::mark_existing(docker, &mut volumes).await?;
        Ok((cfg.name.clone(), volumes))
    }

    /// **label_volumes**: convert the stack's anonymous volumes into labeled
    /// named volumes declared in [`ORCA_FILE`], copying and verifying their
    /// data. Dry run by default; execute acts only on confirmed items that
    /// are still convertible.
    async fn stack_label_volumes(
        &self,
        id: &UnitId,
        row: &StackRow,
        payload: Option<String>,
    ) -> Result<VerbOutcome> {
        let p: LabelVolumesPayload = match payload {
            Some(raw) => serde_json::from_str(&raw)
                .map_err(|e| anyhow::anyhow!("label_volumes payload: {e}"))?,
            None => LabelVolumesPayload::default(),
        };
        let (_, cfg) = ownership::user_config(row).await?;
        let docker = self.adapter.client().map_err(adapter_err)?;
        let containers = ownership::project_containers(docker, &cfg.name).await?;
        let converted = ownership::read_conversions(std::path::Path::new(&row.dir))?;
        let planned = ownership::plan(&cfg, &containers, &converted);
        let warnings = ownership::relabel_warning(&containers)
            .into_iter()
            .collect();
        let migrator = ownership::ComposeMigrator { row, docker };
        let mut result = label_volumes_result(
            docker, &migrator, &cfg.name, &row.name, &planned, &converted, &p,
        )
        .await?;
        result.warnings = warnings;
        Ok(VerbOutcome::Item(ItemOutcome::new(
            id.clone(),
            serde_json::to_string(&result).unwrap_or_default(),
        )))
    }

    /// **volume_policy**: declare (or with no `strategy`, clear) how one named
    /// volume is backed up. Dry run by default.
    async fn stack_volume_policy(
        &self,
        id: &UnitId,
        row: &StackRow,
        payload: Option<String>,
    ) -> Result<VerbOutcome> {
        let raw = payload.ok_or_else(|| anyhow::anyhow!("volume_policy requires a payload"))?;
        let p: VolumePolicyPayload = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("volume_policy payload: {e}"))?;
        let raw_cfg = row
            .compose()
            .map_err(anyhow::Error::from)?
            .config_json()
            .await
            .map_err(anyhow::Error::from)?;
        let cfg = ComposeConfig::parse(&raw_cfg)?;
        let result = volume_policy_result(&row.name, &cfg, &p)?;
        if !result.dry_run {
            match p.strategy {
                Some(strategy) => volume_coverage::put(&VolumePolicy {
                    stack: row.name.clone(),
                    volume: p.volume.clone(),
                    strategy,
                    service: p.service.clone(),
                    command: p.command.clone(),
                })?,
                None => {
                    volume_coverage::remove(&row.name, &p.volume)?;
                }
            }
        }
        Ok(VerbOutcome::Item(ItemOutcome::new(
            id.clone(),
            serde_json::to_string(&result).unwrap_or_default(),
        )))
    }

    /// Minimal backup of a stack: tar its project directory (compose file, `.env`,
    /// and any bind-mounted config under it) into a `.tar.gz`, plus an export or
    /// dump of each named volume with a policy (under `.orca-volumes/`). Data on
    /// external mounts is out of scope (on network storage). Returns a
    /// [`BackupRef`] whose locator is the archive path — a later `restore`
    /// consumes it directly. Routed to the stack's host over the mesh.
    async fn do_stack_backup(
        &self,
        id: &UnitId,
        row: &StackRow,
        payload: Option<String>,
    ) -> Result<VerbOutcome> {
        let p: StackBackupPayload = match payload {
            Some(raw) => {
                serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("backup payload: {e}"))?
            }
            None => StackBackupPayload::default(),
        };
        let dir = std::path::Path::new(&row.dir);
        if !dir.is_dir() {
            return Err(anyhow::anyhow!(
                "stack '{}' dir {} does not exist",
                row.name,
                row.dir
            ));
        }
        let dest = match &p.dest {
            Some(d) => crate::lifecycle::in_backup_root(d, &engine_state::backup_roots())?,
            None => default_backup_dir(dir),
        };
        std::fs::create_dir_all(&dest)
            .map_err(|e| anyhow::anyhow!("create backup dir {}: {e}", dest.display()))?;
        let policies = volume_coverage::policies(&row.name)?;
        let volumes = if policies.is_empty() {
            Vec::new()
        } else {
            self.stack_volumes(row).await?.1
        };
        let compose = row.compose().map_err(anyhow::Error::from)?;
        let docker = self.adapter.client().map_err(adapter_err)?;
        let root = volume_coverage::staging_root(&dest, &row.name)?;
        let ts = plugin_toolkit::time::now().unix_seconds();
        let archive = dest.join(format!("{}-{ts}.tar.gz", row.name));
        let result = async {
            let staged =
                volume_coverage::stage(docker, &root, &compose, &volumes, &policies).await?;
            // The archive holds config and secrets: private from creation, and
            // tar keeps an existing file's mode.
            volume_coverage::create_private(&archive)?;
            let has_staging = !staged.artifacts.is_empty() || !staged.skipped.is_empty();
            let args = tar_args(&archive, &row.dir, &root, has_staging);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            run_tar(&args).await
        }
        .await;
        // Exports can be large; they live on only inside the archive.
        let cleared = std::fs::remove_dir_all(&root)
            .map_err(|e| anyhow::anyhow!("clear {}: {e}", root.display()));
        if result.is_err() && archive.exists() {
            std::fs::remove_file(&archive)
                .map_err(|e| anyhow::anyhow!("remove {}: {e}", archive.display()))?;
        }
        result?;
        cleared?;

        let backup = BackupRef {
            locator: archive.to_string_lossy().into_owned(),
            manager: format!("docker@{}", self.hostname),
            timestamp: ts,
            checksum: None,
        };
        Ok(VerbOutcome::Item(ItemOutcome::new(
            id.clone(),
            serde_json::to_string(&backup).unwrap_or_default(),
        )))
    }

    /// Restore a stack in place from a prior [`BackupRef`]: extract the archive
    /// back over the project directory, then `docker compose up -d` so the running
    /// stack reconciles to the restored compose and returns to service. The
    /// inverse of [`Self::do_stack_backup`], which the RFC pairs it with.
    async fn do_stack_restore(
        &self,
        _id: &UnitId,
        row: &StackRow,
        payload: Option<String>,
    ) -> Result<VerbOutcome> {
        let raw = payload.ok_or_else(|| anyhow::anyhow!("restore requires a payload"))?;
        let p: RestorePayload =
            serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("restore payload: {e}"))?;
        if let Some(component) = &p.component {
            return Err(anyhow::anyhow!(
                "docker stack restore has no component scope (got '{component}')"
            ));
        }
        let archive = p.from.locator;
        if archive.is_empty() {
            return Err(anyhow::anyhow!("restore backup ref has an empty locator"));
        }
        let mut file = restore_source(&archive, &row.dir, &engine_state::backup_roots())?;
        engine_state::validate(&mut file)?;
        let roots = crate::tools::stacks_roots()?;
        let mut staged = StagedRestore::stage(row, &mut file, &roots)?;
        let live = stacks::stack_dir_in_roots(&row.dir, &roots)?;
        let env = staged.env_file();
        let staged_secrets = env
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|e| stacks::env_values(&e))
            .unwrap_or_default();
        let checked = async {
            for files in staged.compose_sets(row) {
                let raw = stacks::resolved_config(&live, &files, env.as_deref()).await?;
                policy::check_stack(&raw, row, &live, &roots)?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(e) = checked {
            // The staged `.env` is discarded with the staging dir, so the
            // caller's scrub of the live one would miss its values.
            let e = anyhow::anyhow!(stacks::redact(&format!("{e:#}"), &staged_secrets));
            return Err(staged.fail(e.context("restore refused; the stack dir is unchanged")));
        }
        let leftover = staged.swap()?;
        let out = ownership::up(row, &[]).await?;
        Ok(VerbOutcome::Action(ActionOutcome {
            changed: true,
            message: format!(
                "restored stack '{}' from {archive}{}; up: {}",
                row.name,
                leftover
                    .map(|p| format!(" (the previous dir is left at {})", p.display()))
                    .unwrap_or_default(),
                out.trim()
            ),
        }))
    }

    /// Shared create/upsert path: register the stack, (optionally) write its
    /// compose/env files, then deploy. `add_only` rejects an existing name.
    async fn stack_deploy(&self, payload: Option<String>, add_only: bool) -> Result<VerbOutcome> {
        let raw = payload.ok_or_else(|| anyhow::anyhow!("deploy requires a payload"))?;
        let p: StackDeployPayload =
            serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("deploy payload: {e}"))?;
        let file = p
            .file
            .clone()
            .unwrap_or_else(|| stacks::DEFAULT_COMPOSE_FILE.to_string());
        stacks::check_file_name(&file)?;
        let roots = crate::tools::stacks_roots()?;
        let dir = stacks::stack_dir_in_roots(&p.dir, &roots)?;
        let current = stacks::get(&p.name)?;
        let existed = current.is_some();
        if add_only && existed {
            return Err(anyhow::anyhow!(
                "stack '{}' already exists; use upsert (action=set) to redeploy",
                p.name
            ));
        }
        let row = StackRow {
            name: p.name.clone(),
            dir: dir.to_string_lossy().into_owned(),
            file,
            enabled: true,
            // Grants are set only through the admin-only `docker.stack_allow`,
            // and stay bound to the services and images they name.
            allow: current
                .as_ref()
                .map(|r| r.allow.clone())
                .unwrap_or_default(),
        };
        row.write_checked(p.compose_yaml.as_deref(), p.compose_env.as_deref(), &roots)
            .await?;
        stacks::put(&row)?;
        if p.deploy {
            ownership::up(&row, &[]).await?;
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
            let name = args.id.id.clone();
            let secrets = stack_secrets(&name, None);
            return scrub_outcome(&name, secrets, self.stack_detail(args).await);
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
            let name = args.id.id.clone();
            let secrets = stack_secrets(&name, args.payload.as_deref());
            return scrub_outcome(&name, secrets, self.stack_update(args).await);
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
            "deploy" => {
                let name = payload_name(args.payload.as_deref());
                let secrets = stack_secrets(&name, args.payload.as_deref());
                scrub_outcome(&name, secrets, self.stack_deploy(args.payload, true).await)
            }
            "exec" => {
                let raw = args.payload.unwrap_or_default();
                let exec: ExecPayload =
                    serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("exec payload: {e}"))?;
                let docker = self.adapter.client().map_err(adapter_err)?;
                let info = docker
                    .inspect_container(&exec.id, None)
                    .await
                    .map_err(|e| anyhow::anyhow!("inspect {}: {e}", exec.id))?;
                let dirs: Vec<String> = stacks::list()?.into_iter().map(|r| r.dir).collect();
                if let Some(why) = exec_refusal(&info, &dirs) {
                    return Err(anyhow::anyhow!("exec in {} refused: {why}", exec.id));
                }
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

    async fn do_delete(&self, args: DeleteArgs) -> Result<VerbOutcome> {
        if args.id.kind == STACK_KIND {
            // Delete is one command: tear the stack down (`compose down`), then
            // deregister it. No separate `action=down` step first.
            let row = stacks::require(&args.id.id)?;
            let secrets = stack_secrets(&row.name, None);
            let teardown = match row.compose() {
                Ok(c) => match c.run_action("down", None, None).await {
                    Ok(out) => {
                        let out = out.trim();
                        if out.is_empty() {
                            "torn down".to_string()
                        } else {
                            format!("torn down ({out})")
                        }
                    }
                    Err(e) => format!("teardown warning: {e}"),
                },
                Err(e) => format!("teardown skipped: {e}"),
            };
            let teardown = stacks::redact(&teardown, &secrets);
            stacks::remove(&args.id.id)?;
            return Ok(VerbOutcome::Action(ActionOutcome {
                changed: true,
                message: format!("stack '{}' {teardown}; deregistered", args.id.id),
            }));
        }
        Err(anyhow::anyhow!(
            "container delete is managed by Compose/CLI; use the docker.delete tool"
        ))
    }

    async fn do_upsert(&self, args: UpsertArgs) -> Result<VerbOutcome> {
        if args.id.kind == STACK_KIND {
            return match args.action.as_str() {
                "set" => {
                    let name = payload_name(args.payload.as_deref());
                    let secrets = stack_secrets(&name, args.payload.as_deref());
                    scrub_outcome(&name, secrets, self.stack_deploy(args.payload, false).await)
                }
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
    /// The keys `.env` sets. Its values are secrets and are never returned.
    pub env_keys: Vec<String>,
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
    /// New compose file contents, checked against the compose policy (see
    /// [`crate::policy`]): settings that reach the host need a grant from
    /// `docker.stack_allow` for their service and image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_yaml: Option<String>,
    /// New `.env` contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_env: Option<String>,
}

/// Payload for `Update{action:"volume_policy"}`.
#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct VolumePolicyPayload {
    /// The compose volume key.
    pub volume: String,
    /// `export` or `dump`; omit to clear the policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<Strategy>,
    /// `dump` only: the service to run the command in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// `dump` only: run with `sh -c` in the service; its stdout is the dump
    /// (e.g. `pg_dumpall -U postgres`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Write the policy. Omitted, returns the change only.
    #[serde(default)]
    pub execute: bool,
}

/// Response for `Update{action:"volume_policy"}`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct VolumePolicyResult {
    /// `true`: nothing was written.
    pub dry_run: bool,
    pub change: PlannedChange,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// Validate a policy change against the stack's config and describe it.
/// Validation runs on the dry run and again on execute, so a policy that has
/// stopped matching the stack is never written.
fn volume_policy_result(
    stack: &str,
    cfg: &ComposeConfig,
    p: &VolumePolicyPayload,
) -> Result<VolumePolicyResult> {
    let target = format!("volume:{stack}/{}", p.volume);
    let change = match p.strategy {
        Some(strategy) => {
            let declared = cfg.volumes.contains_key(&p.volume)
                || cfg.services.values().any(|s| {
                    s.volumes
                        .iter()
                        .any(|m| m.named_volume() == Some(&p.volume))
                });
            if !declared {
                return Err(anyhow::anyhow!(
                    "stack '{stack}' declares no named volume '{}'",
                    p.volume
                ));
            }
            let policy = VolumePolicy {
                stack: stack.to_string(),
                volume: p.volume.clone(),
                strategy,
                service: p.service.clone(),
                command: p.command.clone(),
            };
            policy.validate(cfg)?;
            let detail = match strategy {
                Strategy::Export => "back up by exporting through a helper container".to_string(),
                Strategy::Dump => format!(
                    "back up by running `{}` in service '{}'",
                    p.command.as_deref().unwrap_or_default(),
                    p.service.as_deref().unwrap_or_default()
                ),
            };
            PlannedChange::new(target, "set-policy").with_detail(detail)
        }
        None => PlannedChange::new(target, "clear-policy"),
    };
    Ok(VolumePolicyResult {
        dry_run: !p.execute,
        change,
        how_to_execute: (!p.execute)
            .then(|| "re-invoke action=volume_policy with `execute: true`".to_string()),
    })
}

/// Payload for `Update{action:"label_volumes"}`. No payload is a dry run.
#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct LabelVolumesPayload {
    /// Convert. Omitted, returns the plan only.
    #[serde(default)]
    pub execute: bool,
    /// The dry run's change targets (`<service>:<path>`) to convert.
    #[serde(default)]
    pub items: Vec<String>,
}

/// Response for `Update{action:"label_volumes"}`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct LabelVolumesResult {
    /// `true`: nothing was changed.
    pub dry_run: bool,
    pub changes: Vec<PlannedChange>,
    /// Side effects to expect beyond the changes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// What execute did (absent on a dry run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migrated: Option<Migrated>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

const LABEL_VOLUMES_TOOL: &str = "stack label_volumes";

/// The plan, or on execute the migration of the confirmed items still
/// planned. Confirmed items no longer planned are reported as skipped.
async fn label_volumes_result(
    docker: &bollard::Docker,
    migrator: &dyn Migrator,
    project: &str,
    stack: &str,
    planned: &[ownership::Planned],
    converted: &[ownership::Conversion],
    p: &LabelVolumesPayload,
) -> Result<LabelVolumesResult> {
    let changes: Vec<PlannedChange> = planned.iter().map(ownership::planned_change).collect();
    if !p.execute {
        return Ok(LabelVolumesResult {
            dry_run: true,
            changes,
            warnings: Vec::new(),
            migrated: None,
            how_to_execute: Some(
                "re-invoke action=label_volumes with `execute: true` and `items` set to the change targets; only those still convertible are converted".into(),
            ),
        });
    }
    let current: Vec<String> = planned.iter().map(|x| x.conversion.key()).collect();
    crate::execute::require_confirmed(LABEL_VOLUMES_TOOL, &p.items, &current)?;
    let (act, dropped) = crate::execute::intersect(&p.items, &current);
    let mut migrated =
        ownership::migrate(docker, migrator, project, stack, planned, &act, converted).await;
    migrated
        .skipped
        .extend(dropped.into_iter().map(|item| ownership::NotDone {
            item,
            reason: "no longer an unconverted anonymous volume".into(),
        }));
    Ok(LabelVolumesResult {
        dry_run: false,
        changes,
        warnings: Vec::new(),
        migrated: Some(migrated),
        how_to_execute: None,
    })
}

/// `Detail` `query.extra` for `query.kind = "audit"`.
#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct AuditQuery {
    /// Managed mount roots to judge bind sources against. Default: the
    /// daemon's `ORCA_DOCKER_MANAGED_ROOTS`, else `/mnt/data`, `/mnt/backups`,
    /// `/mnt/downloads`, `/opt/appdata`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_roots: Option<Vec<String>>,
}

/// `Detail` payload when `query.kind = "audit"`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackAudit {
    pub name: String,
    pub managed_roots: Vec<String>,
    pub findings: Vec<Finding>,
}

/// Payload for `Update{action:"fix"}`. Every field defaults: no payload is a
/// dry run.
/// Bind proposals use the daemon's configured managed roots only, so a
/// caller cannot steer a rewrite to a path of its choosing: unknown fields
/// (`managed_roots` included) are refused.
#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde", deny_unknown_fields)]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackFixPayload {
    /// Write the file. Omitted, returns the changes and diff only.
    #[serde(default)]
    pub execute: bool,
    /// The dry run's change targets (finding ids) to apply.
    #[serde(default)]
    pub items: Vec<String>,
}

/// Response for `Update{action:"fix"}`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackFixResult {
    /// `true`: nothing was written.
    pub dry_run: bool,
    /// The rewrites (planned on a dry run, made on execute).
    pub changes: Vec<PlannedChange>,
    /// Line diff of the compose file.
    pub diff: String,
    /// Finding ids written (execute only).
    pub applied: Vec<String>,
    /// Findings that could not be rewritten, and why.
    pub not_fixed: Vec<NotFixed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_to_execute: Option<String>,
}

/// Optional payload for `Update{action:"backup"}`. Every field defaults, so the
/// core pre-mutation guard (which dispatches `backup` with no payload) drives a
/// minimal backup of the stack's project directory.
#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackBackupPayload {
    /// Directory the archive is written to; must resolve inside the daemon's
    /// backup roots (`ORCA_DOCKER_BACKUP_ROOTS`, else `/mnt/backups`). `None`
    /// → a `.orca-backups` sibling of the stack's project directory (a
    /// system-owned WHERE, until the backup target/storage layer resolves it
    /// centrally).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest: Option<String>,
}

/// Payload for `Create{action:"deploy"}` and `Upsert{action:"set"}` — register
/// a stack, optionally (re)write its files, then deploy.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StackDeployPayload {
    /// Unique stack name.
    pub name: String,
    /// Project directory on the host holding the compose file. Must resolve
    /// strictly inside a runtime's `stacks_root` (default `/opt/stacks`).
    pub dir: String,
    /// Compose filename within `dir` (default `docker-compose.yml`); a plain
    /// file name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Compose file contents to write. Omit to register/redeploy an existing
    /// on-disk file unchanged. Either way the config is checked like `edit`'s.
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
    update_actions.push(ActionDecl {
        action: "fix".into(),
        payload_schema: Some(schema_for!(StackFixPayload)),
        response_schema: Some(schema_for!(StackFixResult)),
    });
    update_actions.push(ActionDecl {
        action: "label_volumes".into(),
        payload_schema: Some(schema_for!(LabelVolumesPayload)),
        response_schema: Some(schema_for!(LabelVolumesResult)),
    });
    update_actions.push(ActionDecl {
        action: "volume_policy".into(),
        payload_schema: Some(schema_for!(VolumePolicyPayload)),
        response_schema: Some(schema_for!(VolumePolicyResult)),
    });
    update_actions.extend(STACK_LIFECYCLE.iter().map(|a| ActionDecl {
        action: (*a).into(),
        payload_schema: None,
        response_schema: None,
    }));
    // Minimal backup/restore as managed-unit actions (the pre-mutation guard and
    // scheduler reach these), routed to the stack's host over the mesh.
    update_actions.push(ActionDecl {
        action: ACTION_BACKUP.into(),
        payload_schema: Some(schema_for!(StackBackupPayload)),
        response_schema: Some(schema_for!(BackupRef)),
    });
    update_actions.push(ActionDecl {
        action: ACTION_RESTORE.into(),
        payload_schema: Some(schema_for!(RestorePayload)),
        response_schema: None,
    });

    // A stack's minimal, restore-sufficient state is filesystem paths (its compose
    // project directory). The concrete path is per-instance; the kind declares the
    // strategy. Common caches are excluded.
    let spec = BackupSpec {
        include: Vec::new(),
        exclude: vec![".orca-backups".into()],
        strategies: vec![BackupStrategy::Paths],
    };

    KindDeclaration {
        kind: STACK_KIND.into(),
        backup_spec: Some(spec),
        verbs: vec![
            VerbDecl::list(),
            VerbDecl {
                verb: Verb::Detail,
                query_schema: Some(schema_for!(AuditQuery)),
                actions: vec![],
            },
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

/// Lint findings for a stack's resolved compose config.
async fn stack_findings(row: &StackRow, roots: &[String]) -> Result<Vec<Finding>> {
    let raw = row
        .compose()
        .map_err(anyhow::Error::from)?
        .config_json()
        .await
        .map_err(anyhow::Error::from)?;
    let cfg = ComposeConfig::parse(&raw)?;
    let bound = bound_sources(
        crate::registration::adapter()
            .client()
            .map_err(adapter_err)?,
    )
    .await?;
    Ok(lint::audit(&cfg, &row.dir, roots, &|p| p.exists(), &|p| {
        lint::is_taken(p, &bound)
    }))
}

/// Host paths bind-mounted by any container on this engine.
async fn bound_sources(docker: &bollard::Docker) -> Result<Vec<String>> {
    let all = docker
        .list_containers(Some(
            bollard::query_parameters::ListContainersOptionsBuilder::new()
                .all(true)
                .build(),
        ))
        .await
        .map_err(|e| anyhow::anyhow!("list containers: {e}"))?;
    Ok(all
        .into_iter()
        .flat_map(|c| c.mounts.unwrap_or_default())
        .filter(|m| m.name.is_none())
        .filter_map(|m| m.source)
        .collect())
}

const FIX_TOOL: &str = "stack fix";

/// The plan (dry run) or the record (execute) of a `fix` over `yaml`, plus the
/// file to write when execute changed anything. Pure, so the plan/intersect
/// contract is testable without a compose CLI.
fn fix_result(
    yaml: &str,
    override_yaml: Option<&str>,
    findings: &[Finding],
    p: &StackFixPayload,
) -> Result<(StackFixResult, Option<String>)> {
    let fixable: Vec<String> = findings
        .iter()
        .filter(|f| f.fixable)
        .map(|f| f.id.clone())
        .collect();
    let planned = lint::apply_fixes(yaml, override_yaml, findings, &fixable);
    let change = |id: &String| {
        let f = findings.iter().find(|f| &f.id == id);
        PlannedChange::new(id, "rewrite").with_detail(match f {
            Some(f) => format!(
                "{} → {}",
                f.current,
                f.proposed.as_deref().unwrap_or_default()
            ),
            None => String::new(),
        })
    };
    if !p.execute {
        let result = StackFixResult {
            dry_run: true,
            changes: planned.applied.iter().map(change).collect(),
            diff: lint::diff(yaml, &planned.yaml),
            applied: Vec::new(),
            not_fixed: planned.not_fixed,
            how_to_execute: Some(
                "re-invoke action=fix with `execute: true` and `items` set to the change targets; only those still applicable are written".into(),
            ),
        };
        return Ok((result, None));
    }
    crate::execute::require_confirmed(FIX_TOOL, &p.items, &planned.applied)?;
    let (act, dropped) = crate::execute::intersect(&p.items, &planned.applied);
    let outcome = lint::apply_fixes(yaml, override_yaml, findings, &act);
    let mut not_fixed = outcome.not_fixed;
    not_fixed.extend(dropped.into_iter().map(|id| NotFixed {
        id,
        reason: "no longer a fixable finding".into(),
    }));
    let write = (!outcome.applied.is_empty()).then(|| outcome.yaml.clone());
    let result = StackFixResult {
        dry_run: false,
        changes: outcome.applied.iter().map(change).collect(),
        diff: lint::diff(yaml, &outcome.yaml),
        applied: outcome.applied,
        not_fixed,
        how_to_execute: None,
    };
    Ok((result, write))
}

/// Where a stack backup goes when the caller names no destination: a
/// `.orca-backups` sibling of the stack dir, so the archive is never written
/// inside the directory being archived.
fn default_backup_dir(dir: &std::path::Path) -> std::path::PathBuf {
    dir.parent().unwrap_or(dir).join(".orca-backups")
}

/// Open a restore archive, refused outside the backup roots and outside the
/// stack's own default backup dir, where an un-targeted backup put it.
fn restore_source(archive: &str, stack_dir: &str, roots: &[String]) -> Result<std::fs::File> {
    let default = default_backup_dir(std::path::Path::new(stack_dir));
    let mut allowed = roots.to_vec();
    allowed.push(default.to_string_lossy().into_owned());
    crate::lifecycle::open_archive(archive, &allowed)
}

/// The keys an `.env` file sets, in file order.
fn env_keys(env: &str) -> Vec<String> {
    stacks::env_pairs(env).into_iter().map(|(k, _)| k).collect()
}

/// The `.env` values a stack verb could echo: stack `name`'s now, plus a
/// `compose_env` in `payload`.
fn stack_secrets(name: &str, payload: Option<&str>) -> Vec<String> {
    let mut envs: Vec<String> = stacks::get(name)
        .ok()
        .flatten()
        .and_then(|r| r.read_env())
        .into_iter()
        .collect();
    envs.extend(
        payload
            .and_then(|p| serde_json::from_str::<serde_json::Value>(p).ok())
            .and_then(|v| v.get("compose_env")?.as_str().map(String::from)),
    );
    envs.iter().flat_map(|e| stacks::env_values(e)).collect()
}

fn redact_json(v: &mut serde_json::Value, secrets: &[String]) {
    match v {
        serde_json::Value::String(s) => *s = stacks::redact(s, secrets),
        serde_json::Value::Array(a) => a.iter_mut().for_each(|v| redact_json(v, secrets)),
        serde_json::Value::Object(o) => o.values_mut().for_each(|v| redact_json(v, secrets)),
        _ => {}
    }
}

/// `out` with `secrets`, and the values of stack `name`'s `.env` as it is
/// afterwards, scrubbed from its message, payload or error.
fn scrub_outcome(
    name: &str,
    mut secrets: Vec<String>,
    out: Result<VerbOutcome>,
) -> Result<VerbOutcome> {
    secrets.extend(stack_secrets(name, None));
    match out {
        Ok(VerbOutcome::Action(mut a)) => {
            a.message = stacks::redact(&a.message, &secrets);
            Ok(VerbOutcome::Action(a))
        }
        Ok(VerbOutcome::Item(mut item)) => {
            item.payload = match serde_json::from_str::<serde_json::Value>(&item.payload) {
                Ok(mut v) => {
                    redact_json(&mut v, &secrets);
                    serde_json::to_string(&v).unwrap_or_default()
                }
                Err(_) => stacks::redact(&item.payload, &secrets),
            };
            Ok(VerbOutcome::Item(item))
        }
        Ok(other) => Ok(other),
        Err(e) => Err(anyhow::anyhow!(stacks::redact(&format!("{e:#}"), &secrets))),
    }
}

/// The stack `name` a deploy payload names.
fn payload_name(payload: Option<&str>) -> String {
    payload
        .and_then(|p| serde_json::from_str::<serde_json::Value>(p).ok())
        .and_then(|v| v.get("name")?.as_str().map(String::from))
        .unwrap_or_default()
}

const COMPOSE_WORKING_DIR_LABEL: &str = "com.docker.compose.project.working_dir";

/// Why `exec` into the inspected container is refused, if it is. The unit
/// verbs carry no caller identity (orca#788), so exec is limited to
/// containers of registered stacks, which the compose policy has checked,
/// and refused in any that holds the host: privileged, a host namespace,
/// the docker socket or `SYS_ADMIN`. The gap that remains until the verb
/// carries the caller: any caller can exec in any such container, reading
/// its secrets and data.
fn exec_refusal(
    info: &bollard::models::ContainerInspectResponse,
    stack_dirs: &[String],
) -> Option<String> {
    use bollard::models::HostConfigCgroupnsModeEnum;
    let working_dir = info
        .config
        .as_ref()
        .and_then(|c| c.labels.as_ref())
        .and_then(|l| l.get(COMPOSE_WORKING_DIR_LABEL));
    let registered = working_dir.is_some_and(|wd| {
        let wd = std::path::Path::new(wd);
        stack_dirs.iter().any(|d| {
            wd == std::path::Path::new(d)
                || crate::lifecycle::resolve(std::path::Path::new(d)).is_ok_and(|r| r == wd)
        })
    });
    if !registered {
        return Some("the container is not part of a registered stack".into());
    }
    let hc = info.host_config.clone().unwrap_or_default();
    if hc.privileged == Some(true) {
        return Some("the container is privileged".into());
    }
    for (key, mode) in [
        ("pid", &hc.pid_mode),
        ("ipc", &hc.ipc_mode),
        ("network", &hc.network_mode),
        ("userns", &hc.userns_mode),
        ("uts", &hc.uts_mode),
    ] {
        if mode.as_deref() == Some("host") {
            return Some(format!("the container uses the host {key} namespace"));
        }
    }
    if hc.cgroupns_mode == Some(HostConfigCgroupnsModeEnum::HOST) {
        return Some("the container uses the host cgroup namespace".into());
    }
    if hc.cap_add.iter().flatten().any(|c| {
        let c = c.to_ascii_uppercase();
        matches!(c.strip_prefix("CAP_").unwrap_or(&c), "SYS_ADMIN" | "ALL")
    }) {
        return Some("the container has CAP_SYS_ADMIN".into());
    }
    let sources = info
        .mounts
        .iter()
        .flatten()
        .filter_map(|m| m.source.clone())
        .chain(hc.binds.iter().flatten().cloned());
    for source in sources {
        if source
            .split(':')
            .next()
            .unwrap_or("")
            .ends_with("docker.sock")
        {
            return Some("the container mounts the docker socket".into());
        }
    }
    None
}

/// `tar` arguments for a stack archive: the stack dir (without any stale
/// `.orca-volumes`), plus the staged `.orca-volumes` from `root` when
/// `staged`.
fn tar_args(
    archive: &std::path::Path,
    dir: &str,
    root: &std::path::Path,
    staged: bool,
) -> Vec<String> {
    let mut args = vec![
        "czf".to_string(),
        archive.to_string_lossy().into_owned(),
        format!("--exclude=./{}", volume_coverage::STAGING_DIR),
        "-C".to_string(),
        dir.to_string(),
        ".".to_string(),
    ];
    if staged {
        args.extend([
            "-C".to_string(),
            root.to_string_lossy().into_owned(),
            volume_coverage::STAGING_DIR.to_string(),
        ]);
    }
    args
}

/// Run `tar` through the orca process seam (no runtime named). Used for stack
/// backup/restore; errors carry tar's stderr.
async fn run_tar(args: &[&str]) -> Result<String> {
    use plugin_toolkit::process::Command;
    let out = Command::new("tar").args(args).output().await?;
    if !out.status.success {
        return Err(anyhow::anyhow!(
            "tar {}: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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
                // A container is ephemeral; the stack is the unit of state.
                backup_spec: None,
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
                VerbArgs::Delete(a) => self.do_delete(a).await,
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

    #[test]
    fn stack_declares_backup_restore_actions_and_spec() {
        let stack = stack_declaration();
        // The stack kind declares a paths BackupSpec; container declares none.
        let spec = stack.backup_spec.expect("stack has a backup_spec");
        assert_eq!(spec.strategies, vec![BackupStrategy::Paths]);
        assert!(spec.exclude.iter().any(|e| e == ".orca-backups"));

        let update = stack
            .verbs
            .iter()
            .find(|v| v.verb == Verb::Update)
            .expect("stack has Update verb");
        let backup = update
            .actions
            .iter()
            .find(|a| a.action == ACTION_BACKUP)
            .expect("backup action");
        assert!(backup.payload_schema.is_some() && backup.response_schema.is_some());
        assert!(
            update.actions.iter().any(|a| a.action == ACTION_RESTORE),
            "restore action declared"
        );
    }

    const FIX_YAML: &str =
        "services:\n  app:\n    image: x\n    restart: \"no\"\n  worker:\n    image: y\n";

    fn fix_findings() -> Vec<Finding> {
        let cfg = ComposeConfig::parse(
            r#"{"name":"s","services":{"app":{"restart":"no","volumes":[{"type":"volume","source":"data","target":"/data"}]},"worker":{}}}"#,
        )
        .unwrap();
        lint::audit(&cfg, "/srv/s", &[], &|_| true, &|_| false)
    }

    #[test]
    fn fix_dry_run_returns_changes_and_diff_and_writes_nothing() {
        let (result, write) =
            fix_result(FIX_YAML, None, &fix_findings(), &StackFixPayload::default()).unwrap();
        assert!(result.dry_run && write.is_none());
        let targets: Vec<_> = result.changes.iter().map(|c| c.target.as_str()).collect();
        assert_eq!(targets, vec!["restart:app", "restart:worker"]);
        assert!(
            result.diff.contains("-    restart: \"no\""),
            "{}",
            result.diff
        );
        assert!(result.diff.contains("+    restart: unless-stopped"));
        // The named volume is a finding but not a rewrite.
        assert!(!targets.contains(&"volume:app:data"));
    }

    #[test]
    fn fix_execute_writes_only_confirmed_items_still_applicable() {
        let p = StackFixPayload {
            execute: true,
            items: vec!["restart:app".into(), "restart:gone".into()],
        };
        let (result, write) = fix_result(FIX_YAML, None, &fix_findings(), &p).unwrap();
        assert!(!result.dry_run);
        assert_eq!(result.applied, vec!["restart:app"]);
        assert_eq!(result.not_fixed[0].id, "restart:gone");
        let written = write.expect("a rewrite");
        assert!(written.contains("restart: unless-stopped"));
        // worker was fixable but not confirmed.
        assert!(!written.contains("worker:\n    restart"), "{written}");
    }

    #[test]
    fn fix_refuses_caller_supplied_roots() {
        let err = serde_json::from_str::<StackFixPayload>(
            r#"{"execute":true,"items":["bind:app:/x"],"managed_roots":["/"]}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("managed_roots"), "{err}");
    }

    #[test]
    fn stack_detail_returns_env_keys_never_values() {
        let env = "# comment\nDB_PASSWORD=hunter2\n\nexport TOKEN = abc\nnot a pair\n";
        assert_eq!(env_keys(env), vec!["DB_PASSWORD", "TOKEN"]);
        let schema = serde_json::to_string(&schema_for!(StackDetail)).unwrap();
        assert!(
            schema.contains("env_keys") && !schema.contains("compose_env"),
            "{schema}"
        );
    }

    fn inspected(
        dir: &str,
        host_config: serde_json::Value,
    ) -> bollard::models::ContainerInspectResponse {
        serde_json::from_value(serde_json::json!({
            "Config": {"Labels": {COMPOSE_WORKING_DIR_LABEL: dir}},
            "HostConfig": host_config,
            "Mounts": []
        }))
        .unwrap()
    }

    #[test]
    fn exec_is_limited_to_unprivileged_containers_of_registered_stacks() {
        let dirs = vec!["/opt/stacks/web".to_string()];
        assert_eq!(
            exec_refusal(&inspected("/opt/stacks/web", serde_json::json!({})), &dirs),
            None
        );
        let why = exec_refusal(
            &inspected("/opt/stacks/other", serde_json::json!({})),
            &dirs,
        )
        .unwrap();
        assert!(why.contains("not part of a registered stack"), "{why}");
        let unlabeled: bollard::models::ContainerInspectResponse =
            serde_json::from_value(serde_json::json!({"HostConfig": {}})).unwrap();
        assert!(exec_refusal(&unlabeled, &dirs).is_some());
        for (hc, want) in [
            (serde_json::json!({"Privileged": true}), "privileged"),
            (serde_json::json!({"PidMode": "host"}), "host pid"),
            (serde_json::json!({"IpcMode": "host"}), "host ipc"),
            (serde_json::json!({"NetworkMode": "host"}), "host network"),
            (serde_json::json!({"UsernsMode": "host"}), "host userns"),
            (serde_json::json!({"UTSMode": "host"}), "host uts"),
            (serde_json::json!({"CgroupnsMode": "host"}), "host cgroup"),
            (
                serde_json::json!({"CapAdd": ["CAP_SYS_ADMIN"]}),
                "CAP_SYS_ADMIN",
            ),
            (serde_json::json!({"CapAdd": ["ALL"]}), "CAP_SYS_ADMIN"),
            (
                serde_json::json!({"Binds": ["/var/run/docker.sock:/var/run/docker.sock"]}),
                "docker socket",
            ),
        ] {
            let why = exec_refusal(&inspected("/opt/stacks/web", hc.clone()), &dirs)
                .unwrap_or_else(|| panic!("{hc} was allowed"));
            assert!(why.contains(want), "{hc}: {why}");
        }
        let mut sock = inspected("/opt/stacks/web", serde_json::json!({}));
        sock.mounts = Some(vec![bollard::models::MountPoint {
            source: Some("/run/docker.sock".into()),
            ..Default::default()
        }]);
        assert!(
            exec_refusal(&sock, &dirs)
                .unwrap()
                .contains("docker socket")
        );
    }

    #[test]
    fn fix_execute_without_items_is_refused() {
        let p = StackFixPayload {
            execute: true,
            ..Default::default()
        };
        let err = fix_result(FIX_YAML, None, &fix_findings(), &p).unwrap_err();
        assert!(err.to_string().contains("items from the dry run"), "{err}");
    }

    #[test]
    fn stack_declares_fix_and_an_audit_query() {
        let d = stack_declaration();
        let update = d.verbs.iter().find(|v| v.verb == Verb::Update).unwrap();
        let fix = update.actions.iter().find(|a| a.action == "fix").unwrap();
        assert!(fix.payload_schema.is_some() && fix.response_schema.is_some());
        let detail = d.verbs.iter().find(|v| v.verb == Verb::Detail).unwrap();
        let q = serde_json::to_string(detail.query_schema.as_ref().unwrap()).unwrap();
        assert!(q.contains("managed_roots"));
    }

    fn vp(volume: &str, strategy: Option<Strategy>, execute: bool) -> VolumePolicyPayload {
        VolumePolicyPayload {
            volume: volume.into(),
            strategy,
            service: (strategy == Some(Strategy::Dump)).then(|| "db".into()),
            command: (strategy == Some(Strategy::Dump)).then(|| "pg_dumpall -U postgres".into()),
            execute,
        }
    }

    #[test]
    fn volume_policy_dry_run_describes_and_execute_flags_write() {
        let cfg = ComposeConfig::parse(crate::compose_config::FIXTURE).unwrap();
        let r =
            volume_policy_result("media", &cfg, &vp("pg", Some(Strategy::Dump), false)).unwrap();
        assert!(r.dry_run && r.how_to_execute.is_some());
        assert_eq!(r.change.target, "volume:media/pg");
        assert!(r.change.detail.as_deref().unwrap().contains("pg_dumpall"));
        let r =
            volume_policy_result("media", &cfg, &vp("data", Some(Strategy::Export), true)).unwrap();
        assert!(!r.dry_run);
        let r = volume_policy_result("media", &cfg, &vp("data", None, false)).unwrap();
        assert_eq!(r.change.action, "clear-policy");
    }

    #[test]
    fn volume_policy_rejects_unknown_volumes_and_bad_dumps() {
        let cfg = ComposeConfig::parse(crate::compose_config::FIXTURE).unwrap();
        let err = volume_policy_result("media", &cfg, &vp("nope", Some(Strategy::Export), false))
            .unwrap_err();
        assert!(err.to_string().contains("no named volume"), "{err}");
        let mut p = vp("pg", Some(Strategy::Dump), true);
        p.command = None;
        assert!(volume_policy_result("media", &cfg, &p).is_err());
    }

    #[test]
    fn stack_declares_volume_policy_action() {
        let d = stack_declaration();
        let update = d.verbs.iter().find(|v| v.verb == Verb::Update).unwrap();
        let a = update
            .actions
            .iter()
            .find(|a| a.action == "volume_policy")
            .unwrap();
        assert!(a.payload_schema.is_some() && a.response_schema.is_some());
    }

    #[test]
    fn the_archive_takes_staged_volumes_from_the_run_root_and_never_a_stale_copy() {
        let root = std::path::Path::new("/b/.orca-staging-x");
        let a = tar_args(std::path::Path::new("/b/x.tar.gz"), "/srv/x", root, true);
        assert_eq!(
            a,
            vec![
                "czf",
                "/b/x.tar.gz",
                "--exclude=./.orca-volumes",
                "-C",
                "/srv/x",
                ".",
                "-C",
                "/b/.orca-staging-x",
                ".orca-volumes"
            ]
        );
        assert_eq!(
            tar_args(std::path::Path::new("/b/x.tar.gz"), "/srv/x", root, false).len(),
            6
        );
    }

    #[test]
    fn a_backup_archive_is_private_and_tar_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let stack = dir.path().join("stack");
        std::fs::create_dir_all(&stack).unwrap();
        std::fs::write(stack.join("compose.yaml"), "services: {}\n").unwrap();
        let archive = dir.path().join("x.tar.gz");
        volume_coverage::create_private(&archive).unwrap();
        let args = tar_args(&archive, &stack.to_string_lossy(), dir.path(), false);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        plugin_toolkit::reactor::block_on(run_tar(&args)).unwrap();
        let meta = std::fs::metadata(&archive).unwrap();
        assert!(meta.len() > 0);
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn stack_backup_payload_defaults_and_parses_empty() {
        assert!(StackBackupPayload::default().dest.is_none());
        let p: StackBackupPayload = serde_json::from_str("{}").unwrap();
        assert!(p.dest.is_none());
    }

    struct NoopMigrator;

    impl Migrator for NoopMigrator {
        fn stop<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn start<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn copy<'a>(&'a self, _: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn manifest<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<String>> {
            Box::pin(async { Ok("x".to_string()) })
        }
        fn current_override(&self) -> Result<Option<String>> {
            Ok(None)
        }
        fn write_override<'a>(
            &'a self,
            _: &'a [ownership::Conversion],
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn restore_override(&self, _: Option<&str>) -> Result<()> {
            Ok(())
        }
        fn up<'a>(&'a self, _: &'a str, _: bool) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn label_plan() -> Vec<ownership::Planned> {
        vec![ownership::Planned {
            conversion: ownership::Conversion::new("media", "app", "/cache"),
            old: None,
            running: false,
            blocked: None,
        }]
    }

    fn label_run(
        e: &crate::test_engine::FakeEngine,
        p: LabelVolumesPayload,
    ) -> Result<LabelVolumesResult> {
        plugin_toolkit::reactor::block_on(label_volumes_result(
            &e.client(),
            &NoopMigrator,
            "media",
            "media",
            &label_plan(),
            &[],
            &p,
        ))
    }

    #[test]
    fn label_volumes_dry_run_plans_and_touches_nothing() {
        let e = crate::test_engine::FakeEngine::routed(vec![]);
        let r = label_run(&e, LabelVolumesPayload::default()).unwrap();
        assert!(r.dry_run && r.migrated.is_none() && r.how_to_execute.is_some());
        assert_eq!(r.changes[0].target, "app:/cache");
        assert!(e.requests().is_empty());
    }

    #[test]
    fn label_volumes_execute_needs_items_and_skips_stale_ones() {
        let e = crate::test_engine::FakeEngine::routed(vec![]);
        let err = label_run(
            &e,
            LabelVolumesPayload {
                execute: true,
                items: vec![],
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("items from the dry run"), "{err}");
        let r = label_run(
            &e,
            LabelVolumesPayload {
                execute: true,
                items: vec!["app:/gone".into()],
            },
        )
        .unwrap();
        let m = r.migrated.unwrap();
        assert!(m.converted.is_empty());
        assert_eq!(m.skipped[0].item, "app:/gone");
        assert!(e.requests().is_empty());
    }

    #[test]
    fn stack_declares_label_volumes_action() {
        let d = stack_declaration();
        let update = d.verbs.iter().find(|v| v.verb == Verb::Update).unwrap();
        let a = update
            .actions
            .iter()
            .find(|a| a.action == "label_volumes")
            .unwrap();
        assert!(a.payload_schema.is_some() && a.response_schema.is_some());
    }

    fn path(p: &std::path::Path) -> String {
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn restore_reads_only_from_the_backup_roots_or_the_stacks_own_backups() {
        let roots_dir = tempfile::tempdir().unwrap();
        let stacks = tempfile::tempdir().unwrap();
        let stack = stacks.path().join("web");
        std::fs::create_dir_all(stacks.path().join(".orca-backups")).unwrap();
        let roots = [path(roots_dir.path())];
        let own = stacks.path().join(".orca-backups/web-1.tar.gz");
        let rooted = roots_dir.path().join("web.tar.gz");
        for archive in [&own, &rooted] {
            std::fs::write(archive, b"x").unwrap();
            restore_source(&path(archive), &path(&stack), &roots).unwrap();
        }
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("web.tar.gz"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.path(), roots_dir.path().join("escape")).unwrap();
        for bad in [
            path(&outside.path().join("web.tar.gz")),
            format!("{}/../x.tar.gz", path(roots_dir.path())),
            path(&roots_dir.path().join("escape/web.tar.gz")),
            "web.tar.gz".to_string(),
        ] {
            assert!(
                restore_source(&bad, &path(&stack), &roots).is_err(),
                "{bad}"
            );
        }
    }

    fn register_root(root: &std::path::Path) {
        let args = crate::tools::DockerCreateArgs {
            name: "local".into(),
            socket_path: None,
            host: None,
            url: None,
            stacks_root: Some(path(root)),
            routes: Vec::new(),
            execute: true,
        };
        plugin_toolkit::reactor::block_on(crate::tools::docker_create(
            args,
            &crate::test_support::admin(),
        ))
        .unwrap();
    }

    /// The stack `web` registered at `dir`, with `yaml` and `env` on disk.
    fn registered_stack(dir: &std::path::Path, yaml: &str, env: Option<&str>) -> StackRow {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("compose.yaml"), yaml).unwrap();
        if let Some(env) = env {
            std::fs::write(dir.join(".env"), env).unwrap();
        }
        let row = StackRow {
            name: "web".into(),
            dir: path(dir),
            file: "compose.yaml".into(),
            enabled: true,
            allow: Vec::new(),
        };
        stacks::put(&row).unwrap();
        row
    }

    fn stack_update(action: &str, payload: Option<serde_json::Value>) -> Result<VerbOutcome> {
        let provider = DockerUnitProvider::new(crate::registration::adapter());
        plugin_toolkit::reactor::block_on(provider.do_update(UpdateArgs {
            id: UnitId {
                manager: "docker@test".into(),
                kind: STACK_KIND.into(),
                id: "web".into(),
                name: "web".into(),
            },
            action: action.into(),
            payload: payload.map(|p| p.to_string()),
            caller: None,
        }))
    }

    /// A stack archive in `<dir>/.orca-backups`, where a backup without
    /// `dest` puts it, holding `files`.
    fn stack_archive(dir: &std::path::Path, files: &[(&str, &str)]) -> serde_json::Value {
        let backups = dir.join(".orca-backups");
        std::fs::create_dir_all(&backups).unwrap();
        let archive = backups.join("web-1.tar.gz");
        let gz = flate2::write::GzEncoder::new(
            std::fs::File::create(&archive).unwrap(),
            flate2::Compression::default(),
        );
        let mut b = tar::Builder::new(gz);
        for (name, body) in files {
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_size(body.len() as u64);
            h.set_cksum();
            b.append_data(&mut h, name, body.as_bytes()).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap();
        serde_json::json!({"from": {"locator": path(&archive), "manager": "docker@test", "timestamp": 0}})
    }

    fn err_of(r: Result<VerbOutcome>) -> String {
        match r {
            Ok(_) => panic!("expected a refusal"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn up_lifecycle_edit_and_restore_refuse_a_stack_outside_the_stacks_roots() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let yaml = "services:\n  app:\n    image: x:1\n";
        let dir = outside.path().join("web");
        let ((), _) = crate::test_support::with_db(|| {
            register_root(root.path());
            let row = registered_stack(&dir, yaml, None);
            let compose = row.compose().unwrap();
            let err = plugin_toolkit::reactor::block_on(policy::gate(&row, &compose))
                .unwrap_err()
                .to_string();
            assert!(err.contains("outside the stacks roots"), "gate: {err}");
            for action in ["start", "restart", "build", "pull"] {
                let err = err_of(stack_update(action, None));
                assert!(err.contains("outside the stacks roots"), "{action}: {err}");
            }
            let edit = serde_json::json!({"compose_yaml": "services: {}\n"});
            let err = err_of(stack_update("edit", Some(edit)));
            assert!(err.contains("outside the stacks roots"), "edit: {err}");
            let restore = stack_archive(outside.path(), &[("compose.yaml", "services: {}\n")]);
            let err = err_of(stack_update(ACTION_RESTORE, Some(restore)));
            assert!(err.contains("outside the stacks roots"), "restore: {err}");
            assert!(stack_update("up", None).is_err());
        });
        let mut left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            ["compose.yaml"],
            "nothing was written in the stack dir"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("compose.yaml")).unwrap(),
            yaml
        );
    }

    #[test]
    fn restore_refuses_an_archive_the_policy_refuses_and_scrubs_its_env_values() {
        if !crate::test_support::have_compose() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let yaml = "services:\n  app:\n    image: x:1\n";
        let dir = root.join("web");
        let ((), _) = crate::test_support::with_db(|| {
            register_root(&root);
            registered_stack(&dir, yaml, None);
            let restore = stack_archive(
                &root,
                &[
                    (
                        "compose.yaml",
                        "services:\n  app:\n    image: x:1\n    privileged: true\n    volumes: [\"${V}:/x\"]\n",
                    ),
                    (".env", "V=/nonexistent/s3cr3tvalue\n"),
                ],
            );
            let err = err_of(stack_update(ACTION_RESTORE, Some(restore)));
            assert!(
                err.contains("restore refused") && err.contains("privileged: true"),
                "{err}"
            );
            assert!(!err.contains("s3cr3tvalue") && err.contains("***"), "{err}");
        });
        let mut left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["compose.yaml"]);
        assert_eq!(
            std::fs::read_to_string(dir.join("compose.yaml")).unwrap(),
            yaml
        );
        let mut siblings: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        siblings.sort();
        assert_eq!(siblings, [".orca-backups", "web"], "no staging dir is left");
    }

    #[test]
    fn stack_verb_errors_never_carry_env_values() {
        if !crate::test_support::have_compose() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let dir = root.join("web");
        let ((), _) = crate::test_support::with_db(|| {
            register_root(&root);
            // Compose names the undefined volume, interpolated from `.env`,
            // in its error.
            registered_stack(
                &dir,
                "services:\n  app:\n    image: x:1\n    volumes: [\"${VOL}:/x\"]\n",
                Some("VOL=hunter2vol\n"),
            );
            let err = err_of(stack_update("restart", None));
            assert!(!err.contains("hunter2vol") && err.contains("***"), "{err}");

            let edit = serde_json::json!({
                "compose_yaml": "services:\n  app:\n    image: x:1\n    volumes: [\"${DIR}:/x\"]\n",
                "compose_env": "DIR=/nonexistent/hunter2dir\n",
            });
            let err = err_of(stack_update("edit", Some(edit)));
            assert!(err.contains("binds host path"), "{err}");
            assert!(!err.contains("hunter2dir") && err.contains("***"), "{err}");
        });
        assert_eq!(
            std::fs::read_to_string(dir.join(".env")).unwrap(),
            "VOL=hunter2vol\n",
            "a refused edit writes nothing"
        );
    }

    fn deploy(payload: plugin_toolkit::serde_json::Value) -> String {
        let provider = DockerUnitProvider::new(crate::registration::adapter());
        plugin_toolkit::reactor::block_on(provider.stack_deploy(Some(payload.to_string()), true))
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn deploy_refuses_dirs_and_files_outside_the_stacks_root_before_writing() {
        use crate::test_support::{admin, with_db};
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
        let root_s = path(root.path());
        let ((), tables) = with_db(|| {
            let args = crate::tools::DockerCreateArgs {
                name: "local".into(),
                socket_path: None,
                host: None,
                url: None,
                stacks_root: Some(root_s.clone()),
                routes: Vec::new(),
                execute: true,
            };
            plugin_toolkit::reactor::block_on(crate::tools::docker_create(args, &admin())).unwrap();
            let yaml = "services: {}\n";
            for dir in [
                path(outside.path()),
                format!("{root_s}/web/../../x"),
                path(&root.path().join("escape/web")),
                root_s.clone(),
            ] {
                let err = deploy(plugin_toolkit::serde_json::json!({
                    "name": "web", "dir": dir, "compose_yaml": yaml
                }));
                assert!(
                    err.contains("outside the stacks roots") || err.contains("contains '..'"),
                    "{dir}: {err}"
                );
            }
            let err = deploy(plugin_toolkit::serde_json::json!({
                "name": "web", "dir": format!("{root_s}/web"), "file": "../x.yml",
                "compose_yaml": yaml
            }));
            assert!(err.contains("plain file name"), "{err}");
        });
        assert!(tables.contains_key(&("docker".into(), "runtime_settings".into())));
        assert!(!tables.contains_key(&("docker".into(), "stacks".into())));
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
        assert!(!root.path().join("web").exists());
    }
}
