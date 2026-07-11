//! Docker adapter — talks to the local Docker Engine API via bollard.
//!
//! Wraps [`bollard::Docker`] to satisfy the crate-level [`RuntimeAdapter`]
//! contract. `list()` does one `GET /containers/json?all=1` followed by an
//! inspect per container; inspect-per-container is acceptable for C2 because
//! the §2.1 reconciler probe loop runs at 30s cadence and even 200 inspects
//! complete well under a second on a local Unix socket. Batched/streamed
//! event consumption is a C3+ concern.
//!
//! The adapter is constructed eagerly (no network I/O at `new()`); failures
//! to connect are deferred until the first call, where they surface as
//! [`AdapterError::Unavailable`].

use bollard::Docker;
use bollard::container::LogOutput;
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::models::{
    ContainerStateStatusEnum, MountPoint, RestartPolicy as DockerRestartPolicy,
    RestartPolicyNameEnum,
};
use bollard::query_parameters::{
    InspectContainerOptionsBuilder, ListContainersOptionsBuilder, LogsOptionsBuilder,
};
use plugin_toolkit::async_trait::async_trait;
use std::path::PathBuf;
use std::sync::OnceLock;

use plugin_toolkit::containers::{
    AdapterError, Container, ContainerMount, ContainerState, ExecOutput, ListFilter, LogTail,
    RestartPolicy, RuntimeAdapter, RuntimeKind, local_hostname,
};

/// Local docker adapter. Holds a lazily-initialised `bollard::Docker` client
/// keyed on the standard Unix socket location. The client itself is cheap
/// to clone (it wraps an `Arc<hyper::Client>` internally) but constructing
/// it can fail if the docker socket isn't reachable — we surface that as
/// [`AdapterError::Unavailable`] on the first call rather than at adapter
/// construction time, mirroring how the lxc adapter behaves when `pct`
/// isn't on PATH.
pub struct DockerAdapter {
    client: OnceLock<Docker>,
}

impl DockerAdapter {
    /// Construct a new docker adapter. Does no network I/O; the underlying
    /// bollard client is built on first use.
    pub fn new() -> Self {
        Self {
            client: OnceLock::new(),
        }
    }

    fn client(&self) -> Result<&Docker, AdapterError> {
        if let Some(c) = self.client.get() {
            return Ok(c);
        }
        // `connect_with_defaults` honors `DOCKER_HOST` (colima, rootless, remote
        // engines, TCP) and falls back to the platform default socket/pipe —
        // strictly more capable than the socket-only default, and what makes the
        // adapter reachable against a non-default local engine like colima.
        let built = Docker::connect_with_defaults()
            .map_err(|e| AdapterError::Unavailable(e.to_string()))?;
        // `OnceLock::set` returns `Err(built)` only when another thread won
        // the race; in that case the lock is already populated. Either way
        // the next `get()` returns the live client.
        match self.client.set(built) {
            Ok(()) => {}
            Err(_loser) => {
                // Lost the race — peer thread populated first; their value
                // is fine, ours gets dropped here.
            }
        }
        self.client
            .get()
            .ok_or_else(|| AdapterError::Unavailable("docker client init race lost".into()))
    }
}

impl Default for DockerAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RuntimeAdapter for DockerAdapter {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Docker
    }

    async fn list(&self, filter: &ListFilter) -> Result<Vec<Container>, AdapterError> {
        let client = self.client()?;
        let opts = ListContainersOptionsBuilder::new().all(filter.all).build();
        let summaries = client
            .list_containers(Some(opts))
            .await
            .map_err(map_bollard_err)?;

        let mut out = Vec::with_capacity(summaries.len());
        for summary in summaries {
            // Inspect-per-container in C2 — see module-level rationale.
            let id = match summary.id.clone() {
                Some(i) => i,
                None => {
                    // ContainerSummary.id is documented as always populated;
                    // a missing one is a real wire-protocol problem we want
                    // visible, not silently skipped.
                    return Err(AdapterError::Malformed(
                        "docker container summary missing id".into(),
                    ));
                }
            };
            match self.inspect(&id).await {
                Ok(c) => {
                    if labels_match(&c.labels, &filter.labels) {
                        out.push(c);
                    }
                }
                Err(AdapterError::NotFound(_)) => {
                    // Container disappeared between list and inspect — a
                    // routine race in a busy environment; the row simply
                    // drops out of the result.
                    plugin_toolkit::tracing::debug!(target: "containers::docker", id = %id, "container disappeared during list/inspect race");
                }
                Err(e) => return Err(e),
            }
            // Keep the summary alive so its drop happens after we use the
            // id; explicit drop is clearer than relying on iterator scope.
            drop(summary);
        }
        Ok(out)
    }

    async fn inspect(&self, id: &str) -> Result<Container, AdapterError> {
        let client = self.client()?;
        let opts = InspectContainerOptionsBuilder::new().build();
        let resp = client
            .inspect_container(id, Some(opts))
            .await
            .map_err(map_bollard_err)?;

        Ok(container_from_inspect(resp))
    }

    async fn start(&self, _id: &str) -> Result<(), AdapterError> {
        // C2 ships read paths; start/stop/restart/logs wire up in C3
        // alongside the reconciler loop. Returning `Refused` makes accidental
        // call sites loud rather than silently no-op.
        Err(AdapterError::Refused(
            "DockerAdapter::start lands in C3".into(),
        ))
    }

    async fn stop(&self, _id: &str) -> Result<(), AdapterError> {
        Err(AdapterError::Refused(
            "DockerAdapter::stop lands in C3".into(),
        ))
    }

    async fn restart(&self, _id: &str) -> Result<(), AdapterError> {
        Err(AdapterError::Refused(
            "DockerAdapter::restart lands in C3".into(),
        ))
    }

    async fn logs(&self, id: &str, tail: LogTail) -> Result<String, AdapterError> {
        let client = self.client()?;
        let opts = LogsOptionsBuilder::new()
            .stdout(true)
            .stderr(true)
            .tail(&tail.0.to_string())
            .build();
        let mut stream = client.logs(id, Some(opts));
        let mut out = String::new();
        while let Some(chunk) = plugin_toolkit::stream::next(&mut stream).await {
            let line = chunk.map_err(map_bollard_err)?;
            // `LogOutput`'s `Display`/`to_string` would re-frame; we want the
            // raw bytes (stdout+stderr interleaved as docker delivers them).
            out.push_str(&String::from_utf8_lossy(line.into_bytes().as_ref()));
        }
        Ok(out)
    }

    async fn exec(
        &self,
        id: &str,
        cmd: &[String],
        stdin: Option<String>,
    ) -> Result<ExecOutput, AdapterError> {
        let client = self.client()?;
        let exec = client
            .create_exec(
                id,
                CreateExecOptions {
                    cmd: Some(cmd.to_vec()),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    attach_stdin: Some(stdin.is_some()),
                    ..Default::default()
                },
            )
            .await
            .map_err(map_bollard_err)?;

        let started = client
            .start_exec(&exec.id, None)
            .await
            .map_err(map_bollard_err)?;

        let mut stdout = String::new();
        let mut stderr = String::new();
        if let StartExecResults::Attached {
            mut output,
            mut input,
        } = started
        {
            if let Some(data) = stdin {
                plugin_toolkit::io::write_all_and_shutdown(&mut input, data.as_bytes())
                    .await
                    .map_err(|e| AdapterError::Transport(format!("exec stdin: {e}")))?;
            }
            drop(input);
            while let Some(chunk) = plugin_toolkit::stream::next(&mut output).await {
                match chunk.map_err(map_bollard_err)? {
                    LogOutput::StdOut { message } => {
                        stdout.push_str(&String::from_utf8_lossy(message.as_ref()))
                    }
                    LogOutput::StdErr { message } => {
                        stderr.push_str(&String::from_utf8_lossy(message.as_ref()))
                    }
                    // Console (tty) / stdin echo land on stdout.
                    LogOutput::Console { message } | LogOutput::StdIn { message } => {
                        stdout.push_str(&String::from_utf8_lossy(message.as_ref()))
                    }
                }
            }
        }

        // Exit code is only known after the process finishes — inspect once the
        // attached stream has drained.
        let exit_code = client
            .inspect_exec(&exec.id)
            .await
            .map_err(map_bollard_err)?
            .exit_code;

        Ok(ExecOutput {
            exit_code,
            stdout,
            stderr,
        })
    }
}

/// Classify a bollard error into our typed [`AdapterError`].
fn map_bollard_err(e: bollard::errors::Error) -> AdapterError {
    use bollard::errors::Error as B;
    match e {
        B::DockerResponseServerError {
            status_code: 404,
            message,
        } => AdapterError::NotFound(message),
        B::DockerResponseServerError {
            status_code: 403,
            message,
        }
        | B::DockerResponseServerError {
            status_code: 409,
            message,
        } => AdapterError::Refused(message),
        B::DockerResponseServerError {
            status_code,
            message,
        } => AdapterError::Transport(format!("docker {status_code}: {message}")),
        B::HyperResponseError { .. } | B::HttpClientError { .. } | B::IOError { .. } => {
            AdapterError::Unavailable(e.to_string())
        }
        B::JsonDataError { .. } | B::JsonSerdeError { .. } => {
            AdapterError::Malformed(e.to_string())
        }
        other => AdapterError::Transport(other.to_string()),
    }
}

/// Pure mapping from bollard's [`bollard::models::ContainerInspectResponse`]
/// to our typed [`Container`]. Separated from the adapter so unit tests can
/// hand-construct inspect responses without a live docker daemon.
pub(crate) fn container_from_inspect(resp: bollard::models::ContainerInspectResponse) -> Container {
    let id = resp.id.unwrap_or_default();
    let name = resp
        .name
        .as_deref()
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_default();

    let host_config = resp.host_config;
    let restart_policy = host_config
        .as_ref()
        .and_then(|hc| hc.restart_policy.as_ref())
        .map(map_restart_policy)
        .unwrap_or(RestartPolicy::No);

    let state_struct = resp.state;
    let state = state_struct
        .as_ref()
        .and_then(|s| s.status)
        .map(map_state)
        .unwrap_or(ContainerState::Unknown);
    let started_at = state_struct
        .as_ref()
        .and_then(|s| s.started_at.clone())
        .filter(|s| !s.is_empty() && s != "0001-01-01T00:00:00Z");
    let finished_at = state_struct
        .as_ref()
        .and_then(|s| s.finished_at.clone())
        .filter(|s| !s.is_empty() && s != "0001-01-01T00:00:00Z");
    let exit_code = state_struct
        .as_ref()
        .and_then(|s| s.exit_code)
        .map(|v| v as i32);

    let restart_count = resp.restart_count.unwrap_or(0).max(0) as u32;

    let mounts = resp
        .mounts
        .unwrap_or_default()
        .into_iter()
        .filter_map(map_mount)
        .collect();

    let config = resp.config;
    let labels: Vec<(String, String)> = config
        .as_ref()
        .and_then(|c| c.labels.as_ref())
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    let image = config.and_then(|c| c.image);

    Container {
        id,
        name,
        runtime: RuntimeKind::Docker,
        host: local_hostname().to_string(),
        state,
        restart_policy,
        image,
        labels,
        mounts,
        ports: Vec::new(), // C2 omits — `containers.list` is the §2.1 view, ports lift in inventory.
        started_at,
        finished_at,
        restart_count,
        exit_code,
        startup: None,
    }
}

fn map_restart_policy(p: &DockerRestartPolicy) -> RestartPolicy {
    match p.name {
        Some(RestartPolicyNameEnum::ALWAYS) => RestartPolicy::Always,
        Some(RestartPolicyNameEnum::UNLESS_STOPPED) => RestartPolicy::UnlessStopped,
        Some(RestartPolicyNameEnum::ON_FAILURE) => RestartPolicy::OnFailure,
        // Docker's "empty string means not to restart" — collapses to `No`.
        Some(RestartPolicyNameEnum::NO) | Some(RestartPolicyNameEnum::EMPTY) | None => {
            RestartPolicy::No
        }
    }
}

fn map_state(s: ContainerStateStatusEnum) -> ContainerState {
    match s {
        ContainerStateStatusEnum::CREATED => ContainerState::Created,
        ContainerStateStatusEnum::RUNNING => ContainerState::Running,
        ContainerStateStatusEnum::PAUSED => ContainerState::Paused,
        ContainerStateStatusEnum::RESTARTING => ContainerState::Starting,
        ContainerStateStatusEnum::REMOVING | ContainerStateStatusEnum::STOPPING => {
            ContainerState::Stopping
        }
        ContainerStateStatusEnum::EXITED => ContainerState::Exited,
        ContainerStateStatusEnum::DEAD => ContainerState::Dead,
        ContainerStateStatusEnum::EMPTY => ContainerState::Unknown,
    }
}

fn map_mount(m: MountPoint) -> Option<ContainerMount> {
    // tmpfs / anonymous-volume mounts have an empty source on the host
    // side; they aren't dep-graph candidates so drop them rather than
    // letting them through as `PathBuf::new()`.
    let source = m.source?;
    if source.is_empty() {
        return None;
    }
    let target = m.destination?;
    if target.is_empty() {
        return None;
    }
    let read_only = !m.rw.unwrap_or(true);
    Some(ContainerMount {
        source: PathBuf::from(source),
        target: PathBuf::from(target),
        read_only,
    })
}

/// True when every `(k, v)` in `wanted` appears in `have`.
fn labels_match(have: &[(String, String)], wanted: &[(String, String)]) -> bool {
    wanted
        .iter()
        .all(|w| have.iter().any(|h| h.0 == w.0 && h.1 == w.1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{
        ContainerConfig, ContainerInspectResponse, ContainerState as DockerContainerState,
        HostConfig,
    };
    use std::collections::HashMap;

    fn sample_restart(name: RestartPolicyNameEnum) -> DockerRestartPolicy {
        DockerRestartPolicy {
            name: Some(name),
            maximum_retry_count: None,
        }
    }

    #[test]
    fn restart_policy_maps_all_variants() {
        assert_eq!(
            map_restart_policy(&sample_restart(RestartPolicyNameEnum::ALWAYS)),
            RestartPolicy::Always
        );
        assert_eq!(
            map_restart_policy(&sample_restart(RestartPolicyNameEnum::UNLESS_STOPPED)),
            RestartPolicy::UnlessStopped
        );
        assert_eq!(
            map_restart_policy(&sample_restart(RestartPolicyNameEnum::ON_FAILURE)),
            RestartPolicy::OnFailure
        );
        assert_eq!(
            map_restart_policy(&sample_restart(RestartPolicyNameEnum::NO)),
            RestartPolicy::No
        );
        assert_eq!(
            map_restart_policy(&sample_restart(RestartPolicyNameEnum::EMPTY)),
            RestartPolicy::No
        );
        assert_eq!(
            map_restart_policy(&DockerRestartPolicy {
                name: None,
                maximum_retry_count: None,
            }),
            RestartPolicy::No
        );
    }

    #[test]
    fn state_maps_all_variants() {
        assert_eq!(
            map_state(ContainerStateStatusEnum::CREATED),
            ContainerState::Created
        );
        assert_eq!(
            map_state(ContainerStateStatusEnum::RUNNING),
            ContainerState::Running
        );
        assert_eq!(
            map_state(ContainerStateStatusEnum::PAUSED),
            ContainerState::Paused
        );
        assert_eq!(
            map_state(ContainerStateStatusEnum::RESTARTING),
            ContainerState::Starting
        );
        assert_eq!(
            map_state(ContainerStateStatusEnum::REMOVING),
            ContainerState::Stopping
        );
        assert_eq!(
            map_state(ContainerStateStatusEnum::STOPPING),
            ContainerState::Stopping
        );
        assert_eq!(
            map_state(ContainerStateStatusEnum::EXITED),
            ContainerState::Exited
        );
        assert_eq!(
            map_state(ContainerStateStatusEnum::DEAD),
            ContainerState::Dead
        );
        assert_eq!(
            map_state(ContainerStateStatusEnum::EMPTY),
            ContainerState::Unknown
        );
    }

    fn make_mount(source: &str, dest: &str, rw: bool) -> MountPoint {
        MountPoint {
            typ: None,
            name: None,
            source: Some(source.to_string()),
            destination: Some(dest.to_string()),
            driver: None,
            mode: None,
            rw: Some(rw),
            propagation: None,
        }
    }

    #[test]
    fn mount_maps_rw_and_ro() {
        let m = map_mount(make_mount("/mnt/pool/data", "/data", false))
            .expect("mount with source+dest maps");
        assert_eq!(m.source, PathBuf::from("/mnt/pool/data"));
        assert_eq!(m.target, PathBuf::from("/data"));
        assert!(m.read_only);

        let m = map_mount(make_mount("/mnt/pool/data", "/data", true)).expect("rw mount maps");
        assert!(!m.read_only);
    }

    #[test]
    fn mount_drops_empty_source() {
        // tmpfs mounts surface as empty source.
        let m = map_mount(make_mount("", "/tmp", true));
        assert!(m.is_none());
    }

    #[test]
    fn mount_drops_missing_destination() {
        let m = MountPoint {
            typ: None,
            name: None,
            source: Some("/host".to_string()),
            destination: None,
            driver: None,
            mode: None,
            rw: Some(true),
            propagation: None,
        };
        assert!(map_mount(m).is_none());
    }

    fn full_inspect_response() -> ContainerInspectResponse {
        let mut labels = HashMap::new();
        labels.insert("orca.heal".to_string(), "manual".to_string());
        labels.insert(
            "com.docker.compose.project".to_string(),
            "media".to_string(),
        );

        ContainerInspectResponse {
            id: Some(
                "9c2f4a1b8e7d4c5fa1b2c3d4e5f607189c2f4a1b8e7d4c5fa1b2c3d4e5f60718".to_string(),
            ),
            name: Some("/sabnzbd".to_string()),
            state: Some(DockerContainerState {
                status: Some(ContainerStateStatusEnum::EXITED),
                running: Some(false),
                paused: Some(false),
                restarting: Some(false),
                oom_killed: Some(false),
                dead: Some(false),
                pid: Some(0),
                exit_code: Some(137),
                error: Some(String::new()),
                started_at: Some("2026-06-12T01:23:45Z".to_string()),
                finished_at: Some("2026-06-12T02:00:00Z".to_string()),
                health: None,
            }),
            restart_count: Some(2),
            host_config: Some(HostConfig {
                restart_policy: Some(sample_restart(RestartPolicyNameEnum::UNLESS_STOPPED)),
                ..Default::default()
            }),
            config: Some(ContainerConfig {
                image: Some("lscr.io/linuxserver/sabnzbd:latest".to_string()),
                labels: Some(labels),
                ..Default::default()
            }),
            mounts: Some(vec![
                make_mount("/mnt/pool/data", "/data", true),
                make_mount("/mnt/pool/config/sabnzbd", "/config", false),
                make_mount("", "/tmp", true), // tmpfs, should drop
            ]),
            ..Default::default()
        }
    }

    #[test]
    fn container_from_inspect_maps_full_shape() {
        let c = container_from_inspect(full_inspect_response());
        assert_eq!(c.runtime, RuntimeKind::Docker);
        assert_eq!(c.name, "sabnzbd"); // leading / stripped
        assert_eq!(c.state, ContainerState::Exited);
        assert_eq!(c.restart_policy, RestartPolicy::UnlessStopped);
        assert_eq!(
            c.image.as_deref(),
            Some("lscr.io/linuxserver/sabnzbd:latest")
        );
        assert_eq!(c.exit_code, Some(137));
        assert_eq!(c.restart_count, 2);
        assert_eq!(c.started_at.as_deref(), Some("2026-06-12T01:23:45Z"));
        assert_eq!(c.finished_at.as_deref(), Some("2026-06-12T02:00:00Z"));
        assert_eq!(c.mounts.len(), 2);
        let labels_have_heal = c
            .labels
            .iter()
            .any(|(k, v)| k == "orca.heal" && v == "manual");
        assert!(labels_have_heal);
        assert!(c.startup.is_none()); // docker has no ordering
    }

    #[test]
    fn container_from_inspect_handles_zero_value_timestamps() {
        let mut resp = full_inspect_response();
        if let Some(s) = resp.state.as_mut() {
            s.started_at = Some("0001-01-01T00:00:00Z".to_string());
            s.finished_at = Some(String::new());
        }
        let c = container_from_inspect(resp);
        assert!(c.started_at.is_none());
        assert!(c.finished_at.is_none());
    }

    #[test]
    fn container_from_inspect_defaults_missing_restart_policy_to_no() {
        let mut resp = full_inspect_response();
        resp.host_config = Some(HostConfig {
            restart_policy: None,
            ..Default::default()
        });
        let c = container_from_inspect(resp);
        assert_eq!(c.restart_policy, RestartPolicy::No);
    }

    #[test]
    fn labels_match_requires_all_wanted_present() {
        let have = vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ];
        assert!(labels_match(&have, &[]));
        assert!(labels_match(&have, &[("a".to_string(), "1".to_string())]));
        assert!(!labels_match(
            &have,
            &[("a".to_string(), "wrong".to_string())]
        ));
        assert!(!labels_match(
            &have,
            &[("missing".to_string(), "x".to_string())]
        ));
    }
}
