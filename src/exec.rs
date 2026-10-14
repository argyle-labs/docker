//! Waiting on an Engine API exec for its exit status.

use bollard::Docker;
use plugin_toolkit::prelude::*;

const POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// The exit code of exec `id` once the engine reports it stopped, polling up
/// to `polls` times; `None` if it is still running. The output stream can
/// close before the process is reaped, so this is the only reliable status.
pub(crate) async fn wait_exit(docker: &Docker, id: &str, polls: u32) -> Result<Option<i64>> {
    for _ in 0..polls {
        let inspected = docker
            .inspect_exec(id)
            .await
            .map_err(|e| anyhow!("inspect exec {id}: {e}"))?;
        if inspected.running == Some(false) {
            return inspected
                .exit_code
                .map(Some)
                .ok_or_else(|| anyhow!("exec {id} finished without an exit code"));
        }
        plugin_toolkit::time::sleep(POLL).await;
    }
    Ok(None)
}
