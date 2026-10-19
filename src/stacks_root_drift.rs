//! Disagreement between the configured stacks root(s) and where compose says
//! the running projects actually live
//! (`com.docker.compose.project.working_dir`).

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::time::Duration;

use bollard::Docker;
use bollard::query_parameters::ListContainersOptionsBuilder;
use plugin_toolkit::prelude::*;

pub const WORKING_DIR_LABEL: &str = "com.docker.compose.project.working_dir";
const ENGINE_BUDGET: Duration = Duration::from_secs(3);

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StacksRootDrift {
    pub configured: Vec<String>,
    /// Parent dirs of every live project working dir.
    pub observed_roots: Vec<String>,
    /// Project working dirs outside every configured root.
    pub outside: Vec<String>,
}

pub fn judge(configured: &[String], working_dirs: &[String]) -> Option<StacksRootDrift> {
    let inside = |dir: &str| {
        configured.iter().any(|root| {
            Path::new(dir)
                .strip_prefix(root)
                .is_ok_and(|r| r.components().next().is_some())
        })
    };
    let dirs: BTreeSet<&str> = working_dirs.iter().map(String::as_str).collect();
    let outside: Vec<String> = dirs
        .iter()
        .filter(|d| !inside(d))
        .map(|d| (*d).to_owned())
        .collect();
    if outside.is_empty() {
        return None;
    }
    let observed_roots: BTreeSet<String> = dirs
        .iter()
        .filter_map(|d| Path::new(d).parent())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    Some(StacksRootDrift {
        configured: configured.to_vec(),
        observed_roots: observed_roots.into_iter().collect(),
        outside,
    })
}

pub async fn working_dirs(docker: &Docker) -> Result<Vec<String>> {
    let filters = HashMap::from([("label".to_string(), vec![WORKING_DIR_LABEL.to_string()])]);
    let list = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::new()
                .all(true)
                .filters(&filters)
                .build(),
        ))
        .await
        .map_err(|e| anyhow!("list containers: {e}"))?;
    Ok(list
        .iter()
        .filter_map(|c| c.labels.as_ref()?.get(WORKING_DIR_LABEL).cloned())
        .filter(|d| !d.is_empty())
        .collect())
}

/// The drift against the active engine; an unreachable engine reports none.
pub async fn observe(configured: &[String]) -> Option<StacksRootDrift> {
    let docker = crate::registration::adapter().client().ok()?;
    let dirs = plugin_toolkit::time::timeout(ENGINE_BUDGET, working_dirs(docker))
        .await?
        .ok()?;
    judge(configured, &dirs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn projects_under_the_configured_root_are_not_drift() {
        assert_eq!(
            judge(
                &s(&["/opt/stacks"]),
                &s(&["/opt/stacks/a", "/opt/stacks/b"])
            ),
            None
        );
        assert_eq!(judge(&s(&["/opt/stacks"]), &[]), None);
    }

    #[test]
    fn projects_elsewhere_report_their_roots() {
        let d = judge(
            &s(&["/opt/stacks"]),
            &s(&[
                "/opt/stacks/a",
                "/mnt/user/appdata/b",
                "/mnt/user/appdata/c",
                "/opt/stacks",
            ]),
        )
        .unwrap();
        assert_eq!(d.configured, s(&["/opt/stacks"]));
        assert_eq!(
            d.observed_roots,
            s(&["/mnt/user/appdata", "/opt", "/opt/stacks"])
        );
        assert_eq!(
            d.outside,
            s(&["/mnt/user/appdata/b", "/mnt/user/appdata/c", "/opt/stacks"])
        );
    }

    #[test]
    fn a_sibling_with_a_shared_prefix_is_outside() {
        let d = judge(&s(&["/opt/stacks"]), &s(&["/opt/stacks2/a"])).unwrap();
        assert_eq!(d.outside, s(&["/opt/stacks2/a"]));
    }

    #[test]
    fn working_dirs_come_from_the_compose_label() {
        let e = FakeEngine::routed(vec![Route::new(
            "GET",
            "/containers/json",
            200,
            format!(
                r#"[{{"Id":"a","Labels":{{"{WORKING_DIR_LABEL}":"/srv/a"}}}},{{"Id":"b","Labels":{{}}}}]"#
            ),
        )]);
        let dirs = plugin_toolkit::reactor::block_on(working_dirs(&e.client())).unwrap();
        assert_eq!(dirs, s(&["/srv/a"]));
        assert!(
            e.targets("GET")
                .iter()
                .any(|t| t.contains(WORKING_DIR_LABEL))
        );
    }
}
