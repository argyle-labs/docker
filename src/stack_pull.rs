//! `docker.stack_pull_pinned` — the target half of a stack move: pull each
//! image of a `docker.stack_manifest` by its digest and tag it back to the
//! reference compose names, so `compose up` on this host runs exactly what
//! the source ran instead of pulling a newer `:latest`.
#![allow(clippy::disallowed_types)]

use bollard::Docker;
use bollard::query_parameters::{CreateImageOptionsBuilder, TagImageOptionsBuilder};
use plugin_toolkit::prelude::*;

use crate::stack_manifest::repo_of;

const TOOL: &str = "docker.stack_pull_pinned";

/// One `image=repo@sha256:…` pair from the source's manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub image: String,
    pub pinned: String,
}

pub fn parse(pair: &str) -> Result<Pin> {
    let (image, pinned) = pair
        .split_once('=')
        .ok_or_else(|| anyhow!("'{pair}': expected <image>=<repo@sha256:…>"))?;
    if !pinned.contains("@sha256:") {
        bail!("'{pair}': '{pinned}' is not pinned by digest");
    }
    Ok(Pin {
        image: image.to_owned(),
        pinned: pinned.to_owned(),
    })
}

/// `(repo, tag)` to re-tag `image` as, or `None` when `image` is itself a
/// digest reference and needs no tag.
pub fn tag_target(image: &str) -> Option<(&str, &str)> {
    if image.contains('@') {
        return None;
    }
    let repo = repo_of(image);
    let tag = image[repo.len()..].strip_prefix(':').unwrap_or("latest");
    Some((repo, tag))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "camelCase")]
pub enum FindingKind {
    /// The registry no longer serves this digest; the exact image cannot be
    /// reproduced on the target.
    DigestGone,
    PullFailed,
    TagFailed,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullFinding {
    pub image: String,
    pub pinned: String,
    pub kind: FindingKind,
    pub message: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StackPullOutput {
    pub executed: bool,
    /// `image=pinned` pairs pulled and tagged (execute), or that would be.
    pub pulled: Vec<String>,
    pub findings: Vec<PullFinding>,
}

/// A registry that dropped a digest answers 404 or `manifest unknown`.
fn is_digest_gone(e: &bollard::errors::Error) -> bool {
    match e {
        bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        } => true,
        other => {
            let m = other.to_string().to_lowercase();
            m.contains("manifest unknown") || m.contains("not found")
        }
    }
}

async fn pull(docker: &Docker, reference: &str) -> std::result::Result<(), bollard::errors::Error> {
    let opts = CreateImageOptionsBuilder::new().from_image(reference).build();
    let mut stream = Box::pin(docker.create_image(Some(opts), None, None));
    while let Some(item) = plugin_toolkit::stream::next(&mut stream).await {
        item?;
    }
    Ok(())
}

pub async fn apply(docker: &Docker, pins: &[Pin]) -> StackPullOutput {
    let mut out = StackPullOutput {
        executed: true,
        ..Default::default()
    };
    let finding = |p: &Pin, kind, message: String| PullFinding {
        image: p.image.clone(),
        pinned: p.pinned.clone(),
        kind,
        message,
    };
    for p in pins {
        if let Err(e) = pull(docker, &p.pinned).await {
            let kind = if is_digest_gone(&e) {
                FindingKind::DigestGone
            } else {
                FindingKind::PullFailed
            };
            out.findings.push(finding(p, kind, e.to_string()));
            continue;
        }
        if let Some((repo, tag)) = tag_target(&p.image) {
            let opts = TagImageOptionsBuilder::new().repo(repo).tag(tag).build();
            if let Err(e) = docker.tag_image(&p.pinned, Some(opts)).await {
                out.findings
                    .push(finding(p, FindingKind::TagFailed, e.to_string()));
                continue;
            }
        }
        out.pulled.push(format!("{}={}", p.image, p.pinned));
    }
    out
}

#[orca_struct(args)]
pub struct DockerStackPullPinnedArgs {
    /// `<image>=<repo@sha256:…>` pairs, the `image`/`pinned` fields of the
    /// source host's `docker.stack_manifest`. Comma-separated on the CLI.
    #[arg(long, value_delimiter = ',')]
    pub pins: Vec<String>,
    /// Apply. Omitted, lists what would be pulled and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// **Stage a moved stack's images on this host**: pull each image by the
/// digest the source host runs and tag it to the reference compose uses, so
/// the stack starts on identical images. A digest the registry no longer
/// serves is reported as a `digestGone` finding, never substituted.
#[orca_tool(
    domain = "docker",
    verb = "stack_pull_pinned",
    role = "admin",
    execute_gated = false
)]
async fn docker_stack_pull_pinned(
    args: DockerStackPullPinnedArgs,
    ctx: &ToolCtx,
) -> Result<StackPullOutput> {
    crate::execute::require_admin(TOOL, ctx)?;
    crate::execute::guard(TOOL, args.execute, ctx)?;
    let pins = args
        .pins
        .iter()
        .map(|p| parse(p))
        .collect::<Result<Vec<_>>>()?;
    if !args.execute {
        return Ok(StackPullOutput {
            executed: false,
            pulled: args.pins.clone(),
            findings: Vec::new(),
        });
    }
    let docker = crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    Ok(apply(docker, &pins).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};

    fn pin(image: &str, pinned: &str) -> Pin {
        Pin {
            image: image.into(),
            pinned: pinned.into(),
        }
    }

    #[test]
    fn parse_requires_a_digest() {
        assert_eq!(
            parse("redis:7=redis@sha256:a").unwrap(),
            pin("redis:7", "redis@sha256:a")
        );
        assert!(parse("redis:7").is_err());
        assert!(parse("redis:7=redis:7").is_err());
    }

    #[test]
    fn tag_target_defaults_to_latest_and_keeps_registry_port() {
        assert_eq!(tag_target("redis"), Some(("redis", "latest")));
        assert_eq!(tag_target("reg:5000/app:v1"), Some(("reg:5000/app", "v1")));
        assert_eq!(tag_target("reg:5000/app"), Some(("reg:5000/app", "latest")));
        assert_eq!(tag_target("app@sha256:a"), None);
    }

    #[test]
    fn pulls_by_digest_tags_back_and_reports_a_gone_digest() {
        let e = FakeEngine::routed(vec![
            Route::new(
                "POST",
                "/images/create",
                404,
                r#"{"message":"manifest unknown"}"#,
            )
            .when_query("fromImage=old@sha256:gone"),
            Route::new(
                "POST",
                "/images/create",
                200,
                r#"{"status":"Digest: sha256:a"}"#,
            ),
            Route::new("POST", "/tag", 201, ""),
        ]);
        let out = plugin_toolkit::reactor::block_on(apply(
            &e.client(),
            &[
                pin("redis:latest", "redis@sha256:a"),
                pin("old:1", "old@sha256:gone"),
                pin("app@sha256:b", "app@sha256:b"),
            ],
        ));
        assert_eq!(
            out.pulled,
            ["redis:latest=redis@sha256:a", "app@sha256:b=app@sha256:b"]
        );
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].kind, FindingKind::DigestGone);
        assert_eq!(out.findings[0].image, "old:1");
        let tags: Vec<String> = e
            .targets("POST")
            .into_iter()
            .filter(|t| t.contains("/tag"))
            .collect();
        assert_eq!(tags.len(), 1, "a digest reference is not re-tagged");
        assert!(tags[0].contains("redis@sha256:a/tag"));
        assert!(tags[0].contains("repo=redis") && tags[0].contains("tag=latest"));
    }

    #[test]
    fn dry_run_lists_and_touches_nothing() {
        let out = plugin_toolkit::reactor::block_on(docker_stack_pull_pinned(
            DockerStackPullPinnedArgs {
                pins: vec!["redis:7=redis@sha256:a".into()],
                execute: false,
            },
            &crate::test_support::admin(),
        ))
        .unwrap();
        assert!(!out.executed);
        assert_eq!(out.pulled, ["redis:7=redis@sha256:a"]);
    }

    #[test]
    fn refuses_a_non_admin_caller() {
        for ctx in crate::test_support::non_admins() {
            let err = plugin_toolkit::reactor::block_on(docker_stack_pull_pinned(
                DockerStackPullPinnedArgs {
                    pins: vec![],
                    execute: false,
                },
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
        }
    }
}
