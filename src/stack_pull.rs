//! `docker.stack_pull_pinned` — the target half of a stack move: pull each
//! image of a `docker.stack_manifest` by its digest and tag it back to the
//! reference compose names, so `compose up` on this host runs exactly what
//! the source ran instead of pulling a newer `:latest`.
#![allow(clippy::disallowed_types)]

use bollard::Docker;
use bollard::query_parameters::{CreateImageOptionsBuilder, TagImageOptionsBuilder};
use plugin_toolkit::prelude::*;

use crate::stack_manifest::{normalize, repo_of};

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
    let (image, pinned) = (image.trim(), pinned.trim());
    if image.is_empty() {
        bail!("'{pair}': empty image");
    }
    let Some((_, digest)) = pinned.split_once('@') else {
        bail!("'{pair}': '{pinned}' is not pinned by digest");
    };
    let valid = digest.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    });
    if !valid {
        bail!("'{pair}': '{digest}' is not a sha256 digest");
    }
    // Tagging a different repository's digest as `image` would run the wrong software.
    if normalize(repo_of(pinned)) != normalize(repo_of(image)) {
        bail!("'{pair}': '{pinned}' is not a digest of '{image}'");
    }
    if image.contains('@') && image != pinned {
        bail!("'{pair}': '{image}' already names a different digest");
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
    /// Dry run only: what each pin would be tagged as.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plan: Vec<PlannedPin>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPin {
    pub image: String,
    pub pinned: String,
    /// `repo:tag` the pulled digest would be tagged as, or `no retag`.
    pub tag_as: String,
}

/// Only a missing manifest means the digest is gone; a 404 for a missing
/// repository or unreachable host is a plain pull failure.
fn is_digest_gone(e: &bollard::errors::Error, pinned: &str) -> bool {
    let m = e.to_string().to_lowercase();
    if m.contains("manifest unknown") {
        return true;
    }
    let digest = pinned.split_once('@').map_or("", |(_, d)| d);
    !digest.is_empty()
        && matches!(
            e,
            bollard::errors::Error::DockerResponseServerError {
                status_code: 404,
                ..
            }
        )
        && m.contains(digest)
}

pub(crate) async fn pull(
    docker: &Docker,
    reference: &str,
) -> std::result::Result<(), bollard::errors::Error> {
    let opts = CreateImageOptionsBuilder::new()
        .from_image(reference)
        .build();
    let mut stream = Box::pin(docker.create_image(
        Some(opts),
        None,
        crate::image_update::registry_credentials(reference),
    ));
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
            let kind = if is_digest_gone(&e, &p.pinned) {
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
    /// Return the plan and change nothing. Omitted, applies.
    #[arg(long)]
    #[serde(default, rename = "dryRun", alias = "dry_run")]
    pub dry_run: bool,
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
    let pins = args
        .pins
        .iter()
        .map(|p| parse(p))
        .collect::<Result<Vec<_>>>()?;
    if args.dry_run {
        return Ok(StackPullOutput {
            executed: false,
            plan: pins
                .iter()
                .map(|p| PlannedPin {
                    image: p.image.clone(),
                    pinned: p.pinned.clone(),
                    tag_as: tag_target(&p.image)
                        .map_or_else(|| "no retag".into(), |(r, t)| format!("{r}:{t}")),
                })
                .collect(),
            ..Default::default()
        });
    }
    let docker = &crate::registration::adapter()
        .client()
        .map_err(|e| anyhow!("{e}"))?;
    Ok(apply(docker, &pins).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_engine::{FakeEngine, Route};

    const A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const G: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn at(repo: &str, d: &str) -> String {
        format!("{repo}@{d}")
    }

    fn pin(image: &str, pinned: &str) -> Pin {
        Pin {
            image: image.into(),
            pinned: pinned.into(),
        }
    }

    #[test]
    fn parse_requires_a_digest() {
        assert_eq!(
            parse(&format!(" redis:7 = {} ", at("redis", A))).unwrap(),
            pin("redis:7", &at("redis", A))
        );
        assert!(parse("redis:7").is_err());
        assert!(parse("redis:7=redis:7").is_err());
    }

    #[test]
    fn parse_rejects_empty_halves_and_malformed_digests() {
        assert!(parse(&format!("={}", at("redis", A))).is_err());
        assert!(parse("redis:7=").is_err());
        assert!(parse("redis:7=redis@sha256:a").is_err());
        assert!(
            parse(&format!(
                "redis:7=redis@{}",
                A.to_uppercase().replace("SHA", "sha")
            ))
            .is_err()
        );
        assert!(parse(&format!("redis:7=redis@md5:{}", &A[7..])).is_err());
    }

    #[test]
    fn parse_rejects_a_digest_image_pinned_to_another_digest() {
        let a = format!("app@sha256:{}", "a".repeat(64));
        let b = format!("app@sha256:{}", "b".repeat(64));
        assert!(parse(&format!("{a}={b}")).is_err());
        assert!(parse(&format!("{a}={a}")).is_ok());
    }

    #[test]
    fn parse_matches_repos_across_implicit_docker_hub_prefixes() {
        assert!(parse(&format!("redis:7={}", at("docker.io/library/redis", A))).is_ok());
        assert!(parse(&format!("library/redis={}", at("redis", A))).is_ok());
        let err = parse(&format!("redis:7={}", at("evil/miner", A))).unwrap_err();
        assert!(err.to_string().contains("is not a digest of"));
    }

    #[test]
    fn digest_gone_only_for_a_missing_manifest() {
        let e = |code, msg: &str| bollard::errors::Error::DockerResponseServerError {
            status_code: code,
            message: msg.into(),
        };
        let p = at("redis", A);
        assert!(is_digest_gone(&e(404, "manifest unknown"), &p));
        assert!(is_digest_gone(&e(404, &format!("{A} not found")), &p));
        assert!(!is_digest_gone(&e(404, "repository does not exist"), &p));
        assert!(!is_digest_gone(
            &e(500, "dial tcp: lookup reg: host not found"),
            &p
        ));
    }

    #[test]
    fn stream_error_and_tag_failure_become_findings() {
        let e = FakeEngine::routed(vec![
            Route::new(
                "POST",
                "/images/create",
                200,
                r#"{"errorDetail":{"message":"unauthorized"},"error":"unauthorized"}"#,
            )
            .when_query("fromImage=private"),
            Route::new("POST", "/images/create", 200, r#"{"status":"ok"}"#),
            Route::new("POST", "/tag", 500, r#"{"message":"tag boom"}"#),
        ]);
        let out = plugin_toolkit::reactor::block_on(apply(
            &e.client(),
            &[
                pin("private:1", &at("private", A)),
                pin("redis:7", &at("redis", B)),
            ],
        ));
        assert!(out.pulled.is_empty());
        let kinds: Vec<_> = out
            .findings
            .iter()
            .map(|f| (f.image.as_str(), f.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                ("private:1", FindingKind::PullFailed),
                ("redis:7", FindingKind::TagFailed)
            ]
        );
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
            .when_query("fromImage=old"),
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
                pin("redis:latest", &at("redis", A)),
                pin("old:1", &at("old", G)),
                pin(&at("app", B), &at("app", B)),
            ],
        ));
        assert_eq!(
            out.pulled,
            [
                format!("redis:latest={}", at("redis", A)),
                format!("{}={}", at("app", B), at("app", B))
            ]
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
        assert!(tags[0].contains(&format!("{}/tag", at("redis", A))));
        assert!(tags[0].contains("repo=redis") && tags[0].contains("tag=latest"));
    }

    #[test]
    fn dry_run_lists_and_touches_nothing() {
        let out = plugin_toolkit::reactor::block_on(docker_stack_pull_pinned(
            DockerStackPullPinnedArgs {
                pins: vec![
                    format!("redis:7={}", at("redis", A)),
                    format!("{}={}", at("app", B), at("app", B)),
                ],
                dry_run: true,
            },
            &crate::test_support::admin(),
        ))
        .unwrap();
        assert!(!out.executed);
        assert!(out.pulled.is_empty());
        let tags: Vec<_> = out.plan.iter().map(|p| p.tag_as.as_str()).collect();
        assert_eq!(tags, ["redis:7", "no retag"]);
    }

    #[test]
    fn refuses_a_non_admin_caller() {
        for ctx in crate::test_support::non_admins() {
            let err = plugin_toolkit::reactor::block_on(docker_stack_pull_pinned(
                DockerStackPullPinnedArgs {
                    pins: vec![],
                    dry_run: true,
                },
                &ctx,
            ))
            .unwrap_err();
            crate::test_support::assert_admin_refusal(&err.to_string());
        }
    }
}
