//! Image references: `[registry/]path[:tag][@digest]`, with Docker Hub's
//! implied registry and `library/` namespace filled in so two spellings of
//! one image compare equal.

const DOCKER_HUB: &str = "docker.io";

/// One parsed reference. `repository` is normalized as in [`repository`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl ImageRef {
    pub fn parse(reference: &str) -> Self {
        let (name, digest) = match reference.split_once('@') {
            Some((n, d)) => (n, Some(d.to_string())),
            None => (reference, None),
        };
        let written = written_repository(name);
        let tag = name[written.len()..].strip_prefix(':').map(str::to_string);
        Self {
            repository: repository(written),
            tag,
            digest,
        }
    }

    fn tag_or_latest(&self) -> &str {
        self.tag.as_deref().unwrap_or("latest")
    }

    /// `repository@digest` when pinned, else `repository:tag` (`latest` when
    /// none is named).
    pub fn canonical(&self) -> String {
        match &self.digest {
            Some(d) => format!("{}@{d}", self.repository),
            None => format!("{}:{}", self.repository, self.tag_or_latest()),
        }
    }

    /// Whether an image with `repo_tags` and `repo_digests` is the one this
    /// reference names: by repository and digest when pinned, else by
    /// repository and tag.
    pub fn matches(&self, repo_tags: &[String], repo_digests: &[String]) -> bool {
        match &self.digest {
            Some(d) => repo_digests.iter().any(|rd| {
                let other = ImageRef::parse(rd);
                other.repository == self.repository && other.digest.as_deref() == Some(d)
            }),
            None => repo_tags.iter().any(|t| {
                let other = ImageRef::parse(t);
                other.repository == self.repository && other.tag_or_latest() == self.tag_or_latest()
            }),
        }
    }
}

/// `reference` as written without its tag or digest: `ghcr.io/a/b:1` →
/// `ghcr.io/a/b`.
pub fn written_repository(reference: &str) -> &str {
    let no_digest = reference.split('@').next().unwrap_or(reference);
    let slash = no_digest.rfind('/').map_or(0, |i| i + 1);
    match no_digest[slash..].rfind(':') {
        Some(i) => &no_digest[..slash + i],
        None => no_digest,
    }
}

/// `registry/path` of an image reference with its tag and digest removed,
/// with Docker Hub's implied registry and `library/` namespace filled in.
pub fn repository(reference: &str) -> String {
    let name = written_repository(reference);
    let (registry, path) = match name.split_once('/') {
        Some((first, rest))
            if first.contains('.') || first.contains(':') || first == "localhost" =>
        {
            (first, rest)
        }
        _ => (DOCKER_HUB, name),
    };
    let registry = match registry {
        "index.docker.io" | "registry-1.docker.io" => DOCKER_HUB,
        r => r,
    };
    if registry == DOCKER_HUB && !path.contains('/') {
        format!("{DOCKER_HUB}/library/{path}")
    } else {
        format!("{registry}/{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn repository_fills_in_docker_hub() {
        assert_eq!(repository("nginx"), "docker.io/library/nginx");
        assert_eq!(repository("nginx:1.27"), "docker.io/library/nginx");
        assert_eq!(
            repository("docker.io/library/nginx:latest"),
            "docker.io/library/nginx"
        );
        assert_eq!(
            repository("index.docker.io/grafana/grafana"),
            "docker.io/grafana/grafana"
        );
        assert_eq!(
            repository("grafana/grafana:11"),
            "docker.io/grafana/grafana"
        );
        assert_eq!(
            repository("lscr.io/linuxserver/sonarr:latest"),
            "lscr.io/linuxserver/sonarr"
        );
        assert_eq!(
            repository(&format!("ghcr.io/org/app@{DIGEST}")),
            "ghcr.io/org/app"
        );
        assert_eq!(
            repository("gitea.example:3000/org/app:v1"),
            "gitea.example:3000/org/app"
        );
        assert_eq!(repository("localhost/app"), "localhost/app");
        assert_eq!(repository("docker.io/nginx"), "docker.io/library/nginx");
        assert_eq!(
            repository("index.docker.io/redis:7"),
            "docker.io/library/redis"
        );
        assert_eq!(
            repository("registry-1.docker.io/redis"),
            "docker.io/library/redis"
        );
    }

    #[test]
    fn written_repository_strips_tag_and_digest_but_not_registry_port() {
        assert_eq!(written_repository("redis:7"), "redis");
        assert_eq!(written_repository("ghcr.io/a/b:1.2"), "ghcr.io/a/b");
        assert_eq!(written_repository("reg:5000/app"), "reg:5000/app");
        assert_eq!(written_repository("reg:5000/app:v1"), "reg:5000/app");
        assert_eq!(written_repository("app@sha256:abc"), "app");
    }

    #[test]
    fn parse_splits_tag_and_digest() {
        let r = ImageRef::parse(&format!("reg:5000/app:v1@{DIGEST}"));
        assert_eq!(r.repository, "reg:5000/app");
        assert_eq!(r.tag.as_deref(), Some("v1"));
        assert_eq!(r.digest.as_deref(), Some(DIGEST));
        let r = ImageRef::parse("reg:5000/app");
        assert_eq!(r.tag, None);
        assert_eq!(r.digest, None);
    }

    #[test]
    fn canonical_is_one_spelling() {
        assert_eq!(
            ImageRef::parse("docker.io/library/ha").canonical(),
            "docker.io/library/ha:latest"
        );
        assert_eq!(
            ImageRef::parse("ha:latest").canonical(),
            "docker.io/library/ha:latest"
        );
        assert_eq!(
            ImageRef::parse("ghcr.io/a/b:2").canonical(),
            "ghcr.io/a/b:2"
        );
        assert_eq!(
            ImageRef::parse("localhost:5000/b").canonical(),
            "localhost:5000/b:latest"
        );
        assert_eq!(
            ImageRef::parse(&format!("app:1@{DIGEST}")).canonical(),
            format!("docker.io/library/app@{DIGEST}")
        );
    }

    #[test]
    fn matches_repo_and_tag_against_tags_and_repo_and_digest_against_digests() {
        let tags = vec!["nginx:latest".to_string()];
        let digests = vec![format!("nginx@{DIGEST}")];
        assert!(ImageRef::parse("docker.io/library/nginx").matches(&tags, &[]));
        assert!(!ImageRef::parse("nginx:1").matches(&tags, &[]));
        assert!(!ImageRef::parse("other:latest").matches(&tags, &[]));
        assert!(
            ImageRef::parse(&format!("docker.io/library/nginx@{DIGEST}")).matches(&[], &digests)
        );
        assert!(ImageRef::parse(&format!("nginx:9@{DIGEST}")).matches(&[], &digests));
        assert!(!ImageRef::parse(&format!("other@{DIGEST}")).matches(&[], &digests));
        assert!(!ImageRef::parse(&format!("nginx@{DIGEST}")).matches(&tags, &[]));
    }
}
