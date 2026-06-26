//! Container-level ops via the docker CLI on top of [`crate::run`].
//! Swap to bollard when streaming/events land.
// serde_json::Value is intentional: `docker inspect` returns a large,
// version-dependent JSON array; callers pick the fields they need.
#![allow(clippy::disallowed_types)]

use plugin_toolkit::anyhow;
use plugin_toolkit::serde::{Deserialize, Serialize};
use plugin_toolkit::serde_json::{self, Value};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
pub struct ContainerSummary {
    #[serde(default, rename = "ID", alias = "Id")]
    pub id: String,
    #[serde(default, rename = "Names")]
    pub names: String,
    #[serde(default, rename = "Image")]
    pub image: String,
    #[serde(default, rename = "Status")]
    pub status: String,
    #[serde(default, rename = "State")]
    pub state: String,
    #[serde(default, rename = "Ports")]
    pub ports: String,
}

/// `docker ps --format '{{json .}}'`. When `all=true`, includes stopped.
pub async fn list(all: bool) -> anyhow::Result<Vec<ContainerSummary>> {
    let mut args: Vec<&str> = vec!["ps", "--format", "{{json .}}"];
    if all {
        args.push("--all");
    }
    let out = super::run(&args, None).await?;
    let mut result = Vec::new();
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<ContainerSummary>(line) {
            Ok(c) => result.push(c),
            Err(_) => continue,
        }
    }
    Ok(result)
}

/// `docker logs --tail <n> <container>`. Returns combined stdout+stderr.
/// Default tail is 100; capped to 10_000 to mirror the former plugin schema.
pub async fn logs(container: &str, tail: Option<u32>) -> anyhow::Result<String> {
    if container.is_empty() {
        anyhow::bail!("missing 'container'");
    }
    let n = tail.unwrap_or(100).clamp(1, 10_000);
    let n_str = n.to_string();
    super::run(&["logs", "--tail", &n_str, container], None).await
}

/// `docker start <container>`.
pub async fn start(container: &str) -> anyhow::Result<String> {
    action(container, "start").await
}

/// `docker stop <container>`.
pub async fn stop(container: &str) -> anyhow::Result<String> {
    action(container, "stop").await
}

/// `docker restart <container>`.
pub async fn restart(container: &str) -> anyhow::Result<String> {
    action(container, "restart").await
}

/// `docker inspect <container>` — returns the parsed JSON (an array of one).
pub async fn inspect(container: &str) -> anyhow::Result<Value> {
    if container.is_empty() {
        anyhow::bail!("missing 'container'");
    }
    let out = super::run(&["inspect", container], None).await?;
    Ok(serde_json::from_str(&out)?)
}

async fn action(container: &str, op: &str) -> anyhow::Result<String> {
    if container.is_empty() {
        anyhow::bail!("missing 'container'");
    }
    super::run(&[op, container], None).await
}

/// One row from `docker stats --no-stream --format '{{json .}}'`.
/// Field names match docker's Go template output keys exactly.
#[derive(Debug, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
struct RawStatsRow {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "CPUPerc")]
    cpu_perc: String,
    #[serde(rename = "MemUsage")]
    mem_usage: String,
    #[serde(rename = "BlockIO")]
    block_io: String,
    #[serde(rename = "NetIO")]
    net_io: String,
}

/// Live CPU/memory stats for all running containers.
pub struct ContainerLiveStats {
    pub id: String,
    pub name: String,
    pub cpu_percent: f64,
    pub mem_usage_mb: u64,
    pub mem_limit_mb: u64,
    pub block_read_bytes: u64,
    pub block_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

/// Parse `"1.23%"` → 1.23, returning 0.0 on error.
fn parse_percent(s: &str) -> f64 {
    s.trim_end_matches('%').trim().parse::<f64>().unwrap_or(0.0)
}

/// Parse memory strings like `"1.23GiB / 15.53GiB"` or `"512MiB / 0B"`.
/// Returns `(used_mb, limit_mb)`.
fn parse_mem_pair(s: &str) -> (u64, u64) {
    let mut parts = s.splitn(2, '/');
    let used = parse_size_to_mb(parts.next().unwrap_or("").trim());
    let limit = parse_size_to_mb(parts.next().unwrap_or("").trim());
    (used, limit)
}

/// Parse `"1.5GiB"`, `"512MiB"`, `"2.3kB"`, `"0B"` → MB (truncated).
fn parse_size_to_mb(s: &str) -> u64 {
    let s = s.trim();
    // suffixes in order of longest match first
    for (suffix, factor_bytes) in &[
        ("GiB", 1_073_741_824u64),
        ("MiB", 1_048_576u64),
        ("KiB", 1_024u64),
        ("GB", 1_000_000_000u64),
        ("MB", 1_000_000u64),
        ("kB", 1_000u64),
        ("B", 1u64),
    ] {
        if let Some(num) = s.strip_suffix(suffix) {
            let v: f64 = num.trim().parse().unwrap_or(0.0);
            return (v * (*factor_bytes as f64) / 1_048_576.0) as u64;
        }
    }
    0
}

/// Parse IO pairs like `"1.23MB / 456kB"` → `(read_bytes, write_bytes)`.
fn parse_io_pair(s: &str) -> (u64, u64) {
    let mut parts = s.splitn(2, '/');
    let r = parse_size_to_bytes(parts.next().unwrap_or("").trim());
    let w = parse_size_to_bytes(parts.next().unwrap_or("").trim());
    (r, w)
}

fn parse_size_to_bytes(s: &str) -> u64 {
    let s = s.trim();
    for (suffix, factor) in &[
        ("GiB", 1_073_741_824u64),
        ("MiB", 1_048_576u64),
        ("KiB", 1_024u64),
        ("GB", 1_000_000_000u64),
        ("MB", 1_000_000u64),
        ("kB", 1_000u64),
        ("B", 1u64),
    ] {
        if let Some(num) = s.strip_suffix(suffix) {
            let v: f64 = num.trim().parse().unwrap_or(0.0);
            return (v * (*factor as f64)) as u64;
        }
    }
    0
}

/// `docker stats --no-stream --format '{{json .}}'` for all running containers.
pub async fn live_stats() -> anyhow::Result<Vec<ContainerLiveStats>> {
    let out = super::run(&["stats", "--no-stream", "--format", "{{json .}}"], None).await?;

    let mut result = Vec::new();
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(row) = serde_json::from_str::<RawStatsRow>(line) else {
            continue;
        };
        let cpu_percent = parse_percent(&row.cpu_perc);
        let (mem_usage_mb, mem_limit_mb) = parse_mem_pair(&row.mem_usage);
        let (block_read_bytes, block_write_bytes) = parse_io_pair(&row.block_io);
        let (net_rx_bytes, net_tx_bytes) = parse_io_pair(&row.net_io);
        result.push(ContainerLiveStats {
            id: row.id,
            name: row.name,
            cpu_percent,
            mem_usage_mb,
            mem_limit_mb,
            block_read_bytes,
            block_write_bytes,
            net_rx_bytes,
            net_tx_bytes,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_percent ──────────────────────────────────────────────────────
    #[test]
    fn parse_percent_typical() {
        assert!((parse_percent("12.34%") - 12.34).abs() < 0.001);
    }

    #[test]
    fn parse_percent_zero() {
        assert_eq!(parse_percent("0.00%"), 0.0);
    }

    #[test]
    fn parse_percent_no_symbol() {
        assert!((parse_percent("5.5") - 5.5).abs() < 0.001);
    }

    #[test]
    fn parse_percent_garbage() {
        assert_eq!(parse_percent("--"), 0.0);
    }

    // ── parse_size_to_mb ──────────────────────────────────────────────────
    #[test]
    fn size_mb_gib() {
        assert_eq!(parse_size_to_mb("1GiB"), 1024);
    }

    #[test]
    fn size_mb_mib() {
        assert_eq!(parse_size_to_mb("512MiB"), 512);
    }

    #[test]
    fn size_mb_kib() {
        assert_eq!(parse_size_to_mb("1024KiB"), 1);
    }

    #[test]
    fn size_mb_gb() {
        assert_eq!(parse_size_to_mb("1GB"), 953);
    }

    #[test]
    fn size_mb_mb() {
        assert_eq!(parse_size_to_mb("1MB"), 0);
    }

    #[test]
    fn size_mb_kb() {
        assert_eq!(parse_size_to_mb("1kB"), 0);
    }

    #[test]
    fn size_mb_bytes() {
        assert_eq!(parse_size_to_mb("1048576B"), 1);
    }

    #[test]
    fn size_mb_unknown() {
        assert_eq!(parse_size_to_mb("??"), 0);
    }

    // ── parse_size_to_bytes ───────────────────────────────────────────────
    #[test]
    fn size_bytes_gib() {
        assert_eq!(parse_size_to_bytes("1GiB"), 1_073_741_824);
    }

    #[test]
    fn size_bytes_mib() {
        assert_eq!(parse_size_to_bytes("1MiB"), 1_048_576);
    }

    #[test]
    fn size_bytes_kib() {
        assert_eq!(parse_size_to_bytes("1KiB"), 1024);
    }

    #[test]
    fn size_bytes_gb() {
        assert_eq!(parse_size_to_bytes("1GB"), 1_000_000_000);
    }

    #[test]
    fn size_bytes_mb_si() {
        assert_eq!(parse_size_to_bytes("1MB"), 1_000_000);
    }

    #[test]
    fn size_bytes_kb() {
        assert_eq!(parse_size_to_bytes("1kB"), 1_000);
    }

    #[test]
    fn size_bytes_b() {
        assert_eq!(parse_size_to_bytes("42B"), 42);
    }

    #[test]
    fn size_bytes_unknown() {
        assert_eq!(parse_size_to_bytes("??"), 0);
    }

    // ── parse_mem_pair ─────────────────────────────────────────────────────
    #[test]
    fn mem_pair_typical() {
        let (used, limit) = parse_mem_pair("512MiB / 15GiB");
        assert_eq!(used, 512);
        assert_eq!(limit, 15360);
    }

    #[test]
    fn mem_pair_zero_limit() {
        let (used, limit) = parse_mem_pair("256MiB / 0B");
        assert_eq!(used, 256);
        assert_eq!(limit, 0);
    }

    // ── parse_io_pair ──────────────────────────────────────────────────────
    #[test]
    fn io_pair_typical() {
        let (r, w) = parse_io_pair("1MiB / 512kB");
        assert_eq!(r, 1_048_576);
        assert_eq!(w, 512_000);
    }

    // ── live_stats line parser ─────────────────────────────────────────────
    #[test]
    fn live_stats_parses_two_rows_skips_bad_line() {
        let raw = concat!(
            r#"{"ID":"abc","Name":"web","CPUPerc":"1.23%","MemUsage":"256MiB / 8GiB","BlockIO":"1MiB / 512kB","NetIO":"2MiB / 1MiB"}"#,
            "\n",
            "not valid json\n",
            r#"{"ID":"def","Name":"db","CPUPerc":"0.50%","MemUsage":"512MiB / 8GiB","BlockIO":"0B / 0B","NetIO":"0B / 0B"}"#,
        );

        let mut result = Vec::new();
        for line in raw.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(row) = serde_json::from_str::<RawStatsRow>(line) else {
                continue;
            };
            let cpu_percent = parse_percent(&row.cpu_perc);
            let (mem_usage_mb, mem_limit_mb) = parse_mem_pair(&row.mem_usage);
            let (block_read_bytes, block_write_bytes) = parse_io_pair(&row.block_io);
            let (net_rx_bytes, net_tx_bytes) = parse_io_pair(&row.net_io);
            result.push(ContainerLiveStats {
                id: row.id,
                name: row.name,
                cpu_percent,
                mem_usage_mb,
                mem_limit_mb,
                block_read_bytes,
                block_write_bytes,
                net_rx_bytes,
                net_tx_bytes,
            });
        }

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "web");
        assert!((result[0].cpu_percent - 1.23).abs() < 0.001);
        assert_eq!(result[0].mem_usage_mb, 256);
        assert_eq!(result[0].mem_limit_mb, 8192);
        assert_eq!(result[0].block_read_bytes, 1_048_576);
        assert_eq!(result[0].block_write_bytes, 512_000);
        assert_eq!(result[1].name, "db");
    }
}
