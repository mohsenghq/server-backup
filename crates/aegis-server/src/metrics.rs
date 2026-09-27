//! Prometheus exposition at `GET /metrics` (`docs/06`).
//!
//! Deliberately dependency-free: the numbers come from the catalog on each
//! scrape, so there is no in-process counter to drift out of sync with the
//! database. Gauges are derived, not counted:
//!
//! ```text
//! aegis_hosts{status="reachable"} 2
//! aegis_jobs{status="completed"} 41
//! aegis_backup_bytes_total 918273645
//! aegis_backup_new_bytes_total 7345231
//! aegis_snapshots_recorded 12
//! aegis_uptime_seconds 3600
//! ```

use aegis_core::catalog::Catalog;

/// Process start time, used for the uptime gauge. Set once by the server
/// binary; without it `aegis_uptime_seconds` is omitted.
static STARTED_AT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Record the process start time (call once, early in `main`).
pub fn mark_started() {
    let _ = STARTED_AT.set(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
}

/// Render the exposition text for the catalog's current state.
pub async fn render(catalog: &Catalog, repo_bytes: Option<u64>) -> String {
    let mut out = String::with_capacity(1024);
    let mut line = |name: &str, help: &str, kind: &str, samples: &[(&str, f64)]| {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
        for (labels, value) in samples {
            if labels.is_empty() {
                out.push_str(&format!("{name} {value}\n"));
            } else {
                out.push_str(&format!("{name}{{{labels}}} {value}\n"));
            }
        }
    };

    let hosts = catalog.list_hosts().await.unwrap_or_default();
    let host_samples: Vec<(&str, f64)> = ["reachable", "unreachable", "unknown"]
        .iter()
        .map(|s| {
            let n = hosts.iter().filter(|h| h.status.as_str() == *s).count();
            (*s, n as f64)
        })
        .collect();
    line(
        "aegis_hosts",
        "Registered backup hosts by reachability.",
        "gauge",
        &host_samples,
    );

    let jobs = catalog
        .list_jobs(None, None, None, 1000, 0)
        .await
        .unwrap_or_default();
    let job_samples: Vec<(&str, f64)> = ["running", "completed", "failed"]
        .iter()
        .map(|s| {
            let n = jobs.iter().filter(|j| j.status == *s).count();
            (*s, n as f64)
        })
        .collect();
    line(
        "aegis_jobs",
        "Backup jobs by status (last 1000).",
        "gauge",
        &job_samples,
    );

    let completed: Vec<_> = jobs.iter().filter(|j| j.status == "completed").collect();
    line(
        "aegis_backup_bytes_total",
        "Logical bytes read by completed jobs (last 1000).",
        "counter",
        &[("", completed.iter().map(|j| j.bytes_total as f64).sum())],
    );
    line(
        "aegis_backup_new_bytes_total",
        "Bytes actually written by completed jobs (last 1000).",
        "counter",
        &[("", completed.iter().map(|j| j.bytes_new as f64).sum())],
    );
    line(
        "aegis_snapshots_recorded",
        "Snapshots recorded in the catalog.",
        "gauge",
        &[(
            "",
            catalog
                .list_snapshots_for_host(None, 10_000)
                .await
                .map(|s| s.len())
                .unwrap_or(0) as f64,
        )],
    );
    if let Some(bytes) = repo_bytes {
        line(
            "aegis_repository_bytes",
            "Bytes stored in the control plane's repository.",
            "gauge",
            &[("", bytes as f64)],
        );
    }
    if let Some(start) = STARTED_AT.get() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(*start);
        line(
            "aegis_uptime_seconds",
            "Seconds since the control plane started.",
            "gauge",
            &[("", now.saturating_sub(*start) as f64)],
        );
    }
    out
}
