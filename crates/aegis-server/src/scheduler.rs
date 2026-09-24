//! The in-process cron scheduler (`docs/05` policies, `docs/06` API).
//!
//! The scheduler is spawned by [`serve`] and loads enabled policies
//! from the catalog on startup. Each policy gets a tokio-cron-scheduler
//! job that enqueues [`jobs::JobTask`]s for every host attached to that
//! policy via the `host_policies` join table.  The worker pool pulls
//! tasks off the channel and runs the agentless backup.  Every run
//! writes a `jobs` row so the control plane can display history and
//! status.

use std::path::PathBuf;
use std::sync::Arc;

use aegis_core::catalog::Catalog;
use anyhow::Result;
use tokio_cron_scheduler::{Job, JobScheduler};

use crate::jobs;

/// Start the scheduler as a background task. Returns a handle that
/// can be dropped to shut down the scheduler.
pub async fn start(
    catalog: Catalog,
    master_key: [u8; 32],
    catalog_path: PathBuf,
    events: jobs::EventHub,
) -> Result<SchedulerHandle> {
    let queue = jobs::start(
        Arc::new(catalog.clone()),
        master_key,
        catalog_path.clone(),
        std::env::var("AEGIS_CONCURRENCY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4),
        events,
    )
    .await?;
    let scheduler = JobScheduler::new().await?;
    let policies = catalog.list_policies().await?;
    for policy in &policies {
        if !policy.enabled {
            continue;
        }
        let cat = catalog.clone();
        let cpath = catalog_path.clone();
        let cron = policy.schedule_cron.clone();
        let p = policy.clone();
        let q = queue.clone();
        let job = Job::new_async(&cron, move |_uuid, _scheduler| {
            let cat = cat.clone();
            let cpath = cpath.clone();
            let policy = p.clone();
            let q = q.clone();
            Box::pin(async move {
                let hosts = cat
                    .list_hosts_for_policy(&policy.id)
                    .await
                    .unwrap_or_default();
                for host in hosts {
                    let _ = q
                        .enqueue(jobs::JobTask {
                            policy_id: policy.id.clone(),
                            host_id: host.id,
                            paths_json: policy.paths_json.clone(),
                            bandwidth_limit_kbps: policy.bandwidth_limit_kbps,
                            catalog_path: cpath.clone(),
                            master_key,
                        })
                        .await;
                }
            })
        })?;
        scheduler.add(job).await?;
    }
    scheduler.start().await?;
    Ok(SchedulerHandle {
        _queue: queue,
        scheduler,
    })
}

/// Handle to the running scheduler; dropping it stops the scheduler.
pub struct SchedulerHandle {
    _queue: jobs::Sender,
    scheduler: JobScheduler,
}

impl std::fmt::Debug for SchedulerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchedulerHandle").finish()
    }
}

impl Drop for SchedulerHandle {
    fn drop(&mut self) {
        tokio::runtime::Handle::current().block_on(async {
            let _ = self.scheduler.shutdown().await;
        });
    }
}
