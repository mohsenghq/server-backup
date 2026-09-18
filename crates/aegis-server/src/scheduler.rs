//! The in-process cron scheduler (`docs/05` policies, `docs/06` API).
//!
//! The scheduler is spawned by [`serve`] and loads enabled policies
//! from the catalog at startup. Each policy gets a tokio-cron-scheduler
//! job that runs the agentless backup for every host attached to that
//! policy via the `host_policies` join table. Every run writes a
//! `jobs` row so the control plane can display history and status.

use std::path::{Path, PathBuf};

use aegis_core::catalog::Catalog;
use aegis_core::repo::Repository;
use aegis_core::ssh::{HostConfig, SshManager};
use anyhow::Result;
use tokio_cron_scheduler::{Job, JobScheduler};
use uuid::Uuid;

/// Start the scheduler as a background task. Returns a handle that
/// can be dropped to shut down the scheduler.
pub async fn start(
    catalog: Catalog,
    master_key: [u8; 32],
    catalog_path: PathBuf,
) -> Result<SchedulerHandle> {
    let scheduler = JobScheduler::new().await?;
    let policies = catalog.list_policies().await?;
    for policy in &policies {
        if !policy.enabled {
            continue;
        }
        let cat = catalog.clone();
        let mk = master_key;
        let cpath = catalog_path.clone();
        let cron = policy.schedule_cron.clone();
        let p = policy.clone();
        let job = Job::new_async(&cron, move |_uuid, _scheduler| {
            let cat = cat.clone();
            let mk = mk;
            let path = cpath.clone();
            let policy = p.clone();
            Box::pin(async move {
                let _ = run_policy(&cat, mk, &path, &policy).await;
            })
        })?;
        scheduler.add(job).await?;
    }
    scheduler.start().await?;
    Ok(SchedulerHandle { scheduler })
}

async fn run_policy(
    catalog: &Catalog,
    master_key: [u8; 32],
    catalog_path: &Path,
    policy: &aegis_core::catalog::Policy,
) -> Result<()> {
    let host_rows = catalog
        .list_hosts_for_policy(&policy.id)
        .await
        .map_err(|e| anyhow::anyhow!("listing hosts for policy: {e}"))?;
    for host in host_rows {
        let ssh = SshManager::new();
        let cfg = build_host_config(&host, &master_key, catalog).await?;
        let repo = open_repo(catalog_path).await?;
        let chunker = repo.config().chunker;
        let paths: Vec<String> = serde_json::from_str(&policy.paths_json)
            .map_err(|e| anyhow::anyhow!("parse policy paths: {e}"))?;
        let job_id = Uuid::new_v4().to_string();
        catalog
            .record_job_started(&job_id, &host.id, &policy.id)
            .await
            .map_err(|e| anyhow::anyhow!("inserting job: {e}"))?;
        let result = aegis_core::backup_remote(&repo, &ssh, &cfg, &chunker, &paths).await;
        match result {
            Ok(snap) => {
                catalog
                    .record_job_completed(
                        &job_id,
                        snap.stats.new_chunks as i64,
                        snap.stats.bytes as i64,
                    )
                    .await?;
            }
            Err(e) => {
                catalog.record_job_failed(&job_id, &e.to_string()).await?;
            }
        }
    }
    Ok(())
}

async fn build_host_config(
    host: &aegis_core::catalog::Host,
    master_key: &[u8; 32],
    catalog: &Catalog,
) -> Result<HostConfig> {
    let with_key = catalog.get_host_with_key(&host.id, master_key).await?;
    let pem = with_key.ssh_key_pem;
    let auth = if pem.is_empty() {
        aegis_core::sftp::SftpAuth::Password(
            std::env::var("AEGIS_SSH_PASSWORD").unwrap_or_default(),
        )
    } else {
        let key = russh::keys::decode_secret_key(&String::from_utf8(pem)?, None)?;
        aegis_core::sftp::SftpAuth::Key(std::sync::Arc::new(key))
    };
    Ok(HostConfig::new(host.ssh_user.clone(), host.address.clone(), auth).with_port(host.ssh_port))
}

async fn open_repo(catalog_path: &Path) -> Result<Repository> {
    let pass = std::env::var("AEGIS_PASSPHRASE")
        .map_err(|_| anyhow::anyhow!("AEGIS_PASSPHRASE is required"))?;
    let backend = Box::new(aegis_core::backend::LocalBackend::new(catalog_path));
    Repository::open(backend, &pass)
        .await
        .map_err(|e| anyhow::anyhow!("opening repository: {e}"))
}

/// Handle to the running scheduler; dropping it stops the scheduler.
pub struct SchedulerHandle {
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
