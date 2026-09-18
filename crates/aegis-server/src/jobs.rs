//! Job queue + worker pool (`docs/05` policies → `docs/06` jobs).
//!
//! The scheduler enqueues [`JobTask`]s onto a bounded
//! `tokio::sync::broadcast` channel; a pool of workers pulls tasks
//! off the channel and runs the agentless backup, recording
//! `running`→`completed`/`failed` in the catalog.  The worker count
//! is capped by `AEGIS_CONCURRENCY` (default 4).

use std::path::Path;
use std::sync::Arc;

use aegis_core::catalog::{Catalog, HostWithKey};
use aegis_core::repo::Repository;
use aegis_core::ssh::SshManager;
use anyhow::Result;
use tokio::sync::broadcast;
use uuid::Uuid;

/// A unit of work: back up one host under one policy.
#[derive(Clone)]
pub struct JobTask {
    pub policy_id: String,
    pub host_id: String,
    pub paths_json: String,
    pub catalog_path: std::path::PathBuf,
    pub master_key: [u8; 32],
}

/// Start the worker pool; returns a sender the scheduler can push onto.
pub async fn start(
    catalog: Arc<Catalog>,
    master_key: [u8; 32],
    catalog_path: std::path::PathBuf,
    concurrency: usize,
) -> Result<Sender> {
    let (tx, _rx) = broadcast::channel::<JobTask>(concurrency * 2);
    let tx = Arc::new(tx);
    for _ in 0..concurrency {
        let cat = catalog.clone();
        let mk = master_key;
        let cpath = catalog_path.clone();
        let mut rx = tx.subscribe();
        tokio::spawn(async move {
            while let Ok(task) = rx.recv().await {
                run_task(cat.clone(), mk, &cpath, task).await;
            }
        });
    }
    Ok(Sender { tx })
}

/// Sender half: the scheduler pushes [`JobTask`]s through it.
#[derive(Clone)]
pub struct Sender {
    tx: Arc<broadcast::Sender<JobTask>>,
}

impl Sender {
    pub async fn enqueue(&self, task: JobTask) -> Result<()> {
        self.tx
            .send(task)
            .map_err(|e| anyhow::anyhow!("job queue closed: {e}"))?;
        Ok(())
    }
}

async fn run_task(catalog: Arc<Catalog>, master_key: [u8; 32], catalog_path: &Path, task: JobTask) {
    let job_id = Uuid::new_v4().to_string();
    if let Err(e) = catalog
        .record_job_started(&job_id, &task.host_id, &task.policy_id)
        .await
    {
        let _ = catalog.record_job_failed(&job_id, &e.to_string()).await;
        return;
    }
    let result = async {
        let ssh = SshManager::new();
        let cfg = build_host_config(&task.host_id, &master_key, &catalog).await?;
        let repo = open_repo(catalog_path, &master_key).await?;
        let chunker = repo.config().chunker;
        let paths: Vec<String> = serde_json::from_str(&task.paths_json)
            .map_err(|e| anyhow::anyhow!("parse policy paths: {e}"))?;
        let snapshot = aegis_core::backup_remote(&repo, &ssh, &cfg, &chunker, &paths).await?;
        catalog
            .record_job_completed(
                &job_id,
                snapshot.stats.new_bytes as i64,
                snapshot.stats.bytes as i64,
            )
            .await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(e) = result {
        let _ = catalog.record_job_failed(&job_id, &e.to_string()).await;
    }
}

async fn build_host_config(
    host_id: &str,
    master_key: &[u8; 32],
    catalog: &Catalog,
) -> Result<aegis_core::ssh::HostConfig> {
    let HostWithKey {
        host: h,
        ssh_key_pem: pem,
    } = catalog.get_host_with_key(host_id, master_key).await?;
    let auth = if pem.is_empty() {
        aegis_core::sftp::SftpAuth::Password(
            std::env::var("AEGIS_SSH_PASSWORD").unwrap_or_default(),
        )
    } else {
        let key = russh::keys::decode_secret_key(&String::from_utf8(pem)?, None)?;
        aegis_core::sftp::SftpAuth::Key(std::sync::Arc::new(key))
    };
    Ok(
        aegis_core::ssh::HostConfig::new(h.ssh_user.clone(), h.address.clone(), auth)
            .with_port(h.ssh_port),
    )
}

async fn open_repo(catalog_path: &Path, _master_key: &[u8; 32]) -> Result<Repository> {
    let pass = std::env::var("AEGIS_PASSPHRASE")
        .map_err(|_| anyhow::anyhow!("AEGIS_PASSPHRASE is required"))?;
    let backend = Box::new(aegis_core::backend::LocalBackend::new(catalog_path));
    Repository::open(backend, &pass)
        .await
        .map_err(|e| anyhow::anyhow!("opening repository: {e}"))
}
