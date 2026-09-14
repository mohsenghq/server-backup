//! Integration tests for the `aegis host …` workflow's engine path: hosts
//! registered in the catalog, backed up concurrently over the agentless path
//! against in-process SSH servers, with reachability recorded back. (The CLI
//! module itself is exercised via the clap debug-assert and the engine path
//! here mirrors `hosts::backup_all` exactly.)

mod sftp_server;

use aegis_core::catalog::{BackupMode, Catalog, HostStatus};
use aegis_core::sftp::SftpAuth;
use aegis_core::ssh::{HostConfig, SshManager};
use aegis_core::{ChunkerConfig, Repository, Snapshot};
use std::sync::Arc;
use tempfile::TempDir;

fn fast_kdf() -> aegis_core::crypto::KdfParams {
    aegis_core::crypto::KdfParams {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    }
}

fn fast_chunker() -> ChunkerConfig {
    ChunkerConfig::new(64, 256, 1024).unwrap()
}

fn test_host(port: u16) -> HostConfig {
    HostConfig::new(USERNAME, "127.0.0.1", SftpAuth::Password(PASSWORD.into()))
        .with_port(port)
        .with_host_key_policy(aegis_core::sftp::HostKeyPolicy::AcceptAny)
}

fn write_tree(root: &std::path::Path) {
    let dir = root.join("site");
    std::fs::create_dir_all(dir.join("etc")).unwrap();
    std::fs::write(dir.join("etc/app.conf"), b"key=value\n").unwrap();
    std::fs::write(dir.join("etc/big.bin"), vec![0xCDu8; 5000]).unwrap();
}

use sftp_server::{PASSWORD, USERNAME};

#[tokio::test]
async fn host_inventory_backup_all_and_restore() {
    // Two independent "hosts" (two jailed servers) plus a repo + catalog.
    let host_a = TempDir::new().unwrap();
    let host_b = TempDir::new().unwrap();
    write_tree(host_a.path());
    write_tree(host_b.path());
    let repo_dir = TempDir::new().unwrap();

    let port_a = sftp_server::spawn_sftp_server(host_a.path().to_path_buf())
        .await
        .unwrap();
    let port_b = sftp_server::spawn_sftp_server(host_b.path().to_path_buf())
        .await
        .unwrap();

    let catalog = Arc::new(Catalog::in_memory().await.unwrap());
    // Passwords are never persisted: hosts with no stored key fall back to
    // AEGIS_SSH_PASSWORD at connect time — exactly the CLI's contract.
    let h1 = catalog
        .add_host(
            "web-1",
            "127.0.0.1",
            port_a,
            USERNAME,
            b"",
            BackupMode::Agentless,
            &test_key(),
        )
        .await
        .unwrap();
    let h2 = catalog
        .add_host(
            "web-2",
            "127.0.0.1",
            port_b,
            USERNAME,
            b"",
            BackupMode::Agentless,
            &test_key(),
        )
        .await
        .unwrap();
    assert_eq!(catalog.list_hosts().await.unwrap().len(), 2);

    let repo = Arc::new(
        Repository::init_local_with_kdf(repo_dir.path(), fast_chunker(), "pass", fast_kdf())
            .await
            .unwrap(),
    );

    let results = backup_all(
        catalog.clone(),
        repo.clone(),
        vec![test_host(port_a), test_host(port_b)],
        "/site",
    )
    .await;
    assert_eq!(results.len(), 2, "one result per host");
    assert!(
        results.iter().all(|(_, _, e)| e.is_none()),
        "all hosts succeeded"
    );

    // Reachability recorded back into the catalog.
    assert_eq!(
        catalog.get_host(&h1.id).await.unwrap().status,
        HostStatus::Reachable
    );
    assert_eq!(
        catalog.get_host(&h2.id).await.unwrap().status,
        HostStatus::Reachable
    );

    // Restore host A's snapshot and compare byte-for-byte.
    let (h1_name, snapshot, _) = results.iter().find(|(n, _, _)| n == "web-1").unwrap();
    let _ = h1_name;
    let out = TempDir::new().unwrap();
    repo.restore(&snapshot.as_ref().unwrap().id, out.path())
        .await
        .unwrap();
    for rel in ["site/etc/app.conf", "site/etc/big.bin"] {
        let a = std::fs::read(host_a.path().join(rel)).unwrap();
        let b = std::fs::read(out.path().join(rel)).unwrap();
        assert_eq!(a, b, "{rel} restored byte-identically");
    }

    // A failing host is reported, not fatal: point one at a dead port.
    catalog.remove_host(&h1.id).await.unwrap();
    catalog.remove_host(&h2.id).await.unwrap();
    let dead = catalog
        .add_host(
            "dead",
            "127.0.0.1",
            1,
            USERNAME,
            b"",
            BackupMode::Agentless,
            &test_key(),
        )
        .await
        .unwrap();
    let results = backup_all(catalog.clone(), repo, vec![test_host(1)], "/site").await;
    let (_, _, err) = &results[0];
    assert!(err.is_some(), "dead host must fail with an error");
    assert_eq!(
        catalog.get_host(&dead.id).await.unwrap().status,
        HostStatus::Unreachable
    );
}

fn test_key() -> [u8; 32] {
    [9u8; 32]
}

/// The concurrent, capacity-capped loop the CLI's `hosts::backup_all` runs,
/// mirrored against the public `aegis-core` API.
async fn backup_all(
    catalog: Arc<Catalog>,
    repo: Arc<Repository>,
    cfgs: Vec<HostConfig>,
    path: &str,
) -> Vec<(String, Option<Snapshot>, Option<String>)> {
    let hosts = catalog.list_hosts().await.unwrap();
    let ssh = Arc::new(SshManager::new());
    let sem = Arc::new(tokio::sync::Semaphore::new(4));
    let mut jobs = tokio::task::JoinSet::new();
    for (host, cfg) in hosts.into_iter().zip(cfgs) {
        let catalog = catalog.clone();
        let ssh = ssh.clone();
        let sem = sem.clone();
        let repo = repo.clone();
        let paths = vec![path.to_string()];
        jobs.spawn(async move {
            let _permit = sem.acquire().await;
            let chunker = repo.config().chunker;
            match aegis_core::backup_remote(&repo, &ssh, &cfg, &chunker, &paths).await {
                Ok(s) => {
                    let _ = catalog
                        .set_host_status(&host.id, HostStatus::Reachable)
                        .await;
                    (host.name.clone(), Some(s), None)
                }
                Err(e) => {
                    let _ = catalog
                        .set_host_status(&host.id, HostStatus::Unreachable)
                        .await;
                    (host.name.clone(), None, Some(e.to_string()))
                }
            }
        });
    }
    let mut out = Vec::new();
    while let Some(res) = jobs.join_next().await {
        out.push(res.unwrap());
    }
    out
}
