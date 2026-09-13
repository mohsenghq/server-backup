//! Integration tests for agentless remote-read backup: a remote tree served
//! by the in-process SFTP server, backed up into a local repository, then
//! verified and restored byte-identically.

mod sftp_server;

use aegis_core::sftp::{HostKeyPolicy, SftpAuth};
use aegis_core::ssh::{HostConfig, SshManager};
use aegis_core::{backup_remote, ChunkerConfig, Repository};
use sftp_server::{PASSWORD, USERNAME};
use tempfile::TempDir;

/// Fast Argon2id params for tests (mirrors `backup_restore.rs`).
fn fast_kdf() -> aegis_core::crypto::KdfParams {
    aegis_core::crypto::KdfParams {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    }
}

fn host_config(port: u16) -> HostConfig {
    HostConfig::new(USERNAME, "127.0.0.1", SftpAuth::Password(PASSWORD.into()))
        .with_port(port)
        .with_host_key_policy(HostKeyPolicy::AcceptAny)
}

/// Write a tree with enough mixed content to cross chunk boundaries.
fn write_tree(root: &std::path::Path) {
    let dir = root.join("site");
    std::fs::create_dir_all(dir.join("etc")).unwrap();
    std::fs::create_dir_all(dir.join("var/log")).unwrap();
    std::fs::write(dir.join("etc/nginx.conf"), b"server {\n listen 80;\n}\n").unwrap();
    // One file well past the test chunker's max, to exercise multi-chunking.
    std::fs::write(dir.join("var/log/big.bin"), vec![0xABu8; 7000]).unwrap();
    std::fs::write(dir.join("var/log/app.log"), b"line1\nline2\nline3\n").unwrap();
}

fn fast_chunker() -> ChunkerConfig {
    ChunkerConfig::new(64, 256, 1024).unwrap()
}

#[tokio::test]
async fn remote_backup_snapshots_verify_and_restore() {
    let src = TempDir::new().unwrap();
    write_tree(src.path());
    let repo_dir = TempDir::new().unwrap();
    let port = sftp_server::spawn_sftp_server(src.path().to_path_buf())
        .await
        .unwrap();

    let repo = Repository::init_local_with_kdf(repo_dir.path(), fast_chunker(), "pass", fast_kdf())
        .await
        .unwrap();

    let ssh = SshManager::new();
    let host = host_config(port);
    // The in-process server is jailed to `src`; POSIX-style absolute paths
    // address content inside the jail (the SFTP protocol is POSIX-pathed).
    let root_path = "/site".to_string();
    let snapshot = backup_remote(
        &repo,
        &ssh,
        &host,
        &fast_chunker(),
        std::slice::from_ref(&root_path),
    )
    .await
    .unwrap();

    // Files and bytes were actually captured.
    assert_eq!(snapshot.stats.files, 3, "{:?}", snapshot.stats);
    assert!(snapshot.stats.bytes > 7000);

    // The snapshot verifies deeply.
    repo.verify(&snapshot, true).await.unwrap();

    // Restore is byte-identical to the source.
    let out = TempDir::new().unwrap();
    repo.restore(&snapshot.id, out.path()).await.unwrap();
    let restored = out.path().join("site");
    assert!(restored.join("etc/nginx.conf").exists());
    assert_eq!(
        std::fs::read(restored.join("var/log/big.bin")).unwrap(),
        vec![0xABu8; 7000]
    );
    assert_eq!(
        std::fs::read(restored.join("var/log/app.log")).unwrap(),
        b"line1\nline2\nline3\n"
    );
}

#[tokio::test]
async fn remote_backup_dedups_unchanged_trees() {
    let src = TempDir::new().unwrap();
    write_tree(src.path());
    let repo_dir = TempDir::new().unwrap();
    let port = sftp_server::spawn_sftp_server(src.path().to_path_buf())
        .await
        .unwrap();

    let repo = Repository::init_local_with_kdf(repo_dir.path(), fast_chunker(), "pass", fast_kdf())
        .await
        .unwrap();

    let ssh = SshManager::new();
    let host = host_config(port);
    let root_path = "/site".to_string();
    let first = backup_remote(
        &repo,
        &ssh,
        &host,
        &fast_chunker(),
        std::slice::from_ref(&root_path),
    )
    .await
    .unwrap();
    let second = backup_remote(&repo, &ssh, &host, &fast_chunker(), &[root_path])
        .await
        .unwrap();

    assert!(first.stats.new_chunks > 0);
    // Nothing changed remotely: the second run re-hashes but writes nothing.
    assert_eq!(second.stats.new_chunks, 0);
    assert_eq!(second.stats.new_tree_nodes, 0);
}

#[tokio::test]
async fn relative_remote_path_is_rejected() {
    let src = TempDir::new().unwrap();
    let repo_dir = TempDir::new().unwrap();
    let port = sftp_server::spawn_sftp_server(src.path().to_path_buf())
        .await
        .unwrap();

    let repo = Repository::init_local_with_kdf(repo_dir.path(), fast_chunker(), "pass", fast_kdf())
        .await
        .unwrap();

    let ssh = SshManager::new();
    let host = host_config(port);
    let err = backup_remote(&repo, &ssh, &host, &fast_chunker(), &["etc".into()])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("must be absolute"), "{err}");
}
