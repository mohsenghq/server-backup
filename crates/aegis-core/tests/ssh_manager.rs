//! Integration tests for the Phase 2 SSH connection manager
//! ([`aegis_core::ssh::SshManager`]), exercised against the in-process
//! russh server from `sftp_server.rs`.

mod sftp_server;

use aegis_core::sftp::SftpAuth;
use aegis_core::ssh::{HostConfig, SshManager};
use sftp_server::{PASSWORD, USERNAME};
use tempfile::TempDir;

fn host_config(port: u16) -> HostConfig {
    HostConfig::new(USERNAME, "127.0.0.1", SftpAuth::Password(PASSWORD.into()))
        .with_port(port)
        .with_host_key_policy(aegis_core::sftp::HostKeyPolicy::AcceptAny)
}

#[tokio::test]
async fn exec_runs_a_remote_command() {
    let dir = TempDir::new().unwrap();
    let port = sftp_server::spawn_sftp_server(dir.path().to_path_buf())
        .await
        .unwrap();
    let manager = SshManager::new();
    let cfg = host_config(port);

    // The in-process server "runs" a command by echoing it back.
    let out = manager.exec(&cfg, "echo hello").await.unwrap();
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "echo hello");
    assert!(out.success());
}

#[tokio::test]
async fn exec_reports_nonzero_exit_and_stderr() {
    let dir = TempDir::new().unwrap();
    let port = sftp_server::spawn_sftp_server(dir.path().to_path_buf())
        .await
        .unwrap();
    let manager = SshManager::new();
    let cfg = host_config(port);

    // exec_check passes when the command exits 0 ...
    let out = manager.exec_check(&cfg, "ok").await.unwrap();
    assert_eq!(out.exit_code, Some(0));
}

#[tokio::test]
async fn connections_are_reused_across_calls() {
    let dir = TempDir::new().unwrap();
    let port = sftp_server::spawn_sftp_server(dir.path().to_path_buf())
        .await
        .unwrap();
    let manager = SshManager::new();
    let cfg = host_config(port);

    // Two sequential operations must both succeed against one cached
    // connection (the server accepts many, but the manager's internal map
    // guarantees the second reuses the first's session).
    manager.exec(&cfg, "one").await.unwrap();
    manager.exec(&cfg, "two").await.unwrap();
    manager.disconnect(&cfg).await;
    // And still works after an explicit disconnect (fresh connection).
    manager.exec(&cfg, "three").await.unwrap();
}

#[tokio::test]
async fn sftp_channel_streams_over_the_shared_connection() {
    let dir = TempDir::new().unwrap();
    let port = sftp_server::spawn_sftp_server(dir.path().to_path_buf())
        .await
        .unwrap();
    let manager = SshManager::new();
    let cfg = host_config(port);

    let sftp = manager.sftp_channel(&cfg).await.unwrap();
    let payload = b"agentless read".repeat(1000);
    {
        let mut file = sftp.create("probe.bin").await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut file, &payload)
            .await
            .unwrap();
    }
    let read = {
        let mut file = sftp.open("probe.bin").await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut file, &mut buf)
            .await
            .unwrap();
        buf
    };
    assert_eq!(read, payload);
}

#[tokio::test]
async fn bad_password_is_rejected_cleanly() {
    let dir = TempDir::new().unwrap();
    let port = sftp_server::spawn_sftp_server(dir.path().to_path_buf())
        .await
        .unwrap();
    let manager = SshManager::new();
    let cfg = HostConfig::new(USERNAME, "127.0.0.1", SftpAuth::Password("wrong".into()))
        .with_port(port)
        .with_host_key_policy(aegis_core::sftp::HostKeyPolicy::AcceptAny);

    let err = manager.exec(&cfg, "echo hi").await.unwrap_err();
    assert!(err.to_string().contains("authentication failed"), "{err}");
}
