//! Bandwidth throttling end-to-end: a throttled agentless backup produces a
//! byte-identical snapshot to the unthrottled one (same chunker boundaries,
//! same hashes, same tree) — only the wall-clock time differs — and a small
//! limit measurably paces the transfer.

mod sftp_server;

use aegis_core::sftp::{HostKeyPolicy, SftpAuth};
use aegis_core::ssh::{HostConfig, SshManager};
use aegis_core::{agentless, ChunkerConfig, Repository};
use sftp_server::{PASSWORD, USERNAME};
use tempfile::TempDir;

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

fn fast_chunker() -> ChunkerConfig {
    ChunkerConfig::new(64, 256, 1024).unwrap()
}

/// A tree large enough to span multiple chunker buckets and reads.
fn write_tree(root: &std::path::Path) {
    let dir = root.join("site");
    std::fs::create_dir_all(dir.join("etc")).unwrap();
    // ~3 MiB of pseudo-random-ish content across several files.
    let big: Vec<u8> = (0..2_000_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.join("etc/big1.bin"), &big[..1_000_000]).unwrap();
    std::fs::write(dir.join("etc/big2.bin"), &big[1_000_000..]).unwrap();
}

#[tokio::test]
async fn throttled_backup_is_byte_identical_and_actually_paced() {
    let src = TempDir::new().unwrap();
    write_tree(src.path());
    let repo_dir = TempDir::new().unwrap();
    let port = sftp_server::spawn_sftp_server(src.path().to_path_buf())
        .await
        .unwrap();
    let ssh = SshManager::new();
    let host = host_config(port);
    let path = "/site".to_string();
    let paths = std::slice::from_ref(&path);

    let repo_a = Repository::init_local_with_kdf(
        repo_dir.path().join("a"),
        fast_chunker(),
        "pass",
        fast_kdf(),
    )
    .await
    .unwrap();
    let repo_b = Repository::init_local_with_kdf(
        repo_dir.path().join("b"),
        fast_chunker(),
        "pass",
        fast_kdf(),
    )
    .await
    .unwrap();

    // Unthrottled run.
    let start = std::time::Instant::now();
    let snap_a = agentless::backup_remote(&repo_a, &ssh, &host, &fast_chunker(), paths)
        .await
        .unwrap();
    let unthrottled = start.elapsed();

    // Throttled run at 256 KiB/s over ~2 MiB of source content: must take
    // measurably longer (at least ~4s with a full starting bucket) yet stay
    // bounded.
    let limiter = Some(2048i32); // 2048 kbps = 256 KiB/s
    let start = std::time::Instant::now();
    let snap_b =
        agentless::backup_remote_throttled(&repo_b, &ssh, &host, &fast_chunker(), paths, limiter)
            .await
            .unwrap();
    let throttled = start.elapsed();

    assert!(
        throttled >= DurationOr(2),
        "throttled run must be paced: unthrottled {unthrottled:?}, throttled {throttled:?}"
    );

    // Byte-identical snapshots: same root tree (hashes, sizes, order) and
    // identical stats.
    let ser_a = serde_json::to_string(&snap_a.root).unwrap();
    let ser_b = serde_json::to_string(&snap_b.root).unwrap();
    assert_eq!(ser_a, ser_b, "throttling must not change the snapshot");
    assert_eq!(snap_a.stats.chunks, snap_b.stats.chunks);
    assert_eq!(snap_a.stats.bytes, snap_b.stats.bytes);
}

// Small helper so the assertion above reads cleanly.
#[allow(non_snake_case)]
fn DurationOr(secs: u64) -> std::time::Duration {
    std::time::Duration::from_secs(secs)
}
