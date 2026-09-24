//! Agentless remote-read backup (`docs/04-host-connection-modes.md`).
//!
//! The control plane opens an SSH session to the target, streams each remote
//! file over SFTP, and chunks/hashes/compresses/encrypts locally before the
//! bytes reach the repository. Nothing is staged on the target beyond the SSH
//! session itself — no agent, no temp files, no scheduled task.
//!
//! The snapshot produced is identical in format to a local one: same Merkle
//! tree, same blob envelope, same index. A remote snapshot restores with the
//! ordinary [`Repository::restore`](crate::Repository::restore) and verifies
//! with the ordinary `verify`.
//!
//! Mirroring the local path, only regular files are captured; symlinks and
//! other non-regular remote entries are skipped.

use std::collections::{HashMap, HashSet};

use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, FileType};

use crate::chunk::{chunk_async_stream, ChunkerConfig};
use crate::error::{Error, Result};
use crate::repo::Repository;
use crate::snapshot::SnapshotStats;
use crate::ssh::{HostConfig, SshManager};
use crate::throttle::BandwidthLimiter;
use crate::tree::Node;

/// Per-run state threaded through the recursive walk: what this run has seen
/// and what it has written, plus the stats it is accumulating.
struct Run<'a> {
    repo: &'a Repository,
    sftp: &'a SftpSession,
    chunker: &'a ChunkerConfig,
    stats: SnapshotStats,
    /// Chunk hashes deduplicated within this run.
    seen: HashSet<String>,
    /// Stored blob sizes this run actually wrote (for the snapshot index).
    written: HashMap<String, u64>,
    /// Shared bandwidth bucket when a limit is configured.
    limiter: Option<std::sync::Arc<tokio::sync::Mutex<BandwidthLimiter>>>,
}

/// Back up every regular file under the remote `paths` into `repo` and return
/// the new snapshot.
///
/// Each path must be an absolute remote directory; its files are chunked
/// stream-wise over SFTP, deduplicated against the repository, and committed
/// as one snapshot with one root entry per path.
///
/// # Errors
///
/// Returns [`Error::Ssh`] for transport/authentication/SFTP failures and
/// [`Error::Io`] for repository write failures. An unreadable remote file
/// aborts the run rather than producing a silently incomplete snapshot.
pub async fn backup_remote(
    repo: &Repository,
    ssh: &SshManager,
    host: &HostConfig,
    chunker: &ChunkerConfig,
    paths: &[String],
) -> Result<crate::snapshot::Snapshot> {
    backup_remote_throttled(repo, ssh, host, chunker, paths, None).await
}

/// [`backup_remote`] with an optional bandwidth limit (kiB/s) pacing the
/// SFTP reads. Snapshots are byte-identical either way.
///
/// # Errors
///
/// Same as [`backup_remote`].
pub async fn backup_remote_throttled(
    repo: &Repository,
    ssh: &SshManager,
    host: &HostConfig,
    chunker: &ChunkerConfig,
    paths: &[String],
    bandwidth_limit_kbps: Option<i32>,
) -> Result<crate::snapshot::Snapshot> {
    let limiter = BandwidthLimiter::from_kbps(bandwidth_limit_kbps)
        .map(|l| std::sync::Arc::new(tokio::sync::Mutex::new(l)));
    let sftp = ssh.sftp_channel(host).await?;
    let mut run = Run {
        repo,
        sftp: &sftp,
        chunker,
        stats: SnapshotStats::default(),
        seen: HashSet::new(),
        written: HashMap::new(),
        limiter,
    };
    let mut roots = Vec::with_capacity(paths.len());
    let mut children = Vec::with_capacity(paths.len());

    for path in paths {
        if !path.starts_with('/') {
            return Err(Error::Ssh(format!(
                "remote backup path `{path}` must be absolute"
            )));
        }
        roots.push(path.clone());
        // The tree stores paths relative to the root's parent (one level up),
        // exactly like the local path, so restore recreates the directory by
        // its own name.
        let dir_name = path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or(path)
            .to_string();
        children.push(backup_dir_recursive(&mut run, path, &dir_name).await?);
    }

    let root = Node::Dir {
        name: "root".into(),
        children,
    };
    repo.commit_snapshot(root, roots, run.stats, &mut run.written)
        .await
}

/// Recursively build the tree node for one remote directory.
async fn backup_dir_recursive(run: &mut Run<'_>, dir: &str, name: &str) -> Result<Node> {
    let entries = run
        .sftp
        .read_dir(dir)
        .await
        .map_err(|e| Error::Ssh(format!("read_dir {dir}: {e}")))?;

    let mut listed: Vec<(String, FileType, FileAttributes)> = entries
        .map(|e| {
            let ft = e.file_type();
            let meta = e.metadata();
            (e.file_name(), ft, meta)
        })
        .filter(|(name, _, _)| name != "." && name != "..")
        .collect();
    listed.sort_by(|a, b| a.0.cmp(&b.0));

    let mut children = Vec::with_capacity(listed.len());
    for (entry_name, file_type, meta) in listed {
        let child_path = format!("{}/{entry_name}", dir.trim_end_matches('/'));
        if file_type.is_dir() {
            children.push(Box::pin(backup_dir_recursive(run, &child_path, &entry_name)).await?);
        } else if file_type.is_file() {
            children.push(backup_file(run, &child_path, &entry_name, &meta).await?);
        }
        // Symlinks and other non-regular entries are skipped, as locally.
    }

    let mut node = Node::Dir {
        name: name.to_string(),
        children,
    };
    node.sort();
    Ok(node)
}

/// Stream one remote file over SFTP, chunk and store it; return its node.
async fn backup_file(
    run: &mut Run<'_>,
    path: &str,
    name: &str,
    meta: &FileAttributes,
) -> Result<Node> {
    let file = run
        .sftp
        .open(path)
        .await
        .map_err(|e| Error::Ssh(format!("open {path}: {e}")))?;

    // The chunker drives the reads; the limiter paces the *transfer* after
    // the pass: each file's bytes are charged to the shared bucket, which
    // sleeps for the excess over the configured rate. (The SFTP client
    // delivers file data through an unbounded internal channel, so gating
    // the reader cannot pace the network transfer.)
    let limiter = run.limiter.clone();
    let mut transferred: u64 = 0;
    let mut chunk_hashes = Vec::new();
    // The sink is sync, so first-sight chunk bytes are buffered here and
    // stored after the pass. Already-seen chunks (this run or an earlier
    // snapshot) are dropped immediately — only NEW content costs memory,
    // bounded by the distinct bytes of the file.
    let mut pending: Vec<(String, Vec<u8>)> = Vec::new();
    chunk_async_stream(file, run.chunker, |chunk, bytes| {
        let hex = chunk.hash.to_hex().to_string();
        run.stats.chunks += 1;
        run.stats.bytes += chunk.length as u64;
        chunk_hashes.push(hex.clone());
        transferred += chunk.length as u64;
        if !run.seen.contains(&hex) && !pending.iter().any(|(h, _)| h == &hex) {
            pending.push((hex, bytes.to_vec()));
        }
        Ok(())
    })
    .await?;

    if let Some(l) = &limiter {
        l.lock().await.acquire(transferred).await;
    }

    for (hex, bytes) in pending {
        run.repo
            .store_chunk(
                &hex,
                &bytes,
                &mut run.seen,
                &mut run.stats,
                &mut run.written,
            )
            .await?;
    }

    run.stats.files += 1;
    Ok(Node::File {
        name: name.to_string(),
        size: meta.size.unwrap_or(0),
        mode: meta.permissions,
        mtime: meta.mtime.map(i64::from),
        chunks: chunk_hashes,
    })
}
