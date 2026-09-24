//! Multi-backend replication: mirror a repository's objects to a second
//! backend (Phase 6 roadmap item, `docs/07-web-ui.md` replication config).
//!
//! Replication is a pure object-level copy: every key in the source
//! (`config`, `keys/`, `blobs/`, `snapshots/`, `index/`) that is missing on
//! the target is copied byte-for-byte. Objects already present on the target
//! are left alone, so a repeated run only transfers the delta — the same
//! incremental property backups enjoy. Ciphertexts are opaque here, so the
//! mirror needs no passphrase and stays consistent with the source even
//! across re-keying.
//!
//! The intended mode is `ReplicateMode::Mirror` after every backup job, but
//! the API is standalone: any two backends of the same repo format work
//! (local→SFTP, SFTP→local, …).

use crate::backend::Backend;
use crate::error::{Error, Result};

/// What `replicate` compares and copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicateMode {
    /// Copy every source key missing on the target (default, incremental).
    Mirror,
    /// Like mirror, but also re-copy differing objects (repair after
    /// corruption). Slower: every shared key is read on both sides.
    Repair,
}

/// The result of one replication run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicateStats {
    /// Objects copied to the target this run.
    pub copied: u64,
    /// Objects already present (identical in `Mirror`, or re-copied in
    /// `Repair` counts here only when identical).
    pub skipped: u64,
    /// Objects re-copied because their bytes differed (`Repair` only).
    pub repaired: u64,
}

/// Which prefixes make up a repository. `config` is a bare key; the rest are
/// prefixes enumerated from the source.
pub(crate) const REPO_PREFIXES: [&str; 4] = ["blobs/", "snapshots/", "index/", "keys/"];

/// Mirror the source repository's objects onto the target backend.
///
/// Returns per-run stats. The target needs no passphrase: objects are
/// already encrypted at rest and are copied as opaque bytes.
///
/// # Errors
///
/// Returns backend errors from either side; on `Mirror` the run aborts at
/// the first failure (earlier copies stay valid — writes are atomic).
pub async fn replicate(
    source: &dyn Backend,
    target: &dyn Backend,
    mode: ReplicateMode,
) -> Result<ReplicateStats> {
    let mut stats = ReplicateStats {
        copied: 0,
        skipped: 0,
        repaired: 0,
    };

    // The config must exist on the source: without it this is not a repo.
    let config = source
        .get("config")
        .await
        .map_err(|_| Error::MalformedBlob("source is not a repository: config missing".into()))?;
    match target.exists("config").await? {
        false => {
            target.put("config", &config).await?;
            stats.copied += 1;
        }
        true => {
            let existing = target.get("config").await?;
            if existing != config {
                return Err(Error::MalformedBlob(
                    "target is a different repository (config mismatch)".into(),
                ));
            }
            stats.skipped += 1;
        }
    }

    for prefix in REPO_PREFIXES {
        let keys = source.list(prefix).await?;
        for key in keys {
            let exists = target.exists(&key).await?;
            match (exists, mode) {
                (false, _) => {
                    let data = source.get(&key).await?;
                    target.put(&key, &data).await?;
                    stats.copied += 1;
                }
                (true, ReplicateMode::Mirror) => stats.skipped += 1,
                (true, ReplicateMode::Repair) => {
                    let data = source.get(&key).await?;
                    let existing = target.get(&key).await?;
                    if existing == data {
                        stats.skipped += 1;
                    } else {
                        target.put(&key, &data).await?;
                        stats.repaired += 1;
                    }
                }
            }
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::LocalBackend;

    async fn sample_repo(root: &std::path::Path) -> (Box<dyn Backend>, Vec<String>) {
        let b = LocalBackend::new(root);
        let keys = vec![
            "config".to_string(),
            "keys/default.json".to_string(),
            "blobs/aa/aabbcc".to_string(),
            "blobs/dd/deadbeef".to_string(),
            "snapshots/snap1.json".to_string(),
            "index/snap1.json".to_string(),
        ];
        for (i, k) in keys.iter().enumerate() {
            b.put(k, format!("payload-{i}").as_bytes()).await.unwrap();
        }
        (Box::new(b), keys)
    }

    #[tokio::test]
    async fn mirror_copies_everything_then_only_the_delta() {
        let dir = tempfile::tempdir().unwrap();
        let (source, keys) = sample_repo(dir.path().join("src").as_path()).await;
        let target = LocalBackend::new(dir.path().join("dst"));

        let s1 = replicate(source.as_ref(), &target, ReplicateMode::Mirror)
            .await
            .unwrap();
        assert_eq!(s1.copied, keys.len() as u64);
        assert_eq!(s1.skipped, 0);

        // Second run: nothing new → all skipped.
        let s2 = replicate(source.as_ref(), &target, ReplicateMode::Mirror)
            .await
            .unwrap();
        assert_eq!(s2.copied, 0);
        assert_eq!(s2.skipped, keys.len() as u64);

        // New snapshot appears → only the delta is copied.
        source.put("snapshots/snap2.json", b"two").await.unwrap();
        source.put("index/snap2.json", b"two").await.unwrap();
        let s3 = replicate(source.as_ref(), &target, ReplicateMode::Mirror)
            .await
            .unwrap();
        assert_eq!(s3.copied, 2);
        assert_eq!(s3.skipped, (keys.len() + 2 - 2) as u64);

        // Byte-for-byte equality across both sides.
        for k in &keys {
            assert_eq!(
                source.get(k).await.unwrap(),
                target.get(k).await.unwrap(),
                "key {k}"
            );
        }
    }

    #[tokio::test]
    async fn repair_re_copies_corrupted_objects() {
        let dir = tempfile::tempdir().unwrap();
        let (source, keys) = sample_repo(dir.path().join("src").as_path()).await;
        let target = LocalBackend::new(dir.path().join("dst"));
        replicate(source.as_ref(), &target, ReplicateMode::Mirror)
            .await
            .unwrap();

        // Corrupt one mirrored object.
        target.put("blobs/aa/aabbcc", b"corrupted").await.unwrap();

        let s = replicate(source.as_ref(), &target, ReplicateMode::Repair)
            .await
            .unwrap();
        eprintln!("stats: {s:?} keys: {keys:?}");
        assert_eq!(s.repaired, 1);
        assert_eq!(s.skipped, keys.len() as u64 - 1);
        assert_eq!(s.skipped + s.repaired, keys.len() as u64);
        assert_eq!(target.get("blobs/aa/aabbcc").await.unwrap(), b"payload-2");
    }

    #[tokio::test]
    async fn refuses_to_mirror_a_different_repository() {
        let dir = tempfile::tempdir().unwrap();
        let (source, _) = sample_repo(dir.path().join("src").as_path()).await;
        let target = LocalBackend::new(dir.path().join("dst"));
        target
            .put("config", b"a-different-repo-config")
            .await
            .unwrap();
        let err = replicate(source.as_ref(), &target, ReplicateMode::Mirror)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::MalformedBlob(_)));
    }

    #[tokio::test]
    async fn non_repository_source_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let empty = LocalBackend::new(dir.path().join("empty"));
        let target = LocalBackend::new(dir.path().join("dst"));
        let err = replicate(&empty, &target, ReplicateMode::Mirror)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::MalformedBlob(_)));
    }
}
