//! The repository: init, backup, restore, and snapshot listing.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::backend::{Backend, LocalBackend};
use crate::chunk::{chunk_stream, ChunkerConfig};
use crate::error::{Error, Result};
use crate::snapshot::{FileEntry, Snapshot, SnapshotStats};

/// Repository format version this build reads and writes.
pub const FORMAT_VERSION: u32 = 1;

const CONFIG_KEY: &str = "config";
const BLOBS_PREFIX: &str = "blobs";
const SNAPSHOTS_PREFIX: &str = "snapshots";

/// The repository's `config` document.
///
// ponytail: plaintext in Phase 0. `docs/10-security-model.md` requires this to
// be encrypted under the repo master key; that lands with the Phase 1
// encryption checklist item, alongside `keys/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoConfig {
    /// Repository format version — see [`FORMAT_VERSION`].
    pub version: u32,
    /// Stable identifier for this repository.
    pub id: String,
    /// Chunker parameters, fixed at `init` time. Changing them would defeat
    /// deduplication against existing snapshots.
    pub chunker: ChunkerConfig,
}

/// An open Aegis repository.
pub struct Repository {
    backend: Box<dyn Backend>,
    config: RepoConfig,
}

impl Repository {
    /// Create a repository in an empty or non-existent local directory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RepoExists`] if a `config` is already present,
    /// [`Error::InvalidChunkerConfig`] for bad chunker parameters, or
    /// [`Error::Io`] if the directory cannot be written.
    pub async fn init(path: impl AsRef<Path>, chunker: ChunkerConfig) -> Result<Self> {
        chunker.validate()?;
        let path = path.as_ref();
        let backend = LocalBackend::new(path);
        if backend.exists(CONFIG_KEY).await? {
            return Err(Error::RepoExists(path.to_path_buf()));
        }
        let config = RepoConfig {
            version: FORMAT_VERSION,
            id: uuid::Uuid::new_v4().to_string(),
            chunker,
        };
        let bytes = serde_json::to_vec_pretty(&config).expect("RepoConfig is serializable");
        backend.put(CONFIG_KEY, &bytes).await?;
        Ok(Self {
            backend: Box::new(backend),
            config,
        })
    }

    /// Open an existing repository on the local filesystem.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RepoNotFound`] if there is no `config`,
    /// [`Error::UnsupportedFormat`] if it was written by an incompatible
    /// version, or [`Error::Malformed`] if it cannot be parsed.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let backend = LocalBackend::new(path);
        if !backend.exists(CONFIG_KEY).await? {
            return Err(Error::RepoNotFound(path.to_path_buf()));
        }
        let raw = backend.get(CONFIG_KEY).await?;
        let config: RepoConfig =
            serde_json::from_slice(&raw).map_err(|source| Error::Malformed {
                what: "repository config".into(),
                source,
            })?;
        if config.version != FORMAT_VERSION {
            return Err(Error::UnsupportedFormat {
                found: config.version,
                supported: FORMAT_VERSION,
            });
        }
        Ok(Self {
            backend: Box::new(backend),
            config,
        })
    }

    /// This repository's configuration.
    pub fn config(&self) -> &RepoConfig {
        &self.config
    }

    /// Back up every regular file under `paths`, writing a new snapshot.
    ///
    /// Symlinks are not followed and are skipped this phase. Unreadable files
    /// abort the run rather than producing a silently incomplete snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if a source path or the backend cannot be read/written.
    pub async fn backup(&self, paths: &[PathBuf]) -> Result<Snapshot> {
        let mut files = Vec::new();
        let mut stats = SnapshotStats::default();
        // Chunks deduplicated within this run, so a file duplicated inside one
        // backup does not cost a second existence check per chunk.
        let mut seen: HashSet<String> = HashSet::new();

        let mut roots = Vec::with_capacity(paths.len());
        for root in paths {
            let root = std::fs::canonicalize(root).map_err(|e| Error::io(root, e))?;
            roots.push(root.display().to_string());
            // The snapshot stores paths relative to the root's parent so that
            // restoring recreates the backed-up directory by name.
            let strip_base = root.parent().unwrap_or(root.as_path()).to_path_buf();

            for entry in walkdir::WalkDir::new(&root).follow_links(false) {
                let entry = entry.map_err(|e| {
                    let path = e.path().unwrap_or(&root).to_path_buf();
                    Error::io(
                        path,
                        e.into_io_error()
                            .unwrap_or_else(|| std::io::Error::other("walk failed")),
                    )
                })?;
                if !entry.file_type().is_file() {
                    continue;
                }
                let entry_path = entry.path();
                let rel = entry_path.strip_prefix(&strip_base).unwrap_or(entry_path);
                let meta = entry.metadata().map_err(|e| {
                    Error::io(
                        entry_path,
                        e.into_io_error()
                            .unwrap_or_else(|| std::io::Error::other("metadata failed")),
                    )
                })?;

                let file = std::fs::File::open(entry_path).map_err(|e| Error::io(entry_path, e))?;
                let mut chunk_hashes = Vec::new();
                let mut pending: Vec<(String, Vec<u8>)> = Vec::new();

                // ponytail: reads the whole file every run. The mtime+size
                // fast-path against the previous snapshot (docs/03) and the
                // `redb` dedup index are Phase 1 items; without them an
                // unchanged tree still re-hashes but writes no new blobs.
                chunk_stream(
                    std::io::BufReader::new(file),
                    &self.config.chunker,
                    |chunk, bytes| {
                        let hex = chunk.hash.to_hex().to_string();
                        stats.chunks += 1;
                        stats.bytes += chunk.length as u64;
                        if seen.insert(hex.clone()) {
                            pending.push((hex.clone(), bytes.to_vec()));
                        }
                        chunk_hashes.push(hex);
                        Ok(())
                    },
                )?;

                for (hex, bytes) in pending {
                    let key = blob_key(&hex);
                    if !self.backend.exists(&key).await? {
                        self.backend.put(&key, &bytes).await?;
                        stats.new_chunks += 1;
                        stats.new_bytes += bytes.len() as u64;
                    }
                }

                files.push(FileEntry {
                    path: to_slash(rel),
                    size: meta.len(),
                    mode: file_mode(&meta),
                    mtime: mtime_secs(&meta),
                    chunks: chunk_hashes,
                });
                stats.files += 1;
            }
        }

        let snapshot = Snapshot {
            id: uuid::Uuid::new_v4().simple().to_string(),
            time: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .expect("RFC 3339 formatting of a valid timestamp"),
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "unknown".into()),
            paths: roots,
            files,
            stats,
        };

        let bytes = serde_json::to_vec_pretty(&snapshot).expect("Snapshot is serializable");
        self.backend
            .put(&snapshot_key(&snapshot.id), &bytes)
            .await?;
        Ok(snapshot)
    }

    /// List every snapshot in the repository, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] or [`Error::Malformed`] if a manifest cannot be read or parsed.
    pub async fn list_snapshots(&self) -> Result<Vec<Snapshot>> {
        let mut out = Vec::new();
        for key in self.backend.list(SNAPSHOTS_PREFIX).await? {
            if !key.ends_with(".json") {
                continue;
            }
            let raw = self.backend.get(&key).await?;
            out.push(
                serde_json::from_slice(&raw).map_err(|source| Error::Malformed {
                    what: format!("snapshot manifest {key}"),
                    source,
                })?,
            );
        }
        out.sort_by(|a: &Snapshot, b: &Snapshot| (&b.time, &b.id).cmp(&(&a.time, &a.id)));
        Ok(out)
    }

    /// Load a snapshot by its full id or any unambiguous prefix of it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SnapshotNotFound`] if no snapshot matches, or if the
    /// prefix matches more than one.
    pub async fn find_snapshot(&self, id_or_prefix: &str) -> Result<Snapshot> {
        let mut matches: Vec<Snapshot> = self
            .list_snapshots()
            .await?
            .into_iter()
            .filter(|s| s.id.starts_with(id_or_prefix))
            .collect();
        match matches.len() {
            1 => Ok(matches.remove(0)),
            _ => Err(Error::SnapshotNotFound(id_or_prefix.to_string())),
        }
    }

    /// Restore a snapshot's files beneath `target`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SnapshotNotFound`], [`Error::MissingBlob`] if the
    /// repository is missing a referenced chunk, or [`Error::Io`] on write failure.
    pub async fn restore(&self, id_or_prefix: &str, target: impl AsRef<Path>) -> Result<Snapshot> {
        let snapshot = self.find_snapshot(id_or_prefix).await?;
        let target = target.as_ref();

        for file in &snapshot.files {
            let dest = safe_join(target, &file.path)?;
            if let Some(parent) = dest.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| Error::io(parent, e))?;
            }
            let mut contents = Vec::with_capacity(file.size as usize);
            for hex in &file.chunks {
                let key = blob_key(hex);
                if !self.backend.exists(&key).await? {
                    return Err(Error::MissingBlob(hex.clone()));
                }
                contents.extend_from_slice(&self.backend.get(&key).await?);
            }
            tokio::fs::write(&dest, &contents)
                .await
                .map_err(|e| Error::io(&dest, e))?;
            restore_mode(&dest, file.mode).await?;
        }
        Ok(snapshot)
    }
}

/// Key of a blob, sharded by the first two hex characters of its hash
/// (`docs/03-repository-format.md`) to keep directory fan-out manageable.
fn blob_key(hex: &str) -> String {
    format!("{BLOBS_PREFIX}/{}/{hex}", &hex[..2])
}

fn snapshot_key(id: &str) -> String {
    format!("{SNAPSHOTS_PREFIX}/{id}.json")
}

fn to_slash(path: &Path) -> String {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Join a snapshot-relative path under `base`, rejecting anything that would
/// escape it. Manifests are attacker-influenced input on a shared repository:
/// a `../../etc/cron.d/x` entry must never write outside the restore target.
fn safe_join(base: &Path, rel: &str) -> Result<PathBuf> {
    let mut out = base.to_path_buf();
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg.contains('\\') || seg.contains(':') {
            return Err(Error::io(
                base.join(rel),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unsafe path component in snapshot entry: {rel}"),
                ),
            ));
        }
        out.push(seg);
    }
    Ok(out)
}

#[cfg(unix)]
fn file_mode(meta: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode())
}

#[cfg(not(unix))]
fn file_mode(_meta: &std::fs::Metadata) -> Option<u32> {
    None
}

#[cfg(unix)]
async fn restore_mode(path: &Path, mode: Option<u32>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = mode {
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .await
            .map_err(|e| Error::io(path, e))?;
    }
    Ok(())
}

#[cfg(not(unix))]
async fn restore_mode(_path: &Path, _mode: Option<u32>) -> Result<()> {
    Ok(())
}

fn mtime_secs(meta: &std::fs::Metadata) -> Option<i64> {
    let modified = meta.modified().ok()?;
    match modified.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).ok(),
        Err(e) => i64::try_from(e.duration().as_secs()).ok().map(|s| -s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_rejects_traversal() {
        let base = Path::new("/tmp/restore");
        assert!(safe_join(base, "docs/a.txt").is_ok());
        assert!(safe_join(base, "../etc/passwd").is_err());
        assert!(safe_join(base, "a/../../b").is_err());
        assert!(safe_join(base, "/abs").is_err());
    }
}
