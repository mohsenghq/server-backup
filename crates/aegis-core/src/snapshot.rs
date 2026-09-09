//! Snapshot manifests: what a backup run recorded.
//!
//! Since the Phase 1 format work, a manifest no longer lists files directly —
//! it stores one Merkle tree-root hash per source path
//! (`docs/03-repository-format.md`). The full tree lives in content-addressed
//! blobs; the manifest is the small, verifiable pointer to it.

use serde::{Deserialize, Serialize};

/// The manifest written to `snapshots/<id>.json` by a backup run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Unique snapshot identifier (also its filename stem).
    pub id: String,
    /// RFC 3339 timestamp of when the backup started.
    pub time: String,
    /// Hostname of the machine the backup was taken from.
    pub hostname: String,
    /// The absolute source paths passed to `aegis backup`.
    pub paths: Vec<String>,
    /// Hex BLAKE3 hash of each source path's tree root, in the same order as
    /// [`Snapshot::paths`]. Each root is the hash of a [`crate::tree::TreeNode`]
    /// blob; re-deriving it from the stored blobs detects corruption.
    pub roots: Vec<String>,
    /// Aggregate counters for this run.
    pub stats: SnapshotStats,
}

/// What a backup run moved.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct SnapshotStats {
    /// Number of files captured.
    pub files: u64,
    /// Total logical bytes read from the source.
    pub bytes: u64,
    /// Chunks and tree blobs produced, including duplicates.
    pub chunks: u64,
    /// Blobs that were not already in the repository and had to be written.
    pub new_chunks: u64,
    /// Bytes actually written to the backend as new blobs.
    pub new_bytes: u64,
}

impl Snapshot {
    /// Short form of the id, as displayed by `aegis snapshots`.
    pub fn short_id(&self) -> &str {
        &self.id[..8.min(self.id.len())]
    }

    /// [`Snapshot::time`] trimmed to whole seconds for display.
    ///
    /// The manifest keeps full sub-second precision — it is what breaks ties
    /// between two snapshots taken in the same second — but those digits only
    /// blow out the width of the `aegis snapshots` table.
    pub fn display_time(&self) -> &str {
        match self.time.split_once('.') {
            Some((secs, _)) => secs,
            None => self.time.trim_end_matches('Z'),
        }
    }
}
