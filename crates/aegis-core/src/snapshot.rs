//! Snapshot manifests: what a backup run recorded.

use serde::{Deserialize, Serialize};

/// One backed-up file and the chunks its contents were split into.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path relative to the snapshot root, always `/`-separated.
    pub path: String,
    /// Size of the file in bytes at backup time.
    pub size: u64,
    /// Unix permission bits, or `None` on platforms that do not report them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// Modification time as a Unix timestamp in seconds, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,
    /// Hex BLAKE3 hashes of this file's chunks, in order. Concatenating the
    /// referenced blobs reproduces the file byte for byte.
    pub chunks: Vec<String>,
}

/// The manifest written to `snapshots/<id>.json` by a backup run.
///
// ponytail: Phase 0 stores a flat file list. `docs/03-repository-format.md`
// specifies a Merkle tree of directory trees rooted in a single hash; that is
// the Phase 1 "Full repository format" checklist item. A flat list restores
// correctly and dedups blobs identically — it just cannot dedup *subtrees* or
// verify structure by root hash.
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
    /// Every file captured by this snapshot.
    pub files: Vec<FileEntry>,
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
    /// Chunks produced, including duplicates.
    pub chunks: u64,
    /// Chunks that were not already in the repository and had to be written.
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
