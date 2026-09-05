//! Snapshot manifests: what a backup run recorded, and the per-snapshot blob
//! index that `prune` and `verify` read.

use serde::{Deserialize, Serialize};

use crate::tree::Node;

/// The manifest written to `snapshots/<id>.json` by a backup run.
///
/// The tree itself is content-addressed: every node hashes its canonical
/// serialization, oversize nodes live as blobs under their hash (`tree.rs`),
/// and the root node — always inlined here — carries the aggregate root hash.
/// Two snapshots sharing an unchanged subtree share all of that subtree's
/// node blobs, so re-naming a parent directory no longer re-pays for it.
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
    /// Root of the snapshot's Merkle tree, one child per source path.
    pub root: Node,
    /// Aggregate counters for this run.
    pub stats: SnapshotStats,
}

impl Snapshot {
    /// BLAKE3 hash of the root node's canonical serialization — the single
    /// hash the whole snapshot's structure is committed to.
    pub fn root_hash(&self) -> String {
        self.root.hash_hex()
    }

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

    /// Number of files in the snapshot, computed from the tree.
    pub fn count_files(&self) -> u64 {
        fn go(node: &Node) -> u64 {
            match node {
                Node::File { .. } => 1,
                Node::Ref { .. } => 0, // resolved blobs are counted via stats
                Node::Dir { children, .. } => children.iter().map(go).sum(),
            }
        }
        // Prefer the recorded stat; fall back to walking the inline root.
        if self.stats.files > 0 {
            self.stats.files
        } else {
            go(&self.root)
        }
    }
}

/// What a backup run moved.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct SnapshotStats {
    /// Number of files captured.
    pub files: u64,
    /// Total logical bytes read from the source.
    pub bytes: u64,
    /// Data chunks produced, including duplicates.
    pub chunks: u64,
    /// Chunks that were not already in the repository and had to be written.
    pub new_chunks: u64,
    /// Bytes actually written to the backend as new blobs.
    pub new_bytes: u64,
    /// Node blobs written for the snapshot tree itself (directories and
    /// oversize file nodes).
    pub new_tree_nodes: u64,
}

/// The per-snapshot index written to `index/<id>.json`: every blob (data
/// chunk, tree node, or manifest-adjacent object) the snapshot references,
/// with its size. Written alongside the manifest; it is the input to `prune`'s
/// garbage collection and lets `verify --shallow` work from one small file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotIndex {
    /// Snapshot this index belongs to.
    pub snapshot_id: String,
    /// Every blob hash this snapshot references (data chunks and tree nodes).
    pub blobs: Vec<BlobRef>,
}

/// One blob referenced by a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobRef {
    /// Hex BLAKE3 hash — the blob's address under `blobs/`.
    pub hash: String,
    /// Size of the stored blob in bytes, when known. `None` for indexes
    /// derived by walking a tree rather than read from a written index.
    pub size: Option<u64>,
    /// What kind of content the blob holds.
    pub kind: BlobKind,
}

/// What a blob contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlobKind {
    /// A data chunk of a file's contents.
    Chunk,
    /// A snapshot-tree node (directory or oversize file node).
    TreeNode,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Snapshot {
        Snapshot {
            id: "abc123".into(),
            time: "2026-09-05T12:00:00.123456789Z".into(),
            hostname: "host".into(),
            paths: vec!["/data".into()],
            root: Node::Dir {
                name: "data".into(),
                children: vec![Node::File {
                    name: "a.txt".into(),
                    size: 2,
                    mode: None,
                    mtime: None,
                    chunks: vec![],
                }],
            },
            stats: SnapshotStats::default(),
        }
    }

    #[test]
    fn root_hash_is_the_root_nodes_hash() {
        let mut s = sample();
        let before = s.root_hash();
        assert_eq!(before, s.root.hash_hex());

        // Changing one chunk list changes the root hash: the snapshot is
        // committed to its whole structure.
        if let Node::Dir { children, .. } = &mut s.root {
            if let Node::File { chunks, .. } = &mut children[0] {
                chunks.push("ff".repeat(32));
            }
        }
        assert_ne!(s.root_hash(), before);
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let s = sample();
        let bytes = serde_json::to_vec_pretty(&s).unwrap();
        let back: Snapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.root, s.root);
        assert_eq!(back.root_hash(), s.root_hash());
    }

    #[test]
    fn display_and_count_helpers() {
        let mut s = sample();
        assert_eq!(s.display_time(), "2026-09-05T12:00:00");
        assert_eq!(s.count_files(), 1, "falls back to walking the tree");
        s.stats.files = 7;
        assert_eq!(s.count_files(), 7, "prefers the recorded stat");
        assert_eq!(s.short_id(), "abc123");
    }

    #[test]
    fn index_round_trips() {
        let idx = SnapshotIndex {
            snapshot_id: "abc123".into(),
            blobs: vec![BlobRef {
                hash: "ab".repeat(32),
                size: Some(123),
                kind: BlobKind::Chunk,
            }],
        };
        let bytes = serde_json::to_vec(&idx).unwrap();
        let back: SnapshotIndex = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.blobs.len(), 1);
        assert_eq!(back.blobs[0].kind, BlobKind::Chunk);
    }
}
