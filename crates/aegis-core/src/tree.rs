//! The Merkle tree of a snapshot (`docs/03-repository-format.md`).
//!
//! A snapshot's contents are a tree of trees: leaves reference chunk blobs by
//! hash, directory nodes serialize their children as JSON and are themselves
//! content-addressed. The root node's hash is stored in the snapshot manifest,
//! which gives two properties the Phase 0 flat list could not provide:
//!
//! - **Subtree deduplication** — an unchanged directory hashes to the same node
//!   id regardless of where it appears or what else changed in the snapshot.
//! - **Structural verification** — `aegis verify` (Phase 1) can re-derive the
//!   root hash from the blobs and detect corruption or tampering.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A node in a snapshot's Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TreeNode {
    /// A directory: a named map of child nodes.
    Dir {
        /// Child entries, keyed by name (`/`-free, non-empty, not `.`/`..`).
        entries: Vec<TreeEntry>,
    },
    /// A regular file: metadata plus the ordered list of its chunks.
    File {
        /// Size of the file in bytes at backup time.
        size: u64,
        /// Unix permission bits, or `None` on platforms that do not report them.
        #[serde(skip_serializing_if = "Option::is_none")]
        mode: Option<u32>,
        /// Modification time as a Unix timestamp in seconds, if available.
        #[serde(skip_serializing_if = "Option::is_none")]
        mtime: Option<i64>,
        /// Hex BLAKE3 hashes of this file's chunk blobs, in order. Concatenating
        /// the referenced blobs reproduces the file byte for byte.
        chunks: Vec<String>,
    },
}

/// One named child inside a [`TreeNode::Dir`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    /// File or directory name, a single path component.
    pub name: String,
    /// The child node's content: either inline, or a reference to a tree blob.
    pub node: NodeRef,
}

/// How a child node is stored inside its parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRef {
    /// The node is embedded in its parent (small files and small directories).
    Inline(Box<TreeNode>),
    /// The node lives in its own blob, addressed by hex BLAKE3 hash.
    Blob(String),
}

impl TreeNode {
    /// Collect, in deterministic order, every referenced chunk-blob hash
    /// (hex) reachable from this node. Used by restore, verify, and prune.
    pub fn collect_chunk_hashes(&self, out: &mut Vec<String>) {
        match self {
            TreeNode::Dir { entries } => {
                for entry in entries {
                    match &entry.node {
                        NodeRef::Inline(node) => node.collect_chunk_hashes(out),
                        NodeRef::Blob(_) => {
                            // Blob children are resolved by the caller (repo)
                            // as needed; files reached through them are
                            // discovered when the tree blob is loaded.
                        }
                    }
                }
            }
            TreeNode::File { chunks, .. } => out.extend(chunks.iter().cloned()),
        }
    }
}

/// Serialize a node to the exact bytes stored in (or hashed for) a tree blob.
pub fn serialize_node(node: &TreeNode) -> Result<Vec<u8>> {
    serde_json::to_vec(node).map_err(|e| Error::Malformed {
        what: "tree node".into(),
        source: e,
    })
}

/// Parse a node from stored bytes.
///
/// # Errors
///
/// Returns [`Error::Malformed`] if the bytes are not a valid tree node.
pub fn parse_node(bytes: &[u8]) -> Result<TreeNode> {
    serde_json::from_slice(bytes).map_err(|e| Error::Malformed {
        what: "tree node".into(),
        source: e,
    })
}

/// Validate a single path-component name allowed in [`TreeEntry::name`].
pub(crate) fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains(':')
    {
        return Err(Error::io(
            std::path::Path::new(name),
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsafe name in tree node: {name:?}"),
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_roundtrips_through_serialization() {
        let node = TreeNode::Dir {
            entries: vec![
                TreeEntry {
                    name: "a.txt".into(),
                    node: NodeRef::Inline(Box::new(TreeNode::File {
                        size: 11,
                        mode: Some(0o644),
                        mtime: Some(1_700_000_000),
                        chunks: vec!["ab".repeat(32)],
                    })),
                },
                TreeEntry {
                    name: "sub".into(),
                    node: NodeRef::Blob("cd".repeat(32)),
                },
            ],
        };

        let bytes = serialize_node(&node).unwrap();
        assert_eq!(parse_node(&bytes).unwrap(), node);
    }

    #[test]
    fn empty_file_node_roundtrips() {
        let node = TreeNode::File {
            size: 0,
            mode: None,
            mtime: None,
            chunks: vec![],
        };
        let bytes = serialize_node(&node).unwrap();
        assert_eq!(parse_node(&bytes).unwrap(), node);
    }

    #[test]
    fn rejects_unsafe_names() {
        assert!(validate_name("a.txt").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("..").is_err());
        assert!(validate_name("a/b").is_err());
        assert!(validate_name("a\\b").is_err());
        assert!(validate_name("a:b").is_err());
    }
}
