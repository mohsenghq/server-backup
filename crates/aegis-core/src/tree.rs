//! The snapshot tree: a content-addressed Merkle tree of directories and
//! files (`docs/03-repository-format.md`).
//!
//! Every node serializes to canonical JSON (derived `Serialize`: fields in
//! declaration order) and is addressed by the BLAKE3 hash of that
//! serialization. A node whose serialization exceeds [`INLINE_LIMIT`] is
//! stored as a repository blob and referenced from its parent by a compact
//! [`Node::Ref`] entry; smaller nodes are embedded in their parent directly.
//! The root node is always inlined into the snapshot manifest, so a manifest
//! is self-describing.
//!
//! Because inline-vs-blob depends only on a node's own serialization, the
//! decision is deterministic — identical subtrees hash identically wherever
//! they appear, which is what makes whole-subtree deduplication work: a
//! snapshot sharing an unchanged subtree shares every node blob below it.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Largest node serialization kept inline inside its parent; anything larger
/// becomes a blob referenced by [`Node::Ref`].
pub const INLINE_LIMIT: usize = 4 * 1024;

/// A node of the snapshot tree: a file with its chunk list, a directory with
/// its children, or a reference to a child stored as its own blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Node {
    /// A regular file. Concatenating the referenced data blobs reproduces its
    /// contents byte for byte.
    File {
        /// File name — a single path component, never containing `/`.
        name: String,
        /// Size of the file in bytes at backup time.
        size: u64,
        /// Unix permission bits, or `None` on platforms that do not report them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<u32>,
        /// Modification time as a Unix timestamp in seconds, if available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mtime: Option<i64>,
        /// Hex BLAKE3 hashes of the file's chunks, in order. An empty file
        /// keeps an empty list here and is still restored as a real file.
        chunks: Vec<String>,
    },
    /// A directory and its children, sorted by name.
    Dir {
        /// Directory name — a single path component, never containing `/`.
        name: String,
        /// Child nodes, kept sorted by name so serialization is canonical.
        children: Vec<Node>,
    },
    /// A child whose serialization exceeded [`INLINE_LIMIT`], stored as its
    /// own blob. The hash addresses `blobs/<xx>/<hash>` in the repository.
    Ref {
        /// Name of the referenced file or directory.
        name: String,
        /// Hex BLAKE3 hash of the referenced node's serialization.
        hash: String,
    },
}

impl Node {
    /// This node's name.
    pub fn name(&self) -> &str {
        match self {
            Node::File { name, .. } | Node::Dir { name, .. } | Node::Ref { name, .. } => name,
        }
    }

    /// Sort `Dir` children by name (recursively) so equal trees serialize to
    /// equal bytes. Call before hashing or writing anything.
    pub fn sort(&mut self) {
        if let Node::Dir { children, .. } = self {
            children.sort_by(|a, b| a.name().cmp(b.name()));
            children.iter_mut().for_each(Node::sort);
        }
    }

    /// Validate every name and reference hash in this subtree.
    ///
    /// A snapshot manifest is attacker-influenced input on a shared
    /// repository; every name must be a plain single path component before
    /// anything is written to a restore target.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadPath`] for the first offending name.
    pub fn validate(&self) -> Result<()> {
        match self {
            Node::File { name, .. } | Node::Dir { name, .. } | Node::Ref { name, .. } => {
                check_name(name)?;
            }
        }
        match self {
            Node::Ref { hash, .. } => check_hash(hash),
            Node::Dir { children, .. } => children.iter().try_for_each(Node::validate),
            Node::File { .. } => Ok(()),
        }
    }

    /// Collect the hex hashes of every [`Node::Ref`] in this subtree — the
    /// set of tree blobs a snapshot references (data chunk hashes are on the
    /// file nodes and are collected separately).
    pub fn collect_refs(&self, out: &mut Vec<String>) {
        match self {
            Node::Ref { hash, .. } => out.push(hash.clone()),
            Node::Dir { children, .. } => {
                children.iter().for_each(|c| c.collect_refs(out));
            }
            Node::File { .. } => {}
        }
    }

    /// Collect the hex hashes of every data chunk referenced by file nodes
    /// in this subtree. Does not descend into refs — node blobs are walked
    /// separately (see `Repository::snapshot_index`).
    pub fn collect_chunk_hashes(&self, out: &mut Vec<String>) {
        match self {
            Node::File { chunks, .. } => out.extend(chunks.iter().cloned()),
            Node::Dir { children, .. } => {
                children.iter().for_each(|c| c.collect_chunk_hashes(out));
            }
            Node::Ref { .. } => {}
        }
    }

    /// Canonical serialization of this node — the bytes every hash and blob
    /// is taken over. Never called on an unsorted tree by the builder; direct
    /// callers should [`Node::sort`] first.
    pub fn serialized(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Node serialization is infallible")
    }

    /// The BLAKE3 hash of [`Node::serialized`], hex-encoded.
    pub fn hash_hex(&self) -> String {
        blake3::hash(&self.serialized()).to_hex().to_string()
    }
}

/// Replace every child whose serialization exceeds [`INLINE_LIMIT`] with a
/// [`Node::Ref`], returning those blobs as `(hash, bytes)` pairs.
///
/// The root is returned un-referenced regardless of size (the manifest inlines
/// it), so the returned list never contains a hash for the root itself.
///
/// Blobs produced while compacting a tree: `(hex hash, serialized node)`.
pub type NodeBlobs = Vec<(String, Vec<u8>)>;

/// # Errors
///
/// Propagates whatever `validate`-adjacent errors the walk can produce — in
/// practice only [`Error::BadPath`] for trees containing invalid names.
pub fn build_stored(root: Node) -> Result<(Node, NodeBlobs)> {
    fn go(node: Node, blobs: &mut Vec<(String, Vec<u8>)>) -> Result<Node> {
        let node = match node {
            Node::Dir { name, children } => {
                let mut stored = Vec::with_capacity(children.len());
                for child in children {
                    stored.push(go(child, blobs)?);
                }
                Node::Dir {
                    name,
                    children: stored,
                }
            }
            Node::File { .. } | Node::Ref { .. } => node,
        };
        node.validate()?;
        let bytes = node.serialized();
        if bytes.len() <= INLINE_LIMIT {
            return Ok(node);
        }
        let hash = blake3::hash(&bytes).to_hex().to_string();
        blobs.push((hash.clone(), bytes));
        let name = node.name().to_string();
        Ok(Node::Ref { name, hash })
    }

    let mut blobs = Vec::new();
    let root = go(root, &mut blobs)?;
    Ok((root, blobs))
}

/// Reject anything that is not a safe single path component.
fn check_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.starts_with('/')
        || name.ends_with('/')
        || name.contains('/')
        || name.contains('\\')
        || name.contains(':')
        || name.contains('\0')
    {
        return Err(Error::BadPath(name.to_string()));
    }
    Ok(())
}

/// Require a lowercase 64-character hex BLAKE3 hash.
fn check_hash(hash: &str) -> Result<()> {
    if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(Error::BadPath(hash.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, size: u64) -> Node {
        Node::File {
            name: name.into(),
            size,
            mode: Some(0o644),
            mtime: Some(1_700_000_000),
            chunks: vec!["ab".repeat(32)],
        }
    }

    fn dir(name: &str, children: Vec<Node>) -> Node {
        Node::Dir {
            name: name.into(),
            children,
        }
    }

    #[test]
    fn hash_is_deterministic_and_order_sensitive() {
        let a = dir("root", vec![file("a", 1), file("b", 2)]);
        let b = dir("root", vec![file("a", 1), file("b", 2)]);
        let c = dir("root", vec![file("b", 2), file("a", 1)]);

        assert_eq!(a.hash_hex(), b.hash_hex());
        // Canonical hashing is over the serialized form: unsorted children are
        // different bytes until sorted, so callers must call `sort` first.
        assert_ne!(a.hash_hex(), c.hash_hex());
    }

    #[test]
    fn sorting_makes_child_order_irrelevant() {
        let mut a = dir("root", vec![file("b", 2), file("a", 1)]);
        let mut b = dir("root", vec![file("a", 1), file("b", 2)]);
        a.sort();
        b.sort();
        assert_eq!(a, b);
        assert_eq!(a.hash_hex(), b.hash_hex());
    }

    #[test]
    fn identical_subtrees_hash_identically_wherever_they_appear() {
        let shared = dir("shared", vec![file("x", 10), file("y", 20)]);
        let t1 = dir("root", vec![shared.clone(), file("q", 1)]);
        let t2 = dir("other-root", vec![file("z", 5), shared]);

        fn get<'a>(n: &'a Node, name: &str) -> &'a Node {
            match n {
                Node::Dir { children, .. } => children
                    .iter()
                    .find(|c| c.name() == name)
                    .unwrap_or_else(|| panic!("no child named {name}")),
                _ => panic!("not a dir"),
            }
        }
        assert_eq!(get(&t1, "shared").hash_hex(), get(&t2, "shared").hash_hex());
    }

    #[test]
    fn validate_rejects_unsafe_names_and_bad_hashes() {
        for bad in [
            "..",
            ".",
            "",
            "a/b",
            "a\\b",
            "C:x",
            "/abs",
            "trailing/",
            "nul\0",
        ] {
            assert!(
                dir("root", vec![file(bad, 1)]).validate().is_err(),
                "expected {bad:?} to be rejected"
            );
        }
        assert!(dir("root", vec![file("ok.txt", 1)]).validate().is_ok());
        assert!(dir("ro/to", vec![]).validate().is_err());

        let mut refnode = Node::Ref {
            name: "d".into(),
            hash: "zz".repeat(32),
        };
        assert!(refnode.validate().is_err());
        refnode = Node::Ref {
            name: "d".into(),
            hash: "ab".repeat(32),
        };
        assert!(refnode.validate().is_ok());
    }

    #[test]
    fn build_stores_oversized_children_and_keeps_small_ones_inline() {
        // ~100 file nodes at ~175 B of serialization each: the directory
        // comfortably exceeds the 4 KiB inline limit.
        let big = dir(
            "big",
            (0..100)
                .map(|i| file(&format!("filler-{i:03}"), 0))
                .collect(),
        );
        assert!(big.serialized().len() > INLINE_LIMIT);

        let root = dir("root", vec![big, file("small", 1)]);
        let (stored, blobs) = build_stored(root).unwrap();

        assert_eq!(blobs.len(), 1, "only `big` exceeds the inline limit");
        let (hash, bytes) = &blobs[0];
        assert_eq!(*hash, blake3::hash(bytes).to_hex().to_string());

        match &stored {
            Node::Dir { children, .. } => {
                assert!(children.iter().any(|c| matches!(c, Node::Ref { .. })));
                assert!(children
                    .iter()
                    .any(|c| matches!(c, Node::File { name, .. } if name == "small")));
            }
            other => panic!("root must stay a Dir, got {other:?}"),
        }
        // The root is never in its own blob list.
        assert!(!blobs.iter().any(|(h, _)| *h == stored.hash_hex()));
    }

    #[test]
    fn build_stores_oversized_file_nodes_too() {
        // A file with thousands of chunks: its node serialization exceeds the
        // inline limit even though its data is elsewhere.
        let big_file = Node::File {
            name: "many-chunks.bin".into(),
            size: 100 * 8 * 1024 * 1024,
            mode: None,
            mtime: None,
            chunks: (0..1500).map(|i| format!("{i:064x}")).collect(),
        };
        let root = dir("root", vec![big_file]);
        let (stored, blobs) = build_stored(root).unwrap();
        assert_eq!(blobs.len(), 1);
        let Node::Ref { name, hash } = &stored.children()[0] else {
            panic!("expected a Ref");
        };
        assert_eq!(name, "many-chunks.bin");
        assert_eq!(*hash, blobs[0].0);

        // The blob parses back to the original file node.
        let parsed: Node = serde_json::from_slice(&blobs[0].1).unwrap();
        assert_eq!(parsed.name(), "many-chunks.bin");
        assert_eq!(parsed.chunks().len(), 1500);
    }

    #[test]
    fn nested_refs_are_found_by_walking_node_blobs() {
        let inner = dir(
            "inner",
            (0..100).map(|i| file(&format!("f{i}"), 0)).collect(),
        );
        // Enough siblings that `outer` still exceeds the inline limit even
        // after `inner` is compacted to a Ref entry.
        let outer = dir(
            "outer",
            std::iter::once(inner)
                .chain((0..30).map(|i| file(&format!("g{i}"), 0)))
                .collect(),
        );
        let root = dir("root", vec![outer]);
        let (stored, blobs) = build_stored(root).unwrap();
        assert_eq!(blobs.len(), 2);

        // The inline root only exposes the top-level ref; the nested one is
        // discovered by fetching that node blob and walking it — the walk
        // `verify` performs.
        let mut top = Vec::new();
        stored.collect_refs(&mut top);
        assert_eq!(top.len(), 1);

        let outer_bytes = &blobs.iter().find(|(h, _)| *h == top[0]).unwrap().1;
        let outer_node: Node = serde_json::from_slice(outer_bytes).unwrap();
        let mut nested = Vec::new();
        outer_node.collect_refs(&mut nested);
        assert_eq!(nested.len(), 1);
        assert!(blobs.iter().any(|(h, _)| *h == nested[0]));
    }

    #[test]
    fn json_round_trips() {
        let tree = dir("root", vec![file("a", 1), dir("d", vec![file("b", 2)])]);
        let bytes = serde_json::to_vec(&tree).unwrap();
        let back: Node = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(tree, back);
        assert_eq!(tree.hash_hex(), back.hash_hex());
    }

    impl Node {
        fn children(&self) -> &[Node] {
            match self {
                Node::Dir { children, .. } => children,
                _ => panic!("not a dir"),
            }
        }

        fn chunks(&self) -> &[String] {
            match self {
                Node::File { chunks, .. } => chunks,
                _ => panic!("not a file"),
            }
        }
    }
}
