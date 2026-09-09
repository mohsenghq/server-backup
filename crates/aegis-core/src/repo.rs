//! The repository: init, backup, restore, snapshot listing, and the packed
//! blob→location index.
//!
//! Layout (`docs/03-repository-format.md`): content-addressed `blobs/` holding
//! chunk blobs *and* Merkle tree-node blobs, snapshot manifests in
//! `snapshots/`, and a pack file in `index/` mapping every stored blob hash to
//! its key so a repository can be audited (and, later, garbage-collected)
//! without walking `blobs/`.

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::backend::{Backend, LocalBackend};
use crate::chunk::{chunk_stream, ChunkerConfig};
use crate::crypto::{self, Aad, Key, WrappedKey};
use crate::error::{Error, Result};
use crate::snapshot::{Snapshot, SnapshotStats};
use crate::tree::{self, NodeRef, TreeEntry, TreeNode};

/// Repository format version this build reads and writes.
pub const FORMAT_VERSION: u32 = 2;

const CONFIG_KEY: &str = "config";
const BLOBS_PREFIX: &str = "blobs";
const SNAPSHOTS_PREFIX: &str = "snapshots";
const INDEX_PACK_KEY: &str = "index/pack.json";
const KEYS_PREFIX: &str = "keys";

/// Directories whose serialized form stays below this size are embedded inline
/// in their parent instead of being written as their own tree blob. Small
/// directories benefit little from subtree deduplication, and inlining keeps
/// the tree shallow.
const INLINE_DIR_LIMIT: usize = 4 * 1024;

/// The repository's `config` document.
///
/// Stored **encrypted** under the repo master key (`docs/10-security-model.md`):
/// the backend never sees the plaintext.
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

/// One entry of the `index/` pack: where a blob with a given hash lives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Hex BLAKE3 hash of the blob's plaintext content.
    pub hash: String,
    /// Backend key the blob is stored under (`blobs/<xx>/<hash>`).
    pub key: String,
    /// Length of the stored blob in bytes.
    pub size: u64,
}

/// The packed `index/pack.json` document: every stored blob, keyed by hash.
///
// ponytail: a single JSON pack is fine for Phase 1's corpus size; the `redb`
// on-disk index and pack sharding arrive with the remaining Phase 1 items.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IndexPack {
    /// All blobs currently recorded as present in the repository.
    pub entries: BTreeMap<String, IndexEntry>,
}

impl IndexPack {
    /// Insert or replace the entry for `entry.hash`.
    pub fn record(&mut self, entry: IndexEntry) {
        self.entries.insert(entry.hash.clone(), entry);
    }
}

/// An open Aegis repository.
///
/// Generic over the storage backend so the identical format works on local
/// disk, SFTP (Phase 1), or S3: [`Repository::init_with_backend`] and
/// [`Repository::open_with_backend`] accept any [`Backend`].
pub struct Repository {
    backend: Box<dyn Backend>,
    config: RepoConfig,
    /// Repo master key, unwrapped from `keys/` at open time. Seals every blob,
    /// manifest, and the config. Zeroized on drop.
    master_key: Key,
    /// Blob→location index. Interior-mutable so backup can stay `&self`
    /// (the server will hand out `Arc<Repository>`).
    index: Mutex<IndexPack>,
}

impl Repository {
    /// Create a repository behind a caller-supplied backend, encrypted under
    /// a fresh master key wrapped with `passphrase`.
    ///
    /// The master key is generated client-side, wrapped via Argon2id +
    /// XChaCha20-Poly1305, and stored in `keys/` (`docs/10-security-model.md`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::RepoExists`] if a `config` is already present,
    /// [`Error::InvalidChunkerConfig`] for bad chunker parameters,
    /// [`Error::Crypto`] on KDF/AEAD failure, or [`Error::Io`] if the backend
    /// cannot be written.
    pub async fn init_with_backend(
        backend: Box<dyn Backend>,
        chunker: ChunkerConfig,
        passphrase: &str,
    ) -> Result<Self> {
        chunker.validate()?;
        if backend.exists(CONFIG_KEY).await? {
            return Err(Error::RepoExists(backend.location()));
        }
        let master_key = Key::generate();
        let wrapped = WrappedKey::create(&master_key, passphrase)?;
        let key_bytes = serde_json::to_vec_pretty(&wrapped).expect("WrappedKey is serializable");
        backend
            .put(
                &format!("{KEYS_PREFIX}/{}.json", wrapped.key_id),
                &key_bytes,
            )
            .await?;

        let config = RepoConfig {
            version: FORMAT_VERSION,
            id: uuid::Uuid::new_v4().to_string(),
            chunker,
        };
        let bytes = serde_json::to_vec_pretty(&config).expect("RepoConfig is serializable");
        backend
            .put(CONFIG_KEY, &crypto::seal(&master_key, &bytes, Aad::Config)?)
            .await?;
        let repo = Self {
            backend,
            config,
            master_key,
            index: Mutex::new(IndexPack::default()),
        };
        repo.flush_index().await?;
        Ok(repo)
    }

    /// Open an existing repository behind a caller-supplied backend, unwrapping
    /// its master key with `passphrase`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RepoNotFound`] if there is no `config`,
    /// [`Error::UnsupportedFormat`] if it was written by an incompatible
    /// version, [`Error::NoMatchingKey`] if no key file exists,
    /// [`Error::DecryptionFailed`] for a wrong passphrase or tampered data,
    /// [`Error::Malformed`] if a document cannot be parsed, or [`Error::Io`]
    /// if the backend cannot be read.
    pub async fn open_with_backend(backend: Box<dyn Backend>, passphrase: &str) -> Result<Self> {
        if !backend.exists(CONFIG_KEY).await? {
            return Err(Error::RepoNotFound(backend.location()));
        }
        let sealed_config = backend.get(CONFIG_KEY).await?;

        // Try every wrapped key file; any successful unwrap + config open wins.
        // Wrong passphrases fail AEAD authentication, never leak timing beyond
        // the KDF (identical work per key).
        let key_names = backend
            .list(KEYS_PREFIX)
            .await?
            .into_iter()
            .filter(|k| k.ends_with(".json"));
        let mut last_error = Error::NoMatchingKey;
        let mut opened: Option<(RepoConfig, Key)> = None;
        for key_name in key_names {
            let raw = match backend.get(&key_name).await {
                Ok(raw) => raw,
                Err(e) => {
                    last_error = e;
                    continue;
                }
            };
            let wrapped: WrappedKey = match serde_json::from_slice(&raw) {
                Ok(w) => w,
                Err(source) => {
                    last_error = Error::Malformed {
                        what: format!("key file {key_name}"),
                        source,
                    };
                    continue;
                }
            };
            let master = match wrapped.unwrap_key(passphrase) {
                Ok(k) => k,
                Err(e) => {
                    last_error = e;
                    continue;
                }
            };
            let bytes = match crypto::open(&master, &sealed_config, Aad::Config) {
                Ok(b) => b,
                Err(e) => {
                    last_error = e;
                    continue;
                }
            };
            let config: RepoConfig = match serde_json::from_slice(&bytes) {
                Ok(c) => c,
                Err(source) => {
                    last_error = Error::Malformed {
                        what: "repository config".into(),
                        source,
                    };
                    continue;
                }
            };
            if config.version != FORMAT_VERSION {
                return Err(Error::UnsupportedFormat {
                    found: config.version,
                    supported: FORMAT_VERSION,
                });
            }
            opened = Some((config, master));
            break;
        }
        let (config, master_key) = opened.ok_or(last_error)?;

        let index = match backend.get(INDEX_PACK_KEY).await {
            Ok(raw) => serde_json::from_slice(&raw).map_err(|source| Error::Malformed {
                what: "index pack".into(),
                source,
            })?,
            // A missing or unreadable index is recoverable: it can be rebuilt
            // from `blobs/` with [`Repository::rebuild_index`]. The index is
            // not sensitive (hashes and keys only), so it stays unencrypted.
            Err(_) => IndexPack::default(),
        };
        Ok(Self {
            backend,
            config,
            master_key,
            index: Mutex::new(index),
        })
    }

    /// Create a repository on the local filesystem.
    ///
    /// # Errors
    ///
    /// See [`Repository::init_with_backend`].
    pub async fn init(
        path: impl AsRef<Path>,
        chunker: ChunkerConfig,
        passphrase: &str,
    ) -> Result<Self> {
        Self::init_with_backend(Box::new(LocalBackend::new(path)), chunker, passphrase).await
    }

    /// Open an existing repository on the local filesystem.
    ///
    /// # Errors
    ///
    /// See [`Repository::open_with_backend`].
    pub async fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        Self::open_with_backend(Box::new(LocalBackend::new(path)), passphrase).await
    }

    /// This repository's configuration.
    pub fn config(&self) -> &RepoConfig {
        &self.config
    }

    /// A snapshot of the current blob index.
    pub fn index(&self) -> IndexPack {
        self.index.lock().expect("index lock").clone()
    }

    /// Persist the index pack.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] or [`Error::Malformed`] if the pack cannot be
    /// serialized or written.
    pub async fn flush_index(&self) -> Result<()> {
        let bytes = {
            let index = self.index.lock().expect("index lock");
            serde_json::to_vec_pretty(&*index).expect("IndexPack is serializable")
        };
        self.backend.put(INDEX_PACK_KEY, &bytes).await
    }

    /// Rebuild the index from the blobs actually present in the backend, then
    /// persist it. Used when the pack is missing or suspected stale.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the backend listing fails.
    pub async fn rebuild_index(&self) -> Result<()> {
        let mut entries = BTreeMap::new();
        for key in self.backend.list(BLOBS_PREFIX).await? {
            let hex = key.rsplit('/').next().unwrap_or_default().to_string();
            if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let size = self.backend.size(&key).await.unwrap_or(0);
            entries.insert(
                hex.clone(),
                IndexEntry {
                    hash: hex,
                    key,
                    size,
                },
            );
        }
        *self.index.lock().expect("index lock") = IndexPack { entries };
        self.flush_index().await
    }

    /// Back up every regular file under `paths`, writing a new snapshot.
    ///
    /// The manifest stores one Merkle tree-root hash per source path; directory
    /// nodes larger than [`INLINE_DIR_LIMIT`] are written as their own blobs,
    /// so unchanged subtrees deduplicate at the tree level, not just the chunk
    /// level. Symlinks are not followed and are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if a source path or the backend cannot be
    /// read/written, or [`Error::InvalidInput`]-style [`Error::Io`] for unsafe
    /// file names.
    pub async fn backup(&self, paths: &[PathBuf]) -> Result<Snapshot> {
        let mut roots = Vec::with_capacity(paths.len());
        let mut display_paths = Vec::with_capacity(paths.len());
        let mut stats = SnapshotStats::default();
        // Chunks already hashed this run, so a file duplicated inside one
        // backup does not cost a second backend existence check per chunk.
        let mut seen: HashSet<String> = HashSet::new();

        for root in paths {
            let root = std::fs::canonicalize(root).map_err(|e| Error::io(root, e))?;
            let meta = std::fs::metadata(&root).map_err(|e| Error::io(&root, e))?;
            let node = if meta.is_dir() {
                self.backup_dir(&root, &mut seen, &mut stats).await?
            } else {
                self.backup_file(&root, &meta, &mut seen, &mut stats)
                    .await?
            };
            // The snapshot root is always a blob, never inline, so the manifest
            // can reference it by hash and the tree is independently verifiable.
            let root_hex = self.write_node_blob(&node, &mut seen, &mut stats).await?;
            display_paths.push(root.display().to_string());
            roots.push(root_hex);
        }

        let snapshot = Snapshot {
            id: uuid::Uuid::new_v4().simple().to_string(),
            time: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .expect("RFC 3339 formatting of a valid timestamp"),
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "unknown".into()),
            paths: display_paths,
            roots,
            stats,
        };

        let bytes = serde_json::to_vec_pretty(&snapshot).expect("Snapshot is serializable");
        // Manifests contain source paths and hostnames: encrypt them like data.
        let sealed = crypto::seal(
            &self.master_key,
            &bytes,
            Aad::Blob(&format!("snapshot:{}", snapshot.id)),
        )?;
        self.backend
            .put(&snapshot_key(&snapshot.id), &sealed)
            .await?;
        self.flush_index().await?;
        Ok(snapshot)
    }

    /// Build the tree node for a directory, writing chunk blobs and subtree
    /// blobs to the backend as they complete.
    async fn backup_dir(
        &self,
        dir: &Path,
        seen: &mut HashSet<String>,
        stats: &mut SnapshotStats,
    ) -> Result<TreeNode> {
        self.backup_dir_inner(dir, seen, stats).await
    }

    /// Boxed to keep the recursive future sized.
    fn backup_dir_inner<'a>(
        &'a self,
        dir: &'a Path,
        seen: &'a mut HashSet<String>,
        stats: &'a mut SnapshotStats,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TreeNode>> + Send + 'a>> {
        Box::pin(async move {
            let mut children: Vec<_> = std::fs::read_dir(dir)
                .map_err(|e| Error::io(dir, e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::io(dir, e))?;
            // Deterministic order: same content ⇒ same tree bytes ⇒ same node hash.
            children.sort_by_key(|c| c.file_name());

            let mut entries = Vec::with_capacity(children.len());
            for child in children {
                let child_path = child.path();
                let ft = child.file_type().map_err(|e| Error::io(&child_path, e))?;
                let name = child.file_name().to_string_lossy().into_owned();
                tree::validate_name(&name)?;

                if ft.is_dir() {
                    let node = self.backup_dir(&child_path, seen, stats).await?;
                    entries.push(TreeEntry {
                        name,
                        node: self.node_ref(&node, seen, stats).await?,
                    });
                } else if ft.is_file() {
                    let meta = child.metadata().map_err(|e| Error::io(&child_path, e))?;
                    let file_node = self.backup_file(&child_path, &meta, seen, stats).await?;
                    entries.push(TreeEntry {
                        name,
                        node: NodeRef::Inline(Box::new(file_node)),
                    });
                    stats.files += 1;
                }
                // Symlinks and other non-regular files are skipped (see Known Issues).
            }

            Ok(TreeNode::Dir { entries })
        })
    }

    /// Chunk, hash, and store one regular file, returning its [`TreeNode::File`].
    async fn backup_file(
        &self,
        path: &Path,
        meta: &std::fs::Metadata,
        seen: &mut HashSet<String>,
        stats: &mut SnapshotStats,
    ) -> Result<TreeNode> {
        let file = std::fs::File::open(path).map_err(|e| Error::io(path, e))?;
        let mut chunk_hashes = Vec::new();
        let mut pending: Vec<(String, Vec<u8>)> = Vec::new();

        // ponytail: reads the whole file every run. The mtime+size fast-path
        // against the previous snapshot (docs/03) and the `redb` dedup index
        // are remaining Phase 1 items; without them an unchanged tree still
        // re-hashes but writes no new blobs.
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
            self.put_blob_dedup(&hex, &bytes, stats).await?;
        }

        Ok(TreeNode::File {
            size: meta.len(),
            mode: file_mode(meta),
            mtime: mtime_secs(meta),
            chunks: chunk_hashes,
        })
    }

    /// Turn a completed directory node into a [`NodeRef`]: small directories
    /// stay inline in their parent, larger ones become their own tree blob.
    async fn node_ref(
        &self,
        node: &TreeNode,
        seen: &mut HashSet<String>,
        stats: &mut SnapshotStats,
    ) -> Result<NodeRef> {
        let bytes = tree::serialize_node(node)?;
        if bytes.len() < INLINE_DIR_LIMIT {
            return Ok(NodeRef::Inline(Box::new(node.clone())));
        }
        let hex = self.write_node_blob(node, seen, stats).await?;
        Ok(NodeRef::Blob(hex))
    }

    /// Serialize `node`, hash it, and store it as a content-addressed blob.
    async fn write_node_blob(
        &self,
        node: &TreeNode,
        seen: &mut HashSet<String>,
        stats: &mut SnapshotStats,
    ) -> Result<String> {
        let bytes = tree::serialize_node(node)?;
        let hex = blake3::hash(&bytes).to_hex().to_string();
        // A node appearing twice in one run (duplicate directory) hashes to the
        // same blob; only store it once per run.
        if seen.insert(hex.clone()) {
            self.put_blob_dedup(&hex, &bytes, stats).await?;
        }
        Ok(hex)
    }

    /// Write one content-addressed blob unless it is already present, updating
    /// stats and the in-memory index. The stored bytes are sealed under the
    /// master key with the blob's plaintext hash bound as AAD.
    ///
    /// Callers pass only blobs not already written this run (the chunking
    /// closure deduplicates `pending`; node hashes are deterministic), so no
    /// extra run-local set is consulted here. Cross-snapshot dedup is the
    /// `exists` check.
    async fn put_blob_dedup(
        &self,
        hex: &str,
        bytes: &[u8],
        stats: &mut SnapshotStats,
    ) -> Result<()> {
        let key = blob_key(hex);
        if !self.backend.exists(&key).await? {
            let sealed = crypto::seal(&self.master_key, bytes, Aad::Blob(hex))?;
            self.backend.put(&key, &sealed).await?;
            stats.new_chunks += 1;
            stats.new_bytes += sealed.len() as u64;
        }
        self.index.lock().expect("index lock").record(IndexEntry {
            hash: hex.to_string(),
            key,
            size: bytes.len() as u64,
        });
        Ok(())
    }

    /// Load a tree node, following [`NodeRef::Blob`] references.
    async fn load_node(&self, r#ref: &NodeRef) -> Result<TreeNode> {
        match r#ref {
            NodeRef::Inline(node) => Ok((**node).clone()),
            NodeRef::Blob(hex) => {
                let sealed = self
                    .backend
                    .get(&blob_key(hex))
                    .await
                    .map_err(|e| match e {
                        Error::Io { .. } => Error::MissingBlob(hex.clone()),
                        other => other,
                    })?;
                let bytes = crypto::open(&self.master_key, &sealed, Aad::Blob(hex))
                    .map_err(|_| Error::MissingBlob(hex.clone()))?;
                tree::parse_node(&bytes)
            }
        }
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
            let sealed = self.backend.get(&key).await?;
            let bytes = crypto::open(
                &self.master_key,
                &sealed,
                Aad::Blob(&format!(
                    "snapshot:{}",
                    key.rsplit('/')
                        .next()
                        .unwrap_or_default()
                        .trim_end_matches(".json")
                )),
            )?;
            out.push(
                serde_json::from_slice(&bytes).map_err(|source| Error::Malformed {
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
    /// Each rooted source directory is recreated by its original name under
    /// `target`. Files are streamed chunk by chunk, so peak memory is bounded
    /// by the maximum chunk size rather than the file size.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SnapshotNotFound`], [`Error::MissingBlob`] if the
    /// repository is missing a referenced chunk or tree blob, or [`Error::Io`]
    /// on write failure.
    pub async fn restore(&self, id_or_prefix: &str, target: impl AsRef<Path>) -> Result<Snapshot> {
        let snapshot = self.find_snapshot(id_or_prefix).await?;
        let target = target.as_ref();
        tokio::fs::create_dir_all(target)
            .await
            .map_err(|e| Error::io(target, e))?;

        for (i, root_hex) in snapshot.roots.iter().enumerate() {
            let sealed = self
                .backend
                .get(&blob_key(root_hex))
                .await
                .map_err(|_| Error::MissingBlob(root_hex.clone()))?;
            let bytes = crypto::open(&self.master_key, &sealed, Aad::Blob(root_hex))
                .map_err(|_| Error::MissingBlob(root_hex.clone()))?;
            let node = tree::parse_node(&bytes)?;

            // Recreate the backed-up directory (or file) under its original
            // name, matching how the source path was recorded.
            let name = std::path::Path::new(&snapshot.paths[i])
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "root".to_string());
            tree::validate_name(&name)?;
            self.restore_node(&node, &target.join(name)).await?;
        }
        Ok(snapshot)
    }

    /// Recursively materialize a tree node at `dest`.
    async fn restore_node(&self, node: &TreeNode, dest: &Path) -> Result<()> {
        self.restore_node_inner(node, dest).await
    }

    /// Boxed to keep the recursive future sized.
    fn restore_node_inner<'a>(
        &'a self,
        node: &'a TreeNode,
        dest: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            match node {
                TreeNode::Dir { entries } => {
                    tokio::fs::create_dir_all(dest)
                        .await
                        .map_err(|e| Error::io(dest, e))?;
                    for entry in entries {
                        tree::validate_name(&entry.name)?;
                        let child = self.load_node(&entry.node).await?;
                        self.restore_node(&child, &dest.join(&entry.name)).await?;
                    }
                    Ok(())
                }
                TreeNode::File {
                    size, mode, chunks, ..
                } => {
                    if let Some(parent) = dest.parent() {
                        tokio::fs::create_dir_all(parent)
                            .await
                            .map_err(|e| Error::io(parent, e))?;
                    }
                    let file = std::fs::File::create(dest).map_err(|e| Error::io(dest, e))?;
                    let mut writer = std::io::BufWriter::new(file);
                    for hex in chunks {
                        let sealed = self
                            .backend
                            .get(&blob_key(hex))
                            .await
                            .map_err(|_| Error::MissingBlob(hex.clone()))?;
                        let bytes = crypto::open(&self.master_key, &sealed, Aad::Blob(hex))
                            .map_err(|_| Error::MissingBlob(hex.clone()))?;
                        writer.write_all(&bytes).map_err(|e| Error::io(dest, e))?;
                    }
                    writer.flush().map_err(|e| Error::io(dest, e))?;
                    drop(writer);

                    // A size mismatch means a blob's contents no longer match its
                    // hash — treat it as corruption, not as a best-effort restore.
                    let actual = std::fs::metadata(dest)
                        .map(|m| m.len())
                        .map_err(|e| Error::io(dest, e))?;
                    if actual != *size {
                        return Err(Error::io(
                            dest,
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("restored size {actual} != recorded size {size}"),
                            ),
                        ));
                    }
                    restore_mode(dest, *mode).await
                }
            }
        })
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
    fn blob_keys_are_sharded_by_hash_prefix() {
        let hex = "abcdef".to_string() + &"0".repeat(58);
        assert_eq!(blob_key(&hex), format!("blobs/ab/{hex}"));
    }

    #[test]
    fn index_pack_roundtrips() {
        let mut pack = IndexPack::default();
        pack.record(IndexEntry {
            hash: "ab".repeat(32),
            key: "blobs/ab/ab".into(),
            size: 3,
        });
        let bytes = serde_json::to_vec(&pack).unwrap();
        let parsed: IndexPack = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[&"ab".repeat(32)].size, 3);
    }
}
