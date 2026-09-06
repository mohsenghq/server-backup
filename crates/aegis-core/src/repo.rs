//! The repository: init, backup, restore, and snapshot listing over any
//! [`Backend`].

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::backend::{Backend, LocalBackend};
use crate::blobs;
use crate::chunk::{chunk_stream, ChunkerConfig};
use crate::crypto::KdfParams;
use crate::error::{Error, Result};
use crate::keys::{AeadContext, KeyFile, RepoCrypto};
use crate::snapshot::{BlobKind, BlobRef, Snapshot, SnapshotIndex, SnapshotStats};
use crate::tree::{self, Node};

/// Repository format version this build reads and writes.
pub const FORMAT_VERSION: u32 = 1;

const CONFIG_KEY: &str = "config";
const BLOBS_PREFIX: &str = "blobs";
const SNAPSHOTS_PREFIX: &str = "snapshots";
const INDEX_PREFIX: &str = "index";
const KEYS_PREFIX: &str = "keys";

/// The repository's `config` document.
///
/// Deliberately stored in plaintext: it holds no secrets — only the format
/// version, repo id, chunker parameters, and which key slot opens the repo.
/// Reading it is what tells Aegis *how* to decrypt everything else. All
/// sensitive content (data chunks, tree nodes, snapshot manifests, snapshot
/// indexes) is sealed under the master key before it reaches the backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoConfig {
    /// Repository format version — see [`FORMAT_VERSION`].
    pub version: u32,
    /// Stable identifier for this repository.
    pub id: String,
    /// Chunker parameters, fixed at `init` time. Changing them would defeat
    /// deduplication against existing snapshots.
    pub chunker: ChunkerConfig,
    /// Whether blobs and documents are encrypted (always true for repos this
    /// build creates).
    #[serde(default)]
    pub encrypted: bool,
    /// Which key slot in `keys/` opens this repository.
    #[serde(default)]
    pub key_slot: String,
}

/// An open Aegis repository.
///
/// A repository is a set of keys in a [`Backend`]; `LocalBackend` is only one
/// choice. Every method takes `&self` — backends are shared, interior state
/// is theirs.
pub struct Repository {
    backend: Box<dyn Backend>,
    config: RepoConfig,
    crypto: Option<RepoCrypto>,
}

impl Repository {
    /// Create an encrypted repository in an empty or non-existent location.
    ///
    /// A random master key is generated and wrapped under `passphrase`
    /// (Argon2id → XChaCha20-Poly1305, see `docs/10-security-model.md`) into
    /// the `default` key slot. From this point on, **every** byte the
    /// repository stores — data chunks, tree nodes, snapshot manifests,
    /// snapshot indexes — is ciphertext; only `config` and the wrapped key
    /// file are plaintext, and neither contains secrets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RepoExists`] if a `config` is already present,
    /// [`Error::InvalidChunkerConfig`] for bad chunker parameters, or
    /// [`Error::Io`] if the backend cannot be written.
    pub async fn init(
        backend: Box<dyn Backend>,
        chunker: ChunkerConfig,
        passphrase: &str,
    ) -> Result<Self> {
        Self::init_with_kdf(backend, chunker, passphrase, KdfParams::default()).await
    }

    /// [`Repository::init`] with explicit Argon2id parameters. The parameters
    /// are recorded in the key file, so `open` never has to guess them;
    /// tests use this to keep derivations fast.
    ///
    /// # Errors
    ///
    /// Same as [`Repository::init`], plus [`Error::KdfFailed`] for bad params.
    pub async fn init_with_kdf(
        backend: Box<dyn Backend>,
        chunker: ChunkerConfig,
        passphrase: &str,
        kdf: KdfParams,
    ) -> Result<Self> {
        chunker.validate()?;
        if backend.exists(CONFIG_KEY).await? {
            return Err(Error::RepoExists(backend.describe()));
        }
        let master = crate::crypto::generate_master_key();
        let (crypto, key_file) = RepoCrypto::new_wrapped("default", &master, passphrase, &kdf)?;
        let key_bytes = key_file.to_json()?;
        backend
            .put(&format!("{KEYS_PREFIX}/default.json"), &key_bytes)
            .await?;
        let config = RepoConfig {
            version: FORMAT_VERSION,
            id: uuid::Uuid::new_v4().to_string(),
            chunker,
            encrypted: true,
            key_slot: "default".into(),
        };
        let bytes = serde_json::to_vec_pretty(&config).expect("RepoConfig is serializable");
        backend.put(CONFIG_KEY, &bytes).await?;
        Ok(Self {
            backend,
            config,
            crypto: Some(crypto),
        })
    }

    /// Open an existing repository, unwrapping its master key with
    /// `passphrase`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RepoNotFound`] if there is no `config`,
    /// [`Error::UnsupportedFormat`] if it was written by an incompatible
    /// version, [`Error::Malformed`] if it cannot be parsed,
    /// [`Error::KeyError`] if the configured key slot is missing, and
    /// [`Error::WrongPassphrase`] if the passphrase does not open it.
    pub async fn open(backend: Box<dyn Backend>, passphrase: &str) -> Result<Self> {
        if !backend.exists(CONFIG_KEY).await? {
            return Err(Error::RepoNotFound(backend.describe()));
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
        let crypto = if config.encrypted {
            Some(Self::open_crypto(backend.as_ref(), &config, passphrase).await?)
        } else {
            // A pre-encryption repository: readable, but new writes stay
            // plaintext until it is migrated (Phase 6 re-key flow).
            None
        };
        Ok(Self {
            backend,
            config,
            crypto,
        })
    }

    async fn load_key_file(backend: &dyn Backend, slot: &str) -> Result<KeyFile> {
        let key = format!("{KEYS_PREFIX}/{slot}.json");
        if !backend.exists(&key).await? {
            return Err(Error::KeyError(format!(
                "key slot '{slot}' is missing from the repository"
            )));
        }
        KeyFile::from_json(&backend.get(&key).await?)
    }

    /// Unlock the repository with `passphrase`, trying the configured slot
    /// first and then every other key slot. Passphrases added with `key add`
    /// live in additional slots (`key1`, `key2`, ...), so a repository is
    /// openable by any of its passphrases, not just the one `config`
    /// currently names.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyError`] if no key file parses, and
    /// [`Error::WrongPassphrase`] when the passphrase opens none of them.
    async fn open_crypto(
        backend: &dyn Backend,
        config: &RepoConfig,
        passphrase: &str,
    ) -> Result<RepoCrypto> {
        let mut slots = vec![config.key_slot.clone()];
        for key in backend.list(KEYS_PREFIX).await? {
            if let Some(stem) = key
                .strip_prefix("keys/")
                .and_then(|rest| rest.strip_suffix(".json"))
            {
                if !slots.contains(&stem.to_string()) {
                    slots.push(stem.to_string());
                }
            }
        }
        let mut last = Error::KeyError("repository has no key files".into());
        for slot in slots {
            let Ok(file) = Self::load_key_file(backend, &slot).await else {
                continue;
            };
            match RepoCrypto::from_key_file(&file, passphrase) {
                Ok(crypto) => return Ok(crypto),
                // The passphrase may open another slot; remember the failure
                // in case it opens none.
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Create a repository on the local filesystem — convenience wrapper for
    /// [`Repository::init`] with a [`LocalBackend`].
    ///
    /// # Errors
    ///
    /// Same as [`Repository::init`].
    pub async fn init_local(
        path: impl AsRef<Path>,
        chunker: ChunkerConfig,
        passphrase: &str,
    ) -> Result<Self> {
        Self::init(
            Box::new(LocalBackend::new(path.as_ref())),
            chunker,
            passphrase,
        )
        .await
    }

    /// [`Repository::init_local`] with explicit Argon2id parameters (tests
    /// use this to keep derivations fast).
    ///
    /// # Errors
    ///
    /// Same as [`Repository::init_with_kdf`].
    pub async fn init_local_with_kdf(
        path: impl AsRef<Path>,
        chunker: ChunkerConfig,
        passphrase: &str,
        kdf: KdfParams,
    ) -> Result<Self> {
        Self::init_with_kdf(
            Box::new(LocalBackend::new(path.as_ref())),
            chunker,
            passphrase,
            kdf,
        )
        .await
    }

    /// Open a repository on the local filesystem — convenience wrapper for
    /// [`Repository::open`] with a [`LocalBackend`].
    ///
    /// # Errors
    ///
    /// Same as [`Repository::open`].
    pub async fn open_local(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        Self::open(Box::new(LocalBackend::new(path.as_ref())), passphrase).await
    }

    /// This repository's configuration.
    pub fn config(&self) -> &RepoConfig {
        &self.config
    }

    /// Seal `data` for storage: envelope + compression + (when the repo is
    /// encrypted) AEAD under the repo master key. `key` is the storage key
    /// the sealed bytes will live at, included in error context only.
    fn seal_for(&self, key: &str, context: &AeadContext, data: &[u8]) -> Result<Vec<u8>> {
        match &self.crypto {
            Some(c) => blobs::encrypt_and_encode(c, context, data),
            None => {
                let _ = key;
                Ok(blobs::encode(data))
            }
        }
    }

    /// Inverse of [`Repository::seal_for`].
    fn open_for(&self, key: &str, context: &AeadContext, stored: &[u8]) -> Result<Vec<u8>> {
        match &self.crypto {
            Some(c) => blobs::decrypt_and_decode(c, context, stored),
            None => {
                let _ = key;
                blobs::decode(stored)
            }
        }
    }

    /// The backend this repository operates on.
    pub fn backend(&self) -> &dyn Backend {
        self.backend.as_ref()
    }

    /// Back up every regular file under `paths`, writing a new snapshot.
    ///
    /// Symlinks are not followed and are skipped this phase. Unreadable files
    /// abort the run rather than producing a silently incomplete snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if a source path or the backend cannot be read/written.
    pub async fn backup(&self, paths: &[std::path::PathBuf]) -> Result<Snapshot> {
        let mut stats = SnapshotStats::default();
        // Chunks deduplicated within this run, so a file duplicated inside one
        // backup does not cost a second backend existence check per chunk.
        let mut seen: HashSet<String> = HashSet::new();
        // Sizes of blobs this run actually wrote (data chunks and tree nodes).
        let mut written: HashMap<String, u64> = HashMap::new();

        let mut roots = Vec::with_capacity(paths.len());
        let mut children = Vec::with_capacity(paths.len());
        for root in paths {
            let root = std::fs::canonicalize(root).map_err(|e| Error::io(root, e))?;
            roots.push(root.display().to_string());
            // The tree stores paths relative to the root's parent so that
            // restoring recreates the backed-up directory by name.
            let strip_base = root.parent().unwrap_or(root.as_path()).to_path_buf();
            children.push(
                self.backup_dir(&root, &strip_base, &mut stats, &mut seen, &mut written)
                    .await?,
            );
        }

        let mut root = Node::Dir {
            name: "root".into(),
            children,
        };
        // Sort before hashing: node hashes are taken over the canonical
        // serialization.
        root.sort();
        let (root, node_blobs) = tree::build_stored(root)?;

        for (hash, bytes) in &node_blobs {
            if !self.backend.exists(&blob_key(hash)).await? {
                let stored = self.seal_for(&blob_key(hash), &AeadContext::Hash(hash), bytes)?;
                self.backend.put(&blob_key(hash), &stored).await?;
                stats.new_tree_nodes += 1;
                written.insert(hash.clone(), stored.len() as u64);
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
            root,
            stats,
        };

        // The index lists EVERY blob this snapshot references — not just the
        // new ones — because garbage collection must treat a blob referenced
        // by any live snapshot as reachable, however old the blob is. It is
        // written before the manifest: once `snapshots/<id>.json` exists,
        // `index/<id>.json` does too.
        let index = self.build_index(&snapshot, &written);
        let index_plain = serde_json::to_vec(&index).expect("SnapshotIndex is serializable");
        let index_bytes =
            self.seal_for(&index_key(&snapshot.id), &AeadContext::Doc, &index_plain)?;
        self.backend
            .put(&index_key(&snapshot.id), &index_bytes)
            .await?;

        let manifest_plain =
            serde_json::to_vec_pretty(&snapshot).expect("Snapshot is serializable");
        let manifest_bytes = self.seal_for(
            &snapshot_key(&snapshot.id),
            &AeadContext::Doc,
            &manifest_plain,
        )?;
        self.backend
            .put(&snapshot_key(&snapshot.id), &manifest_bytes)
            .await?;
        Ok(snapshot)
    }

    /// The complete blob reference set of `snapshot`: every data chunk hash
    /// from the tree's file nodes plus every tree-node blob hash, with sizes
    /// filled in for blobs this run wrote.
    fn build_index(&self, snapshot: &Snapshot, written: &HashMap<String, u64>) -> SnapshotIndex {
        let mut chunk_hashes = Vec::new();
        snapshot.root.collect_chunk_hashes(&mut chunk_hashes);
        let mut tree_hashes = Vec::new();
        snapshot.root.collect_refs(&mut tree_hashes);

        let mut seen = HashSet::new();
        let mut blobs = Vec::with_capacity(chunk_hashes.len() + tree_hashes.len());
        for (hash, kind) in chunk_hashes
            .into_iter()
            .map(|h| (h, BlobKind::Chunk))
            .chain(tree_hashes.into_iter().map(|h| (h, BlobKind::TreeNode)))
        {
            if seen.insert(hash.clone()) {
                let size = written.get(&hash).copied();
                blobs.push(BlobRef { hash, size, kind });
            }
        }
        SnapshotIndex {
            snapshot_id: snapshot.id.clone(),
            blobs,
        }
    }

    /// Build the tree node for one backup root: recursively walk `dir`, chunk
    /// and store every regular file.
    async fn backup_dir(
        &self,
        dir: &Path,
        strip_base: &Path,
        stats: &mut SnapshotStats,
        seen: &mut HashSet<String>,
        written: &mut HashMap<String, u64>,
    ) -> Result<Node> {
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "root".into());
        let mut children: Vec<Node> = Vec::new();

        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| Error::io(dir, e))?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let entry_path = entry.path();
            let ft = entry.file_type().map_err(|e| Error::io(&entry_path, e))?;
            if ft.is_dir() {
                children.push(
                    Box::pin(self.backup_dir(&entry_path, strip_base, stats, seen, written))
                        .await?,
                );
            } else if ft.is_file() {
                children.push(
                    self.backup_file(&entry_path, &entry, stats, seen, written)
                        .await?,
                );
            }
            // Symlinks and other non-regular files are skipped this phase.
        }

        let mut node = Node::Dir { name, children };
        node.sort();
        Ok(node)
    }

    /// Chunk, hash, and store one regular file; return its tree node.
    async fn backup_file(
        &self,
        path: &Path,
        entry: &std::fs::DirEntry,
        stats: &mut SnapshotStats,
        seen: &mut HashSet<String>,
        written: &mut HashMap<String, u64>,
    ) -> Result<Node> {
        let name = entry.file_name().to_string_lossy().into_owned();
        let meta = entry.metadata().map_err(|e| Error::io(path, e))?;

        let file = std::fs::File::open(path).map_err(|e| Error::io(path, e))?;
        let mut chunk_hashes = Vec::new();
        let mut pending: Vec<(String, Vec<u8>)> = Vec::new();

        // ponytail: reads the whole file every run. The mtime+size fast-path
        // against the previous snapshot (docs/03) is still owed; without it an
        // unchanged tree re-hashes but writes no new blobs.
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
            if !self.backend.exists(&blob_key(&hex)).await? {
                let stored = self.seal_for(&blob_key(&hex), &AeadContext::Hash(&hex), &bytes)?;
                self.backend.put(&blob_key(&hex), &stored).await?;
                stats.new_chunks += 1;
                stats.new_bytes += stored.len() as u64;
                written.insert(hex, stored.len() as u64);
            }
        }

        stats.files += 1;
        Ok(Node::File {
            name,
            size: meta.len(),
            mode: file_mode(&meta),
            mtime: mtime_secs(&meta),
            chunks: chunk_hashes,
        })
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
            let stored = self.backend.get(&key).await?;
            let raw = self.open_for(&key, &AeadContext::Doc, &stored)?;
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

    /// Load a snapshot's blob index; falls back to deriving it by walking the
    /// snapshot's tree (fetching node blobs) for manifests written before
    /// per-snapshot indexes existed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] or [`Error::Malformed`] if the index cannot be
    /// read or parsed, or walk errors on the fallback path.
    pub async fn snapshot_index(&self, snapshot: &Snapshot) -> Result<SnapshotIndex> {
        let key = index_key(&snapshot.id);
        if self.backend.exists(&key).await? {
            let stored = self.backend.get(&key).await?;
            let raw = self.open_for(&key, &AeadContext::Doc, &stored)?;
            return serde_json::from_slice(&raw).map_err(|source| Error::Malformed {
                what: format!("snapshot index {key}"),
                source,
            });
        }
        // Fallback: derive reachability from the tree itself.
        let mut blobs = Vec::new();
        let mut seen = HashSet::new();
        let mut chunks = Vec::new();
        snapshot.root.collect_chunk_hashes(&mut chunks);
        for hash in chunks {
            if seen.insert(hash.clone()) {
                blobs.push(BlobRef {
                    hash,
                    size: None,
                    kind: BlobKind::Chunk,
                });
            }
        }
        collect_node_blob_hashes(
            self.backend.as_ref(),
            self.crypto.as_ref(),
            &snapshot.root,
            &mut blobs,
            &mut seen,
        )
        .await?;
        Ok(SnapshotIndex {
            snapshot_id: snapshot.id.clone(),
            blobs,
        })
    }

    /// Restore a snapshot's files beneath `target`.
    ///
    /// File contents are streamed chunk-by-chunk to disk; peak memory is
    /// bounded by the chunker's max chunk size, not by file size.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SnapshotNotFound`], [`Error::BadPath`] for unsafe tree
    /// names, [`Error::MissingBlob`] if the repository is missing a referenced
    /// chunk, or [`Error::Io`] on write failure.
    pub async fn restore(&self, id_or_prefix: &str, target: impl AsRef<Path>) -> Result<Snapshot> {
        let snapshot = self.find_snapshot(id_or_prefix).await?;
        let target = target.as_ref();

        tokio::fs::create_dir_all(target)
            .await
            .map_err(|e| Error::io(target, e))?;
        // The synthetic root is a container, not a directory from the source
        // filesystem: its children — one per backed-up path — are laid
        // directly into `target`, so restoring recreates each backed-up
        // directory by name, exactly as Phase 0 did.
        match &snapshot.root {
            Node::Dir { children, .. } => {
                for child in children {
                    restore_node(self.backend.as_ref(), self.crypto.as_ref(), child, target)
                        .await?;
                }
            }
            other => {
                restore_node(self.backend.as_ref(), self.crypto.as_ref(), other, target).await?
            }
        }
        Ok(snapshot)
    }

    /// Union of all blob hashes reachable from a set of snapshots. `index/`
    /// keys are NOT included (they live outside `blobs/`); GC removes those
    /// directly with the pruned manifests.
    ///
    /// # Errors
    ///
    /// Propagates backend and parse errors from the underlying reads.
    pub async fn reachable_blobs(
        &self,
        snapshots: &[Snapshot],
    ) -> Result<HashMap<String, BlobKind>> {
        let mut out: HashMap<String, BlobKind> = HashMap::new();
        for s in snapshots {
            let index = self.snapshot_index(s).await?;
            for b in index.blobs {
                out.entry(b.hash).or_insert(b.kind);
            }
        }
        Ok(out)
    }

    /// Every blob key stored under `blobs/`.
    ///
    /// # Errors
    ///
    /// Propagates backend listing errors.
    pub async fn all_blob_keys(&self) -> Result<Vec<String>> {
        self.backend.list(BLOBS_PREFIX).await
    }

    /// Delete a blob by hash. Prune's only destructive primitive.
    ///
    /// # Errors
    ///
    /// Propagates backend deletion errors.
    pub async fn delete_blob(&self, hash: &str) -> Result<()> {
        self.backend.delete(&blob_key(hash)).await
    }
}

/// Walk a (possibly ref-containing) tree, collecting every referenced
/// tree-node blob hash, fetching ref blobs to descend through them.
async fn collect_node_blob_hashes(
    backend: &dyn Backend,
    crypto: Option<&RepoCrypto>,
    node: &Node,
    out: &mut Vec<BlobRef>,
    seen: &mut HashSet<String>,
) -> Result<()> {
    match node {
        Node::Ref { hash, .. } => {
            if !seen.insert(hash.clone()) {
                return Ok(());
            }
            out.push(BlobRef {
                hash: hash.clone(),
                size: None,
                kind: BlobKind::TreeNode,
            });
            let stored = backend.get(&blob_key(hash)).await?;
            let bytes = decode_blob_hash_ctx(crypto, hash, &stored)?;
            let inner: Node =
                serde_json::from_slice(&bytes).map_err(|source| Error::Malformed {
                    what: format!("tree node {hash}"),
                    source,
                })?;

            Box::pin(collect_node_blob_hashes(backend, crypto, &inner, out, seen)).await
        }
        Node::Dir { children, .. } => {
            for child in children {
                Box::pin(collect_node_blob_hashes(backend, crypto, child, out, seen)).await?;
            }
            Ok(())
        }
        Node::File { .. } => Ok(()),
    }
}

/// Like [`decode_blob`] but authenticating a content-addressed blob against
/// its own hash.
fn decode_blob_hash_ctx(crypto: Option<&RepoCrypto>, hex: &str, stored: &[u8]) -> Result<Vec<u8>> {
    match crypto {
        Some(c) => blobs::decrypt_and_decode(c, &AeadContext::Hash(hex), stored),
        None => blobs::decode(stored),
    }
}

/// Restore one tree node under `dir`.
async fn restore_node(
    backend: &dyn Backend,
    crypto: Option<&RepoCrypto>,
    node: &Node,
    dir: &Path,
) -> Result<()> {
    node.validate()?;
    match node {
        Node::File {
            name,
            mode,
            mtime,
            chunks,
            ..
        } => {
            let dest = safe_join(dir, name)?;
            restore_file(backend, crypto, &dest, chunks).await?;
            restore_mode(&dest, *mode).await?;
            restore_mtime(&dest, *mtime).await;
            Ok(())
        }
        Node::Dir { name, children } => {
            let here = safe_join(dir, name)?;
            tokio::fs::create_dir_all(&here)
                .await
                .map_err(|e| Error::io(&here, e))?;
            for child in children {
                Box::pin(restore_node(backend, crypto, child, &here)).await?;
            }
            Ok(())
        }
        Node::Ref { hash, .. } => {
            let stored = backend.get(&blob_key(hash)).await?;
            // Tree-node blobs are content-addressed: authenticate against the
            // ref's hash, not the Doc context.
            let bytes = decode_blob_hash_ctx(crypto, hash, &stored)?;
            let inner: Node =
                serde_json::from_slice(&bytes).map_err(|source| Error::Malformed {
                    what: format!("tree node {hash}"),
                    source,
                })?;
            Box::pin(restore_node(backend, crypto, &inner, dir)).await
        }
    }
}

/// Stream one file's chunks to disk. Chunk blobs are content-addressed, so
/// each is authenticated against its own hash as the AAD context.
async fn restore_file(
    backend: &dyn Backend,
    crypto: Option<&RepoCrypto>,
    dest: &Path,
    chunks: &[String],
) -> Result<()> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| Error::io(parent, e))?;
    }
    let file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| Error::io(dest, e))?;
    let mut writer = tokio::io::BufWriter::new(file);
    use tokio::io::AsyncWriteExt;

    for hex in chunks {
        let key = blob_key(hex);
        if !backend.exists(&key).await? {
            return Err(Error::MissingBlob(hex.clone()));
        }
        let stored = backend.get(&key).await?;
        let bytes = decode_blob_hash_ctx(crypto, hex, &stored)?;
        writer
            .write_all(&bytes)
            .await
            .map_err(|e| Error::io(dest, e))?;
    }
    writer.flush().await.map_err(|e| Error::io(dest, e))?;
    Ok(())
}

/// Join a snapshot-relative path under `base`, rejecting anything that would
/// escape it. Manifests are attacker-influenced input on a shared repository:
/// a `../../etc/cron.d/x` entry must never write outside the restore target.
fn safe_join(base: &Path, rel: &str) -> Result<std::path::PathBuf> {
    let mut out = base.to_path_buf();
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg.contains('\\') || seg.contains(':') {
            return Err(Error::BadPath(rel.to_string()));
        }
        out.push(seg);
    }
    Ok(out)
}

/// Key of a data or tree-node blob, sharded by the first two hex characters of
/// its hash (`docs/03-repository-format.md`) to keep directory fan-out manageable.
pub(crate) fn blob_key(hex: &str) -> String {
    format!("{BLOBS_PREFIX}/{}/{hex}", &hex[..2])
}

pub(crate) fn snapshot_key(id: &str) -> String {
    format!("{SNAPSHOTS_PREFIX}/{id}.json")
}

pub(crate) fn index_key(id: &str) -> String {
    format!("{INDEX_PREFIX}/{id}.json")
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

/// Reapply the recorded modification time (best effort: failures are ignored,
/// clock skew on the restoring host must not fail a restore).
async fn restore_mtime(path: &Path, mtime: Option<i64>) {
    if let Some(secs) = mtime {
        let _ = filetime::set_file_mtime(path, filetime::FileTime::from_unix_time(secs, 0));
    }
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

    #[test]
    fn blob_index_and_snapshot_keys_are_layout_stable() {
        let hex = "ab".repeat(32);
        assert_eq!(blob_key(&hex), format!("blobs/ab/{hex}"));
        assert_eq!(snapshot_key("id"), "snapshots/id.json");
        assert_eq!(index_key("id"), "index/id.json");
    }
}
