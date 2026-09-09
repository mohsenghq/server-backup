//! Aegis backup engine.
//!
//! `aegis-core` owns everything below the control plane: content-defined
//! chunking, content addressing, the repository format, and the storage backend
//! abstraction. It knows nothing about hosts, policies, or jobs — those are
//! layered on top by `aegis-server` (see `docs/01-architecture.md`).
//!
//! ```no_run
//! # async fn example() -> aegis_core::Result<()> {
//! use aegis_core::{ChunkerConfig, Repository};
//!
//! let repo = Repository::init("/srv/backups", ChunkerConfig::default(), "passphrase").await?;
//! let snapshot = repo.backup(&["/etc".into()]).await?;
//! repo.restore(&snapshot.id, "/tmp/restored").await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

pub mod backend;
pub mod chunk;
pub mod crypto;
pub mod error;
pub mod repo;
pub mod snapshot;
pub mod tree;

pub use backend::{Backend, LocalBackend};
pub use chunk::{Chunk, ChunkHash, ChunkerConfig};
pub use crypto::{KdfParams, Key, WrappedKey, KEY_LEN};
pub use error::{Error, Result};
pub use repo::{IndexEntry, IndexPack, RepoConfig, Repository, FORMAT_VERSION};
pub use snapshot::{Snapshot, SnapshotStats};
pub use tree::{NodeRef, TreeEntry, TreeNode};
