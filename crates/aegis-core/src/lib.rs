//! Aegis backup engine.
//!
//! `aegis-core` owns everything below the control plane: content-defined
//! chunking, content addressing, the repository format, and the storage backend
//! abstraction. It knows nothing about hosts, policies, or jobs — those are
//! layered on top by `aegis-server` (see `docs/01-architecture.md`).
//!
//! ```no_run
//! # async fn example() -> aegis_core::Result<()> {
//! use aegis_core::{ChunkerConfig, LocalBackend, Repository};
//!
//! let backend = Box::new(LocalBackend::new("/srv/backups"));
//! let repo = Repository::init(backend, ChunkerConfig::default(), "passphrase").await?;
//! let snapshot = repo.backup(&["/etc".into()]).await?;
//! repo.restore(&snapshot.id, "/tmp/restored").await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

pub mod agent;
pub mod agent_test_hooks;
pub mod agentless;
pub mod backend;
pub mod blobs;
pub mod catalog;
pub mod chunk;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod replication;
pub mod repo;
pub mod retention;
pub mod sftp;
pub mod snapshot;
pub mod ssh;
pub mod tree;

pub use agentless::backup_remote;
pub use backend::{Backend, LocalBackend};
pub use catalog::{AuditEntry, BackupMode, Catalog, Host, HostStatus, HostWithKey, Job, Policy};
pub use chunk::{Chunk, ChunkHash, ChunkerConfig};
pub use error::{Error, Result};
pub use keys::{AeadContext, KeyFile, PassphraseSource, RepoCrypto};
pub use replication::{replicate, ReplicateMode, ReplicateStats};
pub use repo::{RepoConfig, Repository, FORMAT_VERSION};
pub use sftp::{parse_location, RepoLocation, SftpAuth};
pub use snapshot::{BlobKind, BlobRef, Snapshot, SnapshotIndex, SnapshotStats};
pub use ssh::{ExecOutput, HostConfig, SshManager};
pub use tree::{Node, INLINE_LIMIT};

/// Stable key-layout helpers exposed for integration tests and inspection
/// tooling; not part of the core API surface.
pub mod repo_test_hooks {
    /// The `blobs/<xx>/<hash>` repository key for a hex blob hash.
    pub fn blob_key_for(hex: &str) -> String {
        crate::repo::blob_key(hex)
    }
}
