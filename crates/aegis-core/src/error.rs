//! Error type shared by every `aegis-core` operation.

use std::path::PathBuf;

/// Errors produced by the Aegis engine.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An I/O operation against the local filesystem or a backend failed.
    #[error("i/o error at {path}: {source}")]
    Io {
        /// The path being operated on when the failure occurred.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A repository already exists at the target location.
    #[error("a repository already exists at {0}")]
    RepoExists(PathBuf),

    /// No repository was found at the given location.
    #[error("no repository at {0} (run `aegis init` first)")]
    RepoNotFound(PathBuf),

    /// The repository was written by an incompatible format version.
    #[error("unsupported repository format version {found} (this build supports {supported})")]
    UnsupportedFormat {
        /// Version recorded in the repository's `config`.
        found: u32,
        /// Version this build can read.
        supported: u32,
    },

    /// The requested snapshot does not exist in the repository.
    #[error("snapshot {0} not found")]
    SnapshotNotFound(String),

    /// A blob referenced by a snapshot is missing from the repository.
    #[error("blob {0} referenced by snapshot is missing from the repository")]
    MissingBlob(String),

    /// Stored JSON (a repo config or snapshot manifest) could not be parsed.
    #[error("malformed {what}: {source}")]
    Malformed {
        /// Which document failed to parse.
        what: String,
        /// The underlying deserialization error.
        #[source]
        source: serde_json::Error,
    },

    /// A chunker configuration violated FastCDC's size invariants.
    #[error("invalid chunker configuration: {0}")]
    InvalidChunkerConfig(String),

    /// A cryptographic operation failed outright (bad params, RNG, format).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Decryption failed: wrong passphrase/key, wrong associated data, or a
    /// tampered ciphertext. Authenticated encryption cannot distinguish these.
    #[error("decryption failed (wrong passphrase or corrupted data)")]
    DecryptionFailed,

    /// No key file in the repository matched the supplied passphrase material.
    #[error("no key in this repository matches the provided passphrase")]
    NoMatchingKey,
}

/// Convenience alias for results returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Wrap an [`std::io::Error`] with the path that produced it.
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}
