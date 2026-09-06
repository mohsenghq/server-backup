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
    RepoExists(String),

    /// No repository was found at the given location.
    #[error("no repository at {0} (run `aegis init` first)")]
    RepoNotFound(String),

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

    /// A name in a snapshot tree is not a safe single path component.
    ///
    /// Manifests are attacker-influenced input on a shared repository; a name
    /// that could escape the restore target (`..`, absolute-ish, separator
    /// characters) must never reach the filesystem.
    #[error("unsafe path component in snapshot tree: {0}")]
    BadPath(String),

    /// A stored blob does not match the repository's blob envelope.
    #[error("malformed blob: {0}")]
    MalformedBlob(String),

    /// A stored blob's compressed payload could not be decompressed.
    #[error("decompression failed: {0}")]
    DecompressFailed(String),

    /// Stored content does not hash to its address, or a manifest's committed
    /// hash does not match the tree it accompanies (detected by `verify`).
    #[error("corrupted content: {0}")]
    CorruptBlob(String),

    /// Argon2id key derivation failed.
    #[error("key derivation failed: {0}")]
    KdfFailed(String),

    /// Encrypting data before storage failed.
    #[error("encryption failed: {0}")]
    EncryptFailed(String),

    /// Decrypting stored data failed: wrong key or corrupted ciphertext.
    #[error("decryption failed: {0}")]
    DecryptFailed(String),

    /// The supplied passphrase does not open this repository.
    #[error("wrong passphrase")]
    WrongPassphrase,

    /// No passphrase is available (set `AEGIS_PASSPHRASE` or type one when
    /// prompted).
    #[error("no passphrase available (set AEGIS_PASSPHRASE or run interactively)")]
    NoPassphrase,

    /// A key slot referenced by the repository is missing or invalid.
    #[error("key slot error: {0}")]
    KeyError(String),

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

    /// An SSH transport, authentication or SFTP protocol failure.
    #[error("ssh error: {0}")]
    Ssh(String),

    /// The server's host key changed since it was first recorded.
    ///
    /// This is the classic machine-in-the-middle signal; the session is
    /// refused rather than silently re-recording the key.
    #[error(
        "host key for {host} changed (possible man-in-the-middle attack); \
             remove the old entry from your known_hosts to accept the new key"
    )]
    HostKeyChanged {
        /// The `host:port` whose key changed.
        host: String,
    },
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
