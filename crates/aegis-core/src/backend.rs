//! Storage backend abstraction and the local-filesystem implementation.
//!
//! A backend is a flat, async key/value store over opaque byte blobs. Every
//! repository concept — blobs, snapshots, config — is expressed as keys in this
//! store, so the on-disk layout in `docs/03-repository-format.md` is identical
//! whether the bytes land on local disk, SFTP, or S3.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// A content store Aegis can write a repository into.
///
/// Implementations must be safe to share across tasks. Keys are `/`-separated
/// relative paths (for example `blobs/ab/abcdef…`); backends are responsible for
/// translating them to their native addressing.
#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    /// Read the object stored at `key`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the object is missing or unreadable.
    async fn get(&self, key: &str) -> Result<Vec<u8>>;

    /// Write `data` at `key`, creating or replacing the object.
    ///
    /// Writes are atomic: a reader never observes a partially written object.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the object cannot be written.
    async fn put(&self, key: &str, data: &[u8]) -> Result<()>;

    /// Report whether an object exists at `key`.
    ///
    /// This is the deduplication check on the write path, so it must be cheap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if existence cannot be determined.
    async fn exists(&self, key: &str) -> Result<bool>;

    /// List the keys under `prefix`, in unspecified order.
    ///
    /// A missing prefix yields an empty list rather than an error.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the listing fails.
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;

    /// Delete the object at `key`. Deleting a missing key succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the object exists but cannot be removed.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Size in bytes of the object at `key`, if it exists and the backend can
    /// report sizes cheaply. Used by the index rebuild; a `None` or `0` simply
    /// records an unknown size.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if existence cannot be determined.
    async fn size(&self, key: &str) -> Result<u64>;

    /// Human-readable name of where this backend points (a directory, a host,
    /// a bucket), for error messages.
    fn location(&self) -> std::path::PathBuf;
}

/// A [`Backend`] backed by a directory on the local filesystem.
#[derive(Debug, Clone)]
pub struct LocalBackend {
    root: PathBuf,
}

impl LocalBackend {
    /// Create a backend rooted at `root`. The directory is created on first write.
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    /// The directory this backend writes into.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn resolve(&self, key: &str) -> PathBuf {
        // Keys are generated internally and always `/`-separated; splitting keeps
        // the layout identical on Windows.
        key.split('/').fold(self.root.clone(), |p, seg| p.join(seg))
    }
}

#[async_trait::async_trait]
impl Backend for LocalBackend {
    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let path = self.resolve(key);
        tokio::fs::read(&path).await.map_err(|e| Error::io(path, e))
    }

    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        let path = self.resolve(key);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| Error::io(parent, e))?;
        }
        // Write to a unique temporary sibling, then rename: a crash mid-write
        // leaves the temp file behind rather than a truncated blob that would
        // pass an existence check and corrupt every snapshot referencing it.
        let tmp = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&tmp, data)
            .await
            .map_err(|e| Error::io(&tmp, e))?;
        match tokio::fs::rename(&tmp, &path).await {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                Err(Error::io(path, e))
            }
        }
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        match tokio::fs::metadata(self.resolve(key)).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::io(self.resolve(key), e)),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let base = self.resolve(prefix);
        let mut out = Vec::new();
        let mut stack = vec![(base, prefix.trim_end_matches('/').to_string())];

        while let Some((dir, key_prefix)) = stack.pop() {
            let mut entries = match tokio::fs::read_dir(&dir).await {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(Error::io(&dir, e)),
            };
            while let Some(entry) = entries.next_entry().await.map_err(|e| Error::io(&dir, e))? {
                let name = entry.file_name().to_string_lossy().into_owned();
                let key = if key_prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{key_prefix}/{name}")
                };
                let ft = entry
                    .file_type()
                    .await
                    .map_err(|e| Error::io(entry.path(), e))?;
                if ft.is_dir() {
                    stack.push((entry.path(), key));
                } else {
                    out.push(key);
                }
            }
        }
        Ok(out)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.resolve(key);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::io(path, e)),
        }
    }

    async fn size(&self, key: &str) -> Result<u64> {
        let path = self.resolve(key);
        tokio::fs::metadata(&path)
            .await
            .map(|m| m.len())
            .map_err(|e| Error::io(path, e))
    }

    fn location(&self) -> std::path::PathBuf {
        self.root.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrips_nested_keys() {
        let dir = tempfile::tempdir().unwrap();
        let b = LocalBackend::new(dir.path());

        assert!(!b.exists("blobs/ab/abcd").await.unwrap());
        b.put("blobs/ab/abcd", b"hello").await.unwrap();
        assert!(b.exists("blobs/ab/abcd").await.unwrap());
        assert_eq!(b.get("blobs/ab/abcd").await.unwrap(), b"hello");

        b.put("blobs/cd/cdef", b"world").await.unwrap();
        let mut keys = b.list("blobs").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["blobs/ab/abcd", "blobs/cd/cdef"]);

        b.delete("blobs/ab/abcd").await.unwrap();
        assert!(!b.exists("blobs/ab/abcd").await.unwrap());
        // Deleting a missing key is not an error.
        b.delete("blobs/ab/abcd").await.unwrap();
    }

    #[tokio::test]
    async fn put_replaces_and_list_of_missing_prefix_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let b = LocalBackend::new(dir.path());

        assert!(b.list("snapshots").await.unwrap().is_empty());
        b.put("config", b"one").await.unwrap();
        b.put("config", b"two").await.unwrap();
        assert_eq!(b.get("config").await.unwrap(), b"two");
    }

    #[tokio::test]
    async fn get_of_missing_key_errors() {
        let dir = tempfile::tempdir().unwrap();
        let b = LocalBackend::new(dir.path());
        assert!(b.get("nope").await.is_err());
    }
}
