//! Content-defined chunking (FastCDC) and content addressing (BLAKE3).
//!
//! Splitting on content-defined boundaries rather than fixed offsets is what
//! makes deduplication survive edits: inserting a byte near the start of a file
//! shifts only the chunk containing it, leaving every downstream boundary — and
//! therefore every downstream chunk hash — untouched.

use std::io::Read;

use crate::error::{Error, Result};

/// Default minimum chunk size (512 KiB), per `docs/03-repository-format.md`.
pub const DEFAULT_MIN_SIZE: usize = 512 * 1024;
/// Default average chunk size (1 MiB). FastCDC targets this as the expected size.
pub const DEFAULT_AVG_SIZE: usize = 1024 * 1024;
/// Default maximum chunk size (8 MiB), per `docs/03-repository-format.md`.
pub const DEFAULT_MAX_SIZE: usize = 8 * 1024 * 1024;

/// FastCDC chunk size parameters for a repository.
///
/// These are recorded in the repository `config` at `init` time and must not
/// change afterwards: different parameters produce different chunk boundaries,
/// which would silently defeat deduplication against existing snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChunkerConfig {
    /// Smallest chunk the chunker will emit, in bytes.
    pub min_size: usize,
    /// Target average chunk size, in bytes.
    pub avg_size: usize,
    /// Largest chunk the chunker will emit, in bytes.
    pub max_size: usize,
}

impl Default for ChunkerConfig {
    fn default() -> Self {
        Self {
            min_size: DEFAULT_MIN_SIZE,
            avg_size: DEFAULT_AVG_SIZE,
            max_size: DEFAULT_MAX_SIZE,
        }
    }
}

impl ChunkerConfig {
    /// Build a configuration from explicit sizes.
    ///
    /// Tests and small-file workloads need sizes far below the defaults; this is
    /// the supported way to get them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidChunkerConfig`] unless
    /// `0 < min_size <= avg_size <= max_size` and the sizes fall inside the
    /// bounds the `fastcdc` crate accepts (64 B – 1 GiB).
    pub fn new(min_size: usize, avg_size: usize, max_size: usize) -> Result<Self> {
        let cfg = Self {
            min_size,
            avg_size,
            max_size,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Check the size invariants FastCDC requires.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidChunkerConfig`] describing the first violation found.
    pub fn validate(&self) -> Result<()> {
        // Bounds mirror the `fastcdc::v2020` constructor, which panics outside them.
        const FLOOR: usize = 64;
        const CEIL: usize = 1024 * 1024 * 1024;

        let invalid = |msg: String| Err(Error::InvalidChunkerConfig(msg));
        if self.min_size < FLOOR || self.max_size > CEIL {
            return invalid(format!(
                "sizes must lie within {FLOOR}..={CEIL} bytes, got {}..={}",
                self.min_size, self.max_size
            ));
        }
        if !(self.min_size <= self.avg_size && self.avg_size <= self.max_size) {
            return invalid(format!(
                "expected min <= avg <= max, got {} / {} / {}",
                self.min_size, self.avg_size, self.max_size
            ));
        }
        Ok(())
    }
}

/// A BLAKE3 content hash, used as the identity of a blob in the repository.
pub type ChunkHash = blake3::Hash;

/// One content-defined chunk of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// BLAKE3 hash of the chunk's bytes — its address in the repository.
    pub hash: ChunkHash,
    /// Byte offset of the chunk within the source stream.
    pub offset: u64,
    /// Length of the chunk in bytes.
    pub length: usize,
}

/// Split `data` into content-defined chunks and hash each one.
///
/// # Errors
///
/// Returns [`Error::InvalidChunkerConfig`] if `config` violates FastCDC's invariants.
pub fn chunk_bytes(data: &[u8], config: &ChunkerConfig) -> Result<Vec<Chunk>> {
    config.validate()?;
    let chunker =
        fastcdc::v2020::FastCDC::new(data, config.min_size, config.avg_size, config.max_size);
    Ok(chunker
        .map(|c| Chunk {
            hash: blake3::hash(&data[c.offset..c.offset + c.length]),
            offset: c.offset as u64,
            length: c.length,
        })
        .collect())
}

/// Split a reader into content-defined chunks, invoking `sink` with each chunk
/// and its bytes as they are produced.
///
/// Streaming keeps peak memory bounded by `max_size` rather than by file size,
/// which is what lets Aegis back up files larger than RAM.
///
/// # Errors
///
/// Returns [`Error::InvalidChunkerConfig`] for a bad `config`, [`Error::Io`] if
/// `reader` fails, or whatever error `sink` returns.
pub fn chunk_stream<R, F>(reader: R, config: &ChunkerConfig, mut sink: F) -> Result<()>
where
    R: Read,
    F: FnMut(&Chunk, &[u8]) -> Result<()>,
{
    config.validate()?;
    let chunker =
        fastcdc::v2020::StreamCDC::new(reader, config.min_size, config.avg_size, config.max_size);
    for result in chunker {
        let c = result.map_err(|e| match e {
            fastcdc::v2020::Error::IoError(source) => Error::io("<stream>", source),
            other => Error::io("<stream>", std::io::Error::other(other.to_string())),
        })?;
        let chunk = Chunk {
            hash: blake3::hash(&c.data),
            offset: c.offset,
            length: c.length,
        };
        sink(&chunk, &c.data)?;
    }
    Ok(())
}

/// Split an [`tokio::io::AsyncRead`] stream into content-defined chunks,
/// invoking `sink` with each chunk and its bytes as they are produced.
///
/// The async twin of [`chunk_stream`]: same boundaries, same hashes, same
/// bounded-memory guarantees, but the source can be a network stream (the
/// SFTP file handle of an agentless backup).
///
/// # Errors
///
/// Returns [`Error::InvalidChunkerConfig`] for a bad `config`, [`Error::Io`] if
/// `reader` fails, or whatever error `sink` returns.
pub async fn chunk_async_stream<R, F>(
    mut reader: R,
    config: &ChunkerConfig,
    mut sink: F,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    F: FnMut(&Chunk, &[u8]) -> Result<()>,
{
    config.validate()?;
    let mut chunker = fastcdc::v2020::AsyncStreamCDC::new(
        &mut reader,
        config.min_size,
        config.avg_size,
        config.max_size,
    );
    use tokio_stream::StreamExt;
    let mut stream = std::pin::pin!(chunker.as_stream());
    while let Some(item) = stream.next().await {
        let c = item.map_err(|e| match e {
            fastcdc::v2020::Error::IoError(source) => Error::io("<stream>", source),
            other => Error::io("<stream>", std::io::Error::other(other.to_string())),
        })?;
        let chunk = Chunk {
            hash: blake3::hash(&c.data),
            offset: c.offset,
            length: c.length,
        };
        sink(&chunk, &c.data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes; chunking constant data yields only
    /// max-size chunks and would not exercise boundary detection.
    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn test_config() -> ChunkerConfig {
        ChunkerConfig::new(1024, 4096, 16384).unwrap()
    }

    #[test]
    fn rejects_invalid_configs() {
        // avg below min
        assert!(ChunkerConfig::new(8192, 1024, 16384).is_err());
        // max below avg
        assert!(ChunkerConfig::new(1024, 8192, 4096).is_err());
        // below the crate's floor
        assert!(ChunkerConfig::new(1, 2, 3).is_err());
    }

    #[test]
    fn chunking_is_deterministic() {
        let data = pseudo_random(512 * 1024, 42);
        let cfg = test_config();
        assert_eq!(
            chunk_bytes(&data, &cfg).unwrap(),
            chunk_bytes(&data, &cfg).unwrap()
        );
    }

    #[test]
    fn chunks_respect_size_bounds_and_cover_the_input() {
        let data = pseudo_random(512 * 1024, 7);
        let cfg = test_config();
        let chunks = chunk_bytes(&data, &cfg).unwrap();

        assert!(chunks.len() > 1, "expected the input to split");
        let mut expected_offset = 0u64;
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(c.offset, expected_offset, "chunks must be contiguous");
            assert!(c.length <= cfg.max_size, "chunk exceeds max_size");
            // Only the final chunk may be shorter than min_size (it is the remainder).
            if i + 1 < chunks.len() {
                assert!(c.length >= cfg.min_size, "chunk below min_size");
            }
            expected_offset += c.length as u64;
        }
        assert_eq!(
            expected_offset,
            data.len() as u64,
            "chunks must cover the input"
        );
    }

    #[test]
    fn reassembling_chunks_reproduces_the_input() {
        let data = pseudo_random(256 * 1024, 99);
        let cfg = test_config();
        let mut rebuilt = Vec::new();
        for c in chunk_bytes(&data, &cfg).unwrap() {
            let bytes = &data[c.offset as usize..c.offset as usize + c.length];
            assert_eq!(
                blake3::hash(bytes),
                c.hash,
                "chunk hash must match its bytes"
            );
            rebuilt.extend_from_slice(bytes);
        }
        assert_eq!(rebuilt, data);
    }

    /// The property that makes deduplication real: an insertion near the start
    /// must not invalidate the chunks after it.
    #[test]
    fn insertion_shifts_only_nearby_boundaries() {
        let cfg = test_config();
        let original = pseudo_random(512 * 1024, 3);

        let mut edited = Vec::with_capacity(original.len() + 5);
        edited.extend_from_slice(&original[..2000]);
        edited.extend_from_slice(b"HELLO");
        edited.extend_from_slice(&original[2000..]);

        let before: Vec<_> = chunk_bytes(&original, &cfg).unwrap();
        let after: Vec<_> = chunk_bytes(&edited, &cfg).unwrap();

        let shared: std::collections::HashSet<_> = before.iter().map(|c| c.hash).collect();
        let reused = after.iter().filter(|c| shared.contains(&c.hash)).count();

        // With fixed-size chunking this would be ~0. Content-defined chunking
        // should recover essentially everything after the edited region.
        assert!(
            reused * 10 >= after.len() * 8,
            "expected >=80% chunk reuse after a 5-byte insertion, got {reused}/{}",
            after.len()
        );
    }

    #[test]
    fn stream_and_slice_chunkers_agree() {
        let data = pseudo_random(512 * 1024, 11);
        let cfg = test_config();

        let mut streamed = Vec::new();
        chunk_stream(std::io::Cursor::new(&data), &cfg, |c, bytes| {
            assert_eq!(blake3::hash(bytes), c.hash);
            streamed.push(c.clone());
            Ok(())
        })
        .unwrap();

        assert_eq!(streamed, chunk_bytes(&data, &cfg).unwrap());
    }
}
