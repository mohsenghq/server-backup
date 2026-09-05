//! The blob envelope: a self-describing container for every object stored
//! under `blobs/`.
//!
//! Layout: `[4-byte magic "AE1"][u8 flags][payload]`.
//!
//! The flags byte records how the payload was produced, so old repositories
//! stay readable as the pipeline grows (compression now, encryption next) and
//! a corrupted or foreign blob fails loudly instead of decoding to garbage.
//! The envelope also carries the blob's *decoded* BLAKE3 hash as part of the
//! encryption AAD later — here it just makes the format extensible.

use crate::error::{Error, Result};

/// Envelope magic: `A` `E` `1` followed by the format's flags byte in every
/// stored blob. The trailing `1` is the envelope version, so a future format
/// change can bump it and every old reader rejects new blobs explicitly.
pub const MAGIC: [u8; 4] = *b"AE1\x01";

/// How a blob's payload was produced before storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(pub u8);

impl Flags {
    /// Payload is stored exactly as produced (no transform). Bit 0.
    pub const PLAIN: u8 = 0b0000_0001;
    /// Payload is zstd-compressed. Bit 1. (Encryption will add its own bit
    /// and compose with these.)
    pub const ZSTD: u8 = 0b0000_0010;

    /// Flags for a payload that was compressed.
    pub const fn compressed() -> Self {
        Self(Self::ZSTD)
    }

    /// Flags for a payload stored as-is.
    pub const fn plain() -> Self {
        Self(Self::PLAIN)
    }

    /// Exactly one storage bit must be set.
    fn valid(self) -> bool {
        let f = self.0;
        f == Self::PLAIN || f == Self::ZSTD
    }

    fn is_zstd(self) -> bool {
        self.0 & Self::ZSTD != 0
    }
}

/// Wrap `payload` in the envelope.
pub fn wrap(flags: Flags, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + 1 + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(flags.0);
    out.extend_from_slice(payload);
    out
}

/// Parse the envelope header off `blob` and return `(flags, payload)`.
///
/// # Errors
///
/// Returns [`Error::MalformedBlob`] for wrong magic/version or a flags byte
/// this build does not understand.
pub fn unwrap(blob: &[u8]) -> Result<(Flags, &[u8])> {
    if blob.len() < MAGIC.len() + 1 {
        return Err(Error::MalformedBlob(
            "blob shorter than envelope header".into(),
        ));
    }
    let (magic, rest) = blob.split_at(MAGIC.len());
    if magic != MAGIC {
        return Err(Error::MalformedBlob(format!(
            "bad blob magic {magic:02x?} (expected {MAGIC:02x?})"
        )));
    }
    let flags = Flags(rest[0]);
    if !flags.valid() {
        return Err(Error::MalformedBlob(format!(
            "unknown blob flags {:#010b}",
            flags.0
        )));
    }
    Ok((flags, &rest[1..]))
}

/// zstd compression level chosen for one blob.
///
/// "Adaptive" by content: a quick entropy probe on the payload decides
/// between a fast level (data that will not compress — binaries, already
/// compressed media — spends CPU for nothing) and a normal level for
/// everything else. This stays O(n) and cheap; per-blob level tuning beyond
/// this is a Phase 7 hardening nicety, not a Phase 1 requirement.
pub fn choose_level(payload: &[u8]) -> i32 {
    if payload.len() < 1024 {
        // Small payloads: compression overhead dwarfs the win either way.
        return 1;
    }
    // Sample up to 8 KiB spread over the payload and count unique bytes.
    // High-entropy data (>~200 distinct byte values in the sample) is treated
    // as incompressible.
    let sample_len = payload.len().min(8 * 1024);
    let step = payload.len() / sample_len;
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    let mut i = 0;
    while i < payload.len() {
        let b = payload[i] as usize;
        if !seen[b] {
            seen[b] = true;
            distinct += 1;
            if distinct > 200 {
                return 1;
            }
        }
        i += step.max(1);
    }
    9
}

/// Compress and wrap a payload for storage.
pub fn encode(payload: &[u8]) -> Vec<u8> {
    let level = choose_level(payload);
    if level <= 1 {
        // Not worth trying: store plain.
        return wrap(Flags::plain(), payload);
    }
    let compressed = zstd::stream::encode_all(payload, level);
    match compressed {
        Ok(c) if c.len() < payload.len() => wrap(Flags::compressed(), &c),
        // Compression did not help (or failed): plain is always valid.
        _ => wrap(Flags::plain(), payload),
    }
}

/// Undo [`encode`]: parse the envelope and decompress if needed.
///
/// # Errors
///
/// Returns [`Error::MalformedBlob`] for envelope problems and
/// [`Error::DecompressFailed`] if the zstd stream is corrupt.
pub fn decode(blob: &[u8]) -> Result<Vec<u8>> {
    let (flags, payload) = unwrap(blob)?;
    if flags.is_zstd() {
        zstd::stream::decode_all(payload).map_err(|e| Error::DecompressFailed(e.to_string()))
    } else {
        Ok(payload.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_compressed_and_plain() {
        let repetitive = b"aaaaaaaaaa".repeat(1000);
        let blob = encode(&repetitive);
        let (flags, _) = unwrap(&blob).unwrap();
        assert_eq!(flags, Flags::compressed());
        assert!(
            blob.len() < repetitive.len() / 10,
            "repetitive data must compress hard"
        );
        assert_eq!(decode(&blob).unwrap(), repetitive);

        let tiny = b"hi";
        let blob = encode(tiny);
        let (flags, _) = unwrap(&blob).unwrap();
        assert_eq!(flags, Flags::plain());
        assert_eq!(decode(&blob).unwrap(), tiny);
    }

    #[test]
    fn incompressible_data_is_stored_plain() {
        let mut state = 0x9e3779b9u64;
        let random: Vec<u8> = (0..64 * 1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect();
        let blob = encode(&random);
        let (flags, _) = unwrap(&blob).unwrap();
        assert_eq!(
            flags,
            Flags::plain(),
            "high-entropy data must not be compressed"
        );
        assert_eq!(decode(&blob).unwrap(), random);
    }

    #[test]
    fn unwrap_rejects_garbage_and_unknown_flags() {
        assert!(unwrap(b"short").is_err());
        assert!(unwrap(b"NOTAEGIS-anything").is_err());

        let mut blob = wrap(Flags::plain(), b"x");
        *blob.last_mut().unwrap() = 0xff; // corrupt the flags byte
        blob[4] = 0b1111_1111;
        assert!(unwrap(&blob).is_err());
    }

    #[test]
    fn decode_rejects_corrupt_zstd_stream() {
        let repetitive = b"bbbbbbbb".repeat(500);
        let mut blob = encode(&repetitive);
        let last = blob.len() - 1;
        blob[last] ^= 0xff; // flip bits in the compressed payload
        assert!(decode(&blob).is_err());
    }

    #[test]
    fn magic_is_version_tagged() {
        assert_eq!(&MAGIC, b"AE1\x01");
    }
}
