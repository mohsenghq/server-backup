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
    /// Payload is zstd-compressed. Bit 1. Composes with [`Flags::ENC`].
    pub const ZSTD: u8 = 0b0000_0010;
    /// Payload is encrypted (nonce‖ciphertext‖tag). Bit 2.
    pub const ENC: u8 = 0b0000_0100;

    /// Flags for a payload that was compressed.
    pub const fn compressed() -> Self {
        Self(Self::ZSTD)
    }

    /// Flags for a payload stored as-is.
    pub const fn plain() -> Self {
        Self(Self::PLAIN)
    }

    /// Exactly one storage bit (PLAIN or ZSTD) must be set; ENC may compose
    /// with either.
    fn valid(self) -> bool {
        let f = self.0;
        let storage = f & !Self::ENC;
        storage == Self::PLAIN || storage == Self::ZSTD
    }

    #[allow(dead_code)]
    fn is_enc(self) -> bool {
        self.0 & Self::ENC != 0
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

/// Compress (if it helps) and wrap a plaintext payload for storage.
pub fn encode(payload: &[u8]) -> Vec<u8> {
    let (flags, payload) = compress_payload(payload);
    wrap(flags, &payload)
}

/// Compress-if-helpful shared by the plain and encrypted encode paths.
fn compress_payload(payload: &[u8]) -> (Flags, Vec<u8>) {
    let level = choose_level(payload);
    if level <= 1 {
        return (Flags::plain(), payload.to_vec());
    }
    match zstd::stream::encode_all(payload, level) {
        Ok(c) if c.len() < payload.len() => (Flags::compressed(), c),
        _ => (Flags::plain(), payload.to_vec()),
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
    decompress_payload(flags, payload)
}

fn decompress_payload(flags: Flags, payload: &[u8]) -> Result<Vec<u8>> {
    if flags.0 & Flags::ZSTD != 0 {
        zstd::stream::decode_all(payload).map_err(|e| Error::DecompressFailed(e.to_string()))
    } else {
        Ok(payload.to_vec())
    }
}

/// Encrypt-then-wrap: compress first (compression on ciphertext is
/// useless), then seal under `crypto` for `context`, then envelope.
///
/// # Errors
///
/// Returns whatever [`crate::keys::RepoCrypto::seal`] returns.
pub fn encrypt_and_encode(
    crypto: &crate::keys::RepoCrypto,
    context: &crate::keys::AeadContext,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let (cflags, compressed) = compress_payload(payload);
    let sealed = crypto.seal(context, &compressed)?;
    let flags = cflags.0 | Flags::ENC;
    Ok(wrap(Flags(flags), &sealed))
}

/// Undo [`encrypt_and_encode`]: envelope → authenticate+decrypt → decompress.
///
/// # Errors
///
/// Returns [`Error::MalformedBlob`] for envelope problems,
/// [`Error::DecryptFailed`] for wrong-key or tampered data, and
/// [`Error::DecompressFailed`] for a corrupt zstd stream.
pub fn decrypt_and_decode(
    crypto: &crate::keys::RepoCrypto,
    context: &crate::keys::AeadContext,
    blob: &[u8],
) -> Result<Vec<u8>> {
    let (flags, payload) = unwrap(blob)?;
    if flags.0 & Flags::ENC == 0 {
        return Err(Error::MalformedBlob(
            "blob is not encrypted but this repository requires encryption".into(),
        ));
    }
    let plaintext = crypto.open(context, payload)?;
    decompress_payload(Flags(flags.0 & !Flags::ENC), &plaintext)
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

    #[test]
    fn encrypt_round_trip_and_tamper_rejection() {
        use crate::keys::{AeadContext, PassphraseSource, RepoCrypto};
        // A deterministic-passphrase crypto instance via the real unwrap path.
        let master = crate::crypto::generate_master_key();
        let (crypto, _) = RepoCrypto::new_wrapped(
            "t",
            &master,
            "p",
            &crate::crypto::KdfParams {
                memory_kib: 8 * 1024,
                iterations: 1,
                parallelism: 1,
            },
        )
        .unwrap();
        let ctx = AeadContext::Hash(&"ab".repeat(32));

        let payload = b"secret backup data ".repeat(50);
        let blob = encrypt_and_encode(&crypto, &ctx, &payload).unwrap();
        let (flags, _) = unwrap(&blob).unwrap();
        assert!(flags.0 & Flags::ENC != 0, "encrypted blobs must set ENC");
        assert_eq!(decrypt_and_decode(&crypto, &ctx, &blob).unwrap(), payload);

        // Tampering anywhere in the ciphertext breaks authentication.
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(decrypt_and_decode(&crypto, &ctx, &bad).is_err());

        // A different address context must fail too.
        let other = AeadContext::Hash(&"cd".repeat(32));
        assert!(decrypt_and_decode(&crypto, &other, &blob).is_err());

        // Plain-encoded blobs are rejected in encrypted repos.
        let plain = encode(&payload);
        assert!(decrypt_and_decode(&crypto, &ctx, &plain).is_err());

        // Silence unused-import warnings from the test-only import.
        let _ = PassphraseSource::Env;
    }
}
