//! Encryption at rest: Argon2id key derivation and XChaCha20-Poly1305 AEAD
//! (`docs/03-repository-format.md`, `docs/10-security-model.md`).
//!
//! Model:
//!
//! - A random 32-byte **master key** is generated at `aegis init` and never
//!   leaves the client. It encrypts every blob and the repo `config`.
//! - The master key is **wrapped** (encrypted) with a key derived from the
//!   operator passphrase via Argon2id and stored in `keys/`, so the passphrase
//!   can be rotated later without re-encrypting any data.
//! - Every blob is sealed with a fresh random 24-byte XChaCha20 nonce; the
//!   ciphertext (nonce ‖ AEAD output) is what the backend stores. The storage
//!   backend never sees plaintext.
//! - AAD binds each ciphertext to its repo and purpose, so a blob cannot be
//!   swapped between repositories or between config and data roles.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::Aead, AeadCore, KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Size of the master key in bytes (256-bit).
pub const KEY_LEN: usize = 32;
/// Size of an XChaCha20 nonce in bytes (192-bit, random per seal).
pub const NONCE_LEN: usize = 24;
/// Argon2id salt length in bytes.
pub const SALT_LEN: usize = 16;

/// Purpose/domain string bound into the AEAD as associated data, so a
/// ciphertext produced for one role cannot be replayed in another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aad<'a> {
    /// A data or tree blob identified by its hex plaintext hash.
    Blob(&'a str),
    /// The repository `config` document.
    Config,
    /// A wrapped master key in `keys/`.
    WrappedKey,
}

impl Aad<'_> {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Aad::Blob(hex) => format!("aegis:blob:{hex}").into_bytes(),
            Aad::Config => b"aegis:config".to_vec(),
            Aad::WrappedKey => b"aegis:wrapped-key".to_vec(),
        }
    }
}

/// A 32-byte symmetric key. Zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// Generate a fresh random key (used for the repo master key).
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// View the raw bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error::Crypto("key must be 32 bytes".into()))?;
        Ok(Self(arr))
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        write!(f, "Key(..)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// AEAD parameters recorded next to wrapped keys so old repositories stay
/// readable if the defaults ever change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Argon2 memory cost in KiB.
    pub m_cost_kib: u32,
    /// Argon2 time cost (iterations).
    pub t_cost: u32,
    /// Argon2 parallelism.
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // Argon2 RFC recommendation territory: 64 MiB, 3 passes. Deliberately
        // interactive-but-affordable for a CLI run on a small server.
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// Derive a key-encryption key from a passphrase and salt via Argon2id.
///
/// # Errors
///
/// Returns [`Error::Crypto`] if Argon2id rejects the parameters.
pub fn derive_kdf_key(passphrase: &str, salt: &[u8], params: &KdfParams) -> Result<Key> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.m_cost_kib,
            params.t_cost,
            params.p_cost,
            Some(KEY_LEN),
        )
        .map_err(|e| Error::Crypto(format!("bad KDF params: {e}")))?,
    );
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| Error::Crypto(format!("argon2id failed: {e}")))?;
    Ok(Key(out))
}

/// Seal `plaintext` with XChaCha20-Poly1305 under `key`, binding `aad`.
/// Returns `nonce ‖ ciphertext+tag`, ready for backend storage.
///
/// # Errors
///
/// Returns [`Error::Crypto`] if the AEAD operation fails (practically only on
/// RNG failure).
pub fn seal(key: &Key, plaintext: &[u8], aad: Aad<'_>) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.0.as_ref().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand::rngs::OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad.bytes(),
            },
        )
        .map_err(|e| Error::Crypto(format!("seal failed: {e}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a `nonce ‖ ciphertext+tag` blob produced by [`seal`].
///
/// # Errors
///
/// Returns [`Error::DecryptionFailed`] for a wrong key, wrong AAD, or any
/// tampering; [`Error::Crypto`] for a structurally invalid payload.
pub fn open(key: &Key, sealed: &[u8], aad: Aad<'_>) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + 16 {
        return Err(Error::Crypto("sealed payload too short".into()));
    }
    let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.0.as_ref().into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce_bytes),
            chacha20poly1305::aead::Payload {
                msg: ct,
                aad: &aad.bytes(),
            },
        )
        .map_err(|_| Error::DecryptionFailed)
}

/// A wrapped master key stored as `keys/<keyid>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// Short identifier of this key file (also its filename stem).
    pub key_id: String,
    /// The KDF parameters used for *this* wrapping; recorded per key so
    /// parameters can be strengthened at rotation time without breaking old
    /// key files.
    pub kdf: KdfParams,
    /// Hex Argon2id salt.
    pub salt: String,
    /// Hex `nonce ‖ master key ciphertext` under the passphrase-derived KEK.
    pub wrapped: String,
}

impl WrappedKey {
    /// Wrap a fresh or existing master key under `passphrase`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] on KDF/AEAD failure.
    pub fn create(master: &Key, passphrase: &str) -> Result<Self> {
        let params = KdfParams::default();
        let mut salt = [0u8; SALT_LEN];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let kek = derive_kdf_key(passphrase, &salt, &params)?;
        let sealed = seal(&kek, master.as_bytes(), Aad::WrappedKey)?;
        Ok(Self {
            key_id: uuid::Uuid::new_v4().simple().to_string()[..12].to_string(),
            kdf: params,
            salt: hex_encode(&salt),
            wrapped: hex_encode(&sealed),
        })
    }

    /// Unwrap the master key using `passphrase`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DecryptionFailed`] for a wrong passphrase or a
    /// tampered key file, [`Error::Crypto`] for malformed fields.
    pub fn unwrap_key(&self, passphrase: &str) -> Result<Key> {
        let salt = hex_decode(&self.salt)?;
        let sealed = hex_decode(&self.wrapped)?;
        let kek = derive_kdf_key(passphrase, &salt, &self.kdf)?;
        let bytes = open(&kek, &sealed, Aad::WrappedKey)?;
        Key::from_slice(&bytes)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Crypto(format!("bad hex field: {s:?}")));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| Error::Crypto(e.to_string())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = Key::generate();
        let sealed = seal(&key, b"hello aegis", Aad::Config).unwrap();
        assert_eq!(open(&key, &sealed, Aad::Config).unwrap(), b"hello aegis");
    }

    #[test]
    fn wrong_aad_or_key_fails() {
        let key = Key::generate();
        let sealed = seal(&key, b"secret", Aad::Config).unwrap();
        assert!(open(&key, &sealed, Aad::WrappedKey).is_err());
        assert!(open(&Key::generate(), &sealed, Aad::Config).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = Key::generate();
        let mut sealed = seal(&key, b"secret", Aad::Config).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open(&key, &sealed, Aad::Config).is_err());
    }

    #[test]
    fn nonces_are_fresh_per_seal() {
        let key = Key::generate();
        let a = seal(&key, b"x", Aad::Config).unwrap();
        let b = seal(&key, b"x", Aad::Config).unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }

    #[test]
    fn wrapped_key_roundtrip_and_wrong_passphrase() {
        let master = Key::generate();
        let wrapped = WrappedKey::create(&master, "correct horse").unwrap();
        let unwrapped = wrapped.unwrap_key("correct horse").unwrap();
        assert_eq!(unwrapped.as_bytes(), master.as_bytes());
        assert!(wrapped.unwrap_key("battery staple").is_err());
    }

    #[test]
    fn kdf_is_deterministic_per_salt() {
        let params = KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let a = derive_kdf_key("pw", b"0123456789abcdef", &params).unwrap();
        let b = derive_kdf_key("pw", b"0123456789abcdef", &params).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        let c = derive_kdf_key("pw2", b"0123456789abcdef", &params).unwrap();
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn key_debug_does_not_leak_material() {
        let key = Key::generate();
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "Key(..)");
        assert!(!rendered.contains(&format!("{:02x}", key.as_bytes()[0])));
    }
}
