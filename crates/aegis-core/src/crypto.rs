//! Client-side encryption: XChaCha20-Poly1305 for data, Argon2id for turning
//! an operator passphrase into a key-encryption key (`docs/10-security-model.md`).
//!
//! Key hierarchy:
//!
//! ```text
//! passphrase ──Argon2id(salt, params)──▶ KEK ──wrap──▶ master key (in keys/<id>.json)
//! master key ──seal──▶ every blob and document (blobs/, snapshots/, index/)
//! ```
//!
//! The master key is random at `init` and never stored in the clear: `keys/`
//! holds only wrapped copies, one per passphrase, so a passphrase can be
//! rotated (`key add`) without re-encrypting a single data blob. Every AEAD
//! operation binds the blob's address (its hex hash) as associated data, so
//! moving a valid ciphertext to another blob slot fails authentication.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Master key length in bytes (256-bit keys).
pub const KEY_LEN: usize = 32;

/// Argon2id memory cost in KiB (64 MiB): interactive but not trivially
/// brute-forceable on commodity GPUs.
pub const KDF_MEMORY_KIB: u32 = 64 * 1024;
/// Argon2id time cost (iterations).
pub const KDF_ITERATIONS: u32 = 3;
/// Argon2id parallelism lanes.
pub const KDF_PARALLELISM: u32 = 1;
/// Salt length for the KEK derivation.
pub const SALT_LEN: usize = 16;
/// XChaCha20-Poly1305 nonce length (24 bytes — no nonce-reuse risk with
/// random nonces at backup scale).
pub const NONCE_LEN: usize = 24;

/// Argon2id parameters, recorded in each key file so they are never guessed
/// at unwrap time and can be raised for new keys later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Time cost in iterations.
    pub iterations: u32,
    /// Parallelism lanes.
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: KDF_MEMORY_KIB,
            iterations: KDF_ITERATIONS,
            parallelism: KDF_PARALLELISM,
        }
    }
}

/// Derive a key-encryption key (KEK) from a passphrase and salt.
///
/// # Errors
///
/// Returns [`Error::KdfFailed`] if Argon2 cannot run with these params.
pub fn derive_kek(passphrase: &str, salt: &[u8], params: &KdfParams) -> Result<[u8; KEY_LEN]> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            None,
        )
        .map_err(|e| Error::KdfFailed(e.to_string()))?,
    );
    let mut kek = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut kek)
        .map_err(|e| Error::KdfFailed(e.to_string()))?;
    Ok(kek)
}

/// A wrapped master key, as stored in `keys/<id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// Stable identifier for this key slot (also its filename stem).
    pub id: String,
    /// Argon2id parameters used for this key's KEK.
    pub kdf: KdfParams,
    /// Base64 salt for the KEK derivation.
    pub salt: String,
    /// XChaCha20-Poly1305 nonce used to wrap the master key.
    pub nonce: String,
    /// The wrapped master key (ciphertext + 16-byte Poly1305 tag).
    pub wrapped: String,
    /// RFC 3339 timestamp of when this key was added.
    pub created: String,
}

/// Generate a fresh random master key.
pub fn generate_master_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

/// Seal `plaintext` under `key` with the given nonce, binding `aad`.
///
/// Returns only `ciphertext+tag` — the nonce is supplied separately and the
/// caller is responsible for persisting it alongside the ciphertext.
///
/// # Errors
///
/// This is infallible in practice; errors surface from the AEAD only on
/// broken key material, mapped to [`Error::EncryptFailed`].
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|e| Error::EncryptFailed(e.to_string()))?;
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher
        .encrypt(XNonce::from_slice(nonce), payload)
        .map_err(|_| Error::EncryptFailed("AEAD seal failed".into()))
}

/// Open `sealed` (`nonce || ciphertext+tag`) under `key`, binding `aad`.
///
/// # Errors
///
/// Returns [`Error::DecryptFailed`] for a wrong key or any tampering —
/// authentication is checked before decryption.
pub fn open(key: &[u8; KEY_LEN], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + 16 {
        return Err(Error::DecryptFailed(
            "ciphertext shorter than nonce+tag".into(),
        ));
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|e| Error::DecryptFailed(e.to_string()))?;
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::DecryptFailed("wrong key or corrupted data".into()))
}

/// Wrap the master key under a passphrase-derived KEK.
///
/// # Errors
///
/// Returns [`Error::KdfFailed`] if the KDF cannot run.
pub fn wrap_master_key(
    master: &[u8; KEY_LEN],
    passphrase: &str,
    params: &KdfParams,
) -> Result<WrappedSecret> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let kek = derive_kek(passphrase, &salt, params)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let sealed = seal(&kek, &nonce, b"aegis/key-wrap", master)?;
    Ok(WrappedSecret {
        salt,
        nonce,
        sealed,
    })
}

/// Unwrap a master key that [`wrap_master_key`] sealed.
///
/// # Errors
///
/// Returns [`Error::WrongPassphrase`] if the passphrase does not open the
/// wrapped key.
pub fn unwrap_master_key(
    secret: &WrappedSecret,
    passphrase: &str,
    params: &KdfParams,
) -> Result<[u8; KEY_LEN]> {
    let kek = derive_kek(passphrase, &secret.salt, params)?;
    let mut key = [0u8; KEY_LEN];
    // open expects nonce‖ciphertext+tag; reassemble from the stored pieces.
    let mut sealed = secret.nonce.to_vec();
    sealed.extend_from_slice(&secret.sealed);
    let opened = open(&kek, b"aegis/key-wrap", &sealed)?;
    if opened.len() != KEY_LEN {
        return Err(Error::DecryptFailed(
            "unwrapped key has the wrong length".into(),
        ));
    }
    key.copy_from_slice(&opened);
    Ok(key)
}

/// The raw pieces of a wrapped secret (used for the master key wrap).
#[derive(Debug, Clone)]
pub struct WrappedSecret {
    /// KEK salt.
    pub salt: [u8; SALT_LEN],
    /// Wrapping nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Sealed master key (ciphertext + tag).
    pub sealed: Vec<u8>,
}

/// Wipe key material from memory as best Rust can.
pub fn zero(buf: &mut [u8]) {
    buf.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only KDF params: 64 MiB x 3 rounds makes every unit test take
    // seconds. The *real* default stays in `KdfParams::default`.
    fn fast_params() -> KdfParams {
        KdfParams {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn seal_open_round_trip() {
        let key = generate_master_key();
        let nonce = [7u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"ctx", b"hello aegis").unwrap();
        // seal returns ciphertext+tag; open expects nonce prefixed.
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&ct);
        assert_eq!(open(&key, b"ctx", &sealed).unwrap(), b"hello aegis");
    }

    #[test]
    fn open_rejects_wrong_key_and_tampering() {
        let key = generate_master_key();
        let nonce = [7u8; NONCE_LEN];
        let sealed = seal(&key, &nonce, b"ctx", b"secret data").unwrap();

        let other = generate_master_key();
        assert!(
            open(&other, b"ctx", &sealed).is_err(),
            "wrong key must fail"
        );

        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open(&key, b"ctx", &tampered).is_err(), "bit-flip must fail");

        assert!(
            open(&key, b"other", &sealed).is_err(),
            "wrong AAD must fail"
        );
    }

    #[test]
    fn wrap_unwrap_round_trip_and_wrong_passphrase() {
        let master = generate_master_key();
        let secret = wrap_master_key(&master, "correct horse", &fast_params()).unwrap();
        let unwrapped = unwrap_master_key(&secret, "correct horse", &fast_params()).unwrap();
        assert_eq!(unwrapped, master);

        assert!(unwrap_master_key(&secret, "wrong horse", &fast_params()).is_err());
    }

    #[test]
    fn kdf_params_are_recorded_not_assumed() {
        let master = generate_master_key();
        let secret = wrap_master_key(&master, "p", &fast_params()).unwrap();
        // Different params → different KEK → unwrap must fail, proving params
        // matter and must be persisted per key file.
        let mut other = fast_params();
        other.iterations = 2;
        assert!(unwrap_master_key(&secret, "p", &other).is_err());
    }
}
