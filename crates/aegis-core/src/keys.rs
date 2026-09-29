//! Repository-level encryption plumbing: the key file set, passphrase
//! loading, and the cipher every repo document flows through.
//!
//! Every byte Aegis stores — data chunks, tree nodes, snapshot manifests,
//! snapshot indexes — is sealed here before it reaches a [`Backend`]. The
//! repo `config` is the one plaintext document: it holds no secrets (format
//! version, repo id, chunker params, and the pointer to which key slot opens
//! the repo), because reading *it* is what tells Aegis how to decrypt
//! everything else.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::crypto::{self, KdfParams, WrappedKey, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{Error, Result};

/// AAD domain separator for repo documents that are not content-addressed
/// blobs (manifests, indexes): the key plus this context string. Data chunks
/// and tree nodes additionally bind their own hash (see `AeadContext`).
pub const DOC_CONTEXT: &[u8] = b"aegis/doc/v1";

/// Where wrapped master keys live in the repository key space.
const KEYS_PREFIX: &str = "keys";

fn key_key(slot: &str) -> String {
    format!("{KEYS_PREFIX}/{slot}.json")
}

/// The slot name of a key file's key, if `key` is one (`"keys/key1.json"` →
/// `"key1"`).
fn slot_of(key: &str) -> Option<&str> {
    key.strip_prefix("keys/")
        .and_then(|rest| rest.strip_suffix(".json"))
}

/// The `keys/` document, stored in plaintext JSON: it contains only wrapped
/// material, salts, and parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    /// Which key slot in `RepoConfig::key_slot` this file is.
    pub slot: String,
    /// The wrapped master key.
    pub wrapped_key: WrappedKey,
}

impl KeyFile {
    /// Render the key file's on-disk JSON.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| Error::Malformed {
            what: "key file".into(),
            source: e,
        })
    }

    /// Parse a key file from its on-disk JSON.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if the document cannot be parsed.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| Error::Malformed {
            what: "key file".into(),
            source: e,
        })
    }
}

/// Which AEAD context a blob is sealed in: content-addressed blobs bind their
/// own hash as AAD (moving a ciphertext to another address fails
/// authentication); free-form documents bind a fixed domain string.
pub enum AeadContext<'a> {
    /// A blob stored under its own hash.
    Hash(&'a str),
    /// A repo document at a fixed key.
    Doc,
    /// A host's encrypted SSH key, bound to the host id.
    Host(&'a str),
}

impl AeadContext<'_> {
    pub(crate) fn aad(&self) -> Vec<u8> {
        match self {
            AeadContext::Hash(hex) => {
                let mut aad = b"aegis/blob/v1:".to_vec();
                aad.extend_from_slice(hex.as_bytes());
                aad
            }
            AeadContext::Doc => DOC_CONTEXT.to_vec(),
            AeadContext::Host(id) => {
                let mut aad = b"aegis/host/v1:".to_vec();
                aad.extend_from_slice(id.as_bytes());
                aad
            }
        }
    }
}

/// Encode bytes as standard base64.
pub fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decode standard base64.
///
/// # Errors
///
/// Returns [`Error::KeyError`] on invalid input.
pub fn b64_decode(data: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| Error::KeyError(format!("invalid base64: {e}")))
}

/// Where a passphrase comes from.
#[derive(Debug, Clone, Default)]
pub enum PassphraseSource {
    /// Read from the `AEGIS_PASSPHRASE` environment variable.
    #[default]
    Env,
    /// Prompt on the terminal (confirmation prompt when `confirm`).
    Prompt {
        /// Ask for the passphrase twice and require the copies to match.
        confirm: bool,
    },
}

/// Load a passphrase from the configured source.
///
/// # Errors
///
/// Returns [`Error::NoPassphrase`] if no source can provide one.
pub fn load_passphrase(source: &PassphraseSource) -> Result<String> {
    match source {
        PassphraseSource::Env => std::env::var("AEGIS_PASSPHRASE").map_err(|_| Error::NoPassphrase),
        PassphraseSource::Prompt { confirm } => {
            // A set environment variable overrides the prompt so scripts and
            // CI can drive commands that normally prompt (e.g. `init`).
            if let Ok(pass) = std::env::var("AEGIS_PASSPHRASE") {
                return Ok(pass);
            }
            if !atty::is(atty::Stream::Stdin) {
                return Err(Error::NoPassphrase);
            }
            let first = rpassword::prompt_password("passphrase: ")
                .map_err(|e| Error::KeyError(format!("reading passphrase: {e}")))?;
            if *confirm {
                let second = rpassword::prompt_password("confirm passphrase: ")
                    .map_err(|e| Error::KeyError(format!("reading passphrase: {e}")))?;
                if first != second {
                    return Err(Error::KeyError("passphrases do not match".into()));
                }
            }
            Ok(first)
        }
    }
}

/// Load the *new* passphrase for `key add`: `AEGIS_NEW_PASSPHRASE` when set,
/// otherwise an interactive confirmed prompt.
///
/// # Errors
///
/// Returns [`Error::NoPassphrase`] when nothing is available non-interactively.
pub fn load_new_passphrase() -> Result<String> {
    if let Ok(new) = std::env::var("AEGIS_NEW_PASSPHRASE") {
        return Ok(new);
    }
    if !atty::is(atty::Stream::Stdin) {
        return Err(Error::NoPassphrase);
    }
    load_passphrase(&PassphraseSource::Prompt { confirm: true })
}

/// Unwrap the master key of whichever slot `passphrase` opens.
///
/// The configured slot from `config.key_slot` is tried first, then every other
/// slot in the repository. Rotation adds slots, so a repository is openable by
/// *any* of its passphrases, not just the one `config` happened to name — and
/// deleting a key slot must not be able to strand the repository.
///
/// Returns the slot that was opened along with its crypto.
///
/// # Errors
///
/// Returns [`Error::KeyError`] if no key file can be read, and
/// [`Error::WrongPassphrase`] when `passphrase` opens none of them.
pub async fn open_any_slot(
    backend: &dyn crate::backend::Backend,
    config: &crate::repo::RepoConfig,
    passphrase: &str,
) -> Result<(String, RepoCrypto)> {
    let mut slots = vec![config.key_slot.clone()];
    for key in backend.list(KEYS_PREFIX).await? {
        if let Some(slot) = slot_of(&key) {
            if !slots.iter().any(|s| s == slot) {
                slots.push(slot.to_string());
            }
        }
    }
    let mut last = Error::KeyError("repository has no key files".into());
    for slot in slots {
        let Ok(raw) = backend.get(&key_key(&slot)).await else {
            continue;
        };
        let Ok(file) = KeyFile::from_json(&raw) else {
            continue;
        };
        match RepoCrypto::from_key_file(&file, passphrase) {
            Ok(crypto) => return Ok((file.slot, crypto)),
            // The passphrase may open another slot; remember the failure in
            // case it opens none of them.
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// One passphrase slot in a repository's `keys/` directory, as reported by
/// [`key_list_backend`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlot {
    /// Slot name, and the key file's filename stem (`default`, `key1`, …).
    pub slot: String,
    /// RFC 3339 timestamp of when this slot was created.
    pub created: String,
    /// Argon2id parameters protecting this slot's wrapped key.
    pub kdf: KdfParams,
    /// Whether this is the slot the repository `config` names. Slots other
    /// than this one still open the repository — see [`open_any_slot`] — so
    /// this is a hint, not an access control.
    pub active: bool,
}

/// Add a new passphrase that can open the local repository at `path`.
///
/// The existing master key is unwrapped with `current_passphrase`, then
/// wrapped under `new_passphrase` into the next free `key<N>` slot. Data is
/// untouched — this is what makes passphrase rotation cheap
/// (`docs/10-security-model.md`).
///
/// Returns the id of the new key slot.
///
/// # Errors
///
/// Returns [`Error::WrongPassphrase`] if `current_passphrase` does not open
/// the repository, and backend errors if the key file cannot be written.
pub async fn key_add(
    path: &std::path::Path,
    current_passphrase: &str,
    new_passphrase: &str,
) -> Result<String> {
    key_add_backend(
        Box::new(crate::backend::LocalBackend::new(path)),
        current_passphrase,
        new_passphrase,
    )
    .await
}

/// [`key_add`] against an arbitrary backend (e.g. an SFTP repository).
///
/// # Errors
///
/// Same as [`key_add`].
pub async fn key_add_backend(
    backend: Box<dyn crate::backend::Backend>,
    current_passphrase: &str,
    new_passphrase: &str,
) -> Result<String> {
    let config = read_config(backend.as_ref()).await?;
    // Any passphrase that opens the repo may authorize adding another one, not
    // just the one the config happens to name.
    let (slot, crypto) = open_any_slot(backend.as_ref(), &config, current_passphrase).await?;

    // Next free slot: key1, key2, ... ("default" is slot 0).
    let mut n = 1usize;
    while backend.exists(&key_key(&format!("key{n}"))).await? {
        n += 1;
    }
    let new_slot = format!("key{n}");
    let master = crypto.master_key();
    // Inherit the opened slot's Argon2id params, so a rotation does not
    // silently weaken (or needlessly strengthen) a repository's KDF cost.
    let kdf = KeyFile::from_json(&backend.get(&key_key(&slot)).await?)?
        .wrapped_key
        .kdf;
    let (_new_crypto, new_file) =
        RepoCrypto::new_wrapped(&new_slot, &master, new_passphrase, &kdf)?;
    backend
        .put(&key_key(&new_slot), &new_file.to_json()?)
        .await?;
    Ok(new_slot)
}

/// List the passphrase slots in a repository, in slot-name order.
///
/// A key file that cannot be parsed is reported as an error rather than
/// skipped: an unreadable slot is exactly what an operator rotating keys
/// needs to know about.
///
/// # Errors
///
/// Returns [`Error::RepoNotFound`] if there is no `config`, [`Error::Malformed`]
/// for an unparseable config or key file, and backend errors if `keys/` cannot
/// be listed.
pub async fn key_list_backend(backend: &dyn crate::backend::Backend) -> Result<Vec<KeySlot>> {
    let config = read_config(backend).await?;
    let mut keys = backend.list(KEYS_PREFIX).await?;
    keys.sort();
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        let Some(slot) = slot_of(&key) else { continue };
        let file = KeyFile::from_json(&backend.get(&key).await?)?;
        out.push(KeySlot {
            slot: file.slot,
            created: file.wrapped_key.created,
            kdf: file.wrapped_key.kdf,
            active: slot == config.key_slot,
        });
    }
    Ok(out)
}

/// Revoke a passphrase slot, deleting its `keys/<slot>.json` file.
///
/// This is the destructive half of rotation: the revoked passphrase can no
/// longer unwrap the master key, while the repository's data is untouched —
/// every other slot still opens it. `passphrase` must open the repository, so
/// revoking a key requires proving you hold a working one.
///
/// If the revoked slot is the one the repository `config` names, the config is
/// re-pointed at a surviving slot, so it never references a slot that is gone.
///
/// # Errors
///
/// Returns [`Error::KeyError`] if `slot` does not exist or it is the
/// repository's only remaining slot (which would leave nothing able to open
/// the repository), [`Error::WrongPassphrase`] if `passphrase` does not open
/// the repository, and backend errors if the key file cannot be deleted.
pub async fn key_remove_backend(
    backend: &dyn crate::backend::Backend,
    slot: &str,
    passphrase: &str,
) -> Result<()> {
    let mut config = read_config(backend).await?;
    open_any_slot(backend, &config, passphrase).await?;

    let mut keys = backend.list(KEYS_PREFIX).await?;
    keys.sort();
    let slots: Vec<&str> = keys.iter().filter_map(|k| slot_of(k)).collect();
    if !slots.contains(&slot) {
        return Err(Error::KeyError(format!(
            "no key slot '{slot}' in this repository (have: {})",
            slots.join(", ")
        )));
    }
    if slots.len() == 1 {
        return Err(Error::KeyError(format!(
            "refusing to remove '{slot}': it is the repository's only key slot. \
             add another passphrase with `aegis key-add` first"
        )));
    }
    backend.delete(&key_key(slot)).await?;

    if config.key_slot == slot {
        config.key_slot = slots
            .iter()
            .find(|s| **s != slot)
            .expect("a slot other than the removed one exists")
            .to_string();
        let json = serde_json::to_vec_pretty(&config).expect("RepoConfig is serializable");
        backend.put("config", &json).await?;
    }
    Ok(())
}

/// Read and parse a repository's plaintext `config` document.
async fn read_config(backend: &dyn crate::backend::Backend) -> Result<crate::repo::RepoConfig> {
    if !backend.exists("config").await? {
        return Err(Error::RepoNotFound(backend.describe()));
    }
    serde_json::from_slice(&backend.get("config").await?).map_err(|e| Error::Malformed {
        what: "repository config".into(),
        source: e,
    })
}

/// Everything needed to seal/open a repository's documents: the master key
/// plus its slot metadata.
pub struct RepoCrypto {
    key_slot: String,
    key: [u8; KEY_LEN],
}

impl RepoCrypto {
    /// Generate a new master key and wrap it under `passphrase` into a fresh
    /// key slot (used by `init` and `key add`).
    ///
    /// For `init`, `key_slot` names the new slot. For `key add`, an existing
    /// master key is re-wrapped under the new passphrase into `key_slot`.
    pub fn new_wrapped(
        key_slot: &str,
        master: &[u8; KEY_LEN],
        passphrase: &str,
        params: &KdfParams,
    ) -> Result<(Self, KeyFile)> {
        let secret = crypto::wrap_master_key(master, passphrase, params)?;
        let file = KeyFile {
            slot: key_slot.to_string(),
            wrapped_key: WrappedKey {
                id: key_slot.to_string(),
                kdf: *params,
                salt: b64_encode(&secret.salt),
                nonce: b64_encode(&secret.nonce),
                wrapped: b64_encode(&secret.sealed),
                created: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown".into()),
            },
        };
        Ok((
            Self {
                key_slot: key_slot.to_string(),
                key: *master,
            },
            file,
        ))
    }

    /// Unwrap the master key described by `file` using `passphrase`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WrongPassphrase`] if the passphrase does not open the
    /// wrapped key, and [`Error::KeyError`] for malformed key files.
    pub fn from_key_file(file: &KeyFile, passphrase: &str) -> Result<Self> {
        let w = &file.wrapped_key;
        let salt_bytes = b64_decode(&w.salt)?;
        if salt_bytes.len() != SALT_LEN {
            return Err(Error::KeyError("key file salt has the wrong length".into()));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_bytes);
        let nonce_bytes = b64_decode(&w.nonce)?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(Error::KeyError(
                "key file nonce has the wrong length".into(),
            ));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_bytes);

        let secret = crypto::WrappedSecret {
            salt,
            nonce,
            sealed: b64_decode(&w.wrapped)?,
        };
        let key = crypto::unwrap_master_key(&secret, passphrase, &w.kdf)
            .map_err(|_| Error::WrongPassphrase)?;
        Ok(Self {
            key_slot: file.slot.clone(),
            key,
        })
    }

    /// The key slot this crypto instance was opened with.
    pub fn key_slot(&self) -> &str {
        &self.key_slot
    }

    /// A copy of the master key (callers must zero it after use).
    pub fn master_key(&self) -> [u8; KEY_LEN] {
        self.key
    }

    /// Seal `plaintext` for `context`, producing nonce‖ciphertext‖tag.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EncryptFailed`] if the AEAD cannot run.
    pub fn seal(&self, context: &AeadContext, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut nonce);
        let mut sealed = crypto::seal(&self.key, &nonce, &context.aad(), plaintext)?;
        let mut out = Vec::with_capacity(NONCE_LEN + sealed.len());
        out.extend_from_slice(&nonce);
        out.append(&mut sealed);
        Ok(out)
    }

    /// Open `sealed` (`nonce‖ciphertext‖tag`) for `context`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DecryptFailed`] for a wrong key or tampered data.
    pub fn open(&self, context: &AeadContext, sealed: &[u8]) -> Result<Vec<u8>> {
        crypto::open(&self.key, &context.aad(), sealed)
    }
}

/// Drop the master key from memory.
impl Drop for RepoCrypto {
    fn drop(&mut self) {
        crypto::zero(&mut self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_master_key;

    fn fast_params() -> KdfParams {
        KdfParams {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn wrap_and_reopen_round_trips_through_the_key_file() {
        let master = generate_master_key();
        let (crypto, file) =
            RepoCrypto::new_wrapped("default", &master, "pass phrase", &fast_params()).unwrap();

        let bytes = file.to_json().unwrap();
        let parsed = KeyFile::from_json(&bytes).unwrap();
        let reopened = RepoCrypto::from_key_file(&parsed, "pass phrase").unwrap();

        // Both instances must produce compatible ciphertexts.
        let a = crypto.seal(&AeadContext::Doc, b"payload").unwrap();
        assert_eq!(reopened.open(&AeadContext::Doc, &a).unwrap(), b"payload");
        assert_eq!(reopened.key_slot(), "default");
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let master = generate_master_key();
        let (_, file) =
            RepoCrypto::new_wrapped("default", &master, "right", &fast_params()).unwrap();
        assert!(matches!(
            RepoCrypto::from_key_file(&file, "wrong"),
            Err(Error::WrongPassphrase)
        ));
    }

    #[test]
    fn hash_context_binds_the_address() {
        let master = generate_master_key();
        let (crypto, _) = RepoCrypto::new_wrapped("s", &master, "p", &fast_params()).unwrap();

        let sealed = crypto.seal(&AeadContext::Hash("abcd"), b"data").unwrap();
        assert_eq!(
            crypto.open(&AeadContext::Hash("abcd"), &sealed).unwrap(),
            b"data"
        );
        // The same ciphertext opened under a different address must fail —
        // this is the anti blob-swap property.
        assert!(crypto.open(&AeadContext::Hash("ffff"), &sealed).is_err());
    }

    #[test]
    fn ciphertexts_are_nondeterministic_per_write() {
        let master = generate_master_key();
        let (crypto, _) = RepoCrypto::new_wrapped("s", &master, "p", &fast_params()).unwrap();
        let a = crypto.seal(&AeadContext::Doc, b"same").unwrap();
        let b = crypto.seal(&AeadContext::Doc, b"same").unwrap();
        assert_ne!(a, b, "random nonces must make ciphertexts differ");
    }
}
