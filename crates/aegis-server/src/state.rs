//! Shared state for the axum application.

use std::path::Path;

use aegis_core::catalog::Catalog;
use aegis_core::keys::{KeyFile, RepoCrypto};
use anyhow::{anyhow, Context, Result};

use crate::jobs::EventHub;

/// The catalog plus its unwrapped master key, shared across handlers.
#[derive(Clone)]
pub struct AppState {
    /// The open catalog.
    pub catalog: Catalog,
    /// Live job events (WebSocket broadcast hub).
    pub events: EventHub,
    master_key: [u8; 32],
}

impl AppState {
    /// Open (or create) the catalog and unlock its master key from the
    /// sidecar key file (`<catalog>.key.json`), creating both on first run.
    /// The passphrase comes from `AEGIS_PASSPHRASE` (the server is
    /// non-interactive; no prompt fallback here).
    pub async fn open(catalog_path: impl AsRef<Path>) -> Result<Self> {
        let path = catalog_path.as_ref();
        let catalog = Catalog::open(path)
            .await
            .with_context(|| format!("opening catalog at {}", path.display()))?;
        let key_path = key_sidecar(path);
        let master_key = match std::fs::read_to_string(&key_path) {
            Ok(text) => {
                let file =
                    KeyFile::from_json(text.as_bytes()).context("parsing the catalog key file")?;
                let pass = std::env::var("AEGIS_PASSPHRASE")
                    .map_err(|_| anyhow!("AEGIS_PASSPHRASE is required to unlock the catalog"))?;
                let crypto = RepoCrypto::from_key_file(&file, &pass)
                    .map_err(|e| anyhow!("wrong catalog passphrase: {e}"))?;
                crypto.master_key()
            }
            Err(_) if !key_path.exists() => {
                let pass = std::env::var("AEGIS_PASSPHRASE")
                    .map_err(|_| anyhow!("AEGIS_PASSPHRASE is required on first run"))?;
                let master = aegis_core::crypto::generate_master_key();
                let (_crypto, file) = RepoCrypto::new_wrapped(
                    "catalog",
                    &master,
                    &pass,
                    &aegis_core::crypto::KdfParams::default(),
                )?;
                std::fs::write(&key_path, file.to_json()?)
                    .with_context(|| format!("writing {}", key_path.display()))?;
                master
            }
            Err(e) => return Err(anyhow!("reading {}: {e}", key_path.display())),
        };
        Ok(Self {
            catalog,
            events: EventHub::default(),
            master_key,
        })
    }

    /// The unwrapped catalog master key (for sealing host keys).
    pub fn master_key(&self) -> &[u8; 32] {
        &self.master_key
    }
}

/// `<catalog>.key.json` next to the database file (mirrors the CLI).
fn key_sidecar(path: &Path) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "catalog.db".to_string());
    name.push_str(".key.json");
    path.with_file_name(name)
}
