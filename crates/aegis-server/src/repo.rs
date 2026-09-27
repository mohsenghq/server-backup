//! Where the control plane's repository lives, and how to open it.
//!
//! The server writes every snapshot into one repository: the one named by
//! `AEGIS_REPO`, or — by default — the directory that holds the catalog, so a
//! single mounted volume carries the catalog, its key sidecar, and the backup
//! data.

use std::path::{Path, PathBuf};

use aegis_core::repo::Repository;
use anyhow::{anyhow, Context, Result};

/// The repository location for a given catalog path: `AEGIS_REPO` when set,
/// otherwise the catalog's parent directory.
pub fn repo_path(catalog_path: &Path) -> PathBuf {
    match std::env::var("AEGIS_REPO") {
        Ok(p) if !p.trim().is_empty() => PathBuf::from(p),
        _ => catalog_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")),
    }
}

/// Open the control plane's repository, creating it on first use.
///
/// The repository passphrase is `AEGIS_PASSPHRASE` — the same secret that
/// wraps the catalog's master key.
///
/// # Errors
///
/// Auto-initialization happens *only* when the backend has no `config` at all.
/// A wrong passphrase or a damaged key file is returned as an error, never
/// "repaired" by starting an empty repository on top of existing data.
pub async fn open_or_init(catalog_path: &Path) -> Result<Repository> {
    let path = repo_path(catalog_path);
    let pass = std::env::var("AEGIS_PASSPHRASE")
        .map_err(|_| anyhow!("AEGIS_PASSPHRASE is required to open the repository"))?;
    open_backend_or_init(Box::new(aegis_core::LocalBackend::new(&path)), &pass).await
}

/// Open a repository on any backend, creating it when the backend holds no
/// `config` yet (a first-run target, e.g. a fresh SFTP directory).
pub async fn open_backend_or_init(
    backend: Box<dyn aegis_core::Backend>,
    passphrase: &str,
) -> Result<Repository> {
    let where_ = backend.describe();
    let opened = Repository::open(backend, passphrase).await;
    match opened {
        Ok(repo) => Ok(repo),
        Err(aegis_core::Error::RepoNotFound(_)) => {
            // `open` consumed the backend, so re-open a fresh one over the
            // same location to create the repository. Only `LocalBackend`
            // needs this today; remote targets are created by `replicate`.
            tracing::info!(repo = %where_, "no repository yet; creating one");
            let backend =
                Box::new(aegis_core::LocalBackend::new(&where_)) as Box<dyn aegis_core::Backend>;
            Repository::init(backend, aegis_core::ChunkerConfig::default(), passphrase)
                .await
                .with_context(|| format!("creating repository at {where_}"))
        }
        Err(e) => Err(anyhow!("opening repository at {where_}: {e}")),
    }
}
