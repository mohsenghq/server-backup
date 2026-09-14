//! `aegis host …` — the host inventory commands (`docs/04`, `docs/05`).
//!
//! The catalog is a SQLite file whose master key is wrapped (Argon2id +
//! XChaCha20-Poly1305, the same machinery as repository key files) under a
//! control-plane passphrase into a sidecar `<catalog>.key.json`. Host SSH
//! private keys are envelope-encrypted inside the database under that master
//! key, so neither the DB nor a leak of it alone yields credentials.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aegis_core::catalog::{BackupMode, Catalog, Host, HostStatus};
use aegis_core::keys::{load_passphrase, KeyFile, PassphraseSource, RepoCrypto};
use aegis_core::sftp::{HostKeyPolicy, SftpAuth};
use aegis_core::ssh::{self, HostConfig, SshManager};
use aegis_core::{Repository, Snapshot};
use anyhow::{anyhow, Context, Result};
use russh::keys::PrivateKey;

/// The open catalog plus its unwrapped master key.
pub struct CatalogHandle {
    /// The open catalog.
    pub catalog: Catalog,
    master_key: [u8; 32],
}

impl CatalogHandle {
    /// Open (or create) the catalog at `path`, unlocking (or creating) its
    /// master key with the control-plane passphrase (`AEGIS_PASSPHRASE`, or a
    /// prompt; on first run the passphrase is confirmed).
    pub async fn open(path: &Path) -> Result<Self> {
        let catalog = Catalog::open(path)
            .await
            .with_context(|| format!("opening catalog at {}", path.display()))?;
        let key_path = key_sidecar(path);
        let master_key = match std::fs::read_to_string(&key_path) {
            Ok(text) => {
                let file =
                    KeyFile::from_json(text.as_bytes()).context("parsing the catalog key file")?;
                let pass = load_passphrase(&PassphraseSource::default())
                    .context("loading the catalog passphrase (AEGIS_PASSPHRASE or prompt)")?;
                let crypto = RepoCrypto::from_key_file(&file, &pass)
                    .map_err(|e| anyhow!("wrong catalog passphrase: {e}"))?;
                crypto.master_key()
            }
            Err(_) if !key_path.exists() => {
                // Fresh catalog: generate a master key, wrap it under a
                // (confirmed) passphrase, and store the key file as a
                // sidecar next to the database.
                let pass = load_passphrase(&PassphraseSource::Prompt { confirm: true })
                    .context("choosing a catalog passphrase")?;
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
            master_key,
        })
    }

    /// The unwrapped catalog master key.
    pub fn master_key(&self) -> &[u8; 32] {
        &self.master_key
    }

    /// The decrypted SSH private key (PEM) for a host.
    pub async fn host_key_pem(&self, host: &Host) -> Result<Vec<u8>> {
        let with_key = self
            .catalog
            .get_host_with_key(&host.id, &self.master_key)
            .await
            .with_context(|| format!("decrypting the key for {}", host.name))?;
        Ok(with_key.ssh_key_pem)
    }
}

/// `<catalog>.key.json` next to the database file.
fn key_sidecar(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "catalog.db".to_string());
    name.push_str(".key.json");
    path.with_file_name(name)
}

/// Build the SSH auth for a host: its stored key when it has one, otherwise
/// `AEGIS_SSH_PASSWORD` (passwords are never persisted in the catalog).
pub fn host_auth(host: &Host, key_pem: &[u8]) -> Result<SftpAuth> {
    if key_pem.is_empty() {
        let password = std::env::var("AEGIS_SSH_PASSWORD").map_err(|_| {
            anyhow!(
                "host {} has no stored key; set AEGIS_SSH_PASSWORD to use password auth",
                host.name
            )
        })?;
        return Ok(SftpAuth::Password(password));
    }
    let pem = String::from_utf8(key_pem.to_vec())
        .map_err(|_| anyhow!("host {} has a malformed stored key", host.name))?;
    let key = russh::keys::decode_secret_key(&pem, None)
        .map_err(|e| anyhow!("decoding stored key for {}: {e}", host.name))?;
    Ok(SftpAuth::Key(Arc::new(key)))
}

/// The [`HostConfig`] for running agentless backups against a registered host.
pub fn host_config(host: &Host, key_pem: &[u8], insecure: bool) -> Result<HostConfig> {
    let cfg = HostConfig::new(
        host.ssh_user.clone(),
        host.address.clone(),
        host_auth(host, key_pem)?,
    )
    .with_port(host.ssh_port);
    Ok(if insecure {
        cfg.with_host_key_policy(HostKeyPolicy::AcceptAny)
    } else {
        cfg
    })
}

/// Generate a fresh dedicated ed25519 keypair for a host; returns the private
/// key and the public key in `authorized_keys` format.
pub fn generate_host_key(comment: &str) -> Result<(PrivateKey, String)> {
    Ok(ssh::generate_host_keypair(comment)?)
}

/// Run an agentless backup of `paths` on one host into `repo`.
pub async fn backup_host(
    repo: &Repository,
    ssh: &SshManager,
    cfg: &HostConfig,
    paths: &[String],
) -> Result<Snapshot> {
    Ok(backup_host_inner(repo, ssh, cfg, paths).await?)
}

async fn backup_host_inner(
    repo: &Repository,
    ssh: &SshManager,
    cfg: &HostConfig,
    paths: &[String],
) -> aegis_core::Result<Snapshot> {
    aegis_core::backup_remote(repo, ssh, cfg, &repo.config().chunker, paths).await
}

/// One host's result in a `backup-all` run.
#[derive(Debug)]
pub struct HostRunResult {
    /// Host display name.
    pub name: String,
    /// Host catalog id.
    pub id: String,
    /// The snapshot, when the run succeeded.
    pub snapshot: Option<Snapshot>,
    /// The error message, when the run failed.
    pub error: Option<String>,
}

/// Back up every host in the catalog against `paths`. Hosts run concurrently
/// but the pool is capped at `concurrency` so large fleets don't open
/// hundreds of SSH sessions at once. A failing host does not abort the run;
/// reachability is recorded back into the catalog.
pub async fn backup_all(
    handle: &CatalogHandle,
    repo: Arc<Repository>,
    paths: Vec<String>,
    insecure: bool,
    concurrency: usize,
) -> Vec<HostRunResult> {
    let hosts = match handle.catalog.list_hosts().await {
        Ok(h) => h,
        Err(e) => {
            return vec![HostRunResult {
                name: "<catalog>".into(),
                id: String::new(),
                snapshot: None,
                error: Some(e.to_string()),
            }]
        }
    };
    let ssh = Arc::new(SshManager::new());
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut jobs = tokio::task::JoinSet::new();
    for host in hosts {
        let key = match handle.host_key_pem(&host).await {
            Ok(k) => k,
            Err(e) => {
                let err = e.to_string();
                jobs.spawn(async move {
                    HostRunResult {
                        name: host.name.clone(),
                        id: host.id.clone(),
                        snapshot: None,
                        error: Some(err),
                    }
                });
                continue;
            }
        };
        let cfg = match host_config(&host, &key, insecure) {
            Ok(c) => c,
            Err(e) => {
                let err = e.to_string();
                jobs.spawn(async move {
                    HostRunResult {
                        name: host.name.clone(),
                        id: host.id.clone(),
                        snapshot: None,
                        error: Some(err),
                    }
                });
                continue;
            }
        };
        let ssh = ssh.clone();
        let sem = sem.clone();
        let repo = repo.clone();
        let paths = paths.clone();
        jobs.spawn(async move {
            let _permit = sem.acquire().await;
            let (snapshot, error) = match backup_host_inner(&repo, &ssh, &cfg, &paths).await {
                Ok(s) => (Some(s), None),
                Err(e) => (None, Some(e.to_string())),
            };
            HostRunResult {
                name: host.name.clone(),
                id: host.id.clone(),
                snapshot,
                error,
            }
        });
    }
    let mut out = Vec::new();
    while let Some(res) = jobs.join_next().await {
        let result = res.expect("backup task panicked");
        let status = if result.error.is_some() {
            HostStatus::Unreachable
        } else {
            HostStatus::Reachable
        };
        // Best-effort; failures here don't change the backup results.
        let _ = handle.catalog.set_host_status(&result.id, status).await;
        out.push(result);
    }
    out
}

/// Look up a host by name or id prefix, for `host remove`/`host show`.
pub async fn find_host(handle: &CatalogHandle, ident: &str) -> Result<Host> {
    let hosts = handle.catalog.list_hosts().await?;
    let mut matches: Vec<&Host> = hosts
        .iter()
        .filter(|h| h.id == ident || h.name == ident)
        .collect();
    if matches.len() == 1 {
        return Ok(matches.remove(0).clone());
    }
    if matches.is_empty() && ident.len() >= 4 {
        matches = hosts.iter().filter(|h| h.id.starts_with(ident)).collect();
    }
    match matches.len() {
        1 => Ok(matches.remove(0).clone()),
        0 => Err(anyhow!("no host matches `{ident}`")),
        _ => Err(anyhow!("`{ident}` is ambiguous; use more characters")),
    }
}

/// Mode parsing shared with the CLI's `host add`.
pub fn parse_mode(s: &str) -> Result<BackupMode> {
    s.parse::<BackupMode>().map_err(|e| anyhow!("{e}"))
}
