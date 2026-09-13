//! The SSH connection manager: authenticated, host-key-checked SSH sessions
//! to managed hosts (Phase 2, `docs/04-host-connection-modes.md`).
//!
//! This is the control plane's transport for agentless backup: it reuses the
//! authentication and host-key machinery of the SFTP backend, adds remote
//! command execution (`exec`) for agentless file reads (`tar`/`cat` on the
//! target), an SFTP channel for streaming, and generates the dedicated
//! ed25519 keypair per host that the docs' key-hardening section requires.
//!
//! # Connection reuse
//!
//! [`SshManager`] caches one authenticated connection per host for its
//! lifetime and reuses it across operations; a connection that the server
//! dropped is detected transparently and re-established on next use.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use russh::client;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg};
use tokio::sync::Mutex;

use crate::error::{Error, Result};
use crate::sftp::{connect_handle, HostKeyPolicy, SftpAuth};

/// Everything needed to reach a managed host.
#[derive(Clone)]
pub struct HostConfig {
    /// Remote username.
    pub user: String,
    /// Hostname or IP.
    pub host: String,
    /// TCP port (22 unless overridden).
    pub port: u16,
    /// How to authenticate.
    pub auth: SftpAuth,
    /// Host-key validation policy (default [`HostKeyPolicy::Strict`]).
    pub host_key_policy: HostKeyPolicy,
}

impl std::fmt::Debug for HostConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostConfig")
            .field("user", &self.user)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth", &self.auth)
            .field("host_key_policy", &self.host_key_policy)
            .finish()
    }
}

impl HostConfig {
    /// Build a config with the defaults from docs/04: port 22, strict
    /// host-key checking.
    pub fn new(user: impl Into<String>, host: impl Into<String>, auth: SftpAuth) -> Self {
        Self {
            user: user.into(),
            host: host.into(),
            port: 22,
            auth,
            host_key_policy: HostKeyPolicy::Strict,
        }
    }

    /// Override the port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Override the host-key policy.
    #[must_use]
    pub fn with_host_key_policy(mut self, policy: HostKeyPolicy) -> Self {
        self.host_key_policy = policy;
        self
    }
}

/// Result of a remote command: exit status, stdout and stderr.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    /// The command's exit code (`None` when terminated by a signal or when
    /// the server never sent `exit-status`).
    pub exit_code: Option<u32>,
    /// Everything the command wrote to stdout.
    pub stdout: Vec<u8>,
    /// Everything the command wrote to stderr.
    pub stderr: Vec<u8>,
}

impl ExecOutput {
    /// `true` when the command exited 0.
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// One authenticated SSH connection, with lazily-opened channels.
struct Connection {
    handle: client::Handle<crate::sftp::ClientHandler>,
}

/// Caches authenticated connections per host key (`user@host:port`).
///
/// Cloneable (shared via `Arc` internals); the manager owns connections for
/// its whole lifetime, so a server-side drop surfaces as a reconnect on the
/// next operation rather than a stored error.
pub struct SshManager {
    inner: Arc<Mutex<HashMap<String, Arc<Mutex<Connection>>>>>,
}

impl std::fmt::Debug for SshManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshManager").finish_non_exhaustive()
    }
}

impl Default for SshManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SshManager {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

fn host_key(config: &HostConfig) -> String {
    format!("{}@{}:{}", config.user, config.host, config.port)
}

impl SshManager {
    /// An empty manager.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Drop the cached connection to a host (next use reconnects).
    pub async fn disconnect(&self, config: &HostConfig) {
        self.inner.lock().await.remove(&host_key(config));
    }

    /// Drop every cached connection.
    pub async fn disconnect_all(&self) {
        self.inner.lock().await.clear();
    }

    async fn connection(&self, config: &HostConfig) -> Result<Arc<Mutex<Connection>>> {
        let key = host_key(config);
        let mut map = self.inner.lock().await;
        if let Some(conn) = map.get(&key) {
            if !conn.lock().await.handle.is_closed() {
                return Ok(Arc::clone(conn));
            }
            // Server dropped it; fall through and reconnect.
        }
        let handle = connect_handle(
            &config.user,
            &config.host,
            config.port,
            &config.auth,
            &config.host_key_policy,
        )
        .await
        .map_err(|e| Error::Ssh(format!("{}: {e}", key)))?;
        let conn = Arc::new(Mutex::new(Connection { handle }));
        map.insert(key, Arc::clone(&conn));
        Ok(conn)
    }

    /// Run `command` on the host and collect its output.
    ///
    /// # Errors
    ///
    /// Any transport, authentication, or channel failure maps to
    /// [`Error::Ssh`].
    pub async fn exec(&self, config: &HostConfig, command: &str) -> Result<ExecOutput> {
        let conn = self.connection(config).await?;
        let conn = conn.lock().await;
        let mut channel = conn
            .handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Ssh(format!("opening exec channel: {e}")))?;
        channel
            .exec(true, command)
            .await
            .map_err(|e| Error::Ssh(format!("exec `{command}`: {e}")))?;

        let mut out = ExecOutput {
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } if !data.is_empty() => out.stdout.extend(data),
                russh::ChannelMsg::ExtendedData { data, ext: 1 } if !data.is_empty() => {
                    out.stderr.extend(data)
                }
                russh::ChannelMsg::ExitStatus { exit_status } => out.exit_code = Some(exit_status),
                russh::ChannelMsg::Eof => {}
                russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(out)
    }

    /// Run `command` on the host, requiring exit 0; stderr is quoted in the
    /// error otherwise.
    pub async fn exec_check(&self, config: &HostConfig, command: &str) -> Result<ExecOutput> {
        let out = self.exec(config, command).await?;
        if out.success() {
            Ok(out)
        } else {
            Err(Error::Ssh(format!(
                "`{command}` failed on {}@{}:{} with {:?}: {}",
                config.user,
                config.host,
                config.port,
                out.exit_code,
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    /// Open an SFTP channel on the host's existing connection and return the
    /// raw [`SftpSession`], for streaming file reads in agentless backup.
    ///
    /// Each call opens a fresh channel multiplexed over the cached
    /// connection; sessions are independent and cheap.
    pub async fn sftp_channel(
        &self,
        config: &HostConfig,
    ) -> Result<Arc<russh_sftp::client::SftpSession>> {
        use russh_sftp::client::SftpSession;

        let conn = self.connection(config).await?;
        let conn = conn.lock().await;
        let channel = conn
            .handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Ssh(format!("opening sftp channel: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| Error::Ssh(format!("requesting sftp subsystem: {e}")))?;
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| Error::Ssh(format!("starting SFTP protocol: {e}")))?;
        Ok(Arc::new(sftp))
    }
}

/// Generate a fresh dedicated ed25519 keypair for a host (docs/04:
/// "generate a dedicated ed25519 keypair per host at add-time").
///
/// Returns the private key (envelope-encrypt before storing — see
/// `RepoCrypto`/the server's master key) and its OpenSSH-format public key
/// line for the target's `authorized_keys`.
///
/// # Errors
///
/// Only fails if key generation itself does (which russh reports as
/// [`Error::Ssh`]).
pub fn generate_host_keypair(comment: &str) -> Result<(PrivateKey, String)> {
    use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};

    // Draw the seed from the OS CSPRNG directly; the ssh-key crate's
    // `PrivateKey::random` needs a newer rand_core than our tree carries.
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| Error::Ssh(format!("generating host key seed: {e}")))?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    let key = PrivateKey::new(KeypairData::from(keypair), comment)
        .map_err(|e| Error::Ssh(format!("building private key: {e}")))?;

    let public = key
        .public_key()
        .to_openssh()
        .map_err(|e| Error::Ssh(format!("encoding public key: {e}")))?;
    Ok((key, public))
}

/// Write the private key to `path` in OpenSSH format (used for testing and
/// for the CLI's "hand me the key file" flow; the server encrypts at rest).
///
/// # Errors
///
/// Any filesystem error is wrapped in [`Error::Io`].
/// Write the private key to `path` in unencrypted OpenSSH PEM format.
///
/// For at-rest storage the *server* envelope-encrypts the key with its master
/// key (docs/04); this helper exists for the CLI's "write me a key file to
/// install in `authorized_keys`" flow and for tests. Callers must set the
/// file's permissions appropriately (0600).
///
/// # Errors
///
/// Any filesystem error is wrapped in [`Error::Io`].
pub fn write_private_key(key: &PrivateKey, path: &PathBuf) -> Result<()> {
    let data = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .map_err(|e| Error::Ssh(format!("encoding private key: {e}")))?;
    std::fs::write(path, data.as_bytes()).map_err(|e| Error::io(path, e))
}

/// Load a private key from an OpenSSH-format file (or in-memory bytes) and
/// return it as [`SftpAuth::Key`] ready to authenticate with.
pub fn load_private_key(pem: &str, passphrase: Option<&str>) -> Result<PrivateKeyWithHashAlg> {
    let key = russh::keys::decode_secret_key(pem, passphrase)
        .map_err(|e| Error::Ssh(format!("decoding key: {e}")))?;
    Ok(PrivateKeyWithHashAlg::new(
        Arc::new(key),
        Some(HashAlg::Sha256),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_keys_are_stable_and_distinct() {
        let cfg = HostConfig::new("u", "h", SftpAuth::Password("p".into())).with_port(2222);
        assert_eq!(host_key(&cfg), "u@h:2222");
        let other = HostConfig::new("u", "h", SftpAuth::Password("p".into()));
        assert_ne!(host_key(&cfg), host_key(&other));
    }

    #[test]
    fn debug_output_hides_secrets() {
        let cfg = HostConfig::new("u", "h", SftpAuth::Password("secret".into()));
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("secret"), "leaked: {rendered}");
    }

    #[test]
    fn generates_dedicated_ed25519_keypairs() {
        let (key, line) = generate_host_keypair("aegis:host-x").unwrap();
        assert!(line.starts_with("ssh-ed25519 "));
        assert!(line.ends_with("aegis:host-x"));

        // Round-trips through the OpenSSH encoder.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        write_private_key(&key, &path).unwrap();
        let pem = std::fs::read_to_string(&path).unwrap();
        let loaded = load_private_key(&pem, None).unwrap();
        // Round-trips to valid OpenSSH PEM.
        assert!(loaded
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .is_ok());
    }
}
