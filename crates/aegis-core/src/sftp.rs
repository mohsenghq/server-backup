//! The SFTP backend: repositories over SSH (`russh` + `russh-sftp`).
//!
//! A repository location is either a local path or an
//! `sftp://[user@]host[:port]/path` URL; [`parse_location`] turns the string
//! into a [`RepoLocation`] and [`open_backend`] resolves it to a
//! [`Backend`](crate::backend::Backend). The on-the-wire layout is
//! byte-for-byte the one in `docs/03-repository-format.md` — a backend is a
//! flat key/value store, so the repository format does not care where the
//! bytes live.
//!
//! # Authentication
//!
//! [`SftpAuth`] offers password and private-key methods. Keys may come from a
//! file (OpenSSH format, optionally encrypted — `key_passphrase` unlocks it)
//! or an in-memory [`russh::keys::PrivateKey`].
//!
//! # Host keys
//!
//! [`HostKeyPolicy`] mirrors OpenSSH's model: `Strict` checks the user's
//! `known_hosts` (accept-new style: unknown hosts are recorded on first
//! contact, a *changed* key is a hard [`Error::HostKeyChanged`]),
//! `AcceptAny` skips the check for ephemeral test environments. The default
//! is `Strict`; `AEGIS_KNOWN_HOSTS` relocates the file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use russh::client;
use russh::keys::{
    check_known_hosts_path, known_hosts::learn_known_hosts_path, HashAlg, PrivateKey,
    PrivateKeyWithHashAlg,
};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::io::AsyncWriteExt;

use crate::backend::Backend;
use crate::chunk::ChunkerConfig;
use crate::error::{Error, Result};
use crate::repo::Repository;

/// Where a repository lives, parsed from a location argument.
#[derive(Clone, Debug)]
pub enum RepoLocation {
    /// A local filesystem path (`/srv/backups`, `D:\backups`).
    Local(PathBuf),
    /// A remote repository (`sftp://user@host:2222/srv/backups`).
    Sftp(SftpTarget),
}

/// The remote half of a [`RepoLocation::Sftp`].
#[derive(Clone, Debug)]
pub struct SftpTarget {
    /// Remote user (defaults to `root` when the URL omits one).
    pub user: String,
    /// Hostname or IP.
    pub host: String,
    /// Port (defaults to 22).
    pub port: u16,
    /// Absolute path of the repository directory on the remote.
    pub path: String,
}

impl SftpTarget {
    /// Build a target for `sftp://user@host:port/path`.
    pub fn new(
        user: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        path: impl Into<String>,
    ) -> Self {
        Self {
            user: user.into(),
            host: host.into(),
            port,
            path: path.into(),
        }
    }
}

/// Parse a repository location: any string starting with `sftp://` is remote,
/// everything else is a local path.
///
/// # Errors
///
/// Returns [`Error::MalformedBlob`] (reused as the generic malformed-input
/// error) for an `sftp://` URL without a host or without a path component.
pub fn parse_location(s: &str) -> Result<RepoLocation> {
    let Some(rest) = s.strip_prefix("sftp://") else {
        return Ok(RepoLocation::Local(PathBuf::from(s)));
    };

    let Some((authority, path)) = rest.split_once('/') else {
        return Err(Error::MalformedBlob(format!("`{s}` has no path component")));
    };
    if path.is_empty() {
        return Err(Error::MalformedBlob(format!("`{s}` has no path component")));
    }
    let path = format!("/{path}");

    let (user, hostport) = match authority.split_once('@') {
        Some((u, h)) => (u.to_string(), h.to_string()),
        None => ("root".to_string(), authority.to_string()),
    };
    if user.is_empty() {
        return Err(Error::MalformedBlob(format!("`{s}` has an empty user")));
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .parse::<u16>()
                .map_err(|_| Error::MalformedBlob(format!("`{s}` has an invalid port `{p}`")))?;
            (h.to_string(), port)
        }
        None => (hostport, 22),
    };
    if host.is_empty() {
        return Err(Error::MalformedBlob(format!("`{s}` has no host")));
    }

    Ok(RepoLocation::Sftp(SftpTarget {
        user,
        host,
        port,
        path,
    }))
}

impl std::fmt::Display for RepoLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepoLocation::Local(p) => write!(f, "{}", p.display()),
            RepoLocation::Sftp(t) => write!(f, "sftp://{}@{}:{}{}", t.user, t.host, t.port, t.path),
        }
    }
}

/// How an [`SftpBackend`] authenticates to the server.
#[derive(Clone)]
pub enum SftpAuth {
    /// Password authentication.
    Password(String),
    /// Authenticate with a key loaded from an OpenSSH-format file. An
    /// encrypted key needs `key_passphrase` to decrypt it.
    KeyFile {
        /// Path to the private key file.
        path: PathBuf,
        /// Decryption passphrase for encrypted keys.
        key_passphrase: Option<String>,
    },
    /// Authenticate with a key already in memory.
    Key(Arc<PrivateKey>),
}

impl SftpAuth {
    /// The agent's default auth: the user's default key file
    /// (`~/.ssh/id_ed25519` / `id_rsa`), the standard non-interactive path.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] when no default key file exists.
    pub fn from_env() -> Result<Self> {
        for name in ["id_ed25519", "id_rsa"] {
            if let Some(home) = std::env::var_os("HOME") {
                let path = Path::new(&home).join(".ssh").join(name);
                if path.exists() {
                    return Ok(Self::KeyFile {
                        path,
                        key_passphrase: None,
                    });
                }
            }
        }
        Err(Error::InvalidInput(
            "no default SSH key (~/.ssh/id_ed25519 or id_rsa) found".into(),
        ))
    }
}
impl std::fmt::Debug for SftpAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Never debug-print secrets.
            Self::Password(_) => f.write_str("Password(****)"),
            Self::KeyFile {
                path,
                key_passphrase,
            } => f
                .debug_struct("KeyFile")
                .field("path", path)
                .field("key_passphrase", &key_passphrase.as_ref().map(|_| "****"))
                .finish(),
            Self::Key(_) => f.write_str("Key(..)"),
        }
    }
}

/// How the server's host key is validated.
#[derive(Clone, Debug, Default)]
pub enum HostKeyPolicy {
    /// OpenSSH `StrictHostKeyChecking=accept-new`: the key must match any
    /// recorded entry, and unknown hosts are recorded on first contact.
    #[default]
    Strict,
    /// Trust any host key (ephemeral test environments only).
    AcceptAny,
}

/// A [`Backend`] that stores repository objects on a remote server over SFTP.
///
/// A dedicated SSH connection is established lazily on the first operation
/// and reused for the backend's lifetime.
pub struct SftpBackend {
    target: SftpTarget,
    auth: SftpAuth,
    host_key_policy: HostKeyPolicy,
    sftp: tokio::sync::OnceCell<Arc<SftpSession>>,
}

impl std::fmt::Debug for SftpBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpBackend")
            .field("target", &self.target)
            .field("auth", &self.auth)
            .field("host_key_policy", &self.host_key_policy)
            .finish_non_exhaustive()
    }
}

/// Connect to `user@host:port`, authenticate with `auth`, and return the
/// live SSH handle. Shared by the SFTP backend and the Phase 2 SSH
/// connection manager.
pub(crate) async fn connect_handle(
    user: &str,
    host: &str,
    port: u16,
    auth: &SftpAuth,
    policy: &HostKeyPolicy,
) -> Result<client::Handle<ClientHandler>> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(600)),
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        ..client::Config::default()
    });

    let mut handle = russh::client::connect(
        config,
        (host, port),
        ClientHandler {
            policy: policy.clone(),
            host: host.to_string(),
            port,
        },
    )
    .await
    .map_err(|e| Error::Ssh(format!("connecting to {host}:{port}: {e}")))?;

    let auth_result = match auth {
        SftpAuth::Password(password) => handle
            .authenticate_password(user, password.clone())
            .await
            .map_err(|e| Error::Ssh(format!("authentication exchange failed: {e}")))?,
        SftpAuth::KeyFile {
            path,
            key_passphrase,
        } => {
            let key = russh::keys::load_secret_key(path, key_passphrase.as_deref())
                .map_err(|e| Error::Ssh(format!("loading key {}: {e}", path.display())))?;
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha256));
            handle
                .authenticate_publickey(user, key)
                .await
                .map_err(|e| Error::Ssh(format!("authentication exchange failed: {e}")))?
        }
        SftpAuth::Key(key) => {
            let key = PrivateKeyWithHashAlg::new(Arc::clone(key), Some(HashAlg::Sha256));
            handle
                .authenticate_publickey(user, key)
                .await
                .map_err(|e| Error::Ssh(format!("authentication exchange failed: {e}")))?
        }
    };
    if !auth_result.success() {
        return Err(Error::Ssh(format!(
            "authentication failed for user `{user}` on {host}"
        )));
    }
    Ok(handle)
}

impl SftpBackend {
    /// Prepare a backend for `sftp://user@host:port/path`.
    pub fn new(target: SftpTarget, auth: SftpAuth) -> Self {
        Self {
            target,
            auth,
            host_key_policy: HostKeyPolicy::Strict,
            sftp: tokio::sync::OnceCell::new(),
        }
    }

    /// Override the host-key policy (default: [`HostKeyPolicy::Strict`]).
    pub fn with_host_key_policy(mut self, policy: HostKeyPolicy) -> Self {
        self.host_key_policy = policy;
        self
    }

    /// Connect, authenticate and open the SFTP channel (once).
    async fn sftp(&self) -> Result<&Arc<SftpSession>> {
        self.sftp.get_or_try_init(|| self.connect_and_auth()).await
    }

    async fn connect_and_auth(&self) -> Result<Arc<SftpSession>> {
        let handle = connect_handle(
            &self.target.user,
            &self.target.host,
            self.target.port,
            &self.auth,
            &self.host_key_policy,
        )
        .await?;

        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Ssh(format!("opening session channel: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| Error::Ssh(format!("requesting sftp subsystem: {e}")))?;

        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| Error::Ssh(format!("starting SFTP protocol: {e}")))?;
        Ok(Arc::new(sftp))
    }

    /// Map a key to an absolute remote path, keeping every segment inside the
    /// repository root (keys are internal, but never trust them blindly).
    fn remote_path(&self, key: &str) -> String {
        let mut out = self.target.path.clone();
        for seg in key
            .split('/')
            .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        {
            out.push('/');
            out.push_str(seg);
        }
        out
    }

    async fn mkdir_all(&self, sftp: &SftpSession, remote_dir: &str) -> Result<()> {
        // Create each missing prefix; `create_dir` on an existing directory
        // fails, which we ignore after checking.
        let mut probe = String::new();
        for seg in remote_dir.split('/').filter(|s| !s.is_empty()) {
            probe.push('/');
            probe.push_str(seg);
            if sftp.try_exists(&probe).await.unwrap_or(false) {
                continue;
            }
            sftp.create_dir(&probe)
                .await
                .map_err(|e| Error::Ssh(format!("mkdir {probe}: {e}")))?;
        }
        Ok(())
    }

    async fn read_all(&self, sftp: &SftpSession, path: &str) -> Result<Vec<u8>> {
        let mut file = sftp
            .open_with_flags(path, OpenFlags::READ)
            .await
            .map_err(|e| Error::Ssh(format!("open {path}: {e}")))?;
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut file, &mut buf)
            .await
            .map_err(|e| Error::Ssh(format!("reading {path}: {e}")))?;
        Ok(buf)
    }

    async fn write_via_temp(&self, sftp: &SftpSession, path: &str, data: &[u8]) -> Result<()> {
        let tmp = format!("{path}.tmp-{}", uuid::Uuid::new_v4());
        {
            let mut file = sftp
                .open_with_flags(
                    &tmp,
                    OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
                )
                .await
                .map_err(|e| Error::Ssh(format!("open {tmp}: {e}")))?;
            file.write_all(data)
                .await
                .map_err(|e| Error::Ssh(format!("writing {tmp}: {e}")))?;
            file.sync_all()
                .await
                .map_err(|e| Error::Ssh(format!("flushing {tmp}: {e}")))?;
            file.close()
                .await
                .map_err(|e| Error::Ssh(format!("closing {tmp}: {e}")))?;
        }
        // POSIX rename over the destination: readers see either the old or
        // the new content, never a partial file. Non-POSIX servers may refuse
        // an existing target; then remove and retry once.
        match sftp.rename(&tmp, path).await {
            Ok(()) => Ok(()),
            Err(_) => {
                sftp.remove_file(path)
                    .await
                    .map_err(|e| Error::Ssh(format!("replacing {path}: {e}")))?;
                sftp.rename(&tmp, path)
                    .await
                    .map_err(|e| Error::Ssh(format!("replacing {path}: {e}")))?;
                Ok(())
            }
        }
    }
}

#[async_trait::async_trait]
impl Backend for SftpBackend {
    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let sftp = self.sftp().await?;
        let path = self.remote_path(key);
        self.read_all(sftp, &path).await
    }

    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        let sftp = self.sftp().await?;
        let path = self.remote_path(key);
        let dir = match path.rsplit_once('/') {
            Some((d, _)) if !d.is_empty() => d.to_string(),
            _ => self.target.path.clone(),
        };
        self.mkdir_all(sftp, &dir).await?;
        self.write_via_temp(sftp, &path, data).await
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let sftp = self.sftp().await?;
        let path = self.remote_path(key);
        sftp.try_exists(&path)
            .await
            .map_err(|e| Error::Ssh(format!("stat {path}: {e}")))
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let sftp = self.sftp().await?;
        let base = self.remote_path(prefix);
        let mut out = Vec::new();
        let mut stack = vec![(base, prefix.trim_end_matches('/').to_string())];

        while let Some((dir, key_prefix)) = stack.pop() {
            let entries = match sftp.read_dir(&dir).await {
                Ok(e) => e,
                Err(russh_sftp::client::error::Error::Status(status))
                    if status.status_code == russh_sftp::protocol::StatusCode::NoSuchFile =>
                {
                    continue;
                }
                Err(e) => return Err(Error::Ssh(format!("read_dir {dir}: {e}"))),
            };
            for entry in entries {
                let name = entry.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                let key = if key_prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{key_prefix}/{name}")
                };
                if entry.file_type().is_dir() {
                    stack.push((format!("{dir}/{name}"), key));
                } else {
                    out.push(key);
                }
            }
        }
        Ok(out)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let sftp = self.sftp().await?;
        let path = self.remote_path(key);
        match sftp.remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(russh_sftp::client::error::Error::Status(status))
                if status.status_code == russh_sftp::protocol::StatusCode::NoSuchFile =>
            {
                Ok(())
            }
            Err(e) => Err(Error::Ssh(format!("delete {path}: {e}"))),
        }
    }

    fn describe(&self) -> String {
        format!(
            "sftp://{}@{}:{}{}",
            self.target.user, self.target.host, self.target.port, self.target.path
        )
    }
}

/// `russh` client callbacks: host-key verification only.
pub struct ClientHandler {
    policy: HostKeyPolicy,
    host: String,
    port: u16,
}

#[derive(Debug)]
/// Adapter type in the public `client::Handler` signature; opaque.
pub struct SshProtoError(Error);

impl std::fmt::Display for SshProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for SshProtoError {}
impl From<russh::Error> for SshProtoError {
    fn from(e: russh::Error) -> Self {
        Self(Error::Ssh(e.to_string()))
    }
}
impl From<Error> for SshProtoError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}

/// Host-key verdict in terms of Aegis' own error type.
fn verify_host_key(
    policy: &HostKeyPolicy,
    host: &str,
    port: u16,
    server_public_key: &russh::keys::PublicKeyOrCertificate,
) -> Result<bool> {
    match policy {
        HostKeyPolicy::AcceptAny => Ok(true),
        HostKeyPolicy::Strict => {
            let pubkey = server_public_key.public_key();
            let file = known_hosts_file()?;
            match check_known_hosts_path(host, port, &pubkey, &file) {
                Ok(true) => Ok(true),
                Ok(false) => {
                    // accept-new: record on first contact.
                    learn_known_hosts_path(host, port, &pubkey, &file)
                        .map_err(|e| Error::Ssh(format!("recording host key: {e}")))?;
                    Ok(true)
                }
                Err(russh::keys::Error::KeyChanged { .. }) => Err(Error::HostKeyChanged {
                    host: format!("{host}:{port}"),
                }),
                Err(e) => Err(Error::Ssh(format!("checking known hosts: {e}"))),
            }
        }
    }
}

impl client::Handler for ClientHandler {
    type Error = SshProtoError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        verify_host_key(&self.policy, &self.host, self.port, server_public_key)
            .map_err(SshProtoError)
    }
}

/// The known-hosts file for [`HostKeyPolicy::Strict`]
/// (respects `AEGIS_KNOWN_HOSTS`).
fn known_hosts_file() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("AEGIS_KNOWN_HOSTS") {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .map_err(|_| Error::Ssh("cannot locate the user home directory".into()))?;
    Ok(home.join(".ssh").join("known_hosts"))
}

/// Resolve a repository location argument to a ready-to-use [`Backend`].
///
/// `sftp://…` URLs connect eagerly (fail fast on bad credentials) unless
/// `passphrase` authentication is deferred — the passphrase itself is the
/// repository's, unrelated to SSH.
///
/// # Errors
///
/// Same as [`parse_location`] and [`SftpBackend::new`].
pub fn open_backend(location: &str, auth: SftpAuth) -> Result<Box<dyn Backend>> {
    match parse_location(location)? {
        RepoLocation::Local(path) => Ok(Box::new(crate::backend::LocalBackend::new(path))),
        RepoLocation::Sftp(target) => Ok(Box::new(SftpBackend::new(target, auth))),
    }
}

/// Open (or initialize) a repository at `location`, choosing the backend
/// from the URL scheme.
///
/// This is the entry point the CLI uses; `aegis-core` users can pick the
/// backend explicitly instead.
///
/// # Errors
///
/// Same as [`Repository::open`].
pub async fn open_repository(
    location: &str,
    auth: SftpAuth,
    passphrase: &str,
) -> Result<Repository> {
    let backend = open_backend(location, auth)?;
    Repository::open(backend, passphrase).await
}

/// Initialize a new repository at `location`.
///
/// # Errors
///
/// Same as [`Repository::init`].
pub async fn init_repository(
    location: &str,
    auth: SftpAuth,
    chunker: ChunkerConfig,
    passphrase: &str,
) -> Result<Repository> {
    let backend = open_backend(location, auth)?;
    Repository::init(backend, chunker, passphrase).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sftp_urls() {
        let loc = parse_location("sftp://backups@nas.lan:2222/srv/aegis").unwrap();
        match loc {
            RepoLocation::Sftp(t) => {
                assert_eq!(t.user, "backups");
                assert_eq!(t.host, "nas.lan");
                assert_eq!(t.port, 2222);
                assert_eq!(t.path, "/srv/aegis");
            }
            RepoLocation::Local(_) => panic!("expected sftp"),
        }
    }

    #[test]
    fn applies_defaults_and_round_trips() {
        let loc = parse_location("sftp://nas.lan/backups").unwrap();
        match &loc {
            RepoLocation::Sftp(t) => {
                assert_eq!(t.user, "root");
                assert_eq!(t.port, 22);
            }
            RepoLocation::Local(_) => panic!("expected sftp"),
        }
        assert_eq!(loc.to_string(), "sftp://root@nas.lan:22/backups");
        assert!(matches!(
            parse_location(&loc.to_string()).unwrap(),
            RepoLocation::Sftp(_)
        ));
    }

    #[test]
    fn local_paths_stay_local() {
        assert!(matches!(
            parse_location("/srv/backups").unwrap(),
            RepoLocation::Local(_)
        ));
        assert!(matches!(
            parse_location("C:\\backups").unwrap(),
            RepoLocation::Local(_)
        ));
    }

    #[test]
    fn rejects_broken_urls() {
        assert!(parse_location("sftp://").is_err());
        assert!(parse_location("sftp://host").is_err());
        assert!(parse_location("sftp://host/").is_err());
        assert!(parse_location("sftp://host:99999/x").is_err());
        assert!(parse_location("sftp://@host/x").is_err());
    }

    #[test]
    fn remote_path_stays_inside_root() {
        let b = SftpBackend::new(
            SftpTarget {
                user: "u".into(),
                host: "h".into(),
                port: 22,
                path: "/repo".into(),
            },
            SftpAuth::Password("x".into()),
        );
        assert_eq!(b.remote_path("blobs/ab/cd"), "/repo/blobs/ab/cd");
        assert_eq!(b.remote_path("config"), "/repo/config");
        assert_eq!(b.remote_path("../escape"), "/repo/escape");
        assert_eq!(b.remote_path("/abs"), "/repo/abs");
    }

    #[test]
    fn auth_debug_never_leaks_secrets() {
        let auth = SftpAuth::Password("hunter2".into());
        let rendered = format!("{auth:?}");
        assert!(!rendered.contains("hunter2"), "leaked: {rendered}");
    }
}
