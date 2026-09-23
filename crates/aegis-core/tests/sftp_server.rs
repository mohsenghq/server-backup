//! An in-process SSH + SFTP server for backend tests.
//!
//! Serves a local directory over a real russh transport on 127.0.0.1 so
//! [`aegis_core::sftp::SftpBackend`] is exercised end-to-end — connect,
//! authenticate, host-key check, subsystem negotiation and the SFTP protocol
//! itself — without external sshd.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{HashAlg, PrivateKeyWithHashAlg};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};

use aegis_core::error::{Error, Result};

/// Fixed ed25519 host key for the test server (unencrypted OpenSSH format).
pub const HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACC9TVs/jQWvtsDXqcYInOOSTjuIsy4OomHaPeT4m71vGgAAAJijmckyo5nJ\nMgAAAAtzc2gtZWQyNTUxOQAAACC9TVs/jQWvtsDXqcYInOOSTjuIsy4OomHaPeT4m71vGg\nAAAEDTuc6nRY8eMWXUYUjQvxc/9EyVJ/OuUPgKmDB9r/Zi171NWz+NBa+2wNepxgic45JO\nO4izLg6iYdo95PibvW8aAAAAD2FlZ2lzLXRlc3QtaG9zdAECAwQFBg==\n-----END OPENSSH PRIVATE KEY-----";

/// The only accepted username.
pub const USERNAME: &str = "aegis-test";
/// The only accepted password.
pub const PASSWORD: &str = "test-passphrase";

/// Spawn the server on a free port, serving `root`, and return the port.
pub async fn spawn_sftp_server(root: PathBuf) -> Result<u16> {
    spawn_sftp_server_on("127.0.0.1:0", root).await
}

/// Spawn the server on an explicit address (e.g. a fixed E2E port).
pub async fn spawn_sftp_server_on(addr: &str, root: PathBuf) -> Result<u16> {
    let host_key = russh::keys::decode_secret_key(HOST_KEY, None)
        .map_err(|e| Error::Ssh(format!("decoding test host key: {e}")))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Ssh(format!("binding test server: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::Ssh(format!("resolving test port: {e}")))?
        .port();

    let config = Arc::new(russh::server::Config {
        keys: vec![host_key],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        ..russh::server::Config::default()
    });

    struct Acceptor {
        root: PathBuf,
    }
    impl russh::server::Server for Acceptor {
        type Handler = ConnHandler;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
            ConnHandler {
                root: self.root.clone(),
                parked: tokio::sync::Mutex::new(HashMap::new()),
            }
        }
    }

    // The server lives for the whole test process; leak its state so the
    // spawned future is 'static.
    let acceptor: &'static mut Acceptor = Box::leak(Box::new(Acceptor { root }));
    let listener: &'static tokio::net::TcpListener = Box::leak(Box::new(listener));
    let running = russh::server::Server::run_on_socket(acceptor, config, listener);
    tokio::spawn(running);

    Ok(port)
}

/// One SSH connection: authenticates, parks session channels, and spawns an
/// SFTP handler when the client requests the `sftp` subsystem.
struct ConnHandler {
    root: PathBuf,
    parked: tokio::sync::Mutex<HashMap<russh::ChannelId, russh::Channel<russh::server::Msg>>>,
}

/// Adapter: russh handlers must accept `russh::Error` via `From`.
#[derive(Debug)]
struct ServerError(Error);

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ServerError {}
impl From<russh::Error> for ServerError {
    fn from(e: russh::Error) -> Self {
        Self(Error::Ssh(e.to_string()))
    }
}
impl From<Error> for ServerError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}

impl russh::server::Handler for ConnHandler {
    type Error = ServerError;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> std::result::Result<russh::server::Auth, Self::Error> {
        Ok(if user == USERNAME && password == PASSWORD {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            }
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> std::result::Result<(), Self::Error> {
        let _ = reply.accept().await;
        self.parked.lock().await.insert(channel.id(), channel);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> std::result::Result<(), Self::Error> {
        // The in-process server has no shell; "run" the command by echoing
        // it to stdout and exiting 0. Enough to exercise the exec message
        // path end-to-end (request → stdout → exit-status → close).
        session
            .channel_success(channel)
            .map_err(ServerError::from)?;
        let _ = session.data(channel, data.to_vec());
        session
            .exit_status_request(channel, 0)
            .map_err(ServerError::from)?;
        session.eof(channel).map_err(ServerError::from)?;
        session.close(channel).map_err(ServerError::from)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: russh::ChannelId,
        name: &str,
        session: &mut russh::server::Session,
    ) -> std::result::Result<(), Self::Error> {
        if name != "sftp" {
            session
                .channel_failure(channel)
                .map_err(ServerError::from)?;
            return Ok(());
        }
        let parked = self
            .parked
            .lock()
            .await
            .remove(&channel)
            .ok_or_else(|| ServerError(Error::Ssh("no parked channel".into())))?;
        session
            .channel_success(channel)
            .map_err(ServerError::from)?;
        russh_sftp::server::run(
            parked.into_stream(),
            SftpFs {
                root: self.root.clone(),
                handles: HashMap::new(),
            },
        )
        .await;
        Ok(())
    }
}

/// Serves filesystem operations, jailed inside the repository root.
struct SftpFs {
    root: PathBuf,
    handles: HashMap<String, OpenTarget>,
}

enum OpenTarget {
    Read(std::fs::File),
    Write(std::fs::File),
    Dir { path: PathBuf, listing_sent: bool },
}

impl SftpFs {
    fn resolve(&self, path: &str) -> PathBuf {
        let mut out = self.root.clone();
        for seg in path
            .split('/')
            .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        {
            out.push(seg);
        }
        out
    }

    fn ok(id: u32) -> Status {
        Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        }
    }

    fn attrs_of(meta: std::fs::Metadata) -> FileAttributes {
        let mut attrs = FileAttributes {
            size: Some(meta.len()),
            ..Default::default()
        };
        if let Ok(mtime) = meta.modified() {
            if let Ok(d) = mtime.duration_since(std::time::UNIX_EPOCH) {
                attrs.mtime = Some(u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
            }
        }
        attrs.set_dir(meta.is_dir());
        attrs.set_regular(meta.is_file());
        attrs
    }

    fn list_dir(path: &Path) -> Vec<File> {
        let mut files = Vec::new();
        let Ok(entries) = std::fs::read_dir(path) else {
            return files;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let longname = name.clone();
            files.push(File {
                filename: name,
                longname,
                attrs: Self::attrs_of(entry.metadata().unwrap_or_else(|_| {
                    std::fs::metadata(path).unwrap_or_else(|_| std::fs::metadata(".").unwrap())
                })),
            });
        }
        files
    }
}

impl russh_sftp::server::Handler for SftpFs {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> std::result::Result<Version, Self::Error> {
        // Advertise no extensions: the client falls back to defaults
        // (no fsync, no limits), keeping this server minimal.
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> std::result::Result<Handle, Self::Error> {
        let path = self.resolve(&filename);
        if pflags.contains(OpenFlags::WRITE) {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|_| StatusCode::PermissionDenied)?;
            }
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(pflags.contains(OpenFlags::CREATE))
                .truncate(pflags.contains(OpenFlags::TRUNCATE))
                .open(&path)
                .map_err(|_| StatusCode::NoSuchFile)?;
            let handle = uuid::Uuid::new_v4().to_string();
            self.handles.insert(handle.clone(), OpenTarget::Write(file));
            Ok(Handle { id, handle })
        } else {
            let file = std::fs::File::open(&path).map_err(|_| StatusCode::NoSuchFile)?;
            let handle = uuid::Uuid::new_v4().to_string();
            self.handles.insert(handle.clone(), OpenTarget::Read(file));
            Ok(Handle { id, handle })
        }
    }

    async fn close(&mut self, id: u32, handle: String) -> std::result::Result<Status, Self::Error> {
        self.handles.remove(&handle);
        Ok(Self::ok(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> std::result::Result<Data, Self::Error> {
        use std::io::{Read, Seek, SeekFrom};
        let Some(OpenTarget::Read(file)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::NoSuchFile);
        };
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| StatusCode::Failure)?;
        let mut buf = vec![0u8; len as usize];
        let n = file.read(&mut buf).map_err(|_| StatusCode::Failure)?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> std::result::Result<Status, Self::Error> {
        use std::io::{Seek, SeekFrom, Write};
        let Some(OpenTarget::Write(file)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::NoSuchFile);
        };
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| StatusCode::Failure)?;
        file.write_all(&data).map_err(|_| StatusCode::Failure)?;
        Ok(Self::ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> std::result::Result<Handle, Self::Error> {
        let p = self.resolve(&path);
        if !p.is_dir() {
            return Err(StatusCode::NoSuchFile);
        }
        let handle = uuid::Uuid::new_v4().to_string();
        self.handles.insert(
            handle.clone(),
            OpenTarget::Dir {
                path: p,
                listing_sent: false,
            },
        );
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> std::result::Result<Name, Self::Error> {
        let Some(OpenTarget::Dir { path, listing_sent }) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::NoSuchFile);
        };
        // First call: return the listing. Subsequent calls: EOF. (The
        // client's read_dir loops until it sees an EOF status.)
        if *listing_sent {
            return Err(StatusCode::Eof);
        }
        *listing_sent = true;
        Ok(Name {
            id,
            files: Self::list_dir(path),
        })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> std::result::Result<Status, Self::Error> {
        std::fs::create_dir(self.resolve(&path)).map_err(|_| StatusCode::Failure)?;
        Ok(Self::ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> std::result::Result<Status, Self::Error> {
        std::fs::remove_dir(self.resolve(&path)).map_err(|_| StatusCode::Failure)?;
        Ok(Self::ok(id))
    }

    async fn remove(&mut self, id: u32, path: String) -> std::result::Result<Status, Self::Error> {
        match std::fs::remove_file(self.resolve(&path)) {
            Ok(()) => Ok(Self::ok(id)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StatusCode::NoSuchFile),
            Err(_) => Err(StatusCode::Failure),
        }
    }

    async fn realpath(&mut self, id: u32, path: String) -> std::result::Result<Name, Self::Error> {
        let joined = self.resolve(&path);
        Ok(Name {
            id,
            files: vec![File::dummy(joined.to_string_lossy().into_owned())],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> std::result::Result<Attrs, Self::Error> {
        let meta = std::fs::metadata(self.resolve(&path)).map_err(|_| StatusCode::NoSuchFile)?;
        Ok(Attrs {
            id,
            attrs: Self::attrs_of(meta),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> std::result::Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> std::result::Result<Attrs, Self::Error> {
        let target = self.handles.get(&handle).ok_or(StatusCode::NoSuchFile)?;
        let meta = match target {
            OpenTarget::Read(f) | OpenTarget::Write(f) => {
                f.metadata().map_err(|_| StatusCode::Failure)?
            }
            OpenTarget::Dir { path, .. } => {
                std::fs::metadata(path).map_err(|_| StatusCode::Failure)?
            }
        };
        Ok(Attrs {
            id,
            attrs: Self::attrs_of(meta),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        _path: String,
        _attrs: FileAttributes,
    ) -> std::result::Result<Status, Self::Error> {
        Ok(Self::ok(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        _handle: String,
        _attrs: FileAttributes,
    ) -> std::result::Result<Status, Self::Error> {
        Ok(Self::ok(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> std::result::Result<Status, Self::Error> {
        match std::fs::rename(self.resolve(&oldpath), self.resolve(&newpath)) {
            Ok(()) => Ok(Self::ok(id)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StatusCode::NoSuchFile),
            Err(_) => Err(StatusCode::Failure),
        }
    }
}

/// A convenience constructor used by the tests: an authenticated backend
/// pointing at a freshly spawned in-process server.
#[allow(dead_code)]
pub async fn connected_backend(root: PathBuf) -> Result<(aegis_core::sftp::SftpBackend, u16)> {
    use aegis_core::sftp::{HostKeyPolicy, SftpAuth, SftpBackend, SftpTarget};

    let port = spawn_sftp_server(root.clone()).await?;
    let backend = SftpBackend::new(
        SftpTarget {
            user: USERNAME.to_string(),
            host: "127.0.0.1".to_string(),
            port,
            path: root.to_string_lossy().into_owned(),
        },
        SftpAuth::Password(PASSWORD.to_string()),
    )
    .with_host_key_policy(HostKeyPolicy::AcceptAny);
    Ok((backend, port))
}

// Keep the auth-key path importable for tests that exercise it.
#[allow(unused_imports)]
use russh::keys::PrivateKey as _PrivateKeyForTests;

#[allow(dead_code)]
fn hash_alg_is_available() -> HashAlg {
    HashAlg::Sha256
}

#[allow(dead_code)]
fn wrap_key(key: russh::keys::PrivateKey) -> PrivateKeyWithHashAlg {
    PrivateKeyWithHashAlg::new(std::sync::Arc::new(key), Some(HashAlg::Sha256))
}
