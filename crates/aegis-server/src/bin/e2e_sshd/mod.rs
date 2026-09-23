//! Re-export of the in-process SSH server harness shared with aegis-core's
//! integration tests, for the standalone E2E sshd binary.

#[path = "../../../../aegis-core/tests/sftp_server.rs"]
pub mod sftp_server;

pub use sftp_server::spawn_sftp_server_on;
