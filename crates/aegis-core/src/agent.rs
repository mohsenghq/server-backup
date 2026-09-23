//! Agent mode (`docs/04-host-connection-modes.md`): the opt-in, auto-provisioned
//! counterpart to the agentless path.
//!
//! Two halves:
//!
//! * [`backup_local_into`] — what runs ON the target: chunk/hash local files at
//!   the source and ship only chunks the repository lacks. Used by the
//!   `aegis-agent` binary.
//!
//! * [`push_and_run`] — what the control plane does: detect the target's
//!   OS/arch over the existing SSH session, upload a matching `aegis-agent`
//!   binary via SFTP, and run `agent --once` remotely. A target that can't
//!   run the agent (restricted shell, unsupported arch, missing binary)
//!   returns [`AgentError::Unsupported`], which callers turn into a
//!   transparent agentless fallback.

use std::path::{Path, PathBuf};

use crate::chunk::ChunkerConfig;
use crate::error::{Error, Result};
use crate::repo::Repository;
use crate::snapshot::Snapshot;
use crate::ssh::SshManager;

/// Why a target can't run the agent; callers fall back to agentless mode.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// The remote OS/arch has no matching agent binary, or the remote
    /// refused to execute it.
    #[error("target cannot run the agent: {0}")]
    Unsupported(String),
    /// Transport or remote execution failed in a way worth reporting.
    #[error("agent run failed: {0}")]
    Failed(String),
}

impl From<AgentError> for Error {
    fn from(e: AgentError) -> Self {
        match e {
            AgentError::Unsupported(m) | AgentError::Failed(m) => Error::Ssh(m),
        }
    }
}

/// The agent-side half: back up local `paths` into a repository the agent
/// reaches directly (local dir or `sftp://` URL). Chunking and hashing happen
/// at the source; only chunks the repository lacks are written back.
///
/// # Errors
///
/// Repository open/backup failures propagate.
pub async fn backup_local_into(
    repo_location: &str,
    passphrase: &str,
    paths: &[PathBuf],
    chunker: &ChunkerConfig,
) -> Result<Snapshot> {
    let repo = if repo_location.starts_with("sftp://") {
        let auth = crate::sftp::SftpAuth::from_env()?;
        match crate::sftp::open_repository(repo_location, auth, passphrase).await {
            Ok(repo) => repo,
            // A repo the agent can't open yet is initialized in place.
            Err(Error::RepoNotFound(_)) => {
                let auth = crate::sftp::SftpAuth::from_env()?;
                crate::sftp::init_repository(repo_location, auth, *chunker, passphrase).await?
            }
            Err(e) => return Err(e),
        }
    } else {
        match Repository::open_local(repo_location, passphrase).await {
            Ok(repo) => repo,
            Err(Error::RepoNotFound(_)) => {
                Repository::init_local(repo_location, *chunker, passphrase).await?
            }
            Err(e) => return Err(e),
        }
    };
    repo.backup(paths).await
}

/// The control-plane half: detect the target platform over SSH, upload the
/// matching agent binary, and run one backup remotely.
///
/// `agent_bin_dir` holds pre-built binaries named
/// `aegis-agent-<os>-<arch>` (CI artifacts); the remote invocation mirrors
/// `aegis-agent --once --repo <sftp://…> --path …`. The repo location passed
/// to the agent must be reachable FROM THE TARGET — in practice an `sftp://`
/// URL the agent itself can authenticate against (keys for the agent live on
/// the target, or the target IS the repo host).
///
/// Returns the agent's printed `snapshot <id>` line.
///
/// # Errors
///
/// [`AgentError::Unsupported`] when the platform has no matching binary or
/// the remote cannot execute it; [`AgentError::Failed`] for other failures.
pub async fn push_and_run(
    ssh: &SshManager,
    host: &crate::ssh::HostConfig,
    agent_bin_dir: &Path,
    repo_location: &str,
    passphrase: &str,
    paths: &[String],
) -> std::result::Result<String, AgentError> {
    // 1. Detect the target OS/arch (`uname` covers Linux/macOS; for Windows
    //    targets the agent path is out of scope for now).
    let uname = ssh
        .exec_check(host, "uname -s -m")
        .await
        .map_err(|e| AgentError::Unsupported(format!("uname: {e}")))?;
    let uname_out = String::from_utf8_lossy(&uname.stdout).trim().to_string();
    let platform = platform_of(&uname_out)
        .ok_or_else(|| AgentError::Unsupported(format!("unknown platform: {uname_out}")))?;

    // 2. Upload the matching binary to a temp path.
    let local_bin = agent_bin_dir.join(format!("aegis-agent-{platform}"));
    let bytes = std::fs::read(&local_bin).map_err(|e| {
        AgentError::Unsupported(format!(
            "no agent binary for {platform} at {}: {e}",
            local_bin.display()
        ))
    })?;
    let remote_bin = format!("/tmp/aegis-agent-{}", std::process::id());
    upload(ssh, host, &remote_bin, &bytes).await?;

    // 3. chmod +x and run one backup remotely.
    let chmod = format!("chmod 700 {}", shell_quote(&remote_bin));
    ssh.exec_check(host, &chmod)
        .await
        .map_err(|e| AgentError::Failed(format!("chmod: {e}")))?;

    let mut cmd = format!(
        "{} --once --repo {} --passphrase {}",
        shell_quote(&remote_bin),
        shell_quote(repo_location),
        shell_quote(passphrase),
    );
    for p in paths {
        cmd.push_str(&format!(" --path {}", shell_quote(p)));
    }
    let run = ssh
        .exec(host, &cmd)
        .await
        .map_err(|e| AgentError::Failed(format!("agent exec: {e}")))?;
    // Best-effort cleanup regardless of outcome.
    let _ = ssh
        .exec(host, &format!("rm -f {}", shell_quote(&remote_bin)))
        .await;

    if !run.success() {
        // 127 = command not found: the binary didn't run on this target.
        if run.exit_code == Some(127) {
            return Err(AgentError::Unsupported(format!(
                "agent not executable: {}",
                String::from_utf8_lossy(&run.stderr)
            )));
        }
        return Err(AgentError::Failed(format!(
            "agent exited {:?}: {}",
            run.exit_code,
            String::from_utf8_lossy(&run.stderr)
        )));
    }

    // 4. Extract the snapshot id from the agent's last stdout line.
    let stdout = String::from_utf8_lossy(&run.stdout);
    stdout
        .lines()
        .rev()
        .find_map(|l| l.strip_prefix("snapshot "))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| AgentError::Failed(format!("agent printed no snapshot id: {stdout}")))
}

/// Map `uname -s -m` output to the platform tag used for agent binaries.
fn platform_of(uname: &str) -> Option<&'static str> {
    let mut parts = uname.split_whitespace();
    let os = parts.next()?;
    let arch = parts.next()?;
    match (os, arch) {
        ("Linux", "x86_64") => Some("linux-x86_64"),
        ("Linux", "aarch64") | ("Linux", "arm64") => Some("linux-aarch64"),
        ("Darwin", "x86_64") => Some("macos-x86_64"),
        ("Darwin", "arm64") => Some("macos-aarch64"),
        _ => None,
    }
}

/// Upload bytes to a remote path over the SSH connection's SFTP channel.
async fn upload(
    ssh: &SshManager,
    host: &crate::ssh::HostConfig,
    remote_path: &str,
    bytes: &[u8],
) -> std::result::Result<(), AgentError> {
    let sftp = ssh
        .sftp_channel(host)
        .await
        .map_err(|e| AgentError::Failed(format!("sftp channel: {e}")))?;
    let file = sftp
        .create(remote_path)
        .await
        .map_err(|e| AgentError::Failed(format!("create {remote_path}: {e}")))?;
    use tokio::io::AsyncWriteExt;
    let mut file = file;
    file.write_all(bytes)
        .await
        .map_err(|e| AgentError::Failed(format!("write {remote_path}: {e}")))?;
    file.shutdown()
        .await
        .map_err(|e| AgentError::Failed(format!("close {remote_path}: {e}")))?;
    Ok(())
}

/// Quote a string for POSIX shell consumption.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_uname_output() {
        assert_eq!(platform_of("Linux x86_64"), Some("linux-x86_64"));
        assert_eq!(platform_of("Linux aarch64"), Some("linux-aarch64"));
        assert_eq!(platform_of("Darwin arm64"), Some("macos-aarch64"));
        assert_eq!(platform_of("Windows NT"), None);
        assert_eq!(platform_of(""), None);
    }

    #[test]
    fn quotes_shell_words() {
        assert_eq!(shell_quote("abc"), "'abc'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
