//! `aegis` — the Aegis command-line interface.
//!
//! The CLI is the product: every capability the server, web UI, desktop apps,
//! and MCP server expose must exist here first, and the CLI must stay fully
//! usable with nothing else running (`docs/01-architecture.md`).
//!
//! Passphrases are never accepted on argv: use `AEGIS_PASSPHRASE` (or type
//! one when prompted). On `init` the passphrase is confirmed interactively
//! when no environment variable is set.

use std::path::PathBuf;

use aegis_core::backend::Backend;
use aegis_core::sftp::{HostKeyPolicy, RepoLocation, SftpAuth, SftpBackend};
use aegis_core::{ChunkerConfig, LocalBackend, PassphraseSource, Repository};
use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};

/// Self-hosted, deduplicating, multi-server backup.
#[derive(Parser)]
#[command(name = "aegis", version, about, long_about = None)]
struct Cli {
    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    /// How to authenticate to `sftp://` repositories.
    #[command(flatten)]
    ssh: SshArgs,

    #[command(subcommand)]
    command: Command,
}

/// SSH options, usable with any command that takes a repository location.
/// A repository location is a local directory or an
/// `sftp://[user@]host[:port]/path` URL.
#[derive(Args, Clone)]
struct SshArgs {
    /// SSH user for `sftp://` repositories (overrides the URL's user part).
    #[arg(long, global = true, value_name = "USER")]
    ssh_user: Option<String>,

    /// Authenticate with a password: taken from `AEGIS_SSH_PASSWORD`, or
    /// prompted. Default when no key material is available.
    #[arg(long, global = true)]
    ssh_password: bool,

    /// Authenticate with this private key (OpenSSH format). Defaults to
    /// trying `~/.ssh/id_ed25519` and `~/.ssh/id_rsa`.
    #[arg(long, global = true, value_name = "FILE")]
    ssh_key: Option<PathBuf>,

    /// Passphrase for an encrypted `--ssh-key`: `AEGIS_SSH_KEY_PASSPHRASE`,
    /// or a prompt when the flag is given.
    #[arg(long, global = true)]
    ssh_key_passphrase: bool,

    /// Accept any server host key without checking known_hosts. This
    /// disables man-in-the-middle protection; use only for tests.
    #[arg(long, global = true)]
    insecure_accept_host_key: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new, empty (encrypted) repository.
    Init {
        /// Directory to create the repository in, or an
        /// `sftp://[user@]host[:port]/path` URL.
        #[arg(long, value_name = "LOCATION")]
        repo: String,

        /// Minimum chunk size in bytes. Fixed for the life of the repository.
        #[arg(long, value_name = "BYTES", default_value_t = aegis_core::chunk::DEFAULT_MIN_SIZE)]
        min_chunk_size: usize,

        /// Target average chunk size in bytes. Fixed for the life of the repository.
        #[arg(long, value_name = "BYTES", default_value_t = aegis_core::chunk::DEFAULT_AVG_SIZE)]
        avg_chunk_size: usize,

        /// Maximum chunk size in bytes. Fixed for the life of the repository.
        #[arg(long, value_name = "BYTES", default_value_t = aegis_core::chunk::DEFAULT_MAX_SIZE)]
        max_chunk_size: usize,
    },

    /// Add another passphrase that can open this repository. Data is not
    /// re-encrypted: the existing master key is wrapped under the new
    /// passphrase into a new key slot.
    KeyAdd {
        /// Repository to add the key to.
        #[arg(long, value_name = "LOCATION")]
        repo: String,
    },

    /// Back up one or more paths into a repository as a new snapshot.
    Backup {
        /// Files or directories to back up.
        #[arg(value_name = "PATH", required = true)]
        paths: Vec<PathBuf>,

        /// Repository to write the snapshot into.
        #[arg(long, value_name = "LOCATION")]
        repo: String,
    },

    /// List the snapshots in a repository, newest first.
    Snapshots {
        /// Repository to read.
        #[arg(long, value_name = "LOCATION")]
        repo: String,
    },

    /// Restore a snapshot's files into a target directory.
    Restore {
        /// Snapshot id, or any unambiguous prefix of one.
        #[arg(long, value_name = "ID")]
        snapshot: String,

        /// Repository to read the snapshot from.
        #[arg(long, value_name = "LOCATION")]
        repo: String,

        /// Directory to restore into. Created if it does not exist.
        #[arg(long, value_name = "PATH")]
        target: PathBuf,
    },

    /// Apply retention rules and garbage-collect unreferenced blobs. The
    /// only destructive command: run with --dry-run first to see what would
    /// be removed.
    Prune {
        /// Repository to prune.
        #[arg(long, value_name = "LOCATION")]
        repo: String,

        /// Show what would be deleted without deleting anything.
        #[arg(long)]
        dry_run: bool,

        /// Keep the newest snapshot of each of the last N calendar days.
        #[arg(long, value_name = "N", default_value_t = 7)]
        keep_daily: u32,

        /// Keep the newest snapshot of each of the last N ISO weeks.
        #[arg(long, value_name = "N", default_value_t = 4)]
        keep_weekly: u32,

        /// Keep the newest snapshot of each of the last N calendar months.
        #[arg(long, value_name = "N", default_value_t = 6)]
        keep_monthly: u32,

        /// Always keep the N most recent snapshots, however old.
        #[arg(long, value_name = "N", default_value_t = 3)]
        keep_last: u32,
    },

    /// Check a snapshot's integrity. Shallow (default) confirms every
    /// referenced blob is present and the manifest's tree hash matches;
    /// --deep additionally downloads and re-derives all of them.
    Verify {
        /// Repository to check.
        #[arg(long, value_name = "LOCATION")]
        repo: String,

        /// Snapshot id, or any unambiguous prefix of one. Omit to verify the
        /// newest snapshot.
        #[arg(long, value_name = "ID")]
        snapshot: Option<String>,

        /// Re-derive every blob: download chunks and tree nodes, authenticate,
        /// decompress/decrypt, and re-check their hashes.
        #[arg(long)]
        deep: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init {
            repo,
            min_chunk_size,
            avg_chunk_size,
            max_chunk_size,
        } => {
            let chunker = ChunkerConfig::new(min_chunk_size, avg_chunk_size, max_chunk_size)?;
            let pass = load_passphrase(PassphraseSource::Prompt { confirm: true })
                .context("loading a passphrase for the new repository")?;
            let backend = open_backend(&cli.ssh, &repo)?;
            let r = Repository::init(backend, chunker, &pass)
                .await
                .with_context(|| format!("initializing repository at {repo}"))?;
            emit(
                cli.json,
                &serde_json::json!({ "repository": repo, "id": r.config().id }),
                || {
                    println!(
                        "initialized encrypted repository {} at {repo}",
                        r.config().id
                    )
                },
            );
        }

        Command::KeyAdd { repo } => {
            let existing = load_passphrase(PassphraseSource::default())
                .context("loading the repository's current passphrase")?;
            let new_pass =
                aegis_core::keys::load_new_passphrase().context("loading the new passphrase")?;
            let backend = open_backend(&cli.ssh, &repo)?;
            let r = aegis_core::keys::key_add_backend(backend, &existing, &new_pass)
                .await
                .with_context(|| format!("adding a key to {repo}"))?;
            emit(
                cli.json,
                &serde_json::json!({ "repository": repo, "key_slot": r }),
                || println!("added key slot '{r}' — both passphrases now open this repository"),
            );
        }

        Command::Backup { paths, repo } => {
            let r = open(&cli.ssh, &repo).await?;
            let snapshot = r.backup(&paths).await.context("running backup")?;
            let s = snapshot.stats;
            emit(
                cli.json,
                &serde_json::json!({
                    "id": snapshot.id,
                    "time": snapshot.time,
                    "hostname": snapshot.hostname,
                    "paths": snapshot.paths,
                    "root_hash": snapshot.root_hash(),
                    "stats": s,
                }),
                || {
                    println!(
                        "snapshot {} (tree {})\n  {} files, {} read, {} chunks ({} new, {} written, {} tree nodes)",
                        snapshot.short_id(),
                        &snapshot.root_hash()[..16],
                        s.files,
                        human_bytes(s.bytes),
                        s.chunks,
                        s.new_chunks,
                        human_bytes(s.new_bytes),
                        s.new_tree_nodes,
                    );
                },
            );
        }

        Command::Snapshots { repo } => {
            let r = open(&cli.ssh, &repo).await?;
            let snapshots = r.list_snapshots().await.context("listing snapshots")?;
            emit(cli.json, &snapshots, || {
                if snapshots.is_empty() {
                    println!("no snapshots in {repo}");
                    return;
                }
                println!(
                    "{:<10}  {:<20}  {:<16}  {:>7}  {:>9}  PATHS",
                    "ID", "TIME", "HOST", "FILES", "SIZE"
                );
                for s in &snapshots {
                    println!(
                        "{:<10}  {:<20}  {:<16}  {:>7}  {:>9}  {}",
                        s.short_id(),
                        s.display_time(),
                        s.hostname,
                        s.stats.files,
                        human_bytes(s.stats.bytes),
                        s.paths.join(", "),
                    );
                }
            });
        }

        Command::Restore {
            snapshot,
            repo,
            target,
        } => {
            let r = open(&cli.ssh, &repo).await?;
            let s = r
                .restore(&snapshot, &target)
                .await
                .with_context(|| format!("restoring snapshot {snapshot}"))?;
            emit(
                cli.json,
                &serde_json::json!({ "snapshot": s.id, "target": target, "files": s.stats.files }),
                || {
                    println!(
                        "restored {} files from snapshot {} into {}",
                        s.stats.files,
                        s.short_id(),
                        target.display()
                    );
                },
            );
        }

        Command::Prune {
            repo,
            dry_run,
            keep_daily,
            keep_weekly,
            keep_monthly,
            keep_last,
        } => {
            let r = open(&cli.ssh, &repo).await?;
            let policy = aegis_core::retention::RetentionPolicy {
                keep_daily,
                keep_weekly,
                keep_monthly,
                keep_last,
            };
            let report = r
                .prune(&policy, dry_run)
                .await
                .context("pruning repository")?;
            emit(cli.json, &report, || {
                if dry_run {
                    println!(
                        "dry run — {} snapshot(s) and {} blob(s) would be removed:",
                        report.deleted_snapshots.len(),
                        report.deleted_blobs.len()
                    );
                } else {
                    println!(
                        "pruned {} snapshot(s) and {} blob(s) ({})",
                        report.deleted_snapshots.len(),
                        report.deleted_blobs.len(),
                        human_bytes(report.deleted_blob_bytes)
                    );
                }
                println!(
                    "kept {} snapshot(s): {}",
                    report.kept_snapshots.len(),
                    if report.kept_snapshots.is_empty() {
                        "none".to_string()
                    } else {
                        report
                            .kept_snapshots
                            .iter()
                            .map(|id| id[..8.min(id.len())].to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                );
            });
        }

        Command::Verify {
            repo,
            snapshot,
            deep,
        } => {
            let r = open(&cli.ssh, &repo).await?;
            let s = match snapshot {
                Some(id) => r
                    .find_snapshot(&id)
                    .await
                    .with_context(|| format!("finding snapshot {id}"))?,
                None => r
                    .list_snapshots()
                    .await
                    .context("listing snapshots")?
                    .into_iter()
                    .next()
                    .context(anyhow!("repository has no snapshots to verify"))?,
            };
            let report = r
                .verify(&s, deep)
                .await
                .context("verifying snapshot integrity")?;
            emit(cli.json, &report, || {
                println!(
                    "{} check of snapshot {}: OK — {} files, {} chunks, {} tree blobs",
                    if deep { "deep" } else { "shallow" },
                    s.short_id(),
                    report.files,
                    report.chunks,
                    report.tree_blobs
                );
            });
        }
    }
    Ok(())
}

/// Passphrase policy for commands operating on an existing repository.
fn load_passphrase(source: PassphraseSource) -> Result<String> {
    aegis_core::keys::load_passphrase(&source).map_err(Into::into)
}

/// Build the [`Backend`] for a repository location: a local path or an
/// `sftp://` URL (which connects and authenticates eagerly).
fn open_backend(ssh: &SshArgs, location: &str) -> Result<Box<dyn Backend>> {
    match aegis_core::sftp::parse_location(location)? {
        RepoLocation::Local(path) => Ok(Box::new(LocalBackend::new(path))),
        RepoLocation::Sftp(mut target) => {
            if let Some(user) = &ssh.ssh_user {
                target.user = user.clone();
            }
            let auth = ssh_auth(ssh, location)?;
            let policy = if ssh.insecure_accept_host_key {
                HostKeyPolicy::AcceptAny
            } else {
                HostKeyPolicy::Strict
            };
            let backend = SftpBackend::new(target, auth).with_host_key_policy(policy);
            Ok(Box::new(backend))
        }
    }
}

/// Resolve the SSH authentication method from CLI flags and environment.
fn ssh_auth(ssh: &SshArgs, location: &str) -> Result<SftpAuth> {
    if let Some(path) = &ssh.ssh_key {
        let key_passphrase = if ssh.ssh_key_passphrase {
            Some(
                std::env::var("AEGIS_SSH_KEY_PASSPHRASE").unwrap_or_else(|_| {
                    rpassword::prompt_password("SSH key passphrase: ").unwrap_or_default()
                }),
            )
        } else {
            None
        };
        return Ok(SftpAuth::KeyFile {
            path: path.clone(),
            key_passphrase,
        });
    }
    if ssh.ssh_password {
        let password = std::env::var("AEGIS_SSH_PASSWORD")
            .map_err(|_| anyhow!("--ssh-password set but AEGIS_SSH_PASSWORD is not"))?;
        return Ok(SftpAuth::Password(password));
    }
    // Defaults: a default key file if one exists, otherwise a password from
    // the environment.
    if let Some(home) = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
    {
        for name in ["id_ed25519", "id_rsa"] {
            let path = PathBuf::from(&home).join(".ssh").join(name);
            if path.exists() {
                return Ok(SftpAuth::KeyFile {
                    path,
                    key_passphrase: None,
                });
            }
        }
    }
    if let Ok(password) = std::env::var("AEGIS_SSH_PASSWORD") {
        return Ok(SftpAuth::Password(password));
    }
    Err(anyhow!(
        "no SSH authentication available for {location}: pass --ssh-password with \
         AEGIS_SSH_PASSWORD, or --ssh-key FILE"
    ))
}

async fn open(ssh: &SshArgs, repo: &str) -> Result<Repository> {
    let pass = load_passphrase(PassphraseSource::default())?;
    let backend = open_backend(ssh, repo)?;
    Repository::open(backend, &pass)
        .await
        .with_context(|| format!("opening repository at {repo}"))
}

/// Print `value` as JSON, or run `human` for the text rendering.
fn emit<T: serde::Serialize>(json: bool, value: &T, human: impl FnOnce()) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(value).expect("CLI output is serializable")
        );
    } else {
        human();
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit + 1 < UNITS.len() {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn formats_byte_counts() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
    }
}
