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

pub mod hosts;
mod policy;
mod users;

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
    #[command(about = "Manage local administrators of the control plane")]
    User(users::UserArgs),
    #[command(about = "Create, inspect, or revoke a local catalog session")]
    Session(users::SessionArgs),
    /// Manage backup policies (the scheduler reads these).
    Policy(policy::PolicyArgs),
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

    /// Manage the host inventory (the catalog). First use creates the
    /// catalog and its master key.
    #[command(subcommand)]
    Host(HostCommand),
}

#[derive(Subcommand)]
enum HostCommand {
    /// Register a host in the catalog. With `--generate-key`, a fresh
    /// ed25519 keypair is created: the private key is stored encrypted and
    /// the public key is printed for the host's `authorized_keys`.
    Add {
        /// Path to the catalog database (created if missing).
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,

        /// Display name for the host.
        #[arg(long, value_name = "NAME")]
        name: String,

        /// Hostname or IP the control plane connects to.
        #[arg(long, value_name = "ADDRESS")]
        address: String,

        /// SSH port.
        #[arg(long, value_name = "PORT", default_value_t = 22)]
        port: u16,

        /// SSH login user.
        #[arg(long, value_name = "USER")]
        user: String,

        /// Generate a dedicated keypair instead of using the default SSH
        /// key file (`~/.ssh/id_ed25519` / `id_rsa`) at backup time.
        #[arg(long)]
        generate_key: bool,

        /// Backup mode (`agentless` or `agent`).
        #[arg(long, value_name = "MODE", default_value = "agentless")]
        mode: String,
    },

    /// List the hosts in the catalog.
    List {
        /// Path to the catalog database.
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,
    },

    /// Remove a host from the catalog (by name or id prefix).
    Remove {
        /// Path to the catalog database.
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,

        /// The host's name or id (prefix ok).
        #[arg(value_name = "HOST")]
        host: String,
    },

    /// Back up one or more absolute remote paths on every host in the
    /// catalog, concurrently (capacity-capped). Failing hosts are reported
    /// and do not abort the run.
    BackupAll {
        /// Path to the catalog database.
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,

        /// Repository to write the snapshots into.
        #[arg(long, value_name = "LOCATION")]
        repo: String,

        /// Absolute remote paths to back up on every host.
        #[arg(value_name = "REMOTE_PATH", required = true)]
        paths: Vec<String>,

        /// Maximum hosts backed up at the same time.
        #[arg(long, value_name = "N", default_value_t = 8)]
        concurrency: usize,
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

        Command::User(args) => users::run_user(&args.command, cli.json).await?,
        Command::Session(args) => users::run_session(&args.command, cli.json).await?,

        Command::Policy(args) => policy::run(&args.command, cli.json).await?,
        Command::Host(HostCommand::Add {
            catalog,
            name,
            address,
            port,
            user,
            generate_key,
            mode,
        }) => {
            let mode = hosts::parse_mode(&mode)?;
            let handle = hosts::CatalogHandle::open(&catalog).await?;
            let (key_pem, public_key) = if generate_key {
                let (key, public) = hosts::generate_host_key(&format!("aegis:{name}"))?;
                let pem = key
                    .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                    .map_err(|e| anyhow!("encoding host key: {e}"))?
                    .to_string();
                (pem.into_bytes(), Some(public))
            } else {
                (Vec::new(), None)
            };
            let host = handle
                .catalog
                .add_host(
                    &name,
                    &address,
                    port,
                    &user,
                    &key_pem,
                    mode,
                    handle.master_key(),
                )
                .await
                .context("registering the host")?;
            handle
                .catalog
                .audit(None, "host.add", Some(&name))
                .await
                .ok();
            emit(
                cli.json,
                &serde_json::json!({
                    "id": host.id,
                    "name": host.name,
                    "address": host.address,
                    "port": host.ssh_port,
                    "user": host.ssh_user,
                    "mode": host.mode.as_str(),
                    "public_key": public_key,
                }),
                || {
                    println!("registered host {} ({})", host.name, host.id);
                    if let Some(public) = &public_key {
                        println!("add this line to the host's ~/.ssh/authorized_keys:");
                        println!("  {public}");
                    } else {
                        println!(
                            "no key stored; backups will use ~/.ssh/id_ed25519/id_rsa or AEGIS_SSH_PASSWORD"
                        );
                    }
                },
            );
        }

        Command::Host(HostCommand::List { catalog }) => {
            let handle = hosts::CatalogHandle::open(&catalog).await?;
            let list = handle.catalog.list_hosts().await?;
            let list_json: Vec<serde_json::Value> = list
                .iter()
                .map(|h| {
                    serde_json::json!({
                        "id": h.id,
                        "name": h.name,
                        "address": h.address,
                        "port": h.ssh_port,
                        "user": h.ssh_user,
                        "status": h.status.as_str(),
                        "mode": h.mode.as_str(),
                    })
                })
                .collect();
            emit(cli.json, &list_json, || {
                if list.is_empty() {
                    println!("no hosts registered (use `aegis host add`)");
                    return;
                }
                println!(
                    "{:<10}  {:<20}  {:<24}  {:>5}  {:<10}  {:<11}  MODE",
                    "ID", "NAME", "ADDRESS", "PORT", "USER", "STATUS"
                );
                for h in &list {
                    println!(
                        "{:<10}  {:<20}  {:<24}  {:>5}  {:<10}  {:<11}  {}",
                        &h.id[..8.min(h.id.len())],
                        h.name,
                        h.address,
                        h.ssh_port,
                        h.ssh_user,
                        h.status.as_str(),
                        h.mode.as_str(),
                    );
                }
            });
        }

        Command::Host(HostCommand::Remove { catalog, host }) => {
            let handle = hosts::CatalogHandle::open(&catalog).await?;
            let h = hosts::find_host(&handle, &host).await?;
            let removed = handle.catalog.remove_host(&h.id).await?;
            handle
                .catalog
                .audit(None, "host.remove", Some(&h.name))
                .await
                .ok();
            emit(
                cli.json,
                &serde_json::json!({ "id": h.id, "name": h.name, "removed": removed }),
                || println!("removed host {} ({})", h.name, &h.id[..8.min(h.id.len())]),
            );
        }

        Command::Host(HostCommand::BackupAll {
            catalog,
            repo,
            paths,
            concurrency,
        }) => {
            for p in &paths {
                if !p.starts_with('/') {
                    return Err(anyhow!(
                        "remote path `{p}` must be absolute (agentless mode reads remote files directly)"
                    ));
                }
            }
            let handle = hosts::CatalogHandle::open(&catalog).await?;
            let repo = std::sync::Arc::new(open(&cli.ssh, &repo).await?);
            let results = hosts::backup_all(
                &handle,
                repo,
                paths,
                cli.ssh.insecure_accept_host_key,
                concurrency,
            )
            .await;
            let ok: Vec<&hosts::HostRunResult> =
                results.iter().filter(|r| r.error.is_none()).collect();
            let failed: Vec<&hosts::HostRunResult> =
                results.iter().filter(|r| r.error.is_some()).collect();
            emit(
                cli.json,
                &serde_json::json!({
                    "succeeded": ok.len(),
                    "failed": failed.len(),
                    "hosts": results.iter().map(|r| serde_json::json!({
                        "host": r.name,
                        "snapshot": r.snapshot.as_ref().map(|s| s.id.clone()),
                        "error": r.error,
                    })).collect::<Vec<_>>(),
                }),
                || {
                    println!(
                        "backup-all: {} succeeded, {} failed",
                        ok.len(),
                        failed.len()
                    );
                    for r in &ok {
                        if let Some(s) = &r.snapshot {
                            println!(
                                "  {} — snapshot {} ({} files, {} new)",
                                r.name,
                                s.short_id(),
                                s.stats.files,
                                s.stats.new_chunks
                            );
                        }
                    }
                    for r in &failed {
                        println!(
                            "  {} — FAILED: {}",
                            r.name,
                            r.error.as_deref().unwrap_or("?")
                        );
                    }
                    if !failed.is_empty() {
                        std::process::exit(2);
                    }
                },
            );
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
