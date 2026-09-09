//! `aegis` — the Aegis command-line interface.
//!
//! The CLI is the product: every capability the server, web UI, desktop apps,
//! and MCP server expose must exist here first, and the CLI must stay fully
//! usable with nothing else running (`docs/01-architecture.md`).

use std::path::PathBuf;

use aegis_core::{ChunkerConfig, Repository};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

/// Self-hosted, deduplicating, multi-server backup.
#[derive(Parser)]
#[command(name = "aegis", version, about, long_about = None)]
struct Cli {
    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

/// Where the repository passphrase comes from.
///
/// Precedence: `--passphrase-file`, then `AEGIS_PASSPHRASE`, then an error —
/// the CLI never takes a passphrase as a command-line argument, where it would
/// land in shell history. Interactive TTY prompting arrives with the Phase 3
/// server auth work, which needs the same dialog code.

#[derive(Subcommand)]
enum Command {
    /// Create a new, empty repository.
    Init {
        /// Directory to create the repository in.
        #[arg(long, value_name = "PATH")]
        repo: PathBuf,

        /// Minimum chunk size in bytes. Fixed for the life of the repository.
        #[arg(long, value_name = "BYTES", default_value_t = aegis_core::chunk::DEFAULT_MIN_SIZE)]
        min_chunk_size: usize,

        /// Target average chunk size in bytes. Fixed for the life of the repository.
        #[arg(long, value_name = "BYTES", default_value_t = aegis_core::chunk::DEFAULT_AVG_SIZE)]
        avg_chunk_size: usize,

        /// Maximum chunk size in bytes. Fixed for the life of the repository.
        #[arg(long, value_name = "BYTES", default_value_t = aegis_core::chunk::DEFAULT_MAX_SIZE)]
        max_chunk_size: usize,

        #[command(flatten)]
        passphrase: PassphraseArgs,
    },

    /// Back up one or more paths into a repository as a new snapshot.
    Backup {
        /// Files or directories to back up.
        #[arg(value_name = "PATH", required = true)]
        paths: Vec<PathBuf>,

        /// Repository to write the snapshot into.
        #[arg(long, value_name = "PATH")]
        repo: PathBuf,

        #[command(flatten)]
        passphrase: PassphraseArgs,
    },

    /// List the snapshots in a repository, newest first.
    Snapshots {
        /// Repository to read.
        #[arg(long, value_name = "PATH")]
        repo: PathBuf,

        #[command(flatten)]
        passphrase: PassphraseArgs,
    },

    /// Restore a snapshot's files into a target directory.
    Restore {
        /// Snapshot id, or any unambiguous prefix of one.
        #[arg(long, value_name = "ID")]
        snapshot: String,

        /// Repository to read the snapshot from.
        #[arg(long, value_name = "PATH")]
        repo: PathBuf,

        /// Directory to restore into. Created if it does not exist.
        #[arg(long, value_name = "PATH")]
        target: PathBuf,

        #[command(flatten)]
        passphrase: PassphraseArgs,
    },
}

/// Passphrase options shared by every repository-touching command.
#[derive(clap::Args, Clone, Debug)]
struct PassphraseArgs {
    /// File containing the repository passphrase (first line; trailing
    /// newline stripped). Takes precedence over AEGIS_PASSPHRASE.
    #[arg(long, value_name = "FILE")]
    passphrase_file: Option<PathBuf>,
}

impl PassphraseArgs {
    /// Resolve the passphrase: `--passphrase-file` first, then `AEGIS_PASSPHRASE`.
    fn read(&self) -> Result<String> {
        if let Some(path) = &self.passphrase_file {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading passphrase file {}", path.display()))?;
            return Ok(raw.trim_end_matches(['\r', '\n']).to_string());
        }
        std::env::var("AEGIS_PASSPHRASE")
            .context("no passphrase: set AEGIS_PASSPHRASE or pass --passphrase-file")
    }
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
            passphrase,
        } => {
            let chunker = ChunkerConfig::new(min_chunk_size, avg_chunk_size, max_chunk_size)?;
            let pass = passphrase.read()?;
            let r = Repository::init(&repo, chunker, &pass)
                .await
                .with_context(|| format!("initializing repository at {}", repo.display()))?;
            emit(
                cli.json,
                &serde_json::json!({ "repository": repo, "id": r.config().id }),
                || {
                    println!(
                        "initialized repository {} at {}",
                        r.config().id,
                        repo.display()
                    )
                },
            );
        }

        Command::Backup {
            paths,
            repo,
            passphrase,
        } => {
            let r = open(&repo, &passphrase.read()?).await?;
            let snapshot = r.backup(&paths).await.context("running backup")?;
            let s = snapshot.stats;
            emit(cli.json, &snapshot, || {
                println!(
                    "snapshot {}\n  {} files, {} read, {} chunks ({} new, {} written)",
                    snapshot.short_id(),
                    s.files,
                    human_bytes(s.bytes),
                    s.chunks,
                    s.new_chunks,
                    human_bytes(s.new_bytes),
                );
            });
        }

        Command::Snapshots { repo, passphrase } => {
            let r = open(&repo, &passphrase.read()?).await?;
            let snapshots = r.list_snapshots().await.context("listing snapshots")?;
            emit(cli.json, &snapshots, || {
                if snapshots.is_empty() {
                    println!("no snapshots in {}", repo.display());
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
            passphrase,
        } => {
            let r = open(&repo, &passphrase.read()?).await?;
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
    }
    Ok(())
}

async fn open(repo: &PathBuf, passphrase: &str) -> Result<Repository> {
    Repository::open(repo, passphrase)
        .await
        .with_context(|| format!("opening repository at {}", repo.display()))
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
