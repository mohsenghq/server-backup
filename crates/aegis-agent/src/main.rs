//! The `aegis-agent` binary — agent mode (`docs/04-host-connection-modes.md`).
//!
//! Runs ON the target host. In `--once` mode it performs one backup of local
//! paths into a repository (local or `sftp://`): chunking and hashing happen
//! at the source, and only chunks the repository does not already have cross
//! the SSH channel — the whole point of agent mode for large datasets.
//!
//! The control plane auto-provisions this binary over SSH
//! (`aegis_core::agent::push_and_run`); a host that can't run it falls back
//! to agentless mode transparently.

use std::path::PathBuf;

use aegis_core::chunk::ChunkerConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut repo: Option<String> = None;
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut passphrase = std::env::var("AEGIS_PASSPHRASE").ok();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--once" => {} // the only mode today; accepted for forward-compat
            "--repo" => repo = Some(args.next().unwrap_or_else(|| usage())),
            "--path" => paths.push(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--passphrase" => passphrase = Some(args.next().unwrap_or_else(|| usage())),
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
    }

    let repo = repo.unwrap_or_else(|| usage());
    if paths.is_empty() {
        eprintln!("no --path given");
        usage();
    }
    let passphrase = passphrase.unwrap_or_else(|| {
        eprintln!("AEGIS_PASSPHRASE (or --passphrase) is required");
        std::process::exit(2);
    });

    let snapshot =
        aegis_core::agent::backup_local_into(&repo, &passphrase, &paths, &ChunkerConfig::default())
            .await?;

    println!(
        "snapshot {} files={} bytes={} new_bytes={}",
        snapshot.id, snapshot.stats.files, snapshot.stats.bytes, snapshot.stats.new_bytes
    );
    Ok(())
}

fn usage() -> ! {
    eprintln!("usage: aegis-agent --once --repo <location> --path <dir> [--path <dir> …] [--passphrase <p>]");
    std::process::exit(2);
}
