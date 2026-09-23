//! Standalone in-process SSH server for E2E testing: binds
//! `AEGIS_E2E_SSH_PORT` (default 2222), serves a temp directory tree seeded
//! at `/srv/backup-me` (POSIX-jailed to the served root), and runs forever.

mod e2e_sshd;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port: u16 = std::env::var("AEGIS_E2E_SSH_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2222);

    let dir = tempfile::tempdir()?;
    let root = dir.path().to_path_buf();

    // Seed content the E2E flow will back up. The server jails paths to its
    // root, so a remote `/srv/backup-me` maps to `<root>/srv/backup-me`.
    let target = root.join("srv/backup-me");
    std::fs::create_dir_all(&target)?;
    std::fs::write(target.join("hello.txt"), "hello from e2e\n")?;
    std::fs::write(target.join("data.bin"), vec![42u8; 128 * 1024])?;
    std::fs::create_dir_all(target.join("nested"))?;
    std::fs::write(target.join("nested/deep.txt"), "deep file\n")?;

    eprintln!("e2e sshd: serving {} on 127.0.0.1:{port}", root.display());
    let bound = e2e_sshd::spawn_sftp_server_on(&format!("127.0.0.1:{port}"), root).await?;
    eprintln!("e2e sshd: ready on {bound}");
    tokio::signal::ctrl_c().await?;
    Ok(())
}
