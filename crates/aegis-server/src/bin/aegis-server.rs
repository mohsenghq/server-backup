//! Aegis control plane (`docs/01`, API surface in `docs/06`).
//!
//! Thin binary over the `aegis_server` library; see `src/lib.rs`.

use std::net::SocketAddr;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let addr: SocketAddr = std::env::var("AEGIS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()?;
    let catalog = std::env::var("AEGIS_CATALOG").unwrap_or_else(|_| "aegis-catalog.db".to_string());
    eprintln!("aegis-server listening on {addr} (catalog: {catalog})");
    aegis_server::serve(addr, std::path::PathBuf::from(catalog)).await
}
