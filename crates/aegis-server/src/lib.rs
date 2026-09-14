//! Aegis control plane (`docs/01`, API surface in `docs/06`).
//!
//! Phase 3 skeleton: axum HTTP server exposing the host inventory (backed by
//! the `aegis-core` catalog) and a trigger endpoint that runs agentless
//! backups in-process. Every endpoint maps 1:1 to a CLI command per the
//! CLI-first rule: `POST /api/hosts` ⇔ `aegis host add`,
//! `DELETE /api/hosts/:id` ⇔ `aegis host remove`,
//! `POST /api/jobs/trigger` ⇔ `aegis host backup-all` (single host).

pub mod api;
pub mod state;

use std::net::SocketAddr;

use anyhow::{Context, Result};

/// Run the HTTP server on `addr` with a catalog at `catalog_path`.
pub async fn serve(addr: SocketAddr, catalog_path: std::path::PathBuf) -> Result<()> {
    let app_state = state::AppState::open(catalog_path).await?;
    let app = api::router(app_state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    axum::serve(listener, app)
        .await
        .context("running the HTTP server")?;
    Ok(())
}
