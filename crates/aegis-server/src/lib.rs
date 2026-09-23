//! Aegis control plane (`docs/01`, API surface in `docs/06`).
//!
//! Phase 3 skeleton: axum HTTP server exposing the host inventory (backed by
//! the `aegis-core` catalog) and a trigger endpoint that runs agentless
//! backups in-process. Every endpoint maps 1:1 to a CLI command per the
//! CLI-first rule: `POST /api/hosts` ⇔ `aegis host add`,
//! `DELETE /api/hosts/:id` ⇔ `aegis host remove`,
//! `POST /api/jobs/trigger` ⇔ `aegis host backup-all` (single host).

pub mod api;
pub mod jobs;
pub mod scheduler;
pub mod state;

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tower_http::services::{ServeDir, ServeFile};

/// Run the HTTP server on `addr` with a catalog at `catalog_path`.
/// The scheduler is spawned as a background task and reads policies
/// from the catalog on startup.
///
/// If `web_dist` points to a built `aegis-web` bundle (its `dist`
/// directory), it is served as the web UI at `/`; otherwise the UI is
/// skipped and only the API is available.
pub async fn serve(
    addr: SocketAddr,
    catalog_path: std::path::PathBuf,
    web_dist: Option<std::path::PathBuf>,
) -> Result<()> {
    let app_state = state::AppState::open(&catalog_path).await?;
    let scheduler = scheduler::start(
        app_state.catalog.clone(),
        *app_state.master_key(),
        catalog_path.clone(),
    )
    .await?;
    let app = api::router(app_state);
    // Serve the web UI when a built bundle is available. SPA fallback to
    // index.html for client-side routes; `/api` and `/health` routes take
    // precedence over the fallback service.
    let app = match web_dist.filter(|p| p.join("index.html").exists()) {
        Some(dist) => app.fallback_service(
            ServeDir::new(&dist).not_found_service(ServeFile::new(dist.join("index.html"))),
        ),
        None => app,
    };
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    axum::serve(listener, app)
        .await
        .context("running the HTTP server")?;
    drop(scheduler);
    Ok(())
}
