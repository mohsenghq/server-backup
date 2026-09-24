//! Aegis MCP server binary.
//!
//! Exposes the Aegis REST API as MCP tools over stdio so an agent can
//! manage backups conversationally. Configuration via environment:
//!
//! - `AEGIS_API_URL` (default `http://127.0.0.1:8080`) — the control plane
//! - `AEGIS_API_TOKEN` — a bearer session token (recommended; the REST API
//!   rejects unauthenticated `/api` calls)

use rmcp::ServiceExt;

use aegis_mcp::AegisMcpServer;

fn api_url() -> String {
    std::env::var("AEGIS_API_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::var("AEGIS_API_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    let server = AegisMcpServer::new(api_url(), token);
    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
