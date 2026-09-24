//! HTTP client glue for the Aegis REST API.
//!
//! Every MCP tool is a thin wrapper over the same REST API the web UI
//! calls — no duplicated business logic (per `docs/09-mcp-server.md`).

use std::time::Duration;

use serde_json::Value;

/// A small JSON-over-HTTP client for one Aegis control plane.
#[derive(Clone, Debug)]
pub struct ApiClient {
    base_url: String,
    token: Option<String>,
    http: reqwest::Client,
}

/// An error from an API call: either the transport failed or the server
/// returned a non-success status (with its body for context).
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("request failed: {0}")]
    Transport(String),
    #[error("API returned {status}: {body}")]
    Status { status: u16, body: String },
}

impl ApiClient {
    pub fn new(base_url: impl Into<String>, token: Option<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        Self {
            base_url,
            token,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .expect("reqwest client with default options"),
        }
    }

    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    async fn run(&self, req: reqwest::RequestBuilder) -> Result<Value, ApiError> {
        let resp = self
            .authed(req)
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .text()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(ApiError::Status { status, body });
        }
        if body.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_str(&body)
                .map_err(|e| ApiError::Transport(format!("non-JSON response: {e}")))
        }
    }

    async fn get(&self, path: &str) -> Result<Value, ApiError> {
        self.run(self.http.get(format!("{}{path}", self.base_url)))
            .await
    }

    async fn post(&self, path: &str, json: Value) -> Result<Value, ApiError> {
        self.run(
            self.http
                .post(format!("{}{path}", self.base_url))
                .json(&json),
        )
        .await
    }

    async fn delete(&self, path: &str) -> Result<Value, ApiError> {
        self.run(self.http.delete(format!("{}{path}", self.base_url)))
            .await
    }

    // ----- API operations used by the MCP tools -----

    pub async fn list_hosts(&self) -> Result<Value, ApiError> {
        self.get("/api/hosts").await
    }

    pub async fn add_host(&self, payload: Value) -> Result<Value, ApiError> {
        self.post("/api/hosts", payload).await
    }

    pub async fn remove_host(&self, id: &str) -> Result<Value, ApiError> {
        self.delete(&format!("/api/hosts/{id}")).await
    }

    pub async fn trigger_backup(&self, host_id: &str, agent: bool) -> Result<Value, ApiError> {
        self.post(
            "/api/jobs/trigger",
            serde_json::json!({ "host_id": host_id, "agent": agent }),
        )
        .await
    }

    pub async fn list_jobs(&self) -> Result<Value, ApiError> {
        self.get("/api/jobs").await
    }

    pub async fn list_snapshots(&self, host_id: &str) -> Result<Value, ApiError> {
        self.get(&format!("/api/hosts/{host_id}/snapshots")).await
    }

    pub async fn restore_path(&self, payload: Value) -> Result<Value, ApiError> {
        self.post("/api/restore", payload).await
    }

    pub async fn storage_stats(&self) -> Result<Value, ApiError> {
        self.get("/api/stats").await
    }

    pub async fn recent_alerts(&self) -> Result<Value, ApiError> {
        self.get("/api/alerts").await
    }
}
