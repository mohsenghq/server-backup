//! Aegis MCP server.
//!
//! Exposes the Aegis REST API as MCP tools so an agent can manage backups
//! conversationally. The binary wires this up over stdio; see `main.rs`.

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use serde_json::{json, Value};

use crate::api::{self, ApiClient};

#[derive(Clone)]
pub struct AegisMcpServer {
    client: ApiClient,
    tool_router: ToolRouter<Self>,
}

/// Shared error mapping: API/serialization problems become MCP errors.
fn to_mcp_error(prefix: &str, e: impl std::fmt::Display) -> McpError {
    McpError::internal_error(format!("{prefix}: {e}"), None)
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AddHostRequest {
    #[schemars(description = "Unique host name")]
    pub name: String,
    #[schemars(description = "SSH address (hostname or IP)")]
    pub address: String,
    #[schemars(description = "SSH username")]
    pub user: String,
    #[schemars(description = "SSH port (optional, default 22)")]
    pub port: Option<u16>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct HostIdRequest {
    #[schemars(description = "Host id or name prefix")]
    pub host_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TriggerBackupRequest {
    #[schemars(description = "Host id or name prefix")]
    pub host_id: String,
    #[schemars(description = "Run via the on-host agent if installed (optional, default false)")]
    pub agent: Option<bool>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RestorePathRequest {
    #[schemars(description = "Host id or name prefix")]
    pub host_id: String,
    #[schemars(description = "Snapshot id")]
    pub snapshot_id: String,
    #[schemars(description = "Path inside the snapshot to restore")]
    pub remote_path: String,
    #[schemars(description = "Local destination path")]
    pub destination: String,
}

#[tool_router]
impl AegisMcpServer {
    pub fn new(base_url: String, token: Option<String>) -> Self {
        Self {
            client: ApiClient::new(base_url, token),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "List all backup hosts known to the Aegis control plane")]
    async fn list_hosts(&self) -> Result<CallToolResult, McpError> {
        self.json_result(self.client.list_hosts().await, "list_hosts")
    }

    #[tool(description = "Add a backup host. Paths and policies are configured separately.")]
    async fn add_host(
        &self,
        Parameters(AddHostRequest {
            name,
            address,
            user,
            port,
        }): Parameters<AddHostRequest>,
    ) -> Result<CallToolResult, McpError> {
        let mut payload = json!({ "name": name, "address": address, "user": user });
        if let Some(port) = port {
            payload["port"] = json!(port);
        }
        self.json_result(self.client.add_host(payload).await, "add_host")
    }

    #[tool(
        description = "Remove a host from the control plane. Snapshots already taken are not deleted."
    )]
    async fn remove_host(
        &self,
        Parameters(HostIdRequest { host_id }): Parameters<HostIdRequest>,
    ) -> Result<CallToolResult, McpError> {
        self.json_result(self.client.remove_host(&host_id).await, "remove_host")
    }

    #[tool(description = "Trigger a backup for a host now.")]
    async fn trigger_backup(
        &self,
        Parameters(TriggerBackupRequest { host_id, agent }): Parameters<TriggerBackupRequest>,
    ) -> Result<CallToolResult, McpError> {
        self.json_result(
            self.client
                .trigger_backup(&host_id, agent.unwrap_or(false))
                .await,
            "trigger_backup",
        )
    }

    #[tool(description = "List recent backup jobs with their status")]
    async fn list_jobs(&self) -> Result<CallToolResult, McpError> {
        self.json_result(self.client.list_jobs().await, "list_jobs")
    }

    #[tool(description = "List snapshots taken for a host")]
    async fn list_snapshots(
        &self,
        Parameters(HostIdRequest { host_id }): Parameters<HostIdRequest>,
    ) -> Result<CallToolResult, McpError> {
        self.json_result(self.client.list_snapshots(&host_id).await, "list_snapshots")
    }

    #[tool(description = "Restore a file or directory from a snapshot to a local destination.")]
    async fn restore_path(
        &self,
        Parameters(RestorePathRequest {
            host_id,
            snapshot_id,
            remote_path,
            destination,
        }): Parameters<RestorePathRequest>,
    ) -> Result<CallToolResult, McpError> {
        let payload = json!({
            "host_id": host_id,
            "snapshot_id": snapshot_id,
            "path": remote_path,
            "destination": destination,
        });
        self.json_result(self.client.restore_path(payload).await, "restore_path")
    }

    #[tool(description = "Get repository storage statistics (size, dedup ratio)")]
    async fn get_storage_stats(&self) -> Result<CallToolResult, McpError> {
        self.json_result(self.client.storage_stats().await, "get_storage_stats")
    }

    #[tool(description = "List recent alerts (failed jobs, unreachable hosts)")]
    async fn list_recent_alerts(&self) -> Result<CallToolResult, McpError> {
        self.json_result(self.client.recent_alerts().await, "list_recent_alerts")
    }
}

impl AegisMcpServer {
    /// Turn an API result into a successful tool call returning JSON text.
    fn json_result(
        &self,
        result: Result<Value, api::ApiError>,
        op: &str,
    ) -> Result<CallToolResult, McpError> {
        let value = result.map_err(|e| to_mcp_error(op, e))?;
        let content = Content::json(value).map_err(|e| to_mcp_error(op, e))?;
        Ok(CallToolResult::success(vec![content]))
    }
}

#[tool_handler]
impl ServerHandler for AegisMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_06_18,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Manage Aegis backups through the control-plane REST API. \
                 Start with list_hosts; use trigger_backup to run a backup now and \
                 list_snapshots/list_jobs to inspect results."
                    .to_string(),
            ),
        }
    }
}
