//! Tests for the MCP server: the API client error paths and the MCP
//! protocol surface (initialize + tools/list + a tool call through the
//! rmcp in-memory transport against a stubbed REST backend).

use rmcp::handler::client::ClientHandler;
use rmcp::model::CallToolRequestParam;
use rmcp::model::ClientInfo;
use rmcp::ServiceExt;
use serde_json::{json, Value};

use aegis_mcp::AegisMcpServer;

/// A no-op client handler so we can talk to the server in-process.
#[derive(Debug, Clone, Default)]
struct NoopClient;

impl ClientHandler for NoopClient {
    fn get_info(&self) -> ClientInfo {
        ClientInfo::default()
    }
}

/// Simplest possible TCP listener that never accepts: used to prove the
/// client surfaces connection errors as `ApiError::Transport`.
fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

#[tokio::test]
async fn client_connection_error_is_transport() {
    let client =
        aegis_mcp::api::ApiClient::new(format!("http://127.0.0.1:{}", closed_port()), None);
    let err = client.list_hosts().await.expect_err("connection refused");
    assert!(matches!(err, aegis_mcp::api::ApiError::Transport(_)));
}

/// A minimal stub REST API: answers every request with a fixed JSON body
/// so tool calls can be exercised end-to-end.
async fn spawn_stub_api(body: Value) -> String {
    let app = axum::Router::new().fallback(axum::routing::any(move || {
        let body = body.clone();
        async move { axum::Json(body) }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn mcp_lists_expected_tools() {
    let stub = spawn_stub_api(json!({ "ok": true })).await;
    let (server_transport, client_transport) = tokio::io::duplex(4096);

    tokio::spawn(async move {
        let server = AegisMcpServer::new(stub, Some("test-token".to_string()));
        let _ = server
            .serve(server_transport)
            .await
            .unwrap()
            .waiting()
            .await;
    });

    let client = NoopClient
        .serve(client_transport)
        .await
        .expect("client init");

    let tools = client.peer().list_all_tools().await.expect("list tools");
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    for expected in [
        "list_hosts",
        "add_host",
        "remove_host",
        "trigger_backup",
        "list_jobs",
        "list_snapshots",
        "restore_path",
        "get_storage_stats",
        "list_recent_alerts",
    ] {
        assert!(
            names.contains(&expected),
            "missing tool {expected} in {names:?}"
        );
    }
}

#[tokio::test]
async fn mcp_tool_call_hits_stub_api() {
    let stub = spawn_stub_api(json!({ "hosts": [{ "id": "h1", "name": "web-1" }] })).await;
    let (server_transport, client_transport) = tokio::io::duplex(4096);

    tokio::spawn(async move {
        let server = AegisMcpServer::new(stub, None);
        let _ = server
            .serve(server_transport)
            .await
            .unwrap()
            .waiting()
            .await;
    });

    let client = NoopClient
        .serve(client_transport)
        .await
        .expect("client init");

    let result = client
        .call_tool(CallToolRequestParam {
            name: "list_hosts".into(),
            arguments: None,
        })
        .await
        .expect("call tool");
    let text = result
        .content
        .first()
        .and_then(|c| c.raw.as_text())
        .map(|t| t.text.clone())
        .expect("text content");
    let parsed: Value = serde_json::from_str(&text).expect("json text");
    assert_eq!(parsed["hosts"][0]["name"], "web-1");
}
