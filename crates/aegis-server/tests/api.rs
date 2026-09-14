//! In-process integration tests for the aegis-server API: health, host
//! CRUD, host status test, and the trigger endpoint running a real agentless
//! backup against the in-process SSH server.

use std::net::SocketAddr;

use aegis_core::catalog::HostStatus;
use aegis_core::crypto::KdfParams;
use aegis_core::{ChunkerConfig, Repository};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

// Reuse the in-process SSH server harness from aegis-core's tests.
#[path = "../../aegis-core/tests/sftp_server.rs"]
mod sftp_server;

use sftp_server::{PASSWORD, USERNAME};

fn fast_kdf() -> KdfParams {
    KdfParams {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    }
}

async fn app(catalog: &std::path::Path) -> axum::Router {
    let _ = std::env::var("AEGIS_PASSPHRASE").unwrap_or_else(|_| {
        std::env::set_var("AEGIS_PASSPHRASE", "server-test-pass");
        "server-test-pass".to_string()
    });
    let state = aegis_server::state::AppState::open(catalog)
        .await
        .expect("opening test catalog");
    aegis_server::api::router(state)
}

async fn json_response<T: serde::de::DeserializeOwned>(
    app: axum::Router,
    method: axum::http::Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, T) {
    let mut builder = Request::builder().method(method).uri(uri);
    let request = if let Some(b) = body {
        builder = builder.header("content-type", "application/json");
        builder.body(Body::from(b.to_string())).unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::from_slice(b"{}").unwrap()),
    )
}

#[tokio::test]
async fn health_and_host_crud() {
    let dir = TempDir::new().unwrap();
    let catalog_path = dir.path().join("catalog.db");
    let app = app(&catalog_path).await;

    let (status, body): (_, serde_json::Value) =
        json_response(app.clone(), axum::http::Method::GET, "/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");

    // Add a host.
    let (status, body): (_, serde_json::Value) = json_response(
        app.clone(),
        axum::http::Method::POST,
        "/api/hosts",
        Some(serde_json::json!({
            "name": "web-1",
            "address": "127.0.0.1",
            "ssh_port": 22,
            "ssh_user": "root",
            "mode": "agentless",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add failed: {body}");
    let host_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["mode"], "agentless");

    // List contains it.
    let (_, body): (_, serde_json::Value) =
        json_response(app.clone(), axum::http::Method::GET, "/api/hosts", None).await;
    let list = body.as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["name"], "web-1");

    // Remove it; a second remove 404s.
    let (status, _): (_, serde_json::Value) = json_response(
        app.clone(),
        axum::http::Method::DELETE,
        &format!("/api/hosts/{host_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body): (_, serde_json::Value) = json_response(
        app.clone(),
        axum::http::Method::DELETE,
        &format!("/api/hosts/{host_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn trigger_runs_agentless_backup() {
    let src = TempDir::new().unwrap();
    std::fs::create_dir_all(src.path().join("site/etc")).unwrap();
    std::fs::write(src.path().join("site/etc/a.conf"), b"one\n").unwrap();
    std::fs::write(src.path().join("site/etc/big.bin"), vec![7u8; 6000]).unwrap();
    let repo_dir = TempDir::new().unwrap();
    let port = sftp_server::spawn_sftp_server(src.path().to_path_buf())
        .await
        .unwrap();

    std::env::set_var("AEGIS_SSH_PASSWORD", PASSWORD);
    let dir = TempDir::new().unwrap();
    let catalog_path = dir.path().join("catalog.db");
    let app = app(&catalog_path).await;

    // Register the SSH-test host.
    let (_, body): (_, serde_json::Value) = json_response(
        app.clone(),
        axum::http::Method::POST,
        "/api/hosts",
        Some(serde_json::json!({
            "name": "ssh-host",
            "address": "127.0.0.1",
            "ssh_port": port,
            "ssh_user": USERNAME,
        })),
    )
    .await;
    let host_id = body["id"].as_str().unwrap().to_string();

    // The repo must exist before trigger opens it; create it via aegis-core.
    let _repo = Repository::init_local_with_kdf(
        repo_dir.path(),
        ChunkerConfig::new(64, 256, 1024).unwrap(),
        "server-test-pass",
        fast_kdf(),
    )
    .await
    .unwrap();

    // Trigger a backup.
    let (status, body): (_, serde_json::Value) = json_response(
        app.clone(),
        axum::http::Method::POST,
        "/api/jobs/trigger",
        Some(serde_json::json!({
            "host_id": host_id,
            "paths": ["/site"],
            "repo": repo_dir.path().to_str().unwrap(),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "trigger failed: {body}");
    assert!(body["snapshot_id"].as_str().is_some(), "{body}");
    assert!(body["files"].as_u64().unwrap() >= 2);

    // The host is now reachable per the catalog.
    let state = aegis_server::state::AppState::open(&catalog_path)
        .await
        .unwrap();
    let host = state.catalog.get_host(&host_id).await.unwrap();
    assert_eq!(host.status, HostStatus::Reachable);

    // Relative remote paths are rejected.
    let (status, _): (_, serde_json::Value) = json_response(
        app,
        axum::http::Method::POST,
        "/api/jobs/trigger",
        Some(serde_json::json!({
            "host_id": host_id,
            "paths": ["relative/path"],
            "repo": repo_dir.path().to_str().unwrap(),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // AEGIS_LISTEN smoke: the binary's serve() path binds and answers.
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let bound = listener.local_addr().unwrap();
    drop(listener);
    let server =
        tokio::spawn(async move { aegis_server::serve(bound, dir.path().join("serve.db")).await });
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let resp = reqwest_free(bound).await;
    assert!(resp.contains("ok"), "health via serve(): {resp}");
    server.abort();
}

async fn reqwest_free(addr: SocketAddr) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}
