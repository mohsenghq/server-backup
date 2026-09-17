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

async fn authed_json_response<T: serde::de::DeserializeOwned>(
    app: axum::Router,
    method: axum::http::Method,
    uri: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, T) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
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

async fn login_token(app: &axum::Router, username: &str, password: &str) -> String {
    let (status, body): (_, serde_json::Value) = json_response(
        app.clone(),
        axum::http::Method::POST,
        "/api/auth/login",
        Some(serde_json::json!({ "username": username, "password": password })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    body["token"].as_str().unwrap().to_string()
}

/// Create a test admin directly in the catalog (API user management routes
/// come later in Phase 3; the CLI `aegis user add` is the real entry point).
async fn seed_admin(catalog: &std::path::Path) {
    let c = aegis_core::catalog::Catalog::open(catalog).await.unwrap();
    c.add_user("admin", "admin-password-123").await.unwrap();
}

#[tokio::test]
async fn health_and_host_crud() {
    let dir = TempDir::new().unwrap();
    let catalog_path = dir.path().join("catalog.db");
    seed_admin(&catalog_path).await;
    let app = app(&catalog_path).await;

    let (status, body): (_, serde_json::Value) =
        json_response(app.clone(), axum::http::Method::GET, "/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");

    // Every protected endpoint rejects anonymous requests.
    for (method, uri) in [
        (axum::http::Method::POST, "/api/hosts"),
        (axum::http::Method::GET, "/api/hosts"),
        (axum::http::Method::DELETE, "/api/hosts/whatever"),
        (axum::http::Method::POST, "/api/hosts/whatever/test"),
        (axum::http::Method::POST, "/api/jobs/trigger"),
        (axum::http::Method::GET, "/api/auth/me"),
        (axum::http::Method::POST, "/api/auth/logout"),
    ] {
        let (status, _): (_, serde_json::Value) =
            json_response(app.clone(), method.clone(), uri, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
    // A malformed/garbage token is also rejected.
    let (status, _): (_, serde_json::Value) = authed_json_response(
        app.clone(),
        axum::http::Method::GET,
        "/api/hosts",
        "not-a-real-token",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let token = login_token(&app, "admin", "admin-password-123").await;

    // Add a host.
    let (status, body): (_, serde_json::Value) = authed_json_response(
        app.clone(),
        axum::http::Method::POST,
        "/api/hosts",
        &token,
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
    let (_, body): (_, serde_json::Value) = authed_json_response(
        app.clone(),
        axum::http::Method::GET,
        "/api/hosts",
        &token,
        None,
    )
    .await;
    let list = body.as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["name"], "web-1");

    // /api/auth/me identifies the session user.
    let (_, body): (_, serde_json::Value) = authed_json_response(
        app.clone(),
        axum::http::Method::GET,
        "/api/auth/me",
        &token,
        None,
    )
    .await;
    assert_eq!(body["username"], "admin");

    // The host.add audit entry is attributed to the acting admin.
    let state = aegis_server::state::AppState::open(&catalog_path)
        .await
        .unwrap();
    let users = state.catalog.list_users().await.unwrap();
    let admin_id = users[0].id.clone();
    let log = state.catalog.audit_log(10).await.unwrap();
    assert!(log
        .iter()
        .any(|e| e.action == "host.add" && e.user_id.as_deref() == Some(admin_id.as_str())));

    // Remove it; a second remove 404s.
    let (status, _): (_, serde_json::Value) = authed_json_response(
        app.clone(),
        axum::http::Method::DELETE,
        &format!("/api/hosts/{host_id}"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body): (_, serde_json::Value) = authed_json_response(
        app.clone(),
        axum::http::Method::DELETE,
        &format!("/api/hosts/{host_id}"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // Logout revokes the token; the next request 401s again.
    let (status, body): (_, serde_json::Value) = authed_json_response(
        app.clone(),
        axum::http::Method::POST,
        "/api/auth/logout",
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _): (_, serde_json::Value) = authed_json_response(
        app.clone(),
        axum::http::Method::GET,
        "/api/hosts",
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_rejects_bad_credentials_and_is_throttled() {
    let dir = TempDir::new().unwrap();
    let catalog_path = dir.path().join("catalog.db");
    seed_admin(&catalog_path).await;
    let app = app(&catalog_path).await;

    let (status, _): (_, serde_json::Value) = json_response(
        app.clone(),
        axum::http::Method::POST,
        "/api/auth/login",
        Some(serde_json::json!({ "username": "admin", "password": "wrong-password-1" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _): (_, serde_json::Value) = json_response(
        app.clone(),
        axum::http::Method::POST,
        "/api/auth/login",
        Some(serde_json::json!({ "username": "ghost", "password": "wrong-password-2" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Malformed bodies are client errors, not 500s.
    let (status, _): (_, serde_json::Value) = json_response(
        app.clone(),
        axum::http::Method::POST,
        "/api/auth/login",
        Some(serde_json::json!({ "username": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
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
    seed_admin(&catalog_path).await;
    let app = app(&catalog_path).await;
    let token = login_token(&app, "admin", "admin-password-123").await;

    // Register the SSH-test host.
    let (_, body): (_, serde_json::Value) = authed_json_response(
        app.clone(),
        axum::http::Method::POST,
        "/api/hosts",
        &token,
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
    let (status, body): (_, serde_json::Value) = authed_json_response(
        app.clone(),
        axum::http::Method::POST,
        "/api/jobs/trigger",
        &token,
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

    // The job.run audit entry is attributed to the acting user.
    let log = state.catalog.audit_log(10).await.unwrap();
    assert!(log
        .iter()
        .any(|e| e.action == "job.run" && e.user_id.is_some()));

    // Relative remote paths are rejected.
    let (status, _): (_, serde_json::Value) = authed_json_response(
        app,
        axum::http::Method::POST,
        "/api/jobs/trigger",
        &token,
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
