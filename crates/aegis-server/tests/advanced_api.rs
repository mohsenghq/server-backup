//! Advanced-mode API: `GET /api/audit`, `POST /api/hosts/{id}/key` (SSH key
//! rotation), exercised through the router with a session token.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

async fn setup() -> (TempDir, axum::Router, String) {
    if std::env::var("AEGIS_PASSPHRASE").is_err() {
        std::env::set_var("AEGIS_PASSPHRASE", "adv-test-pass");
    }
    let dir = TempDir::new().unwrap();
    let catalog_path = dir.path().join("catalog.db");
    let cat = aegis_core::catalog::Catalog::open(&catalog_path)
        .await
        .unwrap();
    cat.add_user("admin", "admin-password-123").await.unwrap();
    let state = aegis_server::state::AppState::open(&catalog_path)
        .await
        .unwrap();
    let app = aegis_server::api::router(state);

    let req = Request::builder()
        .method(axum::http::Method::POST)
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "username": "admin", "password": "admin-password-123" })
                .to_string(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let token = body["token"].as_str().unwrap().to_string();
    (dir, app, token)
}

async fn authed(
    app: axum::Router,
    method: axum::http::Method,
    uri: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let req = builder
        .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({})),
    )
}

#[tokio::test]
async fn audit_log_lists_entries() {
    let (_dir, app, token) = setup().await;
    // The login itself wrote a `session.login` audit entry.
    let (status, body) = authed(app, axum::http::Method::GET, "/api/audit", &token, None).await;
    assert_eq!(status, StatusCode::OK);
    let entries = body.as_array().expect("audit array");
    assert!(
        entries.iter().any(|e| e["action"] == "session.login"),
        "session.login missing from audit: {entries:?}"
    );
}

#[tokio::test]
async fn key_rotation_stores_and_rejects_missing_host() {
    let (dir, app, token) = setup().await;

    // Register a host to rotate.
    let (status, body) = authed(
        app.clone(),
        axum::http::Method::POST,
        "/api/hosts",
        &token,
        Some(serde_json::json!({
            "name": "rotate-me",
            "address": "127.0.0.1",
            "ssh_user": "aegis",
            "ssh_key_pem": "old-key"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let host_id = body["id"].as_str().unwrap().to_string();

    // Rotate to a new key.
    let (status, body) = authed(
        app.clone(),
        axum::http::Method::POST,
        &format!("/api/hosts/{host_id}/key"),
        &token,
        Some(serde_json::json!({ "ssh_key_pem": "new-key-pem" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rotated"], true);

    // The stored key (decrypted with the master key) is the new one.
    let cat = aegis_core::catalog::Catalog::open(&dir.path().join("catalog.db"))
        .await
        .unwrap();
    let mk = {
        // Same derivation as AppState: read the sidecar key file.
        let key_path = dir.path().join("catalog.db.key.json");
        let file = aegis_core::keys::KeyFile::from_json(
            std::fs::read_to_string(key_path).unwrap().as_bytes(),
        )
        .unwrap();
        aegis_core::keys::RepoCrypto::from_key_file(&file, "adv-test-pass")
            .unwrap()
            .master_key()
    };
    let with_key = cat.get_host_with_key(&host_id, &mk).await.unwrap();
    assert_eq!(with_key.ssh_key_pem, b"new-key-pem");

    // Rotation against a bogus host id 404s.
    let (status, _) = authed(
        app.clone(),
        axum::http::Method::POST,
        "/api/hosts/nope/key",
        &token,
        Some(serde_json::json!({ "ssh_key_pem": "x" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // And the rotation was audited.
    let (status, body) = authed(app, axum::http::Method::GET, "/api/audit", &token, None).await;
    assert_eq!(status, StatusCode::OK);
    let entries = body.as_array().unwrap();
    assert!(
        entries.iter().any(|e| e["action"] == "host.key_rotate"),
        "host.key_rotate missing: {entries:?}"
    );
}
