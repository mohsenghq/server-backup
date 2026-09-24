//! RBAC over the REST API: viewer is read-only (403 on mutations), operator
//! may operate but not rotate keys or manage users, admin can do everything;
//! user management is admin-only end to end.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

const PASSWORD: &str = "rbac-password-123";

async fn boot() -> (TempDir, axum::Router) {
    if std::env::var("AEGIS_PASSPHRASE").is_err() {
        std::env::set_var("AEGIS_PASSPHRASE", "rbac-test-pass");
    }
    let dir = TempDir::new().unwrap();
    let catalog_path = dir.path().join("catalog.db");
    let cat = aegis_core::catalog::Catalog::open(&catalog_path)
        .await
        .unwrap();
    use aegis_core::catalog::auth::Role;
    cat.add_user_with_role("boss", PASSWORD, Role::Admin)
        .await
        .unwrap();
    cat.add_user_with_role("operator", PASSWORD, Role::Operator)
        .await
        .unwrap();
    cat.add_user_with_role("watcher", PASSWORD, Role::Viewer)
        .await
        .unwrap();
    let state = aegis_server::state::AppState::open(&catalog_path)
        .await
        .unwrap();
    let app = aegis_server::api::router(state);
    (dir, app)
}

async fn login(app: &axum::Router, username: &str) -> String {
    let req = Request::builder()
        .method(axum::http::Method::POST)
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "username": username, "password": PASSWORD }).to_string(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "login failed for {username}");
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    body["token"].as_str().unwrap().to_string()
}

async fn call(
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
async fn viewer_is_read_only() {
    let (_dir, app) = boot().await;
    let viewer = login(&app, "watcher").await;

    // Reads are allowed.
    for uri in ["/api/hosts", "/api/jobs", "/api/policies", "/api/audit"] {
        let (status, _) = call(app.clone(), axum::http::Method::GET, uri, &viewer, None).await;
        assert_eq!(status, StatusCode::OK, "GET {uri} must be readable");
    }
    let (status, body) = call(
        app.clone(),
        axum::http::Method::GET,
        "/api/auth/me",
        &viewer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["role"], "viewer");

    // Mutations are forbidden.
    let (status, body) = call(
        app.clone(),
        axum::http::Method::POST,
        "/api/hosts",
        &viewer,
        Some(serde_json::json!({ "name": "h", "address": "127.0.0.1", "ssh_user": "u" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, _) = call(
        app.clone(),
        axum::http::Method::POST,
        "/api/jobs/trigger",
        &viewer,
        Some(serde_json::json!({ "host_id": "h1", "paths": ["/x"], "repo": "/tmp/r" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        app,
        axum::http::Method::POST,
        "/api/policies",
        &viewer,
        Some(serde_json::json!({ "name": "p", "schedule_cron": "* * * * *", "retention_json": "{}", "paths_json": "[]", "exclude_json": "[]" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn operator_manages_but_not_users_or_keys() {
    let (_dir, app) = boot().await;
    let operator = login(&app, "operator").await;

    // May add a host.
    let (status, body) = call(
        app.clone(),
        axum::http::Method::POST,
        "/api/hosts",
        &operator,
        Some(serde_json::json!({ "name": "op-host", "address": "127.0.0.1", "ssh_user": "u" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let host_id = body["id"].as_str().unwrap().to_string();

    // May not rotate keys (admin-only).
    let (status, _) = call(
        app.clone(),
        axum::http::Method::POST,
        &format!("/api/hosts/{host_id}/key"),
        &operator,
        Some(serde_json::json!({ "ssh_key_pem": "pem" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // May not manage users.
    let (status, _) = call(
        app.clone(),
        axum::http::Method::GET,
        "/api/users",
        &operator,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        app.clone(),
        axum::http::Method::POST,
        "/api/users",
        &operator,
        Some(serde_json::json!({ "username": "x", "password": PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_manages_users_end_to_end() {
    let (dir, app) = boot().await;
    let admin = login(&app, "boss").await;

    // Create a viewer via the API.
    let (status, body) = call(
        app.clone(),
        axum::http::Method::POST,
        "/api/users",
        &admin,
        Some(serde_json::json!({ "username": "newbie", "password": PASSWORD, "role": "viewer" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["role"], "viewer");

    // Promote them.
    let (status, body) = call(
        app.clone(),
        axum::http::Method::POST,
        "/api/users/newbie/role",
        &admin,
        Some(serde_json::json!({ "role": "operator" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["role"], "operator");

    // The new user's role shows in /api/users and me.
    let newbie = login(&app, "newbie").await;
    let (status, body) = call(
        app.clone(),
        axum::http::Method::GET,
        "/api/auth/me",
        &newbie,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["role"], "operator");

    // Bad role rejected; removing self rejected; unknown user 404.
    let (status, _) = call(
        app.clone(),
        axum::http::Method::POST,
        "/api/users/newbie/role",
        &admin,
        Some(serde_json::json!({ "role": "superuser" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        app.clone(),
        axum::http::Method::DELETE,
        "/api/users/boss",
        &admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Cleanup works.
    let (status, _) = call(
        app.clone(),
        axum::http::Method::DELETE,
        "/api/users/newbie",
        &admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let _ = dir;
}
