//! WebSocket live job events: `/api/jobs/ws` authenticates via the `token`
//! query parameter and streams started/completed/failed events published by
//! the worker pool's shared [`aegis_server::jobs::EventHub`].

use std::net::SocketAddr;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use futures_util::StreamExt;
use tempfile::TempDir;
use tower::ServiceExt;

async fn setup() -> (TempDir, axum::Router, String, aegis_server::state::AppState) {
    if std::env::var("AEGIS_PASSPHRASE").is_err() {
        std::env::set_var("AEGIS_PASSPHRASE", "ws-test-pass");
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
    let app = aegis_server::api::router(state.clone());

    // Login for a bearer token.
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
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let token = body["token"].as_str().unwrap().to_string();
    (dir, app, token, state)
}

#[tokio::test]
async fn ws_requires_valid_token() {
    let (_dir, app, _token, _state) = setup().await;

    for uri in ["/api/jobs/ws", "/api/jobs/ws?token=bogus"] {
        let req = Request::builder()
            .method(axum::http::Method::GET)
            .uri(uri)
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn ws_streams_events_from_shared_hub() {
    let (_dir, app, _token, state) = setup().await;

    // Run the router on a real socket so the WebSocket upgrade goes through
    // hyper's real HTTP/1.1 machinery (in-process oneshot lacks the upgrade
    // extension hyper needs).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Log in over the real socket for a token.
    let (ws, _resp) = tokio_tungstenite::connect_async(format!(
        "ws://{addr}/api/jobs/ws?token={}"
            ,
        {
            // Exchange the credentials via the REST login endpoint using a
            // tiny one-shot HTTP request.
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let body = serde_json::json!({
                "username": "admin",
                "password": "admin-password-123"
            })
            .to_string();
            let req = format!(
                "POST /api/auth/login HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            let text = String::from_utf8_lossy(&buf);
            let json = text.rsplit("\r\n\r\n").next().unwrap().trim();
            serde_json::from_str::<serde_json::Value>(json).unwrap()["token"]
                .as_str()
                .unwrap()
                .to_string()
        }
    ))
    .await
    .unwrap();

    // Publish through the shared hub (the same object jobs::start receives
    // in the serve() path) and read the frames off the socket.
    let mut ws = ws;
    state.events.publish(aegis_server::jobs::JobEvent {
        event: "started".into(),
        job_id: "j1".into(),
        host_id: "h1".into(),
        policy_id: "p1".into(),
        bytes_new: None,
        bytes_total: None,
        error: None,
    });
    state.events.publish(aegis_server::jobs::JobEvent {
        event: "completed".into(),
        job_id: "j1".into(),
        host_id: "h1".into(),
        policy_id: "p1".into(),
        bytes_new: Some(42),
        bytes_total: Some(100),
        error: None,
    });

    let mut seen = Vec::new();
    while seen.len() < 2 {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for frame")
            .expect("socket closed")
            .expect("ws error");
        // The server also interleaves ping frames; only count text events.
        if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            seen.push(v["event"].as_str().unwrap().to_string());
            if v["event"] == "completed" {
                assert_eq!(v["bytes_new"], 42);
            }
        }
    }
    assert!(seen.contains(&"started".to_string()), "{seen:?}");
    assert!(seen.contains(&"completed".to_string()), "{seen:?}");

    server.abort();
}
