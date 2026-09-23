//! The `aegis-web` UI is served by the server binary. This test builds a
//! minimal fake bundle on disk (skipping the real npm build) and asserts the
//! static file serving + SPA fallback behaviour of `serve()`.

use std::net::SocketAddr;

#[tokio::test]
async fn web_ui_served_with_spa_fallback() {
    if std::env::var("AEGIS_PASSPHRASE").is_err() {
        std::env::set_var("AEGIS_PASSPHRASE", "webui-test-pass");
    }
    let dir = tempfile::tempdir().unwrap();
    let dist = dir.path().join("dist");
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::write(
        dist.join("index.html"),
        "<html><body>aegis-ui</body></html>",
    )
    .unwrap();
    std::fs::write(dist.join("app.js"), "console.log(1)").unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound = listener.local_addr().unwrap();
    drop(listener);
    let dist_clone = dist.clone();
    let server = tokio::spawn(async move {
        aegis_server::serve(bound, dir.path().join("cat.db"), Some(dist_clone))
            .await
            .unwrap();
    });

    // give the server a moment to bind
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let resp = reqwest_free(bound, "/").await;
    assert!(resp.contains("aegis-ui"), "index served: {resp}");

    // SPA fallback: unknown client-side routes return index.html
    let resp = reqwest_free(bound, "/some/client/route").await;
    assert!(resp.contains("aegis-ui"), "SPA fallback: {resp}");

    // static assets still resolve directly
    let resp = reqwest_free(bound, "/app.js").await;
    assert!(resp.contains("console.log"), "asset served: {resp}");

    // API routes take precedence over the fallback
    let resp = reqwest_free(bound, "/health").await;
    assert!(resp.contains("ok"), "api precedence: {resp}");

    server.abort();
}

async fn reqwest_free(addr: SocketAddr, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}
