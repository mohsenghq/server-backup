//! The Aegis desktop shell (`docs/08-desktop-apps.md`).
//!
//! The same `aegis-web` build runs here as in the browser. On startup the
//! shell spawns a local `aegis-server` sidecar (bundled binary) on an
//! ephemeral port and points the UI at it; when the UI is instead connected
//! to a remote control plane (URL stored in `aegis.remote-url`), the sidecar
//! is not started. All sidecar handling degrades gracefully in plain-browser
//! builds because it only exists inside this shell.

use tauri::Manager;

/// The local catalog directory for the sidecar (`<appdata>/aegis`).
fn sidecar_dir(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    app.path().app_data_dir().ok().map(|d| d.join("aegis"))
}

/// Start the bundled `aegis-server` sidecar and return its base URL.
#[cfg(desktop)]
async fn start_sidecar(
    app: &tauri::AppHandle,
    passphrase: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use tauri_plugin_shell::ShellExt;

    let dir = sidecar_dir(app)
        .ok_or("no app-data directory for the sidecar catalog")?
        .into_os_string();
    std::fs::create_dir_all(&dir)?;

    // Bind on an ephemeral port so concurrent instances never clash; the
    // server prints the chosen port, but simpler and just as private on a
    // laptop: a fixed high port per app instance via the OS picker below.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);

    let (mut rx, _child) = app
        .shell()
        .sidecar("aegis-server")?
        .env("AEGIS_PASSPHRASE", passphrase)
        .env(
            "AEGIS_CATALOG",
            format!("{}/catalog.db", dir.to_string_lossy()),
        )
        .env("AEGIS_LISTEN", format!("127.0.0.1:{port}"))
        .spawn()?;

    // Wait for the health endpoint to answer (sidecar started OK).
    let client = reqwest_health_client();
    let url = format!("http://127.0.0.1:{port}");
    for _ in 0..50 {
        if client
            .get(format!("{url}/health"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            // Keep the child alive: reap output in the background.
            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    if let tauri_plugin_shell::process::CommandEvent::Terminated(_) = event {
                        log::warn!("aegis-server sidecar exited unexpectedly");
                    }
                }
            });
            return Ok(url);
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Err("aegis-server sidecar did not become healthy".into())
}

#[cfg(desktop)]
fn reqwest_health_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .expect("reqwest client builds")
}

/// Ask for the catalog passphrase on first run (persisted in the app store
/// only if the user opts in; otherwise re-asked per launch).
#[cfg(desktop)]
fn sidecar_passphrase(_app: &tauri::AppHandle) -> Option<String> {
    std::env::var("AEGIS_PASSPHRASE").ok().or_else(|| {
        // TODO(Phase 5 polish): prompt via a dedicated window. For now the
        // desktop app inherits the environment like the server binary does.
        None
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            #[cfg(desktop)]
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    match sidecar_passphrase(&handle) {
                        Some(pass) => match start_sidecar(&handle, &pass).await {
                            Ok(url) => log::info!("sidecar healthy at {url}"),
                            Err(e) => log::error!("sidecar failed to start: {e}"),
                        },
                        None => log::info!(
                            "no AEGIS_PASSPHRASE in the environment; running UI-only \
                             (point the app at a remote aegis-server)"
                        ),
                    }
                });
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
