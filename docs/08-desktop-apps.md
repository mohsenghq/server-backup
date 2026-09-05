# Desktop Apps (Tauri)

- Same `aegis-web` React codebase, built once, consumed by both the standalone web deployment and the Tauri shell — no UI fork.
- Tauri bundles `aegis-server` as a local sidecar binary: on first run it starts locally, so the desktop app is a fully self-contained single install (server + UI in one), or it can be pointed at a remote `aegis-server` to manage a fleet from a laptop.
- Windows: `.msi` installer. Linux: `.AppImage` and `.deb`. Both under ~20MB thanks to Tauri's native webview approach (no bundled Chromium).
- Platform detection and any native-only affordances (e.g. local sidecar lifecycle) must degrade gracefully when the same UI build runs in a plain browser against a remote server.
