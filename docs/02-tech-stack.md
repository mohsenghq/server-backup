# Tech Stack

These choices are fixed by default. If something here is unmaintained or clearly wrong once you're actually building, substitute it — but record the substitution and a one-line reason in `PROGRESS.md` under "Deviations," and proceed without waiting for permission.

| Layer | Choice | Why |
|---|---|---|
| Core engine + CLI | **Rust** (edition 2021+) | Predictable low memory, no GC pauses, single static binary, easy cross-compile for the agent |
| Chunking | `fastcdc` (content-defined chunking) | Stable chunk boundaries across edits → real dedup |
| Hashing | `blake3` | SIMD-accelerated, much faster than SHA-256, used as content ID |
| Compression | `zstd` | Best speed/ratio tradeoff, per-blob adaptive level |
| Encryption | `chacha20poly1305` (XChaCha20-Poly1305) + `argon2` for key derivation | Fast on CPUs without AES-NI (small VPS), authenticated encryption |
| Local metadata/index | `redb` (pure-Rust embedded KV) | Fast local dedup index, no native deps |
| SSH | `russh` + `russh-sftp` | Pure Rust, no shelling out to `ssh`/`scp`, easier to sandbox and reason about |
| Object storage backend | `aws-sdk-s3` (S3-compatible) | Covers MinIO, Backblaze B2, Wasabi, AWS |
| Server API | `axum` + `tokio` | Async, WebSocket support, pairs naturally with the rest of the stack |
| Internal RPC (server ↔ core workers) | `tonic` (gRPC) | Typed, streaming-friendly for progress updates |
| Scheduler | `tokio-cron-scheduler` | In-process cron, no external broker needed at this scale |
| Catalog DB | **SQLite** by default (`sqlx`), **Postgres** supported via the same `sqlx` queries | Zero-config self-hosted default; clear upgrade path for larger installs |
| Logging/metrics | `tracing` + `tracing-subscriber`, Prometheus `/metrics` endpoint | Fits a typical existing Prometheus/Grafana setup |
| Web UI | **React 18 + TypeScript**, Vite, TanStack Query, TanStack Router, Tailwind CSS, shadcn/ui, Recharts | Modern, fast dev loop, consistent design system |
| Desktop apps | **Tauri v2** | Wraps the same React UI, ships a native Windows `.msi` and Linux `.AppImage`/`.deb`, bundles `aegis-server` as a local sidecar — tiny installers, near-native performance |
| MCP server | `rmcp` (official Rust MCP SDK) exposing the same REST API | Reuses server logic, no duplicate business rules |
| CI | GitHub Actions | Build matrix for Linux/Windows/macOS, cross-compilation for common Linux arches (x86_64, aarch64) for the agent binary |

## Illustrative backend trait

Not final — a shape to build from:

```rust
#[async_trait]
pub trait Backend: Send + Sync {
    async fn get(&self, key: &str) -> Result<Bytes>;
    async fn put(&self, key: &str, data: Bytes) -> Result<()>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
    async fn delete(&self, key: &str) -> Result<()>;
}
```
