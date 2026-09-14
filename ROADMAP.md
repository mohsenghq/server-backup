# Roadmap

Static plan — what "done" means for each phase. Work top to bottom, in order. Check items off as they're completed (edit this file directly). For "where are we right now," see `PROGRESS.md`, not this file.

## Phase 0 — Foundations

- [x] Initialize Rust workspace: `crates/aegis-core`, `aegis-cli`, `aegis-server`, `aegis-agent`, `aegis-mcp`
- [x] GitHub Actions CI: build + test on Linux/Windows/macOS, `clippy`, `fmt --check`
- [x] `aegis-core`: content-defined chunking (FastCDC) + hashing (BLAKE3)
- [x] `aegis-core`: local filesystem backend
- [x] `aegis-cli`: `aegis backup <path>` and `aegis restore` working end-to-end against a local repo
- [x] Unit tests for the chunker

## Phase 1 — Core Engine Complete

- [x] Full repository format: blobs / index / snapshot manifests (`docs/03-repository-format.md`)
- [x] Encryption (XChaCha20-Poly1305) + key derivation (Argon2id)
- [x] Compression (zstd, adaptive level)
- [x] Retention logic (GFS) + `aegis prune`
- [x] `aegis verify` (integrity check)
- [x] SFTP/SSH backend (`russh` + `russh-sftp`)
- [x] Property-based tests (`proptest`) for chunker/dedup correctness under random mutation
- [x] `criterion` benchmark suite wired into CI

## Phase 2 — Agentless Remote Backup

- [x] SSH connection manager
- [x] Agentless remote-read backup mode (chunk/hash on the control-plane side)
- [x] Host inventory + SQLite catalog
- [x] Capacity-aware multi-host CLI orchestration: `aegis host add`, `aegis host backup-all`
- [x] Integration tests against a real SSH target (container)

## Phase 3 — Server, API, Scheduling

- [x] `aegis-server` skeleton (`axum`)
- [ ] Auth: local users, Argon2 password hashing, sessions
- [ ] Scheduler (`tokio-cron-scheduler`) driving policies
- [ ] Job queue + worker pool
- [ ] Notifications: webhook, Telegram, email
- [ ] Prometheus `/metrics` endpoint
- [ ] Structured logging (`tracing`)
- [ ] Integration tests against the API

## Phase 4 — Web UI

- [ ] React app scaffold (Vite, TypeScript, Tailwind, shadcn/ui)
- [ ] Simple mode: dashboard, add-host wizard, restore browser
- [ ] Advanced mode: raw policy editor, bandwidth throttling, replication config, key rotation, audit log, embedded CLI console
- [ ] WebSocket live job progress
- [ ] Playwright E2E tests for the core flows (add host → run backup → restore a file)

## Phase 5 — Agent Mode + Desktop Apps

- [ ] Auto-push/install of `aegis-agent` over an existing SSH session
- [ ] Agent lifecycle management from the server (start/stop/upgrade)
- [ ] Tauri v2 shell around `aegis-web` (Windows + Linux)
- [ ] Local sidecar bundling of `aegis-server` in the desktop app

## Phase 6 — MCP Server + Advanced Features

- [ ] `aegis-mcp` server (`rmcp`), tools per `docs/09-mcp-server.md`
- [ ] Multi-backend replication
- [ ] Key rotation / re-key flow
- [ ] RBAC / multi-user roles
- [ ] Audit log viewer
- [ ] Bandwidth throttling
- [ ] (stretch) FUSE mount browsing of snapshots

## Phase 7 — Hardening & 1.0

- [ ] Load testing at scale (100+ simulated hosts)
- [ ] Fuzzing the repository format parser (`cargo-fuzz`)
- [ ] Security review pass
- [ ] Install script (`curl | sh`), Docker Compose, systemd units
- [ ] Documentation site
- [ ] 1.0 release checklist sign-off
