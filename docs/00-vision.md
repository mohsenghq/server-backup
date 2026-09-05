# Vision

A self-hosted backup platform that:

- Manages backups for an arbitrary number of remote Linux servers, onboarded with SSH details only — no manual client install required to get started.
- Has a **simple, uncluttered default UI** (add server → pick a policy → done) with an **advanced layer** underneath exposing every knob a power user wants (retention rules, encryption, throttling, hooks, replication).
- Is built **CLI-first**: every feature the UI/API offers must also exist as a documented CLI command. The CLI is the actual product; the server, web UI, desktop apps, and MCP server are all thin orchestration layers on top of it.
- Is extremely fast and lean at the core (content-defined chunking + BLAKE3 hashing + zstd, written in Rust), so it runs comfortably even on small/cheap VPS instances.
- Ships as: a **CLI binary**, a **web app**, **Windows/Linux desktop apps** (same React UI, packaged with Tauri), and an **MCP server** so AI agents can drive it conversationally.
- Reaches feature parity with — and eventually exceeds — established tools like restic, Kopia, BorgBackup, and BackupPC: real deduplication, encryption at rest, incremental snapshots, verifiable integrity, flexible retention, multiple storage backends.

## Non-goals (v1)

- No VM/disk-image-level (bare-metal) backup in v1 — file/directory-level only.
- Source (backed-up) servers are assumed Linux. Windows/Linux desktop apps are **management client** platforms, not backup targets.
- No built-in multi-tenant "backup as a service" billing layer — this is an operator tool for one organization, though it supports multiple internal users (RBAC, Phase 6).
- No proprietary cloud lock-in — all storage backends are open and swappable.
