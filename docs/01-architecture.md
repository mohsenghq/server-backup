# High-Level Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                         aegis-web (React/TS)                          │
│         served standalone OR embedded inside aegis-desktop             │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ REST + WebSocket
┌───────────────────────────────▼───────────────────────────────────────┐
│                     aegis-server (Rust, axum)                          │
│  auth · host inventory · scheduler · job queue · notifications ·       │
│  metrics · SQLite/Postgres catalog                                     │
└───────┬───────────────────────────────────────────────────┬───────────┘
        │ local calls                                       │ SSH (russh)
┌───────▼────────────┐                              ┌───────▼───────────┐
│   aegis-core         │   drives, over SSH, either:   │  remote Linux host │
│   (Rust engine +     │  ── agentless (default): read │  optional lightweight│
│    CLI: `aegis`)     │      files remotely, chunk    │  `aegis agent`      │
│                      │      centrally                │  (pushed over SSH,  │
│  chunk → hash →       │  ── agent mode (opt-in):      │   same binary)      │
│  compress → encrypt   │      chunk/hash on source,     │                     │
│  → write to backend   │      only new data crosses     │                     │
│                       │      the wire                 │                     │
└───────┬──────────────┘                              └────────────────────┘
        │
┌───────▼───────────────────────────────────────────────────────────────┐
│                    Storage backend (pluggable)                        │
│         local disk · SFTP/SSH · S3-compatible · (WebDAV later)         │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────┐
│        aegis-mcp             │  MCP tools → same REST API as aegis-web
│  (stdio/HTTP MCP server)     │
└─────────────────────────────┘
```

Everything above the storage backend is optional except `aegis-core`: the CLI alone, pointed at a local or SFTP repo, is a fully working backup tool with zero server/UI running.

## The one rule that shapes everything else

**CLI-first.** Every capability the server/API/web UI/desktop app/MCP server offers must map 1:1 to a documented `aegis` CLI command. Nothing in a higher layer is allowed to implement backup/restore/prune/verify logic itself — it calls into `aegis-core` (in-process or via the CLI's `--json` mode / local gRPC), full stop. This keeps the system usable standalone forever, keeps the surface area of "things that can have bugs" small, and keeps every higher layer honest about what the engine actually supports.

## Component responsibilities

- **`aegis-core`** — chunking, hashing, compression, encryption, repository format, backend abstraction. No networking beyond talking to backends. No knowledge of "hosts," "policies," or "jobs" — those are control-plane concepts layered on top.
- **`aegis-cli`** — thin binary exposing `aegis-core` as subcommands, plus a `--json` machine-readable mode and a `aegis serve --grpc` long-running mode for the control plane to drive without re-spawning a process per operation.
- **`aegis-server`** — the control plane: host inventory, SSH credential vault, scheduler, job queue, notifications, metrics, the catalog DB. Drives `aegis-core` either in-process or via local gRPC.
- **`aegis-agent`** — the same core engine, cross-compiled small, pushed to remote hosts in agent mode so chunking/hashing happens at the source.
- **`aegis-web`** — the React UI, simple mode + advanced mode, talks only to `aegis-server`'s REST/WebSocket API.
- **`aegis-desktop`** — Tauri shell around the exact same `aegis-web` build, bundling `aegis-server` as a local sidecar.
- **`aegis-mcp`** — MCP tool server that calls the same REST API `aegis-web` calls. No duplicated business logic.
