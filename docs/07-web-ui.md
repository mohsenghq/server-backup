# Web UI

## Simple mode (default)

- Dashboard: host cards (name, last backup time, status dot, storage used).
- "Add server" wizard: hostname/IP, SSH user, paste key or password, pick a policy template (Daily / Weekly / Custom), done.
- Restore browser: pick host → snapshot → browse tree → download/restore.
- Notifications banner for failures.

## Advanced mode (toggle, persisted per user)

- Raw policy editor (cron expression, retention GFS rules, exclude globs, bandwidth cap, pre/post hooks).
- Per-host connection mode override (agentless/agent), key rotation, re-key.
- Multi-backend replication config (mirror a repo to a second backend).
- Full job log viewer, throughput graphs (Recharts), audit log.
- Embedded CLI console (runs `aegis` via the API, output streamed) for power users.

## Cross-cutting

- Real-time progress via WebSocket subscription per running job (percentage, throughput MB/s, ETA).
- This exact UI is the one reused, unmodified, inside the Tauri desktop shell — see `docs/08-desktop-apps.md`. Don't build UI features that assume a browser-only environment (e.g. no `window.open`-only flows without a Tauri-compatible fallback).
