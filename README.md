# Aegis Backup System — build spec

This folder is a ready-to-use project scaffold for Claude Code. Unzip it into a new empty directory and point Claude Code at that directory — it will read `CLAUDE.md` first, then `PROGRESS.md` and `ROADMAP.md`, and start (or resume) work from there. `crates/`, `web/`, and `desktop/` don't exist yet; they get created during Phase 0.

- `CLAUDE.md` — rules and entry point (read this first, every session)
- `PROGRESS.md` — living state: current phase, what's done, next action
- `ROADMAP.md` — the full phase-by-phase checklist
- `docs/` — detailed specs, one topic per file

## Using the CLI (Phase 0)

```sh
cargo run -p aegis-cli -- init     --repo /srv/backups
cargo run -p aegis-cli -- backup /etc --repo /srv/backups
cargo run -p aegis-cli -- snapshots  --repo /srv/backups
cargo run -p aegis-cli -- restore --repo /srv/backups --snapshot <id> --target /tmp/restored
```

Add `--json` to any command for machine-readable output. Snapshots are **not yet
encrypted or compressed** — that lands in Phase 1.
