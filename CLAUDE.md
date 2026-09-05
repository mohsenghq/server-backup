# CLAUDE.md — Aegis Backup System

## What this is

Aegis is a self-hosted, multi-server backup platform: SSH-only onboarding of remote Linux hosts, real content-defined deduplication, encryption at rest, a CLI-first core, a web UI with a simple default view and an advanced power-user layer, Windows/Linux desktop apps (same UI), and an MCP server so AI agents can drive it. Full vision: `docs/00-vision.md`.

This file is the entry point. It is short on purpose — everything else lives in `ROADMAP.md`, `PROGRESS.md`, and `docs/`. Read those, not just this.

## Session start protocol (do this every time, in order)

1. Read `PROGRESS.md`. It tells you the current phase, what's done, and the exact next action. Trust it over your own assumptions about where things are.
2. Read `ROADMAP.md` and look only at the checklist for the **current** phase. Ignore later phases' items for now.
3. Read only the `docs/*.md` files relevant to the current phase (see the map below). Don't re-read docs you already used in a prior session unless `PROGRESS.md` flags something changed.
4. Never redo a checked-off `ROADMAP.md` item. If you believe a checked-off item is actually incomplete or broken, add it under "Known Issues" in `PROGRESS.md` and flag it to the user before undoing or reopening it — don't silently redo work.

## While working

- Work phase by phase, in order. Don't reach for Phase 3/4 features while Phase 0/1 checklist items are still unchecked, even if it would be convenient.
- Check off `ROADMAP.md` items the moment they're actually done — not in a batch at session end.
- Stack choices in `docs/02-tech-stack.md` are fixed by default. If a listed crate/library is unmaintained or clearly wrong once you're building, substitute it, note the substitution and a one-line reason under "Deviations" in `PROGRESS.md`, and proceed — this kind of well-justified swap doesn't need permission first.
- Every new feature goes in this order: CLI command → test → (Phase 3+) API route → (Phase 4+) UI affordance. Never add a UI affordance for something that isn't a CLI command yet.

## Before ending a session

Update `PROGRESS.md`:
- Append one entry to the Session Log (newest first) summarizing what was actually completed.
- Update "Current phase" and "Current status."
- Set a concrete, specific "Next Action" — specific enough that a fresh session with no other memory could pick it up immediately.
- Add anything new under "Known Issues / Open Questions" or "Deviations."

## Non-negotiable engineering principles

- **CLI-first**: every capability the API/UI/MCP expose must exist as a documented `aegis` CLI command first. The CLI must remain fully usable standalone with no server/UI running, at every phase. See `docs/01-architecture.md`.
- **Security model is fixed**: no plaintext secrets at rest, no plaintext data ever touches the storage backend. See `docs/10-security-model.md` — re-read it before touching auth (Phase 3) or before the Phase 7 hardening pass.
- **Performance targets are real requirements, not aspirations.** Keep the `criterion` benchmark suite green. See `docs/11-performance-targets.md`.
- **Testing is part of "done."** A checklist item isn't complete without the tests described in `docs/12-testing-strategy.md` for that layer.
- Code should be clear and idiomatic for its language; public APIs (CLI flags, HTTP routes, MCP tools, Rust crate public items) need real documentation. Prefer boring, well-documented library APIs over clever tricks — this system holds people's only copy of their data.

## Docs map — read only what the current phase needs

| Doc | Read during |
|---|---|
| `docs/00-vision.md` | Once, first session |
| `docs/01-architecture.md` | Once, first session; re-check before any cross-cutting change |
| `docs/02-tech-stack.md` | Phase 0 |
| `docs/03-repository-format.md` | Phase 0–1 |
| `docs/04-host-connection-modes.md` | Phase 2, Phase 5 |
| `docs/05-data-model.md` | Phase 2–3 |
| `docs/06-api-spec.md` | Phase 3 |
| `docs/07-web-ui.md` | Phase 4 |
| `docs/08-desktop-apps.md` | Phase 5 |
| `docs/09-mcp-server.md` | Phase 6 |
| `docs/10-security-model.md` | Before Phase 3 (auth) and before Phase 7 (hardening) |
| `docs/11-performance-targets.md` | Phase 1, Phase 7 |
| `docs/12-testing-strategy.md` | Every phase |

## Repo layout (created starting Phase 0 — this file lives at the root of it)

```
aegis/
  CLAUDE.md
  ROADMAP.md
  PROGRESS.md
  docs/
  crates/
    aegis-core/
    aegis-cli/
    aegis-server/
    aegis-agent/
    aegis-mcp/
  web/
    aegis-web/
  desktop/
    aegis-desktop/
  .github/workflows/
```

`crates/`, `web/`, and `desktop/` do not exist yet — they get created during Phase 0. Everything else in this listing already exists.
