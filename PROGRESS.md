# Progress Tracker

This file is the single source of truth for "where are we." Read it first, every session. Update it last, every session, before ending. See `CLAUDE.md` for the exact protocol.

## Current phase

**Phase 1 — Core Engine Complete.** Phase 0 (Foundations) is complete: all six checklist items in `ROADMAP.md` are checked off.

## Current status

The workspace builds, lints clean, and 19 tests pass. `aegis` backs up and restores a real directory tree against a local repository, with working content-defined deduplication.

What exists:

- Rust workspace (`crates/aegis-core`, `aegis-cli`, `aegis-server`, `aegis-agent`, `aegis-mcp`), edition 2021, shared `[workspace.dependencies]`.
- `aegis-core`:
  - `chunk` — FastCDC (`fastcdc` 5.x `v2020`) + BLAKE3, slice and streaming APIs, `ChunkerConfig { min, avg, max }` defaulting to 512 KiB / 1 MiB / 8 MiB.
  - `backend` — the async `Backend` trait (`get`/`put`/`exists`/`list`/`delete`) and `LocalBackend`, which writes `blobs/<xx>/<hash>` and does atomic write-temp-then-rename.
  - `repo` — `init` / `open` / `backup` / `list_snapshots` / `find_snapshot` / `restore`.
  - `snapshot` — the `snapshots/<id>.json` manifest.
- `aegis-cli` — `aegis init | backup | snapshots | restore`, plus a global `--json` mode.
- `aegis-server`, `aegis-agent`, `aegis-mcp` — compiling stubs only; they exit(1) with a "not implemented yet, see ROADMAP" message.
- `.github/workflows/ci.yml` — build + test on ubuntu/windows/macos, `fmt --check` + `clippy -D warnings` on ubuntu.

Verified end to end (`docs/` + `crates/`, 29 files): backup → restore → `diff -r` reports no differences; a second backup of the unchanged tree writes 0 new chunks and the repository's blob count does not grow. `aegis snapshots` cold start measures 0.00s against the < 50ms target in `docs/11-performance-targets.md`.

## Next action

Start Phase 1 with the first checklist item: **the full repository format** (`docs/03-repository-format.md`) — replace the Phase 0 flat file list in `crates/aegis-core/src/snapshot.rs` with a Merkle tree of directory trees rooted in a single hash, and add the `index/` packed blob→location index. Everything else in Phase 1 (encryption, compression, retention/prune, verify, SFTP) layers on top of that format, so it goes first.

Note before starting: `Repository` currently hardcodes `LocalBackend` inside `init`/`open`. Phase 1's SFTP backend item needs those to take a `Box<dyn Backend>` (or a repo URL) instead — worth doing as part of the format work rather than after it.

## Session log

_(newest first — append one short entry per work session; do not delete old entries)_

- **2026-09-05** — Phase 0 complete. Scaffolded the five-crate workspace; implemented FastCDC+BLAKE3 chunking, the async `Backend` trait with `LocalBackend`, and repository init/backup/restore; built the `aegis` CLI with `--json`; wrote 19 tests (chunker determinism / size bounds / reassembly / boundary stability under insertion, backend roundtrip, backup→restore round trip, unchanged-tree no-op, append-reuses-chunks, snapshot ordering stability); added GitHub Actions CI. Had to install a modern Rust toolchain and disable a dead crates.io mirror first (see Deviations).

## Deviations from ROADMAP.md / docs

_(record any substitution of a library/approach from what the docs specify, with a one-line reason)_

- **Rust toolchain installed via rustup (1.98.1).** The system `rustc`/`cargo` at `/usr/bin` was 1.75.0; `clap` 4.6 needs 1.85, `proptest` 1.11 needs 1.85, and `criterion` 0.8 (both Phase 1 items) needs 1.86. rustup is installed user-local in `~/.cargo`; `/usr/bin/rustc` is untouched. `rust-toolchain.toml` pins `stable`. Invoke as `~/.cargo/bin/cargo` (or put `~/.cargo/bin` first on `PATH`).
- **Disabled a dead crates.io mirror in `~/.cargo/config.toml`.** It replaced crates-io with `https://archive.ito.gov.ir/cargo/`, which times out after 30s while `index.crates.io` answers in <0.5s. Cargo offers no way to undo a source replacement from a project-local config when the project lives under `$HOME`, so the block is commented out in place; **the original is saved at `~/.cargo/config.toml.bak`** — restore it if the mirror comes back. This is a machine-local change, not a repo change.
- **`ChunkerConfig` sizes are `usize`, not `u32`.** `fastcdc` 5.0 takes `usize`; converting at every call site was noise.
- **Phase 0 snapshot manifest is a flat file list, not a Merkle tree.** `docs/03-repository-format.md` specifies a tree of trees; building it is the Phase 1 "Full repository format" checklist item. A flat list restores correctly and dedups blobs identically — it just cannot dedup whole subtrees or verify structure by root hash. Marked with a `ponytail:` comment in `crates/aegis-core/src/snapshot.rs`.

## Known issues / open questions

_(anything that needs a second look, or a question for the user before proceeding)_

- **No encryption or compression yet.** Blobs and the repo `config` are written in plaintext. This is intended for Phase 0 (both are Phase 1 checklist items) but means the current repository format does **not** satisfy `docs/10-security-model.md` and must not be pointed at real data yet. `README.md` says so too.
- **No mtime/size fast-path.** Every backup re-reads and re-hashes every file. Dedup means an unchanged tree writes nothing, but it does not yet approach "the speed of a metadata-only walk" as `docs/11-performance-targets.md` requires. The fast-path is described in `docs/03-repository-format.md`; it needs the `redb` index from Phase 1.
- **`restore` buffers each file fully in memory** before writing it. Fine for the current test corpus, wrong for files larger than RAM — worth fixing when the Merkle format lands, since that changes the read path anyway.
- **Symlinks, hardlinks, empty directories, and non-regular files are skipped** by `backup`. Only regular files are captured. Needs a decision in Phase 1 on how to represent them in the tree format.
- **CI has never actually run** — there is no GitHub remote configured for this repo yet, so the workflow is unverified against real runners.
