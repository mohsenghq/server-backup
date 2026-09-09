# Progress Tracker

This file is the single source of truth for "where are we." Read it first, every session. Update it last, every session, before ending. See `CLAUDE.md` for the exact protocol.

## Current phase

**Phase 1 — Core Engine (in progress).** The "Full repository format" checklist item is done; encryption is next.

## Current status

The workspace builds, lints clean, and 22 tests pass. Snapshots are now Merkle trees rooted in a single hash per source path (`docs/03-repository-format.md`), with a packed `index/` blob→location index and a backend-generic `Repository`.

What exists (Phase 0 items as before, plus this session):

- Rust workspace (`crates/aegis-core`, `aegis-cli`, `aegis-server`, `aegis-agent`, `aegis-mcp`), edition 2021, shared `[workspace.dependencies]`.
- `aegis-core`:
  - `chunk` — FastCDC (`fastcdc` 5.x `v2020`) + BLAKE3, slice and streaming APIs, `ChunkerConfig { min, avg, max }` defaulting to 512 KiB / 1 MiB / 8 MiB.
  - `backend` — the async `Backend` trait (`get`/`put`/`exists`/`list`/`delete`/`size`) and `LocalBackend`, which writes `blobs/<xx>/<hash>` and does atomic write-temp-then-rename.
  - `tree` — `TreeNode` (`Dir`/`File`), `TreeEntry`, `NodeRef` (`Inline`/`Blob`). Directories smaller than 4 KiB serialized embed inline in their parent; larger ones become their own content-addressed tree blob, so unchanged subtrees dedup at the tree level.
  - `repo` — `init`/`open`/`init_with_backend`/`open_with_backend` (any `Box<dyn Backend>`), `backup` (deterministic sorted trees, one root hash per source path), `list_snapshots`/`find_snapshot`, `restore` (streams chunk-by-chunk, bounded memory, verifies restored size), `flush_index`/`rebuild_index`, plus the `IndexPack` (`index/pack.json`) blob→key→size index. Format version **2**.
  - `snapshot` — the `snapshots/<id>.json` manifest: id, time, hostname, paths, `roots` (hex tree-root hashes), stats.
- `aegis-cli` — `aegis init | backup | snapshots | restore`, plus a global `--json` mode.
- `aegis-server`, `aegis-agent`, `aegis-mcp` — compiling stubs only; they exit(1) with a "not implemented yet, see ROADMAP" message.
- `.github/workflows/ci.yml` — build + test on ubuntu/windows/macos, `fmt --check` + `clippy -D warnings` on ubuntu.

Verified end to end: 12 MiB random tree → backup → backup (0 new blobs) → restore by short id → `diff -r` clean; index pack holds one entry per stored blob.

## Next action

Next Phase 1 checklist item: **encryption (XChaCha20-Poly1305) + key derivation (Argon2id)** per `docs/03-repository-format.md` and `docs/10-security-model.md` — add `keys/` (wrapped master key per passphrase), encrypt the repo `config`, and encrypt blob payloads on the put/get paths. Re-read `docs/10-security-model.md` before starting. Compression (zstd) stacks on the same write path and can follow immediately after.

## Session log

_(newest first — append one short entry per work session; do not delete old entries)_

- **2026-09-09** — Phase 1 repository format complete. Replaced the flat snapshot manifest with a Merkle tree (`tree.rs`: Dir/File nodes, inline-vs-blob children, one root hash per source path); added the packed `index/pack.json` with flush and rebuild-from-blobs; made `Repository` backend-generic (`init_with_backend`/`open_with_backend`); made restore stream chunks (bounded memory) and verify restored sizes; bumped format version to 2. Fixed a run-local dedup bug that suppressed chunk writes (caught by the CLI smoke test, then covered by the existing integration tests). 22 tests + clippy `-D warnings` + fmt green; CLI smoke-tested backup→backup→restore with `diff -r` clean.
- **2026-09-05** — Phase 0 complete. Scaffolded the five-crate workspace; implemented FastCDC+BLAKE3 chunking, the async `Backend` trait with `LocalBackend`, and repository init/backup/restore; built the `aegis` CLI with `--json`; wrote 19 tests (chunker determinism / size bounds / reassembly / boundary stability under insertion, backend roundtrip, backup→restore round trip, unchanged-tree no-op, append-reuses-chunks, snapshot ordering stability); added GitHub Actions CI. Had to install a modern Rust toolchain and disable a dead crates.io mirror first (see Deviations).

## Deviations from ROADMAP.md / docs

_(record any substitution of a library/approach from what the docs specify, with a one-line reason)_

- **Rust toolchain installed via rustup (1.98.1).** The system `rustc`/`cargo` at `/usr/bin` was 1.75.0; `clap` 4.6 needs 1.85, `proptest` 1.11 needs 1.85, and `criterion` 0.8 (both Phase 1 items) needs 1.86. rustup is installed user-local in `~/.cargo`; `/usr/bin/rustc` is untouched. `rust-toolchain.toml` pins `stable`. Invoke as `~/.cargo/bin/cargo` (or put `~/.cargo/bin` first on `PATH`).
- **Disabled a dead crates.io mirror in `~/.cargo/config.toml`.** It replaced crates-io with `https://archive.ito.gov.ir/cargo/`, which times out after 30s while `index.crates.io` answers in <0.5s. Cargo offers no way to undo a source replacement from a project-local config when the project lives under `$HOME`, so the block is commented out in place; **the original is saved at `~/.cargo/config.toml.bak`** — restore it if the mirror comes back. This is a machine-local change, not a repo change.
- **`ChunkerConfig` sizes are `usize`, not `u32`.** `fastcdc` 5.0 takes `usize`; converting at every call site was noise.
- **Snapshot manifests are version-2 Merkle trees, not the Phase 0 flat file list.** Repositories created before 2026-09-09 will fail to open with `UnsupportedFormat` — expected, pre-1.0. `docs/03-repository-format.md` specifies a tree of trees; this session built it. The Phase 0 `ponytail` note in `snapshot.rs` is resolved.

## Known issues / open questions

_(anything that needs a second look, or a question for the user before proceeding)_

- **No encryption or compression yet.** Blobs and the repo `config` are written in plaintext. Both are Phase 1 checklist items and are now the **next** items; until they land the repository format does **not** satisfy `docs/10-security-model.md` and must not be pointed at real data yet. `README.md` says so too.
- **No mtime/size fast-path.** Every backup re-reads and re-hashes every file. Dedup means an unchanged tree writes nothing, but it does not yet approach "the speed of a metadata-only walk" as `docs/11-performance-targets.md` requires. The fast-path is described in `docs/03-repository-format.md`.
- **The `index/` pack is a single JSON document, not `redb`.** Fine for current corpus sizes; the `redb` index (and pack sharding if needed) is a follow-up when the fast-path and prune work needs keyed lookups.
- **`restore` verifies by size only, not by re-hashing.** Full hash verification is the `aegis verify` item later in Phase 1.
- **Symlinks, hardlinks, empty directories, and non-regular files are skipped** by `backup`. Only regular files are captured. Needs a decision in Phase 1 on how to represent them in the tree format.
- **CI has never actually run.** The remote is `git@github.com:mohsenghq/server-backup.git` (reachable); the Phase 0 commit is not pushed yet, so `.github/workflows/ci.yml` is unverified against real runners. It will fire on the first push to `main`.
- **Phase 5 needs system packages that require sudo:** Tauri v2 on Linux wants `libwebkit2gtk-4.1-dev`, `libsoup-3.0-dev`, `libjavascriptcoregtk-4.1-dev`, `librsvg2-dev`, and `libayatana-appindicator3-dev` — none are present. Not needed before Phase 5. Everything Phases 0-4 need (cc/gcc/make/pkg-config, docker for the Phase 2 SSH container tests, node 22 + npm 10) is already installed.
