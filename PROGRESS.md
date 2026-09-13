# Progress Tracker

This file is the single source of truth for "where are we." Read it first, every session. Update it last, every session, before ending. See `CLAUDE.md` for the exact protocol.

## Current phase

**Phase 1 — Core Engine (complete, pushed).** All eight checklist items in `ROADMAP.md` are implemented and tested.

**Phase 2 — Agentless Remote Backup (in progress).** The SSH connection manager and the agentless remote-read backup mode are implemented and tested; next up is the host inventory + SQLite catalog.

## Current status

The workspace builds, lints clean (`clippy -D warnings`, `fmt --check`), and 98 tests pass (54 unit + 22 backup/restore integration + 9 property + 5 SFTP + 5 SSH-manager + criterion bench + CLI). `aegis` is a complete Phase 1 core engine; Phase 2 has started with the SSH connection manager (`aegis-core::ssh`).

New in Phase 2:

- `aegis-core::ssh` — the SSH connection manager: `HostConfig` (user/host/port/auth/host-key policy with docs defaults), `SshManager` (per-host connection cache with automatic reconnect after a server-side drop), `exec`/`exec_check` (collects stdout/stderr/exit-status over the exec channel), `sftp_channel` (SFTP sessions multiplexed over the shared connection — the transport for agentless file reads), and `generate_host_keypair` (dedicated per-host ed25519 keypair per docs/04 key hardening) + `write_private_key`/`load_private_key` helpers.
- The connect/auth logic is now shared: `sftp.rs` exposes `connect_handle` (crate-private) used by both the SFTP backend and the connection manager.
- The in-process test SSH server (`tests/sftp_server.rs`) now answers `exec` requests (echo + exit 0), so exec paths are integration-tested without a real sshd; `tests/ssh_manager.rs` covers exec, exec_check, connection reuse across calls, explicit disconnect/reconnect, SFTP streaming over the shared connection, and clean auth-failure errors.
- New workspace dependency: `getrandom = "0.3"` (ssh-key's `PrivateKey::random` needs rand_core 0.10, so the ed25519 keypair is generated from an OS-CSPRNG 32-byte seed via `Ed25519Keypair::from_seed`).
- `aegis-core::agentless` — the agentless remote-read backup: `backup_remote(repo, ssh, host, chunker, &[/abs/paths])` walks remote trees over the SFTP channel, streams every file through the new async chunker (`chunk_async_stream`, the tokio twin of `chunk_stream` — same boundaries, same hashes), dedups against the repository, and commits a snapshot byte-identical in format to a local one. Symlinks/non-regular remote entries are skipped, mirroring the local path. `Repository::store_chunk` and `Repository::commit_snapshot` were factored out of `backup` so both paths share the blob/index/manifest logic.
- Integration tests (`tests/agentless.rs`) run against the in-process SFTP server: backup→deep-verify→byte-identical restore, the dedup property (a second unchanged run writes zero new chunks/nodes), and rejection of relative remote paths. `fastcdc` now enables its `tokio` feature (+ `tokio-stream` for stream iteration).

What exists (Phase 0 items as before, plus all Phase 1 work):

- Rust workspace (`crates/aegis-core`, `aegis-cli`, `aegis-server`, `aegis-agent`, `aegis-mcp`), edition 2021, shared `[workspace.dependencies]`.
- `aegis-core`:
  - `chunk` — FastCDC (`fastcdc` 5.x `v2020`) + BLAKE3, slice and streaming APIs, `ChunkerConfig { min, avg, max }` defaulting to 512 KiB / 1 MiB / 8 MiB.
  - `backend` — the async `Backend` trait (`get`/`put`/`exists`/`list`/`delete`/`size`) with atomic write-temp-then-rename in `LocalBackend`; `sftp` — an SFTP backend over `russh` + `russh-sftp` with host-key pinning (`HostKeyChanged` refuses possible MITM), `sftp://user@host[:port]/path` URL parsing, and ssh-agent support.
  - `tree` — `Node` (`Dir`/`File`/`Ref`), path validation, `build_stored`: nodes serialize under 4 KiB embed inline in their parent; larger ones become their own content-addressed tree blob (`Ref`), so unchanged subtrees dedup at the tree level.
  - `blobs` — versioned `AE1` envelope: `AE1 | version | zstd-compressed | payload`; compression (zstd) applied before encryption on the blob write path, transparently decompressed on read.
  - `crypto` — Argon2id (64 MiB / 3 passes, params recorded per key file) + XChaCha20-Poly1305; master key wrapped into `keys/<slot>.json`; every blob, snapshot manifest, and index is sealed with a fresh 24-byte nonce and AAD role binding (`aegis:blob:<hash>` etc.); `Key` zeroized on drop, redacted in `Debug`.
  - `keys` — `RepoCrypto`/`KeyFile`/`PassphraseSource`: passphrase from `--passphrase-file`, `AEGIS_PASSPHRASE`, or interactive prompt.
  - `repo` — `init`/`open`/`init_with_kdf` over any `Box<dyn Backend>`; `backup` (deterministic sorted trees, one root hash per source path, per-snapshot `SnapshotIndex`); `list_snapshots`/`find_snapshot`; `restore` (streams chunk-by-chunk, bounded memory, unwraps both inline and ref'd synthetic roots); `verify` (shallow manifest/index check and deep full-tree hash re-derivation); `prune` with GFS retention (`retention.rs`: `RetentionPolicy`, `apply_policy`, keep-newest invariant) + garbage collection of unreferenced blobs.
  - `snapshot` — the `snapshots/<id>.json` manifest: id, time, hostname, paths, root, stats.
- `aegis-cli` — `aegis init | backup | snapshots | restore | verify | prune`, plus a global `--json` mode; repo commands take `--passphrase-file FILE`, `AEGIS_PASSPHRASE`, or a TTY prompt; `backup`/`restore`/`init` accept `sftp://` repository URLs.
- `aegis-server`, `aegis-agent`, `aegis-mcp` — compiling stubs only; they exit(1) with a "not implemented yet, see ROADMAP" message.
- `benches/bench.rs` — criterion suite over chunking, hashing, and backup paths; wired into CI.
- `tests/properties.rs` — proptest suite: chunker bounds/exact tiling, shift-resistant re-chunking under append, envelope round-trip, crypto tamper detection, retention invariants (never prunes newest, keeps ≥ keep_last), and an end-to-end arbitrary-tree backup→restore→dedup property. Saved regression seeds in `properties.proptest-regressions`.
- `.github/workflows/ci.yml` — build + test on ubuntu/windows/macos, `fmt --check` + `clippy -D warnings` + criterion benchmarks on ubuntu.

This session also fixed a real bug found by the property suite on Windows: `restore` nested the whole tree one level too deep (`out/root/src/...`) whenever the synthetic root's serialization exceeded the 4 KiB inline limit and was stored as a `Ref` blob; `restore` now fetches and unwraps a ref'd root before laying its children into the target.

## Next action

Continue Phase 2: the host inventory + SQLite catalog (`docs/05-data-model.md`) — the `hosts` table plus CRUD, with SSH keys stored envelope-encrypted.

## Session log

_(newest first — append one short entry per work session; do not delete old entries)_

- **2026-09-13 (2)** — Agentless remote-read backup complete: `aegis-core::agentless::backup_remote` streams remote files over the SSH manager's SFTP channel through a new async chunker, dedups, and commits snapshots identical in format to local ones. Refactored `Repository::backup` to share `store_chunk`/`commit_snapshot` with the new path. 101 tests + clippy `-D warnings` + fmt green; committed locally (push pending).
- **2026-09-13** — Pushed the pending Phase 1 commits (CI now runs against the current tree) and started Phase 2: implemented the SSH connection manager in `aegis-core::ssh` (per-host connection cache, exec/exec_check, sftp_channel multiplexing, per-host ed25519 keypair generation), shared the connect/auth path with the SFTP backend, and taught the in-process test SSH server to answer exec. 98 tests + clippy `-D warnings` + fmt green; committed locally (push pending).
- **2026-09-11** — Resolved the diverged-origin merge (origin carried older drafts of the same Phase 1 work; local HEAD was the superset, so all conflicts resolved with `--ours`) and completed the pull. Fixed the proptest-found restore bug for ref'd synthetic roots (tree > 4 KiB restored one level too deep). Full suite green: 90 tests, clippy `-D warnings`, fmt clean. Brought `PROGRESS.md`/`ROADMAP.md` back in sync with the code (they had drifted; Phase 1 items are all implemented). Merge + fix committed locally; push pending.
- **2026-09-09 (2)** — Phase 1 encryption complete. Added `crypto.rs` (Argon2id KDF, XChaCha20-Poly1305 seal/open with AAD role binding, master-key wrapping into `keys/<keyid>.json`); wired sealing into every blob, snapshot manifest, and the repo config; CLI gained `--passphrase-file` / `AEGIS_PASSPHRASE` on all repo commands. New tests bring the suite to 32; clippy/fmt green. CLI smoke test confirmed: no plaintext at rest, wrong passphrase rejected cleanly. Also pushed the previous session's repository-format work to `origin/main` (first CI run now triggered).
- **2026-09-09** — Phase 1 repository format complete. Replaced the flat snapshot manifest with a Merkle tree (`tree.rs`: Dir/File nodes, inline-vs-blob children, one root hash per source path); added the packed `index/pack.json` with flush and rebuild-from-blobs; made `Repository` backend-generic (`init_with_backend`/`open_with_backend`); made restore stream chunks (bounded memory) and verify restored sizes; bumped format version to 2. Fixed a run-local dedup bug that suppressed chunk writes (caught by the CLI smoke test, then covered by the existing integration tests). 22 tests + clippy `-D warnings` + fmt green; CLI smoke-tested backup→backup→restore with `diff -r` clean.
- **2026-09-05** — Phase 0 complete. Scaffolded the five-crate workspace; implemented FastCDC+BLAKE3 chunking, the async `Backend` trait with `LocalBackend`, and repository init/backup/restore; built the `aegis` CLI with `--json`; wrote 19 tests (chunker determinism / size bounds / reassembly / boundary stability under insertion, backend roundtrip, backup→restore round trip, unchanged-tree no-op, append-reuses-chunks, snapshot ordering stability); added GitHub Actions CI. Had to install a modern Rust toolchain and disable a dead crates.io mirror first (see Deviations).

## Deviations from ROADMAP.md / docs

_(record any substitution of a library/approach from what the docs specify, with a one-line reason)_

- **Rust toolchain installed via rustup (1.98.1).** The system `rustc`/`cargo` at `/usr/bin` was 1.75.0; `clap` 4.6 needs 1.85, `proptest` 1.11 needs 1.85, and `criterion` 0.8 (both Phase 1 items) needs 1.86. rustup is installed user-local in `~/.cargo`; `/usr/bin/rustc` is untouched. `rust-toolchain.toml` pins `stable`. Invoke as `~/.cargo/bin/cargo` (or put `~/.cargo/bin` first on `PATH`).
- **Disabled a dead crates.io mirror in `~/.cargo/config.toml`.** It replaced crates-io with `https://archive.ito.gov.ir/cargo/`, which times out after 30s while `index.crates.io` answers in <0.5s. Cargo offers no way to undo a source replacement from a project-local config when the project lives under `$HOME`, so the block is commented out in place; **the original is saved at `~/.cargo/config.toml.bak`** — restore it if the mirror comes back. This is a machine-local change, not a repo change.
- **`ChunkerConfig` sizes are `usize`, not `u32`.** `fastcdc` 5.0 takes `usize`; converting at every call site was noise.
- **Phase 0 `ponytail` note in `snapshot.rs` resolved**: snapshot manifests are version-2 Merkle trees, not the Phase 0 flat file list. Repositories created before 2026-09-09 fail to open with `UnsupportedFormat` — expected, pre-1.0.
- **The index is a per-snapshot `SnapshotIndex` (`index/<id>.json`) rather than the single `index/pack.json` from an earlier draft**; GC treats every blob referenced by any live snapshot as reachable. It stays plaintext by design (hashes/sizes only, no content, no paths); encrypting it is one call site if reviewers prefer.

## Known issues / open questions

_(anything that needs a second look, or a question for the user before proceeding)_

- **The merge, restore fix, and PROGRESS/ROADMAP updates are committed locally but not pushed**; CI has therefore still not run against the current tree (see next action).
- **The Phase 2 work (SSH manager + agentless backup) is committed locally but not pushed.**
- **No mtime/size fast-path.** Every backup re-reads and re-hashes every file. Dedup means an unchanged tree writes nothing, but it does not yet approach "the speed of a metadata-only walk" as `docs/11-performance-targets.md` requires. The fast-path is described in `docs/03-repository-format.md`.
- **`restore` verifies by size only, not by re-hashing**; `aegis verify --deep` is the full-hash path.
- **Symlinks, hardlinks, empty directories, and non-regular files are skipped** by `backup`. Only regular files are captured. Needs a decision in Phase 1→2 transition on how to represent them in the tree format.
- **Key rotation**: `keys/` supports multiple wrapped slots and `open` tries the configured one, but there is no `aegis key add`/`rotate` command yet (Phase 6 item). A second key file can be created programmatically via `WrappedKey::create`.
- **SFTP backend tests need a real SSH server** (`tests/sftp_server.rs` spins one up locally); confirm they pass in CI on all three runners.
- **Phase 5 needs system packages that require sudo:** Tauri v2 on Linux wants `libwebkit2gtk-4.1-dev`, `libsoup-3.0-dev`, `libjavascriptcoregtk-4.1-dev`, `librsvg2-dev`, and `libayatana-appindicator3-dev` — none are present. Not needed before Phase 5. Everything Phases 0-4 need (cc/gcc/make/pkg-config, docker for the Phase 2 SSH container tests, node 22 + npm 10) is already installed.
