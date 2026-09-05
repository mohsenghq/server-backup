# Performance Targets

These are requirements, not aspirations. Keep the `criterion` benchmark suite (Phase 1) green against these numbers.

- Chunking + hashing throughput: ≥ 400–500 MB/s per core (BLAKE3 is SIMD-friendly — this is achievable, not aspirational).
- Agent idle memory: < 30MB RSS.
- CLI cold start: < 50ms for metadata commands (`aegis snapshots`, `aegis host list`).
- Static binary size: < 15MB per target arch.
- Backup of an unchanged filesystem tree (no new data) should approach the speed of a metadata-only walk, not a full re-read — see the mtime/size fast-path in `docs/03-repository-format.md`.
