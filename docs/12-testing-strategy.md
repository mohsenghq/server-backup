# Testing Strategy ("bug-free and competitive")

A checklist item in `ROADMAP.md` isn't actually done without the tests described here for its layer.

- Unit tests for the chunker, repo format, retention logic.
- Property-based tests (`proptest`) on the chunker/dedup path — random file mutations must still dedup correctly.
- `criterion` benchmark suite tracked in CI to catch performance regressions (targets: `docs/11-performance-targets.md`).
- Integration tests: spin up a real SSH target (container) and exercise agentless + agent modes end to end.
- Chaos tests: kill the connection mid-transfer, verify resume/retry and repo integrity (`aegis verify` must always pass afterward).
- E2E UI tests (Playwright) for the core flows: add host → run backup → restore a file.
- Fuzzing the repository format parser (`cargo-fuzz`) before 1.0 (Phase 7).
