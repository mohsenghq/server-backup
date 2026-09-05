# Security Model

This doc is non-negotiable — re-read it before touching auth (Phase 3) and before the Phase 7 hardening pass.

- Repo data is encrypted client-side (control-plane side in agentless mode, source-side in agent mode) before it ever touches the backend — the storage backend never sees plaintext.
- Master key derived via Argon2id from an operator passphrase; wrapped keys stored in the repo so the passphrase can be rotated without re-encrypting all data.
- SSH private keys for hosts are envelope-encrypted at rest; never logged, never returned by the API after creation.
- All API traffic over TLS (self-signed by default for LAN self-hosting, Let's Encrypt-friendly for public deployments).
- **A compromised source host must not be able to read or corrupt other hosts' backups.**
- **A compromised control plane should not silently corrupt existing snapshots** — blob writes are append-only, `prune` is the only destructive path and it is always explicit and logged (see `docs/03-repository-format.md`, `audit_log` table in `docs/05-data-model.md`).
