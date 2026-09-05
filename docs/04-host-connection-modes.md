# Host Connection Modes

## Agentless (default — "just give me SSH")

`aegis-server` opens an SSH session to the target, reads files remotely (streamed, never staged to disk on the target), and does chunking/hashing/compression/encryption **on the control-plane side**. Zero footprint on the target beyond the SSH session itself. This is the direct, modernized equivalent of BackupPC's pull model, but with real content-defined dedup instead of whole-file dedup.

## Agent mode (opt-in, auto-provisioned)

For large datasets, chunking on the source avoids re-transferring unchanged data every run. When enabled per-host, `aegis-server`:

1. Detects target OS/arch over the existing SSH session.
2. `sftp`-copies the matching static `aegis` binary to a temp path.
3. Runs `aegis agent --once` (or as a systemd unit if the user opts into persistent mode) which chunks/hashes locally and only ships new/changed chunks back over the same SSH channel.
4. Manages upgrades the same way — no manual install step, still "just SSH" from the user's point of view.

Hosts that can't run the agent (restricted shell, unsupported arch) transparently fall back to agentless mode.

## Capacity-aware routing

Host inventory tracks per-host capacity/health so multi-host orchestration (`aegis host backup-all`) can route around a full or unhealthy host and report aggregate stats — same pattern as capacity-aware client routing in other multi-server systems the user runs.

## SSH key hardening

- Generate a dedicated ed25519 keypair per host at add-time; the private key is stored encrypted (envelope-encrypted with the server's master key, never written to disk in plaintext).
- Recommend (and provide a one-click helper for) restricting the key in the target's `authorized_keys` with a `command=` restriction so it can only run the agent/backup invocation Aegis needs — limits blast radius if a key ever leaks.
