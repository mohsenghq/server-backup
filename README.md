# Aegis — self-hosted, deduplicating, multi-server backup

CLI-first backup system: content-defined chunking, real deduplication,
encryption at rest, SSH-only onboarding, a web UI, desktop apps, and an MCP
server. Full vision in `docs/00-vision.md`; current state in `PROGRESS.md`;
the checklist in `ROADMAP.md`.

## Quick start (Docker Compose)

```sh
cp .env.example .env      # set AEGIS_PASSPHRASE (required), tweak the rest
docker compose up -d --build
open http://localhost:8080
```

`AEGIS_PORT` changes the published host port if 8080 is taken; the container
always listens on 8080. All state (catalog, its key sidecar, repositories,
`known_hosts`) lives in the `aegis-data` volume — back that volume up, because
losing the catalog key file means losing the stored host keys.

Create the first admin (passwords come from the environment, never argv), then
add a host in the UI or over the API:

```sh
docker exec -e AEGIS_PASSPHRASE=… -e AEGIS_USER_PASSWORD=… aegis \
    aegis user add --catalog /data/catalog.db --username admin --role admin
```

## Using the CLI

The CLI is the product and works with nothing else running. Every capability
the server, UI, desktop app, and MCP server expose exists here first.

```sh
aegis init      --repo /srv/backups
aegis backup /etc --repo /srv/backups
aegis snapshots    --repo /srv/backups
aegis verify --deep --repo /srv/backups --snapshot <id>
aegis restore --repo /srv/backups --snapshot <id> --target /tmp/restored
aegis host add --name web-1 --address 10.0.0.5 --user root --generate-key
aegis host backup-all --repo /srv/backups /etc /srv/www
```

Add `--json` to any command for machine-readable output. Snapshots are
encrypted (Argon2id + XChaCha20-Poly1305) and compressed; a passphrase is
required for every repository command, taken from `AEGIS_PASSPHRASE`,
`--passphrase-file`, or an interactive prompt.

## Repo layout

- `CLAUDE.md` — rules and entry point (read this first, every session)
- `PROGRESS.md` — living state: current phase, what's done, next action
- `ROADMAP.md` — the full phase-by-phase checklist
- `docs/` — detailed specs, one topic per file
- `crates/` — `aegis-core`, `aegis-cli`, `aegis-server`, `aegis-agent`, `aegis-mcp`, `aegis-web`

