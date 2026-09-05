# API Surface (REST, representative)

```
POST   /api/hosts                  add a host (address, ssh creds, mode)
GET    /api/hosts                  list hosts + live status
DELETE /api/hosts/:id
POST   /api/hosts/:id/test         test SSH connectivity

POST   /api/policies               create a retention/schedule policy
GET    /api/policies

POST   /api/jobs/trigger           { host_id, policy_id } → run now
GET    /api/jobs                   history + filters
WS     /api/jobs/:id/stream        live progress (%, MB/s, ETA)

GET    /api/snapshots?host_id=
POST   /api/restore                { snapshot_id, path, target } → stream/download

GET    /api/stats/storage          per-host and total dedup/storage stats
GET    /metrics                    Prometheus format
```

Every one of these must map directly to a CLI subcommand (`aegis host add`, `aegis job trigger`, `aegis restore …`) so the API is never the only way to do something — see the CLI-first rule in `docs/01-architecture.md`.
