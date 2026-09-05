# MCP Server

Exposes the same operations as the REST API as MCP tools, so an agent (e.g. Claude Code or Claude Desktop) can manage backups conversationally. No duplicated business logic — every tool below calls the same REST API `aegis-web` calls.

- `list_hosts`, `add_host`, `remove_host`
- `trigger_backup`, `get_job_status`, `list_jobs`
- `list_snapshots`, `restore_path`
- `get_storage_stats`
- `list_recent_alerts`

Runs as a stdio MCP server for local agent use, and optionally as an HTTP/SSE MCP server for remote agent access, gated behind the same auth as the REST API.
