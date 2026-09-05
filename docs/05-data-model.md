# Data Model (catalog DB)

Applies to both SQLite (default) and Postgres (via the same `sqlx` queries).

```sql
CREATE TABLE hosts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  ssh_port INTEGER NOT NULL DEFAULT 22,
  ssh_user TEXT NOT NULL,
  ssh_key_encrypted BLOB NOT NULL,
  mode TEXT NOT NULL DEFAULT 'agentless',
  status TEXT NOT NULL DEFAULT 'unknown',
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  schedule_cron TEXT NOT NULL,
  retention_json TEXT NOT NULL,
  paths_json TEXT NOT NULL,
  exclude_json TEXT NOT NULL,
  bandwidth_limit_kbps INTEGER,
  pre_hook TEXT,
  post_hook TEXT
);

CREATE TABLE host_policies (
  host_id TEXT REFERENCES hosts(id),
  policy_id TEXT REFERENCES policies(id),
  PRIMARY KEY (host_id, policy_id)
);

CREATE TABLE jobs (
  id TEXT PRIMARY KEY,
  host_id TEXT REFERENCES hosts(id),
  policy_id TEXT REFERENCES policies(id),
  status TEXT NOT NULL,
  started_at TIMESTAMP,
  finished_at TIMESTAMP,
  bytes_new INTEGER,
  bytes_total INTEGER,
  error TEXT
);

CREATE TABLE snapshots (
  id TEXT PRIMARY KEY,
  host_id TEXT REFERENCES hosts(id),
  job_id TEXT REFERENCES jobs(id),
  repo_ref TEXT NOT NULL,
  size_bytes INTEGER,
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin'
);

CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  action TEXT NOT NULL,
  detail TEXT,
  created_at TIMESTAMP NOT NULL
);
```
