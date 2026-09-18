//! The catalog: a SQLite database recording hosts, policies, jobs, snapshots,
//! users, and the audit log (`docs/05-data-model.md`).
//!
//! SSH private keys are never stored in the clear: they are sealed with the
//! same XChaCha20-Poly1305 AEAD used for repository data, bound to the
//! `aegis:host:<id>` role, so a stolen catalog file yields no credentials
//! without the control-plane key.
//!
//! Queries are runtime-checked `sqlx` (no compile-time macros), keeping the
//! build independent of a live database; the same statements run against
//! Postgres by swapping the pool (a Phase 3 concern).

use std::path::Path;
use std::str::FromStr;

use serde::Serialize;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqliteRow},
    Row,
};

use crate::crypto::{self, KEY_LEN, NONCE_LEN};
use crate::error::{Error, Result};
use crate::keys::AeadContext;

#[allow(missing_docs)]
#[path = "catalog_auth.rs"]
pub mod auth;

pub use auth::{Session, User};

/// How a host is backed up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupMode {
    /// No agent; the control plane reads files over SSH (default).
    Agentless,
    /// The `aegis-agent` runs on the target and pushes.
    Agent,
}

impl BackupMode {
    /// The string stored in the catalog's `mode` column.
    pub fn as_str(self) -> &'static str {
        match self {
            BackupMode::Agentless => "agentless",
            BackupMode::Agent => "agent",
        }
    }
}

impl FromStr for BackupMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "agentless" => Ok(BackupMode::Agentless),
            "agent" => Ok(BackupMode::Agent),
            other => Err(Error::Catalog(format!("unknown backup mode `{other}`"))),
        }
    }
}

/// Reachability of a host as last observed by the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    /// Never probed (the state right after registration).
    Unknown,
    /// Last connection attempt succeeded.
    Reachable,
    /// Last connection attempt failed.
    Unreachable,
}

impl HostStatus {
    /// The string stored in the catalog's `status` column.
    pub fn as_str(self) -> &'static str {
        match self {
            HostStatus::Unknown => "unknown",
            HostStatus::Reachable => "reachable",
            HostStatus::Unreachable => "unreachable",
        }
    }
}

impl FromStr for HostStatus {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "unknown" => Ok(HostStatus::Unknown),
            "reachable" => Ok(HostStatus::Reachable),
            "unreachable" => Ok(HostStatus::Unreachable),
            other => Err(Error::Catalog(format!("unknown host status `{other}`"))),
        }
    }
}

/// A registered backup target.
#[derive(Debug, Clone)]
pub struct Host {
    /// Stable identifier (UUID v4).
    pub id: String,
    /// Human-friendly display name.
    pub name: String,
    /// Hostname or IP the control plane connects to.
    pub address: String,
    /// SSH port (default 22).
    pub ssh_port: u16,
    /// SSH login user.
    pub ssh_user: String,
    /// How this host is backed up.
    pub mode: BackupMode,
    /// Reachability as last observed.
    pub status: HostStatus,
    /// Seconds since the Unix epoch when the host was registered.
    pub created_at: i64,
}

/// A host together with its decrypted SSH private key (PEM). Transient — the
/// key material never persists outside the process.
#[derive(Debug)]
pub struct HostWithKey {
    /// The host record.
    pub host: Host,
    /// PEM-encoded private key, decrypted on read.
    pub ssh_key_pem: Vec<u8>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS hosts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  ssh_port INTEGER NOT NULL DEFAULT 22,
  ssh_user TEXT NOT NULL,
  ssh_key_encrypted BLOB NOT NULL,
  mode TEXT NOT NULL DEFAULT 'agentless',
  status TEXT NOT NULL DEFAULT 'unknown',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  schedule_cron TEXT NOT NULL,
  retention_json TEXT NOT NULL,
  paths_json TEXT NOT NULL,
  exclude_json TEXT NOT NULL,
  bandwidth_limit_kbps INTEGER,
  pre_hook TEXT,
  post_hook TEXT,
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS host_policies (
  host_id TEXT REFERENCES hosts(id),
  policy_id TEXT REFERENCES policies(id),
  PRIMARY KEY (host_id, policy_id)
);

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  host_id TEXT REFERENCES hosts(id),
  policy_id TEXT REFERENCES policies(id),
  status TEXT NOT NULL,
  started_at INTEGER,
  finished_at INTEGER,
  bytes_new INTEGER,
  bytes_total INTEGER,
  error TEXT
);

CREATE TABLE IF NOT EXISTS snapshots (
  id TEXT PRIMARY KEY,
  host_id TEXT REFERENCES hosts(id),
  job_id TEXT REFERENCES jobs(id),
  repo_ref TEXT NOT NULL,
  size_bytes INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin'
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS login_limits (
  bucket TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  attempts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  action TEXT NOT NULL,
  detail TEXT,
  created_at INTEGER NOT NULL
);
";

/// The catalog database.
#[derive(Debug, Clone)]
pub struct Catalog {
    pool: SqlitePool,
}

impl Catalog {
    /// Open (creating if needed) the catalog at `path`.
    pub async fn open(path: &Path) -> Result<Self> {
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .map_err(|e| Error::Catalog(e.to_string()))?
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options)
            .await
            .map_err(|e| Error::Catalog(format!("opening catalog: {e}")))?;
        sqlx::raw_sql(SCHEMA)
            .execute(&pool)
            .await
            .map_err(|e| Error::Catalog(format!("creating schema: {e}")))?;
        Ok(Self { pool })
    }

    /// A purely in-memory catalog (useful for tests and ephemeral use).
    pub async fn in_memory() -> Result<Self> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(|e| Error::Catalog(e.to_string()))?
            .foreign_keys(true);
        let pool = SqlitePool::connect_with(options)
            .await
            .map_err(|e| Error::Catalog(format!("opening catalog: {e}")))?;
        sqlx::raw_sql(SCHEMA)
            .execute(&pool)
            .await
            .map_err(|e| Error::Catalog(format!("creating schema: {e}")))?;
        Ok(Self { pool })
    }

    /// Register a host. `ssh_key_pem` is a PEM-encoded private key; it is
    /// sealed with the control-plane key before it touches disk.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_host(
        &self,
        name: &str,
        address: &str,
        ssh_port: u16,
        ssh_user: &str,
        ssh_key_pem: &[u8],
        mode: BackupMode,
        master_key: &[u8; KEY_LEN],
    ) -> Result<Host> {
        if master_key.len() != KEY_LEN {
            return Err(Error::Catalog("master key must be 32 bytes".into()));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = now_secs();
        let nonce = fresh_nonce();
        let sealed = crypto::seal(
            master_key,
            &nonce,
            &AeadContext::Host(&id).aad(),
            ssh_key_pem,
        )
        .map_err(|e| Error::Catalog(format!("sealing ssh key: {e}")))?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&sealed);
        sqlx::query(
            "INSERT INTO hosts (id, name, address, ssh_port, ssh_user, ssh_key_encrypted, mode, status, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(name)
        .bind(address)
        .bind(i64::from(ssh_port))
        .bind(ssh_user)
        .bind(&blob[..])
        .bind(mode.as_str())
        .bind(HostStatus::Unknown.as_str())
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Catalog(format!("inserting host: {e}")))?;
        Ok(Host {
            id,
            name: name.to_string(),
            address: address.to_string(),
            ssh_port,
            ssh_user: ssh_user.to_string(),
            mode,
            status: HostStatus::Unknown,
            created_at,
        })
    }

    /// List all registered hosts (no key material).
    pub async fn list_hosts(&self) -> Result<Vec<Host>> {
        let rows = sqlx::query(
            "SELECT id, name, address, ssh_port, ssh_user, mode, status, created_at
             FROM hosts ORDER BY created_at, id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Catalog(format!("listing hosts: {e}")))?;
        rows.iter().map(host_from_row).collect()
    }

    /// Fetch one host by id (no key material).
    pub async fn get_host(&self, id: &str) -> Result<Host> {
        let row = sqlx::query(
            "SELECT id, name, address, ssh_port, ssh_user, mode, status, created_at
             FROM hosts WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Catalog(format!("fetching host: {e}")))?
        .ok_or_else(|| Error::Catalog(format!("host `{id}` not found")))?;
        host_from_row(&row)
    }

    /// Fetch one host together with its decrypted SSH key.
    pub async fn get_host_with_key(
        &self,
        id: &str,
        master_key: &[u8; KEY_LEN],
    ) -> Result<HostWithKey> {
        let row = sqlx::query("SELECT * FROM hosts WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::Catalog(format!("fetching host: {e}")))?
            .ok_or_else(|| Error::Catalog(format!("host `{id}` not found")))?;
        let host = host_from_row(&row)?;
        let sealed: Vec<u8> = row
            .try_get("ssh_key_encrypted")
            .map_err(|e| Error::Catalog(format!("reading ssh key column: {e}")))?;
        let pem = crypto::open(master_key, &AeadContext::Host(id).aad(), &sealed)
            .map_err(|_| Error::DecryptFailed("host ssh key".into()))?;
        Ok(HostWithKey {
            host,
            ssh_key_pem: pem,
        })
    }

    /// Update a host's reachability status.
    pub async fn set_host_status(&self, id: &str, status: HostStatus) -> Result<()> {
        let res = sqlx::query("UPDATE hosts SET status = ? WHERE id = ?")
            .bind(status.as_str())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Catalog(format!("updating host status: {e}")))?;
        if res.rows_affected() == 0 {
            return Err(Error::Catalog(format!("host `{id}` not found")));
        }
        Ok(())
    }

    /// Rotate a host's SSH key (re-seals the new PEM under the same id).
    pub async fn set_host_key(
        &self,
        id: &str,
        ssh_key_pem: &[u8],
        master_key: &[u8; KEY_LEN],
    ) -> Result<()> {
        let nonce = fresh_nonce();
        let sealed = crypto::seal(
            master_key,
            &nonce,
            &AeadContext::Host(id).aad(),
            ssh_key_pem,
        )
        .map_err(|e| Error::Catalog(format!("sealing ssh key: {e}")))?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&sealed);
        let res = sqlx::query("UPDATE hosts SET ssh_key_encrypted = ? WHERE id = ?")
            .bind(&blob[..])
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Catalog(format!("updating ssh key: {e}")))?;
        if res.rows_affected() == 0 {
            return Err(Error::Catalog(format!("host `{id}` not found")));
        }
        Ok(())
    }

    /// Remove a host.
    pub async fn remove_host(&self, id: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM hosts WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Catalog(format!("removing host: {e}")))?;
        Ok(res.rows_affected() > 0)
    }

    /// Append an audit-log entry.
    pub async fn audit(
        &self,
        user_id: Option<&str>,
        action: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_log (id, user_id, action, detail, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(action)
        .bind(detail)
        .bind(now_secs())
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Catalog(format!("writing audit log: {e}")))?;
        Ok(())
    }

    /// Read the audit log, newest first.
    pub async fn audit_log(&self, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT id, user_id, action, detail, created_at
             FROM audit_log ORDER BY created_at DESC, id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Catalog(format!("reading audit log: {e}")))?;
        Ok(rows
            .iter()
            .map(|r| AuditEntry {
                id: r.try_get(0).unwrap_or_default(),
                user_id: r.try_get(1).unwrap_or(None),
                action: r.try_get(2).unwrap_or_default(),
                detail: r.try_get(3).unwrap_or(None),
                created_at: r.try_get(4).unwrap_or_default(),
            })
            .collect())
    }

    /// Register a backup policy.
    pub async fn add_policy(&self, policy: &Policy) -> Result<Policy> {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO policies (id, name, schedule_cron, retention_json, paths_json, exclude_json, bandwidth_limit_kbps, pre_hook, post_hook, enabled)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
        )
        .bind(&id)
        .bind(&policy.name)
        .bind(&policy.schedule_cron)
        .bind(&policy.retention_json)
        .bind(&policy.paths_json)
        .bind(&policy.exclude_json)
        .bind(policy.bandwidth_limit_kbps)
        .bind(policy.pre_hook.clone())
        .bind(policy.post_hook.clone())
        .execute(&self.pool)
        .await
        .map_err(|e| match e.as_database_error() {
            Some(db) if db.is_unique_violation() => {
                Error::InvalidInput(format!("policy name `{}` already exists", policy.name))
            }
            _ => Error::Catalog(format!("inserting policy: {e}")),
        })?;
        Ok(Policy {
            id,
            name: policy.name.clone(),
            schedule_cron: policy.schedule_cron.clone(),
            retention_json: policy.retention_json.clone(),
            paths_json: policy.paths_json.clone(),
            exclude_json: policy.exclude_json.clone(),
            bandwidth_limit_kbps: policy.bandwidth_limit_kbps,
            pre_hook: policy.pre_hook.clone(),
            post_hook: policy.post_hook.clone(),
            enabled: true,
        })
    }

    /// List all policies.
    pub async fn list_policies(&self) -> Result<Vec<Policy>> {
        let rows = sqlx::query("SELECT id, name, schedule_cron, retention_json, paths_json, exclude_json, bandwidth_limit_kbps, pre_hook, post_hook, enabled FROM policies ORDER BY name")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Catalog(format!("listing policies: {e}")))?;
        rows.iter().map(Policy::from_row).collect()
    }

    /// Fetch one policy by id.
    pub async fn get_policy(&self, id: &str) -> Result<Policy> {
        let row = sqlx::query(
            "SELECT id, name, schedule_cron, retention_json, paths_json, exclude_json, bandwidth_limit_kbps, pre_hook, post_hook, enabled FROM policies WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Catalog(format!("fetching policy: {e}")))?
        .ok_or_else(|| Error::Catalog(format!("policy `{id}` not found")))?;
        Policy::from_row(&row)
    }

    /// Update a policy (all fields except id are mutable).
    pub async fn update_policy(&self, id: &str, policy: &Policy) -> Result<Policy> {
        sqlx::query(
            "UPDATE policies SET name = ?, schedule_cron = ?, retention_json = ?, paths_json = ?, exclude_json = ?, bandwidth_limit_kbps = ?, pre_hook = ?, post_hook = ?, enabled = ? WHERE id = ?",
        )
        .bind(&policy.name)
        .bind(&policy.schedule_cron)
        .bind(&policy.retention_json)
        .bind(&policy.paths_json)
        .bind(&policy.exclude_json)
        .bind(policy.bandwidth_limit_kbps)
        .bind(policy.pre_hook.clone())
        .bind(policy.post_hook.clone())
        .bind(policy.enabled)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Catalog(format!("updating policy: {e}")))?;
        self.get_policy(id).await
    }

    /// List hosts attached to a policy via `host_policies`.
    pub async fn list_hosts_for_policy(&self, policy_id: &str) -> Result<Vec<Host>> {
        let rows = sqlx::query(
            "SELECT h.id, h.name, h.address, h.ssh_port, h.ssh_user, h.mode, h.status, h.created_at
             FROM host_policies hp
             JOIN hosts h ON h.id = hp.host_id
             WHERE hp.policy_id = ?",
        )
        .bind(policy_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Catalog(format!("listing hosts for policy: {e}")))?;
        rows.iter().map(host_from_row).collect()
    }

    /// Remove a policy and its host-policy assignments.
    pub async fn remove_policy(&self, id: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM policies WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Catalog(format!("removing policy: {e}")))?;
        Ok(res.rows_affected() > 0)
    }

    /// Record a new job run as `running`.
    pub async fn record_job_started(
        &self,
        job_id: &str,
        host_id: &str,
        policy_id: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO jobs (id, host_id, policy_id, status, started_at) VALUES (?, ?, ?, 'running', ?)",
        )
        .bind(job_id)
        .bind(host_id)
        .bind(policy_id)
        .bind(now_secs())
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Catalog(format!("recording job start: {e}")))?;
        Ok(())
    }

    /// Mark a job as completed.
    pub async fn record_job_completed(
        &self,
        job_id: &str,
        bytes_new: i64,
        bytes_total: i64,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE jobs SET status = 'completed', finished_at = ?, bytes_new = ?, bytes_total = ? WHERE id = ?",
        )
        .bind(now_secs())
        .bind(bytes_new)
        .bind(bytes_total)
        .bind(job_id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Catalog(format!("recording job completion: {e}")))?;
        Ok(())
    }

    /// Mark a job as failed.
    pub async fn record_job_failed(&self, job_id: &str, error: &str) -> Result<()> {
        sqlx::query("UPDATE jobs SET status = 'failed', finished_at = ?, error = ? WHERE id = ?")
            .bind(now_secs())
            .bind(error)
            .bind(job_id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Catalog(format!("recording job failure: {e}")))?;
        Ok(())
    }

    /// List jobs with optional filters (host_id, policy_id, status).
    /// Results are newest-first, paginated.
    pub async fn list_jobs(
        &self,
        host_id: Option<&str>,
        policy_id: Option<&str>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Job>> {
        let mut sql = String::from("SELECT id, host_id, policy_id, status, started_at, finished_at, bytes_new, bytes_total, error FROM jobs WHERE 1=1");
        if host_id.is_some() {
            sql.push_str(" AND host_id = ?");
        }
        if policy_id.is_some() {
            sql.push_str(" AND policy_id = ?");
        }
        if status.is_some() {
            sql.push_str(" AND status = ?");
        }
        sql.push_str(" ORDER BY started_at DESC LIMIT ? OFFSET ?");
        let mut query = sqlx::query(&sql);
        if let Some(h) = host_id {
            query = query.bind(h);
        }
        if let Some(p) = policy_id {
            query = query.bind(p);
        }
        if let Some(s) = status {
            query = query.bind(s);
        }
        query = query.bind(limit).bind(offset);
        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Catalog(format!("listing jobs: {e}")))?;
        rows.iter().map(job_from_row).collect()
    }
}

/// A job record from the catalog.
#[derive(Debug, Clone, Serialize)]
pub struct Job {
    /// Stable identifier (UUID v4).
    pub id: String,
    /// Host this job ran against.
    pub host_id: String,
    /// Policy this job ran under.
    pub policy_id: String,
    /// Current status: `running`, `completed`, or `failed`.
    pub status: String,
    /// Seconds since Unix epoch when the job started.
    pub started_at: i64,
    /// Seconds since Unix epoch when the job finished.
    pub finished_at: Option<i64>,
    /// New bytes written to the backend by this job.
    pub bytes_new: i64,
    /// Total bytes read from the source by this job.
    pub bytes_total: i64,
    /// Error message if the job failed.
    pub error: Option<String>,
}

fn job_from_row(row: &SqliteRow) -> Result<Job> {
    Ok(Job {
        id: row
            .try_get("id")
            .map_err(|e| Error::Catalog(format!("reading job id: {e}")))?,
        host_id: row
            .try_get("host_id")
            .map_err(|e| Error::Catalog(format!("reading job host_id: {e}")))?,
        policy_id: row
            .try_get("policy_id")
            .map_err(|e| Error::Catalog(format!("reading job policy_id: {e}")))?,
        status: row
            .try_get("status")
            .map_err(|e| Error::Catalog(format!("reading job status: {e}")))?,
        started_at: row
            .try_get("started_at")
            .map_err(|e| Error::Catalog(format!("reading job started_at: {e}")))?,
        finished_at: row
            .try_get("finished_at")
            .map_err(|e| Error::Catalog(format!("reading job finished_at: {e}")))?,
        bytes_new: row
            .try_get("bytes_new")
            .map_err(|e| Error::Catalog(format!("reading job bytes_new: {e}")))?,
        bytes_total: row
            .try_get("bytes_total")
            .map_err(|e| Error::Catalog(format!("reading job bytes_total: {e}")))?,
        error: row
            .try_get("error")
            .map_err(|e| Error::Catalog(format!("reading job error: {e}")))?,
    })
}

/// A registered backup policy.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Stable identifier (UUID v4).
    pub id: String,
    /// Human-friendly name.
    pub name: String,
    /// Cron expression for the schedule.
    pub schedule_cron: String,
    /// Serialized retention configuration.
    pub retention_json: String,
    /// Serialized JSON array of absolute remote paths to back up.
    pub paths_json: String,
    /// Serialized JSON array of exclude patterns.
    pub exclude_json: String,
    /// Optional bandwidth limit in kbps.
    pub bandwidth_limit_kbps: Option<i32>,
    /// Pre-backup hook command.
    pub pre_hook: Option<String>,
    /// Post-backup hook command.
    pub post_hook: Option<String>,
    /// Whether the schedule is active.
    pub enabled: bool,
}

impl Policy {
    fn from_row(row: &SqliteRow) -> Result<Self> {
        Ok(Policy {
            id: row
                .try_get("id")
                .map_err(|e| Error::Catalog(format!("reading policy id: {e}")))?,
            name: row
                .try_get("name")
                .map_err(|e| Error::Catalog(format!("reading policy name: {e}")))?,
            schedule_cron: row
                .try_get("schedule_cron")
                .map_err(|e| Error::Catalog(format!("reading schedule_cron: {e}")))?,
            retention_json: row
                .try_get("retention_json")
                .map_err(|e| Error::Catalog(format!("reading retention_json: {e}")))?,
            paths_json: row
                .try_get("paths_json")
                .map_err(|e| Error::Catalog(format!("reading paths_json: {e}")))?,
            exclude_json: row
                .try_get("exclude_json")
                .map_err(|e| Error::Catalog(format!("reading exclude_json: {e}")))?,
            bandwidth_limit_kbps: row
                .try_get("bandwidth_limit_kbps")
                .map_err(|e| Error::Catalog(format!("reading bandwidth_limit_kbps: {e}")))?,
            pre_hook: row
                .try_get("pre_hook")
                .map_err(|e| Error::Catalog(format!("reading pre_hook: {e}")))?,
            post_hook: row
                .try_get("post_hook")
                .map_err(|e| Error::Catalog(format!("reading post_hook: {e}")))?,
            enabled: row
                .try_get("enabled")
                .map_err(|e| Error::Catalog(format!("reading enabled: {e}")))?,
        })
    }
}

/// One audit-log row.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Row id (UUID v4).
    pub id: String,
    /// Acting user, if the action was attributed.
    pub user_id: Option<String>,
    /// Action name (e.g. `host.add`, `backup.run`).
    pub action: String,
    /// Optional free-form detail.
    pub detail: Option<String>,
    /// Seconds since the Unix epoch.
    pub created_at: i64,
}

fn fresh_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    getrandom::fill(&mut n).expect("OS CSPRNG unavailable");
    n
}

/// Returns the current Unix timestamp in seconds.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn host_from_row(row: &SqliteRow) -> Result<Host> {
    let port: i64 = row
        .try_get("ssh_port")
        .map_err(|e| Error::Catalog(format!("reading ssh_port: {e}")))?;
    let mode: String = row
        .try_get("mode")
        .map_err(|e| Error::Catalog(format!("reading mode: {e}")))?;
    let status: String = row
        .try_get("status")
        .map_err(|e| Error::Catalog(format!("reading status: {e}")))?;
    Ok(Host {
        id: row.try_get("id").unwrap_or_default(),
        name: row.try_get("name").unwrap_or_default(),
        address: row.try_get("address").unwrap_or_default(),
        ssh_port: u16::try_from(port)
            .map_err(|_| Error::Catalog("ssh_port out of range".into()))?,
        ssh_user: row.try_get("ssh_user").unwrap_or_default(),
        mode: mode.parse()?,
        status: status.parse()?,
        created_at: row.try_get("created_at").unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_LEN] {
        [7u8; KEY_LEN]
    }

    #[tokio::test]
    async fn schema_creates_all_tables() {
        let cat = Catalog::in_memory().await.unwrap();
        // Every table in docs/05 exists.
        for table in [
            "hosts",
            "policies",
            "host_policies",
            "jobs",
            "snapshots",
            "users",
            "audit_log",
        ] {
            let n: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='{table}'"
            ))
            .fetch_one(&cat.pool)
            .await
            .unwrap();
            assert_eq!(n, 1, "table {table} missing");
        }
    }

    #[tokio::test]
    async fn users_schema_defaults_to_admin_and_rejects_duplicate_usernames() {
        let cat = Catalog::in_memory().await.unwrap();
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)")
            .bind("user-1")
            .bind("admin")
            .bind("test-only-placeholder")
            .execute(&cat.pool)
            .await
            .unwrap();

        let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = ?")
            .bind("user-1")
            .fetch_one(&cat.pool)
            .await
            .unwrap();
        assert_eq!(role, "admin");

        let duplicate =
            sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)")
                .bind("user-2")
                .bind("admin")
                .bind("another-test-only-placeholder")
                .execute(&cat.pool)
                .await
                .unwrap_err();
        assert!(duplicate.as_database_error().unwrap().is_unique_violation());
    }

    #[tokio::test]
    async fn host_crud_roundtrip() {
        let cat = Catalog::in_memory().await.unwrap();
        let key = test_key();

        let host = cat
            .add_host(
                "web-1",
                "10.0.0.5",
                2222,
                "root",
                b"-----BEGIN KEY-----\nabc\n",
                BackupMode::Agentless,
                &key,
            )
            .await
            .unwrap();
        assert_eq!(host.ssh_port, 2222);
        assert_eq!(host.mode, BackupMode::Agentless);
        assert_eq!(host.status, HostStatus::Unknown);

        let got = cat.get_host(&host.id).await.unwrap();
        assert_eq!(got.name, "web-1");

        let with_key = cat.get_host_with_key(&host.id, &key).await.unwrap();
        assert_eq!(with_key.ssh_key_pem, b"-----BEGIN KEY-----\nabc\n");

        // Wrong key must not decrypt.
        let bad = [0u8; KEY_LEN];
        assert!(cat.get_host_with_key(&host.id, &bad).await.is_err());

        cat.set_host_status(&host.id, HostStatus::Reachable)
            .await
            .unwrap();
        assert_eq!(
            cat.get_host(&host.id).await.unwrap().status,
            HostStatus::Reachable
        );

        // Key rotation round-trips.
        cat.set_host_key(&host.id, b"new-pem", &key).await.unwrap();
        assert_eq!(
            cat.get_host_with_key(&host.id, &key)
                .await
                .unwrap()
                .ssh_key_pem,
            b"new-pem"
        );

        assert!(cat.remove_host(&host.id).await.unwrap());
        assert!(cat.get_host(&host.id).await.is_err());
        assert!(!cat.remove_host(&host.id).await.unwrap());
    }

    #[tokio::test]
    async fn audit_log_roundtrip() {
        let cat = Catalog::in_memory().await.unwrap();
        cat.audit(Some("u1"), "host.add", Some("web-1"))
            .await
            .unwrap();
        cat.audit(None, "backup.run", None).await.unwrap();
        let log = cat.audit_log(10).await.unwrap();
        assert_eq!(log.len(), 2);
        // Both same-second entries present (order within a second is
        // nondeterministic because ids are random UUIDs).
        let mut actions: Vec<&str> = log.iter().map(|e| e.action.as_str()).collect();
        actions.sort_unstable();
        assert_eq!(actions, ["backup.run", "host.add"]);
        assert!(log
            .iter()
            .any(|e| e.action == "host.add" && e.user_id.as_deref() == Some("u1")));
    }

    #[tokio::test]
    async fn on_disk_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.db");
        let key = test_key();
        {
            let cat = Catalog::open(&path).await.unwrap();
            cat.add_host(
                "db-1",
                "10.0.0.9",
                22,
                "ops",
                b"pem",
                BackupMode::Agent,
                &key,
            )
            .await
            .unwrap();
        }
        let cat = Catalog::open(&path).await.unwrap();
        let hosts = cat.list_hosts().await.unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].mode, BackupMode::Agent);
        assert_eq!(
            cat.get_host_with_key(&hosts[0].id, &key)
                .await
                .unwrap()
                .ssh_key_pem,
            b"pem"
        );
    }

    #[tokio::test]
    async fn rejects_bad_enums() {
        assert!("nope".parse::<BackupMode>().is_err());
        assert!("nope".parse::<HostStatus>().is_err());
    }
}
