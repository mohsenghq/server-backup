//! The REST API (`docs/06-api-spec.md`). Each endpoint maps to a CLI command.

use axum::{
    extract::{Path as UrlPath, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

use aegis_core::catalog::Policy;
use uuid::Uuid;

/// Build the application router. `/health` and `/api/auth/login` are public;
/// everything under `/api` requires a valid bearer session.
pub fn router(state: AppState) -> Router {
    let public = Router::new()
        .route("/health", get(health))
        .route("/api/auth/login", post(login))
        .with_state(state.clone());
    let protected = Router::new()
        .route("/api/hosts", post(add_host).get(list_hosts))
        .route("/api/hosts/{id}", delete(remove_host))
        .route("/api/hosts/{id}/test", post(test_host))
        .route("/api/jobs", get(list_jobs))
        .route("/api/jobs/trigger", post(trigger))
        .route("/api/policies", get(list_policies).post(add_policy))
        .route("/api/policies/{id}", delete(remove_policy))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ))
        .with_state(state);
    public.merge(protected)
}

/// Bearer-token middleware: resolves the session user or answers 401.
async fn require_session(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    let header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let token = header.ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
    let user = state
        .catalog
        .session_user(token)
        .await
        .map_err(|_| ApiError::unauthorized("invalid or expired session"))?;
    request.extensions_mut().insert(user);
    Ok(next.run(request).await)
}

/// `GET /health` — liveness.
async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

/// `POST /api/auth/login` ⇔ `aegis session login`.
#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = state
        .catalog
        .login(&req.username, &req.password)
        .await
        .map_err(|e| match e {
            aegis_core::Error::Unauthorized => ApiError::unauthorized("invalid credentials"),
            aegis_core::Error::RateLimited => ApiError::too_many_requests("try again later"),
            aegis_core::Error::InvalidInput(message) => ApiError::bad_request(message),
            other => ApiError::internal(other.to_string()),
        })?;
    let _ = state
        .catalog
        .audit(Some(&session.user.id), "session.login", None)
        .await;
    Ok(Json(serde_json::json!({
        "token": session.token,
        "username": session.user.username,
        "expires_at": session.expires_at,
    })))
}

/// `POST /api/auth/logout` ⇔ `aegis session logout`.
async fn logout(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
    let revoked = state.catalog.logout(token).await?;
    let _ = state.catalog.audit(None, "session.logout", None).await;
    Ok(Json(serde_json::json!({ "revoked": revoked })))
}

/// `GET /api/auth/me` ⇔ `aegis session show`.
async fn me(
    axum::Extension(user): axum::Extension<aegis_core::catalog::auth::User>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({
        "id": user.id,
        "username": user.username,
        "role": user.role,
    })))
}

/// `POST /api/hosts` ⇔ `aegis host add`.
#[derive(Deserialize)]
pub struct AddHostRequest {
    pub name: String,
    pub address: String,
    #[serde(default = "default_port")]
    pub ssh_port: u16,
    pub ssh_user: String,
    /// OpenSSH PEM private key; empty means password auth at backup time
    /// (`AEGIS_SSH_PASSWORD` on the server process).
    #[serde(default)]
    pub ssh_key_pem: String,
    #[serde(default = "default_mode")]
    pub mode: String,
}

fn default_port() -> u16 {
    22
}

fn default_mode() -> String {
    "agentless".to_string()
}

async fn add_host(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<aegis_core::catalog::auth::User>,
    Json(req): Json<AddHostRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mode: aegis_core::catalog::BackupMode = req
        .mode
        .parse()
        .map_err(|e| ApiError::bad_request(format!("{e}")))?;
    let host = state
        .catalog
        .add_host(
            &req.name,
            &req.address,
            req.ssh_port,
            &req.ssh_user,
            req.ssh_key_pem.as_bytes(),
            mode,
            state.master_key(),
        )
        .await?;
    let _ = state
        .catalog
        .audit(Some(&user.id), "host.add", Some(&req.name))
        .await;
    Ok(Json(serde_json::json!({
        "id": host.id,
        "name": host.name,
        "address": host.address,
        "port": host.ssh_port,
        "user": host.ssh_user,
        "mode": host.mode.as_str(),
        "status": host.status.as_str(),
    })))
}

/// `GET /api/hosts` ⇔ `aegis host list`.
async fn list_hosts(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let hosts = state.catalog.list_hosts().await?;
    Ok(Json(serde_json::json!(hosts
        .iter()
        .map(|h| serde_json::json!({
            "id": h.id,
            "name": h.name,
            "address": h.address,
            "port": h.ssh_port,
            "user": h.ssh_user,
            "mode": h.mode.as_str(),
            "status": h.status.as_str(),
        }))
        .collect::<Vec<_>>())))
}

/// `DELETE /api/hosts/:id` ⇔ `aegis host remove`.
async fn remove_host(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<aegis_core::catalog::auth::User>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let removed = state.catalog.remove_host(&id).await?;
    if !removed {
        return Err(ApiError::not_found(format!("host `{id}` not found")));
    }
    let _ = state
        .catalog
        .audit(Some(&user.id), "host.remove", Some(&id))
        .await;
    Ok(Json(serde_json::json!({ "id": id, "removed": true })))
}

/// `POST /api/hosts/:id/test` — attempt an SSH connect, update status.
async fn test_host(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use aegis_core::sftp::SftpAuth;
    use aegis_core::ssh::HostConfig;

    let with_key = state
        .catalog
        .get_host_with_key(&id, state.master_key())
        .await
        .map_err(|e| ApiError::not_found(e.to_string()))?;
    let host = &with_key.host;
    let auth = if with_key.ssh_key_pem.is_empty() {
        SftpAuth::Password(std::env::var("AEGIS_SSH_PASSWORD").map_err(|_| {
            ApiError::bad_request(
                "host has no stored key and AEGIS_SSH_PASSWORD is not set on the server",
            )
        })?)
    } else {
        let pem = String::from_utf8(with_key.ssh_key_pem)
            .map_err(|_| ApiError::internal("stored key is not UTF-8"))?;
        let key = russh::keys::decode_secret_key(&pem, None)
            .map_err(|e| ApiError::internal(format!("decoding stored key: {e}")))?;
        SftpAuth::Key(std::sync::Arc::new(key))
    };
    let cfg =
        HostConfig::new(host.ssh_user.clone(), host.address.clone(), auth).with_port(host.ssh_port);
    let ssh = aegis_core::ssh::SshManager::new();
    let (status, detail) = match ssh.sftp_channel(&cfg).await {
        Ok(_) => (aegis_core::catalog::HostStatus::Reachable, "connected"),
        Err(e) => (
            aegis_core::catalog::HostStatus::Unreachable,
            &e.to_string()[..],
        ),
    };
    let _ = state.catalog.set_host_status(&id, status).await;
    Ok(Json(serde_json::json!({
        "id": id,
        "status": status.as_str(),
        "detail": detail,
    })))
}

/// `POST /api/jobs/trigger` ⇔ `aegis host backup-all` (single host).
#[derive(Deserialize)]
pub struct TriggerRequest {
    pub host_id: String,
    /// Absolute remote paths to back up.
    pub paths: Vec<String>,
    /// Repository location (local path or sftp:// URL), as in the CLI.
    pub repo: String,
}

#[derive(Serialize)]
struct TriggerResponse {
    snapshot_id: String,
    files: u64,
    new_chunks: u64,
}

async fn trigger(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<aegis_core::catalog::auth::User>,
    Json(req): Json<TriggerRequest>,
) -> Result<Json<TriggerResponse>, ApiError> {
    use aegis_core::sftp::SftpAuth;

    for p in &req.paths {
        if !p.starts_with('/') {
            return Err(ApiError::bad_request(format!(
                "remote path `{p}` must be absolute"
            )));
        }
    }
    let with_key = state
        .catalog
        .get_host_with_key(&req.host_id, state.master_key())
        .await
        .map_err(|e| ApiError::not_found(e.to_string()))?;
    let host = &with_key.host;
    let auth = if with_key.ssh_key_pem.is_empty() {
        SftpAuth::Password(std::env::var("AEGIS_SSH_PASSWORD").map_err(|_| {
            ApiError::bad_request(
                "host has no stored key and AEGIS_SSH_PASSWORD is not set on the server",
            )
        })?)
    } else {
        let pem = String::from_utf8(with_key.ssh_key_pem)
            .map_err(|_| ApiError::internal("stored key is not UTF-8"))?;
        let key = russh::keys::decode_secret_key(&pem, None)
            .map_err(|e| ApiError::internal(format!("decoding stored key: {e}")))?;
        SftpAuth::Key(std::sync::Arc::new(key))
    };
    let cfg = aegis_core::ssh::HostConfig::new(host.ssh_user.clone(), host.address.clone(), auth)
        .with_port(host.ssh_port);

    // Open the repository (passphrase from the environment, like the server
    // itself; AEGIS_PASSPHRASE doubles as the repo passphrase here).
    let pass = std::env::var("AEGIS_PASSPHRASE")
        .map_err(|_| ApiError::internal("AEGIS_PASSPHRASE is required"))?;
    let backend: Box<dyn aegis_core::Backend> = match aegis_core::sftp::parse_location(&req.repo)
        .map_err(|e| ApiError::bad_request(format!("{e}")))?
    {
        aegis_core::sftp::RepoLocation::Local(path) => {
            Box::new(aegis_core::LocalBackend::new(path))
        }
        aegis_core::sftp::RepoLocation::Sftp(target) => {
            // The server-side repo SFTP auth uses the same env fallbacks the
            // CLI uses; key-file default first, then AEGIS_SSH_PASSWORD.
            let sftp_auth = if let Ok(password) = std::env::var("AEGIS_SSH_PASSWORD") {
                SftpAuth::Password(password)
            } else if let Some(home) = std::env::var("HOME")
                .ok()
                .or_else(|| std::env::var("USERPROFILE").ok())
            {
                let mut found = None;
                for name in ["id_ed25519", "id_rsa"] {
                    let p = std::path::PathBuf::from(&home).join(".ssh").join(name);
                    if p.exists() {
                        found = Some(SftpAuth::KeyFile {
                            path: p,
                            key_passphrase: None,
                        });
                        break;
                    }
                }
                found
                    .ok_or_else(|| ApiError::internal("no SFTP auth for the repository location"))?
            } else {
                return Err(ApiError::internal(
                    "no SFTP auth for the repository location",
                ));
            };
            Box::new(aegis_core::sftp::SftpBackend::new(target, sftp_auth))
        }
    };
    let repo = aegis_core::Repository::open(backend, &pass)
        .await
        .map_err(|e| ApiError::bad_request(format!("opening repository: {e}")))?;

    let ssh = aegis_core::ssh::SshManager::new();
    let snapshot = aegis_core::backup_remote(&repo, &ssh, &cfg, &repo.config().chunker, &req.paths)
        .await
        .map_err(|e| ApiError::internal(format!("backup failed: {e}")))?;
    let _ = state
        .catalog
        .set_host_status(&req.host_id, aegis_core::catalog::HostStatus::Reachable)
        .await;
    let _ = state
        .catalog
        .audit(Some(&user.id), "job.run", Some(&req.host_id))
        .await;
    Ok(Json(TriggerResponse {
        snapshot_id: snapshot.id,
        files: snapshot.stats.files,
        new_chunks: snapshot.stats.new_chunks,
    }))
}

/// `GET /api/jobs` ⇔ `aegis job list`.
async fn list_jobs(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let jobs = state.catalog.list_jobs(None, None, None, 100, 0).await?;
    Ok(Json(serde_json::json!(jobs
        .iter()
        .map(|j| serde_json::json!({
            "id": j.id,
            "host_id": j.host_id,
            "policy_id": j.policy_id,
            "status": j.status,
            "started_at": j.started_at,
            "finished_at": j.finished_at,
            "bytes_new": j.bytes_new,
            "bytes_total": j.bytes_total,
            "error": j.error,
        }))
        .collect::<Vec<_>>())))
}

/// `GET /api/policies` ⇔ `aegis policy list`.
async fn list_policies(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let policies = state.catalog.list_policies().await?;
    Ok(Json(serde_json::json!(policies
        .iter()
        .map(|p| serde_json::json!({
            "id": p.id,
            "name": p.name,
            "schedule_cron": p.schedule_cron,
            "enabled": p.enabled,
        }))
        .collect::<Vec<_>>())))
}

/// `POST /api/policies` ⇔ `aegis policy add`.
#[derive(Deserialize)]
pub struct AddPolicyRequest {
    pub name: String,
    pub schedule_cron: String,
    pub retention_json: String,
    pub paths_json: String,
    pub exclude_json: String,
    #[serde(default)]
    pub bandwidth_limit_kbps: Option<i32>,
    #[serde(default)]
    pub pre_hook: Option<String>,
    #[serde(default)]
    pub post_hook: Option<String>,
}

async fn add_policy(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<aegis_core::catalog::auth::User>,
    Json(req): Json<AddPolicyRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let policy = Policy {
        id: Uuid::new_v4().to_string(),
        name: req.name.clone(),
        schedule_cron: req.schedule_cron.clone(),
        retention_json: req.retention_json.clone(),
        paths_json: req.paths_json.clone(),
        exclude_json: req.exclude_json.clone(),
        bandwidth_limit_kbps: req.bandwidth_limit_kbps,
        pre_hook: req.pre_hook,
        post_hook: req.post_hook,
        enabled: true,
    };
    let policy = state
        .catalog
        .add_policy(&policy)
        .await
        .map_err(|e| match e {
            aegis_core::Error::InvalidInput(message) => ApiError::bad_request(message),
            other => ApiError::internal(other.to_string()),
        })?;
    let _ = state
        .catalog
        .audit(Some(&user.id), "policy.add", Some(&req.name))
        .await;
    Ok(Json(serde_json::json!({
        "id": policy.id,
        "name": policy.name,
        "schedule_cron": policy.schedule_cron,
    })))
}

/// `DELETE /api/policies/{id}` ⇔ `aegis policy remove`.
async fn remove_policy(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<aegis_core::catalog::auth::User>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let removed = state.catalog.remove_policy(&id).await?;
    if !removed {
        return Err(ApiError::not_found(format!("policy `{id}` not found")));
    }
    let _ = state
        .catalog
        .audit(Some(&user.id), "policy.remove", Some(&id))
        .await;
    Ok(Json(serde_json::json!({ "id": id, "removed": true })))
}

/// Uniform JSON error responses.
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn too_many_requests(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

impl From<aegis_core::Error> for ApiError {
    fn from(e: aegis_core::Error) -> Self {
        ApiError::internal(e.to_string())
    }
}
