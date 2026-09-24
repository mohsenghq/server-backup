use argon2::password_hash::{
    rand_core::OsRng as PhcOsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sqlx::sqlite::SqliteRow;
use sqlx::Row;
use tokio::sync::Semaphore;

use crate::error::{Error, Result};

use super::Catalog;

const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 32;
const TOKEN_LEN: usize = 32;
const SESSION_TTL_SECS: i64 = 24 * 60 * 60;
const USERNAME_MAX: usize = 64;
const PASSWORD_MIN: usize = 12;
const PASSWORD_MAX: usize = 1024;
/// A user's permission level. Ordered from least to most privileged.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Role {
    /// Read-only: list hosts/jobs/snapshots/audit, no mutations.
    Viewer,
    /// Day-to-day operation: everything except user and key management.
    Operator,
    /// Full control, including user management and key rotation.
    Admin,
}

impl Role {
    pub const ALL: [Role; 3] = [Role::Viewer, Role::Operator, Role::Admin];

    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(role: &str) -> Result<Role> {
        match role {
            "admin" => Ok(Role::Admin),
            "operator" => Ok(Role::Operator),
            "viewer" => Ok(Role::Viewer),
            other => Err(Error::Catalog(format!("unknown role `{other}`"))),
        }
    }
}
const LOGIN_LIMIT: i64 = 30;
const LOGIN_WINDOW_SECS: i64 = 60;
const LOGIN_BUCKET: &str = "global";
const HASH_SEMAPHORE_PERMITS: usize = 4;
const DUMMY_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=1$MDEyMzQ1NjcwMTIzNDU2Nw$aW52YWxpZC1zYWx0LWZvci1kdW1teS1oYXNoLXZlcmlmaWNhdGlvbg";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub role: Role,
}

#[derive(Clone)]
pub struct Session {
    pub token: String,
    pub user: User,
    pub expires_at: i64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("user", &self.user)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl serde::Serialize for Session {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        #[derive(serde::Serialize)]
        struct Repr<'a> {
            token: &'a str,
            user: &'a User,
            expires_at: i64,
        }
        Repr {
            token: &self.token,
            user: &self.user,
            expires_at: self.expires_at,
        }
        .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Session {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Repr {
            token: String,
            user: User,
            expires_at: i64,
        }
        let repr = Repr::deserialize(deserializer)?;
        Ok(Session {
            token: repr.token,
            user: repr.user,
            expires_at: repr.expires_at,
        })
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() || username.len() > USERNAME_MAX {
        return Err(Error::InvalidInput(format!(
            "username must be 1-{USERNAME_MAX} characters"
        )));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(Error::InvalidInput(
            "username may only contain letters, digits, `-`, `_`, `.`".into(),
        ));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<()> {
    let len = password.len();
    if !(PASSWORD_MIN..=PASSWORD_MAX).contains(&len) {
        return Err(Error::InvalidInput(format!(
            "password must be {PASSWORD_MIN}-{PASSWORD_MAX} bytes"
        )));
    }
    Ok(())
}

fn fresh_token() -> String {
    let mut bytes = [0u8; TOKEN_LEN];
    getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn token_hash(token: &str) -> String {
    let digest = blake3::hash(token.as_bytes());
    digest.to_hex().to_string()
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut PhcOsRng);
    let params = argon2::Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| Error::Catalog(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let hash = argon
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::Catalog(format!("hashing password: {e}")))?;
    Ok(hash.to_string())
}

fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

fn user_from_row(row: &SqliteRow) -> Result<User> {
    let role: String = row.try_get("role").map_err(catalog_err("reading role"))?;
    Ok(User {
        id: row.try_get("id").map_err(catalog_err("reading user id"))?,
        username: row
            .try_get("username")
            .map_err(catalog_err("reading username"))?,
        role: Role::from_str(&role)?,
    })
}

fn catalog_err(context: &'static str) -> impl Fn(sqlx::Error) -> Error + 'static {
    move |e| Error::Catalog(format!("{context}: {e}"))
}

impl Catalog {
    fn hash_semaphore(&self) -> &'static Semaphore {
        static SEM: Semaphore = Semaphore::const_new(HASH_SEMAPHORE_PERMITS);
        &SEM
    }

    async fn hash_in_background(&self, password: &str) -> Result<String> {
        let password = zeroize::Zeroizing::new(password.to_string());
        let permit = self
            .hash_semaphore()
            .acquire()
            .await
            .map_err(|_| Error::Catalog("password hashing semaphore closed".into()))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            hash_password(&password)
        })
        .await
        .map_err(|e| Error::Catalog(format!("hash task panicked: {e}")))?
    }

    async fn verify_in_background(&self, password: &str, phc: &str) -> Result<bool> {
        let password = zeroize::Zeroizing::new(password.to_string());
        let phc = phc.to_string();
        let permit = self
            .hash_semaphore()
            .acquire()
            .await
            .map_err(|_| Error::Catalog("password hashing semaphore closed".into()))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify_password(&password, &phc)
        })
        .await
        .map_err(|e| Error::Catalog(format!("verify task panicked: {e}")))
    }

    pub async fn add_user(&self, username: &str, password: &str) -> Result<User> {
        self.add_user_with_role(username, password, Role::Admin)
            .await
    }

    /// Create a user with an explicit role (defaults to admin via [`Catalog::add_user`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] for bad usernames/passwords and
    /// duplicate usernames; [`Error::Catalog`] on storage failures.
    pub async fn add_user_with_role(
        &self,
        username: &str,
        password: &str,
        role: Role,
    ) -> Result<User> {
        validate_username(username)?;
        validate_password(password)?;
        let hash = self.hash_in_background(password).await?;
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)")
            .bind(&id)
            .bind(username)
            .bind(&hash)
            .bind(role.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| match e.as_database_error() {
                Some(db) if db.is_unique_violation() => {
                    Error::InvalidInput(format!("username `{username}` already exists"))
                }
                _ => Error::Catalog(format!("inserting user: {e}")),
            })?;
        Ok(User {
            id,
            username: username.to_string(),
            role,
        })
    }

    /// Change a user's role. Returns `false` if the user does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Catalog`] on storage failures.
    pub async fn set_user_role(&self, username: &str, role: Role) -> Result<bool> {
        validate_username(username)?;
        let res = sqlx::query("UPDATE users SET role = ? WHERE username = ?")
            .bind(role.as_str())
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(catalog_err("updating role"))?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn list_users(&self) -> Result<Vec<User>> {
        let rows = sqlx::query("SELECT id, username, role FROM users ORDER BY username")
            .fetch_all(&self.pool)
            .await
            .map_err(catalog_err("listing users"))?;
        rows.iter().map(user_from_row).collect()
    }

    pub async fn remove_user(&self, username: &str) -> Result<bool> {
        validate_username(username)?;
        let res = sqlx::query("DELETE FROM users WHERE username = ?")
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(catalog_err("removing user"))?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn set_user_password(&self, username: &str, password: &str) -> Result<bool> {
        validate_username(username)?;
        validate_password(password)?;
        let hash = self.hash_in_background(password).await?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(catalog_err("beginning transaction"))?;
        let updated = sqlx::query("UPDATE users SET password_hash = ? WHERE username = ?")
            .bind(&hash)
            .bind(username)
            .execute(&mut *tx)
            .await
            .map_err(catalog_err("updating password"))?;
        if updated.rows_affected() == 0 {
            return Ok(false);
        }
        sqlx::query(
            "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)",
        )
        .bind(username)
        .execute(&mut *tx)
        .await
        .map_err(catalog_err("revoking sessions"))?;
        tx.commit().await.map_err(catalog_err("committing"))?;
        Ok(true)
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<Session> {
        validate_username(username)?;
        validate_password(password)?;
        self.enforce_login_limit().await?;
        let row =
            sqlx::query("SELECT id, username, role, password_hash FROM users WHERE username = ?")
                .bind(username)
                .fetch_optional(&self.pool)
                .await
                .map_err(catalog_err("fetching user"))?;
        let (user, hash) = match row {
            Some(row) => {
                let user = user_from_row(&row)?;
                let hash: String = row
                    .try_get("password_hash")
                    .map_err(catalog_err("reading password hash"))?;
                (Some(user), hash)
            }
            None => (None, DUMMY_HASH.to_string()),
        };
        let ok = self.verify_in_background(password, &hash).await?;
        let user = match (user, ok) {
            (Some(u), true) => u,
            _ => return Err(Error::Unauthorized),
        };
        let token = fresh_token();
        let token_hash = token_hash(&token);
        let expires_at = now_secs() + SESSION_TTL_SECS;
        sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
            .bind(now_secs())
            .execute(&self.pool)
            .await
            .map_err(catalog_err("cleaning sessions"))?;
        let inserted = sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at)
             SELECT ?, id, ? FROM users WHERE id = ? AND password_hash = ?",
        )
        .bind(&token_hash)
        .bind(expires_at)
        .bind(&user.id)
        .bind(&hash)
        .execute(&self.pool)
        .await
        .map_err(catalog_err("creating session"))?;
        if inserted.rows_affected() != 1 {
            return Err(Error::Unauthorized);
        }
        Ok(Session {
            token,
            user,
            expires_at,
        })
    }

    pub async fn session_user(&self, token: &str) -> Result<User> {
        let token_hash = token_hash(token);
        let row = sqlx::query(
            "SELECT u.id, u.username, u.role FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = ? AND s.expires_at > ?",
        )
        .bind(&token_hash)
        .bind(now_secs())
        .fetch_optional(&self.pool)
        .await
        .map_err(catalog_err("looking up session"))?;
        row.as_ref()
            .map(user_from_row)
            .transpose()?
            .ok_or(Error::Unauthorized)
    }

    pub async fn logout(&self, token: &str) -> Result<bool> {
        let token_hash = token_hash(token);
        let res = sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(&token_hash)
            .execute(&self.pool)
            .await
            .map_err(catalog_err("deleting session"))?;
        Ok(res.rows_affected() > 0)
    }

    async fn enforce_login_limit(&self) -> Result<()> {
        self.enforce_login_limit_at(now_secs()).await
    }

    async fn enforce_login_limit_at(&self, now: i64) -> Result<()> {
        let cutoff = now - LOGIN_WINDOW_SECS;
        let result = sqlx::query(
            "INSERT INTO login_limits (bucket, window_start, attempts) VALUES (?, ?, 1)
             ON CONFLICT(bucket) DO UPDATE SET
             attempts = CASE WHEN window_start <= ? THEN 1 ELSE attempts + 1 END,
             window_start = CASE WHEN window_start <= ? THEN excluded.window_start ELSE window_start END
             WHERE window_start <= ? OR attempts < ?",
        )
        .bind(LOGIN_BUCKET)
        .bind(now)
        .bind(cutoff)
        .bind(cutoff)
        .bind(cutoff)
        .bind(LOGIN_LIMIT)
        .execute(&self.pool)
        .await
        .map_err(catalog_err("updating login limits"))?;
        if result.rows_affected() == 0 {
            return Err(Error::RateLimited);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_PASSWORD: &str = "correct-horse-battery";

    async fn cat() -> Catalog {
        Catalog::in_memory().await.unwrap()
    }

    async fn cat_user(c: &Catalog, username: &str) -> User {
        c.add_user(username, GOOD_PASSWORD).await.unwrap()
    }

    async fn login_ok(c: &Catalog, username: &str) -> Session {
        c.login(username, GOOD_PASSWORD).await.unwrap()
    }

    fn row_count<'a>(c: &'a Catalog, sql: &'a str) -> impl std::future::Future<Output = i64> + 'a {
        let pool = c.pool.clone();
        async move { sqlx::query_scalar(sql).fetch_one(&pool).await.unwrap() }
    }

    #[tokio::test]
    async fn add_list_remove_roundtrip() {
        let c = cat().await;
        let u = cat_user(&c, "alice").await;
        assert_eq!(u.role, Role::Admin);
        let users = c.list_users().await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "alice");
        assert!(u.id.len() >= 32);
        assert!(c.remove_user("alice").await.unwrap());
        assert!(!c.remove_user("alice").await.unwrap());
        assert!(c.list_users().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn add_user_rejects_duplicate_and_bad_input() {
        let c = cat().await;
        cat_user(&c, "bob").await;
        let dup = c.add_user("bob", GOOD_PASSWORD).await.unwrap_err();
        assert!(matches!(dup, Error::InvalidInput(_)));
        for bad in ["", "has space", "slash/", "a\"b", &"x".repeat(65)] {
            let e = c.add_user(bad, GOOD_PASSWORD).await.unwrap_err();
            assert!(matches!(e, Error::InvalidInput(_)), "username {bad:?}");
        }
        for pw in ["short", "", &"a".repeat(1025)] {
            let e = c.add_user("carol", pw).await.unwrap_err();
            assert!(matches!(e, Error::InvalidInput(_)), "password {pw:?}");
        }
        assert!(c.add_user("dave", &"a".repeat(12)).await.is_ok());
        assert!(c.add_user("eve", &"a".repeat(1024)).await.is_ok());
    }

    #[tokio::test]
    async fn login_success_and_failures() {
        let c = cat().await;
        cat_user(&c, "alice").await;
        let s = c.login("alice", GOOD_PASSWORD).await.unwrap();
        assert_eq!(s.user.username, "alice");
        assert!(!s.token.is_empty());
        assert!(s.expires_at > now_secs());
        let wrong = c.login("alice", "wrong-password-123").await.unwrap_err();
        assert!(matches!(wrong, Error::Unauthorized));
        let ghost = c.login("nobody", GOOD_PASSWORD).await.unwrap_err();
        assert!(matches!(ghost, Error::Unauthorized));
    }

    #[tokio::test]
    async fn session_user_and_logout_roundtrip() {
        let c = cat().await;
        cat_user(&c, "alice").await;
        let s = login_ok(&c, "alice").await;
        let u = c.session_user(&s.token).await.unwrap();
        assert_eq!(u.username, "alice");
        assert!(c.logout(&s.token).await.unwrap());
        assert!(!c.logout(&s.token).await.unwrap());
        assert!(matches!(
            c.session_user(&s.token).await.unwrap_err(),
            Error::Unauthorized
        ));
        assert!(matches!(
            c.session_user("forged-token").await.unwrap_err(),
            Error::Unauthorized
        ));
    }

    #[tokio::test]
    async fn expired_session_is_unauthorized() {
        let c = cat().await;
        cat_user(&c, "alice").await;
        let s = login_ok(&c, "alice").await;
        let past = now_secs() - 10;
        sqlx::query("UPDATE sessions SET expires_at = ? WHERE token_hash = ?")
            .bind(past)
            .bind(token_hash(&s.token))
            .execute(&c.pool)
            .await
            .unwrap();
        assert!(matches!(
            c.session_user(&s.token).await.unwrap_err(),
            Error::Unauthorized
        ));
    }

    #[tokio::test]
    async fn password_hash_is_argon2id_and_never_plaintext() {
        let c = cat().await;
        cat_user(&c, "alice").await;
        let stored: String =
            sqlx::query_scalar("SELECT password_hash FROM users WHERE username = 'alice'")
                .fetch_one(&c.pool)
                .await
                .unwrap();
        assert!(!stored.contains(GOOD_PASSWORD));
        let phc = PasswordHash::new(&stored).unwrap();
        assert_eq!(phc.algorithm.as_str(), "argon2id");
        let salt = phc.salt.unwrap();
        assert!(salt.len() >= 16);
        let params = phc.params;
        assert!(params
            .iter()
            .any(|(k, v)| k.as_str() == "m" && v.as_str() == "65536"));
        assert!(params
            .iter()
            .any(|(k, v)| k.as_str() == "t" && v.as_str() == "3"));
    }

    #[tokio::test]
    async fn tokens_stored_hashed_only() {
        let c = cat().await;
        cat_user(&c, "alice").await;
        let s = login_ok(&c, "alice").await;
        let stored: Vec<String> = sqlx::query_scalar("SELECT token_hash FROM sessions")
            .fetch_all(&c.pool)
            .await
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert_ne!(stored[0], s.token);
        assert_eq!(stored[0], token_hash(&s.token));
        assert_eq!(row_count(&c, "SELECT COUNT(*) FROM sessions").await, 1);
    }

    #[tokio::test]
    async fn persisted_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.db");
        let token = {
            let c = Catalog::open(&path).await.unwrap();
            c.add_user("alice", GOOD_PASSWORD).await.unwrap();
            let s = c.login("alice", GOOD_PASSWORD).await.unwrap();
            s.token
        };
        let c = Catalog::open(&path).await.unwrap();
        let users = c.list_users().await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "alice");
        let u = c.session_user(&token).await.unwrap();
        assert_eq!(u.username, "alice");
    }

    #[tokio::test]
    async fn set_password_revokes_sessions_atomically() {
        let c = cat().await;
        cat_user(&c, "alice").await;
        let s = login_ok(&c, "alice").await;
        assert!(c
            .set_user_password("alice", "brand-new-pass-123")
            .await
            .unwrap());
        assert!(matches!(
            c.session_user(&s.token).await.unwrap_err(),
            Error::Unauthorized
        ));
        let s2 = c.login("alice", "brand-new-pass-123").await.unwrap();
        assert_eq!(s2.user.username, "alice");
        assert!(matches!(
            c.login("alice", GOOD_PASSWORD).await.unwrap_err(),
            Error::Unauthorized
        ));
        assert!(!c
            .set_user_password("ghost", "brand-new-pass-123")
            .await
            .unwrap());
        assert_eq!(
            row_count(&c, "SELECT COUNT(*) FROM sessions").await,
            1,
            "failed reset must not touch sessions"
        );
    }

    #[tokio::test]
    async fn remove_user_cascades_sessions() {
        let c = cat().await;
        cat_user(&c, "alice").await;
        let s = login_ok(&c, "alice").await;
        assert!(c.remove_user("alice").await.unwrap());
        assert_eq!(row_count(&c, "SELECT COUNT(*) FROM sessions").await, 0);
        assert!(matches!(
            c.session_user(&s.token).await.unwrap_err(),
            Error::Unauthorized
        ));
    }

    #[tokio::test]
    async fn login_limit_blocks_across_cloned_catalogs() {
        let c = cat().await;
        let c2 = c.clone();
        let now = now_secs();
        for _ in 0..15 {
            c.enforce_login_limit_at(now).await.unwrap();
            c2.enforce_login_limit_at(now).await.unwrap();
        }
        assert!(matches!(
            c.enforce_login_limit_at(now + 59).await,
            Err(Error::RateLimited)
        ));
        assert!(matches!(
            c2.login("ghost", GOOD_PASSWORD).await,
            Err(Error::RateLimited)
        ));
        let attempts: i64 = sqlx::query_scalar("SELECT attempts FROM login_limits")
            .fetch_one(&c.pool)
            .await
            .unwrap();
        assert_eq!(attempts, LOGIN_LIMIT);
        c2.enforce_login_limit_at(now + 60).await.unwrap();
        let attempts: i64 = sqlx::query_scalar("SELECT attempts FROM login_limits")
            .fetch_one(&c.pool)
            .await
            .unwrap();
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn unknown_user_costs_same_hash_work() {
        let c = cat().await;
        cat_user(&c, "alice").await;
        let start = std::time::Instant::now();
        let _ = c.login("alice", "wrong-pass-wrong").await;
        let known = start.elapsed();
        let start = std::time::Instant::now();
        let _ = c.login("ghost", "wrong-pass-wrong").await;
        let unknown = start.elapsed();
        let ratio = known.as_secs_f64() / unknown.as_secs_f64().max(0.001);
        assert!(
            (0.25..4.0).contains(&ratio),
            "known {known:?} vs unknown {unknown:?} ratio {ratio}"
        );
    }

    #[tokio::test]
    async fn login_validation_rejects_before_throttle() {
        let c = cat().await;
        cat_user(&c, "alice").await;
        let e = c.login("", GOOD_PASSWORD).await.unwrap_err();
        assert!(matches!(e, Error::InvalidInput(_)));
        let e = c.login("alice", "short").await.unwrap_err();
        assert!(matches!(e, Error::InvalidInput(_)));
        assert_eq!(
            row_count(&c, "SELECT COUNT(*) FROM login_limits").await,
            0,
            "rejected input must not consume throttle budget"
        );
    }

    #[tokio::test]
    async fn unsupported_role_in_catalog_rejected() {
        let c = cat().await;
        cat_user(&c, "alice").await;
        sqlx::query("UPDATE users SET role = 'superuser' WHERE username = 'alice'")
            .execute(&c.pool)
            .await
            .unwrap();
        let e = c.list_users().await.unwrap_err();
        assert!(matches!(e, Error::Catalog(_)));
        assert!(matches!(
            c.login("alice", GOOD_PASSWORD).await.unwrap_err(),
            Error::Catalog(_)
        ));
        let attempts: i64 = sqlx::query_scalar("SELECT attempts FROM login_limits")
            .fetch_one(&c.pool)
            .await
            .unwrap();
        assert_eq!(
            attempts, 1,
            "role failure surfaces after the throttle check"
        );
    }

    #[tokio::test]
    async fn roles_create_login_and_persist() {
        let c = cat().await;
        for (name, role) in [
            ("boss", Role::Admin),
            ("operator-1", Role::Operator),
            ("watcher", Role::Viewer),
        ] {
            let u = c
                .add_user_with_role(name, GOOD_PASSWORD, role)
                .await
                .unwrap();
            assert_eq!(u.role, role);
            let s = c.login(name, GOOD_PASSWORD).await.unwrap();
            assert_eq!(s.user.role, role);
            let back = c.session_user(&s.token).await.unwrap();
            assert_eq!(back.role, role);
        }
        let users = c.list_users().await.unwrap();
        assert_eq!(users.len(), 3);
        assert!(users.iter().any(|u| u.role == Role::Viewer));
    }

    #[tokio::test]
    async fn set_user_role_roundtrip_and_unknown_user() {
        let c = cat().await;
        cat_user(&c, "alice").await;
        assert!(c.set_user_role("alice", Role::Viewer).await.unwrap());
        let s = c.login("alice", GOOD_PASSWORD).await.unwrap();
        assert_eq!(s.user.role, Role::Viewer);
        assert!(!c.set_user_role("ghost", Role::Admin).await.unwrap());
        for bad in ["superuser", "", "ADMIN"] {
            assert!(
                Role::from_str(bad).is_err(),
                "role {bad:?} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn session_debug_never_leaks_token() {
        let c = cat().await;
        cat_user(&c, "alice").await;
        let s = login_ok(&c, "alice").await;
        let dbg = format!("{s:?}");
        assert!(!dbg.contains(&s.token));
        assert!(dbg.contains("Session"));
        let s2 = s.clone();
        assert_eq!(s2.token, s.token);
        assert_eq!(s2.user.id, s.user.id);
    }

    #[tokio::test]
    async fn session_serialization_roundtrip() {
        let c = cat().await;
        cat_user(&c, "alice").await;
        let s = login_ok(&c, "alice").await;
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(&s.token));
        let back: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(back.token, s.token);
        assert_eq!(back.user.username, s.user.username);
        assert_eq!(back.expires_at, s.expires_at);
        let dbg = format!("{:?}", back);
        assert!(!dbg.contains(&back.token));
    }
}
