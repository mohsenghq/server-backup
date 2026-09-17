//! `aegis user …` and `aegis session …` — CLI-first control-plane account
//! management (`docs/05` users/sessions, `docs/06` auth endpoints).
//!
//! User login passwords are separate from the catalog passphrase: they are
//! checked by Argon2id against the `users` table. Session tokens are issued
//! here exactly as the HTTP login issues them, so anything the API can do
//! exists as a CLI command.

use std::path::{Path, PathBuf};

use aegis_core::catalog::Catalog;
use anyhow::Result;
use clap::Args;

/// Shared catalog flag block for user/session commands.
#[derive(Args, Clone)]
pub struct CatalogArgs {
    /// Path to the catalog database (created if missing).
    #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
    pub catalog: PathBuf,
}

#[derive(Args)]
pub struct UserArgs {
    #[command(subcommand)]
    pub command: UserCommand,
}

#[derive(clap::Subcommand)]
pub enum UserCommand {
    /// Register a local administrator. The password comes from
    /// `AEGIS_USER_PASSWORD` or an interactive prompt (never argv).
    Add {
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,
        #[arg(long, value_name = "NAME")]
        username: String,
    },
    /// List local administrators.
    List {
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,
    },
    /// Remove a local administrator (revokes their sessions).
    Remove {
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,
        #[arg(value_name = "NAME")]
        username: String,
    },
    /// Reset an administrator's password (revokes their sessions).
    Passwd {
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,
        #[arg(value_name = "NAME")]
        username: String,
    },
}

#[derive(Args)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub command: SessionCommand,
}

#[derive(clap::Subcommand)]
pub enum SessionCommand {
    /// Log in and print the bearer token for API use.
    Login {
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,
        #[arg(long, value_name = "NAME")]
        username: String,
    },
    /// Revoke a session token.
    Logout {
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,
        /// The token to revoke, or `AEGIS_SESSION_TOKEN` when omitted.
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
    },
    /// Show the user a token belongs to.
    Show {
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
    },
}

fn load_password(prompt: &str) -> Result<String> {
    if let Ok(password) = std::env::var("AEGIS_USER_PASSWORD") {
        return Ok(password);
    }
    if !atty::is(atty::Stream::Stdin) {
        anyhow::bail!("no password available: set AEGIS_USER_PASSWORD or run interactively");
    }
    Ok(rpassword::prompt_password(prompt)?)
}

fn load_token(flag: &Option<String>) -> Result<String> {
    if let Some(token) = flag {
        return Ok(token.clone());
    }
    std::env::var("AEGIS_SESSION_TOKEN")
        .map_err(|_| anyhow::anyhow!("no session token: pass --token or set AEGIS_SESSION_TOKEN"))
}

async fn open_catalog(path: &Path) -> anyhow::Result<Catalog> {
    let catalog = Catalog::open(path).await?;
    Ok(catalog)
}

pub async fn run_session(command: &SessionCommand, json: bool) -> anyhow::Result<()> {
    match command {
        SessionCommand::Login { catalog, username } => {
            let password = load_password("password: ")?;
            let c = open_catalog(catalog).await?;
            let session = c.login(username, &password).await?;
            c.audit(Some(&session.user.id), "session.login", None)
                .await
                .ok();
            crate::emit(
                json,
                &serde_json::json!({
                    "token": session.token,
                    "username": session.user.username,
                    "expires_at": session.expires_at,
                }),
                || {
                    println!("token (use as `Authorization: Bearer <token>`):");
                    println!("{}", session.token);
                    println!("expires at {} (unix seconds)", session.expires_at);
                },
            );
        }
        SessionCommand::Logout { catalog, token } => {
            let token = load_token(token)?;
            let c = open_catalog(catalog).await?;
            let revoked = c.logout(&token).await?;
            c.audit(None, "session.logout", None).await.ok();
            crate::emit(json, &serde_json::json!({ "revoked": revoked }), || {
                if revoked {
                    println!("session revoked");
                } else {
                    println!("token was not active");
                }
            });
        }
        SessionCommand::Show { catalog, token } => {
            let token = load_token(token)?;
            let c = open_catalog(catalog).await?;
            let user = c.session_user(&token).await?;
            crate::emit(
                json,
                &serde_json::json!({ "id": user.id, "username": user.username, "role": user.role }),
                || println!("{} ({})", user.username, user.role),
            );
        }
    }
    Ok(())
}

pub async fn run_user(command: &UserCommand, json: bool) -> anyhow::Result<()> {
    match command {
        UserCommand::Add { catalog, username } => {
            let password = load_password("new user password: ")?;
            let c = open_catalog(catalog).await?;
            let user = c.add_user(username, &password).await?;
            c.audit(None, "user.add", Some(username)).await.ok();
            crate::emit(
                json,
                &serde_json::json!({ "id": user.id, "username": user.username, "role": user.role }),
                || println!("added user {} ({})", user.username, user.role),
            );
        }
        UserCommand::List { catalog } => {
            let c = open_catalog(catalog).await?;
            let users = c.list_users().await?;
            let arr: Vec<serde_json::Value> = users
                .iter()
                .map(|u| {
                    serde_json::json!({
                        "id": u.id,
                        "username": u.username,
                        "role": u.role,
                    })
                })
                .collect();
            crate::emit(json, &arr, || {
                if users.is_empty() {
                    println!("no users (use `aegis user add`)");
                    return;
                }
                println!("{:<38}  {:<24}  ROLE", "ID", "USERNAME");
                for u in &users {
                    println!("{:<38}  {:<24}  {}", u.id, u.username, u.role);
                }
            });
        }
        UserCommand::Remove { catalog, username } => {
            let c = open_catalog(catalog).await?;
            let removed = c.remove_user(username).await?;
            if removed {
                c.audit(None, "user.remove", Some(username)).await.ok();
            }
            crate::emit(
                json,
                &serde_json::json!({ "username": username, "removed": removed }),
                || {
                    if removed {
                        println!("removed user {username}");
                    } else {
                        println!("no user named {username}");
                    }
                },
            );
        }
        UserCommand::Passwd { catalog, username } => {
            let password = load_password("new password: ")?;
            let c = open_catalog(catalog).await?;
            let updated = c.set_user_password(username, &password).await?;
            if updated {
                c.audit(None, "user.passwd", Some(username)).await.ok();
            }
            crate::emit(
                json,
                &serde_json::json!({ "username": username, "updated": updated }),
                || {
                    if updated {
                        println!("password updated for {username}; sessions revoked");
                    } else {
                        println!("no user named {username}");
                    }
                },
            );
        }
    }
    Ok(())
}
