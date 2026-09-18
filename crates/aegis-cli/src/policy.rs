//! `aegis policy …` — manage backup policies (`docs/05`).
//!
//! Policies define when and what the scheduler backs up. The
//! scheduler reads enabled policies from the catalog on startup
//! and runs `aegis-core::backup_remote` for each attached host
//! on the cron schedule.

use std::path::Path;

use aegis_core::catalog::{Catalog, Policy};
use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(clap::Subcommand)]
pub enum PolicyCommand {
    /// Register a backup policy. Paths are a JSON array of
    /// absolute remote paths.
    Add {
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,
        /// Policy name.
        #[arg(long, value_name = "NAME")]
        name: String,
        /// Cron expression (e.g. `0 2 * * *` for daily at 02:00).
        #[arg(long, value_name = "CRON")]
        schedule_cron: String,
        /// Retention configuration as JSON.
        #[arg(long, value_name = "JSON")]
        retention_json: String,
        /// Remote paths as a JSON array (e.g. `["/etc","/var"]`).
        #[arg(long, value_name = "JSON")]
        paths_json: String,
        /// Exclude patterns as a JSON array.
        #[arg(long, value_name = "JSON")]
        exclude_json: String,
        /// Optional bandwidth limit in kbps.
        #[arg(long, value_name = "KBPS")]
        bandwidth_limit_kbps: Option<i32>,
    },
    /// List registered policies.
    List {
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,
    },
    /// Remove a policy.
    Remove {
        #[arg(long, value_name = "FILE", default_value = "aegis-catalog.db")]
        catalog: PathBuf,
        /// Policy name or id.
        #[arg(value_name = "POLICY")]
        policy: String,
    },
}

async fn open_catalog(path: &Path) -> Result<Catalog> {
    Catalog::open(path).await.map_err(anyhow::Error::from)
}

pub async fn run(command: &PolicyCommand, json: bool) -> Result<()> {
    match command {
        PolicyCommand::Add {
            catalog,
            name,
            schedule_cron,
            retention_json,
            paths_json,
            exclude_json,
            bandwidth_limit_kbps,
        } => {
            let c = open_catalog(catalog).await?;
            let policy = Policy {
                id: uuid::Uuid::new_v4().to_string(),
                name: name.clone(),
                schedule_cron: schedule_cron.clone(),
                retention_json: retention_json.clone(),
                paths_json: paths_json.clone(),
                exclude_json: exclude_json.clone(),
                bandwidth_limit_kbps: *bandwidth_limit_kbps,
                pre_hook: None,
                post_hook: None,
                enabled: true,
            };
            let policy = c.add_policy(&policy).await?;
            c.audit(None, "policy.add", Some(name)).await.ok();
            print_json(
                json,
                &serde_json::json!({ "id": policy.id, "name": policy.name, "schedule_cron": policy.schedule_cron }),
                || println!("added policy {} ({})", policy.name, policy.id),
            );
        }
        PolicyCommand::List { catalog } => {
            let c = open_catalog(catalog).await?;
            let policies = c.list_policies().await?;
            let arr: Vec<serde_json::Value> = policies
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "id": p.id,
                        "name": p.name,
                        "schedule_cron": p.schedule_cron,
                        "enabled": p.enabled,
                    })
                })
                .collect();
            print_json(json, &serde_json::to_value(&arr).unwrap(), || {
                if policies.is_empty() {
                    println!("no policies (use `aegis policy add`)");
                    return;
                }
                println!("{:<38}  {:<24}  {:<6}  CRON", "ID", "NAME", "ENABLED");
                for p in &policies {
                    println!(
                        "{:<38}  {:<24}  {:<6}  {}",
                        p.id, p.name, p.enabled, p.schedule_cron
                    );
                }
            });
        }
        PolicyCommand::Remove { catalog, policy } => {
            let c = open_catalog(catalog).await?;
            let removed = c.remove_policy(policy).await?;
            if removed {
                c.audit(None, "policy.remove", Some(policy)).await.ok();
            }
            print_json(
                json,
                &serde_json::json!({ "policy": policy, "removed": removed }),
                || {
                    if removed {
                        println!("removed policy {policy}");
                    } else {
                        println!("no policy named {policy}");
                    }
                },
            );
        }
    }
    Ok(())
}

fn print_json(json: bool, value: &serde_json::Value, human: impl FnOnce()) {
    if json {
        println!("{}", serde_json::to_string_pretty(value).unwrap());
    } else {
        human();
    }
}
