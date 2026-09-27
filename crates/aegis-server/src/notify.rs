//! Job-completion notifications (`docs/03` Phase 3: webhook, Telegram).
//!
//! Both transports are plain HTTPS POSTs, configured entirely through the
//! environment so nothing has to be stored in the catalog:
//!
//! | Variable | Effect |
//! |---|---|
//! | `AEGIS_WEBHOOK_URL` | POST the job event as JSON to this URL |
//! | `AEGIS_TELEGRAM_BOT_TOKEN` + `AEGIS_TELEGRAM_CHAT_ID` | send a short text summary through the bot |
//!
//! Notifications are fire-and-forget: a failed POST is logged and never
//! affects the job's outcome. Email is intentionally not implemented (it needs
//! an SMTP client and credentials in the process environment); point
//! `AEGIS_WEBHOOK_URL` at a mail-relay service instead.

use std::time::Duration;

use crate::jobs::JobEvent;

/// Notification targets, read once from the environment at startup.
#[derive(Debug, Clone, Default)]
pub struct Notifier {
    webhook: Option<String>,
    telegram: Option<(String, String)>,
}

impl Notifier {
    /// Build a notifier from `AEGIS_WEBHOOK_URL` / `AEGIS_TELEGRAM_*`.
    /// Targets missing their companion variable are ignored (a half-configured
    /// Telegram bot is a no-op, not a startup failure).
    pub fn from_env() -> Self {
        let webhook = std::env::var("AEGIS_WEBHOOK_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let telegram = match (
            std::env::var("AEGIS_TELEGRAM_BOT_TOKEN"),
            std::env::var("AEGIS_TELEGRAM_CHAT_ID"),
        ) {
            (Ok(token), Ok(chat)) if !token.trim().is_empty() && !chat.trim().is_empty() => {
                Some((token, chat))
            }
            _ => None,
        };
        Self { webhook, telegram }
    }

    /// `true` when no target is configured (nothing to do).
    pub fn is_empty(&self) -> bool {
        self.webhook.is_none() && self.telegram.is_none()
    }

    /// Announce a finished (or failed) job. Errors are logged, never returned:
    /// a backup that succeeded is still a success if the webhook is down.
    pub async fn job_finished(&self, event: &JobEvent) {
        if self.is_empty() {
            return;
        }
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "building the notification client failed");
                return;
            }
        };
        if let Some(url) = &self.webhook {
            match client.post(url).json(event).send().await {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => {
                    tracing::warn!(url = %url, status = %r.status(), "webhook rejected the notification")
                }
                Err(e) => tracing::warn!(url = %url, error = %e, "webhook notification failed"),
            }
        }
        if let Some((token, chat)) = &self.telegram {
            let url = format!("https://api.telegram.org/bot{token}/sendMessage");
            let text = format!(
                "Aegis job {} on host {}: {} ({} new of {} bytes)",
                &event.job_id[..8.min(event.job_id.len())],
                &event.host_id[..8.min(event.host_id.len())],
                event.event,
                event.bytes_new.unwrap_or(0),
                event.bytes_total.unwrap_or(0)
            );
            let payload = serde_json::json!({ "chat_id": chat, "text": text });
            match client.post(url).json(&payload).send().await {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => tracing::warn!(status = %r.status(), "telegram rejected the notification"),
                Err(e) => tracing::warn!(error = %e, "telegram notification failed"),
            }
        }
    }
}
