//! Bandwidth throttling: token-bucket pacing for backup transfers (Phase 6).
//!
//! The limiter paces the transfer of bytes read from the backup source: the
//! agentless path charges each streamed file's bytes to a shared bucket and
//! sleeps off the excess, which throttles the control plane's effective
//! network throughput. Chunk boundaries and hashes are unchanged: a
//! throttled backup produces byte-identical snapshots to an unthrottled
//! one — only the wall-clock time differs.
//!
//! Implementation: a token bucket refilled lazily at `rate_bps`; `acquire`
//! sleeps until the requested bytes fit the average rate.

use std::time::{Duration, Instant};

/// Paces byte consumption to at most `rate_bps` bytes per second.
///
/// `None` (via [`Option`]-typed configuration) means unlimited: `acquire`
/// returns immediately and costs nothing.
#[derive(Debug, Clone)]
pub struct BandwidthLimiter {
    rate_bps: u64,
    /// Bytes currently available.
    tokens: f64,
    /// Bucket capacity in bytes (one second's worth, minimum 1 KiB).
    capacity: f64,
    last_refill: Instant,
}

impl BandwidthLimiter {
    /// Build a limiter for `rate_bps` bytes/second.
    ///
    /// # Panics
    ///
    /// Never — a zero rate is treated as unlimited by the constructors that
    /// take an `Option`; constructing directly with zero paces to nothing.
    pub fn new(rate_bps: u64) -> Self {
        let capacity = rate_bps.max(1024) as f64;
        Self {
            rate_bps,
            tokens: capacity,
            capacity,
            last_refill: Instant::now(),
        }
    }

    /// Build a limiter from an optional kbps figure: `None` or `None`-like
    /// values (<= 0) mean unlimited.
    pub fn from_kbps(limit_kbps: Option<i32>) -> Option<Self> {
        let kbps = limit_kbps?;
        if kbps <= 0 {
            return None;
        }
        Some(Self::new(kbps as u64 * 1024 / 8))
    }

    /// Bytes currently available in the bucket (refills lazily).
    pub fn available(&mut self) -> u64 {
        self.refill();
        self.tokens.max(0.0) as u64
    }

    /// Consume `bytes` tokens without waiting (callers must check
    /// [`BandwidthLimiter::available`] first).
    pub fn consume(&mut self, bytes: u64) {
        self.tokens -= bytes as f64;
    }

    /// How long to wait before at least `bytes` tokens are available.
    pub fn wait_duration_for(&mut self, bytes: u64) -> Duration {
        self.refill();
        if self.tokens >= bytes as f64 || self.rate_bps == 0 {
            return Duration::ZERO;
        }
        let missing = (bytes as f64 - self.tokens).max(1.0);
        Duration::from_secs_f64((missing / self.rate_bps as f64).clamp(0.001, 0.5))
    }

    /// Wait until at least `bytes` may be consumed, then consume them.
    pub async fn acquire(&mut self, bytes: u64) {
        if self.rate_bps == 0 {
            return;
        }
        let mut remaining = bytes as f64;
        while remaining > 0.0 {
            self.refill();
            if self.tokens <= 0.0 {
                // Sleep until one byte's worth accrues (bounded to 100 ms
                // granularity so scheduling jitter stays small).
                let wait = Duration::from_secs_f64((1.0 / self.rate_bps as f64).clamp(0.001, 0.1));
                tokio::time::sleep(wait).await;
                self.refill();
            }
            let take = remaining.min(self.tokens);
            self.tokens -= take;
            remaining -= take;
        }
    }

    /// Bucket capacity in bytes (used by the reader gate).
    pub fn capacity(&self) -> u64 {
        self.capacity as u64
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens =
                (self.tokens.max(0.0) + elapsed * self.rate_bps as f64).min(self.capacity);
            self.last_refill = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unlimited_when_no_limit_configured() {
        assert!(BandwidthLimiter::from_kbps(None).is_none());
        assert!(BandwidthLimiter::from_kbps(Some(0)).is_none());
        assert!(BandwidthLimiter::from_kbps(Some(-5)).is_none());
    }

    #[tokio::test]
    async fn small_reads_within_bucket_are_instant() {
        // 1 MiB/s bucket: 4 KiB reads fit without waiting.
        let mut limiter = BandwidthLimiter::from_kbps(Some(8192)).unwrap(); // 8192 kbps = 1 MiB/s
        let start = Instant::now();
        for _ in 0..16 {
            limiter.acquire(4096).await;
        }
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "64 KiB inside a 1 MiB bucket must not pace: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn sustained_reads_pace_to_the_configured_rate() {
        // 1024 kbps = 128 KiB/s. Reading 384 KiB (3 seconds' worth) must take
        // at least ~2 seconds (bucket starts full = 1s head start).
        let mut limiter = BandwidthLimiter::new(128 * 1024);
        let total = 384 * 1024;
        let start = Instant::now();
        let mut done = 0;
        while done < total {
            let n = 32 * 1024u64;
            limiter.acquire(n).await;
            done += n;
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1800),
            "384 KiB at 128 KiB/s must take >= 1.8s, took {elapsed:?}"
        );
        assert!(
            elapsed <= Duration::from_secs(10),
            "pacing must not stall: {elapsed:?}"
        );
    }
}
