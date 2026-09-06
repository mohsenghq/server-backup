//! Retention policy selection: which snapshots survive a prune.
//!
//! `aegis prune` is the only destructive path in the system
//! (`docs/03-repository-format.md`), so its selection logic is kept pure and
//! heavily unit-tested here: given a set of snapshots and a policy, decide
//! which snapshots are *kept* and which may be deleted. The engine then
//! garbage-collects every blob referenced only by deleted snapshots.
//!
//! The policy is Grandfather-Father-Son: the most recent `keep_daily` unique
//! calendar days, the most recent `keep_weekly` unique ISO weeks, and the most
//! recent `keep_monthly` unique calendar months each keep one snapshot
//! (newest per bucket). Additionally, the `keep_last` most recent snapshots
//! are always kept regardless of age. Two safety nets apply to everything
//! above: snapshots with unparseable timestamps are never deleted, and the
//! newest snapshot overall is always kept — a prune must never destroy the
//! repository's only recovery point.

use serde::{Deserialize, Serialize};

use crate::snapshot::Snapshot;

/// How many snapshots to keep in each GFS bucket, plus an absolute floor.
///
/// `0` disables a bucket. All-zero means "keep the newest snapshot only".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Keep the newest snapshot of each of the last N distinct calendar days.
    pub keep_daily: u32,
    /// Keep the newest snapshot of each of the last N distinct ISO weeks.
    pub keep_weekly: u32,
    /// Keep the newest snapshot of each of the last N distinct calendar months.
    pub keep_monthly: u32,
    /// Always keep this many most-recent snapshots, however old.
    pub keep_last: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 6,
            keep_last: 3,
        }
    }
}

/// Result of applying a policy to a set of snapshots.
#[derive(Debug, Clone)]
pub struct RetentionDecision {
    /// Snapshots that survive the prune.
    pub kept: Vec<Snapshot>,
    /// Snapshots the policy marked for deletion. Garbage collection must
    /// still treat blobs referenced by any kept snapshot as live.
    pub pruned: Vec<Snapshot>,
}

/// A GFS bucket extractor: map a snapshot timestamp to a bucket identity.
type BucketFn = fn(&str) -> Option<String>;

/// Parse an RFC 3339 timestamp into a UTC [`time::OffsetDateTime`].
///
/// Returns `None` for timestamps retention cannot understand — such snapshots
/// are always kept rather than guessed about.
fn parse_utc(time: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(time, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|dt| dt.to_offset(time::UtcOffset::UTC))
}

/// Bucket key for the "distinct day" rule: the calendar date in UTC.
///
/// Days are distinct by calendar date, not by 24h distance: one snapshot per
/// day of activity survives per kept day, however many runs happened.
fn day_key(time: &str) -> Option<String> {
    let dt = parse_utc(time)?;
    Some(format!(
        "{}-{:02}-{:02}",
        dt.year(),
        u8::from(dt.month()),
        dt.day()
    ))
}

/// Bucket key for the "distinct week" rule: the ISO week `(year, week)` in UTC.
fn week_key(time: &str) -> Option<String> {
    let dt = parse_utc(time)?;
    let (iso_year, iso_week, _) = dt.date().to_iso_week_date();
    Some(format!("{iso_year}-W{iso_week:02}"))
}

/// Bucket key for the "distinct month" rule: `(year, month)` in UTC.
fn month_key(time: &str) -> Option<String> {
    let dt = parse_utc(time)?;
    Some(format!("{}-{:02}", dt.year(), u8::from(dt.month())))
}

/// Apply `policy` to `snapshots` (in any order; they are sorted newest first
/// internally).
///
/// The returned [`RetentionDecision`] partitions the input: every snapshot
/// appears exactly once, in `kept` or in `pruned`.
pub fn apply_policy(snapshots: &[Snapshot], policy: &RetentionPolicy) -> RetentionDecision {
    let mut sorted: Vec<&Snapshot> = snapshots.iter().collect();
    // Newest first, by *parsed* time: unparseable timestamps sort as oldest
    // (never as an accidental "newest" because their text compares large).
    // Ties fall back to the raw string, then the id, so the decision is
    // deterministic.
    fn sort_key(s: &Snapshot) -> (Option<i64>, &str, &str) {
        (
            parse_utc(&s.time).map(|dt| dt.unix_timestamp()),
            &s.time,
            &s.id,
        )
    }
    sorted.sort_by(|a, b| sort_key(b).cmp(&sort_key(a)));

    let mut kept_idx: std::collections::HashSet<usize> = std::collections::HashSet::new();

    // keep_last: the newest N snapshots, always.
    let last_count = policy.keep_last.min(sorted.len() as u32) as usize;
    for i in 0..last_count {
        kept_idx.insert(i);
    }

    // GFS buckets: walk newest first, keep the first (newest) snapshot of
    // each distinct bucket, stop once the bucket quota is exhausted.
    for (limit, key_of) in [
        (policy.keep_daily, day_key as BucketFn),
        (policy.keep_weekly, week_key as BucketFn),
        (policy.keep_monthly, month_key as BucketFn),
    ] {
        if limit == 0 {
            continue;
        }
        let mut used = 0u32;
        let mut seen_buckets = std::collections::HashSet::new();
        for (i, s) in sorted.iter().enumerate() {
            if used >= limit {
                break;
            }
            if let Some(key) = key_of(&s.time) {
                if seen_buckets.insert(key) {
                    kept_idx.insert(i);
                    used += 1;
                }
            }
            // Snapshots with unparseable timestamps are kept unconditionally
            // below, so they never consume a bucket.
        }
    }

    // Safety net: snapshots with unparseable timestamps are never deleted.
    for (i, s) in sorted.iter().enumerate() {
        if parse_utc(&s.time).is_none() {
            kept_idx.insert(i);
        }
    }

    // Safety net: the newest snapshot overall is always kept — a prune that
    // would wipe every snapshot (e.g. keep_last = 0 with no buckets) must not
    // destroy the repository's only recovery point.
    if !sorted.is_empty() {
        kept_idx.insert(0);
    }

    let kept: Vec<Snapshot> = sorted
        .iter()
        .enumerate()
        .filter(|(i, _)| kept_idx.contains(i))
        .map(|(_, s)| (*s).clone())
        .collect();
    let pruned: Vec<Snapshot> = sorted
        .iter()
        .enumerate()
        .filter(|(i, _)| !kept_idx.contains(i))
        .map(|(_, s)| (*s).clone())
        .collect();
    RetentionDecision { kept, pruned }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::SnapshotStats;
    use crate::tree::Node;

    fn snap(id: &str, time: &str) -> Snapshot {
        Snapshot {
            id: id.into(),
            time: time.into(),
            hostname: "h".into(),
            paths: vec![],
            root: Node::File {
                name: "f".into(),
                size: 0,
                mode: None,
                mtime: None,
                chunks: vec![],
            },
            stats: SnapshotStats::default(),
        }
    }

    fn ids(v: &[Snapshot]) -> Vec<String> {
        v.iter().map(|s| s.id.clone()).collect()
    }

    #[test]
    fn keep_last_alone_keeps_only_the_newest_n() {
        let snaps = [
            snap("a", "2026-01-01T10:00:00Z"),
            snap("b", "2026-01-02T10:00:00Z"),
            snap("c", "2026-01-03T10:00:00Z"),
            snap("d", "2026-01-04T10:00:00Z"),
        ];
        let policy = RetentionPolicy {
            keep_daily: 0,
            keep_weekly: 0,
            keep_monthly: 0,
            keep_last: 2,
        };
        let d = apply_policy(&snaps, &policy);
        assert_eq!(ids(&d.kept), vec!["d", "c"]);
        assert_eq!(ids(&d.pruned), vec!["b", "a"]);
    }

    #[test]
    fn daily_buckets_keep_the_newest_snapshot_of_each_day() {
        let snaps = [
            snap("d1-run1", "2026-01-01T09:00:00Z"),
            snap("d1-run2", "2026-01-01T18:00:00Z"),
            snap("d2", "2026-01-02T10:00:00Z"),
            snap("d3", "2026-01-03T10:00:00Z"),
        ];
        let policy = RetentionPolicy {
            keep_daily: 2,
            keep_weekly: 0,
            keep_monthly: 0,
            keep_last: 0,
        };
        let d = apply_policy(&snaps, &policy);
        // Newest run of the two newest days; both jan-1 runs are in one day.
        assert_eq!(ids(&d.kept), vec!["d3", "d2"]);
        assert_eq!(ids(&d.pruned), vec!["d1-run2", "d1-run1"]);
    }

    #[test]
    fn weekly_buckets_use_iso_weeks_across_year_boundaries() {
        // 2020-12-31 is ISO week 53 of 2020; 2021-01-01 is ALSO week 53 of
        // 2020 — the ISO year boundary, which calendar months would miss.
        let snaps = [
            snap("xmas", "2020-12-31T10:00:00Z"),
            snap("newyear", "2021-01-01T10:00:00Z"),
            snap("jan8", "2021-01-08T10:00:00Z"),
        ];
        let policy = RetentionPolicy {
            keep_daily: 0,
            keep_weekly: 2,
            keep_monthly: 0,
            keep_last: 0,
        };
        let d = apply_policy(&snaps, &policy);
        // jan8 owns week 1 of 2021; newyear and xmas share week 53 of 2020,
        // of which only the newer (newyear) is kept.
        assert_eq!(ids(&d.kept), vec!["jan8", "newyear"]);
        assert_eq!(ids(&d.pruned), vec!["xmas"]);
    }

    #[test]
    fn monthly_buckets_keep_one_snapshot_per_month() {
        let snaps = [
            snap("jan-a", "2026-01-05T10:00:00Z"),
            snap("jan-b", "2026-01-20T10:00:00Z"),
            snap("feb", "2026-02-02T10:00:00Z"),
        ];
        let policy = RetentionPolicy {
            keep_daily: 0,
            keep_weekly: 0,
            keep_monthly: 2,
            keep_last: 0,
        };
        let d = apply_policy(&snaps, &policy);
        assert_eq!(ids(&d.kept), vec!["feb", "jan-b"]);
        assert_eq!(ids(&d.pruned), vec!["jan-a"]);
    }

    #[test]
    fn the_newest_snapshot_is_never_pruned() {
        let snaps = [snap("only", "2020-01-01T00:00:00Z")];
        let d = apply_policy(&snaps, &RetentionPolicy::default());
        assert_eq!(ids(&d.kept), vec!["only"]);
        assert!(d.pruned.is_empty());
    }

    #[test]
    fn all_zero_policy_still_keeps_the_newest() {
        let snaps = [
            snap("a", "2026-01-01T10:00:00Z"),
            snap("b", "2026-01-02T10:00:00Z"),
        ];
        let policy = RetentionPolicy {
            keep_daily: 0,
            keep_weekly: 0,
            keep_monthly: 0,
            keep_last: 0,
        };
        let d = apply_policy(&snaps, &policy);
        assert_eq!(ids(&d.kept), vec!["b"]);
        assert_eq!(ids(&d.pruned), vec!["a"]);
    }

    #[test]
    fn unparseable_timestamps_are_always_kept() {
        let snaps = [
            snap("bad", "not-a-timestamp"),
            snap("good", "2026-01-01T10:00:00Z"),
        ];
        let policy = RetentionPolicy {
            keep_daily: 0,
            keep_weekly: 0,
            keep_monthly: 0,
            keep_last: 0,
        };
        let d = apply_policy(&snaps, &policy);
        assert_eq!(d.kept.len(), 2);
        assert!(d.pruned.is_empty());
    }

    #[test]
    fn default_policy_keeps_a_bounded_subset_of_a_dense_history() {
        // 30 days of one snapshot per day; the default policy must keep a
        // reasonable, bounded subset that always includes the newest.
        let snaps: Vec<Snapshot> = (1..=30)
            .map(|day| {
                snap(
                    &format!("s{day:02}"),
                    &format!("2026-03-{day:02}T12:00:00Z"),
                )
            })
            .collect();
        let d = apply_policy(&snaps, &RetentionPolicy::default());
        assert_eq!(d.kept[0].id, "s30");
        // 3 keep_last + 7 daily + up to 4 weekly + 1 monthly, with overlap.
        assert!(d.kept.len() >= 7 && d.kept.len() <= 15);
        assert_eq!(d.kept.len() + d.pruned.len(), 30);
    }
}
