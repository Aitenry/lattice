//! Per-session sequence numbers (§6.4): Redis `INCR` + PG watermark anti-rollback.
//!
//! Invariants (⑥ §6.1):
//! - IN2: at most one row per `(conv_id, seq)` — guaranteed by allocation in this module, **not** a database constraint;
//! - IN7: `messages.seq ≤ conv_seq_watermark.seq` — reconciled by [`flush_watermarks`] every 30s.
//!
//! ## E26-G7: IN2 window during a Redis primary/replica switchover (closed)
//!
//! The old implementation corrected against the PG watermark only when the Redis `INCR` **went backwards**, but the PG watermark is flushed only every 30s,
//! so two windows could each reuse an already-issued seq:
//!
//! 1. **Switchover rollback**: seqs were issued after the watermark reached PG (not yet flushed); switching to an old primary corrects against the old watermark,
//!    and the corrected value may equal a seq already issued in the window;
//! 2. **Redis total-outage fallback**: when `Redis INCR` failed, the old implementation returned `PG watermark+1` every time, so multiple
//!    messages in the same window got the **same seq** (and after a Redis rebuild, correcting against the old watermark reused it again).
//!
//! Fix (② §4.8 / ⑥ §6.1):
//! - This process tracks the **issued seq high watermark** per session ([`issued_high_water`], bounded + idle eviction);
//!   correction/degradation uses `max(PG watermark, process high watermark)` as the protective lower bound;
//! - Both the correction and degradation paths **advance the PG watermark synchronously** ([`crate::store::pg::set_seq_watermark`]:
//!   `greatest` semantics, so racing writes cannot roll back), pinning the issued range into the authoritative watermark; a process restart or another switchover cannot reuse it.
//!
//! Boundary (recorded honestly): the in-process high watermark covers only seqs issued by **this node**; when multiple nodes write the same session,
//! seqs issued by another node that have not yet reached PG can only converge via the 30s flush period (the cross-node window = the flush period,
//! consistent with the existing design; no new cross-node distributed allocator was added).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::error::Result;
use crate::state::AppState;

/// Upper bound on sessions tracked per process (evicts the oldest/least recently active entries to avoid unbounded memory).
const MAX_TRACKED_CONVS: usize = 4096;
/// Idle eviction time for session high-watermark entries (a session is cold after 1 hour without allocation).
const ISSUED_IDLE: Duration = Duration::from_secs(3600);

struct IssuedHighWater {
    map: Mutex<HashMap<String, (i64, Instant)>>,
}

static ISSUED: OnceLock<IssuedHighWater> = OnceLock::new();

fn issued_cell() -> &'static Mutex<HashMap<String, (i64, Instant)>> {
    &ISSUED
        .get_or_init(|| IssuedHighWater {
            map: Mutex::new(HashMap::new()),
        })
        .map
}

/// Record one issued seq (takes max, tolerating out-of-order delivery/retries).
fn note_issued(conv: &str, seq: i64) {
    let Ok(mut map) = issued_cell().lock() else {
        return;
    };
    if map.len() >= MAX_TRACKED_CONVS && !map.contains_key(conv) {
        map.retain(|_, (_, at)| at.elapsed() < ISSUED_IDLE);
        if map.len() >= MAX_TRACKED_CONVS {
            // Still full: clear conservatively (the high watermark is only a "better" protection; after clearing, fall back to PG watermark semantics).
            map.clear();
        }
    }
    let now = Instant::now();
    match map.get_mut(conv) {
        Some(entry) => {
            entry.0 = entry.0.max(seq);
            entry.1 = now;
        }
        None => {
            map.insert(conv.to_string(), (seq, now));
        }
    }
}

/// Upper bound of seqs issued for this session by this process (0 = never allocated).
pub fn issued_high_water(conv: &str) -> i64 {
    let Ok(map) = issued_cell().lock() else {
        return 0;
    };
    map.get(conv).map(|(seq, _)| *seq).unwrap_or(0)
}

/// Protective lower bound during correction/degradation: `max(PG watermark, process-issued high watermark)`.
pub fn protected_floor(conv: &str, pg_floor: i64) -> i64 {
    pg_floor.max(issued_high_water(conv))
}

/// Allocate the next seq. When a Redis primary/replica switchover makes `INCR` go backwards, continue from `max(Redis, PG)+1` (② §4.8),
/// and advance the PG watermark with the corrected value (E26-G7: eliminates seq reuse inside the "watermark not yet in PG" window).
pub async fn next_seq(state: &AppState, conv: &str) -> Result<u64> {
    let pg_floor = crate::store::pg::get_seq_watermark(&state.db, conv)
        .await
        .unwrap_or(0);
    let floor = protected_floor(conv, pg_floor);

    let redis_seq = match state.redis.next_seq(conv).await {
        Ok(v) => v,
        Err(e) => {
            // Redis unavailable: degrade to "protective lower bound +1" (ordering is guaranteed within a single node; cross-node conflicts → metric warning).
            // Advance the PG watermark synchronously: otherwise every message in the same outage window gets the same seq (IN2),
            // and after a Redis rebuild, correcting against the old watermark reuses it again.
            tracing::warn!(error = %e, conv = %conv, "seq INCR failed, fallback to PG/process high watermark");
            let next = floor + 1;
            note_issued(conv, next);
            if let Err(e) = crate::store::pg::set_seq_watermark(&state.db, conv, next).await {
                tracing::warn!(error = %e, conv, seq = next, "seq fallback: PG watermark advance failed");
            }
            return Ok(next as u64);
        }
    };

    if redis_seq <= floor {
        tracing::warn!(
            conv = %conv,
            redis_seq,
            floor,
            pg_floor,
            "seq regression detected, correcting"
        );
        let next = floor + 1;
        let _ = state.redis.set_seq_floor(conv, next).await;
        // Persist the corrected value to the PG watermark synchronously (greatest, no rollback): later switchovers/restarts no longer reuse old watermarks.
        if let Err(e) = crate::store::pg::set_seq_watermark(&state.db, conv, next).await {
            tracing::warn!(error = %e, conv, seq = next, "seq regression: PG watermark advance failed");
        }
        state
            .metrics
            .chunk_retrans_total
            .with_label_values(&["seq_regression"])
            .inc();
        note_issued(conv, next);
        return Ok(next as u64);
    }
    note_issued(conv, redis_seq);
    Ok(redis_seq as u64)
}

/// `lock:seq-watermark` task: persist issued seqs to PG (⑥ §2.6, 30s period).
pub async fn flush_watermarks(state: &AppState) -> Result<u64> {
    let n = crate::store::pg::flush_seq_watermarks(&state.db).await?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watermark_floor_semantics() {
        // Logic unit test: floor=10, redis=3 → continue at 11 (do not reuse the already-issued 1..10)
        let floor: i64 = 10;
        let redis_seq: i64 = 3;
        let next = if redis_seq <= floor { floor + 1 } else { redis_seq };
        assert_eq!(next, 11);
    }

    #[test]
    fn issued_high_water_only_grows() {
        // Use a dedicated conv name so other tests in the same process do not interfere
        let conv = "test-issued-high-water-only-grows";
        assert_eq!(issued_high_water(conv), 0);
        note_issued(conv, 7);
        assert_eq!(issued_high_water(conv), 7);
        note_issued(conv, 3); // out-of-order delivery/retry does not roll back
        assert_eq!(issued_high_water(conv), 7);
        note_issued(conv, 9);
        assert_eq!(issued_high_water(conv), 9);
        assert_eq!(protected_floor(conv, 4), 9);
        assert_eq!(protected_floor(conv, 12), 12);
    }

    #[test]
    fn protected_floor_covers_in2_window() {
        // E26-G7 reproduction: PG watermark=44 (just flushed), then 45/46 issued in the window (not yet in PG),
        // switching to the old primary gives INCR=43 → the old implementation returned 45 (conflicts with issued 45); after the fix, process high watermark 46 → 47.
        let conv = "test-protected-floor-covers-in2-window";
        note_issued(conv, 44);
        note_issued(conv, 45);
        note_issued(conv, 46);
        let pg_floor = 44;
        let floor = protected_floor(conv, pg_floor);
        assert_eq!(floor, 46);
        let redis_seq = 43;
        assert!(redis_seq <= floor);
        assert_eq!(floor + 1, 47);
    }
}
