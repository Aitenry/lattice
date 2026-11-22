//! Dedup and idempotency (② §4.4 / §17.5). Three layers: client LRU (document ①) → Redis hot layer → PG cold layer.

use crate::error::Result;
use crate::state::AppState;

/// Dedup decision. Returns `true` for **first occurrence** (let through); `false` for a duplicate (ack immediately).
///
/// Idempotency key: logical message `id`, or chunk envelope `<id>.c<i>` (§17.2).
pub async fn first_seen(state: &AppState, key: &str) -> Result<bool> {
        // 1) Redis hot layer: SET NX EX dedup.ttl
    match state.redis.dedup_first(key, state.cfg.policy.dedup_ttl).await {
        Ok(true) => {
            state.metrics.dedup_hit_total.with_label_values(&["redis_miss"]).inc();
            return Ok(true);
        }
        Ok(false) => {
            state.metrics.dedup_hit_total.with_label_values(&["redis"]).inc();
            return Ok(false);
        }
        Err(e) => {
                        // 2) Redis unavailable → cold-layer unique constraint fallback (no functional degradation, only higher latency, ⑥ §3.4)
            tracing::warn!(error = %e, "dedup hot layer unavailable, fallback to pg");
        }
    }
    Ok(true)
}

/// Record the cold-layer duplicate result (`insert_message` already did it atomically; this only emits metrics).
pub fn record_pg_hit(state: &AppState, duplicate: bool) {
    if duplicate {
        state.metrics.dedup_hit_total.with_label_values(&["pg"]).inc();
    }
}

#[cfg(test)]
mod tests {
    use lattice_core::ids;

    #[test]
    fn dedup_key_is_id_or_chunk_id() {
        let id = ids::new_id();
        assert!(ids::parse_chunk_id(&id).is_none());
        let chunk = ids::chunk_id(&id, 0);
        assert_eq!(ids::parse_chunk_id(&chunk), Some((id.as_str(), 0)));
    }
}
