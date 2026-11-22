//! Local WAL degradation when PG is unwritable (② §4.8 degradation matrix; the real wiring for PL-12 12.3).
//!
//! Semantics (consistent with the document):
//! - **Only errors provably meaning "PG unavailable"** (connection drop/timeout/pool exhaustion/server shutdown/blocked write/resource exhaustion,
//!   see [`crate::store::pg::is_unavailable`]) enter the WAL; constraint/syntax/type errors (4xx class)
//!   are reported as-is, so bad messages are not accumulated only to fail permanently on replay.
//! - **Only small messages are accepted**: payload inlined, no `payload_ref`, `size ≤ 1MB`. Large messages/large objects fail explicitly
//!   (500 + `details.wal`) and increment `lattice_wal_dropped_total` — never drop silently, and never use disk
//!   as object storage. On rejection the Redis dedup hot-layer key is released, so the client can retry the same id after PG recovers.
//! - **The WAL only fills in persistence**: during degradation, routing/receipts already followed the online path (or offline pending); replay only
//!   calls `insert_message` (idempotency via `message_dedup`) and **does not re-route or resend business receipts**.
//! - A message is accepted only after the WAL append succeeds (fsync); only an append failure itself raises 500.
//!
//! When PG is entirely unavailable, membership checks/member-list reads also fail first (never reaching insert), so a short-lived positive cache
//! provides a fallback (see [`crate::state::PgDegradeCache`]); a cache miss still fails with the original error and never fabricates authorization.

use chrono::{DateTime, Utc};
use lattice_core::Envelope;

use crate::error::{self, Result};
use crate::state::AppState;
use crate::store::pg::{self, InsertOutcome, NewMessage};
use crate::store::wal::{AppendOutcome, WalRecord};

/// Upper bound for a single inlined message eligible for the WAL (= §17.6 payload inline threshold 1MB).
pub const WAL_INLINE_MAX_BYTES: usize = lattice_core::protocol::INLINE_MAX_BYTES;

/// Persistence stage outcome.
#[derive(Debug, Clone)]
pub enum PersistOutcome {
        /// PG wrote normally (including a cold-layer dedup hit; the caller inspects `InsertOutcome.duplicate`)
    Persisted(InsertOutcome),
        /// PG unavailable: appended to the local WAL and fsynced (`wal_bytes` is the file size after append)
    Waled { seq: u64, wal_bytes: u64 },
}

impl PersistOutcome {
    pub fn wal_degraded(&self) -> bool {
        matches!(self, PersistOutcome::Waled { .. })
    }

    pub fn insert_outcome(&self) -> Option<InsertOutcome> {
        match self {
            PersistOutcome::Persisted(o) => Some(*o),
            PersistOutcome::Waled { .. } => None,
        }
    }
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Persisted `size` of the logical message (⑤ §4.2 / E18-GAP-9).
///
/// For inline-payload messages = payload byte count; for large-object/file messages the payload is empty, so the real size exists only in the envelope's
/// `metadata.size` (written by both `/v1/uploads/{id}/complete` and the WS chunk reassembly product). Take the larger of the two to
/// avoid storing large-object messages as `messages.size=0`.
pub fn message_size(env: &Envelope) -> i64 {
    let inline = env.payload.len() as i64;
    let declared = env
        .metadata
        .get("size")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);
    inline.max(declared)
}

/// `chunk_total` of a chunked logical message (default 1; the reassembly product records the total chunk count in `metadata.chunk_total`).
fn chunk_total(env: &Envelope) -> i32 {
    env.metadata
        .get("chunk_total")
        .and_then(|s| s.parse::<i32>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
}

/// Reason a message is not WAL-eligible (used for logs/error details/unit-test assertions).
pub fn ineligible_reason(env: &Envelope, wal_enabled: bool) -> Option<&'static str> {
    if !wal_enabled {
        return Some("wal_disabled");
    }
    if env.is_chunk() {
        return Some("chunked");
    }
    if env.metadata.contains_key("payload_ref") {
                // Large object: the payload lives in MinIO and the PG row is only a reference; the WAL does not replay object storage, so do not pretend to cover it
        return Some("payload_ref");
    }
    if env.payload.len() > WAL_INLINE_MAX_BYTES {
        return Some("payload_too_large");
    }
    None
}

/// Build a WAL record; returns the reason when the message is not WAL-eligible (writes nothing).
pub fn record_for(
    env: &Envelope,
    sender: &str,
    seq: u64,
    expires_at: Option<DateTime<Utc>>,
    wal_enabled: bool,
    recorded_at_ms: u64,
) -> std::result::Result<WalRecord, &'static str> {
    if let Some(reason) = ineligible_reason(env, wal_enabled) {
        return Err(reason);
    }
    Ok(WalRecord {
        id: env.id.clone(),
        conv_id: env.conv_id.clone(),
        sender: sender.to_string(),
        env_type: env.r#type.clone(),
        content_type: if env.content_type.is_empty() {
            None
        } else {
            Some(env.content_type.clone())
        },
        size: env.payload.len() as i64,
        payload_b64: lattice_core::envelope::base64_encode(&env.payload),
        seq: seq as i64,
        expires_at_ms: expires_at.map(|t: DateTime<Utc>| t.timestamp_millis().max(0) as u64),
        ttl_seconds: env.ttl_seconds,
        recorded_at_ms,
    })
}

/// Release the Redis dedup hot-layer claim: called when a message is finally **not** persisted, so a client retry is not mistaken for a duplicate and dropped.
pub async fn release_dedup_claim(state: &AppState, id: &str) {
    if let Err(e) = state
        .redis
        .del(&lattice_core::keys::dedup(id))
        .await
    {
        tracing::warn!(error = %e, id, "release dedup claim failed");
    }
}

/// Error for a message that is not WAL-eligible (explicit rejection: 500 + `details.wal`, never dropped silently).
pub fn ineligible_error(reason: &str) -> crate::error::LatticeError {
    pg::unavailable_error()
        .with_detail("wal", serde_json::json!(reason))
        .with_detail("hint", serde_json::json!("retry after pg recovery or use /v1/uploads"))
}

/// Rejection path for a message that is not WAL-eligible: increments `lattice_wal_dropped_total`, releases the dedup claim, logs, then returns the error.
///
/// Called before seq allocation, to avoid "rejecting the message but still burning a seq" and leaving needless gaps.
pub async fn reject_ineligible(
    state: &AppState,
    env: &Envelope,
    reason: &'static str,
) -> Result<()> {
    state.metrics.wal_dropped_total.inc();
    tracing::warn!(
        id = %env.id,
        size = env.payload.len(),
        reason,
        "message not wal-eligible while pg unavailable; rejecting explicitly (not silently dropped)"
    );
    release_dedup_claim(state, &env.id).await;
    Err(ineligible_error(reason))
}

/// Persist: prefer PG; when PG is provably unavailable, fall back to the local WAL per the rules (② §4.8).
pub async fn persist_with_wal_fallback(
    state: &AppState,
    env: &Envelope,
    sender: &str,
    seq: u64,
    expires_at: Option<DateTime<Utc>>,
) -> Result<PersistOutcome> {
    let payload_ref = env.metadata.get("payload_ref").cloned();
        // Do not attempt PG inside the circuit-breaker window: otherwise every message waits for the pool acquire_timeout (default 5s),
        // and sends/receipts get held up, which contradicts the goal of "still accepting during degradation".
    if state.pg_degraded() {
        return append_or_reject(state, env, sender, seq, expires_at).await;
    }

    let new = NewMessage {
        id: &env.id,
        conv_id: &env.conv_id,
        sender,
        env_type: &env.r#type,
        content_type: if env.content_type.is_empty() {
            None
        } else {
            Some(env.content_type.as_str())
        },
        size: message_size(env),
        chunk_total: chunk_total(env),
        payload: if payload_ref.is_some() {
            None
        } else {
            Some(env.payload.clone())
        },
        payload_ref: payload_ref.as_deref(),
        seq: seq as i64,
        expires_at,
    };
    match pg::insert_message(&state.db, new).await {
        Ok(outcome) => {
                        // Successful write = PG is available: clear any local circuit-breaker window (avoid a lingering breaker window)
            state.mark_pg_up();
            Ok(PersistOutcome::Persisted(outcome))
        }
        Err(e) if pg::is_unavailable_err(&e) => {
            state.mark_pg_down();
            tracing::warn!(
                id = %env.id,
                error = %e,
                "pg insert unavailable; fallback to local wal (② §4.8)"
            );
            append_or_reject(state, env, sender, seq, expires_at).await
        }
        Err(e) => {
                        // Explicit failure: drop the dedup claim so the client can retry with the same id after PG recovers.
            release_dedup_claim(state, &env.id).await;
            Err(e)
        }
    }
}

/// Append the message to the local WAL; not WAL-eligible / over the limit / write failure all fail explicitly (never dropped silently).
async fn append_or_reject(
    state: &AppState,
    env: &Envelope,
    sender: &str,
    seq: u64,
    expires_at: Option<DateTime<Utc>>,
) -> Result<PersistOutcome> {
    let rec = match record_for(
        env,
        sender,
        seq,
        expires_at,
        state.cfg.wal.enabled,
        epoch_ms(),
    ) {
        Ok(rec) => rec,
        Err(reason) => {
            state.metrics.wal_dropped_total.inc();
            tracing::warn!(
                id = %env.id,
                size = env.payload.len(),
                reason,
                "message not wal-eligible while pg unavailable; rejecting explicitly (not silently dropped)"
            );
            release_dedup_claim(state, &env.id).await;
            return Err(ineligible_error(reason));
        }
    };

    match state.wal.append(&rec) {
        Ok(AppendOutcome::Appended) => {
            let wal_bytes = state.wal.size_bytes();
            state.metrics.wal_append_total.with_label_values(&["ok"]).inc();
            state.metrics.wal_size_bytes.set(wal_bytes as i64);
            tracing::warn!(
                id = %env.id,
                seq,
                wal_bytes,
                conv_id = %env.conv_id,
                "pg unavailable: small message appended to local wal (fsync) and accepted"
            );
            Ok(PersistOutcome::Waled { seq, wal_bytes })
        }
        Ok(AppendOutcome::Full) => {
            state.metrics.wal_append_total.with_label_values(&["full"]).inc();
            state.metrics.wal_dropped_total.inc();
            state.metrics.wal_size_bytes.set(state.wal.size_bytes() as i64);
            tracing::error!(
                id = %env.id,
                max_bytes = state.wal.max_bytes(),
                "local wal is full; rejecting message (wal must not grow silently)"
            );
            release_dedup_claim(state, &env.id).await;
            Err(pg::unavailable_error()
                .with_detail("wal", serde_json::json!("full"))
                .with_detail("wal_max_bytes", serde_json::json!(state.wal.max_bytes())))
        }
        Err(e) => {
            state.metrics.wal_append_total.with_label_values(&["fail"]).inc();
            state.metrics.wal_size_bytes.set(state.wal.size_bytes() as i64);
            tracing::error!(id = %env.id, error = %e, "local wal append failed; failing the send");
            release_dedup_claim(state, &env.id).await;
            Err(e)
        }
    }
}

/// Membership check: when PG is healthy, use the authoritative value and refresh the short-lived positive cache; when PG is provably unavailable, accept cache hits only.
///
/// Hot-path optimization (once per uplink message, PL-17): while PG is healthy, a **short-TTL positive cache** hit on `(conv,user)` lets the message through,
/// saving the two PG queries `conversation_by_id` + `member_role`.
/// The cache stores only relations "once verified as true by PG" (no negative cache); a miss always goes to PG;
/// the membership-change API invalidates actively (`transport/http.rs`), and the TTL (default 1s) only serves as a fallback window.
pub async fn ensure_member(state: &AppState, conv_id: &str, sender: &str) -> Result<()> {
    if state.pg_degraded() {
        if state.pg_degrade.is_member(conv_id, sender) {
            tracing::warn!(
                conv_id,
                "pg degraded: membership accepted from short-lived positive cache (② §4.8)"
            );
            return Ok(());
        }
                // Cache miss: never fabricate authorization; fail explicitly as "PG unavailable" (the client may retry later)
        return Err(pg::unavailable_error()
            .with_detail("degrade", serde_json::json!("membership_cache_miss")));
    }

        // Positive cache hit: skip the conversation-existence and role PG queries (only let through relations PG once verified as true).
    if state.member_cache.is_member(conv_id, sender) {
        state.note_member_cache(true);
        return Ok(());
    }
    state.note_member_cache(false);

    match pg::conversation_by_id(&state.db, conv_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return Err(error::not_found("conversation not found")),
        Err(e) if pg::is_unavailable_err(&e) => {
            state.mark_pg_down();
            return fallback_member(state, conv_id, sender, e);
        }
        Err(e) => return Err(e),
    }

    match pg::member_role(&state.db, conv_id, sender).await {
        Ok(Some(_)) => {
                        // Dual write: degrade cache (fallback while PG is unavailable, 5min) + normal-path positive cache (1s, active invalidation).
            state.pg_degrade.remember_member(conv_id, sender);
            state.member_cache.remember_member(conv_id, sender);
            Ok(())
        }
        Ok(None) => Err(error::forbidden("not a member").with_reason("not_member")),
        Err(e) if pg::is_unavailable_err(&e) => {
            state.mark_pg_down();
            fallback_member(state, conv_id, sender, e)
        }
        Err(e) => Err(e),
    }
}

fn fallback_member(
    state: &AppState,
    conv_id: &str,
    sender: &str,
    pg_err: crate::error::LatticeError,
) -> Result<()> {
    if state.pg_degrade.is_member(conv_id, sender) {
        tracing::warn!(
            error = %pg_err,
            conv_id,
            "pg unavailable: membership accepted from short-lived positive cache (② §4.8)"
        );
        Ok(())
    } else {
        tracing::warn!(
            error = %pg_err,
            conv_id,
            "pg unavailable and membership not cached; rejecting send (no authorization fabricated)"
        );
        Err(pg_err)
    }
}

/// Allocate seq during degradation: when PG is unavailable, skip the `conv_seq_watermark` lookup (otherwise every message waits one more pool timeout)
/// and use Redis `INCR` directly; after PG recovers, the 30s watermark task + reconcile converge the values.
pub async fn next_seq_pg_degraded(state: &AppState, conv: &str) -> Result<u64> {
    match state.redis.next_seq(conv).await {
        Ok(v) if v > 0 => Ok(v as u64),
        Ok(_) => {
            tracing::error!(conv, "seq INCR returned non-positive value during pg degradation");
            Err(pg::unavailable_error()
                .with_detail("degrade", serde_json::json!("seq_unavailable")))
        }
        Err(e) => {
                        // PG+Redis double outage is outside the WAL degradation matrix promise (② §4.8 only defines PG being unwritable);
                        // fail explicitly instead of writing the WAL with an untrusted seq (replay would hit seq conflicts/reordering).
            tracing::error!(error = %e, conv, "seq INCR failed during pg degradation; rejecting");
            state
                .metrics
                .chunk_retrans_total
                .with_label_values(&["seq_pg_degraded"])
                .inc();
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn env(ty: &str, payload: Vec<u8>) -> Envelope {
        Envelope {
            id: "01JTEST0000000000000000001".into(),
            conv_id: "01HTEST0000000000000000002".into(),
            r#type: ty.into(),
            content_type: "text/plain".into(),
            payload,
            ..Default::default()
        }
    }

    #[test]
    fn small_inline_message_is_eligible() {
        let e = env("text", vec![0x61; 32]);
        assert!(ineligible_reason(&e, true).is_none());
        let rec = record_for(&e, "01GSENDER", 7, None, true, 1234).unwrap();
        assert_eq!(rec.seq, 7);
        assert_eq!(rec.size, 32);
        assert_eq!(rec.recorded_at_ms, 1234);
        assert_eq!(
            lattice_core::envelope::base64_decode(&rec.payload_b64).unwrap(),
            vec![0x61; 32]
        );
    }

    #[test]
    fn large_message_and_payload_ref_are_never_wal_cached() {
                // >1MB inline message: not cached (explicit rejection; the caller returns 500 + counts dropped)
        let big = env("binary", vec![0x62; WAL_INLINE_MAX_BYTES + 1]);
        assert_eq!(ineligible_reason(&big, true), Some("payload_too_large"));
        assert!(record_for(&big, "s", 1, None, true, 1).is_err());
                // Exactly 1MB is allowed (boundary is ≤)
        let exact = env("binary", vec![0x62; WAL_INLINE_MAX_BYTES]);
        assert!(ineligible_reason(&exact, true).is_none());
                // Large-object reference: payload lives in MinIO; the WAL does not replay object storage
        let mut obj = env("file", vec![]);
        obj.metadata.insert("payload_ref".into(), "lattice-large/x".into());
        assert_eq!(ineligible_reason(&obj, true), Some("payload_ref"));
                // Switch off / chunk envelope also write nothing
        assert_eq!(ineligible_reason(&env("text", vec![1]), false), Some("wal_disabled"));
        let mut chunk = env("binary", vec![1]);
        chunk.chunks = Some(lattice_core::ChunkInfo {
            total: 3,
            index: 0,
            size: 1,
            checksum: vec![],
        });
        assert_eq!(ineligible_reason(&chunk, true), Some("chunked"));
    }

    #[test]
    fn ttl_is_preserved_in_record() {
        let e = env("text", vec![1, 2, 3]);
        let expires = Utc.timestamp_millis_opt(1_700_000_000_000).unwrap();
        let rec = record_for(&e, "s", 1, Some(expires), true, 1).unwrap();
        assert_eq!(rec.expires_at_ms, Some(1_700_000_000_000));
        assert_eq!(rec.ttl_seconds, e.ttl_seconds);
    }

    #[test]
    fn message_size_uses_metadata_for_payload_ref_messages() {
                // E18-GAP-9: file/large-object messages have an empty payload; the real size is in metadata.size
        let mut file = env("file", vec![]);
        file.metadata.insert("payload_ref".into(), "2026/11/22/01J/c0.bin".into());
        file.metadata.insert("size".into(), "8389632".into());
        assert_eq!(message_size(&file), 8_389_632);
        assert_eq!(chunk_total(&file), 1);
                // Chunk reassembly product: chunk_total is recorded in metadata
        let mut chunked = env("binary", vec![]);
        chunked.metadata.insert("payload_ref".into(), "2026/11/22/01K/c0.bin".into());
        chunked.metadata.insert("size".into(), "33554432".into());
        chunked.metadata.insert("chunk_total".into(), "128".into());
        assert_eq!(message_size(&chunked), 33_554_432);
        assert_eq!(chunk_total(&chunked), 128);
                // Inline messages still use payload; junk values in metadata never shrink/grow size into an invalid value
        let inline = env("text", vec![0x61; 32]);
        assert_eq!(message_size(&inline), 32);
        let mut weird = env("text", vec![0x61; 32]);
        weird.metadata.insert("size".into(), "not-a-number".into());
        assert_eq!(message_size(&weird), 32);
        let mut negative = env("text", vec![0x61; 4]);
        negative.metadata.insert("size".into(), "-5".into());
        assert_eq!(message_size(&negative), 4);
    }
}
