//! Message pipeline (② §2.2): uplink stage orchestration + downlink dispatch.
//!
//! ```text
//! validate → dedup → detect → format → seq → persist → route → ack
//! (decode/auth happen in the transport layer, since they depend on protocol frames and connection context)
//! ```
//!
//! Every stage entry checks `[pipeline] bypass` (E31: per-stage bypass for debugging/emergency; empty by default = all effective),
//! and when bypassed only that stage's behavior is skipped and `lattice_pipeline_bypass_total{stage}` is emitted; other stages are unaffected.

pub mod chunk;
pub mod dedup;
pub mod detect;
pub mod encrypt;
pub mod format;
pub mod inspectable;
pub mod policy;
pub mod stage;
pub mod validate;
pub mod wal_degrade;

use chrono::{Duration, Utc};
use lattice_core::protocol::DeliveryState;
use lattice_core::Envelope;

use crate::error::Result;
use crate::pipeline::stage::Recipient;
use crate::state::AppState;

/// Uplink ingestion result (shared by the WS `receipt` and the REST 201 response).
#[derive(Debug, Clone)]
pub struct IngestOutcome {
    pub id: String,
    pub conv_id: String,
    pub seq: u64,
    pub state: DeliveryState,
    pub recipients: Vec<Recipient>,
        /// Idempotency hit (Redis hot layer or the `message_dedup` unique constraint) → reply ack directly (§17.5)
    pub duplicate: bool,
}

/// Uplink main path (the WS `envelope` frame is equivalent to `POST /v1/messages`, ⑤ §4.1).
pub async fn ingest(
    state: &AppState,
    sender: &str,
    sender_device: &str,
    mut env: Envelope,
) -> Result<IngestOutcome> {
        // OTel (E22): ingest stage span (envelope_id/conv_id/seq/low-cardinality sender hash; no payload).
        // With feature `otel` off it is a zero-sized no-op and changes no behavior.
    let __otel_ingest = crate::observe::otel::ingest_span(&env);
        // 0) Server injects sender: any client-supplied value is ignored and audited (⑤ §4.1)
    if !env.sender.is_empty() && env.sender != sender {
        tracing::warn!(declared = %env.sender, actual = %sender, id = %env.id, "sender spoof ignored");
                // **Keep writing PG directly** (the only audit point not wired to `audit_emit`): this is the hot path of every uplink message,
                // sender spoofing is an attack surface and must leave a trace, but NATS publish/ack (or even its degradation path)
                // round-trip latency must not enter the message ingestion path. The existing semantics already are "audit failure only WARNs, never blocks the message";
                // at worst a direct-write failure loses one alert audit and never affects message delivery. Management-plane/account-plane audits all go through
                // `routing::audit::audit_emit` (NATS audit stream → durable consumer).
        if let Err(e) = crate::store::pg::audit(
            &state.db,
            Some(sender),
            "sender_spoof",
            Some(&env.id),
            &serde_json::json!({ "declared": env.sender }),
            None,
        )
        .await
        {
            tracing::warn!(error = %e, "audit write failed");
        }
    }
    env.sender = sender.to_string();
    if env.id.is_empty() {
        env.id = lattice_core::ids::new_id();
    }
    if env.created_at == 0 {
        env.created_at = Utc::now().timestamp_millis() as u64;
    }

        // 0.5) Risk control (E03 / PL-12 12.6–12.7): if the device is inside a risk-control throttling window → reject explicitly with 429
        //      (no caching, no silent drop; the client can back off per Retry-After). With `[risk] enabled=false` (default)
        //      `check_ingest` returns true on its first line = zero side effects; when enabled, the hot path does one in-memory check only
        //      (message-rate sliding window); Redis writes/audit/revocation all run in risk background tasks and do not block this path.
    if !state.risk.check_ingest(sender, sender_device) {
        state
            .metrics
            .ratelimit_dropped_total
            .with_label_values(&["risk"])
            .inc();
        return Err(lattice_core::LatticeError::rate(
            "device temporarily rate-limited by risk engine",
        )
        .with_reason("risk_throttle"));
    }

        // 1) validate: fields, type namespace, quota, thresholds (§17.6 / §17.13)
        //    `[pipeline] bypass=["validate"]` (E31 debug/emergency) → the whole validation block is skipped; other stages are unaffected.
    if !stage_bypassed(state, "validate") {
        validate::validate_envelope(&env)?;
        validate::validate_quota(state, sender, env.payload.len() as u64)?;
        validate::validate_size(state, &env)?;
                // 1.1) Chunk aggregate cap (E14 S7 fix): >32MB must use MinIO Multipart and must not go through the WS chunk path.
                //      Placed before dedup/membership checks: an over-limit chunk registers no idempotency key, writes no chunks_index, and gets no ACK.
        validate::validate_chunk_aggregate(state, &env)?;
    }

        // 2) Membership check: non-members must not send messages to a conversation (⑤ §0.6 403 not_member).
        //    When PG is entirely unavailable (connection drop/timeout, not just write failure) use the short-lived positive cache as a fallback; a miss still fails explicitly
        //    (② §4.8: WAL degradation must not turn the degraded period into "anyone can send to any conversation").
    if !stage_bypassed(state, "member") {
        wal_degrade::ensure_member(state, &env.conv_id, sender).await?;
    }

        // 3) dedup: chunk envelopes first register chunks_index and **do not allocate seq** (§17.2)
        //    Bypassing dedup only skips the "idempotency decision"; chunks_index registration, chunk aggregation and other semantics remain
        //    (bypass does not change a stage's other duties); non-chunk messages simply lose duplicate detection (for debugging).
    let dedup_bypassed = stage_bypassed(state, "dedup");
    let is_chunk = env.is_chunk();
    if is_chunk {
        let key = env.id.clone();
        if !dedup_bypassed && !dedup::first_seen(state, &key).await? {
            return Ok(IngestOutcome {
                id: key,
                conv_id: env.conv_id,
                seq: 0,
                state: DeliveryState::Delivered,
                recipients: Vec::new(),
                duplicate: true,
            });
        }
                // Uplink of a chunk itself: no messages row, no seq, no recipients (dispatch waits for the reassembly side).
                // When chunks are complete, `accept_chunk` internally does "reassembly → whole sha256 verification → MinIO object → logical message
                // through the normal pipeline (allocate seq once / store messages / deliver)"; on failure it returns an error frame (terminal, no partial state).
        chunk::accept_chunk(state, &env, None).await?;
                // Uplink of a chunk itself: no messages row, no seq, no recipients (dispatch waits for the reassembly side)
        return Ok(IngestOutcome {
            id: env.id,
            conv_id: env.conv_id,
            seq: 0,
            state: DeliveryState::Delivered,
            recipients: Vec::new(),
            duplicate: false,
        });
    }

    if !dedup_bypassed && !dedup::first_seen(state, &env.id).await? {
        state
            .metrics
            .msgs_total
            .with_label_values(&["in", &env.r#type, "duplicate"])
            .inc();
        return Ok(IngestOutcome {
            id: env.id,
            conv_id: env.conv_id,
            seq: env.seq,
            state: DeliveryState::Delivered,
            recipients: Vec::new(),
            duplicate: true,
        });
    }

        // 4) detect / format: heuristics only when header fields are untrusted (zero-knowledge mode does not parse the payload)
        //    The two stages can be bypassed independently: with detect bypassed there is no detection result, and format only backfills "existing results".
    let trusted = state.mode() == lattice_core::Mode::ZeroKnowledge;
    let detected = if stage_bypassed(state, "detect") {
        None
    } else {
        Some(detect::detect(&env.content_type, trusted, &env.payload))
    };
    if !stage_bypassed(state, "format") {
        if let Some(detected) = &detected {
            if env.content_type.is_empty() {
                env.content_type = detected.mime.clone();
            }
            if env.r#type.is_empty() || detected.evidence == "magic" {
                env.r#type = detected.r#type.clone();
            }
        }
    }

        // 5) seq: allocated by the server (any client-supplied value is overwritten, ⑤ §4.1).
        //    If the PG breaker is open and the message is not WAL-eligible (large message/large object) → reject explicitly before allocating seq:
        //    no caching, no silent drop, and no wasted seq (② §4.8 covers small messages only).
        //    Bypass seq (debug/emergency) → no allocation, keep `env.seq` as-is (client value/0).
    let seq = if stage_bypassed(state, "seq") {
        env.seq
    } else {
        if state.pg_degraded() {
            if let Some(reason) = wal_degrade::ineligible_reason(&env, state.cfg.wal.enabled) {
                wal_degrade::reject_ineligible(state, &env, reason).await?;
                unreachable!("reject_ineligible always returns Err");
            }
        }
                //    Inside the PG breaker window skip the `conv_seq_watermark` lookup (otherwise every message waits one more pool timeout;
                //    after PG recovers, the 30s watermark task + reconcile converge the values).
        if state.pg_degraded() {
            wal_degrade::next_seq_pg_degraded(state, &env.conv_id).await?
        } else {
            crate::routing::seq::next_seq(state, &env.conv_id).await?
        }
    };
    env.seq = seq;

        // 6) persist: payload inlined (≤1MB); large objects already landed in MinIO via /v1/uploads and carry payload_ref.
        //    PG not writable: small messages are accepted after appending to the local WAL (fsync); large messages/large objects fail explicitly
        //    (no caching, no silent drop). The WAL only fills in persistence; replay does not re-run routing/receipts (② §4.8).
        //    Bypass persist (debug/emergency) → no PG/WAL write and no "in" metric; the later route stage still runs the original path.
    let mut wal_degraded = false;
    if !stage_bypassed(state, "persist") {
        let expires_at = if env.ttl_seconds == 0 {
            None
        } else {
            Some(Utc::now() + Duration::seconds(env.ttl_seconds as i64))
        };
        let persist =
            wal_degrade::persist_with_wal_fallback(state, &env, sender, seq, expires_at).await?;
        wal_degraded = persist.wal_degraded();
        if let Some(outcome) = persist.insert_outcome() {
            if outcome.duplicate {
                                // Cold-layer unique-constraint hit: concurrent/hot-layer-loss scenario (§17.5)
                dedup::record_pg_hit(state, true);
                return Ok(IngestOutcome {
                    id: env.id,
                    conv_id: env.conv_id,
                    seq,
                    state: DeliveryState::Delivered,
                    recipients: Vec::new(),
                    duplicate: true,
                });
            }
        }

        state
            .metrics
            .msgs_total
            .with_label_values(&[
                "in",
                &env.r#type,
                if wal_degraded { "wal" } else { "persisted" },
            ])
            .inc();
    }

        // 7) route: local direct delivery / cross-node / offline enqueue (§17.4).
        //    During WAL degradation the message is already accepted (fsync in WAL), so a routing failure only degrades to persisted and never rolls back into 500;
        //    replay only fills in PG persistence and never re-routes.
        //    Bypass route (debug/emergency) → no delivery, no recipients, accepted state degraded to persisted.
    let routed = if stage_bypassed(state, "route") {
        policy::RouteOutcome {
            state: DeliveryState::Persisted,
            recipients: Vec::new(),
        }
    } else {
        match policy::route_and_deliver(state, &env, sender, seq).await {
            Ok(routed) => routed,
            Err(e) if wal_degraded => {
                tracing::warn!(
                    error = %e,
                    id = %env.id,
                    "route failed in wal-degraded mode; message accepted as persisted (will be replayed)"
                );
                policy::RouteOutcome {
                    state: DeliveryState::Persisted,
                    recipients: Vec::new(),
                }
            }
            Err(e) => return Err(e),
        }
    };

        // 8) Sender receipt state (`sent → routed|persisted`, §4.1 state machine)
    let _ = sender_device;
    state
        .metrics
        .msgs_total
        .with_label_values(&["out", &env.r#type, routed.state.as_str()])
        .inc();

        // OTel (E22): the ingest exit records seq / delivery.state (success path; on error/duplicate early return
        // the guard's Drop ends the span, without changing error semantics).
    crate::observe::otel::finish_ingest(__otel_ingest, seq, routed.state.as_str(), false);

    Ok(IngestOutcome {
        id: env.id,
        conv_id: env.conv_id,
        seq,
        state: routed.state,
        recipients: routed.recipients,
        duplicate: false,
    })
}

/// Whether a stage is bypassed by `[pipeline] bypass` (E31 / ② §2.2).
///
/// When bypassed, **each stage entry** emits `lattice_pipeline_bypass_total{stage}` (E2E asserts "only that stage was bypassed")
/// and logs a WARN (a debug/emergency switch; this log should not appear in normal production).
fn stage_bypassed(state: &AppState, stage: &'static str) -> bool {
    if state.cfg.pipeline.is_bypassed(stage) {
        state
            .metrics
            .pipeline_bypass_total
            .with_label_values(&[stage])
            .inc();
        tracing::warn!(
            stage,
            "pipeline stage bypassed by [pipeline] bypass (debug/emergency only)"
        );
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_shape() {
        let o = IngestOutcome {
            id: "01J".into(),
            conv_id: "01H".into(),
            seq: 3,
            state: DeliveryState::Routed,
            recipients: vec![],
            duplicate: false,
        };
        assert_eq!(o.state.as_str(), "routed");
        assert_eq!(o.seq, 3);
    }

    #[test]
    fn every_declared_stage_is_checked_by_ingest_source() {
                // Static drift guard: for every stage declared in `PIPELINE_STAGES`, ingest must call
                // `stage_bypassed(state, "<stage>")` at the entry (changing the allowed set but forgetting the check = config silently ineffective).
        let src = include_str!("mod.rs");
        for stage in crate::config::PIPELINE_STAGES {
            assert!(
                src.contains(&format!("stage_bypassed(state, \"{stage}\")")),
                                "ingest is missing the bypass check for stage {stage}"
            );
        }
    }
}
