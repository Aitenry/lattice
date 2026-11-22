//! Audit stream (② §4.8 / ⑥ §5.2 / PL-11 / PL-14): unified write entry + NATS durable consumer + degradation.
//!
//! # Write path ([`audit_emit`])
//! 1. Build an [`AuditEvent`] (`id` + `created_at` are generated **once** and reused across retries/replays → idempotency key
//!    `(id, created_at)`, see the `audit_log` partitioned-table primary key);
//! 2. `bus.kind = nats`: `bus.publish_audit` → JetStream publish **awaiting ack**. Success returns immediately; the audit is later persisted
//!    to `audit_log` asynchronously by a durable consumer on this or another node (at-least-once);
//! 3. Publish failure (NATS unavailable/JetStream off) or `bus.kind = redis-pubsub`: **write PG synchronously and directly**
//!    (the degradation path, equally idempotent; duplicate consumption/retries only hit `on conflict do nothing`);
//! 4. Publish failure and direct PG write also fails: WARN + metric + return a diagnosable error. Whether the admin operation fails as a result is
//!    **consistent** with the existing `pg::audit(...)?` semantics (admin routes treat audit failure as 500 and never allow silent success).
//!
//! Why Redis mode skips publish: Redis PubSub has no persistence/no ack; even if sent it cannot uphold
//! "at-least-once", so a synchronous PG write is better (② §4.8 degradation matrix).
//!
//! # Call-site wiring (task-29)
//! `audit_emit` is the **single write entry** for admin/account/security operations and is wired at:
//! - `admin/mod.rs`: drain / queue purge / user.create / user.update / password reset /
//!   quota / role change / suspend+resume / purge / device revoke / dlq replay /
//!   plugin action / format upsert / config patch / keys rotate (jwt and unimplemented targets);
//! - `transport/http.rs`: `login` (**non-fatal**; failure only WARNs and does not affect login), self-service `self.update`,
//!   self-service `self.password_change`;
//! - `hub.rs`: client plugin center audit helper (non-fatal, failure only WARNs).
//!
//! **Deliberately kept direct `store::pg::audit` (not wired, comments at call sites)**:
//! - `pipeline/mod.rs::sender_spoof`: message ingest hot path; audit failure only WARNs, so bus round-trip latency does not
//!   enter the throughput chain;
//! - `upload_complete` / `topic_publish` in `transport/http.rs`: data-plane non-admin operations with
//!   existing non-fatal semantics, and topic publish is a message-volume hot path (avoid raising audit volume to message volume).
//!
//! # Consumption path (NATS mode, [`spawn_consumer`])
//! - Durable **pull** consumer `audit-{node_id}` (filter `audit.log`, DeliverAll, explicit
//!   ack, `max_deliver`); after a node restart it resumes from the last ack, and audits during downtime are held in the Stream;
//! - Per message: parse/validate → `insert into audit_log ... on conflict do nothing` → ack
//!   (`ok` on persistence / `duplicate` on idempotent); PG determinably unavailable → NAK delayed redelivery; malformed event →
//!   immediate DLQ; still failing after `max_deliver` attempts → DLQ (retry the persistence once in place first);
//! - DLQ = ERROR log (event id / action / actor / target only, **no detail payload**)
//!   + `lattice_audit_dlq_total`, `lattice_audit_consume_total{result=dlq|poison}`. The message is still within the Stream
//!   retention period (Limits 7d) and can be replayed manually by event id; this repo has no `audit_dlq` table
//!   (migrations are outside this round's scope), so "DLQ persisted to PG" is not implemented — logs + metrics only.
//!
//! # Boundaries (report conventions)
//! - The idempotency key is `(id, created_at)`: `audit_log` is a partitioned table with primary key `(id, created_at)`, and a unique
//!   constraint on `id` alone is impossible; the write entry ensures one event reuses the same pair. If different producers reuse the same `id` with different
//!   `created_at`, two rows are written (the contract requires producers to guarantee id uniqueness);
//! - In NATS mode, publish ack **only guarantees the event is in the Stream (7d retention)**, not that it is in PG immediately:
//!   while the consumer is down, audits are held in the Stream and backfilled after recovery; unconsumed beyond 7d they are lost (needs lag/DLQ alerting);
//! - Each node has its own durable consumer: every node consumes the full audit stream and persists idempotently (N× inserts for availability:
//!   as long as any node is running, persistence happens), and duplicate consumption creates no duplicate rows;
//! - `detail` accepts JSON objects only; **never stuff message payloads/large objects into audits**; the DLQ log has the same constraint.
//! - In NATS mode, if PG stays unavailable for long (beyond `max_deliver × retry_delay`, roughly 20s by default), the
//!   event goes to DLQ (not persisted to PG; logs + metrics only; the message is still in the Stream for 7d and can be replayed manually).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use futures::future::BoxFuture;
use serde_json::{json, Value};

use crate::error::{LatticeError, Result};
use crate::observe::Metrics;
use crate::state::AppState;
use crate::store::bus::{AuditDelivery, AuditDisposition, AuditEvent, AuditHandler, BusKind};
use crate::store::pg;

// ---------------------------------------------------------------------------
// Write entry: audit_emit
// ---------------------------------------------------------------------------

/// In-process incrementing sequence for audit ids (mixed into the low bits, see [`new_event_id`]).
static AUDIT_ID_SEQ: AtomicU64 = AtomicU64::new(0);

/// Generate an audit id (written to `audit_log.id bigint`).
///
/// Encoding: `(unix_ms & 42bit) << 21 | (process id/sequence mix & 21bit)` — positive, approximately millisecond-ordered,
/// strictly unique within a process. Audits need only uniqueness (the idempotency key also includes `created_at`), not strict cross-process monotonicity:
/// at admin audit volumes (tens of thousands/day), same-millisecond cross-process collisions are negligible, and even a collision is
/// resolved to one row by the `(id, created_at)` primary key + `on conflict do nothing` (never corrupts the table).
pub fn new_event_id() -> i64 {
    let ms = Utc::now().timestamp_millis().max(0) as u64 & ((1 << 42) - 1);
    let seq = AUDIT_ID_SEQ.fetch_add(1, Ordering::Relaxed);
    let mix = (u64::from(std::process::id()))
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(seq.wrapping_mul(0xBF58_476D_1CE4_E5B9));
    (((ms << 21) | (mix & 0x1F_FFFF)) & i64::MAX as u64) as i64
}

/// Normalize IP: invalid/empty values are stored as None (`audit_log.ip inet` rejects garbage, so one bad IP cannot
/// turn the whole audit into a DLQ).
fn sanitize_ip(ip: Option<&str>) -> Option<String> {
    ip.map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .map(|ip| ip.to_string())
}

/// Build an audit event (id/created_at are generated here once; retries must reuse the whole event).
pub fn build_event(
    actor: Option<&str>,
    action: &str,
    target: Option<&str>,
    detail: &Value,
    ip: Option<&str>,
) -> AuditEvent {
    // detail's wire contract is a JSON object (audit search queries fields); when callers occasionally pass a scalar, wrap it
    // instead of sending a non-object (the consumer would treat it as malformed → DLQ).
    let detail = if detail.is_object() {
        detail.clone()
    } else {
        json!({ "value": detail })
    };
    AuditEvent {
        id: new_event_id(),
        created_at: Utc::now(),
        actor: actor.map(str::to_string),
        action: action.to_string(),
        target: target.map(str::to_string),
        detail,
        ip: sanitize_ip(ip),
    }
}

/// **Unified audit write entry** (replaces existing `store::pg::audit(...)` call sites; same parameter shape).
///
/// Semantics:
/// - `Ok(())` = the audit is reliably placed "at least once": in NATS mode it is persisted in the Stream (the consumer will persist soon),
///   or on the degradation path it was written directly to PG;
/// - `Err(_)` = both bus and PG are unavailable → the audit cannot be written. Callers keep the existing semantics (admin routes 500);
///   **never assume the audit was recorded and continue the admin mutation**.
///
/// Compatibility: the parameter shape matches the former `crate::store::pg::audit(...)`; all admin/account call sites
/// have migrated (`crate::routing::audit::audit_emit(&st, actor, action, target, detail, ip)`,
/// where `st` is `Arc<AppState>`). Deliberately kept direct-write data-plane hot paths are described in the module docs.
pub async fn audit_emit(
    st: &Arc<AppState>,
    actor: Option<&str>,
    action: &str,
    target: Option<&str>,
    detail: &Value,
    ip: Option<&str>,
) -> Result<()> {
    let event = build_event(actor, action, target, detail, ip);
    emit_event(st, &event).await.map(|_| ())
}

/// Write an **already built** audit event (for retries/probes/replay; ensures id/created_at are not regenerated).
///
/// Returns `Ok(true)` when the "direct PG write" degradation path was used, `Ok(false)` when published to the audit stream.
pub async fn emit_event(st: &Arc<AppState>, event: &AuditEvent) -> Result<bool> {
    if let Err(reason) = event.validate() {
        return Err(audit_unavailable_error(event, &reason));
    }
    match st.bus.kind() {
        BusKind::Nats => match st.bus.publish_audit(event).await {
            Ok(()) => {
                st.metrics
                    .audit_publish_total
                    .with_label_values(&["ok"])
                    .inc();
                Ok(false)
            }
            Err(e) => {
                // Publish failure → degrade to direct PG write (no loss); metrics use fallback to distinguish "by-design direct writes".
                tracing::warn!(
                    event_id = event.id,
                    action = %event.action,
                    error = %e,
                    "audit publish failed; falling back to direct pg write"
                );
                st.metrics
                    .audit_publish_total
                    .with_label_values(&["fallback"])
                    .inc();
                direct_persist(st, event).await?;
                Ok(true)
            }
        },
        BusKind::RedisPubSub => {
            // The Redis bus has no audit stream: write PG directly by design (no publish, avoiding a WARN per call).
            st.metrics
                .audit_publish_total
                .with_label_values(&["direct"])
                .inc();
            direct_persist(st, event).await?;
            Ok(true)
        }
    }
}

/// Degraded direct PG write; on failure WARN + `publish_total{result=error}` and return a diagnosable error.
async fn direct_persist(st: &Arc<AppState>, event: &AuditEvent) -> Result<()> {
    match persist_audit(&st.db, event).await {
        Ok(_) => Ok(()),
        Err(e) => {
            st.metrics
                .audit_publish_total
                .with_label_values(&["error"])
                .inc();
            tracing::warn!(
                event_id = event.id,
                action = %event.action,
                error = %e,
                "audit write failed: bus publish unavailable and direct pg write failed"
            );
            Err(audit_unavailable_error(
                event,
                &format!("bus publish unavailable and direct pg write failed: {e}"),
            ))
        }
    }
}

/// Diagnosable error for an unwritable audit (admin routes return 500 per existing semantics, but `reason` identifies it as an audit failure).
fn audit_unavailable_error(event: &AuditEvent, reason: &str) -> LatticeError {
    crate::error::internal(format!(
        "audit write failed for action {}: {reason}",
        event.action
    ))
    .with_reason("audit_write_failed")
    .with_detail("event_id", json!(event.id))
    .with_detail("action", json!(event.action))
}

/// Idempotent persistence into `audit_log`: silently skip on `(id, created_at)` conflict.
///
/// Returns `Ok(true)` = a new row was written; `Ok(false)` = idempotent hit (already persisted).
///
/// Why `overriding system value`: `audit_log.id` is `generated always as identity`, so the consumer/publisher/degradation path
/// must override the sequence to write the same id; the id is generated at the write entry (timestamp + sequence),
/// duplicate events reuse the same id, which is what makes `on conflict do nothing` idempotent.
pub async fn persist_audit(pool: &pg::Pool, event: &AuditEvent) -> Result<bool> {
    if let Err(reason) = event.validate() {
        return Err(crate::error::internal(format!("invalid audit event: {reason}"))
            .with_reason("audit_event_invalid"));
    }
    let result = sqlx::query(
        "insert into audit_log (id, actor, action, target, detail, ip, created_at)
         overriding system value
         values ($1,$2,$3,$4,$5,$6::inet,$7)
         on conflict do nothing",
    )
    .bind(event.id)
    .bind(event.actor.as_deref())
    .bind(event.action.as_str())
    .bind(event.target.as_deref())
    .bind(&event.detail)
    .bind(event.ip.as_deref())
    .bind(event.created_at)
    .execute(pool)
    .await
    .map_err(pg::db_err)?;
    Ok(result.rows_affected() > 0)
}

// ---------------------------------------------------------------------------
// Delivery event sourcing (PL-11 11.7 / REMAINING E19)
// ---------------------------------------------------------------------------

/// Action for delivery state transition events (the only value on the audit stream `audit.log`; events go only to the audit stream and never affect delivery decisions).
///
/// # Wire contract (`AuditEvent` shell; E2E asserts directly on this shape)
/// ```json
/// {"id":1792000000000123456,"created_at":"2026-11-22T03:00:00Z","actor":null,
///  "action":"delivery.state","target":"<msg_id>",
///  "detail":{"msg_id":"<msg_id>","to_user":"<user>","to_device":"<device>",
///            "state":"acked","node_id":"node-b","source":"delivery_log",
///            "observed_at":"2026-11-22T03:00:00.123Z"},
///  "ip":null}
/// ```
/// - `state`: the **new value** written to `delivery_log.state` this time (persisted/routed/acked/dropped, etc.);
/// - The event is an **observability copy** of `delivery_log`: consumption/replay is **for audit and data sources only** and must never in turn
///   drive routing, redelivery, ACK, or pending (the authority remains `delivery_log` + Redis pending reconciliation, ⑥ §6.4);
/// - Events are retained with `LATTICE_AUDIT` (Limits 7d); the consumer is idempotent by `(id, created_at)`, so replay is safe;
/// - The Redis PubSub bus has no persistent event stream: do not collect (the data-plane hot path cannot afford an extra PG write for this, ② §8.2).
///
/// # Boundaries (in the implementation and in the report)
/// - Events are published asynchronously **after the hot path** (bounded queue + single consumer, see [`init_delivery_events`]);
///   when the queue is full, events are dropped with periodic WARN: dropped events affect audit completeness, not delivery correctness;
/// - The `record_state` upsert does not return the "old state", so events record **the new state written this time**
///   (repeated writes of the same state also produce events; consumers can fold by `(msg_id,to_device,state)` on their own);
/// - This module reads no events for any decision; `spawn_delivery_event` does exactly one non-blocking `try_send`.
pub const DELIVERY_EVENT_ACTION: &str = "delivery.state";

/// Delivery event queue capacity: enough for ~1s of message peak (NATS mode route/topic full volume); overflow drops observability events.
const DELIVERY_EVENT_QUEUE: usize = 4096;

/// One delivery event request (the hot path submits only this struct; event construction/publish happen in the background task).
#[derive(Debug, Clone)]
pub struct DeliveryEventReq {
    pub msg_id: String,
    pub to_user: String,
    pub to_device: String,
    pub state: String,
    pub node_id: String,
}

/// Background delivery event pipeline (node-level singleton).
struct DeliveryPipeline {
    tx: tokio::sync::mpsc::Sender<DeliveryEventReq>,
    dropped: AtomicU64,
}

static DELIVERY_PIPELINE: std::sync::OnceLock<DeliveryPipeline> = std::sync::OnceLock::new();

/// Start the background delivery event publish task (called once by [`spawn_consumer`] at node startup; idempotent).
///
/// Starts only for `bus.kind = nats`: Redis PubSub has no persistent event stream, and a write entry that writes events directly to PG
/// would raise audit volume to message volume (data-plane hot path, ② §8.2); in that case [`spawn_delivery_event`] is a no-op.
pub fn init_delivery_events(st: Arc<AppState>) {
    if st.bus.kind() != BusKind::Nats {
        tracing::debug!(
            bus = st.bus.kind().as_str(),
            "delivery event pipeline disabled: bus backend has no durable event stream"
        );
        return;
    }
    if DELIVERY_PIPELINE.get().is_some() {
        return;
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<DeliveryEventReq>(DELIVERY_EVENT_QUEUE);
    let pipe = DeliveryPipeline {
        tx,
        dropped: AtomicU64::new(0),
    };
    if DELIVERY_PIPELINE.set(pipe).is_err() {
        return;
    }
    tracing::info!(
        queue = DELIVERY_EVENT_QUEUE,
        action = DELIVERY_EVENT_ACTION,
        "delivery event pipeline started (delivery_log state advances → audit.log event sourcing)"
    );
    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            let event = build_delivery_event(&req);
            // Publish failure: emit_event internally degrades to a direct PG write (at-least-once); events do not affect delivery decisions, so failures only WARN.
            if let Err(e) = emit_event(&st, &event).await {
                tracing::warn!(
                    error = %e,
                    msg_id = %req.msg_id,
                    state = %req.state,
                    "delivery event emit failed (delivery path unaffected)"
                );
            }
        }
    });
}

/// Build a delivery event (id/created_at generated once; on publish failure `emit_event` degrades to a direct PG write; retries/replays reuse it).
pub fn build_delivery_event(req: &DeliveryEventReq) -> AuditEvent {
    let detail = json!({
        "msg_id": req.msg_id,
        "to_user": req.to_user,
        "to_device": req.to_device,
        "state": req.state,
        "node_id": req.node_id,
        "source": "delivery_log",
        "observed_at": Utc::now().to_rfc3339(),
    });
    build_event(
        None,
        DELIVERY_EVENT_ACTION,
        Some(req.msg_id.as_str()),
        &detail,
        None,
    )
}

/// **Hot-path entry**: record one `delivery_log` state write event (non-blocking fire-and-forget).
///
/// Call sites (`routing/online.rs::record_state` and the ACK in `transport/ws.rs`) pay only one
/// `try_send` (O(1), no await); when uninitialized (Redis bus/unit-test binaries) or the queue is full, drop silently
/// (one WARN per 1000 drops). Events go only to the audit stream and **never affect delivery decisions**.
pub fn spawn_delivery_event(
    state: &AppState,
    msg_id: &str,
    to_user: &str,
    to_device: &str,
    state_str: &str,
) {
    let Some(pipe) = DELIVERY_PIPELINE.get() else {
        return;
    };
    let req = DeliveryEventReq {
        msg_id: msg_id.to_string(),
        to_user: to_user.to_string(),
        to_device: to_device.to_string(),
        state: state_str.to_string(),
        node_id: state.node_id.clone(),
    };
    if pipe.tx.try_send(req).is_err() {
        let n = pipe.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if n == 1 || n % 1000 == 0 {
            tracing::warn!(
                dropped = n,
                "delivery event queue full; event dropped (observability only, delivery unaffected)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Consumer: NATS durable consumer → audit_log
// ---------------------------------------------------------------------------

/// Start the audit consumer (asynchronous, does not block node ready).
///
/// - `bus.kind != nats` or `[audit] consumer_enabled=false`: do not start (the write entry already writes PG directly);
/// - Consumer creation/subscription failures only WARN: in NATS mode the write entry already put audits in the Stream, and the consumer
///   backfills after recovery (inner rebuild loop) without loss.
pub fn spawn_consumer(st: Arc<AppState>) {
    // Delivery event sourcing pipeline (E19 / PL-11 11.7): starts when the NATS audit stream is reusable; no-op on the Redis bus.
    // Placed before all early returns: even if this node's audit consumer is disabled, events can still be published for other nodes to consume.
    init_delivery_events(st.clone());
    if !st.cfg.audit.consumer_enabled {
        tracing::info!("audit consumer disabled by [audit] consumer_enabled=false");
        return;
    }
    if st.bus.kind() != BusKind::Nats {
        // Redis PubSub has no persistent audit stream: the write entry audit_emit already takes the "direct PG write" degradation path.
        tracing::info!(
            bus = st.bus.kind().as_str(),
            "audit consumer not started: bus backend has no durable audit stream (audit writes are direct-to-pg)"
        );
        return;
    }

    let node_id = st.node_id.clone();
    let audit = st.cfg.audit.clone();
    let max_deliver = audit.effective_max_deliver();
    let ack_wait = audit.effective_ack_wait();
    let retry_delay = audit.effective_retry_delay();
    let metrics = st.metrics.clone();

    // Consumption callback: protocol/persistence live here; the bus implementation only acks/naks/terms.
    let handler: AuditHandler = {
        let st = st.clone();
        let metrics = metrics.clone();
        Arc::new(move |delivery: AuditDelivery| {
            let st = st.clone();
            let metrics = metrics.clone();
            Box::pin(async move { handle_delivery(&st, &metrics, delivery).await })
                as BoxFuture<'static, AuditDisposition>
        })
    };

    tokio::spawn(async move {
        match st
            .bus
            .subscribe_audit(&node_id, max_deliver, ack_wait, retry_delay, handler)
            .await
        {
            Ok(sub) => {
                tracing::info!(
                    node_id = %node_id,
                    max_deliver,
                    ack_wait_ms = ack_wait.as_millis() as u64,
                    retry_delay_ms = retry_delay.as_millis() as u64,
                    "audit consumer started (durable pull consumer → audit_log)"
                );
                // Handle alive = subscription valid; drop aborts the background consumption task (ends naturally on process exit).
                let _keep_alive = sub;
                futures::future::pending::<()>().await;
            }
            Err(e) => {
                // Deterministically unavailable (non-NATS backend/JetStream off, etc.): the write entry already writes PG directly, no retry.
                tracing::warn!(
                    node_id = %node_id,
                    error = %e,
                    "audit consumer not started; audit writes fall back to direct pg"
                );
            }
        }
    });
}

/// Disposition decision after a consumption failure (pure function, for unit-testing DLQ boundaries).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureAction {
    /// Retryable (PG determinably unavailable and delivery attempts not exhausted) → NAK delayed redelivery.
    Retry,
    /// Non-retryable/retries exhausted → DLQ (ERROR log + metric), terminate and stop redelivering.
    Dlq,
}

/// Decision: `unavailable` (PG determinably unavailable) and `delivered < max_deliver` → retry; otherwise DLQ.
///
/// Note: `delivered` is the **delivery attempt number** (1-based, from `$JS.ACK` metadata), so with
/// `max_deliver=5`, attempts 1..4 fail and retry, and the 5th failure goes to DLQ (matching the NATS server cap).
pub fn classify_failure(unavailable: bool, delivered: i64, max_deliver: i64) -> FailureAction {
    let max_deliver = max_deliver.max(1);
    if unavailable && delivered < max_deliver {
        FailureAction::Retry
    } else {
        FailureAction::Dlq
    }
}

/// Process one delivery: parse → validate → idempotent persistence → return disposition.
async fn handle_delivery(
    st: &Arc<AppState>,
    metrics: &Arc<Metrics>,
    delivery: AuditDelivery,
) -> AuditDisposition {
    // Approximate lag: server pending (how many messages this consumer still has undelivered).
    metrics.audit_consumer_lag.set(delivery.pending as i64);

    let event: AuditEvent = match serde_json::from_slice(&delivery.payload) {
        Ok(ev) => ev,
        Err(e) => {
            // A malformed message never succeeds no matter how many retries: DLQ immediately (terminate) to avoid poisoning the consumer.
            metrics
                .audit_consume_total
                .with_label_values(&["poison"])
                .inc();
            metrics.audit_dlq_total.inc();
            // Redaction: record only length and reason, never the payload.
            tracing::error!(
                delivered = delivery.delivered,
                payload_len = delivery.payload.len(),
                reason = %format!("invalid audit payload: {e}"),
                "audit dlq: undecodable payload dropped from consumer (still in LATTICE_AUDIT stream)"
            );
            return AuditDisposition::Drop;
        }
    };
    if let Err(reason) = event.validate() {
        metrics
            .audit_consume_total
            .with_label_values(&["poison"])
            .inc();
        metrics.audit_dlq_total.inc();
        tracing::error!(
            event_id = event.id,
            action = %event.action,
            delivered = delivery.delivered,
            reason = %format!("invalid audit event: {reason}"),
            "audit dlq: invalid event dropped from consumer"
        );
        return AuditDisposition::Drop;
    }

    match persist_audit(&st.db, &event).await {
        Ok(true) => {
            metrics
                .audit_consume_total
                .with_label_values(&["ok"])
                .inc();
            AuditDisposition::Ack
        }
        Ok(false) => {
            // Idempotent hit: this event was already persisted (restart replay/multi-node independent consumption both land here).
            metrics
                .audit_consume_total
                .with_label_values(&["duplicate"])
                .inc();
            tracing::debug!(
                event_id = event.id,
                action = %event.action,
                "audit consume: duplicate (already persisted)"
            );
            AuditDisposition::Ack
        }
        Err(e) => {
            let unavailable = pg::is_unavailable_err(&e);
            // After retries are exhausted, retry persistence once in place (PG may have just recovered); only then go to DLQ.
            if unavailable
                && classify_failure(unavailable, delivery.delivered, st.cfg.audit.effective_max_deliver())
                    == FailureAction::Dlq
                && persist_audit(&st.db, &event).await.is_ok()
            {
                metrics
                    .audit_consume_total
                    .with_label_values(&["ok"])
                    .inc();
                return AuditDisposition::Ack;
            }
            match classify_failure(
                unavailable,
                delivery.delivered,
                st.cfg.audit.effective_max_deliver(),
            ) {
                FailureAction::Retry => {
                    metrics
                        .audit_consume_total
                        .with_label_values(&["retry"])
                        .inc();
                    tracing::warn!(
                        event_id = event.id,
                        action = %event.action,
                        delivered = delivery.delivered,
                        error = %e,
                        "audit consume deferred: pg unavailable, nack and retry"
                    );
                    AuditDisposition::Retry
                }
                FailureAction::Dlq => {
                    metrics
                        .audit_consume_total
                        .with_label_values(&["dlq"])
                        .inc();
                    metrics.audit_dlq_total.inc();
                    // Redaction: record only id/action/actor/target, never detail (may contain business data).
                    tracing::error!(
                        event_id = event.id,
                        action = %event.action,
                        actor = event.actor.as_deref().unwrap_or(""),
                        target = event.target.as_deref().unwrap_or(""),
                        delivered = delivery.delivered,
                        error = %e,
                        "audit dlq: event not persisted (recoverable from LATTICE_AUDIT stream by event id)"
                    );
                    AuditDisposition::Drop
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// E2E/chaos self-check probe
// ---------------------------------------------------------------------------

/// When `[audit] startup_probe=true`, send one `audit.startup_probe` self-check audit through the unified write entry.
///
/// **For E2E/chaos tests only** (false by default in production, no noise in the audit table), to deterministically verify:
/// - NATS mode: `audit_emit` → `audit.log` → durable consumer → `audit_log` (full chain);
/// - Redis bus mode: `audit_emit` sees no audit stream → direct PG write (degradation path).
pub async fn emit_startup_probe(st: &Arc<AppState>) {
    if !st.cfg.audit.startup_probe {
        return;
    }
    let detail = json!({
        "probe": true,
        "node_id": st.node_id,
        "bus": st.bus.kind().as_str(),
    });
    match audit_emit(
        st,
        Some("system:audit-probe"),
        "audit.startup_probe",
        Some(&st.node_id),
        &detail,
        Some("127.0.0.1"),
    )
    .await
    {
        Ok(()) => tracing::info!(
            node_id = %st.node_id,
            bus = st.bus.kind().as_str(),
            "audit startup probe emitted"
        ),
        Err(e) => tracing::warn!(
            node_id = %st.node_id,
            error = %e,
            "audit startup probe failed (audit write path degraded)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_ids_are_positive_unique_and_time_ordered() {
        let mut ids = Vec::new();
        for _ in 0..64 {
            let id = new_event_id();
            assert!(id > 0, "audit id must be positive bigint: {id}");
            ids.push(id);
        }
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 64, "new_event_id must be unique within a process");
        // 42-bit ms + 21-bit low bits: ids are monotonically non-decreasing as time advances (low bits increment within a millisecond)
        let a = new_event_id();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = new_event_id();
        assert!(b > a, "id should be larger after milliseconds advance: a={a} b={b}");
    }

    #[test]
    fn build_event_sanitizes_ip_and_wraps_scalar_detail() {
        let ev = build_event(
            Some("u1"),
            "user.create",
            Some("u2"),
            &json!("scalar-detail"),
            Some(" 127.0.0.1 "),
        );
        assert_eq!(ev.ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(ev.detail, json!({ "value": "scalar-detail" }));
        assert!(ev.validate().is_ok());

        // Invalid/empty IP → None (one bad IP must not turn the audit into a DLQ)
        for bad in [Some("not-an-ip"), Some(""), Some("   "), None] {
            let ev = build_event(None, "x", None, &json!({}), bad);
            assert!(ev.ip.is_none(), "ip {bad:?} should be dropped");
        }
        // System events (no actor/target) are also allowed
        let ev = build_event(None, "audit.startup_probe", None, &json!({}), None);
        assert!(ev.actor.is_none() && ev.target.is_none());
    }

    #[test]
    fn failure_classification_matches_max_deliver() {
        use FailureAction::*;
        // PG determinably unavailable: attempts 1..max_deliver-1 retry, attempt max_deliver goes to DLQ
        assert_eq!(classify_failure(true, 1, 5), Retry);
        assert_eq!(classify_failure(true, 4, 5), Retry);
        assert_eq!(classify_failure(true, 5, 5), Dlq);
        assert_eq!(classify_failure(true, 9, 5), Dlq);
        // Permanent errors (constraint/format) DLQ on the first delivery, not wasting the retry budget
        assert_eq!(classify_failure(false, 1, 5), Dlq);
        // An invalid max_deliver is treated as 1 (the first failure goes to DLQ)
        assert_eq!(classify_failure(true, 1, 0), Dlq);
        assert_eq!(classify_failure(true, 0, 5), Retry);
    }

    #[test]
    fn failure_classification_never_retries_forever() {
        // For any growing `delivered`, it eventually reaches Dlq (prevents an "infinite retry" regression)
        let max = 3;
        let actions: Vec<FailureAction> = (1..=6).map(|d| classify_failure(true, d, max)).collect();
        assert_eq!(
            actions,
            vec![
                FailureAction::Retry,
                FailureAction::Retry,
                FailureAction::Dlq,
                FailureAction::Dlq,
                FailureAction::Dlq,
                FailureAction::Dlq,
            ]
        );
    }

    // ---- Delivery event sourcing (PL-11 11.7 / E19)----

    #[test]
    fn delivery_event_wire_contract() {
        let req = DeliveryEventReq {
            msg_id: "01JMSG".into(),
            to_user: "01JUSER".into(),
            to_device: "dev-1".into(),
            state: "acked".into(),
            node_id: "node-b".into(),
        };
        let ev = build_delivery_event(&req);
        assert_eq!(ev.action, DELIVERY_EVENT_ACTION);
        assert_eq!(ev.target.as_deref(), Some("01JMSG"));
        assert!(ev.validate().is_ok());
        // detail is the wire contract: E2E asserts directly on these field names (audit_log.detail JSONB).
        for key in [
            "msg_id",
            "to_user",
            "to_device",
            "state",
            "node_id",
            "source",
            "observed_at",
        ] {
            assert!(ev.detail.get(key).is_some(), "missing detail.{key}: {:?}", ev.detail);
        }
        assert_eq!(ev.detail["msg_id"], "01JMSG");
        assert_eq!(ev.detail["to_user"], "01JUSER");
        assert_eq!(ev.detail["to_device"], "dev-1");
        assert_eq!(ev.detail["state"], "acked");
        assert_eq!(ev.detail["node_id"], "node-b");
        assert_eq!(ev.detail["source"], "delivery_log");
        // Events carry no message payload (audits must not embed large payloads, ② §8.2).
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.len() < 1024, "delivery event should stay small, got {} bytes", s.len());
        assert!(!s.contains("\"payload\""), "delivery event must not carry payload: {s}");
        // Events are replayable: the idempotency key fields stay unchanged after serializing/deserializing the same event again.
        let back: AuditEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, ev.id);
        assert_eq!(back.created_at, ev.created_at);
        assert_eq!(back.action, ev.action);
    }

    #[test]
    fn delivery_event_contains_no_payload_or_ip() {
        let req = DeliveryEventReq {
            msg_id: "m1".into(),
            to_user: "u1".into(),
            to_device: "d1".into(),
            state: "persisted".into(),
            node_id: "node-a".into(),
        };
        let ev = build_delivery_event(&req);
        assert!(ev.actor.is_none(), "system delivery events have no actor");
        assert!(ev.ip.is_none(), "delivery events do not record the source IP");
        // State transition events carry no business data beyond attempts; detail must be an object (consumer validation).
        assert!(ev.detail.is_object());
    }
}
