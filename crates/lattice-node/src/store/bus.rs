//! Bus abstraction (② §1 `store/bus.rs`, ⑥ §5).
//!
//! Two implementations; switching swaps only this trait's implementation, invisible to upper layers (`routing/`):
//! - [`RedisBus`]: Redis PubSub (`route.{node}` / `topic.{t}` / `lattice:online`),
//!   i.e. the ⑥ §5 degradation path and ② §4.8 `bus.fallback = "redis-pubsub"`;
//! - [`crate::store::nats::NatsBus`]: NATS JetStream (`LATTICE_ROUTE`/`LATTICE_BROADCAST`
//!   and other Streams, durable push consumer + explicit ack per node), P3 milestone (② §11).
//!
//! Subscription semantics (identical on both paths): the handler is invoked in a background task, and callbacks are **synchronous**, so implementations
//! must not block inside the handler; delivery backpressure is handled by `Hub::try_send` with frame drops + metrics (⑤ §9.5).
//!
//! Online events (`lattice:online`) remain Redis PubSub per ⑥ §3.1: in NATS mode `NatsBus`
//! **delegates** to RedisBus (see the boundary note at the top of `store/nats.rs`) and does not use JetStream.
//!
//! ## Audit stream (② §4.8 / ⑥ §5.2, `LATTICE_AUDIT` / `audit.log`)
//!
//! [`AuditEvent`] is the **wire contract** shared by the audit writer (`audit_emit` in `routing/audit.rs`) and the audit consumer
//! (NATS durable consumer → `audit_log`). Semantics:
//! - `publish_audit`: publishing succeeds only after **JetStream publish + ack**; on failure the write entry
//!   degrades to **direct synchronous PG write** (at-least-once, no loss). Redis PubSub has no persistence/no ack and
//!   does not support the audit stream (the write entry writes PG directly).
//! - `subscribe_audit`: NATS only (durable consumer + explicit ack per node). The consumer
//!   ack/nack/terminates per [`AuditDisposition`]; persistence idempotency is guaranteed by the consumer (PG `on conflict`).
//!
//! ## Media recording stream (⑥ §5.2 `LATTICE_MEDIA` / `media.record.{stream_id}`, PL-13 13.6)
//!
//! [`MediaRecordMsg`] is the **wire contract** shared by the recording producer (WS tunnel `stream-data` tee, `routing/media.rs` background task)
//! and the recording consumer (`routing/media_record.rs`: durable consumer → `[4B len][body]` segment →
//! MinIO). Semantics:
//! - `publish_media`: publishing succeeds only after NATS JetStream publish **+ ack**; on failure/unavailability the
//!   producer **degrades to writing object storage directly** (no dropped frames). Redis PubSub has no persistence/no ack and does not support the recording stream:
//!   the producer goes straight to the local direct-write path (no publish, no error spam).
//! - `subscribe_media`: NATS only (durable pull consumer `media-record-{node_id}` +
//!   explicit ack per node). Messages reach the consumer via [`MediaDelivery`], and the consumer calls
//!   [`MediaDelivery::ack`] **only after a successful write**; failures keep the buffer for retry, and exhausted retries terminate (DLQ = ERROR log + metric).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use futures::future::BoxFuture;

use crate::config::BusCfg;
use crate::error::Result;
use crate::store::redis::Redis;

/// Cross-node delivery envelope (serialized onto the bus; payload is not parsed).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteEnvelope {
    pub target_user: String,
    pub target_device: String,
    pub env_id: String,
    pub conv_id: String,
    pub seq: u64,
    pub frame_cmd: u8,
    pub body_b64: String,
}

/// Audit event envelope: the JSON contract of `audit.log` (one-to-one with `audit_log` columns).
///
/// The idempotency key is **`(id, created_at)`**: `audit_log` is a weekly-partitioned table with primary key
/// `(id, created_at)` (a partitioned-table limitation, ⑥ §2.3: a unique constraint on `id` alone is impossible), so the consumer
/// persists with `insert ... overriding system value ... on conflict do nothing`; the `id` and `created_at` of one event
/// are generated **once at the write entry and reused across retries/replays**, so the same `(id, created_at)`
/// means the same audit row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    /// Audit row id: written to `audit_log.id` (bigint, timestamp + in-process sequence, see `routing/audit.rs`).
    pub id: i64,
    /// Event time (part of the idempotency key; retries/replays must reuse the original value).
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Actor user id; may be empty for system events.
    #[serde(default)]
    pub actor: Option<String>,
    /// Action name (e.g. `user.create` / `role.change` / `queue_purge`).
    pub action: String,
    /// Operation target (user id / node id / resource name, etc.).
    #[serde(default)]
    pub target: Option<String>,
    /// Detail for the trail (JSON object). **Never embed large payloads** (observability constraint, ② §8.2).
    #[serde(default = "empty_detail")]
    pub detail: serde_json::Value,
    /// Source IP (may be empty; written to `audit_log.ip inet`; invalid values are dropped at the write entry).
    #[serde(default)]
    pub ip: Option<String>,
}

fn empty_detail() -> serde_json::Value {
    serde_json::json!({})
}

impl AuditEvent {
    /// Wire contract validation: the consumer DLQs malformed events immediately (instead of retrying forever).
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.id <= 0 {
            return Err("audit id must be positive".into());
        }
        if self.action.trim().is_empty() {
            return Err("audit action is empty".into());
        }
        if !self.detail.is_object() {
            return Err("audit detail must be a JSON object".into());
        }
        Ok(())
    }
}

/// One audit delivery (raw message seen by the consumer + JetStream delivery metadata).
#[derive(Debug, Clone)]
pub struct AuditDelivery {
    /// Raw JSON bytes (parse/validation failures are counted as DLQ by the consumer, not here).
    pub payload: Vec<u8>,
    /// Delivery attempt number (1-based; used for max_deliver → DLQ decisions).
    pub delivered: i64,
    /// How many messages the server believes this consumer still has undelivered (approximate lag; the consumer refreshes its gauge from it).
    pub pending: u64,
}

/// The consumer's disposition for one audit message (the bus implementation acks/naks/terms accordingly; it knows nothing about PG/metrics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditDisposition {
    /// Persisted (or idempotent duplicate) → ack.
    Ack,
    /// Retryable failure (PG briefly unavailable) → nack with delayed redelivery.
    Retry,
    /// Unrecoverable (malformed message / retries exhausted) → terminate, count DLQ, no more redelivery.
    Drop,
}

/// Audit consumption callback: returns the disposition. `BoxFuture` allows holding it across awaits in async traits/tasks.
pub type AuditHandler =
    Arc<dyn Fn(AuditDelivery) -> BoxFuture<'static, AuditDisposition> + Send + Sync>;

// ---------------------------------------------------------------------------
// Media recording stream wire contract (LATTICE_MEDIA / media.record.{stream_id})
// ---------------------------------------------------------------------------

/// Hard cap on a single recording frame body (matches the 64KiB WS tunnel `stream-data`, ⑤ §9.3 / design §17.10).
pub const MEDIA_RECORD_BODY_MAX: usize = 64 * 1024;
/// `stream_id` length cap (same conventions as `STREAM_ID_MAX` in `routing/media.rs`).
pub const MEDIA_RECORD_STREAM_ID_MAX: usize = 64;
/// `node_id` length cap (used by object keys / consumer names, preventing oversized names).
pub const MEDIA_RECORD_NODE_ID_MAX: usize = 128;

/// Media recording bus message (`media.record.{stream_id}`, ⑥ §5.2 `LATTICE_MEDIA`).
///
/// The wire contract is JSON (E2E asserts directly on this shape):
/// ```json
/// {"node_id":"node-a","stream_id":"s-1","seq":1766000000123456,
///  "body_b64":"<base64([1B ver][1B flags][2B id_len][stream_id][payload])>",
///  "ts":1766000000000,"final":false}
/// ```
/// - `node_id`: the ingress node that produced the frame. The consumer **processes only messages with `node_id == this node`**;
///   messages from other nodes/duplicates are acked and dropped (each node's durable consumer sees everything but persists only its own ingress frames);
/// - `stream_id`: the WS tunnel `stream_id` (the subject's trailing token must match the field);
/// - `seq`: a **monotonically increasing per-stream** sequence assigned by the producer (millisecond timestamp high bits + in-process sequence, no rollback across restarts).
///   The consumer uses it for two things: ① idempotency (`seq <= watermark` means duplicate delivery; drop and ack, producing no duplicate object);
///   ② object key (the segment's first `seq` determines the key, and segment boundaries depend only on frame ordering, so replay produces **the same object**);
/// - `body_b64`: base64 of the raw `stream-data` body (including the `[ver][flags][id_len][stream_id]` header;
///   the consumer does not decode the payload, only persisting segments as `[4B BE len][body]`);
/// - `ts`: frame timestamp on the producer side (unix ms; observability/troubleshooting only, not part of idempotency);
/// - `final`: control message (triggered by `stream-sig bye`). `body_b64` is empty and the consumer must immediately flush
///   the stream's incomplete segment; for normal frames this field is `false` (`serde(default)`, external producers may omit it).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MediaRecordMsg {
    pub node_id: String,
    pub stream_id: String,
    pub seq: u64,
    pub body_b64: String,
    pub ts: i64,
    #[serde(default, rename = "final", skip_serializing_if = "is_false")]
    pub last: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl MediaRecordMsg {
    /// Data frame message (`body` is the raw `stream-data` body, including the stream_id header).
    pub fn data(node_id: &str, stream_id: &str, seq: u64, body: &[u8], ts: i64) -> Self {
        Self {
            node_id: node_id.to_string(),
            stream_id: stream_id.to_string(),
            seq,
            body_b64: base64::engine::general_purpose::STANDARD.encode(body),
            ts,
            last: false,
        }
    }

    /// Finalize control message triggered by `bye` (`body_b64` empty).
    pub fn finalize(node_id: &str, stream_id: &str, seq: u64, ts: i64) -> Self {
        Self {
            node_id: node_id.to_string(),
            stream_id: stream_id.to_string(),
            seq,
            body_b64: String::new(),
            ts,
            last: true,
        }
    }

    /// Decode the frame body (base64 + 64KiB cap). `final` control messages return an empty Vec.
    pub fn frame_body(&self) -> std::result::Result<Vec<u8>, String> {
        if self.body_b64.is_empty() {
            return Ok(Vec::new());
        }
        let body = base64::engine::general_purpose::STANDARD
            .decode(self.body_b64.as_bytes())
            .map_err(|e| format!("bad body_b64: {e}"))?;
        if body.len() > MEDIA_RECORD_BODY_MAX {
            return Err(format!(
                "frame body too large: {} > {MEDIA_RECORD_BODY_MAX}",
                body.len()
            ));
        }
        Ok(body)
    }

    /// Wire contract validation: the consumer terminates malformed messages immediately (DLQ) instead of retrying forever.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.node_id.is_empty() || self.node_id.len() > MEDIA_RECORD_NODE_ID_MAX {
            return Err("node_id length out of range".into());
        }
        if !self
            .node_id
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'/' && b != b'*' && b != b'>')
        {
            return Err("node_id has invalid characters".into());
        }
        if self.stream_id.is_empty() || self.stream_id.len() > MEDIA_RECORD_STREAM_ID_MAX {
            return Err("stream_id length out of range".into());
        }
        if !self
            .stream_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        {
            return Err("stream_id has invalid characters".into());
        }
        if self.last {
            // final control messages must not carry a body (avoids being persisted again as a data frame).
            if !self.body_b64.is_empty() {
                return Err("final media record message must not carry body_b64".into());
            }
            return Ok(());
        }
        if self.seq == 0 {
            return Err("data frame seq must be positive".into());
        }
        if self.frame_body()?.is_empty() {
            return Err("data frame body is empty".into());
        }
        Ok(())
    }
}

/// Ack control handle for the media recording consumer (the bus implementation provides ack/nak/term; the consumer knows nothing about NATS types).
///
/// Design: the recording consumer acks **only after a successful write**, so it needs a "take message, ack later" handle;
/// `MediaDelivery` is buffered in segments by the consumer, and each is acked once its flush succeeds.
#[async_trait]
pub trait MediaAck: Send {
    /// Confirm after a successful write/duplicate drop.
    async fn ack(&mut self) -> Result<()>;
    /// Retryable failure (object storage briefly unavailable) → delayed redelivery.
    async fn nak(&mut self, delay: Duration) -> Result<()>;
    /// Unrecoverable/retries exhausted → terminate (no redelivery, count DLQ).
    async fn term(&mut self) -> Result<()>;
}

/// One media recording delivery (raw message seen by the consumer + JetStream delivery metadata + ack handle).
pub struct MediaDelivery {
    /// Raw JSON bytes (parse/validation failures are counted as DLQ by the consumer, not here).
    pub payload: Vec<u8>,
    /// Delivery attempt number (1-based; used for max_deliver → DLQ decisions).
    pub delivered: i64,
    /// How many messages the server believes this consumer still has undelivered (approximate lag; the consumer refreshes its gauge from it).
    pub pending: u64,
    /// Ack control handle; `None` = backend has no ack semantics (currently only NATS produces recording deliveries).
    ack: Option<Box<dyn MediaAck>>,
}

impl MediaDelivery {
    pub fn new(
        payload: Vec<u8>,
        delivered: i64,
        pending: u64,
        ack: Option<Box<dyn MediaAck>>,
    ) -> Self {
        Self {
            payload,
            delivered,
            pending,
            ack,
        }
    }

    /// Whether ack semantics exist (on backends without ack, all consumer ack calls are no-ops).
    pub fn has_ack(&self) -> bool {
        self.ack.is_some()
    }

    pub async fn ack(&mut self) -> Result<()> {
        match self.ack.as_mut() {
            Some(ack) => ack.ack().await,
            None => Ok(()),
        }
    }

    pub async fn nak(&mut self, delay: Duration) -> Result<()> {
        match self.ack.as_mut() {
            Some(ack) => ack.nak(delay).await,
            None => Ok(()),
        }
    }

    pub async fn term(&mut self) -> Result<()> {
        match self.ack.as_mut() {
            Some(ack) => ack.term().await,
            None => Ok(()),
        }
    }
}

/// Media recording subscription handle: `rx` is the bus delivery end; `sub` keeps the underlying subscription task alive (dropping it cancels).
pub struct MediaSubscription {
    pub rx: tokio::sync::mpsc::Receiver<MediaDelivery>,
    pub sub: Box<dyn BusSub>,
}

/// Route subscription callback: the received envelope is already deserialized.
///
/// `true` means "this node handed the frame to a local connection via the hub"; `false` means the target device is not on this node
/// (or the local queue is full). Backends with ack semantics (NATS JetStream) ack/delay-redeliver accordingly;
/// backends without ack (Redis PubSub / core NATS) ignore the return value.
pub type RouteHandler = Arc<dyn Fn(RouteEnvelope) -> bool + Send + Sync>;

/// Online subscription callback: `(user_id, device_id)`.
pub type OnlineHandler = Arc<dyn Fn(String, String) + Send + Sync>;

/// Bus backend type (used to choose the cross-node topic fan-out path, see `routing/topic.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusKind {
    /// Redis PubSub degradation path.
    RedisPubSub,
    /// NATS JetStream (P3).
    Nats,
}

impl BusKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BusKind::RedisPubSub => "redis-pubsub",
            BusKind::Nats => "nats",
        }
    }
}

/// [`BusCfg::kind`] → actual backend. Unknown values fall back to Redis with a warning (② §4.8 degradation matrix).
pub fn select_kind(kind: &str) -> BusKind {
    match kind.trim().to_ascii_lowercase().as_str() {
        "nats" => BusKind::Nats,
        "" | "redis" | "redis-pubsub" => BusKind::RedisPubSub,
        other => {
            tracing::warn!(kind = other, "unknown [bus] kind, using redis-pubsub");
            BusKind::RedisPubSub
        }
    }
}

/// Subscription handle (RAII).
///
/// The subscription is valid while the handle lives; `drop`/`close` cancels on a best-effort basis. The default `close` is a no-op:
/// the Redis PubSub subscription task is spawned inside `Redis::subscribe` and shares the process lifetime
/// (the node needs no separate unsubscribe at runtime, ② §7.2); the NATS implementation uses JetStream subscription/task handles
/// for true cancellation.
pub trait BusSub: Send + Sync {
    fn close(&self) {}
}

#[async_trait]
pub trait Bus: Send + Sync {
    /// Backend type (`routing/topic.rs` chooses the broadcast path from it).
    fn kind(&self) -> BusKind;

    /// Runtime backend health (used by `/v1/ready` `deps.bus`).
    ///
    /// Defaults to true: Redis PubSub is judged separately by `deps.redis`; NATS overrides it with the real connection state,
    /// avoiding a stale `bus=ok` after NATS disconnects (E20-G1 / chaos matrix).
    fn healthy(&self) -> bool {
        true
    }

    /// Broadcast to a node's `route.{node}` channel (point-to-point delivery).
    async fn publish_route(&self, node_id: &str, env: &RouteEnvelope) -> Result<()>;

    /// Broadcast topic fan-out.
    async fn publish_topic(&self, topic: &str, env: &RouteEnvelope) -> Result<()>;

    /// Publish a device online event (drives redelivery, `lattice:online`).
    async fn publish_online(&self, user: &str, device: &str) -> Result<()>;

    /// Subscribe to this node's route channel.
    async fn subscribe_route(
        &self,
        node_id: &str,
        handler: RouteHandler,
    ) -> Result<Box<dyn BusSub>>;

    /// Subscribe to device online events.
    async fn subscribe_online(&self, handler: OnlineHandler) -> Result<Box<dyn BusSub>>;

    /// Subscribe to topic broadcast fan-in (each node sees everything; non-target nodes simply have no such device in the local hub).
    ///
    /// Not implemented by the Redis degradation path: cross-node topics still use point-to-point `route.{node}` (preserving existing behavior,
    /// see `routing/topic.rs`), so Redis mode semantics match P2 exactly.
    async fn subscribe_topic(
        &self,
        _node_id: &str,
        _handler: RouteHandler,
    ) -> Result<Box<dyn BusSub>> {
        Err(crate::error::internal(
            "topic broadcast subscription is only available on the nats bus",
        ))
    }

    /// Publish an audit event to the durable audit stream (`LATTICE_AUDIT` / `audit.log`).
    ///
    /// Returns `Ok` only after NATS JetStream **publish + ack** succeeds; the default implementation returns `Err`:
    /// Redis PubSub has no persistence/no ack, so audits cannot go through it (② §4.8 degradation matrix: in Redis mode
    /// the write entry `routing::audit::audit_emit` **writes PG synchronously and directly**, guaranteeing no loss).
    async fn publish_audit(&self, _event: &AuditEvent) -> Result<()> {
        Err(crate::error::internal(
            "audit stream publish is only available on the nats bus",
        ))
    }

    /// Subscribe to the durable audit stream: NATS only (one durable consumer per node, explicit ack).
    ///
    /// `max_deliver`/`ack_wait` are the consumer's JetStream configuration; `retry_delay` is the NAK delay when the consumer
    /// returns [`AuditDisposition::Retry`]. The default implementation returns `Err`; the caller
    /// (`routing/audit.rs`) records "audit consumer unavailable, write entry writes PG directly" accordingly.
    async fn subscribe_audit(
        &self,
        _node_id: &str,
        _max_deliver: i64,
        _ack_wait: Duration,
        _retry_delay: Duration,
        _handler: AuditHandler,
    ) -> Result<Box<dyn BusSub>> {
        Err(crate::error::internal(
            "audit stream consumer is only available on the nats bus",
        ))
    }

    /// Publish one media recording frame/control message to `media.record.{stream_id}` (`LATTICE_MEDIA`).
    ///
    /// Returns `Ok` only after NATS JetStream **publish + ack** succeeds; the default implementation returns `Err`:
    /// Redis PubSub has no persistence/no ack, so recording cannot go through it — the producer (`routing/media.rs`)
    /// accordingly **degrades to writing object storage directly** (also used when NATS publish fails, to keep "no dropped frames").
    async fn publish_media(&self, _msg: &MediaRecordMsg) -> Result<()> {
        Err(crate::error::internal(
            "media record stream publish is only available on the nats bus",
        ))
    }

    /// Subscribe to the media recording stream: NATS only (durable pull consumer `media-record-{node_id}` per node,
    /// filter `media.record.>`, explicit ack). The default implementation returns `Err`, and the caller
    /// (`routing/media_record.rs`) does not start a consumer (the producer already writes object storage directly).
    ///
    /// The returned delivery handle **must be acked by the consumer after a successful write**; messages not acked within `ack_wait` are
    /// redelivered by the server (at-least-once), with idempotency guaranteed by the consumer per `(node_id, stream_id, seq)`.
    async fn subscribe_media(
        &self,
        _node_id: &str,
        _ack_wait: Duration,
        _max_deliver: i64,
        _retry_delay: Duration,
    ) -> Result<MediaSubscription> {
        Err(crate::error::internal(
            "media record stream consumer is only available on the nats bus",
        ))
    }
}

// ---------------------------------------------------------------------------
// Redis PubSub (degradation path)
// ---------------------------------------------------------------------------

pub struct RedisBus {
    redis: Redis,
}

/// Redis subscription handle: the underlying task is held by `Redis::subscribe`; this handle is a placeholder (close is a no-op).
struct RedisBusSub;

impl BusSub for RedisBusSub {}

impl RedisBus {
    pub fn new(redis: Redis) -> Self {
        RedisBus { redis }
    }

    pub fn channel_topic(topic: &str) -> String {
        format!("topic.{topic}")
    }

    /// `lattice:online` payload `{user, device}` (NATS mode delegates to this implementation; contract unchanged).
    fn online_payload(user: &str, device: &str) -> String {
        serde_json::json!({ "user": user, "device": device }).to_string()
    }
}

#[async_trait]
impl Bus for RedisBus {
    fn kind(&self) -> BusKind {
        BusKind::RedisPubSub
    }

    async fn publish_route(&self, node_id: &str, env: &RouteEnvelope) -> Result<()> {
        let payload = serde_json::to_string(env)
            .map_err(|e| crate::error::internal(format!("route encode failed: {e}")))?;
        self.redis
            .publish(&lattice_core::keys::channel_route(node_id), &payload)
            .await
    }

    async fn publish_topic(&self, topic: &str, env: &RouteEnvelope) -> Result<()> {
        let payload = serde_json::to_string(env)
            .map_err(|e| crate::error::internal(format!("topic encode failed: {e}")))?;
        self.redis
            .publish(&Self::channel_topic(topic), &payload)
            .await
    }

    async fn publish_online(&self, user: &str, device: &str) -> Result<()> {
        self.redis
            .publish(
                &lattice_core::keys::channel_online(),
                &Self::online_payload(user, device),
            )
            .await
    }

    async fn subscribe_route(
        &self,
        node_id: &str,
        handler: RouteHandler,
    ) -> Result<Box<dyn BusSub>> {
        // Subscription failures are handled by the caller (crossnode: warn only; the node can still deliver to local connections).
        self.redis
            .subscribe(vec![lattice_core::keys::channel_route(node_id)], move |_ch, payload| {
                match serde_json::from_str::<RouteEnvelope>(&payload) {
                    // Redis PubSub has no ack semantics: the delivery result is only used for backpressure metrics (handled inside the handler).
                    Ok(env) => {
                        handler(env);
                    }
                    Err(e) => tracing::warn!(error = %e, "invalid route payload"),
                }
            })
            .await?;
        Ok(Box::new(RedisBusSub))
    }

    async fn subscribe_online(&self, handler: OnlineHandler) -> Result<Box<dyn BusSub>> {
        self.redis
            .subscribe(vec![lattice_core::keys::channel_online()], move |_ch, payload| {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) else {
                    return;
                };
                let user = v.get("user").and_then(|x| x.as_str()).unwrap_or_default();
                let device = v.get("device").and_then(|x| x.as_str()).unwrap_or_default();
                if user.is_empty() || device.is_empty() {
                    return;
                }
                handler(user.to_string(), device.to_string());
            })
            .await?;
        Ok(Box::new(RedisBusSub))
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Build the bus from config: `kind = "nats"` connects NATS (connection/JetStream init failure → `Err`),
/// any other value uses Redis PubSub.
///
/// On failure `node.rs` falls back to RedisBus per the degradation matrix and warns (② §4.8) — this function does not silently degrade,
/// otherwise startup logs could not explain "configured nats but actually using Redis".
pub async fn build(cfg: &BusCfg, redis: Redis) -> Result<Arc<dyn Bus>> {
    match select_kind(&cfg.kind) {
        BusKind::Nats => {
            let bus = crate::store::nats::NatsBus::connect(cfg, redis).await?;
            Ok(Arc::new(bus))
        }
        BusKind::RedisPubSub => Ok(Arc::new(RedisBus::new(redis))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_envelope_roundtrip() {
        let env = RouteEnvelope {
            target_user: "01JUSER".into(),
            target_device: "dev-1".into(),
            env_id: "01JMSG".into(),
            conv_id: "01JCONV".into(),
            seq: 42,
            frame_cmd: 3,
            body_b64: "AAEC".into(),
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: RouteEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back.seq, 42);
        assert_eq!(back.env_id, "01JMSG");
        assert_eq!(back.body_b64, "AAEC");
    }

    #[test]
    fn topic_channel_shape() {
        assert_eq!(RedisBus::channel_topic("release"), "topic.release");
    }

    #[test]
    fn online_payload_is_user_device_json() {
        let v: serde_json::Value =
            serde_json::from_str(&RedisBus::online_payload("u1", "d1")).unwrap();
        assert_eq!(v["user"], "u1");
        assert_eq!(v["device"], "d1");
    }

    #[test]
    fn audit_event_wire_contract_roundtrip() {
        let ev = AuditEvent {
            id: 1_792_000_000_000_123_456,
            created_at: chrono::Utc::now(),
            actor: Some("u1".into()),
            action: "user.create".into(),
            target: Some("u2".into()),
            detail: serde_json::json!({ "username": "u2", "role": "user" }),
            ip: Some("127.0.0.1".into()),
        };
        let s = serde_json::to_string(&ev).unwrap();
        // Field names are the wire contract: E2E sends JSON of this shape directly to `audit.log`, and the consumer must parse it.
        for key in [
            "\"id\"",
            "\"created_at\"",
            "\"actor\"",
            "\"action\"",
            "\"target\"",
            "\"detail\"",
            "\"ip\"",
        ] {
            assert!(s.contains(key), "missing {key} in {s}");
        }
        let back: AuditEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, ev.id);
        assert_eq!(back.created_at, ev.created_at);
        assert_eq!(back.action, "user.create");
        assert_eq!(back.detail["role"], "user");
        assert_eq!(back.ip.as_deref(), Some("127.0.0.1"));
        assert!(back.validate().is_ok());
    }

    #[test]
    fn audit_event_defaults_and_validation() {
        // Optional fields may be omitted: detail defaults to `{}`, actor/target/ip default to None (external producers may omit them).
        let ev: AuditEvent = serde_json::from_str(
            r#"{"id":42,"created_at":"2026-11-22T00:00:00Z","action":"node.start"}"#,
        )
        .unwrap();
        assert_eq!(ev.detail, serde_json::json!({}));
        assert!(ev.actor.is_none() && ev.target.is_none() && ev.ip.is_none());
        assert!(ev.validate().is_ok());

        // Malformed events must be detectable (so the consumer DLQs immediately instead of poisoning the consumer with retries).
        let mut bad = ev.clone();
        bad.id = 0;
        assert!(bad.validate().is_err());
        let mut bad = ev.clone();
        bad.action = "  ".into();
        assert!(bad.validate().is_err());
        let mut bad = ev;
        bad.detail = serde_json::json!("not-an-object");
        assert!(bad.validate().is_err());
    }

    #[test]
    fn bus_kind_selection() {
        assert_eq!(select_kind("nats"), BusKind::Nats);
        assert_eq!(select_kind(" NATS "), BusKind::Nats);
        assert_eq!(select_kind("redis-pubsub"), BusKind::RedisPubSub);
        assert_eq!(select_kind("redis"), BusKind::RedisPubSub);
        assert_eq!(select_kind(""), BusKind::RedisPubSub);
        // Unknown value → degrade to Redis (warn, no panic)
        assert_eq!(select_kind("kafka"), BusKind::RedisPubSub);
        assert_eq!(BusKind::Nats.as_str(), "nats");
        assert_eq!(BusKind::RedisPubSub.as_str(), "redis-pubsub");
    }

    // ---- Media recording stream wire contract (PL-13 13.6 / LATTICE_MEDIA)----

    fn sample_body(stream_id: &str, payload: &[u8]) -> Vec<u8> {
        let id = stream_id.as_bytes();
        let mut body = vec![1u8, 0u8, (id.len() >> 8) as u8, (id.len() & 0xff) as u8];
        body.extend_from_slice(id);
        body.extend_from_slice(payload);
        body
    }

    #[test]
    fn media_record_msg_wire_contract_roundtrip() {
        let body = sample_body("st-1", b"opus-frame");
        let msg = MediaRecordMsg::data("node-a", "st-1", 1_766_000_000_123_456, &body, 1_766_000_000_000);
        let s = serde_json::to_string(&msg).unwrap();
        // Field names are the wire contract: E2E / external producers send messages of this shape, and the consumer must parse them.
        for key in ["\"node_id\"", "\"stream_id\"", "\"seq\"", "\"body_b64\"", "\"ts\""] {
            assert!(s.contains(key), "missing {key} in {s}");
        }
        // final is an optional control field: absent on normal data frames (serde default), reducing contract noise.
        assert!(!s.contains("\"final\""));
        let back: MediaRecordMsg = serde_json::from_str(&s).unwrap();
        assert_eq!(back, msg);
        assert!(!back.last);
        assert_eq!(back.frame_body().unwrap(), body);
        assert!(back.validate().is_ok());
    }

    #[test]
    fn media_record_final_marker_is_control_message() {
        let msg = MediaRecordMsg::finalize("node-a", "st-1", 42, 1_766_000_000_000);
        assert!(msg.last);
        assert!(msg.body_b64.is_empty());
        assert!(msg.frame_body().unwrap().is_empty());
        assert!(msg.validate().is_ok());
        let s = serde_json::to_string(&msg).unwrap();
        assert!(s.contains("\"final\":true"), "got {s}");
        // External producers omitting the final field = normal data frame (backward compatible)
        let v: MediaRecordMsg = serde_json::from_str(
            r#"{"node_id":"n","stream_id":"s","seq":1,"body_b64":"AQ==","ts":0}"#,
        )
        .unwrap();
        assert!(!v.last);

        // final control messages must not carry a body (otherwise they could be persisted again as data frames).
        let mut bad = msg.clone();
        bad.body_b64 = "AQ==".into();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn media_record_msg_validation_rejects_bad_input() {
        let body = sample_body("st-1", b"x");
        let good = MediaRecordMsg::data("node-a", "st-1", 7, &body, 0);
        assert!(good.validate().is_ok());

        let mut bad = good.clone();
        bad.node_id = String::new();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.node_id = "bad node".into(); // spaces are not ascii_graphic
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.stream_id = "s 1".into();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.stream_id = String::new();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.seq = 0;
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.body_b64 = "not-base64!!".into();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.body_b64 = String::new(); // data frame body is required
        assert!(bad.validate().is_err());
        // Frames over 64KiB must be rejected (the consumer must not let one malformed message blow up memory)
        let mut huge = serde_json::json!({
            "node_id": "node-a",
            "stream_id": "st-1",
            "seq": 1,
            "body_b64": base64::engine::general_purpose::STANDARD.encode(vec![0u8; MEDIA_RECORD_BODY_MAX + 1]),
            "ts": 0
        });
        huge["final"] = serde_json::Value::Bool(false);
        let huge: MediaRecordMsg = serde_json::from_value(huge).unwrap();
        assert!(huge.validate().is_err());
    }

    #[tokio::test]
    async fn media_delivery_without_ack_is_noop() {
        // Backends without ack semantics (e.g. a future core NATS subscription): ack/nak/term must be no-ops, not panics.
        let mut d = MediaDelivery::new(vec![1, 2, 3], 1, 0, None);
        assert!(!d.has_ack());
        d.ack().await.unwrap();
        d.nak(Duration::from_millis(1)).await.unwrap();
        d.term().await.unwrap();
    }
}
