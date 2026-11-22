//! NATS JetStream bus (P3; ② §4.8, ⑥ §5).
//!
//! # Implemented
//! - At startup, **idempotently create** 4 Streams (reuse if they exist, ⑥ §5.2):
//!   `LATTICE_ROUTE` (`route.>`, WorkQueue retention, delete on consume), `LATTICE_BROADCAST`
//!   (`topic.>`, Limits 24h), `LATTICE_AUDIT` (`audit.log`, Limits 7d),
//!   `LATTICE_MEDIA` (`media.record.>`, Limits 1h); all File storage.
//! - Publish: `publish_route` → `route.{node}`, `publish_topic` → `topic.{topic}`; uses JetStream
//!   publish and **waits for ack (2s timeout)**; on failure falls back to core NATS publish and warns.
//! - Subscribe: beyond core NATS, use **durable push consumer + explicit ack**:
//!   one durable consumer per node for route (`durable_name` includes node_id, filter `route.{self}`,
//!   fixed inbox as `deliver_subject`, `max_deliver=5`); **ack only when the local hub actually finds the target device connection**;
//!   if not found (usually right after a node restart before clients reconnect), NAK with a 1s delay, up to 5 times —
//!   this lets a restarted node resume from the last ack, **so unacked route messages from the offline period are redelivered after the client reconnects**.
//!   One durable consumer per node for topic (filter `topic.>`, DeliverAll), ack on receipt
//!   (it is normal fan-out behavior that a non-target node has no such local device).
//! - Online events (`lattice:online`) **remain Redis PubSub** per ⑥ §3.1: this implementation's
//!   `publish_online`/`subscribe_online` delegate to `RedisBus` and do not write JetStream.
//! - **Audit stream consumer (PL-11 / PL-14)**: on `LATTICE_AUDIT`/`audit.log`, one
//!   **durable pull consumer** per node (`audit-{node_id}`, filter `audit.log`, DeliverAll,
//!   explicit ack, configurable `max_deliver`); a background task keeps pulling → the consumer persists to `audit_log`;
//!   ack after successful persistence, NAK delayed redelivery when PG is briefly unavailable, terminate on malformed/exhausted retries (DLQ = ERROR log
//!   + `lattice_audit_dlq_total`). The durable name is fixed, so a restarted node resumes from the last ack.
//! - **Media recording stream (PL-13 13.6)**: on `LATTICE_MEDIA`/`media.record.>`
//!   - `publish_media`: JetStream publish **+ wait for ack** (no core NATS fallback: recording would rather
//!     degrade to direct object-storage writes than "claim publish success without reaching the Stream"); `Nats-Msg-Id =
//!     {node_id}:{seq}` lets producer retries of the same frame hit the server-side dedup window;
//!   - `subscribe_media`: a durable **pull** consumer `media-record-{node_id}` per node
//!     (filter `media.record.>`, DeliverAll, explicit ack, configurable `max_deliver`/`ack_wait`),
//!     a background task keeps pulling → [`MediaDelivery`] handed to the consumer (`routing/media_record.rs`);
//!     the consumer acks **only after the segment is successfully persisted**; unacked messages are redelivered after a restart; the durable name is fixed,
//!     so a restarted node resumes from the last ack.
//! - Connection state monitoring: async-nats reconnects automatically; this module reads `Client::connection_state()` every 5s and
//!   logs state changes (disconnect/reconnect).
//!
//! # Unimplemented boundaries (P3; do **not** claim "offline-reachable/replayable gaps" externally)
//! 1. No **gap replay** based on `delivery_log` / `topic_offsets`: messages during node downtime are redelivered by the durable consumer only while
//!    still retained in the Stream (subject to `max_age`/`max_bytes`) and not beyond `max_deliver=5`; messages outside the retention/
//!    redelivery window are **not** replayed automatically. The authority for offline redelivery remains
//!    Redis pending + `delivery_log` reconciliation (⑥ §6.4); JetStream is only the fallback for a "brief node restart".
//! 2. **A `JetStream publish` ack only means "persisted in the Stream", not "the target node will consume it"**
//!    (the node may be offline long-term, the Stream retention may expire, the consumer may hit max_deliver, or the target device may no longer be on that node).
//! 3. The broadcast durable consumer is DeliverAll with no `topic_offsets` filtering:
//!    a new node on first startup replays broadcast messages within the Stream retention (24h) — a known P3 boundary.
//! 4. `LATTICE_MEDIA` producer/consumer are wired (recording: `media.record.{stream_id}` →
//!    durable consumer `media-record-{node_id}` → `[4B len][body]` segment → MinIO);
//!    but **still no MP4/OGG muxing, no playback Envelope, no search/playback API** (the design §17.9
//!    muxing consumer and playback Envelope are still gaps, see the boundaries in `routing/media.rs` / `media_record.rs`);
//!    multiple nodes each consume everything and process only frames with `node_id==self`; no cross-node recording dedup/aggregation.
//! 5. Route ack semantics are "handed to an **online connection** in the local hub", not end-to-end device ack
//!    (device-level ack uses WS `ack` frames; unacked deliveries fall back to `delivery_log` reconciliation).
//! 6. The audit consumer's DLQ is **ERROR log + metrics only** (this repo has no `audit_dlq` table;
//!    migrations are outside this round's scope): messages remain in the Stream retention (7d) and can be replayed manually by event id.
//! 7. The media recording consumer's DLQ is likewise **ERROR log + metrics only**
//!    (`lattice_media_record_consume_total{result=dlq}`); messages remain in the Stream retention (1h) and
//!    can be replayed manually by stream/seq. `LATTICE_MEDIA` retention is 1h: frames are lost if the consumer is down for more than 1h
//!    (production should raise max_age per recording duration/throughput or create a longer-retention Stream; not done this round).

use std::sync::Mutex;
use std::time::Duration;

use async_nats::jetstream::consumer::{self, AckPolicy, DeliverPolicy};
use async_nats::jetstream::message::PublishMessage;
use async_nats::jetstream::stream::{self, RetentionPolicy, StorageType};
use async_nats::jetstream::AckKind;
use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;

use crate::config::BusCfg;
use crate::error::Result;
use crate::store::bus::{
    AuditDelivery, AuditDisposition, AuditEvent, AuditHandler, Bus, BusKind, BusSub, MediaAck,
    MediaDelivery, MediaRecordMsg, MediaSubscription, OnlineHandler, RedisBus, RouteEnvelope,
    RouteHandler,
};
use crate::store::redis::Redis;

/// ⑥ §5.2 Stream names.
pub const STREAM_ROUTE: &str = "LATTICE_ROUTE";
pub const STREAM_BROADCAST: &str = "LATTICE_BROADCAST";
pub const STREAM_AUDIT: &str = "LATTICE_AUDIT";
pub const STREAM_MEDIA: &str = "LATTICE_MEDIA";

/// ⑥ §5.1 Subjects (without the `lattice.` prefix; ⑥ is authoritative).
pub const SUBJECT_ROUTE_WILDCARD: &str = "route.>";
pub const SUBJECT_TOPIC_WILDCARD: &str = "topic.>";
pub const SUBJECT_AUDIT: &str = "audit.log";
pub const SUBJECT_MEDIA_WILDCARD: &str = "media.record.>";

/// JetStream publish ack timeout (② §4.8: bus publishes must not slow message persistence).
const PUBLISH_ACK_TIMEOUT: Duration = Duration::from_secs(2);
/// Connection timeout: failures must let `node.rs` fall back to Redis quickly instead of stalling startup.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Redelivery wait for unacked messages.
const ACK_WAIT: Duration = Duration::from_secs(30);
/// Redelivery delay when the target device is not local (gives the client time to reconnect; critical for node restarts).
const REDELIVER_DELAY: Duration = Duration::from_secs(1);
/// Redelivery cap: beyond this, reconciliation/alerting takes over (⑥ §5.2: after `max_deliver=5`, fall back to `delivery_log`).
const MAX_DELIVER: i64 = 5;
/// ROUTE Stream retention cap: ⑥ §5.2 only mandates WorkQueue retention; an extra 24h here prevents
/// route messages for decommissioned nodes from piling up indefinitely (the original P3 task required max_age=24h).
const ROUTE_MAX_AGE: Duration = Duration::from_secs(24 * 3600);
/// Rebuild interval after the audit consumer degrades (NATS reconnect/consumer deleted/subscription stream ended).
/// Messages are still in the Stream (Limits 7d); after rebuild it resumes from the durable ack position, with no loss.
const AUDIT_CONSUMER_RETRY_DELAY: Duration = Duration::from_secs(5);
/// Rebuild interval after the media recording consumer degrades (NATS reconnect/consumer deleted/subscription stream ended).
/// Messages are still in `LATTICE_MEDIA` (Limits 1h); after rebuild it resumes from the durable ack position; the producer
/// degrades to direct object-storage writes on publish failure, so the rebuild window causes no "recording loss" (only duplicate risk, covered by seq idempotency).
const MEDIA_CONSUMER_RETRY_DELAY: Duration = Duration::from_secs(5);
/// Media recording delivery channel capacity: the consumer buffers unpersisted delivery handles in segments,
/// so the channel only needs to cover the instant "consumer processes one"; leave ample margin to avoid briefly blocking the push task.
const MEDIA_DELIVERY_CHANNEL: usize = 1024;

/// Cross-node point-to-point delivery subject.
pub fn route_subject(node_id: &str) -> String {
    format!("route.{node_id}")
}

/// Topic broadcast subject.
pub fn topic_subject(topic: &str) -> String {
    format!("topic.{topic}")
}

/// Media recording subject: `media.record.{stream_id}` (⑥ §5.1 / design §17.9).
pub fn media_record_subject(stream_id: &str) -> String {
    format!("media.record.{stream_id}")
}

/// JetStream durable consumer name (includes node_id; a restarted node reuses the same consumer).
pub fn route_consumer_name(node_id: &str) -> String {
    format!("lattice-route-{}", sanitize_name(node_id))
}

pub fn broadcast_consumer_name(node_id: &str) -> String {
    format!("lattice-broadcast-{}", sanitize_name(node_id))
}

/// Media recording stream durable consumer name: `media-record-{node_id}` (task card/design conventions).
///
/// A restarted node reuses the same durable → resumes from the last ack; multiple nodes each consume the full recording stream independently,
/// and the consumer processes only messages with `node_id == self` (others are acked and dropped), so in an N-node cluster
/// every frame lands only in the ingress node's own object-storage namespace (the key includes node_id).
pub fn media_record_consumer_name(node_id: &str) -> String {
    format!("media-record-{}", sanitize_name(node_id))
}

/// Audit stream durable consumer name: `audit-{node_id}` (task card/⑥ §5.2 conventions).
///
/// A restarted node reuses the same durable → resumes from the last ack; multiple nodes each consume the full audit stream
/// independently (each node's `audit_log` writes are idempotent, so duplicates only hit `on conflict do nothing`).
pub fn audit_consumer_name(node_id: &str) -> String {
    format!("audit-{}", sanitize_name(node_id))
}

/// Delivery inbox for the push consumer (a fixed value: a restarted node still receives messages accumulated while offline).
pub fn route_deliver_subject(node_id: &str) -> String {
    format!("_INBOX.lattice.{}.route", sanitize_name(node_id))
}

pub fn broadcast_deliver_subject(node_id: &str) -> String {
    format!("_INBOX.lattice.{}.broadcast", sanitize_name(node_id))
}

/// Token sanitization for consumer names/inbox: NATS names do not allow `.`, `*`, `>`, spaces, etc.
fn sanitize_name(node_id: &str) -> String {
    node_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The four Stream definitions from ⑥ §5.2 (`ensure_streams` and unit tests share one source to avoid doc/implementation drift).
pub fn stream_specs() -> [stream::Config; 4] {
    [
        stream::Config {
            name: STREAM_ROUTE.to_string(),
            subjects: vec![SUBJECT_ROUTE_WILDCARD.to_string()],
            retention: RetentionPolicy::WorkQueue,
            storage: StorageType::File,
            max_age: ROUTE_MAX_AGE,
            description: Some("cross-node point-to-point delivery (delete on consume; durable pending is handled by Redis/PG)".into()),
            ..Default::default()
        },
        stream::Config {
            name: STREAM_BROADCAST.to_string(),
            subjects: vec![SUBJECT_TOPIC_WILDCARD.to_string()],
            retention: RetentionPolicy::Limits,
            storage: StorageType::File,
            max_age: Duration::from_secs(24 * 3600),
            description: Some("topic broadcast fan-out (Limits 24h)".into()),
            ..Default::default()
        },
        stream::Config {
            name: STREAM_AUDIT.to_string(),
            subjects: vec![SUBJECT_AUDIT.to_string()],
            retention: RetentionPolicy::Limits,
            storage: StorageType::File,
            max_age: Duration::from_secs(7 * 24 * 3600),
            description: Some("event sourcing (Limits 7d; audit consumer per node → PG audit_log)".into()),
            ..Default::default()
        },
        stream::Config {
            name: STREAM_MEDIA.to_string(),
            subjects: vec![SUBJECT_MEDIA_WILDCARD.to_string()],
            retention: RetentionPolicy::Limits,
            storage: StorageType::File,
            max_age: Duration::from_secs(3600),
            description: Some(
                "media recording side path (Limits 1h; producer media.record.* → durable consumer → MinIO)"
                    .into(),
            ),
            ..Default::default()
        },
    ]
}

/// Connect to NATS (shared by `NatsBus::connect` and unit tests, so "unreachable must fail fast with a readable error" is testable).
pub(crate) async fn connect_client(url: &str) -> Result<async_nats::Client> {
    let url = url.trim();
    if url.is_empty() {
        return Err(crate::error::internal("bus.nats_url is empty"));
    }
    match tokio::time::timeout(CONNECT_TIMEOUT, async_nats::connect(url)).await {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(e)) => Err(crate::error::internal(format!(
            "nats connect {url} failed: {e}"
        ))),
        Err(_) => Err(crate::error::internal(format!(
            "nats connect {url} timed out after {}s",
            CONNECT_TIMEOUT.as_secs()
        ))),
    }
}

/// Idempotently create Streams (reuse if they exist; creation failure means the bus is unavailable and `node.rs` degrades to Redis).
async fn ensure_streams(js: &async_nats::jetstream::Context) -> Result<()> {
    for spec in stream_specs() {
        let name = spec.name.clone();
        let subjects = spec.subjects.clone();
        let retention = spec.retention;
        match tokio::time::timeout(Duration::from_secs(10), js.get_or_create_stream(spec)).await {
            Ok(Ok(_stream)) => tracing::info!(
                stream = %name,
                subjects = ?subjects,
                retention = ?retention,
                "jetstream stream ready (created or reused)"
            ),
            Ok(Err(e)) => {
                return Err(crate::error::internal(format!(
                    "jetstream stream {name} init failed: {e} (is nats-server started with -js?)"
                )))
            }
            Err(_) => {
                return Err(crate::error::internal(format!(
                    "jetstream stream {name} init timed out"
                )))
            }
        }
    }
    Ok(())
}

/// NATS JetStream bus.
pub struct NatsBus {
    client: async_nats::Client,
    /// None when `jetstream=false`: degrades to core NATS (real-time only, no offline message retention).
    js: Option<async_nats::jetstream::Context>,
    /// For online events (⑥ §3.1) and the Redis degradation delegation.
    redis: Redis,
}

impl NatsBus {
    /// Connect to NATS and (when `jetstream=true`) idempotently create Streams.
    pub async fn connect(cfg: &BusCfg, redis: Redis) -> Result<Self> {
        let client = connect_client(&cfg.nats_url).await?;
        let js = if cfg.jetstream {
            let ctx = async_nats::jetstream::new(client.clone());
            ensure_streams(&ctx).await?;
            Some(ctx)
        } else {
            tracing::warn!(
                url = %cfg.nats_url,
                "bus.jetstream=false: core NATS only (no stream/durable consumer; offline messages are not retained)"
            );
            None
        };
        let bus = NatsBus { client, js, redis };
        bus.spawn_connection_monitor(cfg.nats_url.trim().to_string());
        tracing::info!(
            url = %cfg.nats_url,
            jetstream = cfg.jetstream,
            "nats bus connected"
        );
        Ok(bus)
    }

    /// async-nats reconnects automatically; this only logs state changes (connection degradation is observable).
    fn spawn_connection_monitor(&self, url: String) {
        let client = self.client.clone();
        let initial = client.connection_state();
        tokio::spawn(async move {
            let mut last = initial;
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let now = client.connection_state();
                if now != last {
                    match now {
                        async_nats::connection::State::Connected => {
                            tracing::info!(url = %url, "nats connection (re)connected")
                        }
                        async_nats::connection::State::Disconnected => tracing::warn!(
                            url = %url,
                            "nats connection lost; async-nats will retry (messages fall back to core publish / Redis degradation matrix ② §4.8)"
                        ),
                        async_nats::connection::State::Pending => {
                            tracing::warn!(url = %url, "nats connection pending")
                        }
                    }
                    last = now;
                }
            }
        });
    }

    /// Publish one message: JetStream publish + wait for ack (2s); on failure fall back to core NATS.
    ///
    /// A core NATS fallback is still likely to be captured by the Stream (it listens on the same subject),
    /// but **loses ack confirmation** — the failure path always warns.
    async fn publish(&self, subject: String, payload: Vec<u8>) -> Result<()> {
        if let Some(js) = self.js.clone() {
            let attempt = {
                let subject = subject.clone();
                let payload = payload.clone();
                async move {
                    let ack = js
                        .publish(subject, Bytes::from(payload))
                        .await
                        .map_err(|e| e.to_string())?;
                    ack.await.map_err(|e| e.to_string())?;
                    Ok::<(), String>(())
                }
            };
            match tokio::time::timeout(PUBLISH_ACK_TIMEOUT, attempt).await {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => tracing::warn!(
                    subject = %subject,
                    error = %e,
                    "jetstream publish/ack failed, falling back to core nats publish"
                ),
                Err(_) => tracing::warn!(
                    subject = %subject,
                    timeout_ms = PUBLISH_ACK_TIMEOUT.as_millis() as u64,
                    "jetstream publish ack timed out, falling back to core nats publish"
                ),
            }
        }
        self.client
            .publish(subject.clone(), Bytes::from(payload))
            .await
            .map_err(|e| {
                tracing::error!(subject = %subject, error = %e, "nats core publish failed");
                crate::error::internal(format!("nats publish {subject} failed: {e}"))
            })
    }

    /// Durable push consumer: after a failure/restart it resumes from the last ack (⑥ §5.2).
    ///
    /// With `require_local_delivery=true` (route consumer), ack only when the handler returns `true`;
    /// otherwise NAK with a delayed redelivery — this covers the seconds after a node restart before clients reconnect.
    #[allow(clippy::too_many_arguments)]
    async fn spawn_push_consumer(
        &self,
        js: &async_nats::jetstream::Context,
        stream_name: &str,
        consumer_name: String,
        deliver_subject: String,
        filter_subject: String,
        handler: RouteHandler,
        kind_label: &'static str,
        require_local_delivery: bool,
    ) -> Result<Box<dyn BusSub>> {
        let stream = js.get_stream(stream_name).await.map_err(|e| {
            crate::error::internal(format!(
                "jetstream stream {stream_name} unavailable: {e} (is nats-server started with -js?)"
            ))
        })?;
        let config = consumer::push::Config {
            durable_name: Some(consumer_name.clone()),
            deliver_subject: deliver_subject.clone(),
            filter_subject: filter_subject.clone(),
            ack_policy: AckPolicy::Explicit,
            ack_wait: ACK_WAIT,
            max_deliver: MAX_DELIVER,
            deliver_policy: DeliverPolicy::All,
            ..Default::default()
        };
        let consumer: consumer::PushConsumer = stream
            .get_or_create_consumer(&consumer_name, config)
            .await
            .map_err(|e| {
                crate::error::internal(format!(
                    "jetstream consumer {consumer_name} init failed: {e}"
                ))
            })?;
        let mut messages = consumer.messages().await.map_err(|e| {
            crate::error::internal(format!(
                "jetstream consumer {consumer_name} subscribe failed: {e}"
            ))
        })?;
        tracing::info!(
            stream = stream_name,
            consumer = %consumer_name,
            deliver_subject = %deliver_subject,
            filter = %filter_subject,
            "jetstream durable consumer ready"
        );
        let task = tokio::spawn(async move {
            while let Some(item) = messages.next().await {
                match item {
                    Ok(msg) => {
                        let parsed = serde_json::from_slice::<RouteEnvelope>(&msg.payload);
                        let delivered = match parsed {
                            Ok(env) => handler(env),
                            Err(e) => {
                                tracing::warn!(
                                    kind = kind_label,
                                    error = %e,
                                    "invalid route envelope on nats bus"
                                );
                                false
                            }
                        };
                        let ack = if require_local_delivery && !delivered {
                            // Target device not on this node yet: delayed redelivery (most often right after a node restart, before WS reconnects).
                            // No more redelivery after max_deliver=5; authoritative redelivery falls back to pending/delivery_log reconciliation.
                            tracing::debug!(
                                kind = kind_label,
                                "target device not connected locally, nak with delay"
                            );
                            msg.ack_with(AckKind::Nak(Some(REDELIVER_DELAY))).await
                        } else {
                            msg.ack().await
                        };
                        if let Err(e) = ack {
                            // ack failure → the server redelivers after ack_wait (at-least-once semantics).
                            tracing::warn!(kind = kind_label, error = %e, "jetstream ack failed (will redeliver)");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(kind = kind_label, error = %e, "jetstream consumer recv error")
                    }
                }
            }
            tracing::warn!(
                kind = kind_label,
                "jetstream consumer message stream ended (subscription degraded)"
            );
        });
        Ok(Box::new(NatsSub::new(task)))
    }

    /// Core NATS real-time subscription when `jetstream=false` (no persistence, offline messages are not retained).
    async fn subscribe_core(
        &self,
        subject: String,
        handler: RouteHandler,
        kind_label: &'static str,
    ) -> Result<Box<dyn BusSub>> {
        let mut sub = self.client.subscribe(subject.clone()).await.map_err(|e| {
            crate::error::internal(format!("nats subscribe {subject} failed: {e}"))
        })?;
        tracing::info!(subject = %subject, "nats core subscription ready (non-jetstream)");
        let task = tokio::spawn(async move {
            while let Some(msg) = sub.next().await {
                match serde_json::from_slice::<RouteEnvelope>(&msg.payload) {
                    // core NATS has no ack semantics: ignore the delivery result.
                    Ok(env) => {
                        handler(env);
                    }
                    Err(e) => tracing::warn!(
                        kind = kind_label,
                        error = %e,
                        "invalid route envelope on nats bus"
                    ),
                }
            }
            tracing::warn!(kind = kind_label, "nats core subscription ended");
        });
        Ok(Box::new(NatsSub::new(task)))
    }

    /// Audit-only **strict** JetStream publish: success requires a publish ack.
    ///
    /// Difference from the generic [`NatsBus::publish`]: on failure it **does not fall back to core NATS** — core publish has no
    /// ack, and claiming success would make the audit write entry skip the "direct PG write" degradation path, possibly losing audits. Audits prefer duplicates
    /// (consumer `(id, created_at)` idempotency) over loss, so only a JetStream ack counts here.
    async fn publish_audit_strict(&self, event: &AuditEvent) -> Result<()> {
        let js = self.js.clone().ok_or_else(|| {
            crate::error::internal(
                "bus.jetstream=false: audit stream is unavailable (core NATS only)",
            )
        })?;
        let payload = serde_json::to_vec(event)
            .map_err(|e| crate::error::internal(format!("audit encode failed: {e}")))?;
        // JetStream has a built-in publish dedup window keyed by Nats-Msg-Id (default 2min): retries of the same event
        // (same id) by the write entry do not leave two copies in the Stream.
        let msg_id = event.id.to_string();
        let attempt = async move {
            let ack = js
                .send_publish(
                    SUBJECT_AUDIT,
                    PublishMessage::build()
                        .payload(Bytes::from(payload))
                        .message_id(msg_id),
                )
                .await
                .map_err(|e| e.to_string())?;
            ack.await.map_err(|e| e.to_string())?;
            Ok::<(), String>(())
        };
        match tokio::time::timeout(PUBLISH_ACK_TIMEOUT, attempt).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(crate::error::internal(format!(
                "audit stream publish failed: {e}"
            ))),
            Err(_) => Err(crate::error::internal(format!(
                "audit stream publish ack timed out after {}ms",
                PUBLISH_ACK_TIMEOUT.as_millis()
            ))),
        }
    }

    /// One audit consumption round: create/reuse a durable **pull** consumer and keep pulling until the subscription stream ends/errors.
    ///
    /// Failures (consumer creation/subscription failure) are rebuilt by the outer loop of [`NatsBus::subscribe_audit`] at a fixed interval
    /// — the durable name is fixed, so after rebuild it resumes from the last ack and messages within the Stream retention (7d) are not lost.
    async fn audit_consume_round(
        js: &async_nats::jetstream::Context,
        consumer_name: &str,
        max_deliver: i64,
        ack_wait: Duration,
        retry_delay: Duration,
        handler: &AuditHandler,
    ) -> Result<()> {
        let stream = js.get_stream(STREAM_AUDIT).await.map_err(|e| {
            crate::error::internal(format!(
                "jetstream stream {STREAM_AUDIT} unavailable: {e} (is nats-server started with -js?)"
            ))
        })?;
        let config = consumer::pull::Config {
            durable_name: Some(consumer_name.to_string()),
            filter_subject: SUBJECT_AUDIT.to_string(),
            ack_policy: AckPolicy::Explicit,
            ack_wait,
            max_deliver,
            deliver_policy: DeliverPolicy::All,
            ..Default::default()
        };
        let consumer: consumer::PullConsumer = stream
            .get_or_create_consumer(consumer_name, config)
            .await
            .map_err(|e| {
                crate::error::internal(format!(
                    "jetstream audit consumer {consumer_name} init failed: {e}"
                ))
            })?;
        tracing::info!(
            stream = STREAM_AUDIT,
            consumer = %consumer_name,
            filter = SUBJECT_AUDIT,
            ack_wait_ms = ack_wait.as_millis() as u64,
            max_deliver,
            "jetstream audit durable consumer ready"
        );
        let mut messages = consumer.messages().await.map_err(|e| {
            crate::error::internal(format!(
                "jetstream audit consumer {consumer_name} subscribe failed: {e}"
            ))
        })?;
        while let Some(item) = messages.next().await {
            match item {
                Ok(msg) => {
                    let (delivered, pending) =
                        msg.info().map(|i| (i.delivered, i.pending)).unwrap_or((1, 0));
                    let disposition = handler(AuditDelivery {
                        payload: msg.payload.to_vec(),
                        delivered,
                        pending,
                    })
                    .await;
                    let acked = match disposition {
                        AuditDisposition::Ack => msg.ack().await,
                        AuditDisposition::Retry => {
                            msg.ack_with(AckKind::Nak(Some(retry_delay))).await
                        }
                        // terminate: stop redelivery without claiming success (the consumer already counted the DLQ).
                        AuditDisposition::Drop => msg.ack_with(AckKind::Term).await,
                    };
                    if let Err(e) = acked {
                        // ack failure → the server redelivers after ack_wait (at-least-once; persistence idempotency covers duplicates).
                        tracing::warn!(
                            consumer = %consumer_name,
                            error = %e,
                            "jetstream audit ack failed (will redeliver)"
                        );
                    }
                }
                Err(e) => tracing::warn!(
                    consumer = %consumer_name,
                    error = %e,
                    "jetstream audit consumer recv error"
                ),
            }
        }
        Err(crate::error::internal(format!(
            "jetstream audit consumer {consumer_name} message stream ended"
        )))
    }

    /// Media-recording-only **strict** JetStream publish: success requires a publish ack.
    ///
    /// Same as audit: **no core NATS fallback** — core publish has no ack, and claiming success would make the producer
    /// skip the "direct object-storage write" degradation path, possibly losing recording frames. Recording prefers duplicates (consumer idempotency by seq)
    /// over loss, so only a JetStream ack counts here.
    async fn publish_media_strict(&self, msg: &MediaRecordMsg) -> Result<()> {
        let js = self.js.clone().ok_or_else(|| {
            crate::error::internal(
                "bus.jetstream=false: media record stream is unavailable (core NATS only)",
            )
        })?;
        let payload = serde_json::to_vec(msg)
            .map_err(|e| crate::error::internal(format!("media record encode failed: {e}")))?;
        let subject = media_record_subject(&msg.stream_id);
        // The JetStream server dedups by Nats-Msg-Id (default 2min window): if the producer retries the same frame
        // (same node_id/seq), the Stream will not contain two copies.
        let msg_id = format!("{}:{}", sanitize_name(&msg.node_id), msg.seq);
        let attempt = async move {
            let ack = js
                .send_publish(
                    subject,
                    PublishMessage::build()
                        .payload(Bytes::from(payload))
                        .message_id(msg_id),
                )
                .await
                .map_err(|e| e.to_string())?;
            ack.await.map_err(|e| e.to_string())?;
            Ok::<(), String>(())
        };
        match tokio::time::timeout(PUBLISH_ACK_TIMEOUT, attempt).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(crate::error::internal(format!(
                "media record stream publish failed: {e}"
            ))),
            Err(_) => Err(crate::error::internal(format!(
                "media record stream publish ack timed out after {}ms",
                PUBLISH_ACK_TIMEOUT.as_millis()
            ))),
        }
    }

    /// One media recording consumption round: create/reuse a durable **pull** consumer and keep pulling deliveries until the stream ends/errors.
    ///
    /// Difference from the audit consumer: here the bus layer does **not** ack — the delivery is sent via `tx.send` together with its ack handle
    /// to the consumer (`routing/media_record.rs`), which aggregates by stream and acks only after a successful write.
    /// `tx.send` returning Err means the consumer task has exited (node draining/shutdown), so the round ends normally.
    async fn media_consume_round(
        js: &async_nats::jetstream::Context,
        consumer_name: &str,
        ack_wait: Duration,
        max_deliver: i64,
        tx: &tokio::sync::mpsc::Sender<MediaDelivery>,
    ) -> Result<()> {
        let stream = js.get_stream(STREAM_MEDIA).await.map_err(|e| {
            crate::error::internal(format!(
                "jetstream stream {STREAM_MEDIA} unavailable: {e} (is nats-server started with -js?)"
            ))
        })?;
        let config = consumer::pull::Config {
            durable_name: Some(consumer_name.to_string()),
            filter_subject: SUBJECT_MEDIA_WILDCARD.to_string(),
            ack_policy: AckPolicy::Explicit,
            ack_wait,
            max_deliver,
            deliver_policy: DeliverPolicy::All,
            ..Default::default()
        };
        let consumer: consumer::PullConsumer = stream
            .get_or_create_consumer(consumer_name, config)
            .await
            .map_err(|e| {
                crate::error::internal(format!(
                    "jetstream media record consumer {consumer_name} init failed: {e}"
                ))
            })?;
        tracing::info!(
            stream = STREAM_MEDIA,
            consumer = %consumer_name,
            filter = SUBJECT_MEDIA_WILDCARD,
            ack_wait_ms = ack_wait.as_millis() as u64,
            max_deliver,
            "jetstream media record durable consumer ready"
        );
        let mut messages = consumer.messages().await.map_err(|e| {
            crate::error::internal(format!(
                "jetstream media record consumer {consumer_name} subscribe failed: {e}"
            ))
        })?;
        while let Some(item) = messages.next().await {
            match item {
                Ok(msg) => {
                    let (delivered, pending) =
                        msg.info().map(|i| (i.delivered, i.pending)).unwrap_or((1, 0));
                    let (raw, acker) = msg.split();
                    let delivery = MediaDelivery::new(
                        raw.payload.to_vec(),
                        delivered,
                        pending,
                        Some(Box::new(NatsMediaAck(acker))),
                    );
                    if tx.send(delivery).await.is_err() {
                        // Consumer task has exited: stop pulling (messages remain in the Stream/durable and are redelivered after restart).
                        return Ok(());
                    }
                }
                Err(e) => tracing::warn!(
                    consumer = %consumer_name,
                    error = %e,
                    "jetstream media record consumer recv error"
                ),
            }
        }
        Err(crate::error::internal(format!(
            "jetstream media record consumer {consumer_name} message stream ended"
        )))
    }
}

/// NATS ack handle for a media recording delivery (split from `Acker`, decoupled from the message body, so it can be buffered across awaits).
struct NatsMediaAck(async_nats::jetstream::message::Acker);

#[async_trait]
impl MediaAck for NatsMediaAck {
    async fn ack(&mut self) -> Result<()> {
        self.0
            .ack()
            .await
            .map_err(|e| crate::error::internal(format!("media record ack failed: {e}")))
    }

    async fn nak(&mut self, delay: Duration) -> Result<()> {
        self.0
            .ack_with(AckKind::Nak(Some(delay)))
            .await
            .map_err(|e| crate::error::internal(format!("media record nak failed: {e}")))
    }

    async fn term(&mut self) -> Result<()> {
        self.0
            .ack_with(AckKind::Term)
            .await
            .map_err(|e| crate::error::internal(format!("media record term failed: {e}")))
    }
}

#[async_trait]
impl Bus for NatsBus {
    fn kind(&self) -> BusKind {
        BusKind::Nats
    }

    fn healthy(&self) -> bool {
        matches!(
            self.client.connection_state(),
            async_nats::connection::State::Connected
        )
    }

    async fn publish_route(&self, node_id: &str, env: &RouteEnvelope) -> Result<()> {
        let payload = serde_json::to_vec(env)
            .map_err(|e| crate::error::internal(format!("route encode failed: {e}")))?;
        self.publish(route_subject(node_id), payload).await
    }

    async fn publish_topic(&self, topic: &str, env: &RouteEnvelope) -> Result<()> {
        let payload = serde_json::to_vec(env)
            .map_err(|e| crate::error::internal(format!("topic encode failed: {e}")))?;
        self.publish(topic_subject(topic), payload).await
    }

    async fn publish_online(&self, user: &str, device: &str) -> Result<()> {
        // ⑥ §3.1: online events are short-lived notifications and do not use JetStream; NATS mode still uses Redis PubSub.
        RedisBus::new(self.redis.clone())
            .publish_online(user, device)
            .await
    }

    async fn subscribe_route(
        &self,
        node_id: &str,
        handler: RouteHandler,
    ) -> Result<Box<dyn BusSub>> {
        match self.js.clone() {
            Some(js) => {
                self.spawn_push_consumer(
                    &js,
                    STREAM_ROUTE,
                    route_consumer_name(node_id),
                    route_deliver_subject(node_id),
                    route_subject(node_id),
                    handler,
                    "route",
                    true,
                )
                .await
            }
            None => {
                self.subscribe_core(route_subject(node_id), handler, "route")
                    .await
            }
        }
    }

    async fn subscribe_online(&self, handler: OnlineHandler) -> Result<Box<dyn BusSub>> {
        // ⑥ §3.1: online events stay on Redis PubSub (NATS mode delegates to RedisBus).
        RedisBus::new(self.redis.clone())
            .subscribe_online(handler)
            .await
    }

    async fn subscribe_topic(
        &self,
        node_id: &str,
        handler: RouteHandler,
    ) -> Result<Box<dyn BusSub>> {
        match self.js.clone() {
            Some(js) => {
                self.spawn_push_consumer(
                    &js,
                    STREAM_BROADCAST,
                    broadcast_consumer_name(node_id),
                    broadcast_deliver_subject(node_id),
                    SUBJECT_TOPIC_WILDCARD.to_string(),
                    handler,
                    "topic",
                    false,
                )
                .await
            }
            None => {
                self.subscribe_core(SUBJECT_TOPIC_WILDCARD.to_string(), handler, "topic")
                    .await
            }
        }
    }

    async fn publish_audit(&self, event: &AuditEvent) -> Result<()> {
        self.publish_audit_strict(event).await
    }

    async fn subscribe_audit(
        &self,
        node_id: &str,
        max_deliver: i64,
        ack_wait: Duration,
        retry_delay: Duration,
        handler: AuditHandler,
    ) -> Result<Box<dyn BusSub>> {
        let js = self.js.clone().ok_or_else(|| {
            crate::error::internal(
                "bus.jetstream=false: audit stream is unavailable (core NATS only)",
            )
        })?;
        // Normalize config conventions: max_deliver at least 1; too small an ack_wait causes normal persistence to be redelivered too.
        let max_deliver = max_deliver.max(1);
        let ack_wait = ack_wait.max(Duration::from_millis(100));
        let retry_delay = retry_delay.max(Duration::from_millis(100));
        let consumer_name = audit_consumer_name(node_id);
        let task = tokio::spawn(async move {
            loop {
                // Subscription stream ended (NATS reconnect/consumer deleted) or consumer creation failed → rebuild;
                // the durable resumes from the ack position, so messages within the Stream retention are not lost.
                if let Err(e) = Self::audit_consume_round(
                    &js,
                    &consumer_name,
                    max_deliver,
                    ack_wait,
                    retry_delay,
                    &handler,
                )
                .await
                {
                    tracing::warn!(
                        consumer = %consumer_name,
                        error = %e,
                        "jetstream audit consumer degraded; recreating"
                    );
                }
                tokio::time::sleep(AUDIT_CONSUMER_RETRY_DELAY).await;
            }
        });
        Ok(Box::new(NatsSub::new(task)))
    }

    async fn publish_media(&self, msg: &MediaRecordMsg) -> Result<()> {
        self.publish_media_strict(msg).await
    }

    async fn subscribe_media(
        &self,
        node_id: &str,
        ack_wait: Duration,
        max_deliver: i64,
        _retry_delay: Duration,
    ) -> Result<MediaSubscription> {
        let js = self.js.clone().ok_or_else(|| {
            crate::error::internal(
                "bus.jetstream=false: media record stream is unavailable (core NATS only)",
            )
        })?;
        // Normalize config conventions: max_deliver at least 1; too small an ack_wait causes normal persistence to be redelivered too
        // (the consumer acks only after the segment is written, so allow for object-storage latency).
        let max_deliver = max_deliver.max(1);
        let ack_wait = ack_wait.max(Duration::from_secs(1));
        let consumer_name = media_record_consumer_name(node_id);
        let (tx, rx) = tokio::sync::mpsc::channel(MEDIA_DELIVERY_CHANNEL);
        let task = tokio::spawn(async move {
            loop {
                // Subscription stream ended (NATS reconnect/consumer deleted) or consumer creation failed → rebuild;
                // the durable resumes from the ack position, so unacked messages within the Stream retention are not lost.
                if let Err(e) = Self::media_consume_round(
                    &js,
                    &consumer_name,
                    ack_wait,
                    max_deliver,
                    &tx,
                )
                .await
                {
                    tracing::warn!(
                        consumer = %consumer_name,
                        error = %e,
                        "jetstream media record consumer degraded; recreating"
                    );
                }
                tokio::time::sleep(MEDIA_CONSUMER_RETRY_DELAY).await;
            }
        });
        Ok(MediaSubscription {
            rx,
            sub: Box::new(NatsSub::new(task)),
        })
    }
}

/// Subscription handle: abort the background task on drop/close (the NATS subscription is cancelled when the task ends).
struct NatsSub {
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl NatsSub {
    fn new(task: tokio::task::JoinHandle<()>) -> Self {
        NatsSub {
            task: Mutex::new(Some(task)),
        }
    }
}

impl BusSub for NatsSub {
    fn close(&self) {
        if let Ok(mut guard) = self.task.lock() {
            if let Some(task) = guard.take() {
                task.abort();
            }
        }
    }
}

impl Drop for NatsSub {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_nats::jetstream::stream::{RetentionPolicy, StorageType};

    /// Simple NATS subject wildcard matcher for tests (`*` one token / `>` trailing multi-token).
    fn subject_matches(pattern: &str, subject: &str) -> bool {
        let mut p = pattern.split('.');
        let mut s = subject.split('.');
        loop {
            match (p.next(), s.next()) {
                (Some(">"), _) => return true,
                (Some("*"), Some(_)) => continue,
                (Some(pt), Some(st)) if pt == st => continue,
                (None, None) => return true,
                _ => return false,
            }
        }
    }

    #[test]
    fn subject_names_match_stream_wildcards() {
        assert_eq!(route_subject("node-a"), "route.node-a");
        assert_eq!(topic_subject("release"), "topic.release");
        assert!(subject_matches(SUBJECT_ROUTE_WILDCARD, &route_subject("node-a")));
        assert!(subject_matches(SUBJECT_TOPIC_WILDCARD, &topic_subject("release")));
        assert!(!subject_matches(SUBJECT_ROUTE_WILDCARD, &topic_subject("release")));
        assert!(subject_matches(SUBJECT_MEDIA_WILDCARD, "media.record.stream-1"));
        // Media recording subject (PL-13 13.6): `media.record.{stream_id}` must be captured by LATTICE_MEDIA
        assert_eq!(media_record_subject("st-abc"), "media.record.st-abc");
        assert!(subject_matches(SUBJECT_MEDIA_WILDCARD, &media_record_subject("st-abc")));
        assert!(!subject_matches(SUBJECT_MEDIA_WILDCARD, "media.other.st-abc"));
        assert!(!subject_matches(SUBJECT_ROUTE_WILDCARD, &media_record_subject("st-abc")));
        assert_eq!(SUBJECT_AUDIT, "audit.log");
        // ⑥ §5.1: subjects have no `lattice.` prefix
        assert!(!route_subject("node-a").starts_with("lattice."));
    }

    #[test]
    fn stream_specs_follow_doc_5_2() {
        let specs = stream_specs();
        let find = |name: &str| specs.iter().find(|s| s.name == name).expect(name);

        let route = find(STREAM_ROUTE);
        assert_eq!(route.subjects, vec!["route.>".to_string()]);
        assert_eq!(route.retention, RetentionPolicy::WorkQueue);
        assert_eq!(route.storage, StorageType::File);
        // The extra 24h cap: prevents unbounded accumulation of messages for decommissioned nodes (see the ROUTE_MAX_AGE comment)
        assert_eq!(route.max_age, ROUTE_MAX_AGE);

        let broadcast = find(STREAM_BROADCAST);
        assert_eq!(broadcast.subjects, vec!["topic.>".to_string()]);
        assert_eq!(broadcast.retention, RetentionPolicy::Limits);
        assert_eq!(broadcast.storage, StorageType::File);
        assert_eq!(broadcast.max_age, Duration::from_secs(24 * 3600));

        let audit = find(STREAM_AUDIT);
        assert_eq!(audit.subjects, vec!["audit.log".to_string()]);
        assert_eq!(audit.retention, RetentionPolicy::Limits);
        assert_eq!(audit.max_age, Duration::from_secs(7 * 24 * 3600));

        let media = find(STREAM_MEDIA);
        assert_eq!(media.subjects, vec!["media.record.>".to_string()]);
        assert_eq!(media.retention, RetentionPolicy::Limits);
        assert_eq!(media.max_age, Duration::from_secs(3600));
    }

    #[test]
    fn consumer_identity_is_stable_and_per_stream() {
        assert_eq!(route_consumer_name("node-a"), "lattice-route-node-a");
        assert_eq!(broadcast_consumer_name("node-a"), "lattice-broadcast-node-a");
        assert_ne!(route_consumer_name("node-a"), route_consumer_name("node-b"));
        // Sanitize node_id characters not allowed in NATS names, ensuring the name is stable across restarts
        assert_eq!(route_consumer_name("a.b/c"), "lattice-route-a_b_c");
        assert_eq!(route_deliver_subject("node-a"), "_INBOX.lattice.node-a.route");
        assert_ne!(
            route_deliver_subject("node-a"),
            broadcast_deliver_subject("node-a")
        );
        // deliver subject must not be captured by route.> (otherwise self-loop)
        assert!(!subject_matches(
            SUBJECT_ROUTE_WILDCARD,
            &route_deliver_subject("node-a")
        ));
        // Audit durable consumer: task card conventions `audit-{node_id}`, does not collide with route/broadcast,
        // and uses the same node_id sanitization rule (same durable reused after restart).
        assert_eq!(audit_consumer_name("node-a"), "audit-node-a");
        assert_eq!(audit_consumer_name("a.b/c"), "audit-a_b_c");
        assert_ne!(audit_consumer_name("node-a"), audit_consumer_name("node-b"));
        assert_ne!(audit_consumer_name("node-a"), route_consumer_name("node-a"));
        assert_ne!(audit_consumer_name("node-a"), broadcast_consumer_name("node-a"));
        // A pull consumer has no deliver_subject: it cannot be captured by any Stream subject wildcard
        assert!(!subject_matches(SUBJECT_AUDIT, &audit_consumer_name("node-a")));
        // Media recording durable consumer: task card conventions `media-record-{node_id}`,
        // filter is `media.record.>`; does not collide with audit/route/broadcast (same durable reused after restart).
        assert_eq!(media_record_consumer_name("node-a"), "media-record-node-a");
        assert_eq!(media_record_consumer_name("a.b/c"), "media-record-a_b_c");
        assert_ne!(
            media_record_consumer_name("node-a"),
            media_record_consumer_name("node-b")
        );
        assert_ne!(
            media_record_consumer_name("node-a"),
            audit_consumer_name("node-a")
        );
        assert_ne!(
            media_record_consumer_name("node-a"),
            route_consumer_name("node-a")
        );
        // A pull consumer name must not be captured by the recording stream filter (otherwise the consumer's own name becomes a message)
        assert!(!subject_matches(
            SUBJECT_MEDIA_WILDCARD,
            &media_record_consumer_name("node-a")
        ));
    }

    #[tokio::test]
    async fn connect_rejects_empty_url_readable() {
        let err = connect_client("   ").await.expect_err("empty url must fail");
        assert!(err.to_string().contains("nats_url"), "got: {err}");
    }

    #[tokio::test]
    async fn connect_failure_is_readable_and_bounded() {
        let started = std::time::Instant::now();
        // A port that will necessarily refuse connections locally: verify fast failure + readable error (node.rs degrades to Redis on this)
        let err = connect_client("nats://127.0.0.1:1")
            .await
            .expect_err("unreachable nats must fail");
        let msg = err.to_string();
        assert!(msg.contains("nats connect"), "got: {msg}");
        assert!(
            started.elapsed() <= CONNECT_TIMEOUT + Duration::from_secs(1),
            "connect failure should be bounded by CONNECT_TIMEOUT, took {:?}",
            started.elapsed()
        );
    }
}
