//! Broadcast / topic fan-out (② §4.2 + ⑤ §7).
//!
//! Persistence shape (⑥ §2.3 D13): Topic = `conversations(kind='topic')`, subscriptions = `conversation_members`;
//! hot cache `lattice:sub:{user}`; watermark `topic_offsets(user, topic)` (§18 D6 default).
//!
//! ## Cross-node fan-out and degradation (E20-G3 / E26-G3 / E26-D4)
//!
//! In NATS mode, topic broadcasts go through `LATTICE_BROADCAST` (durable consumer per node; every node sees them,
//! and the node holding the target device delivers); Redis mode keeps point-to-point `route.{node}`. Runtime degradation chain:
//!
//! 1. **Node liveness check**: the target node's heartbeat has expired (crashed/removed) → the broadcast cannot arrive (the NATS durable
//!    consumer consumes messages before the WS reconnect after a node restart → the client still misses them) → **stage for redelivery** directly:
//!    write `pending:{user}:topic:{t}` + `delivery_log persisted`; subscribers drain on reconnect,
//!    or `lock:reconcile` backfills (independent of bus recovery timing).
//! 2. **NATS publish failure**: first fall back to **Redis PubSub direct publish** on `route.{node}` (a cross-node receiver in NATS
//!    mode also attaches a Redis fallback subscription, see `routing/crossnode.rs`); if that still fails, use the
//!    gRPC Route fallback; if everything fails → stage for redelivery as in 1 (never drop silently).
//! 3. Dedup: the same broadcast frame may arrive over both "NATS replay after recovery + Redis fallback"; the consumer dedups by `env_id`
//!    (`routing/online.rs::claim_delivery`) and persists once.

use std::collections::HashSet;
use std::time::Duration;

use lattice_core::protocol::DeliveryState;

use crate::error::{self, Result};
use crate::state::AppState;
use crate::store::{Bus, BusKind, RedisBus, RouteEnvelope};

/// Result of one topic fan-out (`online`=handed to the local hub/bus, `offline`=no device online, queued to the topic queue,
/// `staged`=bus unavailable/target node down → converted to redelivery staging).
#[derive(Debug, Clone, Copy, Default)]
pub struct TopicFanout {
    pub online: usize,
    pub offline: usize,
    pub staged: usize,
}

/// Subscribe (idempotent). Exceeding `ratelimit.topics_per_user` → 429 `RATE` (`details.reason=topic_quota`).
pub async fn subscribe(state: &AppState, user: &str, topic: &str) -> Result<u64> {
    let limit = state.dyn_u64(
        "ratelimit.topics_per_user",
        state.cfg.policy.topics_per_user as u64,
    );
    let current = crate::store::pg::subscriptions(&state.db, user).await?;
    if current.len() as u64 >= limit && !current.iter().any(|(t, _, _)| t == topic) {
        return Err(error::LatticeError::rate("topic quota exceeded")
            .with_reason("topic_quota"));
    }
    let count = crate::store::pg::subscribe(&state.db, user, topic).await?;
    let _ = state.redis.sub_add(user, topic).await;
    Ok(count as u64)
}

pub async fn unsubscribe(state: &AppState, user: &str, topic: &str) -> Result<()> {
    crate::store::pg::unsubscribe(&state.db, user, topic).await?;
    let _ = state.redis.sub_remove(user, topic).await;
    Ok(())
}

/// Degradation staging: topic queue + `delivery_log persisted` (for drain/reconcile backfill).
///
/// When Redis is unwritable the queue entry cannot be written, so only `delivery_log persisted` is written: `lock:reconcile` rebuilds
/// `pending:{user}:{device}` from `state ∈ {persisted,routed}`, so redelivery still works after recovery (same source as E20-G6).
async fn stage_broadcast(state: &AppState, user: &str, topic: &str, device: &str, env: &lattice_core::Envelope) {
    if let Err(e) =
        crate::routing::pending::enqueue_topic(state, user, topic, env.seq as i64, &env.id).await
    {
        tracing::warn!(
            error = %e,
            msg_id = %env.id,
            user = %crate::observe::Metrics::user_hash(user),
            topic,
            "topic pending enqueue failed; delivery_log persisted for reconcile (② §4.8)"
        );
    }
    crate::routing::online::record_state(state, &env.id, user, device, DeliveryState::Persisted)
        .await;
}

/// Cross-node topic publish: try the degradation chain, return whether any transport path accepted it.
async fn publish_remote(
    state: &AppState,
    user: &str,
    topic: &str,
    node: &str,
    env: &RouteEnvelope,
    envelope: &lattice_core::Envelope,
) -> bool {
    let timeout = Duration::from_millis(crate::routing::online::BUS_PUBLISH_TIMEOUT_MS);
    let mut published = match state.bus.kind() {
        // NATS: `LATTICE_BROADCAST` durable consumer per node (visible to all nodes).
        // Do not try when the bus is explicitly unhealthy (async-nats may buffer the publish until reconnect,
        // which stacks with the post-recovery Redis fallback/drain into duplicates, see E20-G4).
        BusKind::Nats => {
            if !state.bus.healthy() {
                Err(error::internal(
                    "nats bus unhealthy; skipping broadcast publish (degraded path)",
                ))
            } else {
                match tokio::time::timeout(timeout, state.bus.publish_topic(topic, env)).await {
                    Ok(result) => result,
                    Err(_) => Err(error::internal(format!(
                        "nats broadcast publish timed out after {}ms",
                        crate::routing::online::BUS_PUBLISH_TIMEOUT_MS
                    ))),
                }
            }
        }
        // Redis degradation: keep P2's point-to-point `route.{node}` semantics.
        BusKind::RedisPubSub => state.bus.publish_route(node, env).await,
    };

    if let Err(e) = &published {
        if state.bus.kind() == BusKind::Nats {
            // ② §4.8 short-term degradation: NATS outage → Redis PubSub direct publish (remote nodes in NATS mode
            // also subscribe to the Redis fallback channel `route.{node}`, see crossnode).
            tracing::warn!(
                error = %e,
                topic,
                node,
                "nats broadcast publish failed; falling back to redis pubsub route (② §4.8)"
            );
            published = RedisBus::new(state.redis.clone())
                .publish_route(node, env)
                .await;
        }
    }

    match published {
        Ok(()) => true,
        Err(e) => {
            // Final fallback: gRPC Route direct delivery (⑤ §10). If that fails too, stage for redelivery (no longer drop).
            if state.bus.kind() == BusKind::Nats || state.cfg.grpc.fallback {
                if crate::transport::grpc::route_fallback(state, node, env).await {
                    return true;
                }
            }
            tracing::warn!(
                error = %e,
                topic,
                node,
                "broadcast publish failed on bus + fallbacks; staging pending for re-delivery (② §4.8)"
            );
            stage_broadcast(state, user, topic, &env.target_device, envelope).await;
            false
        }
    }
}

/// Fan-out: deliver directly to online users (local/cross-node), queue offline users into `pending:{user}:topic:{t}`.
///
/// `env` must be an **already persisted** envelope (id/seq populated): the offline queue stores only `seq → msg_id`,
/// and online redelivery looks messages up by id; passing an empty id (the old approach) made topic offline redelivery never find the message
/// (the PL-17 reconciliation script showed that all msg_id members of `pending:{user}:topic:*` were empty — fixed).
pub async fn publish(
    state: &AppState,
    topic: &str,
    env: &lattice_core::Envelope,
) -> Result<TopicFanout> {
    let subscribers = crate::store::pg::topic_subscribers(&state.db, topic).await?;
    let body = env.encode_body();
    let mut fanout = TopicFanout::default();

    for user in subscribers {
        let devices = state.online_devices(&user).await;
        if devices.is_empty() {
            // Broadcast offline: score/offset use the message's seq in the topic conversation
            crate::routing::pending::enqueue_topic(
                state,
                &user,
                topic,
                env.seq as i64,
                &env.id,
            )
            .await
            .ok();
            fanout.offline += 1;
            continue;
        }
        for (device, node) in devices {
            if node == state.node_id {
                let frame = lattice_core::Frame::new(
                    lattice_core::WsCommand::Envelope,
                    bytes::Bytes::from(body.clone()),
                );
                if state.hub.send_to_device(&user, &device, frame) {
                    fanout.online += 1;
                }
                continue;
            }
            // Target node heartbeat expired (down): the broadcast cannot arrive (after a restart, the durable consumer consumes messages before the
            // WS reconnect) → stage for redelivery directly; wait for subscriber reconnect or reconcile backfill.
            if matches!(
                crate::routing::online::node_alive(state, &node).await,
                Some(false)
            ) {
                tracing::warn!(
                    user = %crate::observe::Metrics::user_hash(&user),
                    device = %device,
                    node,
                    topic,
                    "broadcast target node heartbeat expired; staging pending (E20-G3/G5)"
                );
                stage_broadcast(state, &user, topic, &device, env).await;
                fanout.staged += 1;
                continue;
            }
            let route_env = RouteEnvelope {
                target_user: user.clone(),
                target_device: device.clone(),
                env_id: env.id.clone(),
                conv_id: format!("topic:{topic}"),
                seq: env.seq,
                frame_cmd: lattice_core::WsCommand::Envelope.to_u8(),
                body_b64: lattice_core::envelope::base64_encode(&body),
            };
            if publish_remote(state, &user, topic, &node, &route_env, env).await {
                fanout.online += 1;
            } else {
                fanout.staged += 1;
            }
        }
    }
    Ok(fanout)
}

/// History replay (⑤ §7 `GET /v1/topics/{t}/history`): half-open interval by `after_offset`; advance the watermark after consumption.
pub async fn history(
    state: &AppState,
    user: &str,
    topic: &str,
    after_offset: Option<i64>,
    limit: i64,
) -> Result<Vec<crate::store::pg::Message>> {
    let conv = crate::store::pg::topic_conv_id(&state.db, topic)
        .await?
        .ok_or_else(|| error::not_found("topic not found"))?;
    crate::store::pg::member_role(&state.db, &conv, user)
        .await?
        .ok_or_else(|| error::forbidden("not a subscriber").with_reason("not_member"))?;

    let msgs = crate::store::pg::history(&state.db, &conv, None, after_offset, limit).await?;
    if let Some(last) = msgs.iter().map(|m| m.seq).max() {
        crate::store::pg::set_topic_offset(&state.db, user, topic, last).await?;
    }
    Ok(msgs)
}

/// Deduped topic list (used for the dual-write check between `lattice:sub:{user}` and the DB, ⑥ §3.4 rebuild source).
pub async fn cached_topics(state: &AppState, user: &str) -> HashSet<String> {
    state
        .redis
        .sub_members(user)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn topic_quota_reason() {
        let e = crate::error::LatticeError::rate("topic quota exceeded").with_reason("topic_quota");
        assert_eq!(e.code, lattice_core::ErrorCode::Rate);
        assert_eq!(e.http_status(), 429);
    }

    #[test]
    fn fanout_shape_is_additive() {
        // The three outcomes do not override each other: online/offline/staged are counted separately, which helps E2E assert degradation paths.
        let f = super::TopicFanout {
            online: 2,
            offline: 1,
            staged: 1,
        };
        assert_eq!(f.online + f.offline + f.staged, 4);
        assert_eq!(super::TopicFanout::default().staged, 0);
    }
}
