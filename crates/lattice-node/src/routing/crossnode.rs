//! Cross-node delivery (② §3.3 / §4.1): subscribe to this node's `route.{node_id}` channel and deliver downstream frames to local connections.
//!
//! The subscription path depends on the bus backend (`Bus::kind`):
//! - NATS: JetStream durable push consumer per node (`store/nats.rs`, unacked offline messages can be redelivered);
//! - Redis: PubSub degradation path (② §4.8).
//!
//! Online events (`lattice:online`) always use Redis PubSub per ⑥ §3.1 — in NATS mode
//! `NatsBus` delegates to `RedisBus` internally, so this is the same code for both backends.
//!
//! Subscription failures do not block startup; they only degrade to "deliver to local connections only" (⑤ §10: the `Route` RPC is the final fallback).

use std::sync::Arc;

use lattice_core::{Frame, WsCommand};

use crate::observe::Metrics;
use crate::state::{AppState, Hub};
use crate::store::{Bus, BusKind, BusSub, OnlineHandler, RedisBus, RouteEnvelope, RouteHandler};

/// Holds the subscription handle until process exit.
///
/// `AppState` does not store `BusSub` (to avoid changing the shared state struct); the node needs no unsubscribe at runtime,
/// so the subscription is reclaimed when the process/runtime ends. A pending task holds it instead of `mem::forget`, so it drops cleanly on exit.
fn hold_subscription(sub: Box<dyn BusSub>) {
    tokio::spawn(async move {
        let _sub = sub;
        std::future::pending::<()>().await;
    });
}

/// Deliver a cross-node envelope to the local hub (shared by route and topic fan-in).
///
/// Returns `true` = the target device is on this node and at least one connection received the frame (the NATS route consumer acks accordingly);
/// `count_backpressure=false` is for topic broadcast fan-in: it is **normal** that a non-target node has no such local device,
/// and it must not be counted as a backpressure drop.
///
/// E20-G4: consumer-side dedup by `(env_id, user, device)` — the bus is at-least-once (JetStream publish
/// timeout falls back to core NATS; the disconnect-window gRPC fallback and the post-recovery Stream replay each deliver once),
/// so the first arrival claims the slot and delivers, while duplicates ack without delivering; a failed delivery (device just disconnected) releases the slot
/// so NAK/redelivery can still succeed.
fn deliver_envelope(hub: &Hub, metrics: &Metrics, env: RouteEnvelope, count_backpressure: bool) -> bool {
    if !crate::routing::online::claim_delivery(&env.env_id, &env.target_user, &env.target_device) {
        tracing::debug!(
            env_id = %env.env_id,
            user = %crate::observe::Metrics::user_hash(&env.target_user),
            device = %env.target_device,
            "duplicate cross-node delivery suppressed (E20-G4 env_id dedupe)"
        );
        return true;
    }
    let Some(cmd) = WsCommand::from_u8(env.frame_cmd) else {
        tracing::warn!(cmd = env.frame_cmd, "unknown cmd in route payload");
        crate::routing::online::release_delivery(&env.env_id, &env.target_user, &env.target_device);
        return false;
    };
    let body = lattice_core::envelope::base64_decode(&env.body_b64).unwrap_or_default();
    let frame = Frame::new(cmd, bytes::Bytes::from(body));
    let delivered = hub.send_to_device(&env.target_user, &env.target_device, frame);
    if !delivered {
        crate::routing::online::release_delivery(&env.env_id, &env.target_user, &env.target_device);
    }
    if !delivered && count_backpressure {
        metrics
            .backpressure_dropped_total
            .with_label_values(&["route"])
            .inc();
    }
    delivered
}

/// Start the route subscription task.
pub async fn spawn_subscriber(state: Arc<AppState>) {
    let node_id = state.node_id.clone();
    let hub = state.hub.clone();
    let metrics = state.metrics.clone();
    let handler: RouteHandler = Arc::new(move |env| deliver_envelope(&hub, &metrics, env, true));

    match state.bus.subscribe_route(&node_id, handler.clone()).await {
        Ok(sub) => {
            hold_subscription(sub);
            tracing::info!(
                node = %node_id,
                bus = state.bus.kind().as_str(),
                "cross-node route subscriber started"
            );
        }
        Err(e) => tracing::warn!(error = %e, "cross-node subscriber failed (degraded)"),
    }

    // E20-G3 / E26-G3: in NATS mode, also attach a **Redis PubSub `route.{node}` fallback subscription**.
    // When NATS is down, the degradation paths in `routing/topic.rs` / `online::forward` PUBLISH directly to
    // Redis `route.{node}` (② §4.8 short-term degradation); without this subscription, "nobody receives what is published".
    // Both paths go through deliver_envelope's env_id dedup, so there is no double delivery.
    if state.bus.kind() == BusKind::Nats {
        let redis_bus = RedisBus::new(state.redis.clone());
        match redis_bus.subscribe_route(&node_id, handler).await {
            Ok(sub) => {
                hold_subscription(sub);
                tracing::info!(
                    node = %node_id,
                    "redis pubsub route fallback subscriber started (nats mode, ② §4.8)"
                );
            }
            Err(e) => tracing::warn!(error = %e, "redis route fallback subscriber failed (degraded)"),
        }
    }
}

/// Start the topic broadcast fan-in task (NATS only: `LATTICE_BROADCAST` durable consumer per node).
///
/// The Redis degradation path does not subscribe to broadcasts: cross-node topics still use point-to-point `route.{node}` (`routing/topic.rs`),
/// exactly matching P2 behavior.
pub async fn spawn_topic_listener(state: Arc<AppState>) {
    if state.bus.kind() != BusKind::Nats {
        return;
    }
    let node_id = state.node_id.clone();
    let hub = state.hub.clone();
    let metrics = state.metrics.clone();
    let handler: RouteHandler = Arc::new(move |env| deliver_envelope(&hub, &metrics, env, false));

    match state.bus.subscribe_topic(&node_id, handler).await {
        Ok(sub) => {
            hold_subscription(sub);
            tracing::info!(
                node = %node_id,
                "cross-node topic broadcast subscriber started (nats)"
            );
        }
        Err(e) => tracing::warn!(error = %e, "topic broadcast subscriber failed (degraded)"),
    }
}

/// Subscribe to device online events (`lattice:online`): redelivery is done by the node holding `lock:deliver:{user}:{device}`.
pub async fn spawn_online_listener(state: Arc<AppState>) {
    let bus_kind = state.bus.kind();
    let outer = state.clone();
    let handler: OnlineHandler = Arc::new(move |user, device| {
        let st = outer.clone();
        tokio::spawn(async move {
            // Only the node **holding that device's connection** redelivers: `lattice:online` is Redis PubSub,
            // so every node receives it; when a non-owner grabs the lock and drains, `hub.send_to_device` necessarily fails,
            // leaving the queue until the next reconnect (most visible for topic queues). Confirm ownership via the online index first.
            let owner = st
                .redis
                .conn_devices(&user)
                .await
                .ok()
                .and_then(|m| m.get(&device).cloned());
            if owner.as_deref() != Some(st.node_id.as_str()) {
                tracing::trace!(user = %user, device = %device, ?owner, "online event not owned by this node, skipped");
                return;
            }
            // Prevent duplicate redelivery across nodes: the lock winner redelivers (⑥ §3.2 `lock:deliver:{user}:{device}`)
            let task = format!("deliver:{user}:{device}");
            if st
                .redis
                .acquire_lock(&task, &st.node_id, 30_000)
                .await
                .unwrap_or(false)
            {
                if let Err(e) = crate::routing::pending::drain_device(&st, &user, &device).await {
                    tracing::warn!(error = %e, "pending drain failed");
                }
                // The same lock also covers the topic offline queue: the WS hello redelivery task may lose to this listener,
                // and if topics are not redelivered here, `pending:{user}:topic:*` stays in the queue forever.
                if let Err(e) = crate::routing::pending::drain_topics(&st, &user, &device).await {
                    tracing::warn!(error = %e, "topic pending drain failed");
                }
                let _ = st.redis.release_lock(&task, &st.node_id).await;
            }
        });
    });

    match state.bus.subscribe_online(handler).await {
        Ok(sub) => {
            hold_subscription(sub);
            tracing::info!(bus = bus_kind.as_str(), "online listener started");
        }
        Err(e) => tracing::warn!(error = %e, "online listener failed (degraded)"),
    }
}

/// Subscribe to dynamic config broadcasts (`lattice:cfg`): carries **changes** only; authoritative values live in PG (⑥ §9 D12).
///
/// Non-persistent config broadcast; stays on Redis PubSub per ⑥ §3.1 and does not go through the bus abstraction.
pub async fn spawn_cfg_listener(state: Arc<AppState>) {
    let outer = state.clone();
    let result = outer
        .redis
        .subscribe(vec![lattice_core::keys::channel_cfg()], move |_ch, payload| {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) else {
                return;
            };
            let Some(key) = v.get("key").and_then(|x| x.as_str()) else {
                return;
            };
            let Some(value) = v.get("value").cloned() else {
                return;
            };
            if let Ok(mut map) = state.dynamic.write() {
                map.insert(key.to_string(), value);
            }
            tracing::info!(key, "dynamic config updated");
        })
        .await;

    if let Err(e) = result {
        tracing::warn!(error = %e, "cfg listener failed (degraded)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_payload_roundtrip() {
        let env = crate::store::RouteEnvelope {
            target_user: "u1".into(),
            target_device: "d1".into(),
            env_id: "01J".into(),
            conv_id: "01H".into(),
            seq: 7,
            frame_cmd: WsCommand::Envelope.to_u8(),
            body_b64: lattice_core::envelope::base64_encode(b"abc"),
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: crate::store::RouteEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(
            lattice_core::envelope::base64_decode(&back.body_b64).unwrap(),
            b"abc"
        );
        assert_eq!(WsCommand::from_u8(back.frame_cmd), Some(WsCommand::Envelope));
    }

    #[test]
    fn deliver_envelope_reaches_local_device() {
        let hub = Hub::default();
        let metrics = Metrics::new();
        let (tx, mut rx) = crate::state::conn_channel();
        hub.register(crate::state::Conn {
            id: 0,
            user: "u1".into(),
            device: "d1".into(),
            tx,
            caps: crate::state::Caps::default(),
            connected_at: std::time::Instant::now(),
            remote_ip: "127.0.0.1".into(),
            protocol: 1,
            node_id: "node-b".into(),
        });
        let env = RouteEnvelope {
            target_user: "u1".into(),
            target_device: "d1".into(),
            env_id: "01J".into(),
            conv_id: "01H".into(),
            seq: 1,
            frame_cmd: WsCommand::Envelope.to_u8(),
            body_b64: lattice_core::envelope::base64_encode(b"hello"),
        };
        assert!(deliver_envelope(&hub, &metrics, env, true));
        let frame = rx.try_recv().expect("frame delivered");
        assert_eq!(frame.cmd, WsCommand::Envelope);
        assert_eq!(frame.body.as_ref(), b"hello");

        // Target device is not on this node: topic fan-in does not count backpressure (route does), and returns false (cannot ack)
        let miss = RouteEnvelope {
            target_user: "u1".into(),
            target_device: "d-other".into(),
            env_id: "01K".into(),
            conv_id: "01H".into(),
            seq: 2,
            frame_cmd: WsCommand::Envelope.to_u8(),
            body_b64: String::new(),
        };
        assert!(!deliver_envelope(&hub, &metrics, miss, false));
    }
}
