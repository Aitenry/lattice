//! Online routing (② §4.1): two-layer Redis index + local connection table.
//!
//! ```text
//! Write: hello/keepalive → HSET conn:{user} {device}=node + EXPIRE 90
//!                          SET  conn:{user}:{device} node EX 90
//! Read: HGETALL conn:{user} → {device: node}
//!       Same node → in-process channel direct delivery (zero Redis round trips)
//!       Cross-node → PUBLISH route.{node_id}
//! ```
//!
//! E20 wrap-up (② §4.8 chaos matrix G4/G5):
//! - **Delivery dedup** (G4): the bus is at-least-once (JetStream publish ack timeout falls back to core NATS,
//!   or the gRPC fallback within a disconnect window and the Stream replay after recovery both arrive), so the same `(env_id, user, device)`
//!   reaches the consumer multiple times. Consumers (NATS route/topic consumer, gRPC Route handler) atomically claim with
//!   [`claim_delivery`] before actually delivering; duplicate frames are acked without delivery. A failed delivery calls [`release_delivery`]
//!   so later redeliveries can still succeed ("prefer duplicates over loss" now applies only to the delivery-failure path, no longer creating duplicates in normal windows).
//! - **Node liveness check** (G5): the conn index TTL of 90s is far longer than the 10s node heartbeat TTL, so for 90s after a node crashes
//!   the index still points at the dead node. Before cross-node decisions, [`node_alive`] filters nodes whose heartbeat has expired (the verdict is cached
//!   for 2s to avoid a Redis SCAN per message); targets are treated as offline → the policy layer converts them to pending/offline queues.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use lattice_core::protocol::DeliveryState;

use crate::error::Result;
use crate::state::AppState;
use crate::store::RouteEnvelope;

/// Routing decision result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// All target devices are on this node
    Local(Vec<String>),
    /// All target devices are on other nodes: node → devices
    Remote(HashMap<String, Vec<String>>),
    /// Target devices exist on both this node and other nodes
    Mixed(Vec<String>, HashMap<String, Vec<String>>),
    /// No online device → go to pending (§17.4-1)
    Offline,
}

/// Per-call limit for cross-node bus publishes (matches the gRPC Route 2s timeout; exceeding it counts as failure and takes the fallback).
pub const BUS_PUBLISH_TIMEOUT_MS: u64 = 2_000;

/// Node heartbeat verdict cache TTL: the node set is not SCANned per message; a 2s-stale down verdict is acceptable
/// (node heartbeat TTL=10s, conn index TTL=90s; this cache shrinks the "stale routing window" from 90s to ≤ one heartbeat period).
const NODE_LIVENESS_TTL: Duration = Duration::from_millis(2_000);

/// Cross-node delivery dedup claim TTL (covers NATS reconnect/durable redelivery windows; 600s ≫ ack_wait/reconnect time).
const DELIVERY_CLAIM_TTL: Duration = Duration::from_secs(600);
/// Upper bound on dedup claims (evict by TTL first, clear when still full; losing a claim only degrades to at-least-once).
const DELIVERY_CLAIM_CAP: usize = 200_000;

#[derive(Default)]
struct NodeLivenessCache {
    checked_at: Option<Instant>,
    nodes: HashSet<String>,
}

static NODE_LIVENESS: OnceLock<Mutex<NodeLivenessCache>> = OnceLock::new();

fn liveness_cache() -> &'static Mutex<NodeLivenessCache> {
    NODE_LIVENESS.get_or_init(|| Mutex::new(NodeLivenessCache::default()))
}

/// Current live node set (the `lattice:node:{id}` heartbeat key exists = alive).
///
/// Redis read failure returns `None` (**unknown**): callers must not treat a remote target as offline on that basis — when Redis is fully down,
/// keep the existing conn index semantics rather than misrouting online targets to pending.
async fn live_nodes(state: &AppState) -> Option<HashSet<String>> {
    if let Ok(cache) = liveness_cache().lock() {
        if let Some(at) = cache.checked_at {
            if at.elapsed() < NODE_LIVENESS_TTL {
                return Some(cache.nodes.clone());
            }
        }
    }
    match state.redis.nodes().await {
        Ok(nodes) => {
            let set: HashSet<String> = nodes.into_iter().map(|(id, _)| id).collect();
            if let Ok(mut cache) = liveness_cache().lock() {
                cache.checked_at = Some(Instant::now());
                cache.nodes = set.clone();
            }
            Some(set)
        }
        Err(e) => {
            tracing::warn!(error = %e, "node liveness read failed (unknown; keep remote targets)");
            None
        }
    }
}

/// Whether the target node is alive: `Some(false)` = heartbeat key expired (deemed down), `None` = cannot determine (Redis unavailable).
pub async fn node_alive(state: &AppState, node_id: &str) -> Option<bool> {
    live_nodes(state)
        .await
        .map(|nodes| nodes.contains(node_id))
}

/// Decide the delivery path from the online index (target by device when `to_devices` is non-empty, §17.4-5).
pub async fn decide(state: &AppState, user: &str, to_devices: &[String]) -> Decision {
    decide_with_policy(state, user, to_devices, false).await
}

/// Policy-aware version of [`decide`]: `primary_only` = user-level "primary device only" override (semantics ⑥, P3).
///
/// `primary_only` **only changes the distribution scope of semantics 1** (all devices by default → primary device only); it does not change device-level
/// ACK/receipt semantics, nor explicit `to_devices` targeting (semantics 5 takes precedence). Primary device = the online target with the smallest
/// `device_id` (ULID time order, equivalent to the earliest registered device; when all devices are offline, user-level pending still applies).
pub async fn decide_with_policy(
    state: &AppState,
    user: &str,
    to_devices: &[String],
    primary_only: bool,
) -> Decision {
    let online = state.online_devices(user).await;
    let mut targets: Vec<(String, String)> = online
        .into_iter()
        .filter(|(dev, _)| to_devices.is_empty() || to_devices.contains(dev))
        .collect();

    if primary_only && to_devices.is_empty() && targets.len() > 1 {
        targets.sort_by(|a, b| a.0.cmp(&b.0));
        targets.truncate(1);
    }

    if targets.is_empty() {
        return Decision::Offline;
    }

    let mut local = Vec::new();
    let mut remote: HashMap<String, Vec<String>> = HashMap::new();
    for (dev, node) in targets {
        if node == state.node_id {
            local.push(dev);
        } else {
            remote.entry(node).or_default().push(dev);
        }
    }

    // E20-G5: the remote node's heartbeat has expired (after a crash/SIGKILL the conn index TTL of 90s has not elapsed) → treat as offline;
    // the policy layer converts the target to pending/offline queues instead of publishing to a channel with no consumer and losing it silently.
    if !remote.is_empty() {
        if let Some(live) = live_nodes(state).await {
            let before: usize = remote.values().map(Vec::len).sum();
            remote.retain(|node, _| live.contains(node));
            let after: usize = remote.values().map(Vec::len).sum();
            if after < before {
                tracing::warn!(
                    user,
                    dropped = before - after,
                    "remote target node heartbeat expired; treating targets as offline (② §4.8)"
                );
            }
        }
    }

    match (local.is_empty(), remote.is_empty()) {
        (false, true) => Decision::Local(local),
        (true, false) => Decision::Remote(remote),
        (false, false) => Decision::Mixed(local, remote),
        (true, true) => Decision::Offline,
    }
}

/// Cross-node forwarding result: devices successfully handed to the bus/gRPC vs failed devices (callers convert failures to pending redelivery).
#[derive(Debug, Clone, Default)]
pub struct ForwardOutcome {
    pub delivered: Vec<String>,
    /// (device, reason): no transport path succeeded; the caller must route to the offline queue instead of dropping.
    pub failed: Vec<(String, String)>,
}

impl ForwardOutcome {
    pub fn is_ok(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Forward one downstream frame across nodes (keeps the old signature: for transient data such as media signaling; returns Err if any device fails).
pub async fn forward(
    state: &AppState,
    node_id: &str,
    user: &str,
    devices: &[String],
    frame_cmd: u8,
    body: Vec<u8>,
) -> Result<()> {
    let outcome = forward_with_env(
        state, node_id, user, "", devices, frame_cmd, body,
    )
    .await;
    match outcome.failed.first() {
        Some((dev, reason)) => Err(crate::error::internal(format!(
            "cross-node forward failed for device {dev}: {reason}"
        ))),
        None => Ok(()),
    }
}

/// Cross-node forwarding (E20: carries `env_id` for consumer-side dedup; a single failure does not abort the remaining devices).
pub async fn forward_with_env(
    state: &AppState,
    node_id: &str,
    user: &str,
    env_id: &str,
    devices: &[String],
    frame_cmd: u8,
    body: Vec<u8>,
) -> ForwardOutcome {
    let mut outcome = ForwardOutcome::default();
    for dev in devices {
        let env = RouteEnvelope {
            target_user: user.to_string(),
            target_device: dev.clone(),
            env_id: env_id.to_string(),
            conv_id: String::new(),
            seq: 0,
            frame_cmd,
            body_b64: lattice_core::envelope::base64_encode(&body),
        };
        // Do not attempt publishing when the bus is explicitly unhealthy (e.g. NATS disconnected): async-nats publish may
        // enter the client buffer and land in the Stream after reconnect → duplicate delivery after recovery; go straight to the gRPC fallback/offline redelivery.
        let publish_result = if state.cfg.degrade.inject_bus_failure || !state.bus.healthy() {
            Err(crate::error::internal(
                "bus unhealthy; skipping publish (gRPC fallback / pending)",
            ))
        } else {
            // Bus publishes must be bounded: when Redis/NATS is half-dead (connection alive but unresponsive), the WS downstream
            // must not hang forever; a timeout counts as failure and goes to the gRPC Route fallback (⑤ §10 / PL-13).
            match tokio::time::timeout(
                Duration::from_millis(BUS_PUBLISH_TIMEOUT_MS),
                state.bus.publish_route(node_id, &env),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(crate::error::internal(format!(
                    "bus publish timed out after {BUS_PUBLISH_TIMEOUT_MS}ms"
                ))),
            }
        };
        if let Err(publish_err) = publish_result {
            // ⑤ §10: final fallback when both NATS and Redis are unavailable. On success emit warn/metric (alerting input);
            // if it still fails, return so the caller can convert to pending — never disguise "not delivered" as success.
            if crate::transport::grpc::route_fallback(state, node_id, &env).await {
                outcome.delivered.push(dev.clone());
                continue;
            }
            outcome
                .failed
                .push((dev.clone(), publish_err.to_string()));
            continue;
        }
        outcome.delivered.push(dev.clone());
    }
    outcome
}

// ---------------------------------------------------------------------------
// E20-G4: cross-node delivery dedup (claim by env_id + user + device)
// ---------------------------------------------------------------------------

static DELIVERY_CLAIMS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

fn claim_cell() -> &'static Mutex<HashMap<String, Instant>> {
    DELIVERY_CLAIMS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn claim_key(env_id: &str, user: &str, device: &str) -> String {
    // Separator is U+001F: ULID/user/device are all visible ASCII and cannot contain it.
    format!("{env_id}\u{1f}{user}\u{1f}{device}")
}

/// Try to claim a cross-node delivery: `true` = first time (deliver); `false` = already delivered (duplicate frame;
/// the consumer should ack without delivering). No dedup when `env_id` is empty (media frames/old callers).
pub fn claim_delivery(env_id: &str, user: &str, device: &str) -> bool {
    if env_id.is_empty() {
        return true;
    }
    let Ok(mut map) = claim_cell().lock() else {
        return true;
    };
    let key = claim_key(env_id, user, device);
    let now = Instant::now();
    if map.get(&key).is_some_and(|at| now.duration_since(*at) < DELIVERY_CLAIM_TTL) {
        return false;
    }
    if map.len() >= DELIVERY_CLAIM_CAP {
        map.retain(|_, at| now.duration_since(*at) < DELIVERY_CLAIM_TTL);
        if map.len() >= DELIVERY_CLAIM_CAP {
            map.clear();
        }
    }
    map.insert(key, now);
    true
}

/// Release the claim when delivery fails (connection not in hub/queue full): later redeliveries can still succeed.
pub fn release_delivery(env_id: &str, user: &str, device: &str) {
    if env_id.is_empty() {
        return;
    }
    if let Ok(mut map) = claim_cell().lock() {
        map.remove(&claim_key(env_id, user, device));
    }
}

/// Unit-test helper: clear dedup claims (global static; avoid cross-test interference).
#[cfg(test)]
pub(crate) fn reset_delivery_claims() {
    if let Ok(mut map) = claim_cell().lock() {
        map.clear();
    }
}

/// Record delivery state (`delivery_log` write; the hot path only records when necessary).
///
/// After a successful write, hand this state transition to the audit stream as an **observability event** (E19 / PL-11 11.7):
/// `routing::audit::spawn_delivery_event` only does one non-blocking enqueue (background publish in NATS mode,
/// no-op in Redis mode); it does not await and does not participate in delivery decisions. Write failures only WARN (existing semantics).
pub async fn record_state(
    state: &AppState,
    msg_id: &str,
    to_user: &str,
    to_device: &str,
    st: DeliveryState,
) {
    match crate::store::pg::upsert_delivery(
        &state.db,
        msg_id,
        to_user,
        to_device,
        st.as_str(),
        &state.node_id,
        false,
    )
    .await
    {
        Ok(()) => crate::routing::audit::spawn_delivery_event(
            state,
            msg_id,
            to_user,
            to_device,
            st.as_str(),
        ),
        Err(e) => tracing::warn!(error = %e, msg_id, "delivery_log write failed"),
    }
}

pub mod cache {
    //! Local stale routing cache (② §4.8: when Redis reads fail, only cache hits are allowed for cross-node delivery).

    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct StateCache {
        route: Mutex<HashMap<String, String>>,
        sent: Mutex<u64>,
        capacity: usize,
    }

    impl StateCache {
        pub fn new(capacity: usize) -> Self {
            StateCache {
                route: Mutex::new(HashMap::new()),
                sent: Mutex::new(0),
                capacity: capacity.max(16),
            }
        }

        pub fn remember(&self, user: &str, device: &str, node: &str) {
            if let Ok(mut m) = self.route.lock() {
                if m.len() >= self.capacity {
                    m.clear();
                }
                m.insert(format!("{user}:{device}"), node.to_string());
            }
        }

        pub fn lookup(&self, user: &str, device: &str) -> Option<String> {
            self.route
                .lock()
                .ok()
                .and_then(|m| m.get(&format!("{user}:{device}")).cloned())
        }

        pub fn mark_sent(&self, n: usize) {
            if let Ok(mut s) = self.sent.lock() {
                *s += n as u64;
            }
        }

        pub fn sent(&self) -> u64 {
            self.sent.lock().map(|s| *s).unwrap_or(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::cache::StateCache;
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Global claim/liveness caches are process-level statics: serialize tests + clear each time to avoid parallel-test interference.
    static TEST_LOCK: StdMutex<()> = StdMutex::new(());

    #[test]
    fn cache_evicts_and_looks_up() {
        let c = StateCache::new(16);
        c.remember("u1", "d1", "node-a");
        assert_eq!(c.lookup("u1", "d1").as_deref(), Some("node-a"));
        assert!(c.lookup("u2", "d1").is_none());
        c.mark_sent(3);
        assert_eq!(c.sent(), 3);
    }

    #[test]
    fn delivery_claims_suppress_duplicates_and_release_on_failure() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_delivery_claims();
        let id = "01CLAIMTEST0000000000000001";
        // First claim succeeds, duplicate frame suppressed
        assert!(claim_delivery(id, "u1", "d1"));
        assert!(!claim_delivery(id, "u1", "d1"));
        // Different device/user dimensions are independent (with multi-device targeting, the same env_id delivers once per device)
        assert!(claim_delivery(id, "u1", "d2"));
        assert!(claim_delivery(id, "u2", "d1"));
        // After a failed delivery releases the claim, redelivery works
        release_delivery(id, "u1", "d2");
        assert!(claim_delivery(id, "u1", "d2"));
        // Empty env_id (media frames/old callers) skips dedup
        assert!(claim_delivery("", "u1", "d1"));
        assert!(claim_delivery("", "u1", "d1"));
    }

    #[test]
    fn forward_outcome_reports_failed_devices() {
        // Pure structure unit test: failed devices must appear in the failed list (callers use it to enqueue pending, not drop silently).
        let mut o = ForwardOutcome::default();
        o.delivered.push("d1".into());
        o.failed.push(("d2".into(), "bus down".into()));
        assert!(!o.is_ok());
        o.failed.clear();
        assert!(o.is_ok());
    }
}
