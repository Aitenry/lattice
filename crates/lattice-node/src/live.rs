//! Console live snapshots (push source for ⑤ §8.5).
//!
//! **Why this layer exists**: `/v1/admin/stream` used to compute the online count and query the node list
//! separately inside the `unfold` of **every connection** — and the node list is a Redis `SCAN`, so 100 concurrent
//! connections meant 100 `SCAN`s/s, while each connection's `select 1` liveness probe fought over the pool.
//!
//! Now instead: **one** background task computes three snapshots (online / nodes / deps) on a fixed cadence;
//! SSE connections only read the in-memory snapshot and serialize it. The cadence aligns with the ⑤ §8.5 event periods:
//!
//! | Snapshot | Period | Event name |
//! | --- | --- | --- |
//! | `online` | 1s | `online` (online count + distribution) |
//! | `nodes` | 2s | `node` (node up/down, connection count, heartbeat) |
//! | `deps` | 5s | `deps` (PG/Redis/bus health, new in v0.13) |
//!
//! All read paths are `RwLock<Value>`: no lock contention and no await points.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde_json::{json, Value};

use crate::state::{AppState, VERSION};

/// The three snapshots. Default to `Null` — the first computation runs **immediately** in `spawn`, so nothing empty is pushed.
#[derive(Default)]
pub struct Live {
    online: RwLock<Value>,
    nodes: RwLock<Value>,
    deps: RwLock<Value>,
}

impl Live {
    pub fn online(&self) -> Value {
        self.online.read().map(|v| v.clone()).unwrap_or(Value::Null)
    }

    pub fn nodes(&self) -> Value {
        self.nodes.read().map(|v| v.clone()).unwrap_or(Value::Null)
    }

    pub fn deps(&self) -> Value {
        self.deps.read().map(|v| v.clone()).unwrap_or(Value::Null)
    }

    fn put(slot: &RwLock<Value>, v: Value) {
        if let Ok(mut w) = slot.write() {
            *w = v;
        }
    }
}

/// Online snapshot (`online` event / same conventions as `GET /v1/admin/online/stats`).
///
/// `by_protocol` is currently always `ws`: the MQTT gateway and gRPC channel are not wired into `Hub` yet
/// (⑤ §9 treats WS as the only main channel), so this does not pretend other protocols exist.
pub fn online_payload(st: &AppState) -> Value {
    let conns = st.hub.all();
    let mut users = std::collections::HashSet::new();
    let mut by_node: std::collections::BTreeMap<String, usize> = Default::default();
    for c in &conns {
        users.insert(c.user.clone());
        *by_node.entry(c.node_id.clone()).or_default() += 1;
    }
    let mut by_protocol: std::collections::BTreeMap<String, usize> = Default::default();
    if !conns.is_empty() {
        by_protocol.insert("ws".to_string(), conns.len());
    }
    json!({
        "online_users": users.len(),
        "online_devices": conns.len(),
        "by_protocol": by_protocol,
        "by_node": by_node,
        "node_id": st.node_id,
        "uptime_s": st.uptime_secs(),
        "updated_at": chrono::Utc::now(),
    })
}

/// Build the node list from the node heartbeat rows in Redis (pure function, easy to unit test).
///
/// Heartbeat values look like `{node_id, version, connections, health, heartbeat_at, ...}`
/// (written by `AppState::heartbeat`). Heartbeats from older versions lack `health`/`heartbeat_at`,
/// so missing fields are handled here: health defaults to `ok`, heartbeat time defaults to `null`,
/// and the frontend shows "—" rather than inventing a time.
pub fn nodes_from_rows(
    local_node: &str,
    version: &str,
    local_conns: usize,
    rows: Vec<(String, String)>,
) -> Vec<Value> {
    let mut items: Vec<Value> = Vec::new();
    for (id, info) in rows {
        let parsed: Value = serde_json::from_str(&info).unwrap_or_else(|_| json!({}));
        let heartbeat_at = parsed
            .get("heartbeat_at")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let is_local = id == local_node;
        // Read this node's connection count from `Hub` directly: heartbeats are written only every 10s, so copying
        // the heartbeat value would lag the connection count by up to 10s, while the page requires real time.
        let connections = if is_local {
            json!(local_conns)
        } else {
            parsed.get("connections").cloned().unwrap_or(Value::Null)
        };
        items.push(json!({
            "node_id": id,
            "version": parsed.get("version").cloned().unwrap_or(Value::Null),
            "connections": connections,
            "health": if is_local {
                "ok".to_string()
            } else {
                parsed.get("health").and_then(|v| v.as_str()).unwrap_or("ok").to_string()
            },
            "heartbeat_at": heartbeat_at,
            "local": is_local,
        }));
    }
    if items.is_empty() {
        // Redis unavailable or heartbeat not written yet: at least report ourselves, don't leave the page empty
        items.push(json!({
            "node_id": local_node,
            "version": version,
            "connections": local_conns,
            "health": "ok",
            "heartbeat_at": chrono::Utc::now(),
            "local": true,
        }));
    }
    items
}

pub async fn nodes_payload(st: &AppState) -> Value {
    let rows = st.redis.nodes().await.unwrap_or_default();
    let items = nodes_from_rows(&st.node_id, VERSION, st.hub.len(), rows);
    let total = items.len();
    json!({ "items": items, "total": total })
}

/// Dependency snapshot (same conventions as `/v1/ready`: PG is the only hard dependency, and only a full outage
/// means not ready; Redis unavailability is `degraded` — the node can still serve, ② §4.8).
///
/// Redis liveness uses [`crate::store::redis::Redis::ping_ready`] (separate short connection + 300ms timeout),
/// so failures within the window cannot drag the snapshot task/`/v1/ready` into unbounded waits (E10 D2/D3).
pub async fn deps_payload(st: &AppState) -> Value {
    let pg = sqlx::query_scalar::<_, i32>("select 1")
        .fetch_one(&st.db)
        .await
        .is_ok();
    let redis = st
        .redis
        .ping_ready(crate::store::redis::READY_PING_TIMEOUT)
        .await
        .is_ok();
    let deps = json!({
        "pg": if pg { "ok" } else { "down" },
        "redis": if redis { "ok" } else { "degraded" },
        "bus": if redis { "ok" } else { "degraded" },
    });
    json!({
        // PG is the only hard dependency: matches the `/v1/ready` 503 condition (E10 D1)
        "ready": pg,
        "deps": deps,
        "node_id": st.node_id,
        "version": VERSION,
    })
}

/// Start the snapshot task. **Compute one round before sleeping** so the first SSE message carries data.
pub fn spawn(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick: u64 = 0;
        loop {
            Live::put(&st.live.online, online_payload(&st));

            if tick % 2 == 0 {
                let nodes = nodes_payload(&st).await;
                Live::put(&st.live.nodes, nodes);
            }

            if tick % 5 == 0 {
                let deps = deps_payload(&st).await;
                // `/v1/ready` and the live stream share the same verdict to avoid inconsistent conclusions
                let ready = deps.get("ready").and_then(|v| v.as_bool()).unwrap_or(false);
                st.ready
                    .store(ready, std::sync::atomic::Ordering::Relaxed);
                Live::put(&st.live.deps, deps);
            }

            tick = tick.wrapping_add(1);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_rows_carry_health_and_heartbeat() {
        let rows = vec![(
            "n1".to_string(),
            json!({
                "version": "0.1.1",
                "connections": 3,
                "health": "ok",
                "heartbeat_at": "2026-01-01T00:00:00Z"
            })
            .to_string(),
        )];
        let items = nodes_from_rows("n1", "0.1.1", 3, rows);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["health"], "ok");
        assert_eq!(items[0]["heartbeat_at"], "2026-01-01T00:00:00Z");
        assert_eq!(items[0]["local"], true);
        // This node's connection count comes from `Hub` (3); do not copy the stale heartbeat value (3 just happens to match)
        assert_eq!(items[0]["connections"], 3);
    }

    #[test]
    fn legacy_heartbeat_without_fields_still_renders() {
        // Heartbeats before v0.12 only had node_id/version/connections, missing health/heartbeat_at
        let rows = vec![("n2".to_string(), json!({"version": "0.4.0"}).to_string())];
        let items = nodes_from_rows("n1", "0.1.1", 0, rows);
        assert_eq!(items[0]["health"], "ok");
        assert!(items[0]["heartbeat_at"].is_null());
        assert_eq!(items[0]["local"], false);
    }

    #[test]
    fn empty_rows_fall_back_to_self() {
        let items = nodes_from_rows("n1", "0.1.1", 2, vec![]);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["node_id"], "n1");
        assert_eq!(items[0]["connections"], 2);
    }
}
