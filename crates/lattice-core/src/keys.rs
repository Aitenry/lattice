//! Redis keys and PubSub channels (single source of truth: design §8.2; concrete form in doc ⑥ §3.1).
//!
//! Key names may only be assembled here — implementation code must not hand-write `format!("lattice:conn:{}")`;
//! this keeps the §17.14 `grep -rn "conn:"` review converging on one place.

/// `lattice:conn:{user}` Hash: field `device_id` → `node_id` (a non-empty HGETALL means the user is online).
pub fn conn_user(user: &str) -> String {
    format!("lattice:conn:{user}")
}

/// `lattice:conn:{user}:{device}` String → `node_id` (exact per-device routing).
pub fn conn_device(user: &str, device: &str) -> String {
    format!("lattice:conn:{user}:{device}")
}

/// `lattice:node:{id}` node heartbeat (TTL 10s).
pub fn node(node_id: &str) -> String {
    format!("lattice:node:{node_id}")
}

/// `lattice:seq:{conv}` monotonic sequence within a session.
pub fn seq(conv: &str) -> String {
    format!("lattice:seq:{conv}")
}

/// `lattice:pending:{user}` user-level offline backlog (score = seq).
pub fn pending_user(user: &str) -> String {
    format!("lattice:pending:{user}")
}

/// `lattice:pending:{user}:{device}` device-targeted offline backlog.
pub fn pending_device(user: &str, device: &str) -> String {
    format!("lattice:pending:{user}:{device}")
}

/// `lattice:pending:{user}:topic:{t}` broadcast offline backlog.
pub fn pending_topic(user: &str, topic: &str) -> String {
    format!("lattice:pending:{user}:topic:{topic}")
}

/// `lattice:stream:{id}` media tunnel session (⑥ §3.1; Hash: a_user/a_device/b_user/b_device, TTL 120s).
///
/// Written only by the `stream-sig` offer in `transport/ws.rs`, then read/renewed by `stream-data`;
/// after a restart or expiry the client simply re-negotiates (the media plane itself is never persisted).
pub fn stream_session(id: &str) -> String {
    format!("lattice:stream:{id}")
}

/// `lattice:dedup:{key}` idempotency hot layer.
pub fn dedup(key: &str) -> String {
    format!("lattice:dedup:{key}")
}

/// `lattice:lock:{task}` distributed lock.
pub fn lock(task: &str) -> String {
    format!("lattice:lock:{task}")
}

/// `lattice:sub:{user}` subscription hot cache (SET).
pub fn sub(user: &str) -> String {
    format!("lattice:sub:{user}")
}

/// `lattice:ratelimit:{user}` token bucket counter.
pub fn ratelimit(user: &str) -> String {
    format!("lattice:ratelimit:{user}")
}

/// `lattice:ratelimit:mqtt:{device}` per-device MQTT rate limit counter (design §17.13: 10 msg/s).
pub fn ratelimit_mqtt(device: &str) -> String {
    format!("lattice:ratelimit:mqtt:{device}")
}

/// `lattice:ratelimit:login:{scope}` failed-login counter (⑤ §1.1).
pub fn ratelimit_login(scope: &str) -> String {
    format!("lattice:ratelimit:login:{scope}")
}

/// `lattice:ratelimit:hub:{scope}:{user}` write operation counter for the plugin hub (⑤ §12 / design §17.16).
///
/// `scope` ∈ `publish|upload|sync`, mapping one-to-one to `details.reason` in ⑤ §12.
pub fn ratelimit_hub(scope: &str, user: &str) -> String {
    format!("lattice:ratelimit:hub:{scope}:{user}")
}

/// `lattice:risk` risk queue (ZSET, score = hit time).
pub fn risk() -> String {
    "lattice:risk".to_string()
}

// ---------------------------------------------------------------------------
// PubSub channels (**not keys**: no TTL, never matched by KEYS/SCAN, §8.2 / ⑥ §3.1)
// ---------------------------------------------------------------------------

/// `route.{node}`: cross-node delivery channel.
#[allow(non_snake_case)]
pub fn channel_route(node_id: &str) -> String {
    format!("route.{node_id}")
}

/// `lattice:online`: device-online event (drives redelivery).
#[allow(non_snake_case)]
pub fn channel_online() -> String {
    "lattice:online".to_string()
}

/// `lattice:cfg`: dynamic config hot-reload broadcast (authoritative value lives in PG `dynamic_config`).
#[allow(non_snake_case)]
pub fn channel_cfg() -> String {
    "lattice:cfg".to_string()
}

/// `lattice:mqtt:{topic}`: MQTT gateway real-time downstream channel (⑤ §11, cross-node real-time fan-out).
///
/// `topic` is a Lattice Topic name (one segment parsed out of `lattice/{topic}/{device}`),
/// and the payload is full `Envelope` protobuf bytes (binary-safe, requires a raw-bytes subscription).
#[allow(non_snake_case)]
pub fn channel_mqtt(topic: &str) -> String {
    format!("lattice:mqtt:{topic}")
}

/// Distributed lock task names (⑥ §2.6 / §6.4).
pub mod tasks {
    pub const CHUNK_CLEAN: &str = "chunk-clean";
    pub const PENDING_CLEAN: &str = "pending-clean";
    pub const DEDUP_CLEAN: &str = "dedup-clean";
    pub const SEQ_WATERMARK: &str = "seq-watermark";
    pub const RECONCILE: &str = "reconcile";
    pub const RECONCILE_SEQ: &str = "reconcile-seq";
    pub const PARTITION_MAINT: &str = "partition-maint";
    pub const DLQ_ARCHIVE: &str = "dlq-archive";
    pub const GC_MULTIPART: &str = "gc-multipart";
    pub const ARCHIVE: &str = "archive";
    pub const GC_OBJECTS: &str = "gc-objects";
    pub const RISK: &str = "risk";
    pub const SNAPSHOT: &str = "snapshot";
    /// Plugin hub: a `pending` draft with no package uploaded for over 30 minutes → `removed` (⑥ §2.6)
    pub const HUB_DRAFT_CLEAN: &str = "hub-draft-clean";
    /// Plugin hub: objects of `removed` versions are reclaimed after 30 days (⑥ §2.6)
    pub const HUB_OBJECT_GC: &str = "hub-object-gc";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_layout_matches_8_2() {
        assert_eq!(conn_user("u1"), "lattice:conn:u1");
        assert_eq!(conn_device("u1", "d1"), "lattice:conn:u1:d1");
        assert_eq!(pending_user("u1"), "lattice:pending:u1");
        assert_eq!(pending_device("u1", "d1"), "lattice:pending:u1:d1");
        assert_eq!(pending_topic("u1", "t1"), "lattice:pending:u1:topic:t1");
        assert_eq!(stream_session("s-1"), "lattice:stream:s-1");
        assert_eq!(dedup("01JABC"), "lattice:dedup:01JABC");
        assert_eq!(seq("c1"), "lattice:seq:c1");
        assert_eq!(sub("u1"), "lattice:sub:u1");
    }

    #[test]
    fn conn_keys_share_hash_tag() {
        // ⑥ §3.3: both key levels must land in the same slot → both carry the same {user} hash tag
        let a = conn_user("{u1}");
        let b = conn_device("{u1}", "d1");
        assert!(a.contains("{u1}") && b.contains("{u1}"));
    }

    #[test]
    fn channels_are_not_keys() {
        assert_eq!(channel_route("node-a"), "route.node-a");
        assert_eq!(channel_online(), "lattice:online");
        assert_eq!(channel_cfg(), "lattice:cfg");
        assert_eq!(channel_mqtt("release"), "lattice:mqtt:release");
        assert_eq!(ratelimit_mqtt("dev-1"), "lattice:ratelimit:mqtt:dev-1");
    }
}
