//! Node state: connection table, dynamic config snapshot, rate-limit buckets, dependency handles (② §2.1 shared task-domain state).
//!
//! The connection table is **process memory** (disposable): loss is recovered by client reconnects (② §2.1 "state data").
//! Cross-node visibility relies on Redis `conn:*`, not this table.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use lattice_core::{keys, Frame, WsCommand};

use crate::auth::{Claims, JwtKeys};
use crate::config::Config;
use crate::observe::Metrics;
use crate::store::{Bus, Redis, S3, Wal};
use crate::store::pg;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Device capability declaration (`hello.caps`, §17.10: capabilities follow hello; `GET /v1/users/{id}` is only a declaration).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Caps {
    #[serde(default)]
    pub formats: Vec<String>,
    #[serde(default)]
    pub compression: Vec<String>,
    #[serde(default)]
    pub e2e: bool,
    #[serde(default)]
    pub quic: bool,
    #[serde(default)]
    pub webrtc: bool,
}

/// **Reserved queue slots** for protected-set frames (⑤ §9.5).
///
/// Protected-set frames (`receipt`/`ack`/`stream-sig`/`byef`) take priority through this separate bounded channel,
/// so they can still enqueue when normal frames fill the 256-frame main queue; only a slow consumer that also fills the reserved channel
/// (64 protected frames cannot drain) falls back to the main queue/drop, counted separately + ERROR log.
pub const PROTECTED_QUEUE_FRAMES: usize = 64;

/// **Dual-channel outbox** for a single connection's downstream (⑤ §9.5 backpressure protection set).
///
/// Design points:
/// - **Normal frames** go only to the main channel (capacity 256; drop and count `lattice_backpressure_dropped_total` when full);
/// - **Protected-set frames** prefer the reserved channel, unaffected by a full main queue; when the reserved channel is also full they fall back to the main channel,
///   and are dropped only when both are full — drops count `lattice_backpressure_protected_dropped_total` and log ERROR
///   (protected frames must never be dropped silently);
/// - `try_send` is non-blocking throughout: pipeline/routing hot paths never wait for a slow consumer (⑤ §9.5).
///
/// The read side drains via [`OutboxReceiver`] with "protected channel first", so protected frames accumulated while the queue was full
/// reach the slow client before normal frames once it resumes reading.
pub struct Outbox {
    normal: mpsc::Sender<Frame>,
    protected: mpsc::Sender<Frame>,
    /// Metrics needed for drop counters; injected by `Hub::register` after `Hub::default()` is built.
    metrics: RwLock<Option<Arc<Metrics>>>,
}

impl Outbox {
    fn set_metrics(&self, metrics: Arc<Metrics>) {
        if let Ok(mut w) = self.metrics.write() {
            *w = Some(metrics);
        }
    }

    fn metrics_handle(&self) -> Option<Arc<Metrics>> {
        self.metrics.read().ok().and_then(|r| r.clone())
    }

    /// Non-blocking delivery. Returns `true` when enqueued (either channel), `false` when dropped per backpressure policy.
    pub fn try_send(&self, frame: Frame) -> bool {
        // OTel (E22): downstream enqueue stage span (cmd + envelope correlation fields; no-op when the feature is off).
        let __otel_enqueue = crate::observe::otel::deliver_span("enqueue", &frame, None);
        let cmd = frame.cmd.as_str();
        if frame.cmd.is_protected_under_backpressure() {
            return match self.protected.try_send(frame) {
                Ok(()) => true,
                // The reserved channel is also full: best-effort fallback to the main channel (usually even fuller, but may still drain).
                Err(mpsc::error::TrySendError::Full(frame)) => match self.normal.try_send(frame) {
                    Ok(()) => true,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        if let Some(m) = self.metrics_handle() {
                            m.backpressure_dropped_total
                                .with_label_values(&[cmd])
                                .inc();
                            m.backpressure_protected_dropped_total
                                .with_label_values(&[cmd])
                                .inc();
                        }
                        // Dropping a protected-set frame breaks the contract (⑤ §9.5): it must be observable via ERROR, never silent.
                        tracing::error!(
                            cmd,
                            "protected frame dropped under backpressure (reserved+normal queues full)"
                        );
                        // OTel (E22): "collect all errors" drill point — dropping a protected frame is an error, separate ERROR span.
                        crate::observe::otel::record_error("ws.backpressure", "protected_frame_dropped");
                        false
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => false,
                },
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            };
        }
        match self.normal.try_send(frame) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                if let Some(m) = self.metrics_handle() {
                    m.backpressure_dropped_total
                        .with_label_values(&[cmd])
                        .inc();
                }
                tracing::debug!(cmd, "backpressure drop");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

/// Read end of [`Outbox`]: **protected channel first**, then the main channel.
pub struct OutboxReceiver {
    normal: mpsc::Receiver<Frame>,
    protected: mpsc::Receiver<Frame>,
}

impl OutboxReceiver {
    /// Take the next frame to write (protected set first). Returns `None` when both channels are closed.
    pub async fn recv(&mut self) -> Option<Frame> {
        let mut normal_open = true;
        let mut protected_open = true;
        loop {
            match (protected_open, normal_open) {
                // Both are live: `biased` lets protected frames dequeue first (they have the lowest delay tolerance when queues are full).
                (true, true) => {
                    tokio::select! {
                        biased;
                        p = self.protected.recv() => match p {
                            Some(f) => return Some(f),
                            None => protected_open = false,
                        },
                        n = self.normal.recv() => match n {
                            Some(f) => return Some(f),
                            None => normal_open = false,
                        },
                    }
                }
                (true, false) => match self.protected.recv().await {
                    Some(f) => return Some(f),
                    None => protected_open = false,
                },
                (false, true) => match self.normal.recv().await {
                    Some(f) => return Some(f),
                    None => normal_open = false,
                },
                (false, false) => return None,
            }
        }
    }

    /// Non-blocking take (unit tests/diagnostics): protected channel first.
    pub fn try_recv(&mut self) -> std::result::Result<Frame, mpsc::error::TryRecvError> {
        match self.protected.try_recv() {
            Ok(f) => Ok(f),
            Err(mpsc::error::TryRecvError::Empty) => self.normal.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected) => match self.normal.try_recv() {
                Err(mpsc::error::TryRecvError::Empty) => {
                    Err(mpsc::error::TryRecvError::Disconnected)
                }
                other => other,
            },
        }
    }
}

/// One active connection.
pub struct Conn {
    pub id: u64,
    pub user: String,
    pub device: String,
    /// Downstream corridor; main queue capacity = 256 frames (§17.13 backpressure), protected-set frames have a reserved channel (⑤ §9.5)
    pub tx: Outbox,
    pub caps: Caps,
    pub connected_at: Instant,
    pub remote_ip: String,
    pub protocol: u8,
    pub node_id: String,
}

/// Connection registry (in-process; the equivalent of `dashmap`: RwLock + HashMap).
#[derive(Default)]
pub struct Hub {
    conns: RwLock<HashMap<u64, Arc<Conn>>>,
    next_id: AtomicU64,
    /// Metrics needed for drop counters; injected by `node::build` after `Hub::default()`.
    metrics: RwLock<Option<Arc<crate::observe::Metrics>>>,
}

impl Hub {
    /// Inject metrics (⑤ §9.5 requires backpressure drops to be counted, so the drop path holds the metrics handle).
    pub fn set_metrics(&self, metrics: Arc<crate::observe::Metrics>) {
        if let Ok(mut w) = self.metrics.write() {
            *w = Some(metrics);
        }
    }

    fn metrics_handle(&self) -> Option<Arc<crate::observe::Metrics>> {
        self.metrics.read().ok().and_then(|r| r.clone())
    }

    pub fn register(&self, mut conn: Conn) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        conn.id = id;
        // Backpressure drops must be counted (⑤ §9.5): inject the metrics handle into the connection outbox on registration.
        if let Some(m) = self.metrics_handle() {
            conn.tx.set_metrics(m);
        }
        let arc = Arc::new(conn);
        if let Ok(mut w) = self.conns.write() {
            w.insert(id, arc);
        }
        id
    }

    pub fn unregister(&self, id: u64) -> Option<Arc<Conn>> {
        self.conns.write().ok().and_then(|mut w| w.remove(&id))
    }

    pub fn get(&self, id: u64) -> Option<Arc<Conn>> {
        self.conns.read().ok().and_then(|r| r.get(&id).cloned())
    }

    pub fn all(&self) -> Vec<Arc<Conn>> {
        self.conns
            .read()
            .map(|r| r.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn of_user(&self, user: &str) -> Vec<Arc<Conn>> {
        self.all().into_iter().filter(|c| c.user == user).collect()
    }

    pub fn user_conn_count(&self, user: &str) -> usize {
        self.of_user(user).len()
    }

    pub fn ip_conn_count(&self, ip: &str) -> usize {
        self.all().iter().filter(|c| c.remote_ip == ip).count()
    }

    pub fn len(&self) -> usize {
        self.conns.read().map(|r| r.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Targeted delivery (§17.4-5: when `to_devices` is non-empty, deliver only to the listed devices).
    pub fn send_to_device(&self, user: &str, device: &str, frame: Frame) -> bool {
        // OTel (E22): WS/topic delivery stage 2/3 — targeted delivery by device (envelope_id decoded from the frame for correlation).
        let __otel = crate::observe::otel::deliver_span("device", &frame, Some(user));
        let hit: Vec<Arc<Conn>> = self
            .of_user(user)
            .into_iter()
            .filter(|c| c.device == device)
            .collect();
        let mut sent = false;
        for c in hit {
            if c.tx.try_send(frame.clone()) {
                sent = true;
            }
        }
        crate::observe::otel::finish_deliver(__otel, usize::from(sent));
        sent
    }

    /// Deliver to all devices (§17.4-1 default).
    pub fn send_to_user(&self, user: &str, frame: Frame) -> usize {
        // OTel (E22): WS/topic delivery stage 3/3 — fan out to all devices (low-cardinality user hash + envelope_id).
        let __otel = crate::observe::otel::deliver_span("user", &frame, Some(user));
        let n = self
            .of_user(user)
            .into_iter()
            .filter(|c| c.tx.try_send(frame.clone()))
            .count();
        crate::observe::otel::finish_deliver(__otel, n);
        n
    }

    pub fn send_to_node_conn(&self, conn_id_hint: &str, frame: Frame) -> usize {
        // OTel (E22): fallback delivery stage (hit this node's connection by device/username hint).
        let __otel = crate::observe::otel::deliver_span("conn", &frame, Some(conn_id_hint));
        let n = self
            .all()
            .into_iter()
            .filter(|c| c.device == conn_id_hint || c.user == conn_id_hint)
            .filter(|c| c.tx.try_send(frame.clone()))
            .count();
        crate::observe::otel::finish_deliver(__otel, n);
        n
    }
}

/// **Short-term positive cache** used while PG is unavailable (② §4.8 WAL degradation companion).
///
/// When PG is unavailable as a whole (connection dropped/timeout, not just write failures), the message pipeline's membership checks/`to_user` default
/// member list reads fail first, before `insert_message` can write the WAL. This caches only facts **previously verified true against authoritative PG values**,
/// and uses them only within a determinable PG-unavailable window + TTL; expired or never-verified
/// relationships are always rejected (no forging new authorization from cache).
pub struct PgDegradeCache {
    ttl: Duration,
    cap: usize,
    /// "{conv}\u{0}{user}" -> last verification time
    members: Mutex<HashMap<String, Instant>>,
    /// conv_id -> (member user_id list, cache time)
    conv_members: Mutex<HashMap<String, (Vec<String>, Instant)>>,
}

/// Degradation cache TTL: covers the "brief PG flapping/failover" window; beyond the TTL, wait for PG recovery.
pub const PG_DEGRADE_CACHE_TTL: Duration = Duration::from_secs(300);
/// Degradation cache capacity limit (conversations/relationships): clear when exceeded, approximate LRU (cache loss only makes degradation more conservative).
pub const PG_DEGRADE_CACHE_CAP: usize = 10_000;

impl PgDegradeCache {
    pub fn new(ttl: Duration, cap: usize) -> Self {
        PgDegradeCache {
            ttl,
            cap: cap.max(64),
            members: Mutex::new(HashMap::new()),
            conv_members: Mutex::new(HashMap::new()),
        }
    }

    fn member_key(conv: &str, user: &str) -> String {
        format!("{conv}\u{0}{user}")
    }

    pub fn remember_member(&self, conv: &str, user: &str) {
        if let Ok(mut m) = self.members.lock() {
            if m.len() >= self.cap {
                m.clear();
            }
            m.insert(Self::member_key(conv, user), Instant::now());
        }
    }

    pub fn is_member(&self, conv: &str, user: &str) -> bool {
        self.members
            .lock()
            .ok()
            .and_then(|m| m.get(&Self::member_key(conv, user)).copied())
            .is_some_and(|at| at.elapsed() < self.ttl)
    }

    pub fn remember_members(&self, conv: &str, users: Vec<String>) {
        if let Ok(mut m) = self.conv_members.lock() {
            if m.len() >= self.cap {
                m.clear();
            }
            m.insert(conv.to_string(), (users, Instant::now()));
        }
    }

    pub fn members(&self, conv: &str) -> Option<Vec<String>> {
        self.conv_members.lock().ok().and_then(|m| {
            m.get(conv)
                .filter(|(_, at)| at.elapsed() < self.ttl)
                .map(|(users, _)| users.clone())
        })
    }
}

impl Default for PgDegradeCache {
    fn default() -> Self {
        Self::new(PG_DEGRADE_CACHE_TTL, PG_DEGRADE_CACHE_CAP)
    }
}

/// Session membership **positive cache** (PL-17 bottleneck fix: the message hot path did 2 PG membership queries per message).
///
/// Design conventions (**no forged authorization**):
/// - Cache only facts **verified true against authoritative PG values**: `(conv,user)` membership, `conv` member lists;
///   misses/expiry always go back to PG for re-verification; when PG says "not a member", **do not cache** (no negative cache).
/// - The short TTL (`[policy] member_cache_ttl_ms`, default 1000ms) is only a fallback window: after PG recovery/flapping,
///   or when the DB is modified directly (external psql), stale authorization lives at most one extra TTL.
/// - Membership mutation endpoints (join/remove/leave/subscription change) **actively invalidate** the corresponding `conv` (see
///   the `transport/http.rs` hooks), so the normal path does not rely on TTL to converge permissions.
/// - The degraded authorization used when PG is fully unavailable still goes through [`PgDegradeCache`] (5-minute positive cache, ② §4.8),
///   with no overlap: this cache is used only on the PG-available path.
pub struct MemberCache {
    ttl: Duration,
    cap: usize,
    /// "{conv}\u{0}{user}" -> last time PG verified membership
    members: Mutex<HashMap<String, Instant>>,
    /// conv_id -> (member user_id list, cache time)
    conv_members: Mutex<HashMap<String, (Vec<String>, Instant)>>,
}

/// Membership cache capacity limit (relationships/conversations counted separately): clear when exceeded, approximate LRU.
/// Cache loss only sends requests back to PG (correctness unaffected), so precise eviction is unnecessary.
pub const MEMBER_CACHE_CAP: usize = 50_000;

impl MemberCache {
    pub fn new(ttl: Duration, cap: usize) -> Self {
        MemberCache {
            ttl,
            cap: cap.max(64),
            members: Mutex::new(HashMap::new()),
            conv_members: Mutex::new(HashMap::new()),
        }
    }

    /// TTL=0 explicitly disables the cache (everything goes to PG; for regression/control, do not silently change semantics in production).
    pub fn enabled(&self) -> bool {
        !self.ttl.is_zero()
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    fn member_key(conv: &str, user: &str) -> String {
        format!("{conv}\u{0}{user}")
    }

    /// Record one `(conv,user)` relationship verified true by PG.
    pub fn remember_member(&self, conv: &str, user: &str) {
        if !self.enabled() {
            return;
        }
        if let Ok(mut m) = self.members.lock() {
            if m.len() >= self.cap {
                m.clear();
            }
            m.insert(Self::member_key(conv, user), Instant::now());
        }
    }

    /// Whether an **unexpired** positive cache entry hits (a hit can skip PG's two queries: conversation existence + role).
    pub fn is_member(&self, conv: &str, user: &str) -> bool {
        if !self.enabled() {
            return false;
        }
        self.members
            .lock()
            .ok()
            .and_then(|m| m.get(&Self::member_key(conv, user)).copied())
            .is_some_and(|at| at.elapsed() < self.ttl)
    }

    /// Record a member list returned by PG (positive cache).
    pub fn remember_members(&self, conv: &str, users: Vec<String>) {
        if !self.enabled() {
            return;
        }
        if let Ok(mut m) = self.conv_members.lock() {
            if m.len() >= self.cap {
                m.clear();
            }
            m.insert(conv.to_string(), (users, Instant::now()));
        }
    }

    /// Hit an unexpired member list cache entry.
    pub fn members(&self, conv: &str) -> Option<Vec<String>> {
        if !self.enabled() {
            return None;
        }
        self.conv_members.lock().ok().and_then(|m| {
            m.get(conv)
                .filter(|(_, at)| at.elapsed() < self.ttl)
                .map(|(users, _)| users.clone())
        })
    }

    /// Actively invalidate **all** caches for a conversation (membership + member list): join/remove/leave/delete/subscription change.
    pub fn invalidate_conv(&self, conv: &str) {
        let prefix = format!("{conv}\u{0}");
        if let Ok(mut m) = self.members.lock() {
            m.retain(|k, _| !k.starts_with(&prefix));
        }
        if let Ok(mut m) = self.conv_members.lock() {
            m.remove(conv);
        }
    }

    /// Actively invalidate a single `(conv,user)` relationship (e.g. only this user leaves; the caller decides whether to clear the member list).
    pub fn invalidate_member(&self, conv: &str, user: &str) {
        if let Ok(mut m) = self.members.lock() {
            m.remove(&Self::member_key(conv, user));
        }
    }
}

impl Default for MemberCache {
    fn default() -> Self {
        Self::new(
            Duration::from_millis(crate::config::DEFAULT_MEMBER_CACHE_TTL_MS),
            MEMBER_CACHE_CAP,
        )
    }
}

/// State shared by all nodes.
pub struct AppState {
    pub cfg: Config,
    pub node_id: String,
    pub db: pg::Pool,
    /// Dedicated admin pool (slow queries do not block the message plane, ② §2.1)
    pub admin_db: pg::Pool,
    pub redis: Redis,
    pub s3: S3,
    pub bus: Arc<dyn Bus>,
    pub wal: Wal,
    /// Short-term positive cache used while PG is unavailable (② §4.8 WAL degradation companion: membership check/member list degradation).
    pub pg_degrade: PgDegradeCache,
    /// Session membership short-TTL positive cache (PL-17 bottleneck fix; membership mutation endpoints actively invalidate, TTL as fallback).
    pub member_cache: MemberCache,
    /// WAL replay in-process lock: startup catch-up and periodic tasks do not overlap (cross-node exclusion uses `lock:wal-replay`).
    pub wal_replay_lock: tokio::sync::Mutex<()>,
    pub hub: Arc<Hub>,
    pub metrics: Arc<Metrics>,
    /// Risk control rule engine (E03 / PL-12; `[risk] enabled=false` by default = zero collection, zero tasks).
    ///
    /// Hot-path hooks: `pipeline::ingest` (message frequency/rate limit), `verify_jwt` (auth failures),
    /// `register_online` (device switch). Match actions run in background tasks (audit/Redis/revocation),
    /// never blocking the message path; lifecycle and boundaries are in the `routing/risk.rs` module docs.
    pub risk: Arc<crate::routing::risk::RiskEngine>,
    /// Console live snapshots (⑤ §8.5 push source, refreshed every second by `live::spawn`)
    pub live: Arc<crate::live::Live>,
    /// JWT key snapshot (§17.11 dual-key overlap rotation): rotation swaps in a new `Arc<JwtKeys>` wholesale.
    ///
    /// Read-heavy, rarely written: auth/signing clone the `Arc` under the lock and release it immediately,
    /// **never holding the lock across await**; writers are admin rotate and the previous-key expiry cleanup task.
    pub jwt: RwLock<Arc<JwtKeys>>,
    /// Key write serialization lock (rotate and prune both touch disk + memory and must be mutually exclusive; admin operations are infrequent).
    pub key_rotate_lock: tokio::sync::Mutex<()>,
    /// Dynamic config snapshot (authoritative values in PG `dynamic_config`, ⑤ §8.4 / ⑥ D12)
    pub dynamic: RwLock<HashMap<String, serde_json::Value>>,
    /// Plugin runtime snapshot (in-memory view of the `plugins` table, used for canary decisions, ② §4.5)
    pub plugins: RwLock<Vec<lattice_plugins::registry::PluginEntry>>,
    /// In-process rate-limit buckets (fallback when Redis is unavailable, ② §4.8)
    pub rate_buckets: Mutex<HashMap<String, crate::store::redis::LocalBucket>>,
    /// Byte rate-limit bucket (§17.13 25MB/s; separate from the message-count bucket so one large message does not consume the count quota).
    pub byte_buckets: Mutex<HashMap<String, crate::store::redis::LocalBucket>>,
    /// Per-tunnel media bitrate token bucket (design §17.9; in-process, cleaned up with the session).
    pub stream_buckets: Mutex<HashMap<String, crate::routing::media::StreamBucket>>,
    /// Media recording side-path delivery handle (PL-13 13.6 minimal verifiable version).
    ///
    /// `None` when `[media] record_enabled=false` (default): `on_data` does not even write to the channel once.
    /// When enabled, `on_data` only `try_send`s (bounded queue 1024, dropped and counted when full), and the background recorder task
    /// aggregates segments by stream_id into MinIO; boundaries (records only raw WS tunnel frames, no muxing/playback/NATS)
    /// are in the recording module comment at the top of `routing/media.rs`.
    pub recorder: Option<Arc<crate::routing::media::MediaRecorder>>,
    /// **Connection pool/relay registry** of the QUIC server proxy skeleton (PL-13 13.3; design §17.9 path ②).
    ///
    /// Exists only under the compile-time `quic` feature: `None` when `[quic] enabled=false` (default) or the feature is off,
    /// with no UDP socket, no spawned tasks, and zero impact on existing WS/media paths.
    #[cfg(feature = "quic")]
    pub quic: Option<Arc<crate::transport::quic::QuicProxy>>,
    /// WebTransport (HTTP/3) browser access gateway (PL-13 13.3; design §17.9 path ②).
    ///
    /// Exists only under the compile-time `webtransport` feature: `None` when `[webtransport] enabled=false` (default) or the feature
    /// is off; no UDP/TLS listener, no spawned tasks, no certificates loaded.
    /// The gateway bridges WT bidirectional streams to `self.quic` (local QUIC listener), reusing auth/TLV/relay/rate limiting.
    #[cfg(feature = "webtransport")]
    pub webtransport: Option<Arc<crate::transport::webtransport::WebTransportProxy>>,
    /// Online routing stale cache: `user -> (device->node, cached_at)`. When Redis reads fail, cached cross-node
    /// delivery is allowed (② §4.1), TTL 120s; hits emit metric alerts.
    pub route_cache: RwLock<HashMap<String, (HashMap<String, String>, Instant)>>,
    pub ready: AtomicBool,
    pub started_at: Instant,
    pub draining: AtomicBool,
}

impl AppState {
    /// Take the JWT key snapshot (release the read lock immediately after cloning the `Arc`; never hold it across await).
    ///
    /// On lock poisoning (a holding writer panicked), take the inner value and keep serving: keys are read-only data,
    /// not worth rejecting all authentication over one panic.
    pub fn jwt_keys(&self) -> Arc<JwtKeys> {
        self.jwt
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Swap in a new JWT key snapshot (admin rotate / previous-key expiry cleanup).
    pub fn install_jwt_keys(&self, keys: JwtKeys) {
        let mut guard = self
            .jwt
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Arc::new(keys);
    }

    /// Unified verification entry (shared by REST/WS): snapshot + failure-reason metrics
    /// `lattice_key_verification_failures_total{reason}`.
    pub fn verify_jwt(&self, token: &str) -> crate::error::Result<Claims> {
        let keys = self.jwt_keys();
        match keys.verify(token) {
            Ok(claims) => Ok(claims),
            Err(e) => {
                let reason = e
                    .details
                    .as_ref()
                    .and_then(|d| d.get("reason"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("other");
                self.metrics
                    .key_verification_failures_total
                    .with_label_values(&[reason])
                    .inc();
                // OTel (E22): auth failure is an error span (100% error sampling drill point; carries only the reason code,
                // never tokens/request bodies).
                crate::observe::otel::record_error("auth.verify_jwt", reason);
                // Risk rule c: auth-failure surge (401 class; global window, no identity). Zero side effects when disabled.
                self.risk.note_auth_failure(reason);
                Err(e)
            }
        }
    }

    pub fn quota(&self) -> lattice_core::Quota {
        self.cfg.quota()
    }

    pub fn mode(&self) -> lattice_core::Mode {
        self.cfg.mode()
    }

    /// Membership cache hit/miss metrics (`lattice_member_cache_total{result=hit|miss}`).
    ///
    /// No metrics when the cache is disabled by config (TTL=0): otherwise metrics would misread "cache off" as 100% miss.
    pub fn note_member_cache(&self, hit: bool) {
        if !self.member_cache.enabled() {
            return;
        }
        self.metrics
            .member_cache_total
            .with_label_values(&[if hit { "hit" } else { "miss" }])
            .inc();
    }

    /// **Actively invalidate** a conversation's membership caches (membership + member list) and count
    /// `lattice_member_cache_total{result=invalidate}`.
    ///
    /// Call only from endpoints where membership truly changes (join/remove/leave/conversation delete/topic subscription change),
    /// see the hooks in `transport/http.rs`; do not call from normal read paths.
    pub fn invalidate_member_cache(&self, conv: &str) {
        if self.member_cache.enabled() {
            self.member_cache.invalidate_conv(conv);
            self.metrics
                .member_cache_total
                .with_label_values(&["invalidate"])
                .inc();
        }
    }

    /// Whether PG is in a local circuit-breaker window (only means "a determinable unavailability occurred recently"; not authoritative health).
    ///
    /// Circuit-breaker state lives in process-level atomics in `store::pg`: once the message plane (WAL degradation) sets it,
    /// hot-path reads/writes in the `pg` layer (delivery log/watermark, etc.) fail fast instead of waiting for a pool timeout per message.
    pub fn pg_degraded(&self) -> bool {
        pg::is_degraded()
    }

    /// Record one determinable PG unavailability (connection/timeout/pool exhaustion…), opening/extending the circuit-breaker window.
    pub fn mark_pg_down(&self) {
        pg::note_degraded();
    }

    /// PG has recovered (WAL replay/liveness probe succeeded): close the circuit-breaker window.
    pub fn mark_pg_up(&self) {
        pg::note_healthy();
    }

    /// Read dynamic config (falling back to static values).
    pub fn dyn_u64(&self, key: &str, fallback: u64) -> u64 {
        self.dynamic
            .read()
            .ok()
            .and_then(|m| m.get(key).cloned())
            .and_then(|v| v.as_u64())
            .unwrap_or(fallback)
    }

    pub fn dyn_bool(&self, key: &str, fallback: bool) -> bool {
        self.dynamic
            .read()
            .ok()
            .and_then(|m| m.get(key).cloned())
            .and_then(|v| v.as_bool())
            .unwrap_or(fallback)
    }

    /// Per-user rate limiting (100 msg/s default, §17.13).
    pub fn allow_msg(&self, user: &str) -> bool {
        let limit = self.dyn_u64("ratelimit.msg_per_s", self.cfg.policy.msg_per_s as u64);
        let mut buckets = match self.rate_buckets.lock() {
            Ok(b) => b,
            Err(_) => return true,
        };
        buckets.entry(user.to_string()).or_default().allow(limit)
    }

    /// Per-user **byte** rate limiting (§17.13 default 25MB/s; `ratelimit.bytes_per_s=0` disables).
    ///
    /// Bucketed separately from `allow_msg`: a 1MB message consumes 1 message quota but 1MB of byte quota.
    pub fn allow_bytes(&self, user: &str, bytes: u64) -> bool {
        let limit = self.dyn_u64("ratelimit.bytes_per_s", self.cfg.policy.bytes_per_s);
        if limit == 0 {
            return true;
        }
        let mut buckets = match self.byte_buckets.lock() {
            Ok(b) => b,
            Err(_) => return true,
        };
        buckets.entry(user.to_string()).or_default().allow_weight(limit, bytes.max(1))
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Connection registration: local table + two-layer Redis keys (② §4.1 write path).
    pub async fn register_online(&self, user: &str, device: &str) -> crate::error::Result<()> {
        // Risk rule b: many new devices/device switches on one account in a short time (WS hello online registration is the hook point).
        // Zero side effects when disabled; when enabled it is one in-memory operation, no Redis/audit (the background task acts).
        self.risk.note_device_online(user, device);
        let ttl = self.cfg.policy.conn_ttl;
        if let Err(e) = self.redis.register_conn(user, device, &self.node_id, ttl).await {
            tracing::warn!(error = %e, "redis register failed (degraded: local only)");
        }
        self.metrics
            .connections
            .with_label_values(&["ws", "open"])
            .inc();
        Ok(())
    }

    pub async fn unregister_online(&self, user: &str, device: &str) {
        if let Err(e) = self.redis.unregister_conn(user, device).await {
            tracing::warn!(error = %e, "redis unregister failed");
        }
        self.metrics
            .connections
            .with_label_values(&["ws", "open"])
            .dec();
    }

    /// Online devices of a target user → node (basis for cross-node routing).
    pub async fn online_devices(&self, user: &str) -> HashMap<String, String> {
        // OTel (E22): route resolution stage span (low-cardinality user hash; no-op when the feature is off).
        // Part of the same span chain as the preceding pipeline.ingest span and the following Hub delivery span.
        let _otel_route = crate::observe::otel::route_resolve_span(user);
        const STALE_TTL: std::time::Duration = std::time::Duration::from_secs(120);
        // When Redis is half-dead (connection alive but unresponsive), downstream routing must not hang forever: 500ms cap;
        // timeouts are treated as read failures and fall back to the stale cache / local hub (② §4.1).
        const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
        let read = match tokio::time::timeout(READ_TIMEOUT, self.redis.conn_devices(user)).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!(user, "redis conn read timed out after 500ms; fallback to stale/local route");
                Err(crate::error::internal("redis conn read timeout"))
            }
        };
        match read {
            Ok(m) => {
                if let Ok(mut cache) = self.route_cache.write() {
                    cache.retain(|_, (_, at)| at.elapsed() < STALE_TTL);
                    // Capacity bound uses the configured route_cache (default 100k); when exceeded, approximate clearing of the oldest is fine;
                    // keep it simple here: above capacity, keep only the most recent 1/2 (avoid sorting on the hot path).
                    let cap = self.cfg.redis.route_cache.max(64);
                    if cache.len() >= cap {
                        let keep = cap / 2;
                        let mut entries: Vec<_> = cache.drain().collect();
                        entries.sort_by_key(|(_, (_, at))| std::cmp::Reverse(*at));
                        for (k, v) in entries.into_iter().take(keep) {
                            cache.insert(k, v);
                        }
                    }
                    cache.insert(user.to_string(), (m.clone(), std::time::Instant::now()));
                }
                m
            }
            Err(e) => {
                if let Ok(cache) = self.route_cache.read() {
                    if let Some((m, at)) = cache.get(user) {
                        if at.elapsed() < STALE_TTL && !m.is_empty() {
                            self.metrics.route_cache_stale_total.inc();
                            tracing::warn!(
                                error = %e,
                                user,
                                devices = m.len(),
                                "redis conn read failed; using stale route cache (allow cached cross-node)"
                            );
                            return m.clone();
                        }
                    }
                }
                tracing::warn!(error = %e, "redis conn read failed, fallback to local hub");
                self.hub
                    .of_user(user)
                    .into_iter()
                    .map(|c| (c.device.clone(), self.node_id.clone()))
                    .collect()
            }
        }
    }

    pub fn node_channel(&self) -> String {
        keys::channel_route(&self.node_id)
    }

    /// Node heartbeat (§17.8 `lattice:node:{id}` EX 10s).
    ///
    /// `heartbeat_at`/`health` were added in v0.13: the console's "server nodes" page must show
    /// "last heartbeat" and health, while Redis TTL only yields remaining seconds, not an absolute time.
    pub async fn heartbeat(&self) {
        let mut info = serde_json::json!({
            "node_id": self.node_id,
            "version": VERSION,
            "connections": self.hub.len(),
            "protocol_version": self.cfg.policy.protocol_version,
            "started_at": self.started_at.elapsed().as_secs(),
            "health": "ok",
            "heartbeat_at": chrono::Utc::now(),
        });
        // Announce the gRPC address to other nodes: gRPC fallback routing discovers peers from node heartbeats (⑤ §10).
        // Empty values omit the field for old-heartbeat compatibility (upgrade order does not matter).
        if !self.cfg.grpc.advertise.is_empty() {
            info["grpc_addr"] = serde_json::Value::String(self.cfg.grpc.advertise.clone());
            info["grpc_tls"] = serde_json::Value::Bool(!self.cfg.grpc.tls_cert.is_empty());
        }
        let info = info.to_string();
        if let Err(e) = self
            .redis
            .heartbeat_node(&self.node_id, &info, lattice_core::protocol::NODE_HEARTBEAT_TTL_SECS)
            .await
        {
            tracing::warn!(error = %e, "node heartbeat failed");
        }
    }
}

/// Downstream queue capacity (§17.13: 256 frames per connection) + reserved protected-set channel (⑤ §9.5).
pub fn conn_channel() -> (Outbox, OutboxReceiver) {
    conn_channel_with_capacity(lattice_core::protocol::BACKPRESSURE_QUEUE_FRAMES)
}

/// Constructor with a specified main queue capacity (unit tests use a small capacity to fill quickly; the protected channel capacity is fixed).
pub fn conn_channel_with_capacity(normal_cap: usize) -> (Outbox, OutboxReceiver) {
    let (tx, rx) = mpsc::channel(normal_cap);
    let (ptx, prx) = mpsc::channel(PROTECTED_QUEUE_FRAMES);
    (
        Outbox {
            normal: tx,
            protected: ptx,
            metrics: RwLock::new(None),
        },
        OutboxReceiver {
            normal: rx,
            protected: prx,
        },
    )
}

/// Graceful shutdown signal (`byef reason=shutdown`, ② §3.1).
pub fn shutdown_frame(reason: &str) -> Frame {
    let body = serde_json::json!({ "reason": reason }).to_string();
    Frame::new(WsCommand::Byef, bytes::Bytes::from(body))
}

pub const DEFAULT_TICK: Duration = Duration::from_millis(250);

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn conn(user: &str, device: &str, cap: usize) -> (Conn, OutboxReceiver) {
        let (tx, rx) = conn_channel_with_capacity(cap);
        (
            Conn {
                id: 0,
                user: user.into(),
                device: device.into(),
                tx,
                caps: Caps::default(),
                connected_at: Instant::now(),
                remote_ip: "203.0.113.7".into(),
                protocol: 1,
                node_id: "node-a".into(),
            },
            rx,
        )
    }

    #[test]
    fn hub_routes_to_user_and_device() {
        let hub = Hub::default();
        let (c1, mut rx1) = conn("u1", "d1", 4);
        let (c2, mut rx2) = conn("u1", "d2", 4);
        hub.register(c1);
        hub.register(c2);
        assert_eq!(hub.user_conn_count("u1"), 2);

        let f = Frame::new(WsCommand::Ack, Bytes::from_static(b"{}"));
        assert_eq!(hub.send_to_user("u1", f.clone()), 2);
        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());

        assert!(hub.send_to_device("u1", "d2", f.clone()));
        assert!(rx2.try_recv().is_ok());
        assert!(rx1.try_recv().is_err());
    }

    #[test]
    fn hub_reports_backpressure_instead_of_blocking() {
        let hub = Hub::default();
        let (c, _rx) = conn("u1", "d1", 1);
        hub.register(c);
        assert!(hub.send_to_user("u1", Frame::new(WsCommand::Ping, Bytes::new())) == 1);
        // Queue full → drop and return 0, without blocking
        assert_eq!(hub.send_to_user("u1", Frame::new(WsCommand::Ping, Bytes::new())), 0);
    }

    #[test]
    fn protected_frames_survive_full_normal_queue_and_are_drained_first() {
        let hub = Hub::default();
        let metrics = Metrics::new();
        hub.set_metrics(metrics.clone());
        let (c, mut rx) = conn("u1", "d1", 1);
        hub.register(c);

        // Main queue (capacity 1) is full: normal frames may be dropped
        assert_eq!(hub.send_to_user("u1", Frame::new(WsCommand::Ping, Bytes::new())), 1);
        assert_eq!(hub.send_to_user("u1", Frame::new(WsCommand::Ping, Bytes::new())), 0);
        // Protected-set frames (receipt) must still enqueue when the main queue is full (⑤ §9.5)
        assert_eq!(
            hub.send_to_user("u1", Frame::new(WsCommand::Receipt, Bytes::from_static(b"{}"))),
            1
        );
        assert_eq!(
            metrics
                .backpressure_dropped_total
                .with_label_values(&["receipt"])
                .get(),
            0,
            "protected-set frames must not count as normal backpressure drops"
        );
        assert_eq!(
            metrics
                .backpressure_protected_dropped_total
                .with_label_values(&["receipt"])
                .get(),
            0
        );
        assert!(
            metrics
                .backpressure_dropped_total
                .with_label_values(&["ping"])
                .get()
                >= 1,
            "dropping normal frames must be counted"
        );

        // Read side prefers the protected channel: receipt first, then normal ping
        assert_eq!(rx.try_recv().unwrap().cmd, WsCommand::Receipt);
        assert_eq!(rx.try_recv().unwrap().cmd, WsCommand::Ping);
    }

    #[tokio::test]
    async fn protected_drops_are_counted_separately_when_reserved_queue_also_full() {
        let hub = Hub::default();
        let metrics = Metrics::new();
        hub.set_metrics(metrics.clone());
        let (c, _rx) = conn("u1", "d1", 1);
        hub.register(c);

        // Main queue full + reserved channel full (64 protected frames backlogged)
        assert_eq!(hub.send_to_user("u1", Frame::new(WsCommand::Ping, Bytes::new())), 1);
        for _ in 0..PROTECTED_QUEUE_FRAMES {
            assert_eq!(
                hub.send_to_user("u1", Frame::new(WsCommand::Receipt, Bytes::from_static(b"{}"))),
                1,
                "protected frames must enqueue before the reserved channel is full"
            );
        }
        // Reserved channel + main queue both full → protected frames are dropped, counted separately (not silent)
        assert_eq!(
            hub.send_to_user("u1", Frame::new(WsCommand::Receipt, Bytes::from_static(b"{}"))),
            0
        );
        assert_eq!(
            metrics
                .backpressure_protected_dropped_total
                .with_label_values(&["receipt"])
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn outbox_receiver_prefers_protected_channel() {
        let (tx, mut rx) = conn_channel_with_capacity(4);
        assert!(tx.try_send(Frame::new(WsCommand::Ping, Bytes::new())));
        assert!(tx.try_send(Frame::new(WsCommand::Receipt, Bytes::new())));
        assert!(tx.try_send(Frame::new(WsCommand::Envelope, Bytes::new())));
        assert_eq!(rx.recv().await.unwrap().cmd, WsCommand::Receipt);
        let rest: Vec<WsCommand> = vec![
            rx.recv().await.unwrap().cmd,
            rx.recv().await.unwrap().cmd,
        ];
        assert_eq!(rest, vec![WsCommand::Ping, WsCommand::Envelope]);
        drop(tx);
        assert!(rx.recv().await.is_none());
    }

    #[test]
    fn ip_counting() {
        let hub = Hub::default();
        let (c1, _r1) = conn("u1", "d1", 2);
        let (c2, _r2) = conn("u2", "d2", 2);
        hub.register(c1);
        hub.register(c2);
        assert_eq!(hub.ip_conn_count("203.0.113.7"), 2);
        assert_eq!(hub.ip_conn_count("198.51.100.1"), 0);
    }

    #[test]
    fn pg_degrade_cache_is_positive_and_ttl_bounded() {
        let cache = PgDegradeCache::new(Duration::from_millis(30), 128);
        // Never trust an unverified relationship (degradation must not forge authorization)
        assert!(!cache.is_member("c1", "u1"));
        cache.remember_member("c1", "u1");
        assert!(cache.is_member("c1", "u1"));
        assert!(!cache.is_member("c1", "u2"), "only verified specific relationships are cached");
        assert!(!cache.is_member("c2", "u1"), "different conversations must not share entries");
        std::thread::sleep(Duration::from_millis(40));
        assert!(!cache.is_member("c1", "u1"), "after TTL expiry, must re-verify against PG");

        cache.remember_members("c1", vec!["u1".into(), "u2".into()]);
        assert_eq!(cache.members("c1").unwrap(), vec!["u1".to_string(), "u2".to_string()]);
        assert!(cache.members("c2").is_none());
    }

    #[test]
    fn member_cache_is_positive_ttl_bounded_and_invalidatable() {
        let cache = MemberCache::new(Duration::from_millis(40), 128);
        // Unverified relationships are not trusted (the cache must not allow out of thin air)
        assert!(!cache.is_member("c1", "u1"));
        cache.remember_member("c1", "u1");
        assert!(cache.is_member("c1", "u1"));
        assert!(!cache.is_member("c1", "u2"), "only verified specific relationships are cached");
        assert!(!cache.is_member("c2", "u1"), "different conversations must not share entries");

        // Active invalidation: return to PG immediately after a membership change (no TTL reliance)
        cache.remember_members("c1", vec!["u1".into(), "u2".into()]);
        assert!(cache.members("c1").is_some());
        cache.invalidate_conv("c1");
        assert!(!cache.is_member("c1", "u1"), "invalidate_conv must clear (conv,user)");
        assert!(cache.members("c1").is_none(), "invalidate_conv must clear the member list");
        // Invalidate only the target conversation; other conversations are unaffected
        cache.remember_member("c2", "u3");
        cache.invalidate_member("c1", "u1");
        assert!(cache.is_member("c2", "u3"));
        assert!(!cache.is_member("c1", "u1"));

        // After TTL expiry, must re-verify against PG
        std::thread::sleep(Duration::from_millis(60));
        assert!(!cache.is_member("c2", "u3"), "after TTL expiry, must re-verify against PG");
        assert!(cache.members("c1").is_none());
    }

    #[test]
    fn member_cache_ttl_zero_disables_cache_entirely() {
        let cache = MemberCache::new(Duration::ZERO, 64);
        assert!(!cache.enabled());
        cache.remember_member("c1", "u1");
        cache.remember_members("c1", vec!["u1".into()]);
        // When disabled it must always miss (callers go to PG); never "remember but not enforce" and silently allow
        assert!(!cache.is_member("c1", "u1"));
        assert!(cache.members("c1").is_none());
    }
}
