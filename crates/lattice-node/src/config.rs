//! Configuration (the TOML summary in doc ② §2.3 + dynamic config).
//!
//! Principle: **static config in TOML, dynamic config in PG `dynamic_config`** (⑥ §2.3).
//! `lattice:cfg` only carries "change broadcast"; nodes read PG before subscribing at startup — otherwise a restart would silently fall back to TOML defaults.
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub node: NodeCfg,
    pub auth: AuthCfg,
    pub pg: PgCfg,
    pub wal: WalCfg,
    pub redis: RedisCfg,
    pub s3: S3Cfg,
    pub bus: BusCfg,
    pub audit: AuditCfg,
    /// Risk-control rule engine (E03 / PL-12 12.6/12.7; off by default, and when off there is no collection or side effect).
    pub risk: RiskCfg,
    pub mqtt: MqttCfg,
    pub grpc: GrpcCfg,
    pub media: MediaCfg,
    /// Compliance hard-delete window (E02: default 7 days; 0 = disable background hard delete).
    pub compliance: ComplianceCfg,
    /// Object-storage maintenance (E04: residual multipart GC).
    pub maintenance: MaintenanceCfg,
    /// QUIC/WebTransport server relay skeleton (design §17.9 path ②; off by default).
    pub quic: QuicCfg,
    /// WebTransport(HTTP/3) browser gateway (design §17.9 path ②; off by default).
    pub webtransport: WebTransportCfg,
    pub policy: PolicyCfg,
    /// Pipeline stage bypass (E31 / ② §2.2): skip stages during debugging/emergency; empty by default = all active.
    pub pipeline: PipelineCfg,
    /// Node-local KEK for `inspectable` mode (E15 / D3): off by default = identical to before it existed.
    pub inspectable: InspectableCfg,
    pub delivery: DeliveryCfg,
    pub degrade: DegradeCfg,
    pub plugins: PluginsCfg,
    pub admin: AdminCfg,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeCfg {
    /// Empty means a ULID is generated at startup (§17.1)
    pub id: String,
    pub listen_http: String,
    pub listen_ws: String,
    pub metrics: String,
    pub log: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthCfg {
    /// Only RS256 is supported (§17.11); symmetric-key schemes are retired
    pub jwt_alg: String,
    pub jwt_ttl: i64,
    pub jwt_issuer: String,
    pub key_dir: String,
    pub fingerprint_required: bool,
    /// Dual-key overlap window for key rotation (hours, ⑤ §8.4 default 24h). Fractions are allowed so E2E/drills
    /// can use a tiny window (e.g. 0.0003h ≈ 1.08s) to verify window expiry; <=0 means expire immediately.
    pub key_overlap_hours: f64,
    /// Interval of the previous-key expiry cleanup job (milliseconds); 0 is invalid → default, with a 100ms floor.
    pub key_prune_interval_ms: u64,
}
impl AuthCfg {
    /// Effective previous cleanup interval: 0 → default 60s; too small is clamped to a 100ms floor (avoids busy waiting).
    pub fn effective_key_prune_interval_ms(&self) -> u64 {
        if self.key_prune_interval_ms == 0 {
            KEY_PRUNE_INTERVAL_MS_DEFAULT
        } else {
            self.key_prune_interval_ms.max(100)
        }
    }
}
/// Default previous-key cleanup interval (1 minute; the window is 24h, so nothing more frequent is needed).
pub const KEY_PRUNE_INTERVAL_MS_DEFAULT: u64 = 60_000;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PgCfg {
    pub url: String,
    pub pool_size: u32,
    pub statement_timeout_ms: u64,
    pub admin_statement_timeout_ms: u64,
}
/// Local WAL (② §4.8 degradation matrix: when PG is not writable, small messages are parked and replayed in order after recovery).
///
/// Only **small messages** are carried (inline payload, no `payload_ref`, `size ≤ 1MB`); large objects/messages
/// take the original error and never enter the WAL (no disk-as-MinIO, and no second amplification on replay).
pub const WAL_MAX_BYTES_DEFAULT: u64 = 64 * 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WalCfg {
    /// Master switch; on by default (degradation is a fallback capability and should be available by default).
    pub enabled: bool,
    /// WAL directory; empty = fall back to `[degrade] pg_wal_dir` (compatible with existing config/deployment volumes).
    pub dir: String,
    /// WAL file byte cap; beyond it appends are rejected and `lattice_wal_dropped_total` is counted
    /// (it must never grow unbounded silently). 0 is invalid → default 64MiB.
    pub max_bytes: u64,
    /// Periodic replay interval (milliseconds); default 2000. E2E/chaos can shrink it via env for speed.
    pub replay_interval_ms: u64,
}
impl WalCfg {
    /// Effective WAL cap: 0 is the only invalid value → default 64MiB.
    pub fn effective_max_bytes(&self) -> u64 {
        if self.max_bytes == 0 {
            WAL_MAX_BYTES_DEFAULT
        } else {
            self.max_bytes
        }
    }
    /// Effective directory: prefer `[wal] dir`, otherwise fall back to `[degrade] pg_wal_dir` (the deployment volume already exists).
    pub fn effective_dir(&self, degrade: &DegradeCfg) -> String {
        let d = self.dir.trim();
        if d.is_empty() {
            degrade.pg_wal_dir.clone()
        } else {
            d.to_string()
        }
    }
    /// Effective replay interval: 0 is invalid → default 2000ms; 100ms floor (prevents a mistyped config becoming a hot loop).
    pub fn effective_replay_interval_ms(&self) -> u64 {
        if self.replay_interval_ms == 0 {
            2000
        } else {
            self.replay_interval_ms.max(100)
        }
    }
}
impl Default for WalCfg {
    fn default() -> Self {
        WalCfg {
            enabled: true,
            dir: String::new(),
            max_bytes: WAL_MAX_BYTES_DEFAULT,
            replay_interval_ms: 2000,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisCfg {
    pub url: String,
    pub pool_size: u32,
    pub route_cache: usize,
    /// `COUNT` hint per round for prefix scans (`SCAN MATCH prefix*`) (PL-17 bottleneck fix).
    ///
    /// It does not change "prefix scan only, never drop keys": SCAN COUNT is only a hint for how much each round returns;
    /// the caller iterates the cursor to 0 and filters by MATCH + dedups, so every matching key is returned.
    /// Raising it only reduces roundtrips (the main CPU source of the hello redelivery scan on large keyspaces).
    /// Valid range 10..=10000; 0 means the default.
    pub scan_count: u32,
}
impl RedisCfg {
    /// Effective SCAN COUNT: 0 → default 1000; out-of-range clamps to [10, 10000] (COUNT is only a hint, keys are never dropped).
    pub fn effective_scan_count(&self) -> u32 {
        if self.scan_count == 0 {
            DEFAULT_REDIS_SCAN_COUNT
        } else {
            self.scan_count.clamp(10, 10_000)
        }
    }
}
/// Default `SCAN COUNT` for prefix scans (PL-17: the old redis-rs `scan_match` default was 10).
pub const DEFAULT_REDIS_SCAN_COUNT: u32 = 1000;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct S3Cfg {
    pub endpoint: String,
    /// Externally reachable endpoint (used by browser/desktop clients to resolve presigned URLs).
    ///
    /// Empty = same as `endpoint`. Under docker it must be a host-reachable address (e.g. `http://127.0.0.1:9000`
    /// or the object store's public domain); otherwise the 302 Location is the in-container hostname `minio:9000`
    /// and the client cannot resolve it — signing covers only the Host header, so this changes the Host in the URL, not the signing scheme.
    pub public_endpoint: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub bucket_large: String,
    pub bucket_media: String,
    pub bucket_cold: String,
    /// Object bucket of the client plugin hub (design §6.9 / ⑥ §4.1; default `lattice-plugins`)
    pub bucket_plugins: String,
    pub presign_ttl: u64,
    pub upload_parallel: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BusCfg {
    /// nats | redis-pubsub (NATS is P3; here the default is redis-pubsub, see doc ② §4.8 degradation matrix)
    pub kind: String,
    pub nats_url: String,
    pub jetstream: bool,
}
/// Audit stream (② §4.8 / ⑥ §5.2: `LATTICE_AUDIT` / `audit.log`) and persistence consumer.
///
/// The write entry `routing::audit::audit_emit` publishes to the NATS audit stream first (a JetStream ack is required for success);
/// on publish failure or with `bus.kind=redis-pubsub` it **writes PG synchronously** (degradation, no loss). The consumer only starts
/// when `bus.kind=nats && bus.jetstream=true`, idempotently persisting stream audits into `audit_log`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditCfg {
    /// Audit consumer switch (on by default). Turning it off does not drop audits: in NATS mode the write entry still publishes to the stream
    /// (retained 7d), this node just does not consume; deployments wanting pure direct-PG writes should use `bus.kind=redis-pubsub`.
    pub consumer_enabled: bool,
    /// consumer `max_deliver`: max deliveries of one message (exceeding it → DLQ: ERROR log + metrics;
    /// the message stays in stream retention and can be replayed manually by event id).
    pub consumer_max_deliver: i64,
    /// consumer `ack_wait` (milliseconds): how long the server waits before redelivering when the processing process crashes/exits.
    pub consumer_ack_wait_ms: u64,
    /// NAK redelivery delay (milliseconds) for retryable failures (PG briefly unavailable).
    pub consumer_retry_delay_ms: u64,
    /// **E2E/chaos testing only**: at startup send one `audit.startup_probe` self-check audit via `audit_emit`.
    ///
    /// Production default false (no noise in the audit table). E2E uses it to deterministically verify both paths:
    /// NATS mode = write entry → `audit.log` → consumer → PG; Redis bus mode = write entry → direct PG write.
    pub startup_probe: bool,
}
/// Audit consumer default `max_deliver` (consistent with the ⑥ §5.2 route consumer convention).
pub const AUDIT_MAX_DELIVER_DEFAULT: i64 = 5;
/// Audit consumer default `ack_wait` (30s; admin-operation audits are low-frequency small transactions, and 30s is plenty to persist).
pub const AUDIT_ACK_WAIT_MS_DEFAULT: u64 = 30_000;
/// Default retry delay for retryable failures (5s).
pub const AUDIT_RETRY_DELAY_MS_DEFAULT: u64 = 5_000;
impl AuditCfg {
    pub fn effective_max_deliver(&self) -> i64 {
        if self.consumer_max_deliver <= 0 {
            AUDIT_MAX_DELIVER_DEFAULT
        } else {
            self.consumer_max_deliver
        }
    }
    /// Effective ack_wait: 0 is invalid → default 30s; too small (<100ms) is clamped, so normal persists are not redelivered by mistake.
    pub fn effective_ack_wait(&self) -> Duration {
        let ms = if self.consumer_ack_wait_ms == 0 {
            AUDIT_ACK_WAIT_MS_DEFAULT
        } else {
            self.consumer_ack_wait_ms.max(100)
        };
        Duration::from_millis(ms)
    }
    /// Effective NAK redelivery delay: 0 → default 5s; too small (<100ms) is clamped.
    pub fn effective_retry_delay(&self) -> Duration {
        let ms = if self.consumer_retry_delay_ms == 0 {
            AUDIT_RETRY_DELAY_MS_DEFAULT
        } else {
            self.consumer_retry_delay_ms.max(100)
        };
        Duration::from_millis(ms)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GrpcCfg {
    /// Internal gRPC service switch (⑤ §10). Production must enable it with mTLS; dev may use plaintext.
    pub enabled: bool,
    /// Listen address; in production expose it only on the internal network/behind an LB, never publicly.
    pub bind: String,
    /// Server certificate chain (PEM; includes intermediates). Empty = plaintext (development only).
    pub tls_cert: String,
    /// Server private key (PEM).
    pub tls_key: String,
    /// Client CA (PEM). When set, client certificates are required and verified (mTLS); empty means one-way TLS only.
    pub tls_client_ca: String,
    /// gRPC address advertised to **other nodes** (host:port), written into the node heartbeat for fallback routing.
    /// Empty = not advertised, so other nodes cannot find this one through the gRPC fallback (dev default empty).
    pub advertise: String,
    /// Whether to allow "bus publish failure → gRPC Route fallback" (⑤ §10: last resort when both NATS and Redis are unavailable).
    pub fallback: bool,
    /// Client certificate/private key used for outbound fallback calls; empty reuses `tls_cert/tls_key`.
    pub client_cert: String,
    pub client_key: String,
    /// Domain for outbound TLS verification (must be one of the server certificate SANs; dev mTLS uses localhost).
    pub tls_domain: String,
    /// Require the client certificate CN to be a known node_id in the Redis node registry (node identity binding, `Route` takes effect).
    /// Requires `tls_client_ca` to obtain the client certificate; default false (upgrade compatibility), production mTLS should set true.
    pub require_known_node_cn: bool,
    /// Require Route to carry `caller_node` matching the mTLS certificate CN (field-level identity binding).
    /// Requires `require_known_node_cn`; default false (compatible with old callers).
    pub require_caller_node: bool,
    /// Peer gRPC address discovery: `auto` (default: heartbeat first, static fallback) | `static` (peers only, no Redis lookup).
    pub discovery: String,
    /// Static peer table `node_id -> host:port`; a second source for gRPC fallback when Redis is unavailable.
    pub peers: HashMap<String, String>,
}
/// Default recorded segment cap 4MiB (see the [`MediaCfg::record_segment_bytes`] field docs).
pub const MEDIA_RECORD_SEGMENT_BYTES_DEFAULT: usize = 4 * 1024 * 1024;
/// Record bus consumer default `ack_wait`: 30s (must exceed the worst segment persist latency so normal writes are not redelivered).
pub const MEDIA_RECORD_BUS_ACK_WAIT_MS_DEFAULT: u64 = 30_000;
/// Record bus consumer default `max_deliver`: 5 (consistent with route/audit; exhaustion → DLQ metric).
pub const MEDIA_RECORD_BUS_MAX_DELIVER_DEFAULT: i64 = 5;
/// Record bus consumer default NAK redelivery delay: 1s (the consumer currently "retries locally from the buffer"; the setting is kept for a future NAK path).
pub const MEDIA_RECORD_BUS_RETRY_DELAY_MS_DEFAULT: u64 = 1_000;
/// Media plane (design §17.9): TURN is deployed standalone as coturn; the node only issues **short-lived credentials**.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MediaCfg {
    /// TURN service URI list (`turn:host:3478?transport=udp`); empty = TURN not configured.
    pub turn_uris: Vec<String>,
    /// coturn `static-auth-secret` (REST API shared secret). **Must come from a Secret/env, never a ConfigMap**.
    pub turn_secret: String,
    /// Credential TTL (seconds, ⑤ §9.7: ≤600s).
    pub turn_ttl: u64,
    /// Per-node concurrent media stream cap (design §17.9; 0 = unlimited, tests only).
    pub max_streams: usize,
    /// Per-stream rate limit (bit/s, design §17.9 default 8Mbps; 0 = unlimited).
    pub stream_bitrate_bps: u64,
    /// **Media recording tee master switch** (PL-13 13.6). Default `false`: no object-storage writes,
    /// no recorder task started, `AppState.recorder` is `None`.
    ///
    /// When enabled it tees only the raw frames of the **WS tunnel fallback path** (`stream-data`):
    /// - `[bus] kind = "nats"`: frames go via `media.record.{stream_id}` (`LATTICE_MEDIA`, JetStream
    ///   publish+ack) → this node's durable consumer `media-record-{node_id}` → segments land in MinIO;
    ///   publish failure/unavailability degrades to direct write (no frame loss);
    /// - other buses (redis-pubsub): aggregate per stream → direct MinIO write.
    ///
    /// Shared boundaries are documented at the top of `routing/media.rs` / `routing/media_record.rs`: **no** MP4/OGG
    /// muxing and no playback Envelope (objects are "raw body with frame boundaries"); retrieval/download APIs
    /// (`/v1/media/recordings*`), a per-segment **manifest object** (frame index `offset/len/seq`,
    /// `format=raw-frames`/`playable=false`), and `record_retention_days` lifecycle reclamation are included.
    pub record_enabled: bool,
    /// Recording object bucket; default `lattice-media` (same as `[s3] bucket_media`). Empty = fall back to `[s3] bucket_media`.
    ///
    /// At startup `ensure_buckets` only guarantees the four `[s3]` buckets exist; pointing this at another bucket requires operations
    /// to create it in advance (otherwise persistence failures only warn + `lattice_media_record_errors_total`, without affecting forwarding).
    pub record_bucket: String,
    /// Byte cap of a single segment (default 4MiB). **0 is invalid → default** (so 0 cannot degrade a segment
    /// into "one object per frame"). Rotation is frame-aligned: an object is flushed once `len >= cap` after append, so a segment may
    /// slightly exceed the cap (at most one more frame body, ≤ 64KiB + 4B length prefix).
    pub record_segment_bytes: usize,
    /// JetStream `ack_wait` of the record bus consumer (milliseconds, default 30000).
    ///
    /// The consumer acks only **after a successful persist**, so this value must exceed the worst segment persist latency; too small
    /// makes the server redeliver even normal writes (the consumer is idempotent by seq and never persists twice, but duplicate deliveries occur).
    /// `0` is invalid → default 30s.
    pub record_bus_ack_wait_ms: u64,
    /// `max_deliver` of the record bus consumer (default 5; exhaustion → DLQ).
    pub record_bus_max_deliver: i64,
    /// NAK redelivery delay after a record bus consume failure (milliseconds, default 1000; the current implementation mainly retries
    /// from a local buffer, and this setting is kept for a future NAK path).
    pub record_bus_retry_delay_ms: u64,
    /// Recording object **lifecycle reclamation** (days; PL-13 13.6; ⑥ §4 object reclamation convention).
    ///
    /// - `0` (default) = **no reclamation**: the background GC job skips entirely, doing no deletes or scans;
    /// - positive = the background job (one round after startup, then every 6h) deletes segment objects, their manifest objects,
    ///   and `media_recordings` rows whose `created_at` is older than that many days (≤1000 rows per round, failures only WARN);
    /// - production suggests 7 (keep one week); E2E uses 1 day and ages temporary rows' `created_at` to verify.
    pub record_retention_days: u64,
}
impl MediaCfg {
    /// Effective segment cap: `0` (the only invalid value) falls back to 4MiB; other positive values apply as configured
    /// (tests use tiny values to force rotation, see `scripts/media-record-e2e.mjs`).
    pub fn effective_record_segment_bytes(&self) -> usize {
        if self.record_segment_bytes == 0 {
            MEDIA_RECORD_SEGMENT_BYTES_DEFAULT
        } else {
            self.record_segment_bytes
        }
    }
    /// Effective recording bucket: empty = fall back to `[s3] bucket_media` (so enabling recording never writes outside the default bucket).
    pub fn effective_record_bucket(&self, s3: &S3Cfg) -> String {
        let b = self.record_bucket.trim();
        if b.is_empty() {
            s3.bucket_media.clone()
        } else {
            b.to_string()
        }
    }
    /// Effective consumer `ack_wait`: `0` invalid falls back to 30s; 1s floor (too small and normal persists get redelivered).
    pub fn effective_record_bus_ack_wait(&self) -> Duration {
        let ms = if self.record_bus_ack_wait_ms == 0 {
            MEDIA_RECORD_BUS_ACK_WAIT_MS_DEFAULT
        } else {
            self.record_bus_ack_wait_ms.max(1_000)
        };
        Duration::from_millis(ms)
    }
    /// Effective consumer `max_deliver`: `<=0` invalid falls back to 5.
    pub fn effective_record_bus_max_deliver(&self) -> i64 {
        if self.record_bus_max_deliver <= 0 {
            MEDIA_RECORD_BUS_MAX_DELIVER_DEFAULT
        } else {
            self.record_bus_max_deliver
        }
    }
    /// Effective consumer NAK redelivery delay: `0` falls back to 1s; 100ms floor (avoids busy-wait redelivery).
    pub fn effective_record_bus_retry_delay(&self) -> Duration {
        let ms = if self.record_bus_retry_delay_ms == 0 {
            MEDIA_RECORD_BUS_RETRY_DELAY_MS_DEFAULT
        } else {
            self.record_bus_retry_delay_ms.max(100)
        };
        Duration::from_millis(ms)
    }
    /// Effective recording object retention days: `0` = reclamation disabled (background GC skips entirely, no SQL/object operations).
    ///
    /// `u64 → i64` overflow saturates at `i64::MAX` (unrealistic: the value is "days", normally 1~3650).
    pub fn effective_record_retention_days(&self) -> i64 {
        i64::try_from(self.record_retention_days).unwrap_or(i64::MAX)
    }
}
impl Default for MediaCfg {
    fn default() -> Self {
        MediaCfg {
            turn_uris: Vec::new(),
            turn_secret: String::new(),
            turn_ttl: 600,
            max_streams: 5_000,
            stream_bitrate_bps: 8 * 1024 * 1024,
            record_enabled: false,
            record_bucket: "lattice-media".into(),
            record_segment_bytes: MEDIA_RECORD_SEGMENT_BYTES_DEFAULT,
            record_bus_ack_wait_ms: MEDIA_RECORD_BUS_ACK_WAIT_MS_DEFAULT,
            record_bus_max_deliver: MEDIA_RECORD_BUS_MAX_DELIVER_DEFAULT,
            record_bus_retry_delay_ms: MEDIA_RECORD_BUS_RETRY_DELAY_MS_DEFAULT,
            record_retention_days: 0,
        }
    }
}
// ---------------------------------------------------------------------------
// Compliance hard-delete window + object-storage maintenance (REMAINING E02 / E04)
// ---------------------------------------------------------------------------
/// Default hard-delete job interval (1 hour; the window is measured in days, so nothing more frequent is needed).
pub const PURGE_CLEANUP_INTERVAL_SECS_DEFAULT: u64 = 3_600;
/// Default residual multipart GC interval (1 hour; the age threshold defaults to 24h).
pub const MULTIPART_GC_INTERVAL_SECS_DEFAULT: u64 = 3_600;
/// Default residual multipart age threshold (24 hours, consistent with ⑥ §2.6 "not completed within > 24h").
pub const MULTIPART_GC_HOURS_DEFAULT: f64 = 24.0;
/// `[compliance]` compliance delete (E02 / ⑤ §8.2 / ② §6):
/// soft delete (PG logical delete + object/Redis cascade cleanup) runs immediately; `purge_hard_delete_days` days later the
/// background job deletes deleted user rows (cascading devices/delivery records).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ComplianceCfg {
    /// Hard-delete window (days): default 7; **`0` = disable** background hard delete (soft delete and residual cascade cleanup still run,
    /// and user rows stay in `deleted` indefinitely for operators to handle manually).
    ///
    /// The window counts from `users.updated_at` written at soft-delete time (`users.status='deleted'`).
    pub purge_hard_delete_days: u64,
    /// Hard-delete job interval (seconds): default 3600; 0 is invalid → default, 60 floor (prevents a mistyped config becoming a hot loop).
    /// Both deployment and E2E can override it with `LATTICE__COMPLIANCE__PURGE_CLEANUP_INTERVAL_SECS`.
    pub purge_cleanup_interval_secs: u64,
}
impl ComplianceCfg {
    /// Whether the hard-delete window is enabled (`0` = disabled).
    pub fn hard_delete_enabled(&self) -> bool {
        self.purge_hard_delete_days > 0
    }
    /// Effective window days (`u64 → i64` overflow saturates at `i64::MAX`; `0` means disabled).
    pub fn effective_hard_delete_days(&self) -> i64 {
        i64::try_from(self.purge_hard_delete_days).unwrap_or(i64::MAX)
    }
    /// Effective hard-delete job interval: 0 → default 3600s; too small (<60s) is clamped.
    pub fn effective_cleanup_interval(&self) -> Duration {
        let secs = if self.purge_cleanup_interval_secs == 0 {
            PURGE_CLEANUP_INTERVAL_SECS_DEFAULT
        } else {
            self.purge_cleanup_interval_secs.max(60)
        };
        Duration::from_secs(secs)
    }
}
impl Default for ComplianceCfg {
    fn default() -> Self {
        ComplianceCfg {
            // ⑤ §8.2: default 7-day hard-delete window.
            purge_hard_delete_days: 7,
            purge_cleanup_interval_secs: PURGE_CLEANUP_INTERVAL_SECS_DEFAULT,
        }
    }
}
/// Default cold archive online retention (days; design §18 D7 suggests "30 days online + cold archive", ⑥ §2.5/§2.6).
pub const ARCHIVE_AFTER_DAYS_DEFAULT: u64 = 30;
/// Default cold archive job interval (seconds; one round per day, ⑥ §2.5/§2.6).
pub const ARCHIVE_INTERVAL_SECS_DEFAULT: u64 = 86_400;
/// Default orphan object GC interval (seconds; one round per day, ⑥ §4.1 `lock:gc-objects`).
pub const OBJECT_GC_INTERVAL_SECS_DEFAULT: u64 = 86_400;
/// Default grace period after `payload_ref` invalidation (message archived/deleted; design §4.1 "delete after 30 days").
pub const OBJECT_GC_GRACE_DAYS_DEFAULT: u64 = 30;

/// `[maintenance]` object-storage maintenance (E04 / ⑥ §2.6 / ⑥ §4):
/// the `lock:gc-multipart` background job scans MinIO for unfinished multipart uploads and aborts them;
/// E01 cold archiving (`lock:archive`) and cold-bucket orphan object GC (`lock:gc-objects`) also live in this section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MaintenanceCfg {
    /// Residual multipart age threshold (**hours, fractions allowed**): default 24.0; `<= 0` = GC disabled.
    ///
    /// Fractions are allowed because E2E uses `0.0003`h (≈1.08s) to verify "abort only when aged, keep when not";
    /// no need to wait 24h; production should still use integer values like 24. NaN counts as disabled.
    pub multipart_gc_hours: f64,
    /// GC job interval (seconds): default 3600; 0 is invalid → default, 60 floor.
    /// Both deployment and E2E can override it with `LATTICE__MAINTENANCE__MULTIPART_GC_INTERVAL_SECS`.
    pub multipart_gc_interval_secs: u64,
    /// **Cold partition archive switch** (E01 / ⑥ §2.5 "archive flow (daily, `lock:archive`)").
    ///
    /// Default `false` = **zero side effects**: no archive job spawned, no PG query, no MinIO access, no archive logs.
    /// When enabled, a positive `archive_after_days` and a usable cold bucket are also required (otherwise each round safely skips/retries).
    pub archive_enabled: bool,
    /// Online retention (days): messages with `created_at < now() - N days` are archivable (default 30, design §18 D7's
    /// "30 days online + cold archive" convention). `0` = archiving has no executable meaning → treated as disabled (safe no-op).
    pub archive_after_days: u64,
    /// Archive target bucket; empty = fall back to `[s3] bucket_cold` (`S3::ensure_buckets` guarantees it at startup).
    /// Pointing at another bucket requires operations to create it first (otherwise uploads fail, data is kept for the next round, never deleted first).
    pub archive_bucket: String,
    /// Archive job interval (seconds): default 86400; 0 is invalid → default, 1s floor (E2E triggers deterministically with 1–2s,
    /// production stays daily).
    pub archive_interval_secs: u64,
    /// **Cold-bucket orphan object GC switch** (E01 / ⑥ §4.1 `lock:gc-objects`; default false = zero side effects).
    ///
    /// Two safe candidate classes:
    /// 1. "Archived objects" registered at archive time whose grace period (`object_gc_grace_days`) has elapsed — before deleting,
    ///    a reverse diff over `payload_ref` / `chunks_index.storage_key` rechecks; still referenced by live messages → skip;
    /// 2. cold-bucket objects **outside the archive/backup namespaces**, past the grace period, and not referenced by any PG row.
    /// The hot bucket (`lattice-large`) is never whole-bucket scanned, to avoid deleting live large objects.
    pub object_gc_enabled: bool,
    /// Orphan object GC interval (seconds): default 86400; 0 is invalid → default, 1s floor.
    pub object_gc_interval_secs: u64,
    /// Grace period (days) after an archived object becomes a reclamation candidate: default 30 (design §4.1 "delete 30 days
    /// after payload_ref invalidation"); `0` = reclaim as soon as due (E2E/drills only; production should keep 30).
    pub object_gc_grace_days: u64,
}
impl MaintenanceCfg {
    /// Whether cold archiving can run: `archive_enabled && archive_after_days > 0` (a 0-day retention makes no sense).
    pub fn archive_should_run(&self) -> bool {
        self.archive_enabled && self.archive_after_days > 0
    }
    /// Effective archive online retention (days; `0` only appears when `archive_should_run()==false`).
    pub fn effective_archive_after_days(&self) -> i64 {
        i64::try_from(self.archive_after_days).unwrap_or(i64::MAX)
    }
    /// Effective archive target bucket: empty = `[s3] bucket_cold`.
    pub fn effective_archive_bucket(&self, s3: &S3Cfg) -> String {
        let b = self.archive_bucket.trim();
        if b.is_empty() {
            s3.bucket_cold.clone()
        } else {
            b.to_string()
        }
    }
    /// Effective archive interval: 0 → default 86400s; 1s floor (deterministic E2E triggering; production daily).
    pub fn effective_archive_interval(&self) -> Duration {
        let secs = if self.archive_interval_secs == 0 {
            ARCHIVE_INTERVAL_SECS_DEFAULT
        } else {
            self.archive_interval_secs.max(1)
        };
        Duration::from_secs(secs)
    }
    /// Whether orphan object GC is enabled (independent of the archive switch: GC can be drilled/rolled back separately).
    pub fn object_gc_should_run(&self) -> bool {
        self.object_gc_enabled
    }
    /// Effective orphan GC interval: 0 → default 86400s; 1s floor.
    pub fn effective_object_gc_interval(&self) -> Duration {
        let secs = if self.object_gc_interval_secs == 0 {
            OBJECT_GC_INTERVAL_SECS_DEFAULT
        } else {
            self.object_gc_interval_secs.max(1)
        };
        Duration::from_secs(secs)
    }
    /// Effective grace period for archived object reclamation: default 30 days; `u64 → i64` overflow saturates at `i64::MAX`.
    pub fn effective_object_gc_grace_days(&self) -> i64 {
        i64::try_from(self.object_gc_grace_days).unwrap_or(i64::MAX)
    }
    /// Whether residual multipart GC is enabled (`<=0`/NaN = disabled).
    pub fn multipart_gc_enabled(&self) -> bool {
        self.multipart_gc_hours.is_finite() && self.multipart_gc_hours > 0.0
    }
    /// Effective age threshold; returns `Duration::ZERO` when disabled (callers check `multipart_gc_enabled` first).
    ///
    /// The cap saturates at 10 years, so a misconfiguration like `1e300` cannot panic `Duration` construction.
    pub fn effective_multipart_gc_age(&self) -> Duration {
        if !self.multipart_gc_enabled() {
            return Duration::ZERO;
        }
        let secs = (self.multipart_gc_hours * 3_600.0).clamp(0.0, 10.0 * 365.0 * 86_400.0);
        Duration::from_secs_f64(secs)
    }
    /// Effective GC interval: 0 → default 3600s; too small (<60s) is clamped.
    pub fn effective_interval(&self) -> Duration {
        let secs = if self.multipart_gc_interval_secs == 0 {
            MULTIPART_GC_INTERVAL_SECS_DEFAULT
        } else {
            self.multipart_gc_interval_secs.max(60)
        };
        Duration::from_secs(secs)
    }
}
impl Default for MaintenanceCfg {
    fn default() -> Self {
        MaintenanceCfg {
            multipart_gc_hours: MULTIPART_GC_HOURS_DEFAULT,
            multipart_gc_interval_secs: MULTIPART_GC_INTERVAL_SECS_DEFAULT,
            // E01: cold archiving is off by default (zero side effects); when on, the default is "30 days online + cold archive".
            archive_enabled: false,
            archive_after_days: ARCHIVE_AFTER_DAYS_DEFAULT,
            archive_bucket: String::new(),
            archive_interval_secs: ARCHIVE_INTERVAL_SECS_DEFAULT,
            object_gc_enabled: false,
            object_gc_interval_secs: OBJECT_GC_INTERVAL_SECS_DEFAULT,
            object_gc_grace_days: OBJECT_GC_GRACE_DAYS_DEFAULT,
        }
    }
}
/// QUIC/WebTransport server relay skeleton config (design §17.9 path ②; PL-13 13.3).
///
/// **Compile-time and runtime switches**:
/// - compile time: crate feature `quic` (off by default). When off, this section still parses (so staged config can be persisted)
///   but the node only logs one WARN at startup and does not listen on UDP;
/// - runtime: with `enabled=false` (default) it does not listen even when the feature is on.
///
/// Stream caps/rate limits are **not redefined here**: `[media] max_streams` (default 5000) and
/// `[media] stream_bitrate_bps` (default 8Mbps) are reused, sharing the same §17.9 convention as the WS tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QuicCfg {
    /// Whether to start the QUIC UDP listener (default false; enable per tenant/scenario where enterprise networks block UDP).
    pub enabled: bool,
    /// UDP listen address (§17.9 design port 443; dev/E2E use a separate port such as 127.0.0.1:18443).
    pub bind: String,
    /// Server certificate chain (PEM, including intermediates). Empty + empty `key` = **dev self-signed temporary certificate** (memory only, replaced on restart).
    pub cert: String,
    /// Server private key (PEM; PKCS#8/EC/RSA parsed by rustls-pemfile).
    pub key: String,
    /// Connection idle timeout (seconds; 0 invalid → default 30s). On fire the connection closes, streams are cleaned, and dropped{reason=closed} is counted.
    pub idle_timeout_secs: u64,
    /// TLS/registration handshake cap (seconds; 0 invalid → default 10s). Aligns with §17.9 "the client degrades after a 10s negotiation timeout".
    pub handshake_timeout_secs: u64,
    /// Validity of server-issued join tokens (seconds; 0 invalid → default 120s, max 3600s).
    ///
    /// Join tokens are HMAC-signed by the server, bound to `stream_id` + purpose + expiry; after expiry a side-B registration is rejected.
    /// Same order of magnitude as the `stream-sig` session TTL (120s): the window from signaling to QUIC pairing.
    pub token_ttl_secs: u64,
}
/// QUIC default UDP port (design §17.9 / 443 in deploy/quic-lb-udp.yaml; local E2E overrides it explicitly).
pub const QUIC_BIND_DEFAULT: &str = "0.0.0.0:4433";
/// QUIC idle timeout default (seconds).
pub const QUIC_IDLE_TIMEOUT_SECS_DEFAULT: u64 = 30;
/// QUIC handshake timeout default (seconds).
pub const QUIC_HANDSHAKE_TIMEOUT_SECS_DEFAULT: u64 = 10;
/// QUIC join token validity default (seconds): covers the window from stream-sig session setup to both sides pairing over QUIC.
pub const QUIC_TOKEN_TTL_SECS_DEFAULT: u64 = 120;
/// QUIC join token validity cap (seconds): a short-lived ticket that must never be configured as "never expires".
pub const QUIC_TOKEN_TTL_SECS_MAX: u64 = 3600;
impl QuicCfg {
    /// Effective idle timeout: 0 invalid → default 30s (so 0 can neither kick connections immediately nor become "never times out").
    pub fn effective_idle_timeout_secs(&self) -> u64 {
        if self.idle_timeout_secs == 0 {
            QUIC_IDLE_TIMEOUT_SECS_DEFAULT
        } else {
            self.idle_timeout_secs
        }
    }
    /// Effective handshake timeout: 0 invalid → default 10s.
    pub fn effective_handshake_timeout_secs(&self) -> u64 {
        if self.handshake_timeout_secs == 0 {
            QUIC_HANDSHAKE_TIMEOUT_SECS_DEFAULT
        } else {
            self.handshake_timeout_secs
        }
    }
    /// Effective join token validity: 0 invalid → default 120s; over the cap (3600s) it saturates, so a short-lived ticket never becomes a long-lived credential.
    pub fn effective_token_ttl_secs(&self) -> u64 {
        if self.token_ttl_secs == 0 {
            QUIC_TOKEN_TTL_SECS_DEFAULT
        } else {
            self.token_ttl_secs.min(QUIC_TOKEN_TTL_SECS_MAX)
        }
    }
}
impl Default for QuicCfg {
    fn default() -> Self {
        QuicCfg {
            enabled: false,
            bind: QUIC_BIND_DEFAULT.into(),
            cert: String::new(),
            key: String::new(),
            idle_timeout_secs: QUIC_IDLE_TIMEOUT_SECS_DEFAULT,
            handshake_timeout_secs: QUIC_HANDSHAKE_TIMEOUT_SECS_DEFAULT,
            token_ttl_secs: QUIC_TOKEN_TTL_SECS_DEFAULT,
        }
    }
}
/// WebTransport(HTTP/3) browser gateway config (design §17.9 path ②; PL-13 13.3).
///
/// **Compile-time and runtime switches** (same as `[quic]`):
/// - compile time: crate feature `webtransport` (off by default, implies `quic`). When off, this section still parses;
///   the node logs one WARN at startup only when `enabled=true`, and creates no UDP/TLS listener;
/// - runtime: with `enabled=false` (default) it does not listen even when the feature is on.
///
/// **Bridge semantics**: the WT gateway is not a second media implementation — it bridges the browser's WebTransport
/// bidirectional stream **as-is** to the local QUIC listener (the gateway is an internal QUIC client); registration/pairing/auth/TLV relay/
/// the 8Mbps per-stream token bucket/per-node stream cap all reuse the existing QUIC implementation; this section only covers the TLS certificate,
/// the HTTP/3 listen address, the upstream trust anchor, and session lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebTransportCfg {
    /// Whether to start the WebTransport (HTTP/3) UDP listener (default false).
    pub enabled: bool,
    /// UDP listen address (browser-reachable; must be a different port from `[quic] bind`).
    pub bind: String,
    /// HTTP/3 server certificate chain (PEM, including intermediates). Empty + empty `key` = **dev self-signed temporary certificate**
    /// (memory only, replaced on restart; browsers must trust it via `serverCertificateHashes`, E2E uses a temporary CA).
    pub cert: String,
    /// HTTP/3 server private key (PEM).
    pub key: String,
    /// Bridge upstream (local QUIC listener) address; empty = derive from `[quic] bind`
    /// (wildcard addresses such as `0.0.0.0`/`[::]` are replaced with loopback 127.0.0.1).
    pub upstream: String,
    /// Trust anchor for the bridge upstream certificate (PEM, may contain a CA chain). Empty = reuse `[quic] cert`;
    /// when both are empty (= QUIC dev self-signed), the bridge **skips verification** for loopback addresses only (WARN, dev only).
    pub upstream_ca: String,
    /// Expected window for WT session registration/pairing (seconds; 0 invalid → default). The actual join token is issued by the QUIC layer,
    /// so its validity follows `[quic] token_ttl_secs`; this value gives the WT side a grace period for handshake/waiting for upstream registration/draining.
    pub token_ttl_secs: u64,
    /// HTTP/3 connection idle timeout (seconds; 0 invalid → default 30s), capped at `WEBTRANSPORT_IDLE_TIMEOUT_SECS_MAX`.
    pub idle_timeout_secs: u64,
    /// WebTransport CONNECT path (default `/media`; CONNECT on any other path returns 404).
    pub path: String,
}
/// WebTransport default UDP port (design §17.9; browser-reachable; distinct from QUIC 4433 to avoid port conflicts on one host).
pub const WEBTRANSPORT_BIND_DEFAULT: &str = "0.0.0.0:4433";
/// WebTransport default CONNECT path.
pub const WEBTRANSPORT_PATH_DEFAULT: &str = "/media";
/// WebTransport idle timeout default (seconds).
pub const WEBTRANSPORT_IDLE_TIMEOUT_SECS_DEFAULT: u64 = 30;
/// WebTransport idle timeout cap (seconds): prevents a misconfiguration from becoming near-permanent connections.
pub const WEBTRANSPORT_IDLE_TIMEOUT_SECS_MAX: u64 = 600;
/// WebTransport session registration window default (seconds): same as the `[quic] token_ttl_secs` default.
pub const WEBTRANSPORT_TOKEN_TTL_SECS_DEFAULT: u64 = 120;
/// WebTransport session registration window cap (seconds).
pub const WEBTRANSPORT_TOKEN_TTL_SECS_MAX: u64 = 3600;
impl WebTransportCfg {
    /// Effective idle timeout: 0 invalid → default 30s; over the cap saturates at 600s.
    pub fn effective_idle_timeout_secs(&self) -> u64 {
        if self.idle_timeout_secs == 0 {
            WEBTRANSPORT_IDLE_TIMEOUT_SECS_DEFAULT
        } else {
            self.idle_timeout_secs
                .min(WEBTRANSPORT_IDLE_TIMEOUT_SECS_MAX)
        }
    }
    /// Effective session registration window: 0 invalid → default 120s; over the cap saturates at 3600s.
    pub fn effective_token_ttl_secs(&self) -> u64 {
        if self.token_ttl_secs == 0 {
            WEBTRANSPORT_TOKEN_TTL_SECS_DEFAULT
        } else {
            self.token_ttl_secs.min(WEBTRANSPORT_TOKEN_TTL_SECS_MAX)
        }
    }
    /// Effective CONNECT path: empty/not starting with `/` → default `/media` (prevents an invalid path from being configured).
    pub fn effective_path(&self) -> &str {
        let p = self.path.trim();
        if p.starts_with('/') {
            p
        } else {
            WEBTRANSPORT_PATH_DEFAULT
        }
    }
}
impl Default for WebTransportCfg {
    fn default() -> Self {
        WebTransportCfg {
            enabled: false,
            bind: WEBTRANSPORT_BIND_DEFAULT.into(),
            cert: String::new(),
            key: String::new(),
            upstream: String::new(),
            upstream_ca: String::new(),
            token_ttl_secs: WEBTRANSPORT_TOKEN_TTL_SECS_DEFAULT,
            idle_timeout_secs: WEBTRANSPORT_IDLE_TIMEOUT_SECS_DEFAULT,
            path: WEBTRANSPORT_PATH_DEFAULT.into(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MqttCfg {
    /// MQTT gateway switch (P3; ⑤ §11). When off, the node does not listen on the MQTT port.
    pub enabled: bool,
    /// Listen address. Production uses 8883 + TLS (terminated by a front proxy, same constraint as HTTP); dev uses 1883 plaintext.
    pub bind: String,
    /// Concurrent online connection cap (over the cap new connections are closed immediately, avoiding message-plane overload).
    pub max_connections: usize,
    /// Outbound QoS1 PUBACK wait timeout (milliseconds); on timeout resend with DUP=1. Default 10s (⑤ §11).
    pub retransmit_ms: u64,
    /// Max outbound QoS1 retransmissions; exceeding it disconnects and counts
    /// `lattice_mqtt_publish_retransmit_total{result=exhausted}`.
    pub max_retransmits: u32,
    /// Rate limit for offline pending redelivery (msg/s per device, same convention as §17.13's 10 msg/s; 0 is treated as 1).
    pub replay_rate_per_sec: u32,
    /// Persistent session Redis TTL (seconds): retention of clean_session=false / MQTT 5 Session Expiry session state
    /// (subscriptions + inbound QoS2 staging + redelivery watermark + outbound QoS2 pending).
    /// Default 3600 (1h); 0 = disable session persistence (equivalent to "no persistent session", `session_present` always 0).
    pub session_ttl_secs: u64,
    /// Clamp cap for the MQTT 5 Session Expiry Interval (seconds): a larger client-declared value is truncated to this cap,
    /// so a misconfiguration or malicious client cannot keep session state in Redis long-term. Default 86400 (1 day).
    pub session_expiry_max_secs: u64,
    /// retained message Redis TTL (seconds): retained semantics are "until cleared/overwritten", so a fallback TTL is added
    /// to prevent long-term leaks (default 30 days); refreshed on every retain=1 publish.
    pub retained_ttl_secs: u64,
    /// MQTT 5 Topic Alias cap (`Topic Alias Maximum`).
    ///
    /// Only when the client's own CONNECT declares `Topic Alias Maximum` is this cap echoed back in CONNACK
    /// with property 0x22 (preserving the existing 3-byte CONNACK shape for clients that do not declare it); the client may use aliases
    /// 1..=this value in PUBLISH to compress the topic; the server maintains an alias→topic map per session (0 invalid,
    /// over the cap/unknown alias/conflicting mapping → DISCONNECT 0x94). See `outbound_topic_alias` for outbound compression.
    /// Default 16; 0 = do not accept aliases (echo 0 even if the client declares them).
    pub topic_alias_max: u16,
    /// MQTT 5 server Receive Maximum (echoed in the server→client CONNACK property 0x21).
    ///
    /// Semantics: cap on in-flight QoS1/2 PUBLISH messages the client sends to this server (the gateway checks the client's inbound
    /// in-flight count and rejects over-limit with DISCONNECT 0x93 Receive Maximum exceeded). At the same time, when the gateway sends
    /// QoS1/2 downstream it honors the Receive Maximum **declared by the client** (over-limit enters bounded queueing, see
    /// `lattice_mqtt_receive_max_total`).
    ///
    /// Compatibility: this value is echoed in CONNACK only when the client's CONNECT itself declares `Receive Maximum(0x21)`
    /// (omitted otherwise = MQTT 5 default 65535, preserving the existing smoke/E2E CONNACK shape contract).
    /// Default 32; 0 = echo 65535 (no limit); cap 65535 (u16).
    pub receive_maximum: u16,
    /// MQTT 5 **outbound** Topic Alias compression switch (default **true**).
    ///
    /// Enabled only when the client's CONNECT declares `Topic Alias Maximum > 0` (and this switch is true): an alias is established for
    /// repeated outbound topics on the same connection (≤ the client cap, per connection); the first PUBLISH carries the full topic + alias,
    /// later ones an empty topic + alias; the mapping is dropped on disconnect and never crosses sessions. With a client cap of 0 or this switch=false
    /// there is no compression at all (counted in `lattice_mqtt_out_alias_total{result=disabled}`).
    pub outbound_topic_alias: bool,
    // ---- TLS / mTLS (PL-11: device certificate X.509 identity) ------------------------------------
    /// MQTT **TLS listener** switch (default **false**; independent of `enabled`: run TLS only or plaintext only).
    ///
    /// When off, `tls_bind` is not listened on and behavior is exactly as before TLS was added (plaintext `bind` unaffected).
    /// Startup failures (certificate/key/CA read or parse failure, port in use) **only WARN**; the node stays ready.
    pub tls_enabled: bool,
    /// TLS listen address (default `0.0.0.0:8883`). dev/E2E use a separate port + Redis db isolation.
    pub tls_bind: String,
    /// Server certificate chain (PEM, may include intermediates; the first must be the leaf). Empty = configuration error (WARN only, no listener).
    pub tls_cert: String,
    /// Server private key (PEM: PKCS#8/PKCS#1/SEC1 all accepted). Empty = configuration error (WARN only, no listener).
    pub tls_key: String,
    /// Client certificate trust anchor (PEM, may contain several). Required when `require_client_cert=true` (fail-closed).
    pub client_ca: String,
    /// Whether to require a client certificate (default **true** = mTLS).
    ///
    /// - true: no certificate or a failed chain validation is rejected during the TLS handshake (counted in
    ///   `lattice_mqtt_tls_auth_total{result=no_cert|bad_cert}`);
    /// - false: connections without a client certificate are allowed (falling back to the plaintext path's PSK/JWT semantics), but **if the client presents a certificate
    ///   it is still verified against `client_ca`** (bad certificates are still rejected).
    pub require_client_cert: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyCfg {
    pub inline_threshold: usize,
    pub chunk_threshold_max: u64,
    pub chunk_part: usize,
    pub chunk_timeout: u64,
    pub dedup_ttl: u64,
    pub client_keepalive: u64,
    pub client_ping: u64,
    pub server_idle_timeout: u64,
    pub conn_ttl: u64,
    pub ack_timeout: u64,
    pub pending_rate_limit: u32,
    pub seq_watermark_flush: u64,
    pub msg_per_s: u32,
    pub bytes_per_s: u64,
    pub topics_per_user: u32,
    /// Session membership positive cache TTL (milliseconds, PL-17 bottleneck fix). Default 1000ms.
    ///
    /// Only `(conv,user)` memberships **verified as true against the authoritative PG value** and `conv` member lists are cached;
    /// the membership-change API invalidates actively (see the invalidate hook in `transport/http.rs`),
    /// so the TTL is only a fallback window (extreme cases such as direct DB edits on the PG side). 0 = disable the cache (go to PG).
    pub member_cache_ttl_ms: u64,
    /// zero-knowledge (default) | inspectable (§17.7)
    pub mode: String,
    pub protocol_min_supported: u8,
    pub protocol_version: u8,
}
/// Default membership positive cache TTL (milliseconds; PL-17 bottleneck fix: the hot path did 2 PG membership queries per message).
pub const DEFAULT_MEMBER_CACHE_TTL_MS: u64 = 1_000;
impl PolicyCfg {
    /// Effective membership cache TTL: 0 = cache disabled (go to PG, for regression/comparison); otherwise the value is used as-is in milliseconds.
    ///
    /// The 60s cap prevents a short TTL from being typo'd into a long-lived authorization window (membership changes actively invalidate,
    /// but the cache remains a "degraded fallback layer" and should not carry hour-level consistency).
    pub fn effective_member_cache_ttl(&self) -> std::time::Duration {
        if self.member_cache_ttl_ms == 0 {
            std::time::Duration::ZERO
        } else {
            std::time::Duration::from_millis(self.member_cache_ttl_ms.min(60_000))
        }
    }
}
/// Pipeline stage names (② §2.2 ingestion orchestration; `[pipeline] bypass` accepts only these names).
///
/// The order is the actual execution order of [`crate::pipeline::ingest`]; `decode`/`auth` happen in the transport layer
/// and are not listed here (they decide "can it get in at all"; bypassing them would be an auth bypass, not a debugging switch).
pub const PIPELINE_STAGES: [&str; 8] = [
    "validate", "member", "dedup", "detect", "format", "seq", "persist", "route",
];
/// `[pipeline]`: ingestion orchestration switch (E31 / ② §2.2 "support `config.pipeline.bypass=[...]`
/// bypass (debugging/emergency)").
///
/// **Debugging/emergency only**: bypassing a stage skips only that stage's own behavior, other stages run normally; each stage
/// entry records `lattice_pipeline_bypass_total{stage}` + a WARN log, making it easy to confirm "only that one stage
/// was bypassed". The default empty array = exactly as before it existed.
///
/// Invalid stage names fail `Config::load` outright (fail-fast): a misspelled name being silently ignored is more dangerous
/// than believing you bypassed something when you did not.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PipelineCfg {
    /// Stage names to bypass (case-insensitive; comma-separated env values allowed).
    pub bypass: Vec<String>,
}
impl PipelineCfg {
    /// Normalized bypass stages (trim + lowercase + dedup, in [`PIPELINE_STAGES`] order).
    ///
    /// Used only for display/logging after startup validation; runtime checks use [`Self::is_bypassed`] (which evaluates the raw config,
    /// so an invalid name that slipped through validation cannot "partially apply").
    pub fn normalized(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for stage in PIPELINE_STAGES {
            if self.is_bypassed(stage) {
                out.push(stage);
            }
        }
        out
    }
    /// Startup validation: an invalid stage name → explicit error (fail-fast) listing the valid set.
    pub fn validate(&self) -> Result<()> {
        let mut invalid = Vec::new();
        for raw in &self.bypass {
            let name = raw.trim().to_ascii_lowercase();
            if name.is_empty() || !PIPELINE_STAGES.contains(&name.as_str()) {
                invalid.push(raw.clone());
            }
        }
        if !invalid.is_empty() {
            return Err(crate::error::format(format!(
                "invalid [pipeline] bypass stage(s): {invalid:?}; legal stages: {}",
                PIPELINE_STAGES.join(", ")
            ))
            .with_reason("pipeline_bypass")
            .with_detail("legal_stages", serde_json::json!(PIPELINE_STAGES)));
        }
        Ok(())
    }
    /// Whether the stage is bypassed (case-insensitive, leading/trailing whitespace ignored).
    pub fn is_bypassed(&self, stage: &str) -> bool {
        self.bypass
            .iter()
            .any(|s| s.trim().eq_ignore_ascii_case(stage))
    }
}
/// `[inspectable]`: **node-local KEK** for auditable-content mode (E15 / D3 default node-local; production KMS not wired).
///
/// Semantic boundaries (implementation in [`crate::pipeline::inspectable`]):
/// - `enabled=false` (default): no KEK material is read or validated and no background job starts → identical to before it existed;
/// - `enabled=true`: at startup load the 32B KEK from `kek` (env/Secret, base64 32B or hex 64 chars) or `kek_file`,
///   and run one wrap/unwrap self-check with it (fail-fast on failure); when `previous_kek`/`previous_kek_id` are set,
///   additionally verify "old KEK decrypts → re-encrypt to the new KEK", for the dual-KEK overlap window
///   of the annual rotation (old data readable, new data uses the new KEK);
/// - the KEK is only used for the **wrap/unwrap trail hook** (envelope metadata `lattice.kek_id` /
///   `lattice.wrapped_key`); payload E2E encryption/decryption stays in the SDK; this node never logs plaintext keys;
/// - production KMS/Vault wrapping and runtime hot rotation (the admin `keys/rotate target=kek` is still explicitly unimplemented)
///   are out of this work package; rotation = change env/files and restart (new KEK + previous pointing at the old KEK).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InspectableCfg {
    /// Master switch; default false.
    pub enabled: bool,
    /// Current KEK id (written into envelope metadata and audits; **must contain no key material**; required when enabled).
    pub kek_id: String,
    /// KEK material: standard base64 (32 bytes) or hex (64 chars). **Production must use env/Secret**;
    /// never put it in TOML/ConfigMap. Mutually exclusive with `kek_file`.
    pub kek: String,
    /// KEK material file path (same content; blank lines/`#` comments allowed). Mutually exclusive with `kek`.
    pub kek_file: String,
    /// previous KEK id (dual-KEK overlap window for re-encryption; appears together with `previous_kek`).
    pub previous_kek_id: String,
    /// previous KEK material (old data still decrypts; clear it when the window ends).
    pub previous_kek: String,
}
impl Default for InspectableCfg {
    fn default() -> Self {
        InspectableCfg {
            enabled: false,
            kek_id: String::new(),
            kek: String::new(),
            kek_file: String::new(),
            previous_kek_id: String::new(),
            previous_kek: String::new(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DeliveryCfg {
    /// Default all-devices (§17.4)
    pub multidevice: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DegradeCfg {
    pub redis_stale_cache: bool,
    pub pg_wal_dir: String,
    pub bus_fallback: String,
    /// **dev/chaos testing only**: force every cross-node bus publish to fail, to deterministically verify the gRPC Route fallback.
    /// Production must keep it false (default); `scripts/grpc-fallback-e2e.mjs` sets it true.
    pub inject_bus_failure: bool,
}
/// Risk-control rule engine (E03 / PL-12 12.6/12.7 / ② §4.7 "rate limiting and risk control").
///
/// Positioning: a **rule engine (not ML)**. Three anomaly patterns:
/// 1. `message_flood`: high message frequency from one device in a short period (sliding window, threshold `max_events_per_min`);
/// 2. `device_switch`: many new devices for one account in a short period (distinct device count in the window, threshold
///    `device_switch_threshold`);
/// 3. `auth_failure_surge`: a short-term surge of authentication failures (JWT verification failures = 401 class, sliding window);
///
/// A hit → `lattice:risk` ZSET (bounded + TTL) → disposition action (`action`) → `audit_log`
/// `risk.detected` / `risk.action` → `lattice_risk_events_total{rule,action}`.
///
/// Default `enabled=false`: no extra Redis connections, no background jobs, hot-path hooks return immediately.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RiskCfg {
    /// Master switch (off by default; when off, zero side effects).
    pub enabled: bool,
    /// Rule a: message-frequency threshold for one device in a short period (messages/minute, 60s sliding window).
    pub max_events_per_min: u64,
    /// Rule b: threshold for new devices appearing for the same account within the window.
    pub device_switch_threshold: u64,
    /// Rule b window (seconds).
    pub device_switch_window_secs: u64,
    /// Rule c: authentication failure count threshold within the window.
    pub auth_failure_threshold: u64,
    /// Rule c window (seconds).
    pub auth_failure_window_secs: u64,
    /// Rule a window (seconds; default 60, E2E can shrink it for speed). 0 invalid → default.
    pub message_window_secs: u64,
    /// `lattice:risk` ZSET bounded size (keep only the newest N hits).
    pub queue_max_events: usize,
    /// `lattice:risk` TTL (seconds; refreshed when a hit is written).
    pub queue_ttl_secs: u64,
    /// Disposition action: `audit` (audit only) | `throttle` (device rate limit) | `reauth` (revoke refresh).
    /// An auth-failure surge has no trustworthy user identity, so the rule layer forces `audit` (see the risk module docs).
    pub action: String,
    /// Rate-limit window for the `throttle` action (seconds, default 300 = 5 minutes).
    pub throttle_secs: u64,
    /// Report debounce for hits of the same target+rule (seconds; default 10, so hot targets do not flood the queue/audit).
    pub report_debounce_secs: u64,
}
impl RiskCfg {
    pub fn message_window(&self) -> Duration {
        Duration::from_secs(if self.message_window_secs == 0 {
            60
        } else {
            self.message_window_secs
        })
    }
    pub fn device_window(&self) -> Duration {
        Duration::from_secs(if self.device_switch_window_secs == 0 {
            300
        } else {
            self.device_switch_window_secs
        })
    }
    pub fn auth_window(&self) -> Duration {
        Duration::from_secs(if self.auth_failure_window_secs == 0 {
            60
        } else {
            self.auth_failure_window_secs
        })
    }
    /// Effective disposition action: invalid/empty falls back to `audit` (minimal intervention; never silently becomes a ban).
    pub fn effective_action(&self) -> &'static str {
        match self.action.trim().to_ascii_lowercase().as_str() {
            "throttle" => "throttle",
            "reauth" => "reauth",
            _ => "audit",
        }
    }
    pub fn throttle_window(&self) -> Duration {
        Duration::from_secs(if self.throttle_secs == 0 {
            300
        } else {
            self.throttle_secs
        })
    }
    pub fn debounce(&self) -> Duration {
        Duration::from_secs(if self.report_debounce_secs == 0 {
            10
        } else {
            self.report_debounce_secs
        })
    }
    pub fn effective_queue_max(&self) -> usize {
        self.queue_max_events.clamp(16, 100_000)
    }
    pub fn effective_queue_ttl(&self) -> u64 {
        if self.queue_ttl_secs == 0 {
            86_400
        } else {
            self.queue_ttl_secs
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginsCfg {
    /// Directory plugin package root: `<wasm_dir>/<ns>/{manifest.json, plugin.wasm, signature?}`.
    /// Empty = do not load directory plugins (the host can still be fed packages from other registries).
    pub wasm_dir: String,
    /// **Legacy field** (old design `[plugins] sidecar.mtls = true`): kept so old config parses,
    /// **no longer drives the sidecar client**. The new semantics are decided by whether all three of
    /// `[plugins.sidecar]`'s `tls_ca/tls_cert/tls_key` are present (all three = mTLS; all empty = plaintext dev; missing = config error, fail-closed).
    pub sidecar_mtls: bool,
    /// Wall-clock cap for a single call (host cap; a manifest may only request less).
    pub timeout_ms: u64,
    /// Per-instance memory cap (MiB, host cap).
    pub memory_mb: u64,
    /// Fuel cap per call (host cap).
    pub instructions: u64,
    /// **Ed25519 verification public keys** (PL-10 / design ② §4.5): `key id → base64 raw 32B public key`.
    ///
    /// The signed body is fixed as `sha256(wasm_bytes || manifest_canonical_json)`; publishers sign with an offline private key,
    /// and the host holds only public keys. Example: `trusted_keys = { "release-2025" = "lR6...=" }`.
    pub trusted_keys: HashMap<String, String>,
    /// Alternate public key file (JSON object `{id: base64}` or `{"keys": {...}}`); merged with `trusted_keys`
    /// (the file overrides same-id entries). Empty = not loaded. Read/parse failure is fail-closed:
    /// only a warning, and no unverified plugin is registered (with `require_verified_signature=true` all are rejected).
    pub trusted_keys_file: String,
    /// Require plugins to be signature-verified (default **true**, fail-closed): unsigned / bad signature / unknown key are all rejected at load.
    /// dev/internal debugging may explicitly set `false`: unsigned packages can load but are `trusted=false` and **cannot be invoked**;
    /// bad signatures/unknown keys are still rejected (a bad signature is treated as tampering).
    pub require_verified_signature: bool,
    /// Whether to read WASM plugins from the PG `plugins` table (PL-10 addition; default **true**).
    ///
    /// Semantics (fail-closed):
    /// - read only `wasm is not null and status in ('active','canary')`; for the same ns take the **highest active version**,
    ///   canary rows are ignored and recorded (no canary routing, never loaded silently);
    /// - read **asynchronously** after node startup (does not block ready); a failed query only WARNs, and plugin registration results go to metrics/admin;
    /// - `wasm_dir` is still scanned and **the directory wins**: on a same-ns conflict the directory package applies and the PG row is skipped with a WARN;
    /// - verification keys are shared with the directory source (`trusted_keys`); a PG row picks a key via `config.signing_key_id`,
    ///   and when absent with exactly one trusted key configured that key is used (multiple keys and no declaration = missing → fail-closed reject).
    pub from_db: bool,
    /// Per-package wasm byte cap for the PG source (default 16MiB): SQL filters by `octet_length` first, over-limit rows are rejected and
    /// counted (prevents OOM from reading a huge bytea). The directory package cap is still enforced by
    /// `lattice_plugins::wasm::registry::MAX_WASM_BYTES` (64MiB).
    pub max_wasm_bytes: u64,
    /// `[plugins.sidecar]`: the node calling an external gRPC plugin sidecar (PL-10 / ⑤ §10).
    /// **Off by default**: when off the node uses `NoopSidecar` ("no converter" passthrough), opens no connection, and has no side effects.
    pub sidecar: SidecarCfg,
}
/// Default per-package wasm cap for the PG source: 16MiB (prevents OOM from reading large DB objects; real plugins are far smaller).
pub const DEFAULT_PG_MAX_WASM_BYTES: u64 = 16 * 1024 * 1024;
impl PluginsCfg {
    /// Effective per-package cap for the PG source: 0 = default 16MiB (never degrade to "unlimited", or huge bytea could take the node down).
    pub fn effective_max_wasm_bytes(&self) -> u64 {
        if self.max_wasm_bytes == 0 {
            DEFAULT_PG_MAX_WASM_BYTES
        } else {
            self.max_wasm_bytes
        }
    }
}
/// `[plugins.sidecar]`: external gRPC plugin sidecar client config (PL-10 / ⑤ §10).
///
/// By default **everything is off/empty**: when unconfigured the node uses `NoopSidecar` to keep the "no converter passthrough" semantics,
/// opens no connection, performs no network IO, and does not affect startup/ready.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SidecarCfg {
    /// Master switch (default false). Enabled but with an empty endpoint/missing certificates → the node only WARNs at startup and falls back to Noop.
    pub enabled: bool,
    /// gRPC endpoint, **must include a scheme**: `http://host:port` (plaintext dev) or
    /// `https://host:port` (mTLS; when `tls_ca/tls_cert/tls_key` are all present).
    pub endpoint: String,
    /// Hard timeout per call (milliseconds); 0 = the default `limits::SIDECAR_TIMEOUT_MS` (500ms).
    pub timeout_ms: u64,
    /// CA used to verify the sidecar server certificate (PEM file path; empty = plaintext dev).
    pub tls_ca: String,
    /// Certificate the node presents as a gRPC client (PEM file path; empty = plaintext dev).
    pub tls_cert: String,
    /// Client certificate private key (PEM file path; empty = plaintext dev).
    pub tls_key: String,
}
impl Default for SidecarCfg {
    fn default() -> Self {
        SidecarCfg {
            enabled: false,
            endpoint: String::new(),
            timeout_ms: lattice_plugins::limits::SIDECAR_TIMEOUT_MS,
            tls_ca: String::new(),
            tls_cert: String::new(),
            tls_key: String::new(),
        }
    }
}
impl SidecarCfg {
    /// Effective timeout: 0 = default 500ms; invalid/meaningless values (0) fall back rather than "everything times out immediately".
    pub fn effective_timeout_ms(&self) -> u64 {
        if self.timeout_ms == 0 {
            lattice_plugins::limits::SIDECAR_TIMEOUT_MS
        } else {
            self.timeout_ms
        }
    }
    /// Whether all three TLS values are empty (plaintext dev; the node WARNs at startup when enabled).
    pub fn tls_unset(&self) -> bool {
        self.tls_ca.trim().is_empty()
            && self.tls_cert.trim().is_empty()
            && self.tls_key.trim().is_empty()
    }
    /// Whether all three TLS values are present (mTLS).
    pub fn tls_complete(&self) -> bool {
        !self.tls_ca.trim().is_empty()
            && !self.tls_cert.trim().is_empty()
            && !self.tls_key.trim().is_empty()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminCfg {
    /// Admin and data plane use isolated connection pools (doc ② §2.1 / §12 P6)
    pub pool_size: u32,
    pub sse_max_connections: usize,
    /// Bootstrap administrator username for the first deployment (⑤ §8.2 "first administrator").
    pub bootstrap_username: String,
    /// Bootstrap administrator password: used to create the account **only when the user table is empty** (⑤ §8.2).
    ///
    /// If empty, no bootstrap happens — an empty DB at startup only logs one warn suggesting `POST /v1/admin/users`
    /// or this setting to create the account. Production should inject it from a K8s Secret and clear it afterwards (② §6).
    pub bootstrap_password: Option<String>,
}
impl Default for Config {
    fn default() -> Self {
        Config {
            node: NodeCfg::default(),
            auth: AuthCfg::default(),
            pg: PgCfg::default(),
            wal: WalCfg::default(),
            redis: RedisCfg::default(),
            s3: S3Cfg::default(),
            bus: BusCfg::default(),
            audit: AuditCfg::default(),
            risk: RiskCfg::default(),
            mqtt: MqttCfg::default(),
            grpc: GrpcCfg::default(),
            media: MediaCfg::default(),
            compliance: ComplianceCfg::default(),
            maintenance: MaintenanceCfg::default(),
            quic: QuicCfg::default(),
            webtransport: WebTransportCfg::default(),
            policy: PolicyCfg::default(),
            pipeline: PipelineCfg::default(),
            inspectable: InspectableCfg::default(),
            delivery: DeliveryCfg::default(),
            degrade: DegradeCfg::default(),
            plugins: PluginsCfg::default(),
            admin: AdminCfg::default(),
        }
    }
}
impl Default for NodeCfg {
    fn default() -> Self {
        NodeCfg {
            id: String::new(),
            listen_http: "0.0.0.0:8080".into(),
            listen_ws: "0.0.0.0:8443".into(),
            metrics: "127.0.0.1:9100".into(),
            log: "json".into(),
        }
    }
}
impl Default for AuthCfg {
    fn default() -> Self {
        AuthCfg {
            jwt_alg: "RS256".into(),
            jwt_ttl: 900,
            jwt_issuer: "lattice".into(),
            key_dir: "/etc/lattice/keys".into(),
            fingerprint_required: true,
            key_overlap_hours: 24.0,
            key_prune_interval_ms: KEY_PRUNE_INTERVAL_MS_DEFAULT,
        }
    }
}
impl Default for PgCfg {
    fn default() -> Self {
        PgCfg {
            url: "postgres://lattice_app@pg:5432/lattice?sslmode=require".into(),
            pool_size: 32,
            statement_timeout_ms: 5_000,
            admin_statement_timeout_ms: 30_000,
        }
    }
}
impl Default for RedisCfg {
    fn default() -> Self {
        RedisCfg {
            url: "redis://redis:6379".into(),
            pool_size: 64,
            route_cache: 100_000,
            scan_count: DEFAULT_REDIS_SCAN_COUNT,
        }
    }
}
impl Default for S3Cfg {
    fn default() -> Self {
        S3Cfg {
            endpoint: "http://minio:9000".into(),
            public_endpoint: String::new(),
            region: "us-east-1".into(),
            access_key: String::new(),
            secret_key: String::new(),
            bucket_large: "lattice-large".into(),
            bucket_media: "lattice-media".into(),
            bucket_cold: "lattice-cold".into(),
            bucket_plugins: "lattice-plugins".into(),
            presign_ttl: 900,
            upload_parallel: 8,
        }
    }
}
impl Default for BusCfg {
    fn default() -> Self {
        BusCfg {
            kind: "redis-pubsub".into(),
            nats_url: "nats://nats:4222".into(),
            jetstream: true,
        }
    }
}
impl Default for AuditCfg {
    fn default() -> Self {
        AuditCfg {
            consumer_enabled: true,
            consumer_max_deliver: AUDIT_MAX_DELIVER_DEFAULT,
            consumer_ack_wait_ms: AUDIT_ACK_WAIT_MS_DEFAULT,
            consumer_retry_delay_ms: AUDIT_RETRY_DELAY_MS_DEFAULT,
            startup_probe: false,
        }
    }
}
impl Default for MqttCfg {
    fn default() -> Self {
        MqttCfg {
            enabled: false,
            bind: "0.0.0.0:1883".into(),
            max_connections: 10_000,
            // ⑤ §11: retransmission timeout/cap for QoS1 at-least-once; E2E can shorten it via env for speed.
            retransmit_ms: 10_000,
            max_retransmits: 3,
            // §17.13: 10 msg/s per device
            replay_rate_per_sec: 10,
            // QoS2/persistent session/WILL/retained (PL-11 additions): session 1h, MQTT5 session cap 1 day, retained 30 days
            session_ttl_secs: 3_600,
            session_expiry_max_secs: 86_400,
            retained_ttl_secs: 30 * 24 * 3_600,
            // MQTT 5 Topic Alias (PL-11 addition): CONNACK announces acceptance of aliases 1..=16.
            topic_alias_max: 16,
            // MQTT 5 Receive Maximum / outbound Topic Alias (more PL-11 additions):
            // server inbound in-flight cap 32 (echoed in CONNACK 0x21; 0 = echo 65535); outbound alias compression on by default.
            receive_maximum: crate::transport::mqtt::DEFAULT_RECEIVE_MAXIMUM,
            outbound_topic_alias: true,
            // TLS/mTLS (PL-11): off by default; default 8883 + require client certificates (fail-closed).
            tls_enabled: false,
            tls_bind: "0.0.0.0:8883".into(),
            tls_cert: String::new(),
            tls_key: String::new(),
            client_ca: String::new(),
            require_client_cert: true,
        }
    }
}
impl Default for GrpcCfg {
    fn default() -> Self {
        GrpcCfg {
            enabled: false,
            bind: "127.0.0.1:9090".into(),
            tls_cert: String::new(),
            tls_key: String::new(),
            tls_client_ca: String::new(),
            advertise: String::new(),
            fallback: true,
            client_cert: String::new(),
            client_key: String::new(),
            tls_domain: "localhost".into(),
            require_known_node_cn: false,
            require_caller_node: false,
            discovery: "auto".into(),
            peers: HashMap::new(),
        }
    }
}
impl Default for PolicyCfg {
    fn default() -> Self {
        use lattice_core::protocol as P;
        PolicyCfg {
            inline_threshold: P::INLINE_MAX_BYTES,
            chunk_threshold_max: P::CHUNK_THRESHOLD_MAX_BYTES,
            chunk_part: P::CHUNK_PART_BYTES,
            chunk_timeout: P::CHUNK_TIMEOUT_SECS,
            dedup_ttl: P::DEDUP_TTL_SECS,
            client_keepalive: P::KEEPALIVE_INTERVAL_SECS,
            client_ping: P::WS_PING_INTERVAL_SECS,
            server_idle_timeout: P::SERVER_DEAD_SECS,
            conn_ttl: P::CONN_TTL_SECS,
            ack_timeout: P::ACK_TIMEOUT_SECS,
            pending_rate_limit: P::PENDING_RATE_LIMIT_PER_SEC,
            seq_watermark_flush: P::SEQ_WATERMARK_FLUSH_SECS,
            msg_per_s: P::Quota::default().msg_per_s,
            bytes_per_s: P::Quota::default().bytes_per_s,
            topics_per_user: P::Quota::default().topics,
            member_cache_ttl_ms: DEFAULT_MEMBER_CACHE_TTL_MS,
            mode: "zero-knowledge".into(),
            protocol_min_supported: P::MIN_SUPPORTED_PROTOCOL,
            protocol_version: P::PROTOCOL_VERSION,
        }
    }
}
impl Default for DeliveryCfg {
    fn default() -> Self {
        DeliveryCfg {
            multidevice: "all-devices".into(),
        }
    }
}
impl Default for DegradeCfg {
    fn default() -> Self {
        DegradeCfg {
            redis_stale_cache: true,
            pg_wal_dir: "/var/lib/lattice/wal".into(),
            bus_fallback: "redis-pubsub".into(),
            inject_bus_failure: false,
        }
    }
}
impl Default for RiskCfg {
    fn default() -> Self {
        RiskCfg {
            // Safe default: off. Risk control is an operations policy and must not silently start collecting/acting after an upgrade.
            enabled: false,
            max_events_per_min: 120,
            device_switch_threshold: 3,
            device_switch_window_secs: 300,
            auth_failure_threshold: 10,
            auth_failure_window_secs: 60,
            message_window_secs: 60,
            queue_max_events: 1_000,
            queue_ttl_secs: 86_400,
            // Minimal intervention: audit only by default, never rate-limit/revoke; only an explicit throttle/reauth changes user availability.
            action: "audit".into(),
            throttle_secs: 300,
            report_debounce_secs: 10,
        }
    }
}
impl Default for PluginsCfg {
    fn default() -> Self {
        PluginsCfg {
            wasm_dir: "/etc/lattice/plugins".into(),
            sidecar_mtls: true,
            timeout_ms: lattice_plugins::limits::SIDECAR_TIMEOUT_MS,
            memory_mb: lattice_plugins::limits::MEMORY_MB,
            instructions: lattice_plugins::limits::INSTRUCTIONS,
            trusted_keys: HashMap::new(),
            trusted_keys_file: String::new(),
            // Safe default: require signature verification. dev-internal format plugins may explicitly set `require_verified_signature = false`.
            require_verified_signature: true,
            // By default read active/canary WASM plugins from the PG `plugins` table (the directory is still scanned and wins).
            from_db: true,
            // PG per-package cap 16MiB (prevents huge-bytea OOM); directory packages are still 64MiB.
            max_wasm_bytes: 16 * 1024 * 1024,
            // Off by default: with no sidecar configured the node uses NoopSidecar (passthrough), opening no connection.
            sidecar: SidecarCfg::default(),
        }
    }
}
impl Default for AdminCfg {
    fn default() -> Self {
        AdminCfg {
            pool_size: 8,
            sse_max_connections: lattice_core::protocol::SSE_MAX_CONNECTIONS,
            bootstrap_username: String::new(),
            bootstrap_password: None,
        }
    }
}
impl Config {
    /// Read TOML + environment overrides (`LATTICE__SECTION__FIELD`, e.g. `LATTICE__PG__URL`).
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut cfg = match path {
            Some(p) if p.exists() => {
                let raw = std::fs::read_to_string(p)
                    .map_err(|e| crate::error::internal(format!("read config failed: {e}")))?;
                toml::from_str(&raw)
                    .map_err(|e| crate::error::internal(format!("parse config failed: {e}")))?
            }
            _ => Config::default(),
        };
        cfg.apply_env();
        // Startup validation must fail fast: config errors such as an invalid bypass stage name / missing inspectable KEK
        // would silently turn into "thought it was bypassed" / "thought there was a KEK", which is more dangerous than refusing to start (E31/E15).
        cfg.validate()?;
        // inspectable node-local KEK load + startup self-check (no side effects when disabled).
        crate::pipeline::inspectable::bootstrap(&cfg.inspectable)?;
        Ok(cfg)
    }
    /// Startup validation of static config (fail-fast; `Config::load` and unit tests use the same contract).
    pub fn validate(&self) -> Result<()> {
        self.pipeline.validate()?;
        crate::pipeline::inspectable::validate_config(&self.inspectable, self.mode())?;
        Ok(())
    }
    /// Environment overrides (deployments only change env vars; secrets never hit disk).
    pub fn apply_env(&mut self) {
        for (k, v) in std::env::vars() {
            let Some(rest) = k.strip_prefix("LATTICE__") else {
                continue;
            };
            let parts: Vec<String> = rest.split("__").map(|s| s.to_lowercase()).collect();
            match parts.as_slice() {
                [s, f] if s == "node" && f == "id" => self.node.id = v,
                [s, f] if s == "node" && f == "listen_http" => self.node.listen_http = v,
                [s, f] if s == "node" && f == "listen_ws" => self.node.listen_ws = v,
                [s, f] if s == "node" && f == "metrics" => self.node.metrics = v,
                [s, f] if s == "pg" && f == "url" => self.pg.url = v,
                // Local WAL degradation (② §4.8)
                [s, f] if s == "wal" && f == "enabled" => {
                    self.wal.enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "wal" && f == "dir" => self.wal.dir = v,
                [s, f] if s == "wal" && f == "max_bytes" => {
                    if let Ok(n) = v.parse() {
                        self.wal.max_bytes = n;
                    }
                }
                [s, f] if s == "wal" && f == "replay_interval_ms" => {
                    if let Ok(n) = v.parse() {
                        self.wal.replay_interval_ms = n;
                    }
                }
                [s, f] if s == "redis" && f == "url" => self.redis.url = v,
                // Prefix scan batch size (PL-17: SCAN COUNT, 0 treated as the default 1000)
                [s, f] if s == "redis" && f == "scan_count" => {
                    if let Ok(n) = v.parse() {
                        self.redis.scan_count = n;
                    }
                }
                [s, f] if s == "s3" && f == "endpoint" => self.s3.endpoint = v,
                [s, f] if s == "s3" && f == "access_key" => self.s3.access_key = v,
                [s, f] if s == "s3" && f == "secret_key" => self.s3.secret_key = v,
                [s, f] if s == "auth" && f == "key_dir" => self.auth.key_dir = v,
                [s, f] if s == "policy" && f == "mode" => self.policy.mode = v,
                // Pipeline stage bypass (E31): `LATTICE__PIPELINE__BYPASS=validate,dedup` (empty = no bypass).
                // Invalid stage names are not silently dropped here; `Config::validate` fails fast.
                [s, f] if s == "pipeline" && f == "bypass" => {
                    self.pipeline.bypass = v
                        .split(',')
                        .map(str::trim)
                        .filter(|x| !x.is_empty())
                        .map(str::to_string)
                        .collect();
                }
                // inspectable node-local KEK (E15): material only via env/Secret or a file, never in TOML.
                [s, f] if s == "inspectable" && f == "enabled" => {
                    self.inspectable.enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "inspectable" && f == "kek_id" => self.inspectable.kek_id = v,
                [s, f] if s == "inspectable" && f == "kek" => self.inspectable.kek = v,
                [s, f] if s == "inspectable" && f == "kek_file" => self.inspectable.kek_file = v,
                [s, f] if s == "inspectable" && f == "previous_kek_id" => {
                    self.inspectable.previous_kek_id = v
                }
                [s, f] if s == "inspectable" && f == "previous_kek" => {
                    self.inspectable.previous_kek = v
                }
                // Membership positive cache TTL (PL-17: the hot path did 2 PG membership queries per message; 0 disables the cache)
                [s, f] if s == "policy" && f == "member_cache_ttl_ms" => {
                    if let Ok(n) = v.parse() {
                        self.policy.member_cache_ttl_ms = n;
                    }
                }
                [s, f] if s == "bus" && f == "kind" => self.bus.kind = v,
                // Risk-control rule engine (E03): E2E/drills override all thresholds and actions via env without touching TOML.
                [s, f] if s == "risk" && f == "enabled" => {
                    self.risk.enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "risk" && f == "max_events_per_min" => {
                    if let Ok(n) = v.parse() {
                        self.risk.max_events_per_min = n;
                    }
                }
                [s, f] if s == "risk" && f == "message_window_secs" => {
                    if let Ok(n) = v.parse() {
                        self.risk.message_window_secs = n;
                    }
                }
                [s, f] if s == "risk" && f == "device_switch_threshold" => {
                    if let Ok(n) = v.parse() {
                        self.risk.device_switch_threshold = n;
                    }
                }
                [s, f] if s == "risk" && f == "device_switch_window_secs" => {
                    if let Ok(n) = v.parse() {
                        self.risk.device_switch_window_secs = n;
                    }
                }
                [s, f] if s == "risk" && f == "auth_failure_threshold" => {
                    if let Ok(n) = v.parse() {
                        self.risk.auth_failure_threshold = n;
                    }
                }
                [s, f] if s == "risk" && f == "auth_failure_window_secs" => {
                    if let Ok(n) = v.parse() {
                        self.risk.auth_failure_window_secs = n;
                    }
                }
                [s, f] if s == "risk" && f == "queue_max_events" => {
                    if let Ok(n) = v.parse() {
                        self.risk.queue_max_events = n;
                    }
                }
                [s, f] if s == "risk" && f == "queue_ttl_secs" => {
                    if let Ok(n) = v.parse() {
                        self.risk.queue_ttl_secs = n;
                    }
                }
                [s, f] if s == "risk" && f == "action" => self.risk.action = v,
                [s, f] if s == "risk" && f == "throttle_secs" => {
                    if let Ok(n) = v.parse() {
                        self.risk.throttle_secs = n;
                    }
                }
                [s, f] if s == "risk" && f == "report_debounce_secs" => {
                    if let Ok(n) = v.parse() {
                        self.risk.report_debounce_secs = n;
                    }
                }
                [s, f] if s == "admin" && f == "bootstrap_username" => {
                    self.admin.bootstrap_username = v
                }
                [s, f] if s == "admin" && f == "bootstrap_password" => {
                    self.admin.bootstrap_password = Some(v)
                }
                [s, f] if s == "node" && f == "log" => self.node.log = v,
                // Remaining overrides the deployment plane (K8s/Helm) needs: without them the chart would have to stuff non-secret config into ConfigMap,
                // while deployment-specific values such as the public endpoint / bucket names / MQTT switches belong in environment variables.
                [s, f] if s == "s3" && f == "public_endpoint" => self.s3.public_endpoint = v,
                [s, f] if s == "s3" && f == "region" => self.s3.region = v,
                [s, f] if s == "s3" && f == "bucket_large" => self.s3.bucket_large = v,
                [s, f] if s == "s3" && f == "bucket_media" => self.s3.bucket_media = v,
                [s, f] if s == "s3" && f == "bucket_cold" => self.s3.bucket_cold = v,
                [s, f] if s == "s3" && f == "bucket_plugins" => self.s3.bucket_plugins = v,
                [s, f] if s == "s3" && f == "presign_ttl" => {
                    if let Ok(n) = v.parse() {
                        self.s3.presign_ttl = n;
                    }
                }
                [s, f] if s == "bus" && f == "nats_url" => self.bus.nats_url = v,
                [s, f] if s == "bus" && f == "jetstream" => {
                    self.bus.jetstream = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                // Audit stream consumer (PL-11/PL-14): E2E uses env to shrink ack_wait/retry delay for speed
                [s, f] if s == "audit" && f == "consumer_enabled" => {
                    self.audit.consumer_enabled =
                        matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "audit" && f == "consumer_max_deliver" => {
                    if let Ok(n) = v.parse() {
                        self.audit.consumer_max_deliver = n;
                    }
                }
                [s, f] if s == "audit" && f == "consumer_ack_wait_ms" => {
                    if let Ok(n) = v.parse() {
                        self.audit.consumer_ack_wait_ms = n;
                    }
                }
                [s, f] if s == "audit" && f == "consumer_retry_delay_ms" => {
                    if let Ok(n) = v.parse() {
                        self.audit.consumer_retry_delay_ms = n;
                    }
                }
                [s, f] if s == "audit" && f == "startup_probe" => {
                    self.audit.startup_probe = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "mqtt" && f == "enabled" => {
                    self.mqtt.enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "mqtt" && f == "bind" => self.mqtt.bind = v,
                [s, f] if s == "mqtt" && f == "max_connections" => {
                    if let Ok(n) = v.parse() {
                        self.mqtt.max_connections = n;
                    }
                }
                // QoS1 reliability (PL-11): retransmission timeout/cap, offline redelivery rate; E2E uses short timeouts for speed
                [s, f] if s == "mqtt" && f == "retransmit_ms" => {
                    if let Ok(n) = v.parse() {
                        self.mqtt.retransmit_ms = n;
                    }
                }
                [s, f] if s == "mqtt" && f == "max_retransmits" => {
                    if let Ok(n) = v.parse() {
                        self.mqtt.max_retransmits = n;
                    }
                }
                [s, f] if s == "mqtt" && f == "replay_rate_per_sec" => {
                    if let Ok(n) = v.parse() {
                        self.mqtt.replay_rate_per_sec = n;
                    }
                }
                // QoS2/persistent session/retained (PL-11 additions): session TTL / MQTT5 session cap / retained fallback TTL
                [s, f] if s == "mqtt" && f == "session_ttl_secs" => {
                    if let Ok(n) = v.parse() {
                        self.mqtt.session_ttl_secs = n;
                    }
                }
                [s, f] if s == "mqtt" && f == "session_expiry_max_secs" => {
                    if let Ok(n) = v.parse() {
                        self.mqtt.session_expiry_max_secs = n;
                    }
                }
                [s, f] if s == "mqtt" && f == "retained_ttl_secs" => {
                    if let Ok(n) = v.parse() {
                        self.mqtt.retained_ttl_secs = n;
                    }
                }
                // Wildcards/shared subscriptions (no switch needed: filter syntax extends naturally); Topic Alias cap (0=off)
                [s, f] if s == "mqtt" && f == "topic_alias_max" => {
                    if let Ok(n) = v.parse() {
                        self.mqtt.topic_alias_max = n;
                    }
                }
                // MQTT 5 Receive Maximum / outbound Topic Alias (more PL-11 additions)
                [s, f] if s == "mqtt" && f == "receive_maximum" => {
                    if let Ok(n) = v.parse() {
                        self.mqtt.receive_maximum = n;
                    }
                }
                [s, f] if s == "mqtt" && f == "outbound_topic_alias" => {
                    self.mqtt.outbound_topic_alias =
                        matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                // TLS/mTLS (PL-11): `LATTICE__MQTT__TLS_*` overrides; certificates/keys are paths only (content never goes in env).
                [s, f] if s == "mqtt" && f == "tls_enabled" => {
                    self.mqtt.tls_enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "mqtt" && f == "tls_bind" => self.mqtt.tls_bind = v,
                [s, f] if s == "mqtt" && f == "tls_cert" => self.mqtt.tls_cert = v,
                [s, f] if s == "mqtt" && f == "tls_key" => self.mqtt.tls_key = v,
                [s, f] if s == "mqtt" && f == "client_ca" => self.mqtt.client_ca = v,
                [s, f] if s == "mqtt" && f == "require_client_cert" => {
                    self.mqtt.require_client_cert =
                        matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "grpc" && f == "enabled" => {
                    self.grpc.enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "grpc" && f == "bind" => self.grpc.bind = v,
                [s, f] if s == "grpc" && f == "tls_cert" => self.grpc.tls_cert = v,
                [s, f] if s == "grpc" && f == "tls_key" => self.grpc.tls_key = v,
                [s, f] if s == "grpc" && f == "tls_client_ca" => self.grpc.tls_client_ca = v,
                [s, f] if s == "grpc" && f == "advertise" => self.grpc.advertise = v,
                [s, f] if s == "grpc" && f == "fallback" => {
                    self.grpc.fallback = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "grpc" && f == "client_cert" => self.grpc.client_cert = v,
                [s, f] if s == "grpc" && f == "client_key" => self.grpc.client_key = v,
                [s, f] if s == "grpc" && f == "tls_domain" => self.grpc.tls_domain = v,
                [s, f] if s == "grpc" && f == "require_known_node_cn" => {
                    self.grpc.require_known_node_cn =
                        matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "grpc" && f == "require_caller_node" => {
                    self.grpc.require_caller_node =
                        matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "grpc" && f == "discovery" => self.grpc.discovery = v,
                [s, f] if s == "grpc" && f == "peers" => {
                    // Format: "node-a=10.0.0.1:9090,node-b=10.0.0.2:9090"
                    self.grpc.peers = v
                        .split(',')
                        .filter_map(|pair| {
                            let (id, addr) = pair.split_once('=')?;
                            let id = id.trim();
                            let addr = addr.trim();
                            (!id.is_empty() && !addr.is_empty())
                                .then(|| (id.to_string(), addr.to_string()))
                        })
                        .collect()
                }
                [s, f] if s == "media" && f == "turn_uris" => {
                    self.media.turn_uris = v
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                }
                [s, f] if s == "media" && f == "turn_secret" => self.media.turn_secret = v,
                [s, f] if s == "media" && f == "turn_ttl" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.media.turn_ttl = n;
                    }
                }
                [s, f] if s == "media" && f == "max_streams" => {
                    if let Ok(n) = v.parse::<usize>() {
                        self.media.max_streams = n;
                    }
                }
                [s, f] if s == "media" && f == "stream_bitrate_bps" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.media.stream_bitrate_bps = n;
                    }
                }
                [s, f] if s == "media" && f == "record_enabled" => {
                    self.media.record_enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "media" && f == "record_bucket" => self.media.record_bucket = v,
                [s, f] if s == "media" && f == "record_segment_bytes" => {
                    if let Ok(n) = v.parse::<usize>() {
                        self.media.record_segment_bytes = n;
                    }
                }
                [s, f] if s == "media" && f == "record_bus_ack_wait_ms" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.media.record_bus_ack_wait_ms = n;
                    }
                }
                [s, f] if s == "media" && f == "record_bus_max_deliver" => {
                    if let Ok(n) = v.parse::<i64>() {
                        self.media.record_bus_max_deliver = n;
                    }
                }
                [s, f] if s == "media" && f == "record_bus_retry_delay_ms" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.media.record_bus_retry_delay_ms = n;
                    }
                }
                // Recording object lifecycle reclamation: 0 = no reclamation (default); positive = retention days
                [s, f] if s == "media" && f == "record_retention_days" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.media.record_retention_days = n;
                    }
                }
                // Compliance hard-delete window (E02): `LATTICE__COMPLIANCE__PURGE_HARD_DELETE_DAYS`
                // and job-interval overrides; E2E overrides the interval so background jobs do not race manual triggers.
                [s, f] if s == "compliance" && f == "purge_hard_delete_days" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.compliance.purge_hard_delete_days = n;
                    }
                }
                [s, f] if s == "compliance" && f == "purge_cleanup_interval_secs" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.compliance.purge_cleanup_interval_secs = n;
                    }
                }
                // Residual multipart GC (E04): the age threshold allows fractions (E2E uses 0.0003h ≈ 1.08s)
                [s, f] if s == "maintenance" && f == "multipart_gc_hours" => {
                    if let Ok(n) = v.parse::<f64>() {
                        self.maintenance.multipart_gc_hours = n;
                    }
                }
                [s, f] if s == "maintenance" && f == "multipart_gc_interval_secs" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.maintenance.multipart_gc_interval_secs = n;
                    }
                }
                // Cold archive / orphan object GC (E01): `LATTICE__MAINTENANCE__ARCHIVE_*`
                // and `LATTICE__MAINTENANCE__OBJECT_GC_*`; E2E triggers deterministically with short intervals.
                [s, f] if s == "maintenance" && f == "archive_enabled" => {
                    self.maintenance.archive_enabled =
                        matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "maintenance" && f == "archive_after_days" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.maintenance.archive_after_days = n;
                    }
                }
                [s, f] if s == "maintenance" && f == "archive_bucket" => {
                    self.maintenance.archive_bucket = v
                }
                [s, f] if s == "maintenance" && f == "archive_interval_secs" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.maintenance.archive_interval_secs = n;
                    }
                }
                [s, f] if s == "maintenance" && f == "object_gc_enabled" => {
                    self.maintenance.object_gc_enabled =
                        matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "maintenance" && f == "object_gc_interval_secs" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.maintenance.object_gc_interval_secs = n;
                    }
                }
                [s, f] if s == "maintenance" && f == "object_gc_grace_days" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.maintenance.object_gc_grace_days = n;
                    }
                }
                // QUIC server relay skeleton (feature=quic; E2E enables it via env and points it at a separate port/temporary certificate)
                [s, f] if s == "quic" && f == "enabled" => {
                    self.quic.enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "quic" && f == "bind" => self.quic.bind = v,
                [s, f] if s == "quic" && f == "cert" => self.quic.cert = v,
                [s, f] if s == "quic" && f == "key" => self.quic.key = v,
                [s, f] if s == "quic" && f == "idle_timeout_secs" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.quic.idle_timeout_secs = n;
                    }
                }
                [s, f] if s == "quic" && f == "handshake_timeout_secs" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.quic.handshake_timeout_secs = n;
                    }
                }
                [s, f] if s == "quic" && f == "token_ttl_secs" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.quic.token_ttl_secs = n;
                    }
                }
                // WebTransport(HTTP/3) browser gateway (feature=webtransport; E2E enables it via env and points it at a separate port/temporary certificate)
                [s, f] if s == "webtransport" && f == "enabled" => {
                    self.webtransport.enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "webtransport" && f == "bind" => self.webtransport.bind = v,
                [s, f] if s == "webtransport" && f == "cert" => self.webtransport.cert = v,
                [s, f] if s == "webtransport" && f == "key" => self.webtransport.key = v,
                [s, f] if s == "webtransport" && f == "upstream" => self.webtransport.upstream = v,
                [s, f] if s == "webtransport" && f == "upstream_ca" => {
                    self.webtransport.upstream_ca = v
                }
                [s, f] if s == "webtransport" && f == "token_ttl_secs" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.webtransport.token_ttl_secs = n;
                    }
                }
                [s, f] if s == "webtransport" && f == "idle_timeout_secs" => {
                    if let Ok(n) = v.parse::<u64>() {
                        self.webtransport.idle_timeout_secs = n;
                    }
                }
                [s, f] if s == "webtransport" && f == "path" => self.webtransport.path = v,
                // Plugin WASM host (PL-10 / design ② §4.5): directory, limits, Ed25519 verification config.
                // trusted_keys looks like "release-2025=<base64>,internal=<base64>".
                [s, f] if s == "plugins" && f == "wasm_dir" => self.plugins.wasm_dir = v,
                [s, f] if s == "plugins" && f == "sidecar_mtls" => {
                    self.plugins.sidecar_mtls = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "plugins" && f == "timeout_ms" => {
                    if let Ok(n) = v.parse() {
                        self.plugins.timeout_ms = n;
                    }
                }
                [s, f] if s == "plugins" && f == "memory_mb" => {
                    if let Ok(n) = v.parse() {
                        self.plugins.memory_mb = n;
                    }
                }
                [s, f] if s == "plugins" && f == "instructions" => {
                    if let Ok(n) = v.parse() {
                        self.plugins.instructions = n;
                    }
                }
                [s, f] if s == "plugins" && f == "trusted_keys" => {
                    // Like "release-2025=<base64pub>,internal=<base64pub>"
                    self.plugins.trusted_keys = v
                        .split(',')
                        .filter_map(|pair| {
                            let (id, key) = pair.split_once('=')?;
                            let id = id.trim();
                            let key = key.trim();
                            (!id.is_empty() && !key.is_empty())
                                .then(|| (id.to_string(), key.to_string()))
                        })
                        .collect();
                }
                [s, f] if s == "plugins" && f == "trusted_keys_file" => {
                    self.plugins.trusted_keys_file = v
                }
                [s, f] if s == "plugins" && f == "require_verified_signature" => {
                    self.plugins.require_verified_signature =
                        matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                // PG `plugins` table registration (PL-10 addition): default true; E2E can disable it via env to isolate the directory path.
                [s, f] if s == "plugins" && f == "from_db" => {
                    self.plugins.from_db = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "plugins" && f == "max_wasm_bytes" => {
                    if let Ok(n) = v.parse() {
                        self.plugins.max_wasm_bytes = n;
                    }
                }
                // External gRPC sidecar (PL-10 / ⑤ §10): off by default; env looks like
                // `LATTICE__PLUGINS__SIDECAR__ENABLED=true` / `..._ENDPOINT=http://127.0.0.1:19090`.
                [s, sub, f] if s == "plugins" && sub == "sidecar" && f == "enabled" => {
                    self.plugins.sidecar.enabled =
                        matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, sub, f] if s == "plugins" && sub == "sidecar" && f == "endpoint" => {
                    self.plugins.sidecar.endpoint = v
                }
                [s, sub, f] if s == "plugins" && sub == "sidecar" && f == "timeout_ms" => {
                    if let Ok(n) = v.parse() {
                        self.plugins.sidecar.timeout_ms = n;
                    }
                }
                [s, sub, f] if s == "plugins" && sub == "sidecar" && f == "tls_ca" => {
                    self.plugins.sidecar.tls_ca = v
                }
                [s, sub, f] if s == "plugins" && sub == "sidecar" && f == "tls_cert" => {
                    self.plugins.sidecar.tls_cert = v
                }
                [s, sub, f] if s == "plugins" && sub == "sidecar" && f == "tls_key" => {
                    self.plugins.sidecar.tls_key = v
                }
                [s, f] if s == "degrade" && f == "inject_bus_failure" => {
                    self.degrade.inject_bus_failure =
                        matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                [s, f] if s == "auth" && f == "jwt_issuer" => self.auth.jwt_issuer = v,
                [s, f] if s == "auth" && f == "jwt_ttl" => {
                    if let Ok(n) = v.parse() {
                        self.auth.jwt_ttl = n;
                    }
                }
                [s, f] if s == "auth" && f == "fingerprint_required" => {
                    self.auth.fingerprint_required =
                        matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
                }
                // Dual-key overlap window (hours; fractions allowed for E2E drills) + previous cleanup interval
                [s, f] if s == "auth" && f == "key_overlap_hours" => {
                    if let Ok(n) = v.parse::<f64>() {
                        if n.is_finite() {
                            self.auth.key_overlap_hours = n.max(0.0);
                        }
                    }
                }
                [s, f] if s == "auth" && f == "key_prune_interval_ms" => {
                    if let Ok(n) = v.parse() {
                        self.auth.key_prune_interval_ms = n;
                    }
                }
                _ => {}
            }
        }
    }
    pub fn quota(&self) -> lattice_core::Quota {
        lattice_core::Quota {
            msg_per_s: self.policy.msg_per_s,
            bytes_per_s: self.policy.bytes_per_s,
            topics: self.policy.topics_per_user,
            storage_bytes: lattice_core::Quota::default().storage_bytes,
        }
    }
    pub fn mode(&self) -> lattice_core::Mode {
        match self.policy.mode.as_str() {
            "inspectable" => lattice_core::Mode::Inspectable,
            _ => lattice_core::Mode::ZeroKnowledge,
        }
    }
    /// Server-accepted protocol range `[max(min_supported, N-1), N]` (§17.12).
    pub fn protocol_range(&self) -> (u8, u8) {
        let n = self.policy.protocol_version;
        (
            self.policy.protocol_min_supported.max(n.saturating_sub(1)),
            n,
        )
    }
}
/// Default config file (deploy/compose/dev.yaml references the same content, avoiding drift between the two).
pub const SAMPLE_TOML: &str = r#"
[node]
id = ""
listen_http = "0.0.0.0:8080"
listen_ws = "0.0.0.0:8443"
metrics = "127.0.0.1:9100"
log = "json"
[auth]
jwt_alg = "RS256"
jwt_ttl = 900
jwt_issuer = "lattice"
key_dir = "/etc/lattice/keys"
fingerprint_required = true
key_overlap_hours = 24.0                    # dual-key overlap window (hours, ⑤ §8.4; fractions allowed for drills)
key_prune_interval_ms = 60000               # previous expiry cleanup interval; 0 invalid → default, too small clamps to 100ms
[pg]
url = "postgres://lattice_app@pg:5432/lattice?sslmode=disable"
pool_size = 32
[wal]
enabled = true                           # small messages go to the local WAL when PG is not writable (② §4.8)
dir = ""                                 # empty = fall back to [degrade] pg_wal_dir (K8s emptyDir volume)
max_bytes = 67108864                     # 64MiB; 0 invalid → default, over-limit appends are rejected and counted as dropped
replay_interval_ms = 2000                # periodic replay interval
[redis]
url = "redis://redis:6379"
pool_size = 64
[s3]
endpoint = "http://minio:9000"
public_endpoint = ""                     # address reachable by browser/desktop clients; empty = same as endpoint
bucket_large = "lattice-large"
bucket_media = "lattice-media"
bucket_cold = "lattice-cold"
bucket_plugins = "lattice-plugins"
presign_ttl = 900
upload_parallel = 8
[bus]
kind = "redis-pubsub"
[risk]
# Risk-control rule engine (E03 / PL-12 12.6/12.7; rule engine, not ML). Off by default = no collection, no side effects.
enabled = false
max_events_per_min = 120                 # rule a: message-count threshold for one device in a 60s sliding window
message_window_secs = 60                 # rule a window (0 invalid → 60)
device_switch_threshold = 3              # rule b: distinct new-device count threshold for the same account in the window
device_switch_window_secs = 300          # rule b window
auth_failure_threshold = 10              # rule c: auth-failure count threshold in the window (JWT verification failure = 401 class)
auth_failure_window_secs = 60            # rule c window
queue_max_events = 1000                  # bounded lattice:risk ZSET (keep only the newest N)
queue_ttl_secs = 86400                   # lattice:risk TTL (refreshed when a hit is written)
action = "audit"                         # disposition: audit (audit only) | throttle (device rate limit) | reauth (revoke refresh)
throttle_secs = 300                      # throttle window (default 5 minutes)
report_debounce_secs = 10                # report debounce for hits of the same target+rule
[mqtt]
enabled = false                          # P3: gateway listens on 1883 (TLS terminated by a front proxy); enabled in dev.toml
bind = "0.0.0.0:1883"
max_connections = 10000
# retransmit_ms = 10000                  # outbound QoS1/QoS2 PUBACK/PUBREC wait timeout
# max_retransmits = 3                    # outbound QoS1/QoS2 retransmission cap (disconnect when exceeded)
# replay_rate_per_sec = 10               # offline topic pending redelivery rate (msg/s per device)
# --- QoS2 / persistent session / retained (PL-11 additions) ----------------------------------------
# session_ttl_secs = 3600                # clean=false session state Redis TTL (0 = disable persistent sessions)
# session_expiry_max_secs = 86400        # clamp cap for the MQTT 5 Session Expiry Interval
# retained_ttl_secs = 2592000            # retained fallback TTL (30 days; refreshed on every retain=1 publish)
# --- Wildcards / shared subscriptions / Topic Alias (more PL-11 additions) --------------------------------
# topic_alias_max = 16                   # MQTT5 Topic Alias cap (echoed in CONNACK 0x22 once the client declares it; 0=no aliases)
# --- MQTT5 Receive Maximum / Subscription Identifier / outbound Topic Alias --------------
# receive_maximum = 32                   # server inbound QoS1/2 in-flight cap (echoed in CONNACK 0x21 once the client declares it; 0=echo 65535)
# outbound_topic_alias = true            # outbound topic alias compression (only when the client's Topic Alias Maximum>0)
# --- TLS / mTLS device certificates (PL-11; off by default, plaintext bind unaffected) -----------------------
tls_enabled = false                      # true = additionally listen on tls_bind (TLS/mTLS); startup failures only WARN
tls_bind = "0.0.0.0:8883"                # TLS listen address (dev/E2E use a separate port)
# tls_cert = "/etc/lattice/tls/mqtt.crt" # server certificate chain PEM (first is the leaf); empty = config error, no listener
# tls_key = "/etc/lattice/tls/mqtt.key"  # server private key PEM (PKCS#8/PKCS#1/SEC1)
# client_ca = "/etc/lattice/tls/mqtt-client-ca.crt"  # client certificate trust anchor (required when require_client_cert)
require_client_cert = true               # require client certificates (mTLS); when false, no certificate falls back to PSK/JWT
[grpc]
enabled = false                          # internal gRPC (⑤ §10); production enables it with mTLS
bind = "127.0.0.1:9090"
# advertise = "node-a:9090"              # address advertised to other nodes (written to heartbeat for gRPC fallback routing)
fallback = true                          # whether to use the gRPC Route fallback when bus publish fails
# tls_cert = "/etc/lattice/tls/server.crt"
# tls_key = "/etc/lattice/tls/server.key"
# tls_client_ca = "/etc/lattice/tls/ca.crt"
# client_cert = "/etc/lattice/tls/client.crt"   # defaults to reusing tls_cert
# client_key = "/etc/lattice/tls/client.key"
# tls_domain = "localhost"                       # SAN for outbound verification
# require_known_node_cn = true                   # the client certificate CN must be a known node_id (Route)
# require_caller_node = true                     # Route.caller_node must exist and == the certificate CN
# discovery = "auto"                              # auto=heartbeat first, static fallback; static=peers only
# peers = { "node-b" = "10.0.0.2:9090" }          # static peer table used when Redis is unavailable
[media]
# TURN is deployed standalone as coturn (design §17.9); the node only issues short-lived credentials (⑤ §9.7).
# Production: turn_secret must come from a Secret/env (LATTICE__MEDIA__TURN_SECRET), never ConfigMap.
# turn_uris = ["turn:turn.example.com:3478?transport=udp"]
# turn_secret = "<coturn static-auth-secret>"
# turn_ttl = 600                                 # ≤600s
# max_streams = 5000                             # per-node concurrent media stream cap (§17.9)
# stream_bitrate_bps = 8388608                   # 8Mbps per stream (§17.9)
# --- Media recording tee (PL-13 13.6; off by default) ---------------------------------------------
# record_enabled = true                          # tee only WS tunnel stream-data raw frames; with bus=nats they go via media.record.* to object storage
# record_bucket = "lattice-media"                # empty = fall back to [s3] bucket_media
# record_segment_bytes = 4194304                 # 4MiB per-segment cap (shared by both persist paths); 0 invalid → default
# record_bus_ack_wait_ms = 30000                 # recording consumer ack_wait; must be > the worst persist latency
# record_bus_max_deliver = 5                     # recording consumer redelivery cap; exhaustion → DLQ log+metric
# record_bus_retry_delay_ms = 1000               # recording consumer NAK redelivery delay (currently mostly local buffer retries)
# record_retention_days = 7                      # lifecycle reclamation: 0=no reclamation (default); positive=retention days, GC ≤1000 rows per round
[compliance]
# Compliance delete (E02 / ⑤ §8.2): soft delete + object/Redis cascade run immediately; after the window the background job hard-deletes user rows.
purge_hard_delete_days = 7               # hard-delete window (days); 0 = disable background hard delete
purge_cleanup_interval_secs = 3600       # hard-delete job interval (seconds); 0 invalid → default, 60 floor
[maintenance]
# Object-storage maintenance (E04 / ⑥ §2.6): residual multipart upload reclamation (lock:gc-multipart).
multipart_gc_hours = 24.0                # unfinished multipart age threshold (hours, fractions allowed; <=0=off)
multipart_gc_interval_secs = 3600        # reclamation job interval (seconds); 0 invalid → default, 60 floor
# --- E01 cold archive (⑥ §2.5/§2.6 lock:archive; off by default = zero side effects) ----------------------
archive_enabled = false                  # true = run one "export→zstd→cold bucket→DETACH" round every archive_interval_secs
archive_after_days = 30                  # online retention (days); created_at < now()-N days is archivable (0=off)
archive_bucket = ""                      # empty = fall back to [s3] bucket_cold (ensure_buckets guarantees it)
archive_interval_secs = 86400            # job interval (seconds); 0 invalid → default 86400, 1s floor (E2E uses 1–2s)
# --- E01 orphan object GC (⑥ §4.1 lock:gc-objects; off by default = zero side effects) ------------------
object_gc_enabled = false                # true = reclaim archived object candidates + unreferenced cold-bucket objects
object_gc_interval_secs = 86400          # job interval (seconds); 0 invalid → default 86400, 1s floor
object_gc_grace_days = 30                # grace period for archived objects (days, design §4.1 "delete 30 days after invalidation"; 0=immediate, E2E only)
[quic]
# QUIC/WebTransport server relay skeleton (design §17.9 path ②; the unfinished P4 item of PL-13 13.3).
# Dual switch: compile-time feature `quic` (off by default) + this section's enabled (default false).
# Stream caps/rate limits reuse [media] max_streams / stream_bitrate_bps; not repeated here.
enabled = false
bind = "0.0.0.0:4433"                  # design port 443 (deploy/quic-lb-udp.yaml); dev/E2E use a separate port
# cert = "/etc/lattice/tls/quic.crt"   # empty + empty key = dev self-signed temporary certificate (memory only, never production)
# key = "/etc/lattice/tls/quic.key"
idle_timeout_secs = 30
handshake_timeout_secs = 10            # aligned with §17.9 "the client degrades after a 10s negotiation timeout"
token_ttl_secs = 120                   # join token short-lived ticket (bound to stream_id+purpose+expiry; cap 3600)
[webtransport]
# WebTransport(HTTP/3) browser gateway (design §17.9 path ②; PL-13 13.3).
# Dual switch: compile-time feature `webtransport` (off by default, implies quic) + this section's enabled (default false).
# Bridge semantics: WT bidirectional stream → local QUIC listener (the gateway is an internal QUIC client); auth/TLV/relay/rate limiting all reuse [quic].
# The port must differ from [quic] bind (two UDP listeners on one host compete for the port; a conflict only WARNs and the node stays ready).
enabled = false
bind = "0.0.0.0:4433"                  # browser-reachable HTTP/3 port; dev/E2E use a separate port
# cert = "/etc/lattice/tls/wt.crt"     # empty + empty key = dev self-signed temporary certificate (memory only, never production)
# key = "/etc/lattice/tls/wt.key"
# upstream = "127.0.0.1:4433"          # bridge upstream; empty = derive from [quic] bind (wildcards become loopback)
# upstream_ca = "/etc/lattice/tls/ca.crt"  # empty = reuse [quic] cert; with QUIC dev self-signed the bridge skips verification (loopback only, WARN)
token_ttl_secs = 120                   # WT session registration/pairing window (aligned with [quic] token_ttl_secs; cap 3600)
idle_timeout_secs = 30                 # HTTP/3 connection idle timeout (cap 600)
path = "/media"                        # WebTransport CONNECT path; other paths return 404
[plugins]
# Server-side WASM format plugin host (design ② §4.5 / PL-10; the binary must be built with `--features wasm-host`).
# Directory layout: <wasm_dir>/<ns>/manifest.json + plugin.wasm + signature
# The signed body is fixed as sha256(wasm || manifest_canonical_json), Ed25519 (64B, stored base64 in manifest.signature).
wasm_dir = "/etc/lattice/plugins"
timeout_ms = 500                           # wall-clock cap per call (a manifest may only request less)
memory_mb = 64                             # per-instance memory cap (MiB)
instructions = 100000000                   # fuel cap per call
require_verified_signature = true          # default fail-closed: unsigned/bad signature/unknown key are not loaded
from_db = true                             # after startup, asynchronously read the PG `plugins` table (active/canary; does not block ready)
max_wasm_bytes = 16777216                  # PG per-package cap 16MiB (directory packages still 64MiB)
# trusted_keys = { "release-2025" = "<base64 raw 32B Ed25519 pubkey>" }
# trusted_keys_file = "/etc/lattice/plugins/trusted_keys.json"   # {"<id>": "<base64 pubkey>"}
[plugins.sidecar]
# External gRPC plugin sidecar (PL-10 / ⑤ §10; off by default → NoopSidecar passthrough, no connection).
# When enabled the node only validates config at startup (lazy connect) and connects on the first call; unreachable → the call fails (messages still pass through).
# 500ms timeout / 30s circuit break are a fixed contract (changing timeout_ms only affects the client hard-timeout cap).
enabled = false
# endpoint = "http://127.0.0.1:19090"          # plaintext is dev only; startup WARN
# timeout_ms = 500                             # 0 = default 500
# --- mTLS (enabled only when all three are present; missing = config error, node WARNs and falls back to Noop, never silent plaintext) ---
# tls_ca = "/etc/lattice/tls/sidecar-ca.crt"   # verify the sidecar server certificate
# tls_cert = "/etc/lattice/tls/sidecar-client.crt"
# tls_key = "/etc/lattice/tls/sidecar-client.key"
[policy]
mode = "zero-knowledge"
dedup_ttl = 86400
chunk_threshold_max = 33554432
chunk_part = 262144
protocol_version = 1
protocol_min_supported = 1
[pipeline]
# Stage bypass (E31 / ② §2.2 debugging/emergency): valid stage names validate/member/dedup/detect/format/seq/
# persist/route; default empty = all active. An invalid name fails at startup (fail-fast).
bypass = []

[inspectable]
# Node-local KEK for auditable-content mode (E15 / D3; off by default = identical to before it existed).
# Production material only via env/Secret (LATTICE__INSPECTABLE__KEK*); never in TOML/ConfigMap.
enabled = false
# kek_id = "kek-2026"                      # current KEK id (for envelope metadata/audit, no material)
# kek = "<base64 32B | hex 64 chars>"      # one of kek/kek_file; required when enabled=true
# kek_file = "/etc/lattice/kek/current"    # rotation window: provide previous_kek/previous_kek_id as a pair
# previous_kek_id = "kek-2025"
# previous_kek = "<base64 32B | hex 64 chars>"
"#;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sample_toml_parses_and_matches_defaults() {
        let cfg: Config = toml::from_str(SAMPLE_TOML).unwrap();
        let def = Config::default();
        assert_eq!(cfg.policy.dedup_ttl, def.policy.dedup_ttl);
        assert_eq!(cfg.policy.chunk_part, def.policy.chunk_part);
    }
    #[test]
    fn perf_tuning_defaults_and_bounds() {
        let def = Config::default();
        // SCAN batching: default COUNT=1000 (PL-17; the old redis-rs scan_match default was 10)
        assert_eq!(def.redis.scan_count, DEFAULT_REDIS_SCAN_COUNT);
        assert_eq!(def.redis.effective_scan_count(), 1_000);
        // Membership cache: default 1000ms
        assert_eq!(def.policy.member_cache_ttl_ms, DEFAULT_MEMBER_CACHE_TTL_MS);
        assert_eq!(
            def.policy.effective_member_cache_ttl(),
            Duration::from_millis(1_000)
        );
        let mut cfg = Config::default();
        cfg.redis.scan_count = 0; // 0 = not configured → default
        assert_eq!(cfg.redis.effective_scan_count(), DEFAULT_REDIS_SCAN_COUNT);
        cfg.redis.scan_count = 1; // too small → raise to the floor (COUNT=1 degenerates to per-key scanning)
        assert_eq!(cfg.redis.effective_scan_count(), 10);
        cfg.redis.scan_count = 99_999; // too large → clamp to the cap (COUNT is only a hint, keys are never dropped)
        assert_eq!(cfg.redis.effective_scan_count(), 10_000);
        cfg.redis.scan_count = 500;
        assert_eq!(cfg.redis.effective_scan_count(), 500);
        // Membership cache TTL: 0 = explicitly disabled (go to PG); the 60s cap prevents a typo becoming a long authorization window.
        cfg.policy.member_cache_ttl_ms = 0;
        assert_eq!(cfg.policy.effective_member_cache_ttl(), Duration::ZERO);
        cfg.policy.member_cache_ttl_ms = 5_000;
        assert_eq!(
            cfg.policy.effective_member_cache_ttl(),
            Duration::from_millis(5_000)
        );
        cfg.policy.member_cache_ttl_ms = 3_600_000;
        assert_eq!(
            cfg.policy.effective_member_cache_ttl(),
            Duration::from_millis(60_000)
        );
    }
    #[test]
    fn perf_tuning_env_overrides_parse() {
        std::env::set_var("LATTICE__REDIS__SCAN_COUNT", "250");
        std::env::set_var("LATTICE__POLICY__MEMBER_CACHE_TTL_MS", "0");
        let mut cfg = Config::default();
        cfg.apply_env();
        std::env::remove_var("LATTICE__REDIS__SCAN_COUNT");
        std::env::remove_var("LATTICE__POLICY__MEMBER_CACHE_TTL_MS");
        assert_eq!(cfg.redis.scan_count, 250);
        assert_eq!(cfg.policy.member_cache_ttl_ms, 0);
    }
    #[test]
    fn protocol_range_never_goes_below_min() {
        let mut cfg = Config::default();
        cfg.policy.protocol_version = 1;
        cfg.policy.protocol_min_supported = 1;
        assert_eq!(cfg.protocol_range(), (1, 1));
        cfg.policy.protocol_version = 3;
        assert_eq!(cfg.protocol_range(), (2, 3));
        cfg.policy.protocol_min_supported = 2;
        assert_eq!(cfg.protocol_range(), (2, 3));
    }
    #[test]
    fn mode_names_are_only_two() {
        let mut cfg = Config::default();
        assert_eq!(cfg.mode(), lattice_core::Mode::ZeroKnowledge);
        cfg.policy.mode = "inspectable".into();
        assert_eq!(cfg.mode(), lattice_core::Mode::Inspectable);
        cfg.policy.mode = "transparent".into();
        assert_eq!(
            cfg.mode(),
            lattice_core::Mode::ZeroKnowledge,
            "legacy names are always treated as the default"
        );
    }
    #[test]
    fn media_record_defaults_are_off() {
        let cfg = Config::default();
        assert!(
            !cfg.media.record_enabled,
            "recording is off by default (production must not silently create recording side effects)"
        );
        assert_eq!(cfg.media.record_bucket, "lattice-media");
        assert_eq!(cfg.media.record_segment_bytes, 4 * 1024 * 1024);
        assert_eq!(cfg.media.effective_record_segment_bytes(), 4 * 1024 * 1024);
        assert_eq!(cfg.media.effective_record_bucket(&cfg.s3), "lattice-media");
        // Recording bus consumer defaults: ack_wait 30s / max_deliver 5 / NAK 1s
        assert_eq!(cfg.media.record_bus_ack_wait_ms, 30_000);
        assert_eq!(cfg.media.record_bus_max_deliver, 5);
        assert_eq!(cfg.media.record_bus_retry_delay_ms, 1_000);
        assert_eq!(
            cfg.media.effective_record_bus_ack_wait(),
            Duration::from_secs(30)
        );
        assert_eq!(cfg.media.effective_record_bus_max_deliver(), 5);
        assert_eq!(
            cfg.media.effective_record_bus_retry_delay(),
            Duration::from_secs(1)
        );
        // Lifecycle reclamation is off by default (0 = no reclamation; production suggests 7, shown in the sample config)
        assert_eq!(cfg.media.record_retention_days, 0);
        assert_eq!(cfg.media.effective_record_retention_days(), 0);
    }
    #[test]
    fn media_record_retention_effective_days() {
        let mut cfg = Config::default();
        // Production suggested value 7 days: applies as configured (background GC uses it for the created_at cutoff)
        cfg.media.record_retention_days = 7;
        assert_eq!(cfg.media.effective_record_retention_days(), 7);
        // 1 day (the smallest retention E2E uses) works
        cfg.media.record_retention_days = 1;
        assert_eq!(cfg.media.effective_record_retention_days(), 1);
        // 0 = reclamation disabled (the background job short-circuits, doing no deletion at all)
        cfg.media.record_retention_days = 0;
        assert_eq!(cfg.media.effective_record_retention_days(), 0);
    }
    #[test]
    fn media_record_bus_consumer_invalid_values_fall_back() {
        let mut cfg = Config::default();
        // 0/negative invalid: fall back to defaults, never "redeliver per frame / busy-wait NAK"
        cfg.media.record_bus_ack_wait_ms = 0;
        cfg.media.record_bus_max_deliver = 0;
        cfg.media.record_bus_retry_delay_ms = 0;
        assert_eq!(
            cfg.media.effective_record_bus_ack_wait(),
            Duration::from_millis(MEDIA_RECORD_BUS_ACK_WAIT_MS_DEFAULT)
        );
        assert_eq!(
            cfg.media.effective_record_bus_max_deliver(),
            MEDIA_RECORD_BUS_MAX_DELIVER_DEFAULT
        );
        assert_eq!(
            cfg.media.effective_record_bus_retry_delay(),
            Duration::from_millis(MEDIA_RECORD_BUS_RETRY_DELAY_MS_DEFAULT)
        );
        // A too-small ack_wait is raised to the 1s floor (normal persists must not be redelivered by mistake)
        cfg.media.record_bus_ack_wait_ms = 10;
        assert_eq!(
            cfg.media.effective_record_bus_ack_wait(),
            Duration::from_secs(1)
        );
        // Tests may shrink it (E2E uses 5s to speed up restart-redelivery verification)
        cfg.media.record_bus_ack_wait_ms = 5_000;
        assert_eq!(
            cfg.media.effective_record_bus_ack_wait(),
            Duration::from_millis(5_000)
        );
    }
    #[test]
    fn media_record_segment_zero_falls_back_to_default() {
        let mut cfg = Config::default();
        // 0 is the only invalid value: fall back to the default, never degrade a segment to "one object per frame"
        cfg.media.record_segment_bytes = 0;
        assert_eq!(
            cfg.media.effective_record_segment_bytes(),
            MEDIA_RECORD_SEGMENT_BYTES_DEFAULT
        );
        // Positive values (even tiny ones; tests use them to force rotation) apply as configured
        cfg.media.record_segment_bytes = 64;
        assert_eq!(cfg.media.effective_record_segment_bytes(), 64);
        // An empty bucket name falls back to [s3] bucket_media, so recording never writes to an unexpected bucket
        cfg.media.record_bucket = "  ".into();
        assert_eq!(
            cfg.media.effective_record_bucket(&cfg.s3),
            cfg.s3.bucket_media
        );
    }
    #[test]
    fn media_record_env_overrides_parse() {
        // apply_env reads the process environment directly; here we only verify the mapping logic for overridable fields (without polluting other tests in this process:
        // by using std::env::set_var/remove_var under serial execution, with unique variable names).
        std::env::set_var("LATTICE__MEDIA__RECORD_ENABLED", "true");
        std::env::set_var("LATTICE__MEDIA__RECORD_BUCKET", "lattice-media-e2e");
        std::env::set_var("LATTICE__MEDIA__RECORD_SEGMENT_BYTES", "64");
        std::env::set_var("LATTICE__MEDIA__RECORD_RETENTION_DAYS", "3");
        let mut cfg = Config::default();
        cfg.apply_env();
        std::env::remove_var("LATTICE__MEDIA__RECORD_ENABLED");
        std::env::remove_var("LATTICE__MEDIA__RECORD_BUCKET");
        std::env::remove_var("LATTICE__MEDIA__RECORD_SEGMENT_BYTES");
        std::env::remove_var("LATTICE__MEDIA__RECORD_RETENTION_DAYS");
        assert!(cfg.media.record_enabled);
        assert_eq!(cfg.media.record_bucket, "lattice-media-e2e");
        assert_eq!(cfg.media.effective_record_segment_bytes(), 64);
        assert_eq!(cfg.media.record_retention_days, 3);
        assert_eq!(cfg.media.effective_record_retention_days(), 3);
    }
    #[test]
    fn wal_defaults_and_effective_values() {
        let cfg = Config::default();
        assert!(
            cfg.wal.enabled,
            "WAL degradation is on by default (② §4.8 fallback capability is available by default)"
        );
        assert_eq!(cfg.wal.max_bytes, WAL_MAX_BYTES_DEFAULT);
        assert_eq!(cfg.wal.max_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.wal.effective_max_bytes(), WAL_MAX_BYTES_DEFAULT);
        // Empty dir = fall back to the existing [degrade] pg_wal_dir (K8s emptyDir volume), preserving deployment semantics
        assert!(cfg.wal.dir.is_empty());
        assert_eq!(cfg.wal.effective_dir(&cfg.degrade), cfg.degrade.pg_wal_dir);
        assert_eq!(cfg.wal.effective_replay_interval_ms(), 2000);
        // 0 is the only invalid value: max_bytes falls back to default and replay falls back to default; a too-small replay clamps to 100ms
        let mut wal = WalCfg {
            max_bytes: 0,
            replay_interval_ms: 0,
            ..WalCfg::default()
        };
        assert_eq!(wal.effective_max_bytes(), WAL_MAX_BYTES_DEFAULT);
        assert_eq!(wal.effective_replay_interval_ms(), 2000);
        wal.replay_interval_ms = 1;
        assert_eq!(wal.effective_replay_interval_ms(), 100);
        // An explicit dir takes precedence over [degrade] pg_wal_dir
        let cfg2: Config = toml::from_str(
            "[wal]\ndir = \"./data/wal-e2e\"\nmax_bytes = 1024\nreplay_interval_ms = 500\n",
        )
        .unwrap();
        assert_eq!(cfg2.wal.effective_dir(&cfg2.degrade), "./data/wal-e2e");
        assert_eq!(cfg2.wal.effective_max_bytes(), 1024);
        assert_eq!(cfg2.wal.effective_replay_interval_ms(), 500);
    }
    #[test]
    fn wal_env_overrides_parse() {
        // Runs in parallel with the media env test in the same process: variable names differ, so they do not pollute each other.
        std::env::set_var("LATTICE__WAL__ENABLED", "false");
        std::env::set_var("LATTICE__WAL__DIR", ".dev/wal-env-test");
        std::env::set_var("LATTICE__WAL__MAX_BYTES", "2048");
        std::env::set_var("LATTICE__WAL__REPLAY_INTERVAL_MS", "250");
        let mut cfg = Config::default();
        cfg.apply_env();
        std::env::remove_var("LATTICE__WAL__ENABLED");
        std::env::remove_var("LATTICE__WAL__DIR");
        std::env::remove_var("LATTICE__WAL__MAX_BYTES");
        std::env::remove_var("LATTICE__WAL__REPLAY_INTERVAL_MS");
        assert!(!cfg.wal.enabled);
        assert_eq!(cfg.wal.dir, ".dev/wal-env-test");
        assert_eq!(cfg.wal.effective_max_bytes(), 2048);
        assert_eq!(cfg.wal.effective_replay_interval_ms(), 250);
    }
    #[test]
    fn key_rotation_defaults_match_17_11() {
        let cfg = Config::default();
        assert_eq!(cfg.auth.key_overlap_hours, 24.0, "⑤ §8.4: dual-key overlap defaults to 24h");
        assert_eq!(
            cfg.auth.key_prune_interval_ms,
            KEY_PRUNE_INTERVAL_MS_DEFAULT
        );
        assert_eq!(
            cfg.auth.effective_key_prune_interval_ms(),
            KEY_PRUNE_INTERVAL_MS_DEFAULT
        );
        // 0 invalid → default; too small (1ms) clamps to the 100ms floor, avoiding a busy loop
        let mut auth = AuthCfg {
            key_prune_interval_ms: 0,
            ..AuthCfg::default()
        };
        assert_eq!(
            auth.effective_key_prune_interval_ms(),
            KEY_PRUNE_INTERVAL_MS_DEFAULT
        );
        auth.key_prune_interval_ms = 1;
        assert_eq!(auth.effective_key_prune_interval_ms(), 100);
        auth.key_prune_interval_ms = 300;
        assert_eq!(auth.effective_key_prune_interval_ms(), 300);
        // TOML supports fractional windows (E2E/drills use tiny values)
        let cfg2: Config = toml::from_str("[auth]\nkey_overlap_hours = 0.0003\n").unwrap();
        assert!((cfg2.auth.key_overlap_hours - 0.0003).abs() < f64::EPSILON);
    }
    #[test]
    fn key_rotation_env_overrides_parse() {
        // Variable names differ, so they do not pollute other env tests in the same process.
        std::env::set_var("LATTICE__AUTH__KEY_OVERLAP_HOURS", "0.5");
        std::env::set_var("LATTICE__AUTH__KEY_PRUNE_INTERVAL_MS", "300");
        let mut cfg = Config::default();
        cfg.apply_env();
        std::env::remove_var("LATTICE__AUTH__KEY_OVERLAP_HOURS");
        std::env::remove_var("LATTICE__AUTH__KEY_PRUNE_INTERVAL_MS");
        assert_eq!(cfg.auth.key_overlap_hours, 0.5);
        assert_eq!(cfg.auth.effective_key_prune_interval_ms(), 300);
    }
    #[test]
    fn audit_defaults_match_audit_stream_contract() {
        let cfg = Config::default();
        // consumer on by default; the E2E probe off by default (production should not write test noise into the audit table)
        assert!(cfg.audit.consumer_enabled);
        assert!(!cfg.audit.startup_probe);
        assert_eq!(cfg.audit.consumer_max_deliver, AUDIT_MAX_DELIVER_DEFAULT);
        assert_eq!(cfg.audit.consumer_max_deliver, 5);
        assert_eq!(cfg.audit.consumer_ack_wait_ms, AUDIT_ACK_WAIT_MS_DEFAULT);
        assert_eq!(
            cfg.audit.consumer_retry_delay_ms,
            AUDIT_RETRY_DELAY_MS_DEFAULT
        );
        assert_eq!(
            cfg.audit.effective_ack_wait(),
            Duration::from_millis(AUDIT_ACK_WAIT_MS_DEFAULT)
        );
        assert_eq!(
            cfg.audit.effective_retry_delay(),
            Duration::from_millis(AUDIT_RETRY_DELAY_MS_DEFAULT)
        );
        // 0/negative invalid → default; too small clamps to the 100ms floor (avoids mistaken redelivery/busy waiting)
        let mut audit = AuditCfg {
            consumer_max_deliver: 0,
            consumer_ack_wait_ms: 0,
            consumer_retry_delay_ms: 0,
            ..AuditCfg::default()
        };
        assert_eq!(audit.effective_max_deliver(), AUDIT_MAX_DELIVER_DEFAULT);
        audit.consumer_max_deliver = -3;
        assert_eq!(audit.effective_max_deliver(), AUDIT_MAX_DELIVER_DEFAULT);
        audit.consumer_ack_wait_ms = 1;
        assert_eq!(audit.effective_ack_wait(), Duration::from_millis(100));
        audit.consumer_retry_delay_ms = 1;
        assert_eq!(audit.effective_retry_delay(), Duration::from_millis(100));
        // The TOML section is independently configurable (E2E uses small values to speed up DLQ/redelivery)
        let cfg2: Config = toml::from_str(
            "[audit]\nconsumer_enabled = false\nconsumer_max_deliver = 2\n\
             consumer_ack_wait_ms = 500\nconsumer_retry_delay_ms = 200\nstartup_probe = true\n",
        )
        .unwrap();
        assert!(!cfg2.audit.consumer_enabled);
        assert_eq!(cfg2.audit.effective_max_deliver(), 2);
        assert_eq!(cfg2.audit.effective_ack_wait(), Duration::from_millis(500));
        assert_eq!(
            cfg2.audit.effective_retry_delay(),
            Duration::from_millis(200)
        );
        assert!(cfg2.audit.startup_probe);
    }
    #[test]
    fn audit_env_overrides_parse() {
        // Variable names differ, so they do not pollute other env tests in the same process.
        std::env::set_var("LATTICE__AUDIT__CONSUMER_ENABLED", "false");
        std::env::set_var("LATTICE__AUDIT__CONSUMER_MAX_DELIVER", "3");
        std::env::set_var("LATTICE__AUDIT__CONSUMER_ACK_WAIT_MS", "1500");
        std::env::set_var("LATTICE__AUDIT__CONSUMER_RETRY_DELAY_MS", "250");
        std::env::set_var("LATTICE__AUDIT__STARTUP_PROBE", "true");
        let mut cfg = Config::default();
        cfg.apply_env();
        std::env::remove_var("LATTICE__AUDIT__CONSUMER_ENABLED");
        std::env::remove_var("LATTICE__AUDIT__CONSUMER_MAX_DELIVER");
        std::env::remove_var("LATTICE__AUDIT__CONSUMER_ACK_WAIT_MS");
        std::env::remove_var("LATTICE__AUDIT__CONSUMER_RETRY_DELAY_MS");
        std::env::remove_var("LATTICE__AUDIT__STARTUP_PROBE");
        assert!(!cfg.audit.consumer_enabled);
        assert_eq!(cfg.audit.effective_max_deliver(), 3);
        assert_eq!(cfg.audit.effective_ack_wait(), Duration::from_millis(1500));
        assert_eq!(
            cfg.audit.effective_retry_delay(),
            Duration::from_millis(250)
        );
        assert!(cfg.audit.startup_probe);
    }
    #[test]
    fn quic_defaults_are_off_and_zero_falls_back() {
        let cfg = Config::default();
        // §17.9 path ② is enabled on demand: by default existing media paths (WebRTC direct / WS tunnel) are untouched
        assert!(!cfg.quic.enabled, "the QUIC relay must be off by default");
        assert_eq!(cfg.quic.bind, QUIC_BIND_DEFAULT);
        assert!(
            cfg.quic.cert.is_empty() && cfg.quic.key.is_empty(),
            "empty certificate = dev self-signed"
        );
        assert_eq!(
            cfg.quic.effective_idle_timeout_secs(),
            QUIC_IDLE_TIMEOUT_SECS_DEFAULT
        );
        assert_eq!(
            cfg.quic.effective_handshake_timeout_secs(),
            QUIC_HANDSHAKE_TIMEOUT_SECS_DEFAULT
        );
        assert_eq!(
            cfg.quic.effective_token_ttl_secs(),
            QUIC_TOKEN_TTL_SECS_DEFAULT
        );
        // 0 is the only invalid value: fall back to default (neither kick connections immediately nor wait for the handshake forever)
        let mut q = QuicCfg {
            idle_timeout_secs: 0,
            handshake_timeout_secs: 0,
            token_ttl_secs: 0,
            ..QuicCfg::default()
        };
        assert_eq!(
            q.effective_idle_timeout_secs(),
            QUIC_IDLE_TIMEOUT_SECS_DEFAULT
        );
        assert_eq!(
            q.effective_handshake_timeout_secs(),
            QUIC_HANDSHAKE_TIMEOUT_SECS_DEFAULT
        );
        assert_eq!(q.effective_token_ttl_secs(), QUIC_TOKEN_TTL_SECS_DEFAULT);
        // Positive values apply as configured (E2E uses short timeouts for speed)
        q.idle_timeout_secs = 7;
        q.handshake_timeout_secs = 3;
        q.token_ttl_secs = 30;
        assert_eq!(q.effective_idle_timeout_secs(), 7);
        assert_eq!(q.effective_handshake_timeout_secs(), 3);
        assert_eq!(q.effective_token_ttl_secs(), 30);
        // join tokens are short-lived tickets: over the cap they saturate (never a near-permanent credential)
        q.token_ttl_secs = 86_400;
        assert_eq!(q.effective_token_ttl_secs(), QUIC_TOKEN_TTL_SECS_MAX);
        // The TOML section is independently configurable, and serde(default) covers a missing section (deployments need not add it first)
        let cfg2: Config = toml::from_str(
            "[quic]\nenabled = true\nbind = \"127.0.0.1:18443\"\n\
             cert = \"/tmp/q.crt\"\nkey = \"/tmp/q.key\"\n\
             idle_timeout_secs = 5\nhandshake_timeout_secs = 2\n",
        )
        .unwrap();
        assert!(cfg2.quic.enabled);
        assert_eq!(cfg2.quic.bind, "127.0.0.1:18443");
        assert_eq!(cfg2.quic.effective_idle_timeout_secs(), 5);
        let cfg3: Config = toml::from_str("[policy]\nmode = \"zero-knowledge\"\n").unwrap();
        assert!(!cfg3.quic.enabled, "missing [quic] section = off by default");
    }
    #[test]
    fn quic_env_overrides_parse() {
        // Variable names differ, so they do not pollute other env tests in the same process.
        std::env::set_var("LATTICE__QUIC__ENABLED", "true");
        std::env::set_var("LATTICE__QUIC__BIND", "127.0.0.1:18443");
        std::env::set_var("LATTICE__QUIC__CERT", ".dev/quic-tls/server.crt");
        std::env::set_var("LATTICE__QUIC__KEY", ".dev/quic-tls/server.key");
        std::env::set_var("LATTICE__QUIC__IDLE_TIMEOUT_SECS", "5");
        std::env::set_var("LATTICE__QUIC__HANDSHAKE_TIMEOUT_SECS", "2");
        std::env::set_var("LATTICE__QUIC__TOKEN_TTL_SECS", "45");
        let mut cfg = Config::default();
        cfg.apply_env();
        std::env::remove_var("LATTICE__QUIC__ENABLED");
        std::env::remove_var("LATTICE__QUIC__BIND");
        std::env::remove_var("LATTICE__QUIC__CERT");
        std::env::remove_var("LATTICE__QUIC__KEY");
        std::env::remove_var("LATTICE__QUIC__IDLE_TIMEOUT_SECS");
        std::env::remove_var("LATTICE__QUIC__HANDSHAKE_TIMEOUT_SECS");
        std::env::remove_var("LATTICE__QUIC__TOKEN_TTL_SECS");
        assert!(cfg.quic.enabled);
        assert_eq!(cfg.quic.bind, "127.0.0.1:18443");
        assert_eq!(cfg.quic.cert, ".dev/quic-tls/server.crt");
        assert_eq!(cfg.quic.effective_idle_timeout_secs(), 5);
        assert_eq!(cfg.quic.effective_handshake_timeout_secs(), 2);
        assert_eq!(cfg.quic.effective_token_ttl_secs(), 45);
    }
    #[test]
    fn webtransport_defaults_are_off_and_clamped() {
        let cfg = Config::default();
        // Off by default: no HTTP/3 UDP listener, no certificates loaded, zero side effects on existing media paths.
        assert!(!cfg.webtransport.enabled, "WebTransport must be off by default");
        assert_eq!(cfg.webtransport.bind, WEBTRANSPORT_BIND_DEFAULT);
        assert_eq!(cfg.webtransport.effective_path(), WEBTRANSPORT_PATH_DEFAULT);
        assert!(
            cfg.webtransport.cert.is_empty() && cfg.webtransport.key.is_empty(),
            "empty certificate = dev self-signed"
        );
        assert!(
            cfg.webtransport.upstream.is_empty(),
            "empty = derive from [quic] bind"
        );
        assert_eq!(
            cfg.webtransport.effective_idle_timeout_secs(),
            WEBTRANSPORT_IDLE_TIMEOUT_SECS_DEFAULT
        );
        assert_eq!(
            cfg.webtransport.effective_token_ttl_secs(),
            WEBTRANSPORT_TOKEN_TTL_SECS_DEFAULT
        );
        // 0 is invalid and falls back to default; caps saturate (never near-permanent connections or long-lived tickets)
        let mut w = WebTransportCfg {
            idle_timeout_secs: 0,
            token_ttl_secs: 0,
            path: "media".into(),
            ..WebTransportCfg::default()
        };
        assert_eq!(
            w.effective_idle_timeout_secs(),
            WEBTRANSPORT_IDLE_TIMEOUT_SECS_DEFAULT
        );
        assert_eq!(
            w.effective_token_ttl_secs(),
            WEBTRANSPORT_TOKEN_TTL_SECS_DEFAULT
        );
        // An invalid path (not starting with /) falls back to the default, so CONNECT can never be unmatchable
        assert_eq!(w.effective_path(), WEBTRANSPORT_PATH_DEFAULT);
        w.idle_timeout_secs = 7;
        w.token_ttl_secs = 30;
        w.path = "/media/v2".into();
        assert_eq!(w.effective_idle_timeout_secs(), 7);
        assert_eq!(w.effective_token_ttl_secs(), 30);
        assert_eq!(w.effective_path(), "/media/v2");
        w.idle_timeout_secs = 86_400;
        w.token_ttl_secs = 86_400;
        assert_eq!(
            w.effective_idle_timeout_secs(),
            WEBTRANSPORT_IDLE_TIMEOUT_SECS_MAX
        );
        assert_eq!(
            w.effective_token_ttl_secs(),
            WEBTRANSPORT_TOKEN_TTL_SECS_MAX
        );
        // The TOML section is independently configurable; a missing section = off by default (old deployment configs need no change)
        let cfg2: Config = toml::from_str(
            "[webtransport]\nenabled = true\nbind = \"127.0.0.1:18446\"\n\
             cert = \"/tmp/wt.crt\"\nkey = \"/tmp/wt.key\"\n\
             upstream = \"127.0.0.1:18445\"\nupstream_ca = \"/tmp/ca.crt\"\n\
             idle_timeout_secs = 5\ntoken_ttl_secs = 45\npath = \"/media\"\n",
        )
        .unwrap();
        assert!(cfg2.webtransport.enabled);
        assert_eq!(cfg2.webtransport.bind, "127.0.0.1:18446");
        assert_eq!(cfg2.webtransport.upstream, "127.0.0.1:18445");
        assert_eq!(cfg2.webtransport.upstream_ca, "/tmp/ca.crt");
        assert_eq!(cfg2.webtransport.effective_idle_timeout_secs(), 5);
        assert_eq!(cfg2.webtransport.effective_token_ttl_secs(), 45);
        let cfg3: Config = toml::from_str("[policy]\nmode = \"zero-knowledge\"\n").unwrap();
        assert!(
            !cfg3.webtransport.enabled,
            "missing [webtransport] section = off by default"
        );
    }
    #[test]
    fn webtransport_env_overrides_parse() {
        // Variable names differ, so they do not pollute other env tests in the same process.
        std::env::set_var("LATTICE__WEBTRANSPORT__ENABLED", "true");
        std::env::set_var("LATTICE__WEBTRANSPORT__BIND", "127.0.0.1:18446");
        std::env::set_var("LATTICE__WEBTRANSPORT__CERT", ".dev/wt-tls/server.crt");
        std::env::set_var("LATTICE__WEBTRANSPORT__KEY", ".dev/wt-tls/server.key");
        std::env::set_var("LATTICE__WEBTRANSPORT__UPSTREAM", "127.0.0.1:18445");
        std::env::set_var("LATTICE__WEBTRANSPORT__UPSTREAM_CA", ".dev/wt-tls/ca.crt");
        std::env::set_var("LATTICE__WEBTRANSPORT__IDLE_TIMEOUT_SECS", "5");
        std::env::set_var("LATTICE__WEBTRANSPORT__TOKEN_TTL_SECS", "45");
        std::env::set_var("LATTICE__WEBTRANSPORT__PATH", "/media");
        let mut cfg = Config::default();
        cfg.apply_env();
        for key in [
            "ENABLED",
            "BIND",
            "CERT",
            "KEY",
            "UPSTREAM",
            "UPSTREAM_CA",
            "IDLE_TIMEOUT_SECS",
            "TOKEN_TTL_SECS",
            "PATH",
        ] {
            std::env::remove_var(format!("LATTICE__WEBTRANSPORT__{key}"));
        }
        assert!(cfg.webtransport.enabled);
        assert_eq!(cfg.webtransport.bind, "127.0.0.1:18446");
        assert_eq!(cfg.webtransport.cert, ".dev/wt-tls/server.crt");
        assert_eq!(cfg.webtransport.key, ".dev/wt-tls/server.key");
        assert_eq!(cfg.webtransport.upstream, "127.0.0.1:18445");
        assert_eq!(cfg.webtransport.upstream_ca, ".dev/wt-tls/ca.crt");
        assert_eq!(cfg.webtransport.effective_idle_timeout_secs(), 5);
        assert_eq!(cfg.webtransport.effective_token_ttl_secs(), 45);
        assert_eq!(cfg.webtransport.effective_path(), "/media");
    }
    #[test]
    fn mqtt_tls_defaults_are_off_and_fail_closed() {
        // Off by default: 8883 is not listened on, plaintext bind behavior is completely unchanged (zero-impact upgrade).
        let cfg = Config::default();
        assert!(!cfg.mqtt.tls_enabled, "the TLS listener must be off by default");
        assert_eq!(cfg.mqtt.tls_bind, "0.0.0.0:8883");
        assert!(cfg.mqtt.tls_cert.is_empty());
        assert!(cfg.mqtt.tls_key.is_empty());
        assert!(cfg.mqtt.client_ca.is_empty());
        assert!(
            cfg.mqtt.require_client_cert,
            "mTLS requires client certificates by default (fail-closed; no certificate must not silently pass)"
        );
        // Missing [mqtt] section = all defaults (old deployment configs need no change)
        let cfg2: Config = toml::from_str("[node]\nid = \"n1\"\n").unwrap();
        assert!(!cfg2.mqtt.tls_enabled);
        assert!(cfg2.mqtt.require_client_cert);
        // SAMPLE_TOML is valid: the new TLS fields must appear explicitly in the sample but stay off
        let sample: Config = toml::from_str(SAMPLE_TOML).unwrap();
        assert!(!sample.mqtt.tls_enabled);
        assert_eq!(sample.mqtt.tls_bind, "0.0.0.0:8883");
        assert!(sample.mqtt.require_client_cert);
        // The TOML section is independently configurable
        let cfg3: Config = toml::from_str(
            "[mqtt]\ntls_enabled = true\ntls_bind = \"127.0.0.1:18883\"\n\
             tls_cert = \"/tmp/server.crt\"\ntls_key = \"/tmp/server.key\"\n\
             client_ca = \"/tmp/client-ca.crt\"\nrequire_client_cert = false\n",
        )
        .unwrap();
        assert!(cfg3.mqtt.tls_enabled);
        assert_eq!(cfg3.mqtt.tls_bind, "127.0.0.1:18883");
        assert_eq!(cfg3.mqtt.tls_cert, "/tmp/server.crt");
        assert_eq!(cfg3.mqtt.tls_key, "/tmp/server.key");
        assert_eq!(cfg3.mqtt.client_ca, "/tmp/client-ca.crt");
        assert!(!cfg3.mqtt.require_client_cert);
    }
    #[test]
    fn mqtt_receive_maximum_and_outbound_alias_config() {
        // Defaults: server Receive Maximum=32 (the 0 = echo 65535 semantics live in mqtt.rs), outbound alias compression on.
        let cfg = Config::default();
        assert_eq!(cfg.mqtt.receive_maximum, 32);
        assert!(cfg.mqtt.outbound_topic_alias);
        // Missing [mqtt] section = defaults (old deployment configs need no change)
        let cfg2: Config = toml::from_str("[node]\nid = \"n1\"\n").unwrap();
        assert_eq!(cfg2.mqtt.receive_maximum, 32);
        assert!(cfg2.mqtt.outbound_topic_alias);
        // The TOML section is independently configurable (0 = echo 65535; outbound aliases off)
        let cfg3: Config =
            toml::from_str("[mqtt]\nreceive_maximum = 7\noutbound_topic_alias = false\n").unwrap();
        assert_eq!(cfg3.mqtt.receive_maximum, 7);
        assert!(!cfg3.mqtt.outbound_topic_alias);
        // env overrides (LATTICE__MQTT__RECEIVE_MAXIMUM / OUTBOUND_TOPIC_ALIAS)
        std::env::set_var("LATTICE__MQTT__RECEIVE_MAXIMUM", "9");
        std::env::set_var("LATTICE__MQTT__OUTBOUND_TOPIC_ALIAS", "false");
        let mut cfg4 = Config::default();
        cfg4.apply_env();
        std::env::remove_var("LATTICE__MQTT__RECEIVE_MAXIMUM");
        std::env::remove_var("LATTICE__MQTT__OUTBOUND_TOPIC_ALIAS");
        assert_eq!(cfg4.mqtt.receive_maximum, 9);
        assert!(!cfg4.mqtt.outbound_topic_alias);
    }
    #[test]
    fn mqtt_tls_env_overrides_parse() {
        // Variable names differ, so they do not pollute other env tests in the same process.
        std::env::set_var("LATTICE__MQTT__TLS_ENABLED", "true");
        std::env::set_var("LATTICE__MQTT__TLS_BIND", "127.0.0.1:18884");
        std::env::set_var("LATTICE__MQTT__TLS_CERT", ".dev/mqtt-tls/server.crt");
        std::env::set_var("LATTICE__MQTT__TLS_KEY", ".dev/mqtt-tls/server.key");
        std::env::set_var("LATTICE__MQTT__CLIENT_CA", ".dev/mqtt-tls/client-ca.crt");
        std::env::set_var("LATTICE__MQTT__REQUIRE_CLIENT_CERT", "0");
        let mut cfg = Config::default();
        cfg.apply_env();
        std::env::remove_var("LATTICE__MQTT__TLS_ENABLED");
        std::env::remove_var("LATTICE__MQTT__TLS_BIND");
        std::env::remove_var("LATTICE__MQTT__TLS_CERT");
        std::env::remove_var("LATTICE__MQTT__TLS_KEY");
        std::env::remove_var("LATTICE__MQTT__CLIENT_CA");
        std::env::remove_var("LATTICE__MQTT__REQUIRE_CLIENT_CERT");
        assert!(cfg.mqtt.tls_enabled);
        assert_eq!(cfg.mqtt.tls_bind, "127.0.0.1:18884");
        assert_eq!(cfg.mqtt.tls_cert, ".dev/mqtt-tls/server.crt");
        assert_eq!(cfg.mqtt.tls_key, ".dev/mqtt-tls/server.key");
        assert_eq!(cfg.mqtt.client_ca, ".dev/mqtt-tls/client-ca.crt");
        assert!(!cfg.mqtt.require_client_cert);
    }
    #[test]
    fn plugins_defaults_are_fail_closed() {
        let cfg = Config::default();
        assert_eq!(cfg.plugins.wasm_dir, "/etc/lattice/plugins");
        assert!(
            cfg.plugins.require_verified_signature,
            "signature verification must be on by default (fail-closed)"
        );
        assert!(cfg.plugins.trusted_keys.is_empty());
        assert!(cfg.plugins.trusted_keys_file.is_empty());
        assert_eq!(
            cfg.plugins.timeout_ms,
            lattice_plugins::limits::SIDECAR_TIMEOUT_MS
        );
        assert_eq!(cfg.plugins.memory_mb, lattice_plugins::limits::MEMORY_MB);
        assert_eq!(
            cfg.plugins.instructions,
            lattice_plugins::limits::INSTRUCTIONS
        );
        assert!(cfg.plugins.from_db, "PG registration is on by default (the directory still wins)");
        assert_eq!(cfg.plugins.max_wasm_bytes, 16 * 1024 * 1024);
        // The TOML section is independently configurable (trusted_keys is an id→base64 map)
        let cfg2: Config = toml::from_str(
            "[plugins]\nwasm_dir = \"/tmp/wasm-plugins\"\n\
             require_verified_signature = false\n\
             from_db = false\nmax_wasm_bytes = 1024\n\
             timeout_ms = 150\nmemory_mb = 8\ninstructions = 3000000\n\
             trusted_keys = { \"release-1\" = \"AAAA\", \"internal\" = \"BBBB\" }\n\
             trusted_keys_file = \"/tmp/trusted_keys.json\"\n",
        )
        .unwrap();
        assert_eq!(cfg2.plugins.wasm_dir, "/tmp/wasm-plugins");
        assert!(!cfg2.plugins.require_verified_signature);
        assert!(!cfg2.plugins.from_db);
        assert_eq!(cfg2.plugins.max_wasm_bytes, 1024);
        assert_eq!(cfg2.plugins.timeout_ms, 150);
        assert_eq!(cfg2.plugins.memory_mb, 8);
        assert_eq!(cfg2.plugins.instructions, 3_000_000);
        assert_eq!(cfg2.plugins.trusted_keys.len(), 2);
        assert_eq!(cfg2.plugins.trusted_keys["release-1"], "AAAA");
        assert_eq!(cfg2.plugins.trusted_keys_file, "/tmp/trusted_keys.json");
        // Missing [plugins] section = all defaults (old deployment configs need no change)
        let cfg3: Config = toml::from_str("[node]\nid = \"n1\"\n").unwrap();
        assert_eq!(cfg3.plugins.wasm_dir, "/etc/lattice/plugins");
        assert!(cfg3.plugins.require_verified_signature);
    }
    #[test]
    fn plugins_env_overrides_parse() {
        // Variable names differ, so they do not pollute other env tests in the same process.
        std::env::set_var("LATTICE__PLUGINS__WASM_DIR", ".dev/wasm-plugins");
        std::env::set_var("LATTICE__PLUGINS__REQUIRE_VERIFIED_SIGNATURE", "false");
        std::env::set_var("LATTICE__PLUGINS__TIMEOUT_MS", "150");
        std::env::set_var("LATTICE__PLUGINS__MEMORY_MB", "8");
        std::env::set_var("LATTICE__PLUGINS__INSTRUCTIONS", "3000000");
        std::env::set_var(
            "LATTICE__PLUGINS__TRUSTED_KEYS",
            "release-1=AAAA,internal=BBBB",
        );
        std::env::set_var("LATTICE__PLUGINS__TRUSTED_KEYS_FILE", "/tmp/tk.json");
        std::env::set_var("LATTICE__PLUGINS__FROM_DB", "false");
        std::env::set_var("LATTICE__PLUGINS__MAX_WASM_BYTES", "2048");
        let mut cfg = Config::default();
        cfg.apply_env();
        std::env::remove_var("LATTICE__PLUGINS__WASM_DIR");
        std::env::remove_var("LATTICE__PLUGINS__REQUIRE_VERIFIED_SIGNATURE");
        std::env::remove_var("LATTICE__PLUGINS__TIMEOUT_MS");
        std::env::remove_var("LATTICE__PLUGINS__MEMORY_MB");
        std::env::remove_var("LATTICE__PLUGINS__INSTRUCTIONS");
        std::env::remove_var("LATTICE__PLUGINS__TRUSTED_KEYS");
        std::env::remove_var("LATTICE__PLUGINS__TRUSTED_KEYS_FILE");
        std::env::remove_var("LATTICE__PLUGINS__FROM_DB");
        std::env::remove_var("LATTICE__PLUGINS__MAX_WASM_BYTES");
        assert_eq!(cfg.plugins.wasm_dir, ".dev/wasm-plugins");
        assert!(!cfg.plugins.require_verified_signature);
        assert!(!cfg.plugins.from_db);
        assert_eq!(cfg.plugins.max_wasm_bytes, 2048);
        assert_eq!(cfg.plugins.timeout_ms, 150);
        assert_eq!(cfg.plugins.memory_mb, 8);
        assert_eq!(cfg.plugins.instructions, 3_000_000);
        assert_eq!(cfg.plugins.trusted_keys.len(), 2);
        assert_eq!(cfg.plugins.trusted_keys["internal"], "BBBB");
        assert_eq!(cfg.plugins.trusted_keys_file, "/tmp/tk.json");
    }
    #[test]
    fn plugins_sidecar_defaults_are_disabled_and_fail_closed() {
        // Off by default: no connection, NoopSidecar passthrough semantics (⑤ §10 failure behavior).
        let cfg = Config::default();
        assert!(!cfg.plugins.sidecar.enabled);
        assert!(cfg.plugins.sidecar.endpoint.is_empty());
        assert!(cfg.plugins.sidecar.tls_unset());
        assert!(!cfg.plugins.sidecar.tls_complete());
        assert_eq!(
            cfg.plugins.sidecar.timeout_ms,
            lattice_plugins::limits::SIDECAR_TIMEOUT_MS
        );
        assert_eq!(cfg.plugins.sidecar.effective_timeout_ms(), 500);
        // 0 = default 500ms (never degrade to "0ms means everything times out")
        let mut zero = SidecarCfg::default();
        zero.timeout_ms = 0;
        assert_eq!(zero.effective_timeout_ms(), 500);
        // The TOML section is independently configurable ([plugins.sidecar])
        let cfg2: Config = toml::from_str(
            "[plugins.sidecar]\nenabled = true\nendpoint = \"https://sidecar:19090\"\n\
             timeout_ms = 250\ntls_ca = \"/tmp/ca.pem\"\ntls_cert = \"/tmp/c.pem\"\n\
             tls_key = \"/tmp/k.pem\"\n",
        )
        .unwrap();
        assert!(cfg2.plugins.sidecar.enabled);
        assert_eq!(cfg2.plugins.sidecar.endpoint, "https://sidecar:19090");
        assert_eq!(cfg2.plugins.sidecar.effective_timeout_ms(), 250);
        assert!(cfg2.plugins.sidecar.tls_complete());
        assert!(!cfg2.plugins.sidecar.tls_unset());
        // Missing [plugins.sidecar] section = off by default (old deployment configs need no change)
        let cfg3: Config = toml::from_str("[plugins]\nwasm_dir = \"/tmp/wasm\"\n").unwrap();
        assert!(!cfg3.plugins.sidecar.enabled);
        // SAMPLE_TOML is valid and off by default
        let sample: Config = toml::from_str(SAMPLE_TOML).unwrap();
        assert!(!sample.plugins.sidecar.enabled);
        // Partial TLS: neither complete nor all-empty → the node fails closed as a config error (never silent plaintext)
        let cfg4: Config = toml::from_str("[plugins.sidecar]\ntls_ca = \"/tmp/ca.pem\"\n").unwrap();
        assert!(!cfg4.plugins.sidecar.tls_complete());
        assert!(!cfg4.plugins.sidecar.tls_unset());
    }
    #[test]
    fn plugins_sidecar_env_overrides_parse() {
        // Variable names differ, so they do not pollute other env tests in the same process.
        std::env::set_var("LATTICE__PLUGINS__SIDECAR__ENABLED", "true");
        std::env::set_var(
            "LATTICE__PLUGINS__SIDECAR__ENDPOINT",
            "http://127.0.0.1:19090",
        );
        std::env::set_var("LATTICE__PLUGINS__SIDECAR__TIMEOUT_MS", "250");
        std::env::set_var("LATTICE__PLUGINS__SIDECAR__TLS_CA", "/tmp/ca.pem");
        std::env::set_var("LATTICE__PLUGINS__SIDECAR__TLS_CERT", "/tmp/c.pem");
        std::env::set_var("LATTICE__PLUGINS__SIDECAR__TLS_KEY", "/tmp/k.pem");
        let mut cfg = Config::default();
        cfg.apply_env();
        std::env::remove_var("LATTICE__PLUGINS__SIDECAR__ENABLED");
        std::env::remove_var("LATTICE__PLUGINS__SIDECAR__ENDPOINT");
        std::env::remove_var("LATTICE__PLUGINS__SIDECAR__TIMEOUT_MS");
        std::env::remove_var("LATTICE__PLUGINS__SIDECAR__TLS_CA");
        std::env::remove_var("LATTICE__PLUGINS__SIDECAR__TLS_CERT");
        std::env::remove_var("LATTICE__PLUGINS__SIDECAR__TLS_KEY");
        assert!(cfg.plugins.sidecar.enabled);
        assert_eq!(cfg.plugins.sidecar.endpoint, "http://127.0.0.1:19090");
        assert_eq!(cfg.plugins.sidecar.effective_timeout_ms(), 250);
        assert_eq!(cfg.plugins.sidecar.tls_ca, "/tmp/ca.pem");
        assert_eq!(cfg.plugins.sidecar.tls_cert, "/tmp/c.pem");
        assert_eq!(cfg.plugins.sidecar.tls_key, "/tmp/k.pem");
        assert!(cfg.plugins.sidecar.tls_complete());
    }
    // ---- E02 compliance hard-delete window / E04 residual multipart GC config ----
    #[test]
    fn compliance_and_maintenance_defaults_match_spec() {
        let cfg = Config::default();
        // ⑤ §8.2: default 7-day hard-delete window; ⑥ §2.6: by default only multipart uploads unfinished for 24h are reclaimed.
        assert_eq!(cfg.compliance.purge_hard_delete_days, 7);
        assert!(cfg.compliance.hard_delete_enabled());
        assert_eq!(cfg.compliance.effective_hard_delete_days(), 7);
        assert_eq!(
            cfg.compliance.effective_cleanup_interval(),
            Duration::from_secs(PURGE_CLEANUP_INTERVAL_SECS_DEFAULT)
        );
        assert_eq!(cfg.maintenance.multipart_gc_hours, 24.0);
        assert!(cfg.maintenance.multipart_gc_enabled());
        assert_eq!(
            cfg.maintenance.effective_multipart_gc_age(),
            Duration::from_secs(24 * 3600)
        );
        assert_eq!(
            cfg.maintenance.effective_interval(),
            Duration::from_secs(MULTIPART_GC_INTERVAL_SECS_DEFAULT)
        );
        // 0 = off (compliance hard delete / multipart GC), but the interval still falls back to the default rather than 0
        let mut off = Config::default();
        off.compliance.purge_hard_delete_days = 0;
        off.maintenance.multipart_gc_hours = 0.0;
        assert!(!off.compliance.hard_delete_enabled());
        assert_eq!(off.compliance.effective_hard_delete_days(), 0);
        assert!(!off.maintenance.multipart_gc_enabled());
        assert_eq!(off.maintenance.effective_multipart_gc_age(), Duration::ZERO);
        // Interval floor/default: 0 → default; 1 → raised to 60s
        let mut bounds = Config::default();
        bounds.compliance.purge_cleanup_interval_secs = 0;
        bounds.maintenance.multipart_gc_interval_secs = 0;
        assert_eq!(
            bounds.compliance.effective_cleanup_interval(),
            Duration::from_secs(3_600)
        );
        assert_eq!(
            bounds.maintenance.effective_interval(),
            Duration::from_secs(3_600)
        );
        bounds.compliance.purge_cleanup_interval_secs = 1;
        bounds.maintenance.multipart_gc_interval_secs = 5;
        assert_eq!(
            bounds.compliance.effective_cleanup_interval(),
            Duration::from_secs(60)
        );
        assert_eq!(
            bounds.maintenance.effective_interval(),
            Duration::from_secs(60)
        );
        // E2E convention: 0.0003h ≈ 1.08s (fractions allowed, for "abort only when aged")
        let mut tiny = Config::default();
        tiny.maintenance.multipart_gc_hours = 0.0003;
        let age = tiny.maintenance.effective_multipart_gc_age();
        assert!(age > Duration::from_millis(1_000) && age < Duration::from_millis(1_200));
        // NaN / negative / infinity: all treated as off (no panic, no wrongful deletion)
        for bad in [f64::NAN, -1.0, f64::INFINITY] {
            let mut c = Config::default();
            c.maintenance.multipart_gc_hours = bad;
            assert!(!c.maintenance.multipart_gc_enabled(), "bad={bad}");
            assert_eq!(c.maintenance.effective_multipart_gc_age(), Duration::ZERO);
        }
        // SAMPLE_TOML section is valid and matches the defaults (deployment-file drift check)
        let sample: Config = toml::from_str(SAMPLE_TOML).unwrap();
        assert_eq!(sample.compliance.purge_hard_delete_days, 7);
        assert_eq!(sample.maintenance.multipart_gc_hours, 24.0);
    }
    #[test]
    fn compliance_and_maintenance_env_overrides_parse() {
        // Variable names differ, so they do not pollute other env tests in the same process.
        std::env::set_var("LATTICE__COMPLIANCE__PURGE_HARD_DELETE_DAYS", "0");
        std::env::set_var("LATTICE__COMPLIANCE__PURGE_CLEANUP_INTERVAL_SECS", "120");
        std::env::set_var("LATTICE__MAINTENANCE__MULTIPART_GC_HOURS", "0.5");
        std::env::set_var("LATTICE__MAINTENANCE__MULTIPART_GC_INTERVAL_SECS", "90");
        let mut cfg = Config::default();
        cfg.apply_env();
        std::env::remove_var("LATTICE__COMPLIANCE__PURGE_HARD_DELETE_DAYS");
        std::env::remove_var("LATTICE__COMPLIANCE__PURGE_CLEANUP_INTERVAL_SECS");
        std::env::remove_var("LATTICE__MAINTENANCE__MULTIPART_GC_HOURS");
        std::env::remove_var("LATTICE__MAINTENANCE__MULTIPART_GC_INTERVAL_SECS");
        assert!(!cfg.compliance.hard_delete_enabled());
        assert_eq!(
            cfg.compliance.effective_cleanup_interval(),
            Duration::from_secs(120)
        );
        assert!(cfg.maintenance.multipart_gc_enabled());
        assert_eq!(
            cfg.maintenance.effective_multipart_gc_age(),
            Duration::from_secs(1_800)
        );
        assert_eq!(
            cfg.maintenance.effective_interval(),
            Duration::from_secs(90)
        );
    }
    // ---- E01: cold archive / orphan object GC config ----
    #[test]
    fn archive_and_object_gc_defaults_are_disabled_and_bounded() {
        let cfg = Config::default();
        // Off by default = zero side effects; retention/bucket/interval semantics match the design docs.
        assert!(!cfg.maintenance.archive_enabled);
        assert!(!cfg.maintenance.archive_should_run());
        assert_eq!(cfg.maintenance.archive_after_days, ARCHIVE_AFTER_DAYS_DEFAULT);
        assert_eq!(cfg.maintenance.archive_after_days, 30);
        assert!(cfg.maintenance.archive_bucket.is_empty(), "empty = fall back to [s3] bucket_cold");
        assert_eq!(
            cfg.maintenance.effective_archive_interval(),
            Duration::from_secs(ARCHIVE_INTERVAL_SECS_DEFAULT)
        );
        assert!(!cfg.maintenance.object_gc_enabled);
        assert!(!cfg.maintenance.object_gc_should_run());
        assert_eq!(
            cfg.maintenance.object_gc_grace_days,
            OBJECT_GC_GRACE_DAYS_DEFAULT
        );
        assert_eq!(
            cfg.maintenance.effective_object_gc_interval(),
            Duration::from_secs(OBJECT_GC_INTERVAL_SECS_DEFAULT)
        );
        // Default directory convention once enabled: 30 days online, cold-bucket fallback
        let mut on = Config::default();
        on.maintenance.archive_enabled = true;
        on.maintenance.object_gc_enabled = true;
        assert!(on.maintenance.archive_should_run());
        assert!(on.maintenance.object_gc_should_run());
        assert_eq!(on.maintenance.effective_archive_after_days(), 30);
        assert_eq!(
            on.maintenance.effective_archive_bucket(&on.s3),
            on.s3.bucket_cold
        );
        assert_eq!(
            on.maintenance.effective_object_gc_grace_days(),
            30
        );
        // A custom bucket applies; a 0-day retention = archiving has no executable meaning (safe no-op)
        let mut custom = Config::default();
        custom.maintenance.archive_enabled = true;
        custom.maintenance.archive_bucket = "custom-cold".into();
        assert_eq!(
            custom.maintenance.effective_archive_bucket(&custom.s3),
            "custom-cold"
        );
        custom.maintenance.archive_after_days = 0;
        assert!(!custom.maintenance.archive_should_run());
        // Interval: 0 → default; 1 → 1s floor (deterministic E2E triggering; production daily)
        let mut bounds = Config::default();
        bounds.maintenance.archive_interval_secs = 0;
        bounds.maintenance.object_gc_interval_secs = 0;
        assert_eq!(
            bounds.maintenance.effective_archive_interval(),
            Duration::from_secs(86_400)
        );
        assert_eq!(
            bounds.maintenance.effective_object_gc_interval(),
            Duration::from_secs(86_400)
        );
        bounds.maintenance.archive_interval_secs = 1;
        bounds.maintenance.object_gc_interval_secs = 1;
        assert_eq!(
            bounds.maintenance.effective_archive_interval(),
            Duration::from_secs(1)
        );
        assert_eq!(
            bounds.maintenance.effective_object_gc_interval(),
            Duration::from_secs(1)
        );
        // SAMPLE_TOML section is valid and matches the defaults (deployment-file drift check)
        let sample: Config = toml::from_str(SAMPLE_TOML).unwrap();
        assert!(!sample.maintenance.archive_enabled);
        assert_eq!(sample.maintenance.archive_after_days, 30);
        assert_eq!(sample.maintenance.archive_interval_secs, 86_400);
        assert!(!sample.maintenance.object_gc_enabled);
        assert_eq!(sample.maintenance.object_gc_grace_days, 30);
    }
    #[test]
    fn archive_and_object_gc_env_overrides_parse() {
        // Variable names differ, so they do not pollute other env tests in the same process.
        std::env::set_var("LATTICE__MAINTENANCE__ARCHIVE_ENABLED", "true");
        std::env::set_var("LATTICE__MAINTENANCE__ARCHIVE_AFTER_DAYS", "7");
        std::env::set_var("LATTICE__MAINTENANCE__ARCHIVE_BUCKET", "cold-e2e");
        std::env::set_var("LATTICE__MAINTENANCE__ARCHIVE_INTERVAL_SECS", "2");
        std::env::set_var("LATTICE__MAINTENANCE__OBJECT_GC_ENABLED", "true");
        std::env::set_var("LATTICE__MAINTENANCE__OBJECT_GC_INTERVAL_SECS", "3");
        std::env::set_var("LATTICE__MAINTENANCE__OBJECT_GC_GRACE_DAYS", "0");
        let mut cfg = Config::default();
        cfg.apply_env();
        std::env::remove_var("LATTICE__MAINTENANCE__ARCHIVE_ENABLED");
        std::env::remove_var("LATTICE__MAINTENANCE__ARCHIVE_AFTER_DAYS");
        std::env::remove_var("LATTICE__MAINTENANCE__ARCHIVE_BUCKET");
        std::env::remove_var("LATTICE__MAINTENANCE__ARCHIVE_INTERVAL_SECS");
        std::env::remove_var("LATTICE__MAINTENANCE__OBJECT_GC_ENABLED");
        std::env::remove_var("LATTICE__MAINTENANCE__OBJECT_GC_INTERVAL_SECS");
        std::env::remove_var("LATTICE__MAINTENANCE__OBJECT_GC_GRACE_DAYS");
        assert!(cfg.maintenance.archive_should_run());
        assert_eq!(cfg.maintenance.effective_archive_after_days(), 7);
        assert_eq!(
            cfg.maintenance.effective_archive_bucket(&cfg.s3),
            "cold-e2e"
        );
        assert_eq!(
            cfg.maintenance.effective_archive_interval(),
            Duration::from_secs(2)
        );
        assert!(cfg.maintenance.object_gc_should_run());
        assert_eq!(
            cfg.maintenance.effective_object_gc_interval(),
            Duration::from_secs(3)
        );
        assert_eq!(cfg.maintenance.effective_object_gc_grace_days(), 0);
    }
    // ---- E31: `[pipeline] bypass` stage bypass config ----
    fn valid_kek_b64() -> String {
        lattice_core::envelope::base64_encode(&[0x11u8; 32])
    }
    #[test]
    fn pipeline_bypass_defaults_to_empty_and_covers_eight_stages() {
        let cfg = Config::default();
        assert!(cfg.pipeline.bypass.is_empty(), "no stage is bypassed by default");
        assert!(cfg.pipeline.normalized().is_empty());
        // The valid stage set covers the ② §2.2 ingestion orchestration (≥4; this implementation has 8)
        assert!(PIPELINE_STAGES.len() >= 4);
        for stage in [
            "validate", "member", "dedup", "detect", "format", "seq", "persist", "route",
        ] {
            assert!(
                PIPELINE_STAGES.contains(&stage),
                "missing legal stage {stage}"
            );
            let mut one = Config::default();
            one.pipeline.bypass = vec![stage.to_string()];
            one.pipeline.validate().unwrap();
            assert!(one.pipeline.is_bypassed(stage));
            // Only one stage is bypassed; other stages are unaffected
            for other in PIPELINE_STAGES {
                assert_eq!(
                    one.pipeline.is_bypassed(other),
                    other == stage,
                    "stage {stage} bypass leaked to {other}"
                );
            }
            assert_eq!(one.pipeline.normalized(), vec![stage]);
        }
    }
    #[test]
    fn pipeline_bypass_parse_and_case_insensitive_lookup() {
        let cfg: Config = toml::from_str(
            r#"
[pipeline]
bypass = [" Validate ", "dedup", ""]
"#,
        )
        .unwrap();
        // An empty string is invalid (empty after trim) → validate must fail, never silently ignore
        assert!(cfg.pipeline.validate().is_err());
        assert!(cfg.pipeline.is_bypassed("validate"));
        assert!(cfg.pipeline.is_bypassed("DEDUP"));
        assert!(!cfg.pipeline.is_bypassed("route"));
        let cfg: Config = toml::from_str(
            r#"
[pipeline]
bypass = ["validate", "route"]
"#,
        )
        .unwrap();
        cfg.pipeline.validate().unwrap();
        assert_eq!(cfg.pipeline.normalized(), vec!["validate", "route"]);
        // Keep the ingestion order (not the config file order)
        assert_eq!(cfg.pipeline.bypass, vec!["validate", "route"]);
    }
    #[test]
    fn pipeline_bypass_invalid_stage_fails_fast_with_legal_list() {
        let mut cfg = Config::default();
        cfg.pipeline.bypass = vec!["validate".into(), "vaildate".into()];
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.code, lattice_core::ErrorCode::Format);
        let reason = err
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|v| v.as_str());
        assert_eq!(reason, Some("pipeline_bypass"));
        let msg = format!("{err}");
        assert!(msg.contains("vaildate"), "the error message must name the invalid value: {msg}");
        assert!(msg.contains("validate"), "the error message must list the valid set: {msg}");
    }
    #[test]
    fn pipeline_bypass_env_overrides_parse() {
        std::env::set_var("LATTICE__PIPELINE__BYPASS", "validate, dedup,route");
        let mut cfg = Config::default();
        cfg.apply_env();
        std::env::remove_var("LATTICE__PIPELINE__BYPASS");
        assert_eq!(cfg.pipeline.bypass, vec!["validate", "dedup", "route"]);
        cfg.validate().unwrap();
        assert!(cfg.pipeline.is_bypassed("dedup"));
        assert!(!cfg.pipeline.is_bypassed("member"));
        // An empty env value = no bypass (not an "invalid empty name")
        std::env::set_var("LATTICE__PIPELINE__BYPASS", "");
        let mut empty = Config::default();
        empty.apply_env();
        std::env::remove_var("LATTICE__PIPELINE__BYPASS");
        assert!(empty.pipeline.bypass.is_empty());
        empty.validate().unwrap();
    }
    // ---- E15: `[inspectable]` node-local KEK config ----
    #[test]
    fn inspectable_defaults_are_off_and_zero_side_effect() {
        let cfg = Config::default();
        assert!(!cfg.inspectable.enabled, "off by default: identical to before it existed");
        assert!(cfg.inspectable.kek_id.is_empty());
        assert!(cfg.inspectable.kek.is_empty() && cfg.inspectable.kek_file.is_empty());
        // When disabled, leftover KEK material is neither validated nor loaded (supports rolling rollout: configure material first, flip the switch later)
        let mut staged = Config::default();
        staged.inspectable.kek = "not-even-valid".into();
        staged.inspectable.kek_id = "kek-staged".into();
        staged.validate().unwrap();
    }
    #[test]
    fn inspectable_toml_parse_and_env_overrides() {
        let cfg: Config = toml::from_str(&format!(
            r#"
[policy]
mode = "inspectable"
[inspectable]
enabled = true
kek_id = "kek-2026"
kek = "{}"
previous_kek_id = "kek-2025"
previous_kek = "{}"
"#,
            valid_kek_b64(),
            lattice_core::envelope::base64_encode(&[0x22u8; 32])
        ))
        .unwrap();
        cfg.validate().unwrap();
        assert!(cfg.inspectable.enabled);
        assert_eq!(cfg.inspectable.kek_id, "kek-2026");
        std::env::set_var("LATTICE__INSPECTABLE__ENABLED", "true");
        std::env::set_var("LATTICE__POLICY__MODE", "inspectable");
        std::env::set_var("LATTICE__INSPECTABLE__KEK_ID", "kek-env");
        std::env::set_var("LATTICE__INSPECTABLE__KEK", valid_kek_b64());
        let mut envcfg = Config::default();
        envcfg.apply_env();
        for k in [
            "LATTICE__INSPECTABLE__ENABLED",
            "LATTICE__POLICY__MODE",
            "LATTICE__INSPECTABLE__KEK_ID",
            "LATTICE__INSPECTABLE__KEK",
        ] {
            std::env::remove_var(k);
        }
        envcfg.validate().unwrap();
        assert!(envcfg.inspectable.enabled);
        assert_eq!(envcfg.inspectable.kek_id, "kek-env");
        assert_eq!(envcfg.mode(), lattice_core::Mode::Inspectable);
    }
    #[test]
    fn inspectable_invalid_configs_fail_fast() {
        // enabled=true but mode is not inspectable (otherwise "KEK configured but never used")
        let mut c = Config::default();
        c.inspectable.enabled = true;
        c.inspectable.kek_id = "kek-1".into();
        c.inspectable.kek = valid_kek_b64();
        assert!(c.validate().is_err(), "a mode mismatch must fail");
        // Missing KEK material
        let mut c = Config::default();
        c.policy.mode = "inspectable".into();
        c.inspectable.enabled = true;
        c.inspectable.kek_id = "kek-1".into();
        assert!(c.validate().is_err(), "enabled without material must fail");
        // kek and kek_file both configured (ambiguous source)
        let mut c = Config::default();
        c.policy.mode = "inspectable".into();
        c.inspectable.enabled = true;
        c.inspectable.kek_id = "kek-1".into();
        c.inspectable.kek = valid_kek_b64();
        c.inspectable.kek_file = "/tmp/kek".into();
        assert!(c.validate().is_err(), "two sources must fail");
        // No kek_id
        let mut c = Config::default();
        c.policy.mode = "inspectable".into();
        c.inspectable.enabled = true;
        c.inspectable.kek = valid_kek_b64();
        assert!(c.validate().is_err(), "enabled without kek_id must fail");
        // Material length is not 32B
        let mut c = Config::default();
        c.policy.mode = "inspectable".into();
        c.inspectable.enabled = true;
        c.inspectable.kek_id = "kek-1".into();
        c.inspectable.kek = lattice_core::envelope::base64_encode(&[0u8; 16]);
        assert!(c.validate().is_err(), "less than 32B must fail");
        // previous configured only halfway
        let mut c = Config::default();
        c.policy.mode = "inspectable".into();
        c.inspectable.enabled = true;
        c.inspectable.kek_id = "kek-1".into();
        c.inspectable.kek = valid_kek_b64();
        c.inspectable.previous_kek = valid_kek_b64();
        assert!(c.validate().is_err(), "previous material/id must come in pairs");
        // previous_kek_id equals the current kek_id (pointless rotation / overwrite risk)
        let mut c = Config::default();
        c.policy.mode = "inspectable".into();
        c.inspectable.enabled = true;
        c.inspectable.kek_id = "kek-1".into();
        c.inspectable.kek = valid_kek_b64();
        c.inspectable.previous_kek_id = "kek-1".into();
        c.inspectable.previous_kek = lattice_core::envelope::base64_encode(&[0x22u8; 32]);
        assert!(c.validate().is_err(), "previous_kek_id must not equal the current id");
    }
    #[test]
    fn sample_toml_has_pipeline_and_inspectable_sections_with_safe_defaults() {
        let sample: Config = toml::from_str(SAMPLE_TOML).unwrap();
        assert!(sample.pipeline.bypass.is_empty());
        assert!(!sample.inspectable.enabled);
        assert_eq!(
            serde_json::to_value(&sample).unwrap()["pipeline"]["bypass"],
            serde_json::json!([])
        );
        // The sample matches the defaults (deployment-file drift check)
        let def = Config::default();
        assert_eq!(sample.pipeline.bypass, def.pipeline.bypass);
        assert_eq!(sample.inspectable.enabled, def.inspectable.enabled);
    }
}
