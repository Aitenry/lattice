//! Scheduled jobs (section ⑦: lock + idempotency + rate limiting; authoritative job table in ⑥ §2.6/§6.4).
//!
//! Each job first acquires `lattice:lock:{task}` and skips if it cannot — guaranteeing single-instance execution per cluster (⑥ §3.2).

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use chrono::{DateTime, TimeZone, Utc};

use crate::state::AppState;
use crate::store::pg;

pub struct JobSpec {
    pub name: &'static str,
    pub task: &'static str,
    pub interval: Duration,
    pub ttl_ms: u64,
}

pub const JOBS: [JobSpec; 11] = [
    JobSpec { name: "chunk-clean", task: lattice_core::keys::tasks::CHUNK_CLEAN, interval: Duration::from_secs(300), ttl_ms: 60_000 },
    JobSpec { name: "pending-clean", task: lattice_core::keys::tasks::PENDING_CLEAN, interval: Duration::from_secs(60), ttl_ms: 30_000 },
    JobSpec { name: "dedup-clean", task: lattice_core::keys::tasks::DEDUP_CLEAN, interval: Duration::from_secs(3600), ttl_ms: 120_000 },
    JobSpec { name: "seq-watermark", task: lattice_core::keys::tasks::SEQ_WATERMARK, interval: Duration::from_secs(5), ttl_ms: 30_000 },
    JobSpec { name: "seq-flush-30s", task: lattice_core::keys::tasks::SEQ_WATERMARK, interval: Duration::from_secs(30), ttl_ms: 30_000 },
    JobSpec { name: "reconcile", task: lattice_core::keys::tasks::RECONCILE, interval: Duration::from_secs(300), ttl_ms: 60_000 },
    JobSpec { name: "reconcile-seq", task: lattice_core::keys::tasks::RECONCILE_SEQ, interval: Duration::from_secs(3600), ttl_ms: 120_000 },
    JobSpec { name: "snapshot", task: lattice_core::keys::tasks::SNAPSHOT, interval: Duration::from_secs(60), ttl_ms: 30_000 },
    JobSpec { name: "partition-maint", task: lattice_core::keys::tasks::PARTITION_MAINT, interval: Duration::from_secs(86400), ttl_ms: 600_000 },
    // Plugin hub: clean up drafts whose package body was not uploaded within 30 minutes (⑤ §12.3 / ⑥ §2.6)
    JobSpec { name: "hub-draft-clean", task: lattice_core::keys::tasks::HUB_DRAFT_CLEAN, interval: Duration::from_secs(300), ttl_ms: 60_000 },
    // Plugin hub: reclaim objects of withdrawn versions after 30 days (⑥ §2.6)
    JobSpec { name: "hub-object-gc", task: lattice_core::keys::tasks::HUB_OBJECT_GC, interval: Duration::from_secs(86400), ttl_ms: 600_000 },
];

/// Media recording lifecycle GC interval (PL-13 13.6): run one round after startup, then every 6h.
///
/// The task card says "daily (or startup + 6h cycle)"; we take the latter: the startup catch-up also cleans during rolling updates,
/// and a 6h cycle removes expired objects within half a day of the retention window ending (object-storage cost beats exact timing).
pub const MEDIA_RECORD_GC_INTERVAL: Duration = Duration::from_secs(6 * 3600);
/// Max index rows processed by one media-recording GC round (bounded batch; matches the
/// `limit` cap of `pg::media_recordings_expired`, avoiding a full table scan / long-held locks).
pub const MEDIA_RECORD_GC_BATCH_MAX: i64 = 1000;
/// Max consecutive delete failures allowed in one GC round: a half-dead object store cannot stall a round for 1000×30s;
/// failed rows stay for the next round (deletion is idempotent).
pub const MEDIA_RECORD_GC_ERROR_BUDGET: u64 = 10;

/// Whether retention days enable reclamation (`0` = no reclamation; pure function for unit tests and doc consistency).
pub fn media_record_retention_enabled(days: i64) -> bool {
    days > 0
}

/// S3/MinIO availability probe gate (② §4.8 "MinIO unavailable → server pauses chunk jobs").
///
/// When object storage is unavailable, **short-circuit this round** of object maintenance jobs: only WARN + record
/// `lattice_multipart_gc_total{result="paused"}`, with no per-bucket/per-object failure retries; recovery lets the next round continue (the job is idempotent).
/// The probe only opens a TCP connection with a 2s cap; no signing, no requests, no effect on node ready or the message plane.
async fn s3_maintenance_paused(st: &Arc<AppState>, task: &'static str) -> bool {
    match st.s3.probe().await {
        Ok(()) => false,
        Err(e) => {
            st.metrics
                .multipart_gc_total
                .with_label_values(&["paused"])
                .inc();
            tracing::warn!(
                task,
                error = %e,
                "s3 unavailable; maintenance task paused this round (② §4.8)"
            );
            true
        }
    }
}

/// Start all background jobs.
pub fn spawn_all(st: Arc<AppState>) {
    // Node heartbeat, 10s (§17.8)
    {
        let st = st.clone();
        tokio::spawn(async move {
            loop {
                st.heartbeat().await;
                tokio::time::sleep(Duration::from_secs(lattice_core::protocol::NODE_HEARTBEAT_TTL_SECS)).await;
            }
        });
    }

    // Periodic WAL replay (② §4.8): the startup catch-up runs once before `node::build` is ready; only the periodic job is here.
    // Interval from `[wal] replay_interval_ms` (default 2s); E2E can shrink it for speed.
    {
        let st = st.clone();
        tokio::spawn(async move {
            let interval = Duration::from_millis(st.cfg.wal.effective_replay_interval_ms());
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = replay_wal_once(&st).await {
                    tracing::warn!(error = %e, "wal replay round failed");
                }
            }
        });
    }

    // JWT previous key expiry cleanup (⑤ §8.4 dual-key overlap window): after the window, remove the old key from the verification set,
    // delete the prev file, and clean metadata; **audit is not deleted** (audit_log is the key-rotation trail).
    // Interval from `[auth] key_prune_interval_ms` / `LATTICE__AUTH__KEY_PRUNE_INTERVAL_MS`.
    {
        let st = st.clone();
        tokio::spawn(async move {
            let interval = Duration::from_millis(st.cfg.auth.effective_key_prune_interval_ms());
            loop {
                tokio::time::sleep(interval).await;
                match prune_jwt_previous(&st).await {
                    Ok(true) => tracing::info!("expired jwt previous key pruned"),
                    Ok(false) => {}
                    Err(e) => tracing::warn!(error = %e, "jwt previous key prune failed"),
                }
            }
        });
    }

    // Media recording lifecycle GC (PL-13 13.6): run one round after startup, then every 6h.
    // - retention=0 (default) = no reclamation: the job still exists but short-circuits every round (no SQL/object operations);
    // - single instance per cluster: acquire `lock:media-record-gc` (when Redis is unavailable, degrade to local execution per node —
    //   deletion itself is idempotent: object DELETE 404 counts as success, row DELETE is idempotent by id);
    // - failures only WARN, never affecting node ready/forwarding (cleanup is a side channel).
    {
        let st = st.clone();
        tokio::spawn(async move {
            // Staggered start: wait for migrations/service readiness and avoid bootstrap write amplification on first boot.
            tokio::time::sleep(Duration::from_secs(3)).await;
            loop {
                media_record_gc_round(&st).await;
                tokio::time::sleep(MEDIA_RECORD_GC_INTERVAL).await;
            }
        });
    }

    // Compliance hard-delete window (REMAINING E02 / ⑤ §8.2): run one round 30s after startup, then on the
    // `[compliance] purge_cleanup_interval_secs` (default 1h) cycle. With `purge_hard_delete_days=0` each round
    // short-circuits immediately (soft delete and object/Redis cascades still run at once via the purge API).
    // Design tradeoff: the startup catch-up cleans users whose window expires during rolling restarts; the 30s delay ensures migrations/
    // service readiness and avoids racing a just-triggered synchronous purge (E2E triggers deterministically via an admin hook).
    {
        let st = st.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            loop {
                purge_cleanup_round(&st).await;
                tokio::time::sleep(st.cfg.compliance.effective_cleanup_interval()).await;
            }
        });
    }

    // Residual multipart GC (REMAINING E04 / ⑥ §2.6): run one round 20s after startup, then on the
    // `[maintenance] multipart_gc_interval_secs` (default 1h) cycle; with `multipart_gc_hours<=0` each round
    // short-circuits immediately. Only unfinished uploads returned by ListMultipartUploads are aborted; completed objects are not in that
    // list (E04's core invariant, see store/s3.rs::list_multipart_uploads).
    {
        let st = st.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(20)).await;
            loop {
                gc_multipart_round(&st).await;
                tokio::time::sleep(st.cfg.maintenance.effective_interval()).await;
            }
        });
    }

    // Cold partition/row archiving (REMAINING E01 / ⑥ §2.5 `lock:archive`): **off by default = zero side effects**
    // (with `archive_enabled=false` no job is spawned, no PG query, no MinIO access). When enabled, run one round 4s after startup
    // (E2E triggers deterministically on a 1–2s cycle; production daily); the cycle comes from `archive_interval_secs`.
    if st.cfg.maintenance.archive_should_run() {
        let st = st.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(4)).await;
            loop {
                archive_round(&st).await;
                tokio::time::sleep(st.cfg.maintenance.effective_archive_interval()).await;
            }
        });
    }

    // Cold-bucket orphan object GC (REMAINING E01 / ⑥ §4.1 `lock:gc-objects`): **off by default = zero side effects**;
    // a separate switch so drills/rollbacks can run apart from archiving. First round 8s after startup, cycle `object_gc_interval_secs`.
    if st.cfg.maintenance.object_gc_should_run() {
        let st = st.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(8)).await;
            loop {
                object_gc_round(&st).await;
                tokio::time::sleep(st.cfg.maintenance.effective_object_gc_interval()).await;
            }
        });
    }

    for spec in JOBS {
        let st = st.clone();
        tokio::spawn(async move {
            // Stagger the first batch so rounds do not fire together
            tokio::time::sleep(Duration::from_secs((spec.interval.as_secs() % 17).max(1))).await;
            loop {
                if st
                    .redis
                    .acquire_lock(spec.task, &format!("{}:{}", st.node_id, spec.name), spec.ttl_ms)
                    .await
                    .unwrap_or(false)
                {
                    if let Err(e) = run(&st, spec.name).await {
                        tracing::warn!(job = spec.name, error = %e, "job failed");
                    }
                    let _ = st
                        .redis
                        .release_lock(spec.task, &format!("{}:{}", st.node_id, spec.name))
                        .await;
                }
                tokio::time::sleep(spec.interval).await;
            }
        });
    }

    tracing::info!(jobs = JOBS.len(), "background jobs started");
}

/// One round of media-recording lifecycle GC: lock (cluster single instance) → run → release; failures only WARN.
///
/// Lock TTL is 10min: a round handles ≤1000 rows with an error budget of 10, normally far below that; if a node is SIGKILLed
/// the lock expires naturally and the next round (startup catch-up after restart) continues (deletion is idempotent; concurrent deletion of the same object is safe).
async fn media_record_gc_round(st: &Arc<AppState>) {
    let days = st.cfg.media.effective_record_retention_days();
    if !media_record_retention_enabled(days) {
        tracing::debug!(
            retention_days = days,
            "media record gc skipped: [media] record_retention_days=0 (retention disabled)"
        );
        return;
    }
    // Chunk/object maintenance jobs pause while MinIO is unavailable (② §4.8): avoid per-object failure retries each round.
    if s3_maintenance_paused(st, "media-record-gc").await {
        return;
    }
    let owner = format!("{}:media-record-gc", st.node_id);
    match st
        .redis
        .acquire_lock("media-record-gc", &owner, 600_000)
        .await
    {
        Ok(true) => {
            match media_record_gc_once(st).await {
                Ok(0) => tracing::debug!(
                    retention_days = days,
                    "media record gc done: no expired segments"
                ),
                Ok(deleted) => tracing::info!(
                    retention_days = days,
                    deleted,
                    "media record gc done: expired segments deleted"
                ),
                Err(e) => tracing::warn!(error = %e, "media record gc failed (will retry next round)"),
            }
            let _ = st.redis.release_lock("media-record-gc", &owner).await;
        }
        Ok(false) => {
            tracing::debug!("media record gc skipped: lock:media-record-gc held by another node");
        }
        Err(e) => {
            // Redis unavailable: GC is idempotent cleanup, so local execution fits retention semantics better than "no cleanup at all".
            tracing::debug!(
                error = %e,
                "redis lock unavailable; running media record gc locally (deletes are idempotent)"
            );
            match media_record_gc_once(st).await {
                Ok(0) => {}
                Ok(deleted) => tracing::info!(
                    retention_days = days,
                    deleted,
                    "media record gc (local, redis lock unavailable) deleted expired segments"
                ),
                Err(e) => tracing::warn!(error = %e, "media record gc (local) failed"),
            }
        }
    }
}

/// Run one media-recording lifecycle GC round (PL-13 13.6 / ⑥ §4 object GC): returns the number of index rows deleted this round.
///
/// Semantics (in the implementation and in the report):
/// - **Bounded batch**: at most `MEDIA_RECORD_GC_BATCH_MAX` (1000) rows per round, oldest first;
/// - **Objects before rows**: delete the segment and manifest objects first, then the index row; any failure keeps the row
///   for the next round (deleting the row first would orphan the object as unlocatable garbage);
/// - **manifest may be null**: old rows / rows whose generation failed have `manifest_key=NULL`; only the segment object is deleted;
/// - **Expired only**: `created_at < now() - retention_days` (index row write time; new segments untouched);
/// - **Error budget**: a round aborts after `MEDIA_RECORD_GC_ERROR_BUDGET` delete failures,
///   so a half-dead object store cannot stall one round for 1000×30s; remaining rows continue next round; failures only WARN + metrics.
pub async fn media_record_gc_once(st: &Arc<AppState>) -> crate::error::Result<u64> {
    let days = st.cfg.media.effective_record_retention_days();
    if !media_record_retention_enabled(days) {
        return Ok(0);
    }
    let rows = pg::media_recordings_expired(&st.db, days, MEDIA_RECORD_GC_BATCH_MAX).await?;
    let mut deleted = 0u64;
    let mut errors = 0u64;
    for row in rows {
        if errors >= MEDIA_RECORD_GC_ERROR_BUDGET {
            tracing::warn!(
                errors,
                "media record gc error budget exhausted; remaining expired rows deferred to next round"
            );
            break;
        }
        let mut ok = true;
        if let Err(e) = st.s3.delete_object(&row.bucket, &row.object_key).await {
            ok = false;
            errors += 1;
            st.metrics
                .media_record_gc_total
                .with_label_values(&["error"])
                .inc();
            tracing::warn!(
                error = %e,
                recording_id = %row.id,
                bucket = %row.bucket,
                key = %row.object_key,
                "media record gc: segment object delete failed (row kept for retry)"
            );
        }
        if ok {
            if let Some(manifest_key) = row.manifest_key.as_deref() {
                if let Err(e) = st.s3.delete_object(&row.bucket, manifest_key).await {
                    ok = false;
                    errors += 1;
                    st.metrics
                        .media_record_gc_total
                        .with_label_values(&["error"])
                        .inc();
                    tracing::warn!(
                        error = %e,
                        recording_id = %row.id,
                        bucket = %row.bucket,
                        key = %manifest_key,
                        "media record gc: manifest object delete failed (row kept for retry)"
                    );
                }
            }
        }
        if !ok {
            continue;
        }
        match pg::media_recording_delete(&st.db, &row.id).await {
            Ok(true) => {
                deleted += 1;
                st.metrics
                    .media_record_gc_total
                    .with_label_values(&["deleted"])
                    .inc();
            }
            // Row already deleted concurrently (another node/previous round): idempotent, counts as success but not as deleted.
            Ok(false) => tracing::debug!(
                recording_id = %row.id,
                "media record gc: row already deleted (idempotent)"
            ),
            Err(e) => {
                errors += 1;
                st.metrics
                    .media_record_gc_total
                    .with_label_values(&["error"])
                    .inc();
                tracing::warn!(
                    error = %e,
                    recording_id = %row.id,
                    "media record gc: index row delete failed (objects already gone; retry next round)"
                );
            }
        }
    }
    st.metrics.media_record_gc_rows.set(deleted as i64);
    Ok(deleted)
}

// ---------------------------------------------------------------------------
// REMAINING E02: compliance purge cascade residual cleanup (MinIO objects / Redis keys / hard-delete window)
// ---------------------------------------------------------------------------

/// Distributed lock name for the hard-delete window job (the ⑥ §2.6 `lock:*` table does not register purge-cleanup; this task adds it,
/// and `lattice-core` is out of scope this round, so it is kept separate from `gc-multipart` (already registered in keys::tasks):
/// the latter uses `keys::tasks::GC_MULTIPART`; here a jobs.rs constant is used, with lock keys still `lattice:lock:*`).
pub const PURGE_CLEANUP_LOCK: &str = "purge-cleanup";

/// User messages processed per batch (bounded batch of object deletes + PG row deletes; on failure the whole batch stays for the next round).
pub const PURGE_CLEANUP_BATCH: i64 = 200;
/// Max consecutive object delete failures allowed in a round: a half-dead object store cannot stall it (failures keep PG rows
/// for the next round; no "row deleted, object still there" leak).
pub const PURGE_OBJECT_ERROR_BUDGET: u64 = 10;
/// purge cleanup progress key TTL (30 days; covers the default 7-day hard-delete window plus the operations investigation period).
///
/// The key name `lattice:purge:{user}` **is not in `lattice-core::keys`**: that crate is out of scope this round
/// (same treatment as `lattice:upload:` / `lattice:idem:` in `store/redis.rs`), and it is only a job progress
/// snapshot, not authoritative data (after loss the purge cascade still reruns idempotently from PG rows; `purge-residual-scan.ps1`
/// uses the object_keys it records to HEAD each key after the PG rows are gone and verify the objects really are absent).
pub const PURGE_PROGRESS_TTL_SECS: u64 = 30 * 24 * 3_600;
/// Max object keys recorded in progress (for the residual scanner's per-key HEAD; over the cap sets `manifest_truncated`).
pub const PURGE_MANIFEST_MAX_KEYS: usize = 10_000;
/// Message budget for `POST /users/{id}/purge` synchronous inline cleanup (the remainder continues in the background so API latency stays bounded).
pub const PURGE_INLINE_MAX_MESSAGES: usize = 200;
/// Max deleted users processed by one hard-delete round.
pub const PURGE_CLEANUP_MAX_USERS: i64 = 100;
/// Trace cap for the full-prefix scan over `lattice:upload:` / `lattice:stream:` during Redis-dimension cleanup
/// (prevents a pathological keyspace from dragging out one purge; leftover keys rely on TTL and are noted in logs/WARN).
pub const PURGE_REDIS_SCAN_CAP: usize = 2_000;

/// Compliance purge cleanup progress (Redis `lattice:purge:{user}` JSON; `cleanup` in `GET /users/{id}/purge`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PurgeProgress {
    pub user_id: String,
    /// `queued` → `objects` → `redis` → `done`; `error` on failure (`last_error` holds the reason).
    pub phase: String,
    pub messages_deleted: u64,
    pub chunks_deleted: u64,
    pub objects_deleted: u64,
    pub objects_failed: u64,
    pub redis_keys_deleted: u64,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    /// Deleted object key list (bounded; lets the residual scanner HEAD each key and verify 404 after the PG rows are gone).
    #[serde(default)]
    pub object_keys: Vec<String>,
    /// Whether `object_keys` was truncated at `PURGE_MANIFEST_MAX_KEYS`.
    #[serde(default)]
    pub manifest_truncated: bool,
}

impl PurgeProgress {
    pub fn complete(&self) -> bool {
        self.phase == "done"
    }
}

/// The `lattice:purge:{user}` key (see [`PURGE_PROGRESS_TTL_SECS`]).
pub fn purge_progress_key(user_id: &str) -> String {
    format!("lattice:purge:{user_id}")
}

/// Load purge progress (the `cleanup` field of `GET /v1/admin/users/{id}/purge`).
pub async fn load_purge_progress(
    st: &Arc<AppState>,
    user_id: &str,
) -> crate::error::Result<Option<PurgeProgress>> {
    let raw = st
        .redis
        .get_json(&purge_progress_key(user_id))
        .await
        ?;
    Ok(raw.and_then(|s| serde_json::from_str::<PurgeProgress>(&s).ok()))
}

async fn save_purge_progress(
    st: &Arc<AppState>,
    p: &PurgeProgress,
) -> crate::error::Result<()> {
    let body = serde_json::to_string(p)
        .map_err(|e| crate::error::internal(format!("purge progress encode failed: {e}")))?;
    st.redis
        .set_json(
            &purge_progress_key(&p.user_id),
            &body,
            PURGE_PROGRESS_TTL_SECS,
        )
        .await
}

/// Explicit Redis keys purge must **delete outright** (user/device/topic dimensions, ⑥ §3.1):
/// two connection layers, three pending sets, subscription hot cache, rate-limit buckets, MQTT session/WILL keys, login account rate-limit bucket.
///
/// Pure function: E2E/unit tests assert the key layout against the same contract, avoiding implementation/doc drift.
pub fn purge_explicit_redis_keys(
    user_id: &str,
    username: Option<&str>,
    devices: &[String],
) -> Vec<String> {
    use lattice_core::keys;
    let mut keys = vec![
        keys::conn_user(user_id),
        keys::pending_user(user_id),
        keys::sub(user_id),
        keys::ratelimit(user_id),
    ];
    for d in devices {
        keys.push(keys::conn_device(user_id, d));
        keys.push(keys::pending_device(user_id, d));
        keys.push(keys::ratelimit_mqtt(d));
    }
    if let Some(u) = username.map(str::trim).filter(|u| !u.is_empty()) {
        // Account-dimension login rate-limit key: `lattice:ratelimit:login:acct:{username}` (⑤ §1.1).
        keys.push(keys::ratelimit_login(&format!("acct:{u}")));
    }
    keys
}

/// Redis key prefixes purge must **delete wholesale by prefix** (covers device/topic subkeys that appear dynamically).
pub fn purge_redis_prefixes(user_id: &str) -> Vec<String> {
    use lattice_core::keys;
    vec![
        format!("{}:", keys::conn_user(user_id)),
        format!("{}:", keys::pending_user(user_id)),
        // MQTT persistent session/WILL keys: `lattice:mqtt:sess:{user}:{device}:{client}:state|out`
        // / `lattice:mqtt:will:{user}:{device}:{client}` (local key layout in transport/mqtt.rs).
        format!("lattice:mqtt:sess:{user_id}:"),
        format!("lattice:mqtt:will:{user_id}:"),
    ]
}

/// Result of one purge residual cleanup (aggregated by the API/job/metrics).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PurgeResidualSummary {
    pub messages_deleted: u64,
    pub chunks_deleted: u64,
    pub objects_deleted: u64,
    pub objects_failed: u64,
    pub redis_keys_deleted: u64,
    /// All three dimensions (messages / chunk objects / Redis) are fully cleaned (the hard-delete job uses this to decide whether the user row can go).
    pub complete: bool,
}

#[derive(sqlx::FromRow)]
struct PurgeMessageRow {
    id: String,
    payload_ref: Option<String>,
}

#[derive(sqlx::FromRow)]
struct PurgeChunkRow {
    storage_key: Option<String>,
}

#[derive(sqlx::FromRow)]
struct PurgeObjectRow {
    object_key: String,
    source_object_key: Option<String>,
}

#[derive(sqlx::FromRow)]
struct DeletedUserRow {
    id: String,
}

/// Run purge cascade residual cleanup for one user (idempotent; safe to call repeatedly from the API inline, background job, or hard-delete job).
///
/// Semantics (in the implementation and in the report):
/// - **Only this user's own data**: messages with `messages.sender = user`, their chunk objects
///   (`messages.payload_ref` + `chunks_index.storage_key`), delivery records, and
///   `lattice:...` keys in the userId/deviceId dimensions;
/// - **Objects before rows**: if an object delete fails → this batch's PG rows stay for the next round; never "rows gone, object still there"
///   as unlocatable garbage (same principle as media GC / hub GC);
/// - **Bounded batch**: at most `max_messages` messages per call (default 200 inline, larger in the background);
/// - **Failures counted, never panic**: object failures are bounded by `PURGE_OBJECT_ERROR_BUDGET`;
/// - **Idempotent**: object DELETE 404 counts as success; PG deletes by id; progress in Redis is only for display/scan manifests.
pub async fn purge_user_residuals(
    st: &Arc<AppState>,
    user_id: &str,
    max_messages: usize,
) -> crate::error::Result<PurgeResidualSummary> {
    let mut progress = load_purge_progress(st, user_id).await?.unwrap_or_else(|| {
        PurgeProgress {
            user_id: user_id.to_string(),
            phase: "queued".into(),
            ..Default::default()
        }
    });
    if progress.started_at.is_none() {
        progress.started_at = Some(Utc::now());
    }
    if !progress.complete() {
        progress.phase = "objects".into();
    }
    save_purge_progress(st, &progress).await?;

    let mut summary = PurgeResidualSummary::default();
    let bucket = st.cfg.s3.bucket_large.clone();
    let mut manifest_seen: std::collections::HashSet<String> =
        progress.object_keys.iter().cloned().collect();
    let mut error_budget_hit = false;

    loop {
        if summary.messages_deleted as usize >= max_messages {
            break;
        }
        let remaining_budget = max_messages.saturating_sub(summary.messages_deleted as usize);
        let batch = (remaining_budget as i64).clamp(1, PURGE_CLEANUP_BATCH);
        let rows: Vec<PurgeMessageRow> = sqlx::query_as(
            "select id, payload_ref from messages
             where sender = $1 order by created_at limit $2",
        )
        .bind(user_id)
        .bind(batch)
        .fetch_all(&st.db)
        .await
        .map_err(crate::error::db)?;
        if rows.is_empty() {
            break;
        }
        let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
        let chunk_rows: Vec<PurgeChunkRow> = sqlx::query_as(
            "select storage_key from chunks_index
             where msg_id = any($1) and storage_key is not null",
        )
        .bind(&ids)
        .fetch_all(&st.db)
        .await
        .map_err(crate::error::db)?;

        let mut keys: Vec<String> = Vec::new();
        for row in &rows {
            if let Some(k) = row.payload_ref.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
                keys.push(k.to_string());
            }
        }
        for row in &chunk_rows {
            if let Some(k) = row.storage_key.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
                keys.push(k.to_string());
            }
        }
        keys.sort();
        keys.dedup();

        // Delete objects first; any failure → keep this batch's PG rows (retry next round), avoiding unlocatable garbage objects.
        let mut batch_object_failed = false;
        for key in &keys {
            match st.s3.delete_object(&bucket, key).await {
                Ok(()) => {
                    summary.objects_deleted += 1;
                    progress.objects_deleted += 1;
                    st.metrics
                        .purge_objects_total
                        .with_label_values(&["deleted"])
                        .inc();
                    if progress.object_keys.len() < PURGE_MANIFEST_MAX_KEYS {
                        if manifest_seen.insert(key.clone()) {
                            progress.object_keys.push(key.clone());
                        }
                    } else {
                        progress.manifest_truncated = true;
                    }
                }
                Err(e) => {
                    batch_object_failed = true;
                    summary.objects_failed += 1;
                    progress.objects_failed += 1;
                    st.metrics
                        .purge_objects_total
                        .with_label_values(&["failed"])
                        .inc();
                    tracing::warn!(
                        error = %e,
                        user = %user_id,
                        key = %key,
                        "purge: object delete failed (pg rows kept for retry)"
                    );
                    if summary.objects_failed >= PURGE_OBJECT_ERROR_BUDGET {
                        error_budget_hit = true;
                        break;
                    }
                }
            }
        }
        if batch_object_failed {
            progress.phase = "objects".into();
            progress.last_error = Some(format!(
                "{} object delete(s) failed; pg rows kept for retry",
                summary.objects_failed
            ));
            save_purge_progress(st, &progress).await?;
            break;
        }

        // All objects deleted → safe to delete PG (chunks before messages; delivery_log cleaned at the same time)
        let chunks_deleted = sqlx::query("delete from chunks_index where msg_id = any($1)")
            .bind(&ids)
            .execute(&st.db)
            .await
            .map_err(crate::error::db)?
            .rows_affected();
        summary.chunks_deleted += chunks_deleted;
        progress.chunks_deleted += chunks_deleted;
        sqlx::query("delete from delivery_log where msg_id = any($1)")
            .bind(&ids)
            .execute(&st.db)
            .await
            .map_err(crate::error::db)?;
        let msgs_deleted = sqlx::query("delete from messages where id = any($1)")
            .bind(&ids)
            .execute(&st.db)
            .await
            .map_err(crate::error::db)?
            .rows_affected();
        summary.messages_deleted += msgs_deleted;
        progress.messages_deleted += msgs_deleted;

        // dedup hot layer: best effort (TTL fallback; failures do not block PG deletion, only WARN)
        for id in &ids {
            if let Err(e) = st.redis.del(&lattice_core::keys::dedup(id)).await {
                tracing::warn!(error = %e, id = %id, "purge: dedup key delete failed (ttl fallback)");
            }
        }
        save_purge_progress(st, &progress).await?;
        if msgs_deleted == 0 {
            // Defensive: rows were cleaned concurrently (another node/previous round) → break the loop
            break;
        }
    }

    // Are messages/chunks fully cleared? Only then clean the Redis dimension (otherwise wait for the next round, so residual keys
    // do not disappear while routing/redelivery can still hit a half-cleaned state).
    let remaining_messages: i64 =
        sqlx::query_scalar("select count(*) from messages where sender = $1")
            .bind(user_id)
            .fetch_one(&st.db)
            .await
            .map_err(crate::error::db)?;

    if remaining_messages == 0 && !error_budget_hit {
        progress.phase = "redis".into();
        save_purge_progress(st, &progress).await?;
        match purge_user_redis_keys(st, user_id).await {
            Ok(deleted) => {
                summary.redis_keys_deleted = deleted;
                progress.redis_keys_deleted += deleted;
                st.metrics
                    .purge_cleanup_total
                    .with_label_values(&["redis_ok"])
                    .inc();
            }
            Err(e) => {
                progress.last_error = Some(format!("redis cleanup failed: {e}"));
                st.metrics
                    .purge_cleanup_total
                    .with_label_values(&["redis_error"])
                    .inc();
                save_purge_progress(st, &progress).await?;
                tracing::warn!(error = %e, user = %user_id, "purge: redis key cleanup failed (retry next round)");
                return Ok(summary);
            }
        }
        // Fallback recheck: complete only when messages/chunks/PG rows are all 0
        let final_remaining: i64 =
            sqlx::query_scalar("select count(*) from messages where sender = $1")
                .bind(user_id)
                .fetch_one(&st.db)
                .await
                .map_err(crate::error::db)?;
        summary.complete = final_remaining == 0;
        if summary.complete {
            progress.phase = "done".into();
            progress.finished_at = Some(Utc::now());
            st.metrics
                .purge_cleanup_total
                .with_label_values(&["objects_ok"])
                .inc();
            tracing::info!(
                user = %user_id,
                messages = summary.messages_deleted,
                chunks = summary.chunks_deleted,
                objects = summary.objects_deleted,
                redis_keys = summary.redis_keys_deleted,
                "purge: residual cleanup complete"
            );
        }
    } else if error_budget_hit || summary.objects_failed > 0 {
        // Object delete failures (whether or not the error budget is exhausted) keep PG rows; count objects_error separately
        // so alerts can tell a half-dead object store from "normal, no data" (failures keep rows, next round retries).
        st.metrics
            .purge_cleanup_total
            .with_label_values(&["objects_error"])
            .inc();
        progress.last_error = Some(if error_budget_hit {
            "object delete error budget exhausted; retry next round".to_string()
        } else {
            format!(
                "{} object delete(s) failed; {} message row(s) kept for retry",
                summary.objects_failed, remaining_messages
            )
        });
        progress.phase = "objects".into();
    }

    if !summary.complete {
        let phase = progress.phase_if_not_done();
        progress.phase = phase;
    }
    save_purge_progress(st, &progress).await?;
    Ok(summary)
}

impl PurgeProgress {
    fn phase_if_not_done(&self) -> String {
        if self.phase == "done" {
            "done".into()
        } else if self.messages_deleted > 0 || !self.object_keys.is_empty() {
            "objects".into()
        } else {
            "queued".into()
        }
    }
}

/// Delete the **basic** Redis keys of the user/device dimensions (explicit keys + two conn layers / three pending sets + MQTT
/// session/WILL prefixes). Called inline by `POST /users/{id}/purge` (low latency, no full-prefix scan); returns the key count deleted.
pub async fn purge_user_redis_keys_basic(
    st: &Arc<AppState>,
    user_id: &str,
) -> crate::error::Result<u64> {
    let username: Option<String> = sqlx::query_scalar("select username from users where id = $1")
        .bind(user_id)
        .fetch_optional(&st.db)
        .await
        .map_err(crate::error::db)?;
    let devices: Vec<String> = sqlx::query_scalar("select id from devices where user_id = $1")
        .bind(user_id)
        .fetch_all(&st.db)
        .await
        .map_err(crate::error::db)?;

    let mut keys: Vec<String> = purge_explicit_redis_keys(user_id, username.as_deref(), &devices);
    for prefix in purge_redis_prefixes(user_id) {
        let mut found = st
            .redis
            .scan_prefix(&prefix)
            .await
            ?;
        keys.append(&mut found);
    }
    keys.sort();
    keys.dedup();
    let mut deleted = 0u64;
    for key in keys {
        match st.redis.del(&key).await {
            Ok(()) => deleted += 1,
            Err(e) => {
                tracing::warn!(error = %e, key = %key, "purge: redis key delete failed (retry next round)");
            }
        }
    }
    Ok(deleted)
}

/// Delete Redis keys of the user/device/topic dimensions (basic keys + upload session / media tunnel session / risk-control observation keys).
/// Returns the key count deleted. Called by background purge cleanup after messages are cleared (full scope).
async fn purge_user_redis_keys(
    st: &Arc<AppState>,
    user_id: &str,
) -> crate::error::Result<u64> {
    let username: Option<String> = sqlx::query_scalar("select username from users where id = $1")
        .bind(user_id)
        .fetch_optional(&st.db)
        .await
        .map_err(crate::error::db)?;
    let devices: Vec<String> = sqlx::query_scalar("select id from devices where user_id = $1")
        .bind(user_id)
        .fetch_all(&st.db)
        .await
        .map_err(crate::error::db)?;

    let mut deleted = purge_user_redis_keys_basic(st, user_id).await?;
    let mut keys: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for key in st
        .redis
        .scan_prefix("lattice:upload:")
        .await
        ?
    {
        if scanned >= PURGE_REDIS_SCAN_CAP {
            tracing::warn!(
                cap = PURGE_REDIS_SCAN_CAP,
                "purge: upload session scan cap reached; remaining keys rely on ttl"
            );
            break;
        }
        scanned += 1;
        if let Ok(Some(raw)) = st.redis.get_json(&key).await {
            let owner = serde_json::from_str::<serde_json::Value>(&raw)
                .ok()
                .and_then(|v| v.get("user_id").and_then(|u| u.as_str()).map(str::to_string));
            if owner.as_deref() == Some(user_id) {
                keys.push(key);
            }
        }
    }

    // Media tunnel session (`lattice:stream:{id}` Hash: a_user/b_user): delete if either participant is this user.
    let stream_prefix = lattice_core::keys::stream_session("");
    for key in st
        .redis
        .scan_prefix(&stream_prefix)
        .await
        ?
    {
        if scanned >= PURGE_REDIS_SCAN_CAP {
            break;
        }
        scanned += 1;
        let Some(id) = key.strip_prefix(&stream_prefix) else {
            continue;
        };
        if let Ok(Some(map)) = st.redis.stream_session_get(id).await {
            if map.values().any(|v| v == user_id) {
                keys.push(key);
            }
        }
    }

    // Risk-control observation key `lattice:risk:throttle:{user}:{device}` (③ §4.7).
    for key in st
        .redis
        .scan_prefix("lattice:risk:throttle:")
        .await
        ?
    {
        let hit_user = key.contains(user_id);
        let hit_device = devices.iter().any(|d| key.contains(d.as_str()));
        let hit_username = username
            .as_deref()
            .map(|u| key.contains(&format!(":{u}:")))
            .unwrap_or(false);
        if hit_user || hit_device || hit_username {
            keys.push(key);
        }
    }

    keys.sort();
    keys.dedup();
    for key in keys {
        match st.redis.del(&key).await {
            Ok(()) => deleted += 1,
            Err(e) => {
                tracing::warn!(error = %e, key = %key, "purge: redis key delete failed (retry next round)");
            }
        }
    }
    Ok(deleted)
}

/// Per-category purge residual counts for the current user (the `residual` field of `GET /users/{id}/purge`; lets the console/
/// operations confirm "all three residual classes = 0"; the object dimension is the progress manifest length — the scanner HEADs each key again).
pub async fn purge_residual_counts(
    st: &Arc<AppState>,
    user_id: &str,
) -> crate::error::Result<serde_json::Value> {
    let messages: i64 = sqlx::query_scalar("select count(*) from messages where sender = $1")
        .bind(user_id)
        .fetch_one(&st.db)
        .await
        .map_err(crate::error::db)?;
    let chunks: i64 = sqlx::query_scalar(
        "select count(*) from chunks_index c
         join messages m on m.id = c.msg_id
         where m.sender = $1 and c.storage_key is not null",
    )
    .bind(user_id)
    .fetch_one(&st.db)
    .await
    .map_err(crate::error::db)?;
    let delivery: i64 = sqlx::query_scalar("select count(*) from delivery_log where to_user = $1")
        .bind(user_id)
        .fetch_one(&st.db)
        .await
        .map_err(crate::error::db)?;
    let devices: i64 = sqlx::query_scalar("select count(*) from devices where user_id = $1")
        .bind(user_id)
        .fetch_one(&st.db)
        .await
        .map_err(crate::error::db)?;
    let status: Option<String> = sqlx::query_scalar("select status from users where id = $1")
        .bind(user_id)
        .fetch_optional(&st.db)
        .await
        .map_err(crate::error::db)?;
    let progress = load_purge_progress(st, user_id).await?;
    let (phase, objects_recorded) = progress
        .as_ref()
        .map(|p| (p.phase.clone(), p.object_keys.len() as i64))
        .unwrap_or_else(|| ("none".into(), 0));
    Ok(json!({
        "pg_messages": messages,
        "pg_chunks": chunks,
        "pg_delivery_log": delivery,
        "pg_devices": devices,
        "pg_user_status": status,
        "minio_objects_recorded": objects_recorded,
        "cleanup_phase": phase,
    }))
}

/// Result of one hard-delete window job round.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PurgeCleanupSummary {
    pub enabled: bool,
    /// Due deleted users found inside the lock this round.
    pub due: u64,
    /// Users hard-deleted (user row + cascaded devices + delivery/topic watermark rows).
    pub deleted: u64,
    /// Users held for the next round because residual object/Redis cleanup is incomplete (not counted as failures).
    pub pending: u64,
    /// Users that failed this round (PG/objects/Redis).
    pub failed: u64,
}

/// Run one hard-delete window cleanup round (`lock:purge-cleanup` single instance; failures only WARN, retried next round).
///
/// Only deleted users whose **residual cleanup is complete** are hard-deleted (objects first, rows after); otherwise they stay for
/// the next round — better to delay the hard delete than to leave "user gone, objects still there" unlocatable residue.
pub async fn purge_cleanup_once(
    st: &Arc<AppState>,
) -> crate::error::Result<PurgeCleanupSummary> {
    let mut summary = PurgeCleanupSummary::default();
    if !st.cfg.compliance.hard_delete_enabled() {
        return Ok(summary);
    }
    summary.enabled = true;
    let days = st.cfg.compliance.effective_hard_delete_days();
    let due: Vec<DeletedUserRow> = sqlx::query_as(
        "select id from users
         where status = 'deleted'
           and updated_at <= now() - make_interval(days => $1)
         order by updated_at limit $2",
    )
    .bind(days.min(i32::MAX as i64) as i32)
    .bind(PURGE_CLEANUP_MAX_USERS)
    .fetch_all(&st.db)
    .await
    .map_err(crate::error::db)?;
    summary.due = due.len() as u64;

    for row in due {
        let user_id = row.id;
        match purge_user_residuals(st, &user_id, usize::MAX / 2).await {
            Ok(r) if r.complete => match purge_hard_delete_rows(st, &user_id).await {
                Ok(true) => {
                    let _ = st.redis.del(&purge_progress_key(&user_id)).await;
                    summary.deleted += 1;
                    st.metrics
                        .purge_cleanup_total
                        .with_label_values(&["user_deleted"])
                        .inc();
                    let _ = crate::routing::audit::audit_emit(
                        st,
                        Some("system:purge"),
                        "user_purge_hard_delete",
                        Some(&user_id),
                        &json!({
                            "reason": "purge_hard_delete_window",
                            "window_days": days,
                            "messages_deleted": r.messages_deleted,
                            "chunks_deleted": r.chunks_deleted,
                            "objects_deleted": r.objects_deleted,
                            "redis_keys_deleted": r.redis_keys_deleted,
                        }),
                        None,
                    )
                    .await;
                    tracing::info!(
                        user = %user_id,
                        window_days = days,
                        "purge: deleted user hard-deleted after window"
                    );
                }
                Ok(false) => {
                    // Already deleted concurrently (another node/previous round): idempotent, count as done
                    summary.deleted += 1;
                }
                Err(e) => {
                    summary.failed += 1;
                    st.metrics
                        .purge_cleanup_total
                        .with_label_values(&["user_error"])
                        .inc();
                    tracing::warn!(error = %e, user = %user_id, "purge: hard delete failed (retry next round)");
                }
            },
            Ok(_) => {
                // Residual not fully cleaned: keep it, continue next round (object failures keep PG rows)
                summary.pending += 1;
            }
            Err(e) => {
                summary.failed += 1;
                st.metrics
                    .purge_cleanup_total
                    .with_label_values(&["user_error"])
                    .inc();
                tracing::warn!(error = %e, user = %user_id, "purge: residual cleanup failed (retry next round)");
            }
        }
    }
    st.metrics.purge_cleanup_users.set(summary.deleted as i64);
    Ok(summary)
}

/// Delete the rows remaining for a deleted user (called after residual cleanup completes).
///
/// Order: other user_id-dimension tables → plugin ownership (`hub_plugins.owner_id` has **no** on delete cascade,
/// so handling it later would make the users delete fail) → user row (devices/conversation_members/installs are cleaned by FK
/// cascade). Returns `false` = the user row no longer exists (idempotent).
async fn purge_hard_delete_rows(
    st: &Arc<AppState>,
    user_id: &str,
) -> crate::error::Result<bool> {
    for sql in [
        "delete from delivery_log where to_user = $1",
        "delete from topic_offsets where user_id = $1",
        "delete from read_watermark where user_id = $1",
        "delete from conversation_members where user_id = $1",
    ] {
        sqlx::query(sql)
            .bind(user_id)
            .execute(&st.db)
            .await
            .map_err(crate::error::db)?;
    }

    // Plugin ownership: plugins owned by the user (version objects too; on failure abort the round and retry next round)
    let owned_plugins: Vec<String> =
        sqlx::query_scalar("select id from hub_plugins where owner_id = $1")
            .bind(user_id)
            .fetch_all(&st.db)
            .await
            .map_err(crate::error::db)?;
    let bucket_plugins = st.cfg.s3.bucket_plugins.clone();
    for plugin_id in &owned_plugins {
        let versions: Vec<PurgeObjectRow> = sqlx::query_as(
            "select object_key, source_object_key from hub_plugin_versions where plugin_id = $1",
        )
        .bind(plugin_id)
        .fetch_all(&st.db)
        .await
        .map_err(crate::error::db)?;
        for v in versions {
            for key in std::iter::once(Some(v.object_key)).chain(std::iter::once(v.source_object_key)) {
                let Some(key) = key.filter(|k| !k.trim().is_empty()) else {
                    continue;
                };
                st.s3
                    .delete_object(&bucket_plugins, &key)
                    .await
                    .map_err(|e| crate::error::internal(format!("purge hub object {key}: {e}")))?;
            }
        }
        for sql in [
            "delete from hub_plugin_installs where plugin_id = $1",
            "delete from hub_plugin_versions where plugin_id = $1",
            "delete from hub_plugins where id = $1",
        ] {
            sqlx::query(sql)
                .bind(plugin_id)
                .execute(&st.db)
                .await
                .map_err(crate::error::db)?;
        }
    }
    // If the user uploaded versions of other plugins: break the reference (do not delete others' versions, and do not let the FK block user deletion)
    sqlx::query("update hub_plugin_versions set uploaded_by = null where uploaded_by = $1")
        .bind(user_id)
        .execute(&st.db)
        .await
        .map_err(crate::error::db)?;

    let deleted = sqlx::query("delete from users where id = $1 and status = 'deleted'")
        .bind(user_id)
        .execute(&st.db)
        .await
        .map_err(crate::error::db)?
        .rows_affected();
    Ok(deleted > 0)
}

/// Scheduling shell for the hard-delete job: acquire `lock:purge-cleanup` (cluster single instance) → run → release; failures only WARN.
async fn purge_cleanup_round(st: &Arc<AppState>) {
    if !st.cfg.compliance.hard_delete_enabled() {
        tracing::debug!(
            "purge hard-delete job skipped: [compliance] purge_hard_delete_days=0 (window disabled)"
        );
        return;
    }
    let owner = format!("{}:purge-cleanup", st.node_id);
    match st.redis.acquire_lock(PURGE_CLEANUP_LOCK, &owner, 900_000).await {
        Ok(true) => {
            match purge_cleanup_once(st).await {
                Ok(s) if s.due == 0 => {
                    tracing::debug!("purge hard-delete round: no due users")
                }
                Ok(s) => tracing::info!(
                    due = s.due,
                    deleted = s.deleted,
                    pending = s.pending,
                    failed = s.failed,
                    "purge hard-delete round done"
                ),
                Err(e) => tracing::warn!(error = %e, "purge hard-delete round failed (retry next round)"),
            }
            let _ = st.redis.release_lock(PURGE_CLEANUP_LOCK, &owner).await;
        }
        Ok(false) => {
            tracing::debug!("purge hard-delete skipped: lock:purge-cleanup held by another node")
        }
        Err(e) => {
            // Redis unavailable: the hard delete is itself idempotent (objects first, rows after), so local execution is safer than "never clean".
            tracing::debug!(
                error = %e,
                "redis lock unavailable; running purge hard-delete locally (idempotent)"
            );
            if let Err(e) = purge_cleanup_once(st).await {
                tracing::warn!(error = %e, "purge hard-delete (local) failed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// REMAINING E04: residual multipart GC (`lock:gc-multipart`)
// ---------------------------------------------------------------------------

/// Max ListMultipartUploads pages per round (server cap 1000 per page; residual uploads are usually far under one page).
pub const MULTIPART_GC_MAX_PAGES: usize = 8;
/// Max Abort failures allowed per round (exceeding it aborts the round; retried next round).
pub const MULTIPART_GC_ERROR_BUDGET: u64 = 10;

/// Buckets taking part in residual multipart GC (stable order for log/metric reconciliation).
///
/// No fixed prefix: ListMultipartUploads lists only **unfinished** uploads (no object scan, independent of object count),
/// so a whole-bucket scan cannot miss residue from third-party clients under any prefix; `S3::list_multipart_uploads` still keeps
/// the prefix parameter for troubleshooting/E2E. Empty bucket names are skipped.
pub fn multipart_gc_buckets(cfg: &crate::config::S3Cfg) -> Vec<String> {
    let mut out = Vec::new();
    for b in [
        &cfg.bucket_large,
        &cfg.bucket_media,
        &cfg.bucket_cold,
        &cfg.bucket_plugins,
    ] {
        let b = b.trim();
        if !b.is_empty() && !out.iter().any(|x: &String| x == b) {
            out.push(b.to_string());
        }
    }
    out
}

/// Whether an unfinished multipart's `Initiated` (RFC3339 from S3, e.g.
/// `2026-11-22T03:40:25.000Z`) exceeds the age threshold.
///
/// Returns `None` = time parse failure (the caller **does not abort**, counts an error, and retries next round; "cannot understand"
/// must never become "too old" and abort someone's live upload). Future times (clock skew) count as not aged.
pub fn multipart_upload_aged(
    initiated: &str,
    max_age: Duration,
    now: DateTime<Utc>,
) -> Option<bool> {
    let t = DateTime::parse_from_rfc3339(initiated.trim())
        .ok()?
        .with_timezone(&Utc);
    Some(match now.signed_duration_since(t).to_std() {
        Ok(age) => age > max_age,
        Err(_) => false,
    })
}

/// Result of one residual multipart GC round.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct MultipartGcSummary {
    pub enabled: bool,
    /// Buckets scanned this round.
    pub buckets: u64,
    /// Total unfinished uploads returned by ListMultipartUploads (including not-yet-aged ones).
    pub scanned_uploads: u64,
    /// Uploads past the age threshold that should be aborted.
    pub aged_uploads: u64,
    /// Successful aborts (including idempotent 404).
    pub aborted: u64,
    /// List/abort failure count (a list failure counts 1 per bucket).
    pub errors: u64,
}

/// Run one residual multipart GC round.
///
/// Semantics (in the implementation and in the report):
/// - **Abort only unfinished uploads**: data comes from S3 ListMultipartUploads; completed objects are simply not in that list,
///   so "never delete completed objects" is guaranteed by the protocol, not guessed from prefixes/ages;
/// - **Abort only when aged**: `multipart_gc_hours` (default 24h, fractions allowed for E2E);
/// - **Unparsable Initiated is never aborted** (counted as an error, retried next round);
/// - Failures are bounded by `MULTIPART_GC_ERROR_BUDGET`, only WARN + metrics, never affecting node ready/forwarding.
pub async fn gc_multipart_once(
    st: &Arc<AppState>,
) -> crate::error::Result<MultipartGcSummary> {
    let mut summary = MultipartGcSummary::default();
    if !st.cfg.maintenance.multipart_gc_enabled() {
        return Ok(summary);
    }
    summary.enabled = true;
    let buckets = multipart_gc_buckets(&st.cfg.s3);
    summary.buckets = buckets.len() as u64;
    // MinIO unavailable → pause this round (② §4.8): no per-bucket connection failure waits; recovery lets the next round continue.
    if s3_maintenance_paused(st, "multipart-gc").await {
        return Ok(summary);
    }
    let max_age = st.cfg.maintenance.effective_multipart_gc_age();
    let now = Utc::now();
    for bucket in buckets {
        let uploads = match st
            .s3
            .list_multipart_uploads(&bucket, None, MULTIPART_GC_MAX_PAGES)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                summary.errors += 1;
                tracing::warn!(
                    error = %e,
                    bucket = %bucket,
                    "multipart gc: list multipart uploads failed (retry next round)"
                );
                continue;
            }
        };
        for up in uploads {
            summary.scanned_uploads += 1;
            match multipart_upload_aged(&up.initiated, max_age, now) {
                Some(false) => continue, // not aged: keep it (may be a live upload)
                None => {
                    summary.errors += 1;
                    st.metrics
                        .multipart_gc_total
                        .with_label_values(&["error"])
                        .inc();
                    tracing::warn!(
                        bucket = %bucket,
                        key = %up.key,
                        upload_id = %up.upload_id,
                        initiated = %up.initiated,
                        "multipart gc: unparsable Initiated; skip abort (retry next round)"
                    );
                    continue;
                }
                Some(true) => summary.aged_uploads += 1,
            }
            match st
                .s3
                .abort_multipart_upload(&bucket, &up.key, &up.upload_id)
                .await
            {
                Ok(()) => {
                    summary.aborted += 1;
                    st.metrics
                        .multipart_gc_total
                        .with_label_values(&["aborted"])
                        .inc();
                    tracing::info!(
                        bucket = %bucket,
                        key = %up.key,
                        upload_id = %up.upload_id,
                        initiated = %up.initiated,
                        "multipart gc: aborted stale incomplete upload"
                    );
                }
                Err(e) => {
                    summary.errors += 1;
                    st.metrics
                        .multipart_gc_total
                        .with_label_values(&["error"])
                        .inc();
                    tracing::warn!(
                        error = %e,
                        bucket = %bucket,
                        key = %up.key,
                        upload_id = %up.upload_id,
                        "multipart gc: abort failed (retry next round)"
                    );
                    if summary.errors >= MULTIPART_GC_ERROR_BUDGET {
                        tracing::warn!(
                            errors = summary.errors,
                            "multipart gc: error budget exhausted; remaining uploads deferred"
                        );
                        break;
                    }
                }
            }
        }
        if summary.errors >= MULTIPART_GC_ERROR_BUDGET {
            break;
        }
    }
    st.metrics.multipart_gc_uploads.set(summary.scanned_uploads as i64);
    if summary.aborted == 0 {
        st.metrics
            .multipart_gc_total
            .with_label_values(&["skipped"])
            .inc();
    }
    Ok(summary)
}

/// Scheduling shell for residual multipart GC: acquire `lock:gc-multipart` → run → release; failures only WARN.
async fn gc_multipart_round(st: &Arc<AppState>) {
    if !st.cfg.maintenance.multipart_gc_enabled() {
        tracing::debug!(
            "multipart gc skipped: [maintenance] multipart_gc_hours<=0 (disabled)"
        );
        return;
    }
    let owner = format!("{}:gc-multipart", st.node_id);
    let task = lattice_core::keys::tasks::GC_MULTIPART;
    match st.redis.acquire_lock(task, &owner, 600_000).await {
        Ok(true) => {
            match gc_multipart_once(st).await {
                Ok(s) if s.scanned_uploads == 0 => {
                    tracing::debug!("multipart gc round: no incomplete uploads")
                }
                Ok(s) => tracing::info!(
                    buckets = s.buckets,
                    scanned = s.scanned_uploads,
                    aged = s.aged_uploads,
                    aborted = s.aborted,
                    errors = s.errors,
                    "multipart gc round done"
                ),
                Err(e) => tracing::warn!(error = %e, "multipart gc round failed (retry next round)"),
            }
            let _ = st.redis.release_lock(task, &owner).await;
        }
        Ok(false) => {
            tracing::debug!("multipart gc skipped: lock:gc-multipart held by another node")
        }
        Err(e) => {
            // Redis unavailable: abort is idempotent (404 counts as cleaned), so local execution is safer than "never reclaim".
            tracing::debug!(
                error = %e,
                "redis lock unavailable; running multipart gc locally (idempotent)"
            );
            if let Err(e) = gc_multipart_once(st).await {
                tracing::warn!(error = %e, "multipart gc (local) failed");
            }
        }
    }
}


// ---------------------------------------------------------------------------
// REMAINING E01: cold archiving (`lock:archive`) and cold-bucket orphan object GC (`lock:gc-objects`)
// ---------------------------------------------------------------------------

/// Cold archive job lock TTL (30 minutes): a round handles at most 2 whole partitions + 4 row batches, normally far below that;
/// if a node is SIGKILLed the lock expires naturally and the next round (startup catch-up after restart) continues (deterministic object keys → idempotent overwrite).
pub const ARCHIVE_LOCK_TTL_MS: u64 = 1_800_000;
/// Orphan object GC job lock TTL (10 minutes).
pub const OBJECT_GC_LOCK_TTL_MS: u64 = 600_000;

/// Scheduling shell for one cold archive round: acquire `lock:archive` → run → release; failures only WARN.
///
/// **No local multi-node fallback when Redis is unavailable**: `DETACH`/row deletion are not idempotent "running twice is harmless" operations
/// (two nodes could export the same partition and delete the same rows; the latter would fail and roll back, but it wastes object storage and
/// breaks lock semantics); `lock:dedup-clean` serialization also depends on this lock. The next round continues after Redis recovers.
async fn archive_round(st: &Arc<AppState>) {
    let owner = format!("{}:archive", st.node_id);
    match st
        .redis
        .acquire_lock(
            crate::maintenance::archive::ARCHIVE_LOCK,
            &owner,
            ARCHIVE_LOCK_TTL_MS,
        )
        .await
    {
        Ok(true) => {
            match crate::maintenance::archive::archive_round_once(st).await {
                Ok(s) if s.paused => {
                    tracing::debug!("archive round paused: s3 unavailable")
                }
                Ok(s) => {
                    tracing::info!(
                        partitions_seen = s.partitions_seen,
                        partitions_archived = s.partitions_archived,
                        partitions_failed = s.partitions_failed,
                        rows_archived = s.rows_archived,
                        dedup_rows = s.dedup_rows_exported,
                        objects = s.objects_uploaded,
                        errors = s.errors,
                        "archive round done"
                    );
                    // Audit trail: partition DETACH is an admin action that removes data from the online table (⑥ §2.5 step 5
                    // requires an audit before DROP after the observation window; here we record DETACH itself).
                    for name in &s.detached_partitions {
                        let _ = crate::routing::audit::audit_emit(
                            st,
                            Some("system:archive"),
                            "archive.detach",
                            Some(name),
                            &json!({
                                "reason": "storage lifecycle archive (lock:archive)",
                                "cutoff_days": s.cutoff_days,
                                "rows_archived": s.rows_archived,
                                "bucket": st.cfg.maintenance.effective_archive_bucket(&st.cfg.s3),
                                "note": "partition kept detached for observation (not dropped)",
                            }),
                            None,
                        )
                        .await;
                    }
                }
                Err(e) => {
                    st.metrics
                        .archive_rounds_total
                        .with_label_values(&["error"])
                        .inc();
                    tracing::warn!(error = %e, "archive round failed (retry next round)");
                }
            }
            let _ = st
                .redis
                .release_lock(crate::maintenance::archive::ARCHIVE_LOCK, &owner)
                .await;
        }
        Ok(false) => tracing::debug!("archive skipped: lock:archive held by another node"),
        Err(e) => tracing::warn!(
            error = %e,
            "redis lock unavailable; archive round skipped (multi-node DETACH must stay single-instance)"
        ),
    }
}

/// Scheduling shell for one orphan object GC round: acquire `lock:gc-objects` → run → release; failures only WARN.
async fn object_gc_round(st: &Arc<AppState>) {
    let owner = format!("{}:gc-objects", st.node_id);
    match st
        .redis
        .acquire_lock(
            crate::maintenance::archive::OBJECT_GC_LOCK,
            &owner,
            OBJECT_GC_LOCK_TTL_MS,
        )
        .await
    {
        Ok(true) => {
            match crate::maintenance::archive::object_gc_round_once(st).await {
                Ok(s) if s.paused => {
                    tracing::debug!("object gc round paused: s3 unavailable")
                }
                Ok(s) => tracing::info!(
                    scanned = s.scanned,
                    deleted = s.deleted,
                    referenced = s.referenced,
                    protected = s.protected,
                    errors = s.errors,
                    "object gc round done"
                ),
                Err(e) => tracing::warn!(error = %e, "object gc round failed (retry next round)"),
            }
            let _ = st
                .redis
                .release_lock(crate::maintenance::archive::OBJECT_GC_LOCK, &owner)
                .await;
        }
        Ok(false) => tracing::debug!("object gc skipped: lock:gc-objects held by another node"),
        Err(e) => {
            // Deletion cannot be rolled back: when Redis is unavailable, skip GC (delete next round) rather than delete concurrently on several nodes.
            tracing::warn!(error = %e, "redis lock unavailable; object gc round skipped")
        }
    }
}

///
/// previous key expiry cleanup (idempotent; safe to call repeatedly from the periodic job).
///
/// A lock-free fast check avoids acquiring an async lock every tick; when truly expired, serialize with rotate (`key_rotate_lock`),
/// then double-check, delete the file/write metadata on a blocking thread, and finally swap in the new snapshot.
/// Returns `true` when an old key was actually removed this time.
pub async fn prune_jwt_previous(st: &Arc<AppState>) -> crate::error::Result<bool> {
    if !st.jwt_keys().previous_expired() {
        return Ok(false);
    }
    let _guard = st.key_rotate_lock.lock().await;
    let keys = st.jwt_keys();
    if !keys.previous_expired() {
        return Ok(false);
    }
    let new = tokio::task::spawn_blocking(move || keys.prune_previous())
        .await
        .map_err(|e| crate::error::internal(format!("jwt key prune task failed: {e}")))??;
    match new {
        Some(k) => {
            st.install_jwt_keys(k);
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Result of replaying one WAL record (pure logic; unit tests cover the "clear only when all succeed / retain on partial failure" rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayItem {
    /// Backfill succeeded
    Ok,
    /// Cold-layer unique constraint hit: already backfilled (retry/crash recovery), equivalent to success
    Duplicate,
    /// Unrecoverable (constraint/FK style 4xx, e.g. session deleted) → drop the record to avoid poisoning the WAL
    Poison,
    /// PG still unavailable (connection/timeout) → abort this round, keep the record for retry
    Transient,
}

/// Wrap-up action after one replay round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayAction {
    /// All processed (success/duplicate/poison) → clear the WAL (dedup prevents equivalent duplicate writes)
    ClearAll,
    /// Transient failure with no earlier poison → keep the whole file (retry the round; dedup makes written records idempotent)
    RetainAll,
    /// Transient failure with an earlier poison → keep records from index `index` on (drop poison)
    RetainFrom(usize),
}

/// Decide the WAL wrap-up action (no disk/DB access).
pub fn replay_action(results: &[ReplayItem]) -> ReplayAction {
    match results
        .iter()
        .position(|r| matches!(r, ReplayItem::Transient))
    {
        None => ReplayAction::ClearAll,
        Some(i) => {
            if results[..i].contains(&ReplayItem::Poison) {
                ReplayAction::RetainFrom(i)
            } else {
                ReplayAction::RetainAll
            }
        }
    }
}

/// One local WAL replay round (② §4.8): idempotent backfill via `insert_message` per record.
///
/// Semantics (in the implementation and in the report):
/// - **Persistence only**: no re-routing, no re-sending business receipts. Degraded acceptance already handled routing/receipts on the online path
///   (or put offline targets into pending); replaying would deliver twice.
/// - **Idempotent**: relies on the `message_dedup` unique constraint; retrying the whole round after a mid-way crash yields only duplicates.
/// - **Clear only when all succeed**: transient failures retain the file (retry next round); permanent failures (poison) are dropped and counted,
///   otherwise one bad record would block the WAL forever.
/// - Multi-node mutex via `lock:wal-replay`; when Redis is unavailable it degrades to an in-process lock (the WAL is a node-local file).
pub async fn replay_wal_once(st: &Arc<AppState>) -> crate::error::Result<()> {
    if !st.cfg.wal.enabled {
        return Ok(());
    }
    // In-process reentrancy: the startup catch-up and the periodic job may overlap.
    let Ok(_local_guard) = st.wal_replay_lock.try_lock() else {
        return Ok(());
    };
    st.metrics.wal_size_bytes.set(st.wal.size_bytes() as i64);
    let records = st.wal.read_all()?;
    if records.is_empty() {
        // With no pending records, probe health meanwhile: PG recovered → clear the local circuit-breaker window (otherwise the message plane keeps taking the degraded path).
        if st.pg_degraded() && pg::probe(&st.db).await.is_ok() {
            st.mark_pg_up();
            tracing::info!("pg reachable again (wal replay probe); degrade window cleared");
        }
        return Ok(());
    }

    let owner = format!("{}:wal-replay", st.node_id);
    let mut redis_locked = false;
    match st.redis.acquire_lock("wal-replay", &owner, 30_000).await {
        Ok(true) => redis_locked = true,
        Ok(false) => {
            tracing::debug!("wal replay skipped: lock:wal-replay is held elsewhere");
            return Ok(());
        }
        Err(e) => {
            tracing::debug!(error = %e, "redis lock unavailable; replaying node-local wal under in-process lock");
        }
    }

    let mut results: Vec<ReplayItem> = Vec::with_capacity(records.len());
    for rec in records.iter() {
        if rec.seq <= 0 {
            // Old-format/corrupt record (missing seq) cannot be backfilled: count poison and drop it; it must not block the queue.
            results.push(ReplayItem::Poison);
            st.metrics.wal_replay_total.with_label_values(&["poison"]).inc();
            tracing::error!(id = %rec.id, "wal replay: record has no seq, dropping (poison)");
            continue;
        }
        let Some(payload) = lattice_core::envelope::base64_decode(&rec.payload_b64) else {
            results.push(ReplayItem::Poison);
            st.metrics.wal_replay_total.with_label_values(&["poison"]).inc();
            tracing::error!(id = %rec.id, "wal replay: payload_b64 decode failed, dropping (poison)");
            continue;
        };
        let created_at = Utc
            .timestamp_millis_opt(rec.recorded_at_ms as i64)
            .single()
            .unwrap_or_else(Utc::now);
        let expires_at = rec
            .expires_at_ms
            .and_then(|ms| Utc.timestamp_millis_opt(ms as i64).single());
        let new = pg::NewMessage {
            id: &rec.id,
            conv_id: &rec.conv_id,
            sender: &rec.sender,
            env_type: &rec.env_type,
            content_type: rec.content_type.as_deref(),
            size: rec.size,
            chunk_total: 1,
            payload: Some(payload),
            payload_ref: None,
            seq: rec.seq,
            expires_at,
        };
        match pg::insert_message_at(&st.db, new, created_at).await {
            Ok(o) if o.duplicate => {
                results.push(ReplayItem::Duplicate);
                st.metrics.wal_replay_total.with_label_values(&["duplicate"]).inc();
            }
            Ok(_) => {
                results.push(ReplayItem::Ok);
                st.metrics.wal_replay_total.with_label_values(&["ok"]).inc();
            }
            Err(e) if pg::is_unavailable_err(&e) => {
                st.mark_pg_down();
                results.push(ReplayItem::Transient);
                st.metrics.wal_replay_total.with_label_values(&["error"]).inc();
                tracing::warn!(error = %e, id = %rec.id, "wal replay deferred: pg still unavailable");
                break;
            }
            Err(e) => {
                results.push(ReplayItem::Poison);
                st.metrics.wal_replay_total.with_label_values(&["poison"]).inc();
                tracing::error!(error = %e, id = %rec.id, "wal replay: permanent failure, dropping record");
            }
        }
    }

    let action = replay_action(&results);
    match action {
        ReplayAction::ClearAll => {
            st.wal.clear()?;
            st.metrics.wal_size_bytes.set(0);
            let ok = results.iter().filter(|r| matches!(r, ReplayItem::Ok)).count();
            let dup = results.iter().filter(|r| matches!(r, ReplayItem::Duplicate)).count();
            let poison = results.iter().filter(|r| matches!(r, ReplayItem::Poison)).count();
            st.mark_pg_up();
            tracing::info!(replayed = ok, duplicate = dup, poison, "wal replay complete; wal cleared");
        }
        ReplayAction::RetainAll => {
            st.metrics.wal_size_bytes.set(st.wal.size_bytes() as i64);
            tracing::warn!(
                records = records.len(),
                "wal replay incomplete (pg unavailable); records retained for next round"
            );
        }
        ReplayAction::RetainFrom(idx) => {
            st.wal.replace(&records[idx..])?;
            st.metrics.wal_size_bytes.set(st.wal.size_bytes() as i64);
            tracing::warn!(
                retained = records.len() - idx,
                "wal replay partially complete; poison dropped, pending retained for next round"
            );
        }
    }

    if redis_locked {
        let _ = st.redis.release_lock("wal-replay", &owner).await;
    }
    Ok(())
}

async fn run(st: &Arc<AppState>, name: &str) -> crate::error::Result<()> {
    match name {
        "chunk-clean" => {
            let n = pg::clean_chunks(&st.db, 1000).await?;
            if n > 0 {
                tracing::info!(removed = n, "chunk_clean");
            }
        }
        "pending-clean" => {
            // pending TTL: message-level expiry is driven by messages.expires_at; also delete the matching Redis
            // pending ZSET entries in a targeted way (E17-D2), so expired entries for long-offline users do not linger.
            let expired = pg::expire_messages(&st.db, 1000).await?;
            let mut removed = 0u64;
            for msg_id in &expired {
                let targets = pg::expire_delivery_targets(&st.db, msg_id).await?;
                for (user, device) in targets {
                    let key = if device == "*" {
                        lattice_core::keys::pending_user(&user)
                    } else {
                        lattice_core::keys::pending_device(&user, &device)
                    };
                    if st.redis.pending_remove(&key, msg_id).await.is_ok() {
                        removed += 1;
                    }
                }
            }
            if !expired.is_empty() {
                tracing::info!(count = expired.len(), pending_removed = removed, "messages expired");
            }
        }
        "dedup-clean" => {
            // Serialized with `lock:archive` (⑥ §6.3 P7): while archiving is exporting dedup records for some time range,
            // the cleanup job must not delete those records first, or messages in the cold archive could be re-ingested because dedup records are missing.
            // Approach: dedup-clean acquires the same `lock:archive` first; if it cannot (archive is running) it skips this round,
            // and cleans up next round (default 1h later). When Redis is unavailable, archiving itself also skips (multi-node DETACH
            // is not degraded locally), so we conservatively skip too, avoiding racing archiving inside the "lock unavailable window".
            let owner = format!("{}:dedup-clean", st.node_id);
            match st
                .redis
                .acquire_lock(crate::maintenance::archive::ARCHIVE_LOCK, &owner, 120_000)
                .await
            {
                Ok(true) => {
                    let n = pg::clean_dedup(&st.db, 1000).await?;
                    if n > 0 {
                        tracing::info!(removed = n, "dedup_clean");
                    }
                    let _ = st
                        .redis
                        .release_lock(crate::maintenance::archive::ARCHIVE_LOCK, &owner)
                        .await;
                }
                Ok(false) => tracing::debug!(
                    "dedup-clean skipped: lock:archive held by archive round (serialized, ⑥ §6.3 P7)"
                ),
                Err(e) => tracing::warn!(
                    error = %e,
                    "dedup-clean skipped: archive lock unavailable (keep dedup records for archive safety)"
                ),
            }
        }
        "seq-watermark" | "seq-flush-30s" => {
            let n = pg::flush_seq_watermarks(&st.db).await?;
            tracing::debug!(updated = n, "seq watermark flushed");
        }
        "reconcile" => {
            // Backfill pending from delivery_log(state ∈ {persisted, routed}) (⑥ §3.4/§6.4)
            let rows = pg::reconcile_candidates(&st.db, 500).await?;
            let mut rebuilt = 0;
            for row in rows {
                let key = if row.to_device == "*" {
                    lattice_core::keys::pending_user(&row.to_user)
                } else {
                    lattice_core::keys::pending_device(&row.to_user, &row.to_device)
                };
                if let Ok(Some(msg)) = pg::message_by_id(&st.db, &row.msg_id).await {
                    if st.redis.pending_add(&key, msg.seq, &row.msg_id).await.is_ok() {
                        rebuilt += 1;
                    }
                }
            }
            if rebuilt > 0 {
                tracing::warn!(rebuilt, "pending reconcile rebuilt entries");
            }
        }
        "reconcile-seq" => {
            let conflicts = pg::reconcile_seq_conflicts(&st.db).await?;
            if conflicts > 0 {
                // P2 alert; do not auto-fix (⑥ §6.4)
                tracing::error!(conflicts, "seq uniqueness violation detected");
            }
        }
        "snapshot" => {
            let online = st.hub.len() as f64;
            pg::insert_snapshot(&st.db, "cluster", "connections", &json!({ "node": st.node_id }), online)
                .await?;
            let pending = st
                .redis
                .pending_len(&lattice_core::keys::pending_user(&st.node_id))
                .await
                .unwrap_or(0) as f64;
            pg::insert_snapshot(&st.db, "queue", "pending_depth", &json!({ "scope": "user" }), pending)
                .await?;
            st.metrics.wal_size_bytes.set(st.wal.size_bytes() as i64);
        }
        "partition-maint" => {
            let created = pg::maintain_partitions(&st.db).await?;
            tracing::info!(created, "partition maintenance done");
        }
        // Plugin hub: pending drafts past the deadline become removed (the object does not exist yet, so no object delete is needed)
        "hub-draft-clean" => {
            let n = pg::hub_expire_drafts(&st.db, 500).await?;
            if n > 0 {
                tracing::info!(expired = n, "hub drafts expired");
            }
        }
        // Plugin hub: objects of removed versions are deleted after 30 days, then the rows are cleaned
        "hub-object-gc" => {
            // MinIO unavailable → pause this round's object GC (② §4.8); the next round continues after recovery.
            if s3_maintenance_paused(st, "hub-object-gc").await {
                return Ok(());
            }
            let rows = pg::hub_removed_versions_to_gc(&st.db, 30, 500).await?;
            let bucket = st.s3.cfg().bucket_plugins.clone();
            for (id, key, source_key) in rows {
                // Package and source package are two objects: any delete failure keeps the version row, retried next round
                // (deleting the row first would orphan the object as forever-unlocatable garbage).
                let package_ok = match st.s3.delete_object(&bucket, &key).await {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::warn!(error = %e, key = %key, "hub package object delete failed");
                        false
                    }
                };
                let source_ok = match source_key.as_deref() {
                    Some(sk) => match st.s3.delete_object(&bucket, sk).await {
                        Ok(()) => true,
                        Err(e) => {
                            tracing::warn!(error = %e, key = sk, "hub source object delete failed");
                            false
                        }
                    },
                    None => true,
                };
                if package_ok && source_ok {
                    if let Err(e) = pg::hub_delete_version(&st.db, &id).await {
                        tracing::warn!(error = %e, version_id = %id, "hub version row delete failed");
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_lifecycle_jobs_use_documented_locks_and_stay_out_of_generic_jobs() {
        // E01: lock names must match ⑥ §2.5/§4.1 and lattice_core::keys::tasks verbatim.
        assert_eq!(
            crate::maintenance::archive::ARCHIVE_LOCK,
            lattice_core::keys::tasks::ARCHIVE
        );
        assert_eq!(
            crate::maintenance::archive::OBJECT_GC_LOCK,
            lattice_core::keys::tasks::GC_OBJECTS
        );
        assert_eq!(crate::maintenance::archive::ARCHIVE_LOCK, "archive");
        assert_eq!(crate::maintenance::archive::OBJECT_GC_LOCK, "gc-objects");
        // archive / gc-objects are scheduled by dedicated jobs (configurable cycle + staggered start + separate switch),
        // so they must not also appear in the generic JOBS table — otherwise two schedulers would share one lock concurrently.
        assert!(!JOBS
            .iter()
            .any(|j| j.task == crate::maintenance::archive::ARCHIVE_LOCK
                || j.task == crate::maintenance::archive::OBJECT_GC_LOCK));
        // Lock TTL is bounded (expires naturally after a SIGKILL; never held forever).
        assert!(ARCHIVE_LOCK_TTL_MS >= 60_000 && ARCHIVE_LOCK_TTL_MS <= 3_600_000);
        assert!(OBJECT_GC_LOCK_TTL_MS >= 60_000 && OBJECT_GC_LOCK_TTL_MS <= 3_600_000);
    }

    #[test]
    fn job_table_uses_documented_locks() {
        let names: Vec<&str> = JOBS.iter().map(|j| j.task).collect();
        for task in [
            "chunk-clean",
            "pending-clean",
            "dedup-clean",
            "seq-watermark",
            "reconcile",
            "reconcile-seq",
            "snapshot",
            "partition-maint",
            "hub-draft-clean",
            "hub-object-gc",
        ] {
            assert!(names.contains(&task), "missing {task}");
        }
    }

    #[test]
    fn wal_replay_clears_only_when_all_records_done() {
        use ReplayItem::*;
        // All succeeded (including dedup duplicates) → clear
        assert_eq!(replay_action(&[Ok, Duplicate, Ok]), ReplayAction::ClearAll);
        // A single poison (permanent failure) → still clearable after dropping it (otherwise the WAL is poisoned forever)
        assert_eq!(replay_action(&[Poison]), ReplayAction::ClearAll);
        // Transient failure: keep the file, retry the whole round next time (already-written records are idempotent via dedup, no duplicate rows)
        assert_eq!(replay_action(&[Ok, Transient]), ReplayAction::RetainAll);
        assert_eq!(replay_action(&[Transient]), ReplayAction::RetainAll);
        // Transient failure only after poison → compact the file, keeping the unbackfilled records from the transient failure on
        assert_eq!(
            replay_action(&[Ok, Poison, Ok, Transient]),
            ReplayAction::RetainFrom(3)
        );
    }

    #[test]
    fn wal_replay_retry_is_idempotent_by_dedup() {
        // Idempotency: on a whole-round retry, "already backfilled" records hit message_dedup → Duplicate,
        // equivalent to Ok (counted as processed), so the second round can still ClearAll without rewriting the same messages.
        use ReplayItem::*;
        let first_round = [Ok, Transient];
        assert_eq!(replay_action(&first_round), ReplayAction::RetainAll);
        let second_round = [Duplicate, Ok];
        assert_eq!(replay_action(&second_round), ReplayAction::ClearAll);
    }

    /// Media-recording lifecycle GC bounds (PL-13 13.6): cycle/batch/error budget/"0=off" are fixed,
    /// and these constants are also the assertion basis for E2E and operations docs.
    #[test]
    fn media_record_gc_bounds_and_retention_gate() {
        assert_eq!(MEDIA_RECORD_GC_INTERVAL, Duration::from_secs(6 * 3600));
        assert_eq!(MEDIA_RECORD_GC_BATCH_MAX, 1000, "per-round batch must be bounded");
        assert_eq!(MEDIA_RECORD_GC_BATCH_MAX, MEDIA_RECORD_GC_BATCH_MAX.clamp(1, 1000));
        assert!(MEDIA_RECORD_GC_ERROR_BUDGET >= 1);
        // 0 = no reclamation (default); any positive number = enabled (retention semantics come from the SQL created_at cutoff)
        assert!(!media_record_retention_enabled(0));
        assert!(!media_record_retention_enabled(-1));
        assert!(media_record_retention_enabled(1));
        assert!(media_record_retention_enabled(7));
    }

    // ---- E02: purge cascade residual cleanup key layout / bounds ----

    #[test]
    fn purge_redis_key_layout_covers_user_and_device_dimensions() {
        use lattice_core::keys;
        let devices = vec!["dev-1".to_string(), "dev-2".to_string()];
        let keys = purge_explicit_redis_keys("u1", Some("alice"), &devices);
        for expect in [
            keys::conn_user("u1"),
            keys::pending_user("u1"),
            keys::sub("u1"),
            keys::ratelimit("u1"),
            keys::conn_device("u1", "dev-1"),
            keys::conn_device("u1", "dev-2"),
            keys::pending_device("u1", "dev-1"),
            keys::pending_device("u1", "dev-2"),
            keys::ratelimit_mqtt("dev-1"),
            keys::ratelimit_mqtt("dev-2"),
            keys::ratelimit_login("acct:alice"),
        ] {
            assert!(keys.contains(&expect), "missing purge key {expect}");
        }
        // Empty username / empty device list produce no extra keys; other users are not touched
        let bare = purge_explicit_redis_keys("u1", Some("  "), &[]);
        assert_eq!(bare.len(), 4);
        assert!(!bare.iter().any(|k| k.contains("acct:")));
        assert!(!bare.iter().any(|k| k.contains("u2")));
        // Prefixes: two conn layers + three pending sets + MQTT session/WILL (dynamic device/topic subkeys)
        let prefixes = purge_redis_prefixes("u1");
        for expect in [
            "lattice:conn:u1:",
            "lattice:pending:u1:",
            "lattice:mqtt:sess:u1:",
            "lattice:mqtt:will:u1:",
        ] {
            assert!(prefixes.contains(&expect.to_string()), "missing prefix {expect}");
        }
        assert_eq!(purge_progress_key("u1"), "lattice:purge:u1");
    }

    #[test]
    fn purge_progress_phase_transitions_are_bounded() {
        let mut p = PurgeProgress {
            user_id: "u1".into(),
            phase: "queued".into(),
            ..Default::default()
        };
        assert!(!p.complete());
        // No progress yet → still queued (safe to retry)
        assert_eq!(p.phase_if_not_done(), "queued");
        p.messages_deleted = 1;
        assert_eq!(p.phase_if_not_done(), "objects");
        p.phase = "done".into();
        assert!(p.complete());
        assert_eq!(p.phase_if_not_done(), "done");
        // Error budget/batch constant contract (asserted by E2E and operations docs)
        assert!(PURGE_OBJECT_ERROR_BUDGET >= 1);
        assert!(PURGE_CLEANUP_BATCH >= 1 && PURGE_CLEANUP_BATCH <= 1000);
        assert!(PURGE_INLINE_MAX_MESSAGES >= 1);
        assert_eq!(PURGE_CLEANUP_LOCK, "purge-cleanup");
        assert_eq!(PURGE_PROGRESS_TTL_SECS, 30 * 24 * 3_600);
    }

    // ---- E04: residual multipart GC age/bucket/bounds ----

    #[test]
    fn multipart_upload_age_gate() {
        let now = Utc
            .with_ymd_and_hms(2026, 11, 22, 12, 0, 0)
            .single()
            .unwrap();
        let max_age = Duration::from_secs(24 * 3600);
        // Over 24h → should abort
        assert_eq!(
            multipart_upload_aged("2026-11-21T11:59:59.000Z", max_age, now),
            Some(true)
        );
        // Exactly the 24h boundary: not aged (only strictly greater aborts)
        assert_eq!(
            multipart_upload_aged("2026-11-21T12:00:00.000Z", max_age, now),
            Some(false)
        );
        // Fresh upload (may be in flight) → keep
        assert_eq!(
            multipart_upload_aged("2026-11-22T11:59:59.000Z", max_age, now),
            Some(false)
        );
        // Future time (clock skew) → treat as not aged
        assert_eq!(
            multipart_upload_aged("2026-11-22T13:00:00.000Z", max_age, now),
            Some(false)
        );
        // Parse failure → None (the caller must not abort; count an error and retry next round)
        assert_eq!(multipart_upload_aged("not-a-time", max_age, now), None);
        assert_eq!(multipart_upload_aged("", max_age, now), None);
        // E2E tiny threshold: 0.0003h ≈ 1.08s (abort only after >1.08s; a 1s fresh upload is kept)
        let tiny = Duration::from_secs_f64(0.0003 * 3600.0);
        assert_eq!(
            multipart_upload_aged("2026-11-22T11:59:58.000Z", tiny, now),
            Some(true),
            "initiated 2s ago should be aged"
        );
        assert_eq!(
            multipart_upload_aged("2026-11-22T11:59:59.000Z", tiny, now),
            Some(false),
            "initiated 1s ago is under the 1.08s threshold, should be kept"
        );
    }

    #[test]
    fn multipart_gc_targets_and_bounds() {
        let cfg = crate::config::S3Cfg {
            bucket_large: "large".into(),
            bucket_media: "media".into(),
            bucket_cold: "cold".into(),
            bucket_plugins: "plugins".into(),
            ..Default::default()
        };
        assert_eq!(
            multipart_gc_buckets(&cfg),
            vec![
                "large".to_string(),
                "media".to_string(),
                "cold".to_string(),
                "plugins".to_string()
            ]
        );
        // Empty bucket names skipped; duplicate names deduped (never abort the same bucket twice)
        let dup = crate::config::S3Cfg {
            bucket_large: "same".into(),
            bucket_media: " ".into(),
            bucket_cold: "same".into(),
            bucket_plugins: String::new(),
            ..Default::default()
        };
        assert_eq!(multipart_gc_buckets(&dup), vec!["same".to_string()]);
        // Paging/error budget bounded (no infinite paging or long retries against a half-dead object store)
        assert!((1..=100).contains(&MULTIPART_GC_MAX_PAGES));
        assert!(MULTIPART_GC_ERROR_BUDGET >= 1);
    }
}
