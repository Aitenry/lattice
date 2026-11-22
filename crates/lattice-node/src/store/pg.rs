//! PostgreSQL access layer (DDL authority: doc ⑥ §2; this file covers read/write paths only).
//!
//! Conventions:
//! - A single message's `messages` + `message_dedup` go in the **same transaction/single statement** (⑥ §2.1 transaction boundary);
//! - Redis/NATS operations always come after the transaction (avoid holding locks in long transactions);
//! - `messages` is a partitioned table → queries always include a `created_at` range for partition pruning (⑥ §2.4).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};

use crate::error::{db, LatticeError, Result};

pub type Pool = PgPool;

// ---------------------------------------------------------------------------
// Local PG circuit breaker (② §4.8: PG unwritable → hot path fails fast / uses WAL)
// ---------------------------------------------------------------------------

/// Circuit-breaker window: after a determinable unavailability, the message plane skips non-essential PG calls within the window, so each message does not wait
/// for the pool `acquire_timeout` (5s default) and drag down WS/REST receipts; cleared by WAL replay/liveness probe success.
pub const PG_DEGRADE_BACKOFF_MS: u64 = 3_000;

static DEGRADED_UNTIL_MS: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Whether the local PG circuit-breaker window is active ("a determinable unavailability occurred recently", not authoritative health).
pub fn is_degraded() -> bool {
    DEGRADED_UNTIL_MS.load(Ordering::Relaxed) > now_ms()
}

/// Record one determinable PG unavailability (open/extend the circuit-breaker window). Called by the message plane/WAL replay;
/// not set globally in `db_err`, to avoid slow admin queries timing out and harming the message plane.
pub fn note_degraded() {
    DEGRADED_UNTIL_MS.store(now_ms() + PG_DEGRADE_BACKOFF_MS, Ordering::Relaxed);
}

/// PG has recovered (WAL replay/liveness probe/successful write): close the circuit-breaker window.
pub fn note_healthy() {
    DEGRADED_UNTIL_MS.store(0, Ordering::Relaxed);
}

/// Hot-path fast failure during degradation (no pool connection, no 5s acquire wait).
#[inline]
fn degraded_fast_fail() -> Option<LatticeError> {
    is_degraded().then(unavailable_error)
}

// ---------------------------------------------------------------------------
// Determinable error classification (② §4.8 PG unwritable → local WAL degradation)
// ---------------------------------------------------------------------------

/// Whether an error is a determinable "PG unavailable": connection lost/timeout/pool exhaustion/server shutdown/write blocked/resource exhaustion.
///
/// Only these errors may take WAL degradation; constraint (23505/23503 etc.), syntax, type, and other 4xx errors must
/// be reported as-is — swallowing them into the WAL only makes bad messages fail forever on replay (poison).
pub fn is_unavailable(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Io(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed
        | sqlx::Error::Tls(_)
        | sqlx::Error::Protocol(_) => true,
        sqlx::Error::Database(dbe) => {
            let code = dbe.code().map(|c| c.into_owned()).unwrap_or_default();
            matches!(
                code.as_str(),
                // Class 08: connection exception (connection setup/loss/protocol errors)
                "08000" | "08001" | "08003" | "08004" | "08006" | "08007" | "08P01"
                // 57P0x: admin shutdown / crash shutdown / not yet connectable / idle session timeout
                | "57P01" | "57P02" | "57P03" | "57P05"
                // Class 53: resource exhaustion (disk full/out of memory/too many connections)
                | "53100" | "53200" | "53300" | "53400"
                // write blocked / deadlock / serialization failure (retryable)
                | "55P03" | "40P01" | "40001"
                // statement timeout / transaction already failed
                | "57014" | "25P02"
            )
        }
        _ => false,
    }
}

/// `storage unavailable` (`details.reason = pg_unavailable`): the marker for WAL degradation decisions.
pub fn unavailable_error() -> LatticeError {
    crate::error::internal("storage unavailable")
        .with_detail("dep", serde_json::json!("pg"))
        .with_reason("pg_unavailable")
}

/// Whether a [`LatticeError`] carries the `pg_unavailable` marker (i.e. produced by [`db_err`]/[`unavailable_error`]).
pub fn is_unavailable_err(e: &LatticeError) -> bool {
    e.details
        .as_ref()
        .and_then(|d| d.get("reason"))
        .and_then(|r| r.as_str())
        == Some("pg_unavailable")
}

/// sqlx error → [`LatticeError`]; determinable-unavailable errors are tagged `reason=pg_unavailable`.
pub fn db_err(e: sqlx::Error) -> LatticeError {
    if is_unavailable(&e) {
        tracing::error!(error = %e, "pg unavailable");
        unavailable_error()
    } else {
        db(e)
    }
}

/// Lightweight liveness probe (`select 1`): when WAL replay has no pending records, use it to decide whether PG has recovered and clear the local circuit breaker.
pub async fn probe(pool: &Pool) -> Result<()> {
    sqlx::query("select 1").execute(pool).await.map_err(db_err)?;
    note_healthy();
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    /// Avatar (migration 0008; null = unset, the frontend falls back to name initials).
    ///
    /// One of two value shapes (validated by `transport::http::validate_avatar` in the API layer):
    /// an `https://` external link, or an inline `data:image/(png|jpeg|webp|gif);base64,...` (≤256KiB).
    pub avatar: Option<String>,
    pub status: String,
    /// Admin role (⑥ §2.3 `users.role`: admin|ops|viewer) — the sole source of the JWT claim (⑤ §0.2).
    pub role: String,
    pub capabilities: Value,
    pub quota: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Device {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub platform: Option<String>,
    pub token_hash: Option<String>,
    pub fingerprint: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Conversation {
    pub id: String,
    pub kind: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Member {
    pub conv_id: String,
    pub user_id: String,
    pub joined_at: DateTime<Utc>,
    pub role: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Message {
    pub id: String,
    pub conv_id: String,
    pub sender: String,
    pub env_type: String,
    pub content_type: Option<String>,
    pub size: i64,
    pub chunk_total: i32,
    pub payload: Option<Vec<u8>>,
    pub payload_ref: Option<String>,
    pub status: String,
    pub seq: i64,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeliveryRow {
    pub msg_id: String,
    pub to_user: String,
    pub to_device: String,
    pub state: String,
    pub attempts: i32,
    pub last_at: Option<DateTime<Utc>>,
    pub acked_at: Option<DateTime<Utc>>,
    pub node_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChunkRow {
    pub id: String,
    pub msg_id: String,
    /// Owning conversation; older data may be null (written before migration 0011).
    pub conv_id: Option<String>,
    pub total: i32,
    pub idx: i32,
    pub size: i64,
    pub checksum: Option<Vec<u8>>,
    pub storage_key: Option<String>,
    pub uploaded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditRow {
    pub id: i64,
    pub actor: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub detail: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PluginRow {
    pub id: String,
    pub ns: String,
    pub version: i32,
    pub status: String,
    pub canary_ratio: i32,
    pub sidecar_addr: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FormatRow {
    pub id: String,
    pub r#type: String,
    pub mime: Option<String>,
    pub handler: String,
    pub detect_rules: Value,
    pub builtin: bool,
}

/// Conversation list row: `unread` is derived from `read_watermark` and `messages.max(seq)` (⑤ §3).
#[derive(Debug, Clone)]
pub struct ConvSummary {
    pub id: String,
    pub kind: String,
    pub name: Option<String>,
    pub last_seq: i64,
    pub last_msg_at: Option<DateTime<Utc>>,
    pub unread: i64,
    pub members: i64,
}

pub async fn connect(url: &str, pool_size: u32, statement_timeout_ms: u64) -> Result<Pool> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(pool_size.max(2))
        .acquire_timeout(std::time::Duration::from_secs(5))
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                // Must execute one by one: sqlx uses the extended protocol (prepared statements), and PG's
                // "cannot insert multiple commands into a prepared statement"
                // directly rejects multi-command strings like `set a=...; set b=...` — so the pool
                // cannot establish a single connection (observed in E2E).
                sqlx::query(&format!("set statement_timeout = {statement_timeout_ms}"))
                    .execute(&mut *conn)
                    .await?;
                sqlx::query("set idle_in_transaction_session_timeout = 30000")
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .map_err(db)?;
    Ok(pool)
}

/// Migration: `lattice-node/migrations/`, forward only (⑥ §8), run once during deployment (under lock, ② §7.2).
pub async fn migrate(pool: &Pool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await.map_err(|e| {
        tracing::error!(error = %e, "migration failed");
        crate::error::internal(format!("migration failed: {e}"))
    })
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/// Create a user (⑤ §8.2 `POST /v1/admin/users`; role values ⑥ §2.3 `users.role`).
///
/// `role` must be explicit — the `users.role` default `viewer` is only a DDL fallback;
/// silently landing at the lowest privilege when a caller "forgets to pass a role" is harder to diagnose than an error.
pub async fn create_user(
    pool: &Pool,
    username: &str,
    password_hash: &str,
    display_name: Option<&str>,
    role: &str,
) -> Result<User> {
    sqlx::query_as::<_, User>(
        "insert into users (id, username, password_hash, display_name, role)
         values ($1,$2,$3,$4,$5) returning *",
    )
    .bind(lattice_core::ids::new_id())
    .bind(username)
    .bind(password_hash)
    .bind(display_name)
    .bind(role)
    .fetch_one(pool)
    .await
    .map_err(db)
}

/// Total user count (including inactive, excluding `deleted`).
///
/// Used for exactly one purpose: at startup, decide "is this a brand-new database" to allow bootstrap account creation
/// (⑤ §8.2 "first administrator"). **Not** for pagination counts — that is `list_users`' total.
pub async fn count_users(pool: &Pool) -> Result<i64> {
    let row = sqlx::query("select count(*) as c from users where status <> 'deleted'")
        .fetch_one(pool)
        .await
        .map_err(db)?;
    Ok(row.get::<i64, _>("c"))
}

pub async fn user_by_username(pool: &Pool, username: &str) -> Result<Option<User>> {
    sqlx::query_as::<_, User>("select * from users where username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
        .map_err(db)
}

pub async fn user_by_id(pool: &Pool, id: &str) -> Result<Option<User>> {
    sqlx::query_as::<_, User>("select * from users where id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(db)
}

pub async fn update_user(
    pool: &Pool,
    id: &str,
    display_name: Option<&str>,
    capabilities: Option<&Value>,
) -> Result<Option<User>> {
    sqlx::query_as::<_, User>(
        "update users set
            display_name = coalesce($2, display_name),
            capabilities = coalesce($3, capabilities),
            updated_at = now()
         where id = $1 returning *",
    )
    .bind(id)
    .bind(display_name)
    .bind(capabilities)
    .fetch_optional(pool)
    .await
    .map_err(db)
}

/// Update user profile (display name + avatar): self-service (`PATCH /v1/users/me`) and admin
/// (`PATCH /v1/admin/users/{id}`) share one UPDATE, so "both fields in one request"
/// either succeed together or fail together (no half state where only the display name changed).
///
/// Field update semantics use [`Option<Option<&str>>`] to express three states:
/// - outer `None`        = **leave** the field unchanged (omitted in the request);
/// - `Some(None)`       = **clear** the field (empty string in the request);
/// - `Some(Some(v))`    = write the new value.
///
/// Difference from [`update_user`] (internal merge semantics / `coalesce`): this writes explicitly, because
/// "clear display name/remove avatar" is a legitimate operation; identity fields (username/role/status) are deliberately not in
/// this endpoint (⑤ §8.2: role changes have their own endpoint; username is not editable).
pub async fn set_user_profile(
    pool: &Pool,
    id: &str,
    display_name: Option<Option<&str>>,
    avatar: Option<Option<&str>>,
) -> Result<Option<User>> {
    sqlx::query_as::<_, User>(
        "update users set
            display_name = case when $2 then $3::text else display_name end,
            avatar = case when $4 then $5::text else avatar end,
            updated_at = now()
         where id = $1 returning *",
    )
    .bind(id)
    .bind(display_name.is_some())
    .bind(display_name.flatten())
    .bind(avatar.is_some())
    .bind(avatar.flatten())
    .fetch_optional(pool)
    .await
    .map_err(db)
}

pub async fn set_user_status(pool: &Pool, id: &str, status: &str) -> Result<bool> {
    let r = sqlx::query("update users set status = $2, updated_at = now() where id = $1")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(r.rows_affected() > 0)
}

pub async fn set_user_quota(pool: &Pool, id: &str, quota: &Value) -> Result<bool> {
    let r = sqlx::query("update users set quota = $2, updated_at = now() where id = $1")
        .bind(id)
        .bind(quota)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(r.rows_affected() > 0)
}

/// Change admin role (⑤ §8.2 `POST /v1/admin/users/{id}/role`; value source ⑥ §2.3 `users.role`).
pub async fn set_user_role(pool: &Pool, id: &str, role: &str) -> Result<bool> {
    let r = sqlx::query("update users set role = $2, updated_at = now() where id = $1")
        .bind(id)
        .bind(role)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(r.rows_affected() > 0)
}

/// Replace the password hash (shared by admin reset and self-service password change; the caller handles argon2id rehash and audit).
///
/// Only changes `password_hash` (+`updated_at`), never touches `devices`: session revocation is decided explicitly by the caller via
/// [`revoke_user_devices`] (self-service keeps the current device, admin reset revokes all).
pub async fn set_user_password(pool: &Pool, id: &str, password_hash: &str) -> Result<bool> {
    let r = sqlx::query("update users set password_hash = $2, updated_at = now() where id = $1")
        .bind(id)
        .bind(password_hash)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(r.rows_affected() > 0)
}

/// Count active accounts with a given role (protects against "the last admin cannot be demoted", ⑤ §8.2).
pub async fn count_users_by_role(pool: &Pool, role: &str) -> Result<i64> {
    let row = sqlx::query(
        "select count(*) as c from users where role = $1 and status <> 'deleted'",
    )
    .bind(role)
    .fetch_one(pool)
    .await
    .map_err(db)?;
    Ok(row.get::<i64, _>("c"))
}

pub async fn list_users(
    pool: &Pool,
    q: Option<&str>,
    status: Option<&str>,
    page: i64,
    page_size: i64,
) -> Result<(Vec<User>, i64)> {
    let pattern = q.map(|s| format!("%{s}%"));
    let total: i64 = sqlx::query_scalar(
        "select count(*) from users
         where ($1::text is null or username ilike $1 or display_name ilike $1)
           and ($2::text is null or status = $2)",
    )
    .bind(pattern.as_deref())
    .bind(status)
    .fetch_one(pool)
    .await
    .map_err(db)?;

    let rows = sqlx::query_as::<_, User>(
        "select * from users
         where ($1::text is null or username ilike $1 or display_name ilike $1)
           and ($2::text is null or status = $2)
         order by created_at desc limit $3 offset $4",
    )
    .bind(pattern.as_deref())
    .bind(status)
    .bind(page_size)
    .bind((page - 1).max(0) * page_size)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    Ok((rows, total))
}

/// Compliance deletion progress statistics (⑤ §8.2: PG/MinIO/Redis per-item counts).
pub async fn purge_counts(pool: &Pool, user_id: &str) -> Result<serde_json::Value> {
    let messages: i64 = sqlx::query_scalar(
        "select count(*) from messages m
         join conversation_members cm on cm.conv_id = m.conv_id and cm.user_id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(db)?;
    let devices: i64 = sqlx::query_scalar("select count(*) from devices where user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(db)?;
    Ok(serde_json::json!({ "pg_messages": messages, "pg_devices": devices, "minio_objects": 0 }))
}

/// Soft delete → hard delete (the default 7-day window is enforced by a task, ⑤ §8.2).
pub async fn soft_delete_user(pool: &Pool, user_id: &str) -> Result<()> {
    let mut tx = pool.begin().await.map_err(db)?;
    sqlx::query("update users set status = 'deleted', updated_at = now() where id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    sqlx::query("update devices set revoked_at = now() where user_id = $1 and revoked_at is null")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    sqlx::query("delete from read_watermark where user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    sqlx::query("delete from conversation_members where user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)
}

// ---------------------------------------------------------------------------
// Devices and refresh tokens (§17.11: hashes only)
// ---------------------------------------------------------------------------

pub async fn upsert_device(
    pool: &Pool,
    user_id: &str,
    fingerprint: &str,
    name: Option<&str>,
    platform: Option<&str>,
    token_hash: Option<&str>,
) -> Result<Device> {
    // ⑥ §2.3 devices_active_fp_uk: reuse the existing row for the same user+fingerprint, avoiding device table bloat
    sqlx::query_as::<_, Device>(
        "insert into devices (id, user_id, name, platform, token_hash, fingerprint, last_seen)
         values ($1,$2,$3,$4,$5,$6, now())
         on conflict (user_id, fingerprint) where revoked_at is null and fingerprint is not null
         do update set token_hash = coalesce(excluded.token_hash, devices.token_hash),
                       name = coalesce(excluded.name, devices.name),
                       platform = coalesce(excluded.platform, devices.platform),
                       last_seen = now()
         returning *",
    )
    .bind(lattice_core::ids::new_id())
    .bind(user_id)
    .bind(name)
    .bind(platform)
    .bind(token_hash)
    .bind(fingerprint)
    .fetch_one(pool)
    .await
    .map_err(db)
}

pub async fn device_by_token_hash(pool: &Pool, hash: &str) -> Result<Option<Device>> {
    sqlx::query_as::<_, Device>(
        "select * from devices where token_hash = $1 and revoked_at is null",
    )
    .bind(hash)
    .fetch_optional(pool)
    .await
    .map_err(db)
}

pub async fn device_by_id(pool: &Pool, id: &str) -> Result<Option<Device>> {
    sqlx::query_as::<_, Device>("select * from devices where id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(db)
}

pub async fn rotate_device_token(pool: &Pool, id: &str, token_hash: &str) -> Result<bool> {
    let r = sqlx::query(
        "update devices set token_hash = $2, last_seen = now() where id = $1 and revoked_at is null",
    )
    .bind(id)
    .bind(token_hash)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(r.rows_affected() > 0)
}

pub async fn devices_of(pool: &Pool, user_id: &str) -> Result<Vec<Device>> {
    sqlx::query_as::<_, Device>(
        "select * from devices where user_id = $1 order by (revoked_at is null) desc, last_seen desc nulls last",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(db)
}

pub async fn list_devices_admin(
    pool: &Pool,
    user: Option<&str>,
    revoked: Option<bool>,
) -> Result<Vec<Device>> {
    sqlx::query_as::<_, Device>(
        "select * from devices
         where ($1::text is null or user_id = $1)
           and ($2::bool is null or (revoked_at is not null) = $2)
         order by last_seen desc nulls last limit 500",
    )
    .bind(user)
    .bind(revoked)
    .fetch_all(pool)
    .await
    .map_err(db)
}

pub async fn revoke_device(pool: &Pool, id: &str) -> Result<bool> {
    let r = sqlx::query("update devices set revoked_at = now() where id = $1 and revoked_at is null")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(r.rows_affected() > 0)
}

/// Revoke a user's active device sessions (refresh tokens become invalid immediately); returns the number of revoked rows.
///
/// `keep_device` is for self-service password change "keep the current device, kick the others" (⑤ §2 self-service semantics);
/// admin password reset passes `None` = revoke all. Access JWTs are stateless snapshots (TTL 900s, ⑤ §0.2),
/// so this only guarantees the refresh chain cannot be renewed immediately; callers that need "disconnect now" also close online connections.
/// Already revoked historical device rows are not counted again (condition `revoked_at is null`).
pub async fn revoke_user_devices(
    pool: &Pool,
    user_id: &str,
    keep_device: Option<&str>,
) -> Result<i64> {
    let r = sqlx::query(
        "update devices set revoked_at = now()
         where user_id = $1 and revoked_at is null
           and ($2::text is null or id <> $2)",
    )
    .bind(user_id)
    .bind(keep_device)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(r.rows_affected() as i64)
}

pub async fn touch_device(pool: &Pool, id: &str) -> Result<()> {
    sqlx::query("update devices set last_seen = now() where id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Conversations and members
// ---------------------------------------------------------------------------

pub async fn create_conversation(
    pool: &Pool,
    kind: &str,
    name: Option<&str>,
    creator: &str,
    member_ids: &[String],
) -> Result<Conversation> {
    let mut tx = pool.begin().await.map_err(db)?;
    let conv = sqlx::query_as::<_, Conversation>(
        "insert into conversations (id, kind, name) values ($1,$2,$3) returning *",
    )
    .bind(lattice_core::ids::new_id())
    .bind(kind)
    .bind(name)
    .fetch_one(&mut *tx)
    .await
    .map_err(db)?;

    sqlx::query(
        "insert into conversation_members (conv_id, user_id, role) values ($1,$2,'owner')
         on conflict do nothing",
    )
    .bind(&conv.id)
    .bind(creator)
    .execute(&mut *tx)
    .await
    .map_err(db)?;

    for uid in member_ids {
        if uid == creator {
            continue;
        }
        sqlx::query(
            "insert into conversation_members (conv_id, user_id, role) values ($1,$2,'member')
             on conflict do nothing",
        )
        .bind(&conv.id)
        .bind(uid)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    }
    tx.commit().await.map_err(db)?;
    Ok(conv)
}

pub async fn conversation_by_id(pool: &Pool, id: &str) -> Result<Option<Conversation>> {
    if let Some(e) = degraded_fast_fail() {
        return Err(e);
    }
    sqlx::query_as::<_, Conversation>("select * from conversations where id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)
}

/// Reuse the conversation/member tables to represent Topics (⑥ §2.3 D13).
pub async fn ensure_topic(pool: &Pool, topic: &str) -> Result<Conversation> {
    if let Some(c) = sqlx::query_as::<_, Conversation>(
        "select * from conversations where kind = 'topic' and name = $1",
    )
    .bind(topic)
    .fetch_optional(pool)
    .await
    .map_err(db)?
    {
        return Ok(c);
    }
    sqlx::query_as::<_, Conversation>(
        "insert into conversations (id, kind, name) values ($1,'topic',$2)
         on conflict (name) where kind = 'topic' do update set name = excluded.name
         returning *",
    )
    .bind(lattice_core::ids::new_id())
    .bind(topic)
    .fetch_one(pool)
    .await
    .map_err(db)
}

/// DM idempotency: one pair of users can have only one `kind='dm'` conversation (⑤ §3).
pub async fn find_dm(pool: &Pool, a: &str, b: &str) -> Result<Option<Conversation>> {
    sqlx::query_as::<_, Conversation>(
        "select c.* from conversations c
         join conversation_members m1 on m1.conv_id = c.id and m1.user_id = $1
         join conversation_members m2 on m2.conv_id = c.id and m2.user_id = $2
         where c.kind = 'dm'
         order by c.created_at asc limit 1",
    )
    .bind(a)
    .bind(b)
    .fetch_optional(pool)
    .await
    .map_err(db)
}

pub async fn member_role(pool: &Pool, conv: &str, user: &str) -> Result<Option<String>> {
    if let Some(e) = degraded_fast_fail() {
        return Err(e);
    }
    sqlx::query_scalar::<_, String>(
        "select role from conversation_members where conv_id = $1 and user_id = $2",
    )
    .bind(conv)
    .bind(user)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub async fn members_of(pool: &Pool, conv: &str) -> Result<Vec<Member>> {
    if let Some(e) = degraded_fast_fail() {
        return Err(e);
    }
    sqlx::query_as::<_, Member>(
        "select * from conversation_members where conv_id = $1 order by joined_at asc",
    )
    .bind(conv)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

pub async fn add_members(pool: &Pool, conv: &str, ids: &[String]) -> Result<u64> {
    let mut n = 0;
    for uid in ids {
        let r = sqlx::query(
            "insert into conversation_members (conv_id, user_id) values ($1,$2) on conflict do nothing",
        )
        .bind(conv)
        .bind(uid)
        .execute(pool)
        .await
        .map_err(db)?;
        n += r.rows_affected();
    }
    Ok(n)
}

pub async fn remove_member(pool: &Pool, conv: &str, uid: &str) -> Result<bool> {
    let r = sqlx::query("delete from conversation_members where conv_id = $1 and user_id = $2")
        .bind(conv)
        .bind(uid)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(r.rows_affected() > 0)
}

pub async fn rename_conversation(pool: &Pool, conv: &str, name: &str) -> Result<bool> {
    let r = sqlx::query("update conversations set name = $2 where id = $1")
        .bind(conv)
        .bind(name)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(r.rows_affected() > 0)
}

/// Conversations I participate in: `last_seq` = `max(messages.seq)`, `unread` = last_seq − read watermark (⑤ §3).
pub async fn list_conversations(pool: &Pool, user: &str) -> Result<Vec<ConvSummary>> {
    let rows = sqlx::query(
        "select c.id, c.kind, c.name,
                coalesce(mx.max_seq, 0) as last_seq,
                mx.last_at as last_msg_at,
                greatest(coalesce(mx.max_seq,0) - coalesce(rw.read_seq,0), 0) as unread,
                (select count(*) from conversation_members cm2 where cm2.conv_id = c.id) as members
         from conversation_members cm
         join conversations c on c.id = cm.conv_id
         left join lateral (
            select max(seq) as max_seq, max(created_at) as last_at
            from messages m where m.conv_id = c.id and m.created_at >= now() - interval '3 months'
         ) mx on true
         left join lateral (
            select max(last_read_seq) as read_seq from read_watermark r
            where r.conv_id = c.id and r.user_id = $1
         ) rw on true
         where cm.user_id = $1
         order by coalesce(mx.last_at, c.created_at) desc
         limit 200",
    )
    .bind(user)
    .fetch_all(pool)
    .await
    .map_err(db)?;

    Ok(rows
        .into_iter()
        .map(|r| ConvSummary {
            id: r.get("id"),
            kind: r.get("kind"),
            name: r.get("name"),
            last_seq: r.get("last_seq"),
            last_msg_at: r.get("last_msg_at"),
            unread: r.get("unread"),
            members: r.get("members"),
        })
        .collect())
}

pub async fn list_conversations_admin(
    pool: &Pool,
    q: Option<&str>,
    kind: Option<&str>,
    page: i64,
    page_size: i64,
) -> Result<(Vec<ConvSummary>, i64)> {
    let pattern = q.map(|s| format!("%{s}%"));
    let total: i64 = sqlx::query_scalar(
        "select count(*) from conversations
         where ($1::text is null or name ilike $1) and ($2::text is null or kind = $2)",
    )
    .bind(pattern.as_deref())
    .bind(kind)
    .fetch_one(pool)
    .await
    .map_err(db)?;

    let rows = sqlx::query(
        "select c.id, c.kind, c.name,
                coalesce(mx.max_seq, 0) as last_seq, mx.last_at as last_msg_at, 0::bigint as unread,
                (select count(*) from conversation_members cm where cm.conv_id = c.id) as members
         from conversations c
         left join lateral (
            select max(seq) as max_seq, max(created_at) as last_at from messages m where m.conv_id = c.id
         ) mx on true
         where ($1::text is null or c.name ilike $1) and ($2::text is null or c.kind = $2)
         order by c.created_at desc limit $3 offset $4",
    )
    .bind(pattern.as_deref())
    .bind(kind)
    .bind(page_size)
    .bind((page - 1).max(0) * page_size)
    .fetch_all(pool)
    .await
    .map_err(db)?;

    let items = rows
        .into_iter()
        .map(|r| ConvSummary {
            id: r.get("id"),
            kind: r.get("kind"),
            name: r.get("name"),
            last_seq: r.get("last_seq"),
            last_msg_at: r.get("last_msg_at"),
            unread: r.get("unread"),
            members: r.get("members"),
        })
        .collect();
    Ok((items, total))
}

// ---------------------------------------------------------------------------
// Messages (dedup on write; seq is allocated first by the caller, see routing::seq)
// ---------------------------------------------------------------------------

pub struct NewMessage<'a> {
    pub id: &'a str,
    pub conv_id: &'a str,
    pub sender: &'a str,
    pub env_type: &'a str,
    pub content_type: Option<&'a str>,
    pub size: i64,
    pub chunk_total: i32,
    pub payload: Option<Vec<u8>>,
    pub payload_ref: Option<&'a str>,
    pub seq: i64,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy)]
pub struct InsertOutcome {
    /// Hit the `message_dedup` unique constraint = duplicate message (§17.5)
    pub duplicate: bool,
}

/// Single-statement "dedup insert + message write": does not write `messages` on a `message_dedup` conflict.
pub async fn insert_message(pool: &Pool, m: NewMessage<'_>) -> Result<InsertOutcome> {
    insert_message_impl(pool, &m, None).await
}

/// WAL replay only: write with the **original `created_at`** (the partition key preserves the original order, not the replay time as message time).
///
/// Shares one SQL with [`insert_message`]; only falls back to the column default `now()` when `created_at` is null.
pub async fn insert_message_at(
    pool: &Pool,
    m: NewMessage<'_>,
    created_at: DateTime<Utc>,
) -> Result<InsertOutcome> {
    insert_message_impl(pool, &m, Some(created_at)).await
}

async fn insert_message_impl(
    pool: &Pool,
    m: &NewMessage<'_>,
    created_at: Option<DateTime<Utc>>,
) -> Result<InsertOutcome> {
    let row = sqlx::query(
        // Parameters: $1 id, $2 conv_id, $3 sender, $4 env_type, $5 content_type, $6 size,
        // $7 chunk_total, $8 payload, $9 payload_ref, $10 seq, $11 expires_at, $12 created_at.
        // Note both `message_dedup.expires_at` and `messages.expires_at` take $11 (it used to be $3,
        // stuffing sender's text into a timestamptz column, making message sends always 500).
        "with d as (
            insert into message_dedup (id, conv_id, expires_at) values ($1,$2,$11::timestamptz)
            on conflict (id) do nothing
            returning id
         )
         insert into messages (id, conv_id, sender, env_type, content_type, size, chunk_total,
                               payload, payload_ref, status, seq, created_at, expires_at)
         select $1,$2,$3,$4,$5,$6,$7,$8,$9,'persisted',$10,coalesce($12::timestamptz, now()),$11::timestamptz
         from d returning seq",
    )
    .bind(m.id)
    .bind(m.conv_id)
    .bind(m.sender)
    .bind(m.env_type)
    .bind(m.content_type)
    .bind(m.size)
    .bind(m.chunk_total)
    .bind(m.payload.as_deref())
    .bind(m.payload_ref)
    .bind(m.seq)
    .bind(m.expires_at)
    .bind(created_at)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    // Successful write = PG available: clear the message plane's local circuit breaker (replay/normal writes both land here)
    note_healthy();
    Ok(InsertOutcome { duplicate: row.is_none() })
}

/// Fetch a message by id: with a 3-month window for partition pruning (⑥ §2.4 known cost).
pub async fn message_by_id(pool: &Pool, id: &str) -> Result<Option<Message>> {
    if let Some(e) = degraded_fast_fail() {
        return Err(e);
    }
    sqlx::query_as::<_, Message>(
        "select * from messages
         where id = $1 and created_at >= now() - interval '3 months'
         order by created_at desc limit 1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(db)
}

pub async fn message_by_id_in_conv(pool: &Pool, id: &str, conv: &str) -> Result<Option<Message>> {
    if let Some(e) = degraded_fast_fail() {
        return Err(e);
    }
    sqlx::query_as::<_, Message>(
        "select * from messages where id = $1 and conv_id = $2 order by created_at desc limit 1",
    )
    .bind(id)
    .bind(conv)
    .fetch_optional(pool)
    .await
    .map_err(db)
}

/// Batch-fetch message creation times (for the `before_ts` filter of `POST /v1/admin/queue/purge`, ⑤ §8.3).
///
/// pending is a ZSET with score = seq (⑥ §3.1) and carries no timestamp, so PG must be queried.
pub async fn message_times(
    pool: &Pool,
    ids: &[String],
) -> Result<Vec<(String, DateTime<Utc>)>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, (String, DateTime<Utc>)>(
        "select id, created_at from messages
         where id = any($1) and created_at >= now() - interval '3 months'",
    )
    .bind(ids)
    .fetch_all(pool)
    .await
    .map_err(db)
}

/// History pagination (⑤ §0.4): `before_seq`/`after_seq` half-open interval, ordered by `seq desc`.
pub async fn history(
    pool: &Pool,
    conv: &str,
    before_seq: Option<i64>,
    after_seq: Option<i64>,
    limit: i64,
) -> Result<Vec<Message>> {
    sqlx::query_as::<_, Message>(
        "select * from messages
         where conv_id = $1
           and ($2::bigint is null or seq < $2)
           and ($3::bigint is null or seq > $3)
           and created_at >= now() - interval '3 months'
         order by seq desc limit $4",
    )
    .bind(conv)
    .bind(before_seq)
    .bind(after_seq)
    .bind(limit.clamp(1, 200))
    .fetch_all(pool)
    .await
    .map_err(db)
}

pub async fn max_seq(pool: &Pool, conv: &str) -> Result<i64> {
    let v: Option<i64> = sqlx::query_scalar("select max(seq) from messages where conv_id = $1")
        .bind(conv)
        .fetch_one(pool)
        .await
        .map_err(db)?;
    Ok(v.unwrap_or(0))
}

pub async fn search_messages_admin(
    pool: &Pool,
    id: Option<&str>,
    conv: Option<&str>,
    user: Option<&str>,
    state: Option<&str>,
    page: i64,
    page_size: i64,
) -> Result<Vec<Message>> {
    sqlx::query_as::<_, Message>(
        "select distinct m.* from messages m
         left join delivery_log d on d.msg_id = m.id
         where ($1::text is null or m.id = $1)
           and ($2::text is null or m.conv_id = $2)
           and ($3::text is null or m.sender = $3 or d.to_user = $3)
           and ($4::text is null or d.state = $4)
         order by m.created_at desc limit $5 offset $6",
    )
    .bind(id)
    .bind(conv)
    .bind(user)
    .bind(state)
    .bind(page_size)
    .bind((page - 1).max(0) * page_size)
    .fetch_all(pool)
    .await
    .map_err(db)
}

/// Advance the incomplete delivery rows of an expired message to `expired`, returning their targets (to clear Redis pending).
///
/// pending-clean used to change only `messages.status`, leaving Redis ZSET entries for lazy cleanup when the user comes online;
/// long-offline users kept occupying memory (E17-D2). Here the targets are returned, and the job `ZREM`s them directly.
pub async fn expire_delivery_targets(
    pool: &Pool,
    msg_id: &str,
) -> Result<Vec<(String, String)>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "update delivery_log set state = 'expired'
         where msg_id = $1 and state in ('persisted','routed')
         returning to_user, to_device",
    )
    .bind(msg_id)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    Ok(rows)
}

pub async fn expire_messages(pool: &Pool, limit: i64) -> Result<Vec<String>> {
    let ids: Vec<String> = sqlx::query_scalar(
        "update messages set status = 'expired'
         where id in (
            select id from messages
            where expires_at is not null and expires_at < now() and status = 'persisted'
            limit $1
         ) returning id",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    Ok(ids)
}

// ---------------------------------------------------------------------------
// Read watermark (§17.4-4)
// ---------------------------------------------------------------------------

/// Monotonic max: rollback values are ignored (⑤ §3). Returns the watermark after persistence.
pub async fn set_read(pool: &Pool, conv: &str, user: &str, device: &str, seq: i64) -> Result<i64> {
    let clamped = sqlx::query_scalar::<_, i64>(
        "select coalesce(max(seq),0) from messages where conv_id = $1",
    )
    .bind(conv)
    .fetch_one(pool)
    .await
    .map_err(db)?;
    let seq = seq.min(clamped.max(0));

    let v: i64 = sqlx::query_scalar(
        "insert into read_watermark (conv_id, user_id, device_id, last_read_seq)
         values ($1,$2,$3,$4)
         on conflict (conv_id, device_id) do update
           set last_read_seq = greatest(read_watermark.last_read_seq, excluded.last_read_seq),
               updated_at = now()
         returning last_read_seq",
    )
    .bind(conv)
    .bind(user)
    .bind(device)
    .bind(seq)
    .fetch_one(pool)
    .await
    .map_err(db)?;
    Ok(v)
}

pub async fn read_map(pool: &Pool, user: &str) -> Result<HashMap<String, i64>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "select conv_id, max(last_read_seq) from read_watermark where user_id = $1 group by conv_id",
    )
    .bind(user)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    Ok(rows.into_iter().collect())
}

// ---------------------------------------------------------------------------
// Delivery audit (delivery_log)
// ---------------------------------------------------------------------------

pub async fn upsert_delivery(
    pool: &Pool,
    msg_id: &str,
    to_user: &str,
    to_device: &str,
    state: &str,
    node_id: &str,
    attempt: bool,
) -> Result<()> {
    if let Some(e) = degraded_fast_fail() {
        return Err(e);
    }
    sqlx::query(
        "insert into delivery_log (msg_id, to_user, to_device, state, attempts, last_at, node_id, acked_at)
         values ($1,$2,$3,$4,$5, now(), $6, case when $4 = 'acked' then now() else null end)
         on conflict (msg_id, to_user, to_device) do update
           set state = excluded.state,
               attempts = delivery_log.attempts + case when $7 then 1 else 0 end,
               last_at = now(),
               acked_at = coalesce(excluded.acked_at, delivery_log.acked_at),
               node_id = excluded.node_id",
    )
    .bind(msg_id)
    .bind(to_user)
    .bind(to_device)
    .bind(state)
    .bind(if attempt { 1 } else { 0 })
    .bind(node_id)
    .bind(attempt)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

pub async fn delivery_of(pool: &Pool, msg_id: &str) -> Result<Vec<DeliveryRow>> {
    sqlx::query_as::<_, DeliveryRow>(
        "select * from delivery_log where msg_id = $1 order by to_device asc",
    )
    .bind(msg_id)
    .fetch_all(pool)
    .await
    .map_err(db)
}

/// Minimal delivery row for redelivery retransmission/dead-letter decisions (E17: `routing/pending.rs::drain_device`).
///
/// Reads only the target row: device-level queues use the real `to_device`, user-level queues use `'*'` (all-devices-offline placeholder row).
/// `attempts`/`last_at` are existing columns of `delivery_log` (⑥ §2.3); semantics per ② §4.2:
/// "ack → ZREM; timeout → redeliver (backoff 1/2/4/8/16s, max 5 times) → dead letter dlq".
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeliveryRetryRow {
    pub to_device: String,
    pub state: String,
    pub attempts: i32,
    pub last_at: Option<DateTime<Utc>>,
}

pub async fn delivery_retry_row(
    pool: &Pool,
    msg_id: &str,
    to_user: &str,
    to_device: &str,
) -> Result<Option<DeliveryRetryRow>> {
    if let Some(e) = degraded_fast_fail() {
        return Err(e);
    }
    sqlx::query_as::<_, DeliveryRetryRow>(
        "select to_device, state, attempts, last_at from delivery_log
         where msg_id = $1 and to_user = $2 and to_device = $3
         limit 1",
    )
    .bind(msg_id)
    .bind(to_user)
    .bind(to_device)
    .fetch_optional(pool)
    .await
    .map_err(db)
}

/// Reset the retry count after dead-letter replay (E17).
///
/// `admin replay` handles "state: dlq → routed" then `enqueue_user`, but `attempts`
/// still holds the accumulated value from before the dead letter; without resetting, the next `drain_device` immediately decides "limit reached"
/// and flips it back to `dlq`, making replay useless. This resets only rows with `state='routed'` whose `attempts` already reached the threshold;
/// rows in normal delivery are unaffected.
pub async fn reset_delivery_attempts(
    pool: &Pool,
    msg_id: &str,
    to_user: &str,
    threshold: i32,
) -> Result<u64> {
    if let Some(e) = degraded_fast_fail() {
        return Err(e);
    }
    let r = sqlx::query(
        "update delivery_log set attempts = 0
         where msg_id = $1 and to_user = $2 and state = 'routed' and attempts >= $3",
    )
    .bind(msg_id)
    .bind(to_user)
    .bind(threshold)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(r.rows_affected())
}

/// ⑤ §8.3 `GET /v1/admin/dlq`: `delivery_log.state='dlq'`, partial index `delivery_log_dlq_idx`.
pub async fn dlq_list(
    pool: &Pool,
    conv: Option<&str>,
    user: Option<&str>,
    page: i64,
    page_size: i64,
) -> Result<Vec<DeliveryRow>> {
    sqlx::query_as::<_, DeliveryRow>(
        "select d.* from delivery_log d
         left join messages m on m.id = d.msg_id
         where d.state = 'dlq'
           and ($1::text is null or m.conv_id = $1)
           and ($2::text is null or d.to_user = $2)
         order by d.last_at desc nulls last limit $3 offset $4",
    )
    .bind(conv)
    .bind(user)
    .bind(page_size)
    .bind((page - 1).max(0) * page_size)
    .fetch_all(pool)
    .await
    .map_err(db)
}

pub async fn mark_delivery_state(pool: &Pool, msg_id: &str, device: &str, state: &str) -> Result<()> {
    if let Some(e) = degraded_fast_fail() {
        return Err(e);
    }
    sqlx::query(
        "update delivery_log set state = $3,
            acked_at = case when $3 = 'acked' then now() else acked_at end,
            last_at = now()
         where msg_id = $1 and to_device = $2",
    )
    .bind(msg_id)
    .bind(device)
    .bind(state)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Chunk index (§17.2: chunks do not enter messages and do not allocate seq)
// ---------------------------------------------------------------------------

pub async fn upsert_chunk(
    pool: &Pool,
    msg_id: &str,
    conv_id: Option<&str>,
    total: i32,
    idx: i32,
    size: i64,
    checksum: Option<Vec<u8>>,
    storage_key: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "insert into chunks_index (id, msg_id, conv_id, total, idx, size, checksum, storage_key)
         values ($1,$2,$3,$4,$5,$6,$7,$8)
         on conflict (msg_id, idx) do update
           set conv_id = coalesce(excluded.conv_id, chunks_index.conv_id),
               size = excluded.size, checksum = excluded.checksum, storage_key = excluded.storage_key",
    )
    .bind(lattice_core::ids::chunk_id(msg_id, idx as u32))
    .bind(msg_id)
    .bind(conv_id)
    .bind(total)
    .bind(idx)
    .bind(size)
    .bind(checksum)
    .bind(storage_key)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

pub async fn chunks_of(pool: &Pool, msg_id: &str) -> Result<Vec<ChunkRow>> {
    sqlx::query_as::<_, ChunkRow>(
        "select * from chunks_index where msg_id = $1 order by idx asc",
    )
    .bind(msg_id)
    .fetch_all(pool)
    .await
    .map_err(db)
}

/// Delete all in-flight chunk index rows for one logical message (E18: reassembly verification failure → terminal state, no half products).
///
/// Called only by the reassembly path on "overall checksum failure / chunk data lost": after row deletion the client can re-upload
/// with the same chunk ids (the caller also revokes the Redis dedup claims, see `pipeline::chunk`).
pub async fn delete_chunks(pool: &Pool, msg_id: &str) -> Result<u64> {
    let r = sqlx::query("delete from chunks_index where msg_id = $1")
        .bind(msg_id)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(r.rows_affected())
}

/// Clean up chunks not reassembled within 24h (⑥ §2.6 `lock:chunk-clean`).
pub async fn clean_chunks(pool: &Pool, limit: i64) -> Result<u64> {
    let r = sqlx::query(
        "delete from chunks_index where id in (
            select id from chunks_index where uploaded_at < now() - interval '24 hours' limit $1
         )",
    )
    .bind(limit)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(r.rows_affected())
}

// ---------------------------------------------------------------------------
// seq watermark (§6.4: guards against Redis primary/replica rollback)
// ---------------------------------------------------------------------------

pub async fn get_seq_watermark(pool: &Pool, conv: &str) -> Result<i64> {
    if let Some(e) = degraded_fast_fail() {
        return Err(e);
    }
    let v: Option<i64> =
        sqlx::query_scalar("select seq from conv_seq_watermark where conv_id = $1")
            .bind(conv)
            .fetch_optional(pool)
            .await
            .map_err(db)?;
    Ok(v.unwrap_or(0))
}

pub async fn set_seq_watermark(pool: &Pool, conv: &str, seq: i64) -> Result<()> {
    sqlx::query(
        "insert into conv_seq_watermark (conv_id, seq) values ($1,$2)
         on conflict (conv_id) do update set seq = greatest(conv_seq_watermark.seq, excluded.seq),
                                             updated_at = now()",
    )
    .bind(conv)
    .bind(seq)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

/// `lock:seq-watermark` (§6.4 / ⑥ §2.6): backfill the persisted `max(seq)` as the watermark.
///
/// Only processes conversations active within the last day — the watermark guards against Redis rollback, so cold conversations need no refresh every 30s.
pub async fn flush_seq_watermarks(pool: &Pool) -> Result<u64> {
    if let Some(e) = degraded_fast_fail() {
        return Err(e);
    }
    let r = sqlx::query(
        "insert into conv_seq_watermark (conv_id, seq)
         select conv_id, max(seq) from messages
         where created_at >= now() - interval '1 day'
         group by conv_id
         on conflict (conv_id) do update
           set seq = greatest(conv_seq_watermark.seq, excluded.seq), updated_at = now()",
    )
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(r.rows_affected())
}

// ---------------------------------------------------------------------------
// Topic subscriptions and broadcast watermarks (reuse conversations + conversation_members)
// ---------------------------------------------------------------------------

pub async fn subscribe(pool: &Pool, user: &str, topic: &str) -> Result<i64> {
    let conv = ensure_topic(pool, topic).await?;
    sqlx::query(
        "insert into conversation_members (conv_id, user_id, role) values ($1,$2,'member')
         on conflict do nothing",
    )
    .bind(&conv.id)
    .bind(user)
    .execute(pool)
    .await
    .map_err(db)?;
    let n: i64 = sqlx::query_scalar(
        "select count(*) from conversation_members cm join conversations c on c.id = cm.conv_id
         where c.kind = 'topic' and c.name = $1",
    )
    .bind(topic)
    .fetch_one(pool)
    .await
    .map_err(db)?;
    Ok(n)
}

pub async fn unsubscribe(pool: &Pool, user: &str, topic: &str) -> Result<bool> {
    let r = sqlx::query(
        "delete from conversation_members cm
         using conversations c
         where cm.conv_id = c.id and c.kind = 'topic' and c.name = $2 and cm.user_id = $1",
    )
    .bind(user)
    .bind(topic)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(r.rows_affected() > 0)
}

pub async fn subscriptions(pool: &Pool, user: &str) -> Result<Vec<(String, i64, i64)>> {
    let rows = sqlx::query(
        "select c.name,
                coalesce(o.last_offset, 0) as last_offset,
                coalesce((select max(seq) from messages m where m.conv_id = c.id), 0)
                  - coalesce(o.last_offset, 0) as unread
         from conversation_members cm
         join conversations c on c.id = cm.conv_id and c.kind = 'topic'
         left join topic_offsets o on o.topic = c.name and o.user_id = $1
         where cm.user_id = $1
         order by c.name",
    )
    .bind(user)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.get::<Option<String>, _>("name").unwrap_or_default(),
                r.get::<Option<i64>, _>("last_offset").unwrap_or(0),
                r.get::<Option<i64>, _>("unread").unwrap_or(0),
            )
        })
        .collect())
}

pub async fn set_topic_offset(pool: &Pool, user: &str, topic: &str, offset: i64) -> Result<()> {
    sqlx::query(
        "insert into topic_offsets (user_id, topic, last_offset) values ($1,$2,$3)
         on conflict (user_id, topic) do update
           set last_offset = greatest(topic_offsets.last_offset, excluded.last_offset),
               updated_at = now()",
    )
    .bind(user)
    .bind(topic)
    .bind(offset)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

pub async fn topic_subscribers(pool: &Pool, topic: &str) -> Result<Vec<String>> {
    sqlx::query_scalar(
        "select cm.user_id from conversation_members cm
         join conversations c on c.id = cm.conv_id
         where c.kind = 'topic' and c.name = $1",
    )
    .bind(topic)
    .fetch_all(pool)
    .await
    .map_err(db)
}

pub async fn topic_conv_id(pool: &Pool, topic: &str) -> Result<Option<String>> {
    sqlx::query_scalar("select id from conversations where kind = 'topic' and name = $1")
        .bind(topic)
        .fetch_optional(pool)
        .await
        .map_err(db)
}

// ---------------------------------------------------------------------------
// Dynamic config / audit / formats / plugins / time-series snapshots
// ---------------------------------------------------------------------------

pub async fn config_all(pool: &Pool) -> Result<Vec<(String, Value)>> {
    let rows: Vec<(String, Value)> = sqlx::query_as("select key, value from dynamic_config")
        .fetch_all(pool)
        .await
        .map_err(db)?;
    Ok(rows)
}

pub async fn config_set(pool: &Pool, key: &str, value: &Value, by: &str) -> Result<()> {
    sqlx::query(
        "insert into dynamic_config (key, value, updated_by) values ($1,$2,$3)
         on conflict (key) do update set value = excluded.value, updated_at = now(),
                                         updated_by = excluded.updated_by",
    )
    .bind(key)
    .bind(value)
    .bind(by)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

pub async fn audit(
    pool: &Pool,
    actor: Option<&str>,
    action: &str,
    target: Option<&str>,
    detail: &Value,
    ip: Option<&str>,
) -> Result<()> {
    if let Some(e) = degraded_fast_fail() {
        return Err(e);
    }
    sqlx::query(
        "insert into audit_log (actor, action, target, detail, ip)
         values ($1,$2,$3,$4,$5::inet)",
    )
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(detail)
    .bind(ip)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

pub async fn audit_list(
    pool: &Pool,
    actor: Option<&str>,
    action: Option<&str>,
    page: i64,
    page_size: i64,
) -> Result<(Vec<AuditRow>, i64)> {
    let total: i64 = sqlx::query_scalar(
        "select count(*) from audit_log
         where ($1::text is null or actor = $1) and ($2::text is null or action = $2)",
    )
    .bind(actor)
    .bind(action)
    .fetch_one(pool)
    .await
    .map_err(db)?;
    let rows = sqlx::query_as::<_, AuditRow>(
        "select id, actor, action, target, detail, created_at from audit_log
         where ($1::text is null or actor = $1) and ($2::text is null or action = $2)
         order by created_at desc limit $3 offset $4",
    )
    .bind(actor)
    .bind(action)
    .bind(page_size)
    .bind((page - 1).max(0) * page_size)
    .fetch_all(pool)
    .await
    .map_err(db)?;
    Ok((rows, total))
}

pub async fn formats_all(pool: &Pool) -> Result<Vec<FormatRow>> {
    sqlx::query_as::<_, FormatRow>("select * from formats order by type")
        .fetch_all(pool)
        .await
        .map_err(db)
}

pub async fn format_upsert(
    pool: &Pool,
    r#type: &str,
    mime: Option<&str>,
    handler: &str,
    detect_rules: &Value,
) -> Result<FormatRow> {
    sqlx::query_as::<_, FormatRow>(
        "insert into formats (id, type, mime, handler, detect_rules, builtin)
         values ($1,$2,$3,$4,$5,false)
         on conflict (type) do update set mime = excluded.mime, handler = excluded.handler,
                                          detect_rules = excluded.detect_rules
         returning *",
    )
    .bind(lattice_core::ids::new_id())
    .bind(r#type)
    .bind(mime)
    .bind(handler)
    .bind(detect_rules)
    .fetch_one(pool)
    .await
    .map_err(db)
}

pub async fn plugins_all(pool: &Pool) -> Result<Vec<PluginRow>> {
    sqlx::query_as::<_, PluginRow>(
        "select id, ns, version, status, canary_ratio, sidecar_addr, published_at
         from plugins order by ns, version desc",
    )
    .fetch_all(pool)
    .await
    .map_err(db)
}

pub async fn plugin_publish(
    pool: &Pool,
    ns: &str,
    version: i32,
    action: &str,
    ratio: i32,
) -> Result<()> {
    match action {
        "publish" => {
            sqlx::query(
                "update plugins set status = 'active', canary_ratio = 0, published_at = now()
                 where ns = $1 and version = $2",
            )
            .bind(ns)
            .bind(version)
            .execute(pool)
            .await
            .map_err(db)?;
        }
        "rollback" => {
            sqlx::query("update plugins set status = 'rolled_back' where ns = $1 and version = $2")
                .bind(ns)
                .bind(version)
                .execute(pool)
                .await
                .map_err(db)?;
        }
        "canary" => {
            sqlx::query(
                "update plugins set status = 'canary', canary_ratio = $3 where ns = $1 and version = $2",
            )
            .bind(ns)
            .bind(version)
            .bind(ratio.clamp(0, 100))
            .execute(pool)
            .await
            .map_err(db)?;
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WASM plugin registry (read **published/canary** plugin packages from the PG `plugins` table; PL-10 node startup registration)
// ---------------------------------------------------------------------------
//
// Read-only: does not change plugin state/publish semantics. Version selection, signature verification, and directory priority happen in `crate::plugins`;
// this only "selects candidate rows by SQL conditions" (including SQL-level size filtering to avoid huge bytea in memory).

/// A WASM-form candidate package in the `plugins` table (for node `[plugins] from_db=true` startup registration).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PluginWasmRow {
    pub id: String,
    pub ns: String,
    pub version: i32,
    pub status: String,
    /// wasm binary (`plugins.wasm bytea`; SQL already filtered by `max_wasm_bytes`).
    pub wasm: Vec<u8>,
    /// Raw Ed25519 signature (`plugins.signature bytea`; empty bytea = unsigned, rejected fail-closed).
    pub signature: Vec<u8>,
    /// `config` jsonb: `manifest` (preferred full manifest) or `entry/deps/limits/signing_key_id`.
    pub config: Value,
}

/// Metadata for candidate rows exceeding `[plugins] max_wasm_bytes` (**wasm bytes are not read**; used for alerts/metrics only).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PluginWasmOversizeRow {
    pub ns: String,
    pub version: i32,
    pub status: String,
    pub wasm_bytes: i64,
}

/// Read registerable WASM plugin candidate rows (`status in ('active','canary')` and wasm non-empty).
///
/// - `order by ns asc, version desc`: the caller takes the max version per ns (this function does not choose);
/// - SQL-level `octet_length(wasm) <= max_wasm_bytes` pre-filter: oversized objects are not read into memory (OOM protection);
///   oversized rows are listed separately by [`plugin_wasm_oversized`];
/// - Query failure returns Err: **the caller only WARNs**, and must not block node ready.
pub async fn plugin_wasm_candidates(
    pool: &Pool,
    max_wasm_bytes: i64,
) -> Result<Vec<PluginWasmRow>> {
    sqlx::query_as::<_, PluginWasmRow>(
        "select id, ns, version, status, wasm, signature, config
           from plugins
          where wasm is not null
            and status in ('active','canary')
            and octet_length(wasm) <= $1
          order by ns asc, version desc",
    )
    .bind(max_wasm_bytes.max(0))
    .fetch_all(pool)
    .await
    .map_err(db)
}

/// Read candidate rows exceeding `max_wasm_bytes` (only `octet_length`; for rejection counts/troubleshooting).
pub async fn plugin_wasm_oversized(
    pool: &Pool,
    max_wasm_bytes: i64,
) -> Result<Vec<PluginWasmOversizeRow>> {
    sqlx::query_as::<_, PluginWasmOversizeRow>(
        "select ns, version, status, octet_length(wasm)::bigint as wasm_bytes
           from plugins
          where wasm is not null
            and status in ('active','canary')
            and octet_length(wasm) > $1
          order by ns asc, version desc",
    )
    .bind(max_wasm_bytes.max(0))
    .fetch_all(pool)
    .await
    .map_err(db)
}

pub async fn insert_snapshot(
    pool: &Pool,
    scope: &str,
    name: &str,
    labels: &Value,
    value: f64,
) -> Result<()> {
    sqlx::query(
        "insert into metric_snapshot (ts, scope, name, labels, value) values (now(),$1,$2,$3,$4)
         on conflict (ts, scope, name, labels) do update set value = excluded.value",
    )
    .bind(scope)
    .bind(name)
    .bind(labels)
    .bind(value)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

pub async fn snapshot_series(
    pool: &Pool,
    name: &str,
    minutes: i64,
) -> Result<Vec<(DateTime<Utc>, f64)>> {
    let rows: Vec<(DateTime<Utc>, f64)> = sqlx::query_as(
        "select ts, value from metric_snapshot
         where name = $1 and ts >= now() - ($2 || ' minutes')::interval
         order by ts asc limit 1440",
    )
    .bind(name)
    .bind(minutes.to_string())
    .fetch_all(pool)
    .await
    .map_err(db)?;
    Ok(rows)
}

/// Data source for pending rebuild reconciliation (⑥ §6.4 `lock:reconcile`).
pub async fn reconcile_candidates(pool: &Pool, limit: i64) -> Result<Vec<DeliveryRow>> {
    sqlx::query_as::<_, DeliveryRow>(
        "select * from delivery_log
         where state in ('persisted','routed')
           and acked_at is null
           and (last_at is null or last_at < now() - interval '90 seconds')
         order by created_at asc limit $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(db)
}

/// seq uniqueness/watermark reconciliation (⑥ §6.1 IN2/IN7).
pub async fn reconcile_seq_conflicts(pool: &Pool) -> Result<i64> {
    let n: i64 = sqlx::query_scalar(
        "select count(*) from (
            select conv_id, seq from messages
            where created_at >= now() - interval '3 months'
            group by conv_id, seq having count(*) > 1
         ) t",
    )
    .fetch_one(pool)
    .await
    .map_err(db)?;
    Ok(n)
}

pub async fn clean_dedup(pool: &Pool, limit: i64) -> Result<u64> {
    let r = sqlx::query(
        "delete from message_dedup where id in (
            select id from message_dedup where expires_at is not null and expires_at < now() limit $1
         )",
    )
    .bind(limit)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(r.rows_affected())
}

/// Partition pre-creation (⑥ §2.5 `lock:partition-maint`).
///
/// - `messages`: monthly, 3 months ahead;
/// - `metric_snapshot`: **daily**, from 1 day before to 7 days ahead (⑥ §2.2/§2.5/§2.6: online retention 30 days,
///   so the partition span must be shorter than the retention period, otherwise `DROP` cannot drop old partitions), and also drop daily partitions older than retention
///   (trend data outside retention needs no cold archive; long-period data lives in Prometheus).
pub async fn maintain_partitions(pool: &Pool) -> Result<u64> {
    let mut created = 0u64;

    // Boundaries must come directly from SQL (consistent with migrations/0002).
    // Do not reverse-parse from partition names: `substring(x from 'y(\d{4})m(\d{2})')` returns only the **first** capture group,
    // so with the month lost every partition would compute as [January, February) of that year, and creating a new month reports
    // "partition ... would overlap partition ..." (partitions pre-created by the migration are silently skipped due to if not exists,
    // so it only shows up when crossing into a new month).
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "select format('messages_y%sm%s', to_char(m,'YYYY'), to_char(m,'MM')),
                m::text,
                (m + interval '1 month')::date::text
           from (
            select (date_trunc('month', now()) + (i || ' month')::interval)::date as m
            from generate_series(0, 3) as i
         ) s",
    )
    .fetch_all(pool)
    .await
    .map_err(db)?;

    for (part, from, to) in rows {
        let ddl = format!(
            "create table if not exists {part} partition of messages \
             for values from ('{from}') to ('{to}')"
        );
        match sqlx::query(&ddl).execute(pool).await {
            Ok(r) => created += r.rows_affected(),
            Err(e) => tracing::warn!(error = %e, partition = %part, "partition precreate failed"),
        }
    }

    // metric_snapshot: pre-create daily (from 1 day before to 7 days ahead)
    let days: Vec<(String, String, String)> = sqlx::query_as(
        "select format('metric_snapshot_y%sm%sd%s', to_char(d,'YYYY'), to_char(d,'MM'), to_char(d,'DD')),
                d::text, (d + 1)::text
           from (select (current_date + i)::date as d from generate_series(-1, 7) as i) s",
    )
    .fetch_all(pool)
    .await
    .map_err(db)?;
    for (part, from, to) in days {
        let ddl = format!(
            "create table if not exists {part} partition of metric_snapshot \
             for values from ('{from}') to ('{to}')"
        );
        match sqlx::query(&ddl).execute(pool).await {
            Ok(r) => created += r.rows_affected(),
            Err(e) => tracing::warn!(error = %e, partition = %part, "metric partition precreate failed"),
        }
    }

    // metric_snapshot: drop daily partitions older than 30 days (⑥ §2.6, `lock:snapshot`/this task's responsibility)
    let old: Vec<(String,)> = sqlx::query_as(
        "select format('metric_snapshot_y%sm%sd%s', to_char(d,'YYYY'), to_char(d,'MM'), to_char(d,'DD'))
           from (select (current_date - g)::date as d from generate_series(31, 36) as g) s",
    )
    .fetch_all(pool)
    .await
    .map_err(db)?;
    for (part,) in old {
        match sqlx::query(&format!("drop table if exists {part}")).execute(pool).await {
            Ok(_) => tracing::info!(partition = %part, "metric partition dropped (retention 30d)"),
            Err(e) => tracing::warn!(error = %e, partition = %part, "metric partition drop failed"),
        }
    }

    Ok(created)
}

// ---------------------------------------------------------------------------
// Client plugin center (design §6.9 / contract ⑤ §12 / data structures ⑥ §2.3)
//
// Unrelated to the `plugins` table above (server-side format handlers): here we store distribution metadata
// and version object keys for desktop client third-party plugins, plus **per-user** install records and plugin data snapshots.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HubPluginRow {
    pub id: String,
    pub plugin_id: String,
    pub name: String,
    pub description: String,
    pub readme: String,
    pub icon: Option<String>,
    pub category: String,
    pub tags: Vec<String>,
    pub owner_id: String,
    pub owner_username: String,
    pub owner_display_name: Option<String>,
    pub status: String,
    pub latest_version: Option<String>,
    pub downloads: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Projection shared by list/detail: plugin + owner + latest version + the caller's install record.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HubCatalogRow {
    pub id: String,
    pub plugin_id: String,
    pub name: String,
    pub description: String,
    pub icon: Option<String>,
    pub category: String,
    pub tags: Vec<String>,
    pub owner_id: String,
    pub owner_username: String,
    pub owner_display_name: Option<String>,
    pub latest_version: Option<String>,
    pub downloads: i64,
    pub versions_count: i64,
    pub updated_at: DateTime<Utc>,
    pub latest_size: Option<i64>,
    /// Whether the latest version has a source package (⑤ §12.1, v2 contract §1.5; detail still uses versions[] as the authority)
    pub latest_has_source: Option<bool>,
    pub installed_version: Option<String>,
    pub install_enabled: Option<bool>,
    pub install_data_rev: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HubVersionRow {
    pub id: String,
    pub plugin_row_id: String,
    pub version: String,
    pub asset_name: String,
    pub size: i64,
    pub sha256: String,
    pub object_key: String,
    pub changelog: String,
    pub manifest: Value,
    pub status: String,
    pub downloads: i64,
    pub published_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    // ---- v2 contract §1.1: optional source package (four columns live and die together, see migration 0006)----
    pub source_asset_name: Option<String>,
    pub source_size: Option<i64>,
    pub source_sha256: Option<String>,
    pub source_object_key: Option<String>,
}

/// Source package location info (projection of `hub_source_info`; returned only when all four columns are non-null).
#[derive(Debug, Clone)]
pub struct HubSourceInfo {
    pub asset_name: String,
    pub size: i64,
    pub sha256: String,
    pub object_key: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HubInstallRow {
    pub plugin_id: String,
    pub version: String,
    pub enabled: bool,
    pub data: Value,
    pub data_rev: i64,
    pub data_updated_at: Option<DateTime<Utc>>,
    pub last_device: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct HubNewVersion<'a> {
    pub plugin_id: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub readme: Option<&'a str>,
    pub icon: Option<&'a str>,
    pub category: &'a str,
    pub tags: &'a [String],
    pub version: &'a str,
    pub changelog: &'a str,
    pub asset_name: &'a str,
    pub size: i64,
    pub sha256: &'a str,
    pub object_key: &'a str,
    pub manifest: &'a Value,
    // ---- v2 contract §1.2: optional source package metadata (`None` = no source for this version)----
    //
    // Note there is **no** `source_object_key` here: at POST declaration time the object key is not yet "uploaded";
    // it is filled by [`hub_set_source`] only after the object is actually written to `lattice-plugins` — it is also the
    // sole trusted marker for `has_source` / download 404 / PUT idempotency (the migration 0006 CHECK allows
    // "declared but not uploaded", i.e. asset/size/sha set while object_key is empty).
    pub source_asset_name: Option<&'a str>,
    pub source_size: Option<i64>,
    pub source_sha256: Option<&'a str>,
}

/// Result of `hub_set_source`.
///
/// Idempotency/conflict decisions live in the SQL transaction (`for update`), not in handler memory:
/// when two different source packages are uploaded concurrently for the same version, only the database can give a single answer.
#[derive(Debug, PartialEq, Eq)]
pub enum HubSetSourceOutcome {
    /// First write: object key and metadata persisted
    Stored,
    /// Same sha already exists: idempotent retry, not written again
    Idempotent,
    /// Source exists with a different sha: only a new version can change it (⑤ §12.4)
    Conflict { published_sha256: String },
    /// Version does not exist (or was deleted)
    NotFound,
}

/// Publish result (create plugin or add version): either a draft awaiting upload, or an idempotency/conflict hit.
#[derive(Debug)]
pub enum HubDraftOutcome {
    Draft {
        plugin: HubPluginRow,
        version: HubVersionRow,
        /// The version draft already existed before this round (idempotent retry) → handler returns 200 instead of 201
        reused: bool,
    },
    /// Same version and sha already published: idempotent retry returns the existing version directly
    AlreadyPublished {
        plugin: HubPluginRow,
        version: HubVersionRow,
    },
}

/// Failure reason for publishing a draft (handler maps to 403/409).
#[derive(Debug)]
pub enum HubDraftError {
    NotOwner,
    VersionPublished { sha256: String },
    Db(sqlx::Error),
}

impl From<sqlx::Error> for HubDraftError {
    fn from(e: sqlx::Error) -> Self {
        HubDraftError::Db(e)
    }
}

fn hub_owner_fields(row: HubPluginRow) -> HubPluginRow {
    row
}

/// Read the plugin body (including owner display name). `status` is unrestricted (the caller decides visibility).
pub async fn hub_plugin_by_plugin_id(pool: &Pool, plugin_id: &str) -> Result<Option<HubPluginRow>> {
    sqlx::query_as::<_, HubPluginRow>(
        "select p.id, p.plugin_id, p.name, p.description, p.readme, p.icon, p.category, p.tags,
                p.owner_id, u.username as owner_username, u.display_name as owner_display_name,
                p.status, p.latest_version, p.downloads, p.created_at, p.updated_at
         from hub_plugins p join users u on u.id = p.owner_id
         where p.plugin_id = $1",
    )
    .bind(plugin_id)
    .fetch_optional(pool)
    .await
    .map_err(db)
}

/// List query. Empty `q`/`category` means no filter; sort enum see design §17.16.
pub async fn hub_catalog(
    pool: &Pool,
    viewer_id: &str,
    q: &str,
    category: &str,
    sort: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<HubCatalogRow>, i64)> {
    let order = match sort {
        "popular" => "p.downloads desc, p.updated_at desc",
        "name" => "lower(p.name) asc, p.plugin_id asc",
        _ => "p.updated_at desc, p.plugin_id asc",
    };
    let sql = format!(
        "select p.id, p.plugin_id, p.name, p.description, p.icon, p.category, p.tags,
                p.owner_id, u.username as owner_username, u.display_name as owner_display_name,
                p.latest_version, p.downloads,
                (select count(*) from hub_plugin_versions vv
                  where vv.plugin_row_id = p.id and vv.status = 'published') as versions_count,
                p.updated_at,
                lv.size as latest_size,
                (lv.source_object_key is not null) as latest_has_source,
                i.version as installed_version, i.enabled as install_enabled, i.data_rev as install_data_rev
         from hub_plugins p
         join users u on u.id = p.owner_id
         left join hub_plugin_versions lv
                on lv.plugin_row_id = p.id and lv.version = p.latest_version and lv.status = 'published'
         left join hub_plugin_installs i on i.plugin_id = p.plugin_id and i.user_id = $1
         where p.status = 'published'
           and exists (select 1 from hub_plugin_versions v where v.plugin_row_id = p.id and v.status = 'published')
           and ($2 = '' or p.name ilike '%' || $2 || '%' or p.description ilike '%' || $2 || '%'
                or p.plugin_id ilike '%' || $2 || '%'
                or exists (select 1 from unnest(p.tags) t where t ilike '%' || $2 || '%'))
           and ($3 = '' or p.category = $3)
         order by {order}
         limit $4 offset $5"
    );
    let items = sqlx::query_as::<_, HubCatalogRow>(&sql)
        .bind(viewer_id)
        .bind(q)
        .bind(category)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(db)?;

    let total: i64 = sqlx::query_scalar(
        "select count(*) from hub_plugins p
         where p.status = 'published'
           and exists (select 1 from hub_plugin_versions v where v.plugin_row_id = p.id and v.status = 'published')
           and ($1 = '' or p.name ilike '%' || $1 || '%' or p.description ilike '%' || $1 || '%'
                or p.plugin_id ilike '%' || $1 || '%'
                or exists (select 1 from unnest(p.tags) t where t ilike '%' || $1 || '%'))
           and ($2 = '' or p.category = $2)",
    )
    .bind(q)
    .bind(category)
    .fetch_one(pool)
    .await
    .map_err(db)?;
    Ok((items, total))
}

/// Version list (by default only published, newest published first).
pub async fn hub_versions_of(pool: &Pool, plugin_row_id: &str, include_removed: bool) -> Result<Vec<HubVersionRow>> {
    sqlx::query_as::<_, HubVersionRow>(
        "select id, plugin_row_id, version, asset_name, size, sha256, object_key, changelog,
                manifest, status, downloads, published_at, created_at,
                source_asset_name, source_size, source_sha256, source_object_key
         from hub_plugin_versions
         where plugin_row_id = $1 and (status = 'published' or $2)
         order by published_at desc nulls last, created_at desc",
    )
    .bind(plugin_row_id)
    .bind(include_removed)
    .fetch_all(pool)
    .await
    .map_err(db)
}

pub async fn hub_version(pool: &Pool, plugin_row_id: &str, version: &str) -> Result<Option<HubVersionRow>> {
    sqlx::query_as::<_, HubVersionRow>(
        "select id, plugin_row_id, version, asset_name, size, sha256, object_key, changelog,
                manifest, status, downloads, published_at, created_at,
                source_asset_name, source_size, source_sha256, source_object_key
         from hub_plugin_versions where plugin_row_id = $1 and version = $2",
    )
    .bind(plugin_row_id)
    .bind(version)
    .fetch_optional(pool)
    .await
    .map_err(db)
}

/// Version source package location info: returns `Some` only when all four columns are set (the ⑥ CHECK guarantees all-or-nothing).
pub async fn hub_source_info(
    pool: &Pool,
    plugin_row_id: &str,
    version: &str,
) -> Result<Option<HubSourceInfo>> {
    let row: Option<(Option<String>, Option<i64>, Option<String>, Option<String>)> =
        sqlx::query_as(
            "select source_asset_name, source_size, source_sha256, source_object_key
             from hub_plugin_versions where plugin_row_id = $1 and version = $2",
        )
        .bind(plugin_row_id)
        .bind(version)
        .fetch_optional(pool)
        .await
        .map_err(db)?;
    Ok(match row {
        Some((Some(asset_name), Some(size), Some(sha256), Some(object_key))) => Some(HubSourceInfo {
            asset_name,
            size,
            sha256,
            object_key,
        }),
        _ => None,
    })
}

/// Whether a version already has an **uploaded** source package (`has_source` for list/detail).
pub async fn hub_has_source(pool: &Pool, plugin_row_id: &str, version: &str) -> Result<bool> {
    let hit: Option<bool> = sqlx::query_scalar(
        "select (source_object_key is not null) from hub_plugin_versions
         where plugin_row_id = $1 and version = $2",
    )
    .bind(plugin_row_id)
    .bind(version)
    .fetch_optional(pool)
    .await
    .map_err(db)?;
    Ok(hit.unwrap_or(false))
}

/// Metadata write after the source package object is stored (⑤ §12.4; v2 contract §1.3 idempotency/409).
///
/// The decision is made **inside the transaction** (`for update`); the handler only builds the package, validates, and writes the object:
/// - Already **uploaded** (`source_object_key` non-null) with the same sha → [`HubSetSourceOutcome::Idempotent`];
/// - Already uploaded with a different sha → [`HubSetSourceOutcome::Conflict`] (publish a new version to change source);
/// - Declared but not yet uploaded (`source_object_key` null) → write the four columns (the object key is persisted only now) → `Stored`;
/// - Version row missing / unpublished → `NotFound` (handler maps 404).
///
/// `source_object_key` is the sole marker that "the source object was written to object storage": the POST declaration stage writes only
/// asset_name/size/sha256, so list `has_source`, download 404, and PUT idempotency all rely on it.
pub async fn hub_set_source(
    pool: &Pool,
    version_id: &str,
    asset_name: &str,
    size: i64,
    sha256: &str,
    object_key: &str,
) -> Result<HubSetSourceOutcome> {
    let mut tx = pool.begin().await.map_err(db)?;
    let current: Option<(Option<String>, Option<String>, String)> = sqlx::query_as(
        "select source_sha256, source_object_key, status
         from hub_plugin_versions where id = $1 for update",
    )
    .bind(version_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;
    let Some((declared_sha, uploaded_key, status)) = current else {
        tx.rollback().await.ok();
        return Ok(HubSetSourceOutcome::NotFound);
    };
    if status == "removed" {
        tx.rollback().await.ok();
        return Ok(HubSetSourceOutcome::NotFound);
    }
    if uploaded_key.is_some() {
        let published_sha256 = declared_sha.unwrap_or_default();
        tx.rollback().await.ok();
        return Ok(if published_sha256 == sha256 {
            HubSetSourceOutcome::Idempotent
        } else {
            HubSetSourceOutcome::Conflict { published_sha256 }
        });
    }
    if let Some(declared) = &declared_sha {
        // The declared value was locked at POST time; inequality means the version row changed after the read (rare concurrency);
        // treat it as "declared with a different sha" to avoid persisting bytes that do not match the declaration.
        if declared != sha256 {
            let published_sha256 = declared.clone();
            tx.rollback().await.ok();
            return Ok(HubSetSourceOutcome::Conflict { published_sha256 });
        }
    }
    sqlx::query(
        "update hub_plugin_versions
         set source_asset_name = $2, source_size = $3, source_sha256 = $4, source_object_key = $5
         where id = $1",
    )
    .bind(version_id)
    .bind(asset_name)
    .bind(size)
    .bind(sha256)
    .bind(object_key)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(HubSetSourceOutcome::Stored)
}

/// Publish a draft: create a plugin or add a version to an existing plugin (single transaction, `for update` prevents concurrent double writes of the same version).
pub async fn hub_create_draft(
    pool: &Pool,
    user_id: &str,
    is_admin: bool,
    v: &HubNewVersion<'_>,
) -> std::result::Result<HubDraftOutcome, HubDraftError> {
    let mut tx = pool.begin().await.map_err(HubDraftError::Db)?;

    let existing = sqlx::query_as::<_, HubPluginRow>(
        "select p.id, p.plugin_id, p.name, p.description, p.readme, p.icon, p.category, p.tags,
                p.owner_id, u.username as owner_username, u.display_name as owner_display_name,
                p.status, p.latest_version, p.downloads, p.created_at, p.updated_at
         from hub_plugins p join users u on u.id = p.owner_id
         where p.plugin_id = $1 for update of p",
    )
    .bind(v.plugin_id)
    .fetch_optional(&mut *tx)
    .await?;

    let plugin = match existing {
        Some(mut plugin) => {
            if plugin.owner_id != user_id && !is_admin {
                return Err(HubDraftError::NotOwner);
            }
            sqlx::query(
                "update hub_plugins
                 set name = $2, description = $3,
                     readme = coalesce($4, readme),
                     icon = coalesce($5, icon),
                     category = $6, tags = $7,
                     status = 'published', updated_at = now()
                 where id = $1",
            )
            .bind(&plugin.id)
            .bind(v.name)
            .bind(v.description)
            .bind(v.readme)
            .bind(v.icon)
            .bind(v.category)
            .bind(v.tags)
            .execute(&mut *tx)
            .await?;
            plugin.name = v.name.to_string();
            plugin.description = v.description.to_string();
            if let Some(r) = v.readme {
                plugin.readme = r.to_string();
            }
            if let Some(i) = v.icon {
                plugin.icon = Some(i.to_string());
            }
            plugin.category = v.category.to_string();
            plugin.tags = v.tags.to_vec();
            plugin.status = "published".into();
            plugin.updated_at = Utc::now();
            plugin
        }
        None => {
            let id = lattice_core::ids::new_id();
            sqlx::query(
                "insert into hub_plugins (id, plugin_id, name, description, readme, icon, category, tags, owner_id)
                 values ($1,$2,$3,$4,coalesce($5,''),coalesce($6,'other'),$7,$8,$9)",
            )
            .bind(&id)
            .bind(v.plugin_id)
            .bind(v.name)
            .bind(v.description)
            .bind(v.readme)
            .bind(v.icon)
            .bind(v.category)
            .bind(v.tags)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query_as::<_, HubPluginRow>(
                "select p.id, p.plugin_id, p.name, p.description, p.readme, p.icon, p.category, p.tags,
                        p.owner_id, u.username as owner_username, u.display_name as owner_display_name,
                        p.status, p.latest_version, p.downloads, p.created_at, p.updated_at
                 from hub_plugins p join users u on u.id = p.owner_id where p.id = $1",
            )
            .bind(&id)
            .fetch_one(&mut *tx)
            .await?
        }
    };

    let prev = sqlx::query_as::<_, HubVersionRow>(
        "select id, plugin_row_id, version, asset_name, size, sha256, object_key, changelog,
                manifest, status, downloads, published_at, created_at,
                source_asset_name, source_size, source_sha256, source_object_key
         from hub_plugin_versions where plugin_row_id = $1 and version = $2 for update",
    )
    .bind(&plugin.id)
    .bind(v.version)
    .fetch_optional(&mut *tx)
    .await?;

    let reused = prev.is_some();
    let version_row = match prev {
        Some(row) if row.status == "published" => {
            if row.sha256 == v.sha256 {
                // Idempotent retry of a published version: the package body is no longer overwritten, but **adding** a source package declaration is allowed —
                // if the client sent the package first and the source later (or the previous source upload failed), resending the same POST
                // should still yield the source_upload target (⑤ §12.3 `source_upload` in the response).
                // A version that already has a source declaration accepts no further source metadata changes (change source only by bumping the version).
                let mut row = row;
                if row.source_sha256.is_none() {
                    if let (Some(a), Some(s), Some(sha)) =
                        (v.source_asset_name, v.source_size, v.source_sha256)
                    {
                        // object_key stays NULL: the source object is not uploaded yet; after PUT .../source succeeds
                        // `hub_set_source` fills it (that is the basis for has_source).
                        sqlx::query(
                            "update hub_plugin_versions
                             set source_asset_name = $2, source_size = $3, source_sha256 = $4
                             where id = $1",
                        )
                        .bind(&row.id)
                        .bind(a)
                        .bind(s)
                        .bind(sha)
                        .execute(&mut *tx)
                        .await?;
                        row.source_asset_name = Some(a.to_string());
                        row.source_size = Some(s);
                        row.source_sha256 = Some(sha.to_string());
                    }
                }
                tx.commit().await?;
                return Ok(HubDraftOutcome::AlreadyPublished { plugin, version: row });
            }
            return Err(HubDraftError::VersionPublished { sha256: row.sha256 });
        }
        Some(row) => {
            // Draft retry: overwrite metadata for the same version (replace the package if sha changed; the old object was never written).
            // Source metadata uses coalesce: when the request has no source, keep the declared value (do not misinterpret
            // "the client omitted the source field this time" as "delete the source declaration"); once the request
            // carries new source metadata, clear object_key — the old source object corresponds to the
            // old sha and must go through PUT again to count as "uploaded" (old objects must not impersonate a new declaration).
            sqlx::query(
                "update hub_plugin_versions
                 set asset_name = $2, size = $3, sha256 = $4, object_key = $5,
                     changelog = $6, manifest = $7, uploaded_by = $8, status = 'pending',
                     source_asset_name = coalesce($9, source_asset_name),
                     source_size = coalesce($10, source_size),
                     source_sha256 = coalesce($11, source_sha256),
                     source_object_key = case when $11 is null then source_object_key else null end
                 where id = $1",
            )
            .bind(&row.id)
            .bind(v.asset_name)
            .bind(v.size)
            .bind(v.sha256)
            .bind(v.object_key)
            .bind(v.changelog)
            .bind(v.manifest)
            .bind(user_id)
            .bind(v.source_asset_name)
            .bind(v.source_size)
            .bind(v.source_sha256)
            .execute(&mut *tx)
            .await?;
            HubVersionRow {
                asset_name: v.asset_name.into(),
                size: v.size,
                sha256: v.sha256.into(),
                object_key: v.object_key.into(),
                changelog: v.changelog.into(),
                manifest: v.manifest.clone(),
                source_asset_name: v
                    .source_asset_name
                    .map(str::to_string)
                    .or(row.source_asset_name),
                source_size: v.source_size.or(row.source_size),
                source_sha256: v.source_sha256.map(str::to_string).or(row.source_sha256),
                source_object_key: if v.source_sha256.is_some() {
                    None
                } else {
                    row.source_object_key
                },
                ..row
            }
        }
        None => {
            let id = lattice_core::ids::new_id();
            sqlx::query(
                "insert into hub_plugin_versions
                   (id, plugin_row_id, version, asset_name, size, sha256, object_key, changelog, manifest, uploaded_by,
                    source_asset_name, source_size, source_sha256)
                 values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            )
            .bind(&id)
            .bind(&plugin.id)
            .bind(v.version)
            .bind(v.asset_name)
            .bind(v.size)
            .bind(v.sha256)
            .bind(v.object_key)
            .bind(v.changelog)
            .bind(v.manifest)
            .bind(user_id)
            .bind(v.source_asset_name)
            .bind(v.source_size)
            .bind(v.source_sha256)
            .execute(&mut *tx)
            .await?;
            sqlx::query_as::<_, HubVersionRow>(
                "select id, plugin_row_id, version, asset_name, size, sha256, object_key, changelog,
                        manifest, status, downloads, published_at, created_at,
                        source_asset_name, source_size, source_sha256, source_object_key
                 from hub_plugin_versions where id = $1",
            )
            .bind(&id)
            .fetch_one(&mut *tx)
            .await?
        }
    };

    tx.commit().await?;
    Ok(HubDraftOutcome::Draft {
        plugin: hub_owner_fields(plugin),
        version: version_row,
        reused,
    })
}

/// After the package body is stored: move the version to `published` and advance the latest-version pointer (semver comparison is done in Rust).
pub async fn hub_publish_version(pool: &Pool, version_id: &str) -> Result<Option<HubVersionRow>> {
    let mut tx = pool.begin().await.map_err(db)?;
    let version = sqlx::query_as::<_, HubVersionRow>(
        "select id, plugin_row_id, version, asset_name, size, sha256, object_key, changelog,
                manifest, status, downloads, published_at, created_at,
                source_asset_name, source_size, source_sha256, source_object_key
         from hub_plugin_versions where id = $1 for update",
    )
    .bind(version_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;
    let Some(mut version) = version else {
        return Ok(None);
    };
    if version.status == "published" {
        tx.commit().await.ok();
        return Ok(Some(version));
    }
    sqlx::query(
        "update hub_plugin_versions set status = 'published', published_at = now() where id = $1",
    )
    .bind(&version.id)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    version.status = "published".into();
    version.published_at = Some(Utc::now());

    let published: Vec<(String,)> = sqlx::query_as(
        "select version from hub_plugin_versions where plugin_row_id = $1 and status = 'published'",
    )
    .bind(&version.plugin_row_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(db)?;
    let latest = published
        .into_iter()
        .map(|(v,)| v)
        .max_by(|a, b| crate::hub::compare_semver(a, b));

    sqlx::query("update hub_plugins set latest_version = $2, updated_at = now() where id = $1")
        .bind(&version.plugin_row_id)
        .bind(&latest)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(Some(version))
}

/// Unpublish a version; returns (whether the version existed, whether the plugin still has a published version).
pub async fn hub_remove_version(pool: &Pool, plugin_row_id: &str, version: &str) -> Result<bool> {
    let mut tx = pool.begin().await.map_err(db)?;
    let affected = sqlx::query(
        "update hub_plugin_versions set status = 'removed'
         where plugin_row_id = $1 and version = $2 and status <> 'removed'",
    )
    .bind(plugin_row_id)
    .bind(version)
    .execute(&mut *tx)
    .await
    .map_err(db)?
    .rows_affected();
    if affected == 0 {
        tx.rollback().await.ok();
        return Ok(false);
    }
    let remaining: Vec<(String,)> = sqlx::query_as(
        "select version from hub_plugin_versions where plugin_row_id = $1 and status = 'published'",
    )
    .bind(plugin_row_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(db)?;
    let latest = remaining
        .into_iter()
        .map(|(v,)| v)
        .max_by(|a, b| crate::hub::compare_semver(a, b));
    sqlx::query("update hub_plugins set latest_version = $2, updated_at = now() where id = $1")
        .bind(plugin_row_id)
        .bind(&latest)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(true)
}

pub async fn hub_remove_plugin(pool: &Pool, plugin_row_id: &str) -> Result<bool> {
    // Plugin versions are unpublished together with the plugin: otherwise "delete plugin → re-import the same version" hits 409
    // `version_published` (the old version row is still published but no longer visible in the list, which users cannot understand).
    // After versions move to removed, objects are reclaimed by lock:hub-object-gc within a 30-day window; republishing overwrites the same version row.
    let mut tx = pool.begin().await.map_err(db)?;
    sqlx::query(
        "update hub_plugin_versions set status = 'removed'
         where plugin_row_id = $1 and status <> 'removed'",
    )
    .bind(plugin_row_id)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    let n = sqlx::query("update hub_plugins set status = 'removed', updated_at = now() where id = $1")
        .bind(plugin_row_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?
        .rows_affected();
    tx.commit().await.map_err(db)?;
    Ok(n > 0)
}

pub async fn hub_bump_plugin_download(pool: &Pool, plugin_row_id: &str) -> Result<()> {
    sqlx::query("update hub_plugins set downloads = downloads + 1 where id = $1")
        .bind(plugin_row_id)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(())
}

pub async fn hub_bump_version_download(pool: &Pool, version_id: &str) -> Result<()> {
    sqlx::query("update hub_plugin_versions set downloads = downloads + 1 where id = $1")
        .bind(version_id)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(())
}

/// Install record list (`include_data` includes the data snapshot; when the plugin is unpublished the handler sets the `plugin` field to null).
pub async fn hub_installs(pool: &Pool, user_id: &str, include_data: bool) -> Result<Vec<HubInstallRow>> {
    let sql = if include_data {
        "select plugin_id, version, enabled, data, data_rev, data_updated_at, last_device, updated_at
         from hub_plugin_installs where user_id = $1 order by updated_at desc"
    } else {
        "select plugin_id, version, enabled, '{}'::jsonb as data, data_rev, data_updated_at,
                last_device, updated_at
         from hub_plugin_installs where user_id = $1 order by updated_at desc"
    };
    sqlx::query_as::<_, HubInstallRow>(sql)
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(db)
}

pub async fn hub_install_of(pool: &Pool, user_id: &str, plugin_id: &str) -> Result<Option<HubInstallRow>> {
    sqlx::query_as::<_, HubInstallRow>(
        "select plugin_id, version, enabled, data, data_rev, data_updated_at, last_device, updated_at
         from hub_plugin_installs where user_id = $1 and plugin_id = $2",
    )
    .bind(user_id)
    .bind(plugin_id)
    .fetch_optional(pool)
    .await
    .map_err(db)
}

#[derive(Debug)]
pub enum HubInstallOutcome {
    Created(HubInstallRow),
    Updated(HubInstallRow),
    /// `data_rev` on `data` submission differs from the server: return the server's current value and ask the client to merge and retry
    Conflict(HubInstallRow),
}

/// Install record upsert (⑤ §12.7).
///
/// `force` applies only to `data`: `version`/`enabled` are idempotent overwrites and need no revision number.
/// Lock the row with `for update`: otherwise two devices submitting concurrently both read the old `data_rev` and both write successfully,
/// making conflict detection meaningless.
pub async fn hub_install_upsert(
    pool: &Pool,
    user_id: &str,
    plugin_id: &str,
    version: Option<&str>,
    enabled: Option<bool>,
    data: Option<&Value>,
    data_rev: Option<i64>,
    device_id: Option<&str>,
    force: bool,
) -> Result<HubInstallOutcome> {
    let mut tx = pool.begin().await.map_err(db)?;
    let existing = sqlx::query_as::<_, HubInstallRow>(
        "select plugin_id, version, enabled, data, data_rev, data_updated_at, last_device, updated_at
         from hub_plugin_installs where user_id = $1 and plugin_id = $2 for update",
    )
    .bind(user_id)
    .bind(plugin_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;

    let outcome = match existing {
        None => {
            let rev = if data.is_some() { 1 } else { 0 };
            let row = sqlx::query_as::<_, HubInstallRow>(
                "insert into hub_plugin_installs
                   (user_id, plugin_id, version, enabled, data, data_rev, data_updated_at, last_device)
                 values ($1,$2,coalesce($3,''),coalesce($4,true),coalesce($5,'{}'::jsonb),$6,
                         case when $5 is null then null else now() end, $7)
                 returning plugin_id, version, enabled, data, data_rev, data_updated_at, last_device, updated_at",
            )
            .bind(user_id)
            .bind(plugin_id)
            .bind(version)
            .bind(enabled)
            .bind(data)
            .bind(rev)
            .bind(device_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            HubInstallOutcome::Created(row)
        }
        Some(mut row) => {
            if let Some(d) = data {
                let client_rev = data_rev.unwrap_or(0);
                if !force && client_rev != row.data_rev {
                    tx.rollback().await.ok();
                    return Ok(HubInstallOutcome::Conflict(row));
                }
                row.data = d.clone();
                row.data_rev += 1;
                row.data_updated_at = Some(Utc::now());
            }
            if let Some(v) = version {
                row.version = v.to_string();
            }
            if let Some(e) = enabled {
                row.enabled = e;
            }
            let updated = sqlx::query_as::<_, HubInstallRow>(
                "update hub_plugin_installs
                 set version = $3, enabled = $4, data = $5, data_rev = $6,
                     data_updated_at = $7, last_device = coalesce($8, last_device), updated_at = now()
                 where user_id = $1 and plugin_id = $2
                 returning plugin_id, version, enabled, data, data_rev, data_updated_at, last_device, updated_at",
            )
            .bind(user_id)
            .bind(plugin_id)
            .bind(&row.version)
            .bind(row.enabled)
            .bind(&row.data)
            .bind(row.data_rev)
            .bind(row.data_updated_at)
            .bind(device_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            HubInstallOutcome::Updated(updated)
        }
    };
    tx.commit().await.map_err(db)?;
    Ok(outcome)
}

pub async fn hub_install_delete(pool: &Pool, user_id: &str, plugin_id: &str) -> Result<bool> {
    let n = sqlx::query("delete from hub_plugin_installs where user_id = $1 and plugin_id = $2")
        .bind(user_id)
        .bind(plugin_id)
        .execute(pool)
        .await
        .map_err(db)?
        .rows_affected();
    Ok(n > 0)
}

/// Console statistics (⑤ §12.8).
pub async fn hub_stats(pool: &Pool) -> Result<Value> {
    let plugins: i64 = sqlx::query_scalar("select count(*) from hub_plugins where status = 'published'")
        .fetch_one(pool)
        .await
        .map_err(db)?;
    let versions: i64 =
        sqlx::query_scalar("select count(*) from hub_plugin_versions where status = 'published'")
            .fetch_one(pool)
            .await
            .map_err(db)?;
    let installs: i64 = sqlx::query_scalar("select count(*) from hub_plugin_installs")
        .fetch_one(pool)
        .await
        .map_err(db)?;
    let downloads_total: i64 =
        sqlx::query_scalar("select coalesce(sum(downloads),0)::bigint from hub_plugins")
            .fetch_one(pool)
            .await
            .map_err(db)?;
    let storage_bytes: i64 = sqlx::query_scalar(
        "select coalesce(sum(size),0)::bigint from hub_plugin_versions where status = 'published'",
    )
    .fetch_one(pool)
    .await
    .map_err(db)?;

    let top = sqlx::query_as::<_, (String, String, i64)>(
        "select plugin_id, name, downloads from hub_plugins
         where status = 'published' order by downloads desc, updated_at desc limit 5",
    )
    .fetch_all(pool)
    .await
    .map_err(db)?;
    let recent = sqlx::query_as::<_, (String, String, Option<DateTime<Utc>>)>(
        "select p.plugin_id, v.version, v.published_at
         from hub_plugin_versions v join hub_plugins p on p.id = v.plugin_row_id
         where v.status = 'published' order by v.published_at desc nulls last limit 5",
    )
    .fetch_all(pool)
    .await
    .map_err(db)?;

    Ok(serde_json::json!({
        "plugins": plugins,
        "versions": versions,
        "installs": installs,
        "downloads_total": downloads_total,
        "storage_bytes": storage_bytes,
        "top": top.into_iter().map(|(plugin_id, name, downloads)| serde_json::json!({
            "plugin_id": plugin_id, "name": name, "downloads": downloads
        })).collect::<Vec<_>>(),
        "recent": recent.into_iter().map(|(plugin_id, version, published_at)| serde_json::json!({
            "plugin_id": plugin_id, "version": version, "published_at": published_at
        })).collect::<Vec<_>>(),
    }))
}

/// Clean up timed-out `pending` drafts (⑥ §2.6, 30 minutes). Returns the number cleaned.
pub async fn hub_expire_drafts(pool: &Pool, limit: i64) -> Result<u64> {
    let n = sqlx::query(
        "update hub_plugin_versions set status = 'removed'
         where id in (
           select id from hub_plugin_versions
           where status = 'pending' and created_at < now() - interval '30 minutes'
           order by created_at limit $1 for update skip locked
         )",
    )
    .bind(limit)
    .execute(pool)
    .await
    .map_err(db)?
    .rows_affected();
    Ok(n)
}

/// Unpublished versions awaiting reclamation (objects retained 30 days, ⑥ §2.6).
pub async fn hub_removed_versions_to_gc(
    pool: &Pool,
    older_than_days: i64,
    limit: i64,
) -> Result<Vec<(String, String, Option<String>)>> {
    sqlx::query_as::<_, (String, String, Option<String>)>(
        "select id, object_key, source_object_key from hub_plugin_versions
         where status = 'removed'
           and created_at < now() - make_interval(days => $1::int)
         order by created_at limit $2",
    )
    .bind(older_than_days)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(db)
}

pub async fn hub_delete_version(pool: &Pool, version_id: &str) -> Result<()> {
    sqlx::query("delete from hub_plugin_versions where id = $1")
        .bind(version_id)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Media recording segment index (PL-13 13.6 search/download; migration 0009_media_recordings.sql)
//
// Stores metadata only (no payload): the recording object itself is in MinIO; this table holds "a recording segment's boundaries/size/object location".
// There is exactly one write point: `routing/media_record.rs::index_segment` (called by both the aggregate-stream consumer and the direct-write
// recorder's successful-persist branch); the idempotency key is the `object_key` unique constraint.
// ---------------------------------------------------------------------------

/// Media recording segment index row (`media_recordings`).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MediaRecordingRow {
    pub id: String,
    pub stream_id: String,
    pub node_id: String,
    pub object_key: String,
    /// Playback manifest object key (migration 0010); None = old row/manifest generation failed (not fabricated).
    pub manifest_key: Option<String>,
    /// Segment first frame seq; the **direct-write path has no frame seq** → None (no fabricated sequence).
    pub first_seq: Option<i64>,
    /// Segment last frame seq; direct-write path → None.
    pub last_seq: Option<i64>,
    pub frames: i32,
    pub size_bytes: i64,
    pub bucket: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    /// Reserved: codec (always None this round).
    pub codec: Option<String>,
    /// Reserved: container format (always None this round, no MP4/OGG).
    pub format: Option<String>,
}

/// Insert parameters for a new index row (`id`/`created_at` come from SQL defaults/the caller).
#[derive(Debug, Clone)]
pub struct NewMediaRecording<'a> {
    pub stream_id: &'a str,
    pub node_id: &'a str,
    pub object_key: &'a str,
    /// Playback manifest object key (`None` = generation failed; the row is still searchable/downloadable, only the manifest API 404s).
    pub manifest_key: Option<&'a str>,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    pub frames: usize,
    pub size_bytes: usize,
    pub bucket: &'a str,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
}

/// Idempotently write one recording index: `Ok(true)` = newly inserted, `Ok(false)` = `object_key` already exists (replay).
///
/// Idempotency relies on the `object_key` unique constraint + `on conflict do nothing` (not check-then-insert, avoiding concurrent replay races).
/// Failures (PG unavailable, etc.) are returned as-is; the caller degrades to WARN (recording forwarding/persistence are unaffected).
pub async fn media_recording_insert(
    pool: &Pool,
    rec: NewMediaRecording<'_>,
) -> Result<bool> {
    let to_i64 = |v: u64| i64::try_from(v).ok();
    let res = sqlx::query(
        "insert into media_recordings
           (id, stream_id, node_id, object_key, manifest_key, first_seq, last_seq,
            frames, size_bytes, bucket, started_at, ended_at)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         on conflict (object_key) do nothing",
    )
    .bind(lattice_core::ids::new_id())
    .bind(rec.stream_id)
    .bind(rec.node_id)
    .bind(rec.object_key)
    .bind(rec.manifest_key)
    .bind(rec.first_seq.and_then(to_i64))
    .bind(rec.last_seq.and_then(to_i64))
    .bind(i32::try_from(rec.frames).unwrap_or(i32::MAX))
    .bind(i64::try_from(rec.size_bytes).unwrap_or(i64::MAX))
    .bind(rec.bucket)
    .bind(rec.started_at)
    .bind(rec.ended_at)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(res.rows_affected() == 1)
}

/// Fetch a recording index by id (unknown id → None).
pub async fn media_recording_by_id(pool: &Pool, id: &str) -> Result<Option<MediaRecordingRow>> {
    sqlx::query_as::<_, MediaRecordingRow>(
        "select id, stream_id, node_id, object_key, manifest_key, first_seq, last_seq, frames,
                size_bytes, bucket, created_at, started_at, ended_at, codec, format
         from media_recordings where id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(db)
}

/// List (descending + cursor pagination): `stream_id` optional filter; `before` = the last entry of the previous page `(created_at,id)`.
///
/// Uses `(created_at, id) < (cursor_created_at, cursor_id)` instead of offset: while objects are continuously written,
/// offset pagination misses/duplicates (new rows insert at the front, shifting everything). The index `(stream_id, created_at desc, id desc)`
/// exactly covers filter + sort + range.
pub async fn media_recordings_list(
    pool: &Pool,
    stream_id: Option<&str>,
    limit: i64,
    before: Option<(&DateTime<Utc>, &str)>,
) -> Result<Vec<MediaRecordingRow>> {
    let before_at = before.map(|(at, _)| at.clone());
    let before_id = before.map(|(_, id)| id);
    sqlx::query_as::<_, MediaRecordingRow>(
        "select id, stream_id, node_id, object_key, manifest_key, first_seq, last_seq, frames,
                size_bytes, bucket, created_at, started_at, ended_at, codec, format
         from media_recordings
         where ($1::text is null or stream_id = $1)
           and ($2::timestamptz is null or (created_at, id) < ($2, $3))
         order by created_at desc, id desc
         limit $4",
    )
    .bind(stream_id)
    .bind(before_at)
    .bind(before_id)
    .bind(limit.clamp(1, 200))
    .fetch_all(pool)
    .await
    .map_err(db)
}

/// Lifecycle reclamation (PL-13 13.6): fetch a batch of recording index rows **older than the retention period** (oldest first, bounded batch).
///
/// - `created_at < now() - retention_days days`: retention starts from index write time (= after the object was persisted);
/// - ascending + `limit`: the caller processes at most ≤1000 rows per call (batched cleanup to avoid long transactions/stalls);
/// - index rows are read only; object/manifest deletion is performed per row by the caller (`jobs::media_record_gc_once`).
pub async fn media_recordings_expired(
    pool: &Pool,
    retention_days: i64,
    limit: i64,
) -> Result<Vec<MediaRecordingRow>> {
    sqlx::query_as::<_, MediaRecordingRow>(
        "select id, stream_id, node_id, object_key, manifest_key, first_seq, last_seq, frames,
                size_bytes, bucket, created_at, started_at, ended_at, codec, format
         from media_recordings
         where created_at < now() - make_interval(days => $1::int)
         order by created_at asc, id asc
         limit $2",
    )
    // 0 days = disable reclamation (the caller short-circuits; raise to 1 defensively here: never delete a just-written segment).
    .bind(i32::try_from(retention_days.max(1)).unwrap_or(i32::MAX))
    .bind(limit.clamp(1, 1000))
    .fetch_all(pool)
    .await
    .map_err(db)
}

/// Delete one recording index row (GC calls it after object + manifest deletion succeed); returns whether a row was actually deleted (idempotent).
///
/// Delete the object first, then the row: on mid-way failure the row remains so the next round can still locate the object and retry (no unlocatable garbage objects).
pub async fn media_recording_delete(pool: &Pool, id: &str) -> Result<bool> {
    let res = sqlx::query("delete from media_recordings where id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db)?;
    Ok(res.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    /// Minimal DatabaseError stub: used only to verify the SQLSTATE classification matrix (no DB connection).
    #[derive(Debug)]
    struct FakeDbError {
        code: &'static str,
    }

    impl std::fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "fake db error {}", self.code)
        }
    }

    impl std::error::Error for FakeDbError {}

    impl sqlx::error::DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            "fake db error"
        }
        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.code))
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    fn db_code(code: &'static str) -> sqlx::Error {
        sqlx::Error::database(FakeDbError { code })
    }

    #[test]
    fn unavailable_classification_matrix() {
        // Connection/pool layer: determinably unavailable → WAL degradation allowed
        assert!(is_unavailable(&sqlx::Error::PoolTimedOut));
        assert!(is_unavailable(&sqlx::Error::PoolClosed));
        assert!(is_unavailable(&sqlx::Error::Protocol("unexpected eof".into())));
        assert!(is_unavailable(&sqlx::Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset"
        ))));
        // connection exception(08)/admin shutdown(57P0x)/resource exhaustion(53)/statement timeout(57014)/deadlock(40P01)
        for code in [
            "08000", "08001", "08006", "08P01", "57P01", "57P02", "57P03", "53300", "53100",
            "57014", "40P01", "40001", "55P03",
        ] {
            assert!(is_unavailable(&db_code(code)), "{code} must be determinably unavailable");
        }
        // constraint/syntax/type and other 4xx classes: not "PG unavailable", must be reported as-is (must not pile into the WAL as poison)
        for code in ["23505", "23503", "23502", "42601", "42703", "42P01", "22P02"] {
            assert!(!is_unavailable(&db_code(code)), "{code} must not enter the WAL");
        }
        assert!(!is_unavailable(&sqlx::Error::RowNotFound));
    }

    #[test]
    fn unavailable_error_is_tagged_for_wal_degrade() {
        let e = unavailable_error();
        assert!(is_unavailable_err(&e), "WAL degradation decision relies on the reason=pg_unavailable marker");
        assert_eq!(e.details.as_ref().unwrap()["dep"], serde_json::json!("pg"));
        // Ordinary internal errors must not be misjudged as "PG unavailable" (otherwise bad messages pile into the WAL)
        assert!(!is_unavailable_err(&crate::error::internal("boom")));
        assert!(!is_unavailable_err(&crate::error::not_found("nope")));
    }
}
