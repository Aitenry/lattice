//! Admin REST plane (contract authority: ⑤ §8; RBAC in §0.2; dangerous operations must carry `reason`).
//!
//! Isolated from the data plane: dedicated connection pool + dedicated route tree (② §2.1 / §12 P6).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use base64::engine::general_purpose::{
    STANDARD as B64, STANDARD_NO_PAD as B64_NO_PAD, URL_SAFE as B64_URL,
    URL_SAFE_NO_PAD as B64_URL_NO_PAD,
};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};

use lattice_core::LatticeError;

use crate::auth::rbac::AuthUser;
use crate::state::AppState;
use crate::transport::http::{
    ip_of, message_json, parse_state, require_role, validate_avatar, ApiErr, ApiResult, PageQuery,
    Q,
};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // §8.1 Online and nodes
        .route("/v1/admin/online", get(online))
        .route("/v1/admin/online/stats", get(online_stats))
        .route("/v1/admin/nodes", get(nodes))
        .route("/v1/admin/nodes/:id/drain", post(drain_start).get(drain_progress))
        .route("/v1/admin/queue", get(queue))
        .route("/v1/admin/queue/purge", post(queue_purge))
        .route("/v1/admin/stream", get(stream))
        .route("/v1/admin/metrics", get(metrics))
        // §8.2 Users/devices/quota/compliance delete
        .route("/v1/admin/users", get(users).post(users_create))
        // Profile changes (admin|ops) and password reset (admin only; ⑤ §8.2 account management completion)
        .route("/v1/admin/users/:id", patch(user_update))
        .route("/v1/admin/users/:id/password", post(user_password_reset))
        .route("/v1/admin/users/:id/quota", post(quota))
    .route("/v1/admin/users/:id/role", post(role_change))
        .route("/v1/admin/users/:id/suspend", post(suspend))
        .route("/v1/admin/users/:id/resume", post(resume))
        .route("/v1/admin/users/:id/purge", post(purge_start).get(purge_progress))
        // Operations cleanup hooks (REMAINING E02/E04): manually trigger one "hard-delete window"/"residual multipart GC" round,
        // same implementation as the background jobs (idempotent, locked, only WARN without blocking the node); admin + reason for the trail.
        .route(
            "/v1/admin/maintenance/purge-cleanup",
            post(maintenance_purge_cleanup),
        )
        .route(
            "/v1/admin/maintenance/gc-multipart",
            post(maintenance_gc_multipart),
        )
        .route("/v1/admin/devices", get(devices))
        .route("/v1/admin/devices/:id", delete(device_revoke))
        // §8.3 Sessions and message retrieval
        .route("/v1/admin/conversations", get(conversations))
        .route("/v1/admin/conversations/:id", get(conversation_detail))
        .route("/v1/admin/messages", get(messages))
        .route("/v1/admin/messages/:id/delivery", get(delivery))
        .route("/v1/admin/replay", post(replay))
        .route("/v1/admin/dlq", get(dlq))
        .route("/v1/admin/audit", get(audit))
        // §8.4 Plugins/formats/config/keys
        .route("/v1/admin/plugins", get(plugins).post(plugin_action))
        // WASM plugin invoke entry (PL-10): admin only; body {input_b64, entry?};
        // errors 422/500 carry details.reason (not_found/not_verified/circuit_open/timeout/…).
        .route(
            "/v1/admin/plugins/:ns/invoke",
            post(plugin_invoke)
                .layer(axum::extract::DefaultBodyLimit::max(12 * 1024 * 1024)),
        )
        .route("/v1/admin/plugins/:ns/stats", get(plugin_stats))
        // WASM plugin hot reload (PL-10 hot reload): admin; body optional {source:"all|dir|pg"} (default all).
        // Rebuild the registry atomically with one swap; on failure keep the old snapshot (500 + details.reason).
        .route(
            "/v1/admin/plugins/wasm/reload",
            post(plugin_wasm_reload),
        )
        .route("/v1/admin/formats", get(formats).post(format_upsert))
        .route("/v1/admin/config", get(config_get).patch(config_patch))
        .route("/v1/admin/keys/rotate", post(keys_rotate))
        // Unified degradation/dependency status (read-only; E20-G1/E26)
        .route("/v1/admin/degrade", get(degrade_get))
        .route("/v1/admin/keys", get(keys))
}

// ---------------------------------------------------------------------------
// §8.1 Online and nodes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OnlineQuery {
    user: Option<String>,
    device: Option<String>,
}

/// `GET /v1/admin/online`: device → node, connection age, protocol, remote IP summary.
async fn online(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Q(q): Q<OnlineQuery>,
) -> ApiResult<Response> {
    // Global connection inventory (not personal content): ops/admin only.
    require_role(&user, crate::auth::Role::Ops)?;
    let target = q
        .user
        .clone()
        .ok_or_else(|| ApiErr(LatticeError::protocol("user is required")))?;
    let devices = st.online_devices(&target).await;
    let local: Vec<Value> = st
        .hub
        .of_user(&target)
        .into_iter()
        .filter(|c| q.device.as_ref().map(|d| &c.device == d).unwrap_or(true))
        .map(|c| {
            json!({
                "device": c.device,
                "node": c.node_id,
                "protocol": "ws",
                "connected_at": chrono::Utc::now() - chrono::Duration::seconds(c.connected_at.elapsed().as_secs() as i64),
                "duration_s": c.connected_at.elapsed().as_secs(),
                "remote_ip": c.remote_ip,
                "caps": c.caps,
                "local": true,
            })
        })
        .collect();
    Ok(Json(json!({
        "user": target,
        "devices": local,
        "index": devices,
    }))
    .into_response())
}

/// `GET /v1/admin/online/stats`: online users/devices plus distribution by protocol and node.
///
/// Shares `live::online_payload` with the SSE `online` event, so the numbers cannot diverge ("two separate
/// calculations that disagree" — v0.13 cleanup).
async fn online_stats(State(st): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    Ok(Json(crate::live::online_payload(&st)).into_response())
}

/// `GET /v1/admin/nodes`: node list (heartbeat/connections/version/health).
async fn nodes(State(st): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    Ok(Json(crate::live::nodes_payload(&st).await).into_response())
}

#[derive(Debug, Deserialize)]
struct DrainReq {
    #[serde(default)]
    reason: String,
    #[serde(default = "default_wait")]
    wait_seconds: u64,
}

fn default_wait() -> u64 {
    30
}

/// `POST /v1/admin/nodes/{id}/drain`: remove from routing and drain, 202 + task id (⑤ §8.1).
async fn drain_start(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<DrainReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    if req.reason.trim().is_empty() {
        return Err(ApiErr(LatticeError::format("reason is required").with_reason("reason")));
    }
    if req.wait_seconds > 30 {
        return Err(ApiErr(
            LatticeError::format("wait_seconds must be <= 30").with_reason("wait_seconds"),
        ));
    }
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "node_drain",
        Some(&id),
        &json!({ "reason": req.reason, "wait_seconds": req.wait_seconds }),
        ip_of(&headers).as_deref(),
    )
    .await?;

    if id == st.node_id {
        let st2 = st.clone();
        tokio::spawn(async move {
            crate::transport::ws::drain_all(&st2).await;
        });
    }
    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(json!({ "task_id": lattice_core::ids::new_id(), "node_id": id, "state": "draining" })),
    )
        .into_response())
}

/// `GET /v1/admin/nodes/{id}/drain`: drain progress (remaining connections / byef frames sent).
async fn drain_progress(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    let remaining = if id == st.node_id { st.hub.len() } else { 0 };
    Ok(Json(json!({
        "node_id": id,
        "draining": st.draining.load(Ordering::Relaxed),
        "remaining_connections": remaining,
        "byef_sent": if st.draining.load(Ordering::Relaxed) { remaining } else { 0 },
    }))
    .into_response())
}

#[derive(Debug, Deserialize)]
struct QueueQuery {
    user: Option<String>,
    scope: Option<String>,
    /// Optional: only a given device queue (scope=device). Default = aggregate all device queues of the user.
    device: Option<String>,
    /// Optional: only a given topic queue (scope=topic). Default = aggregate all topic queues of the user.
    topic: Option<String>,
}

/// `GET /v1/admin/queue`: offline queue depths, oldest message time (three queue sets).
/// `GET /v1/admin/degrade`: unified degradation/dependency status (ops/admin read-only).
async fn degrade_get(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    Ok(Json(crate::degrade::summary(&st)).into_response())
}

async fn queue(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Q(q): Q<QueueQuery>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    let target = q
        .user
        .ok_or_else(|| ApiErr(LatticeError::protocol("user is required")))?;
    let (depth, oldest) = crate::routing::pending::depth(&st, &target).await;
    // §8.1 three queue sets: user is the aggregate; device/topic must be queryable by id and must also expose all queue details.
    // The old implementation hardcoded `dev-1` for device scope and did not query queues for topic scope (E17-D1).
    let mut device_depths = serde_json::Map::new();
    let mut topic_depths = serde_json::Map::new();
    let mut device_depth = 0i64;
    let mut topic_depth = 0i64;
    let scope = q.scope.clone().unwrap_or_else(|| "user".into());
    match scope.as_str() {
        "device" => {
            if let Some(dev) = q.device.as_deref() {
                let n = st
                    .redis
                    .pending_len(&lattice_core::keys::pending_device(&target, dev))
                    .await
                    .unwrap_or(0);
                device_depth = n;
                device_depths.insert(dev.to_string(), json!(n));
            } else {
                let keys = st
                    .redis
                    .scan_prefix(&format!("lattice:pending:{}:", target))
                    .await
                    .unwrap_or_default();
                for key in keys.into_iter().filter(|k| !k.contains(":topic:")) {
                    let n = st.redis.pending_len(&key).await.unwrap_or(0);
                    device_depth = device_depth.saturating_add(n);
                    if let Some(dev) = key.rsplit(':').next() {
                        device_depths.insert(dev.to_string(), json!(n));
                    }
                }
            }
        }
        "topic" => {
            if let Some(topic) = q.topic.as_deref() {
                let n = st
                    .redis
                    .pending_len(&lattice_core::keys::pending_topic(&target, topic))
                    .await
                    .unwrap_or(0);
                topic_depth = n;
                topic_depths.insert(topic.to_string(), json!(n));
            } else {
                let keys = st
                    .redis
                    .scan_prefix(&format!("lattice:pending:{}:topic:", target))
                    .await
                    .unwrap_or_default();
                for key in keys {
                    let n = st.redis.pending_len(&key).await.unwrap_or(0);
                    topic_depth = topic_depth.saturating_add(n);
                    if let Some(topic) = key.split(":topic:").nth(1) {
                        topic_depths.insert(topic.to_string(), json!(n));
                    }
                }
            }
        }
        "user" => {}
        other => {
            return Err(ApiErr(
                LatticeError::format(format!("unknown scope: {other}")).with_reason("scope"),
            ))
        }
    }
    Ok(Json(json!({
        "user": target,
        "scope": scope,
        "depth": depth,
        "oldest_seq": oldest,
        "device_depth": device_depth,
        "topic_depth": topic_depth,
        "device": q.device,
        "topic": q.topic,
        "device_depths": device_depths,
        "topic_depths": topic_depths,
    }))
    .into_response())
}

#[derive(Debug, Deserialize)]
struct PurgeQueueReq {
    user: String,
    scope: Option<String>,
    before_ts: Option<String>,
    reason: String,
}

/// `before_ts` accepts RFC3339 or unix seconds (⑤ §8.3 leaves the format open, so both are accepted).
fn parse_ts(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(d) = chrono::DateTime::parse_from_rfc3339(s.trim()) {
        return Some(d.with_timezone(&chrono::Utc));
    }
    chrono::DateTime::from_timestamp(s.trim().parse::<i64>().ok()?, 0)
}

/// `POST /v1/admin/queue/purge`: clean offline queues → `{removed}` (ops).
async fn queue_purge(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    headers: HeaderMap,
    Json(req): Json<PurgeQueueReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    if req.reason.trim().is_empty() {
        return Err(ApiErr(LatticeError::format("reason is required")));
    }
    // scope decides which pending class to clean (⑥ §3.1 three queue sets); concrete device/topic ids are discovered by scanning,
    // so the caller need not specify them (⑤ §8.3 only defines scope granularity).
    let scope = req.scope.as_deref().unwrap_or("user");
    let keys: Vec<String> = match scope {
        "user" => vec![lattice_core::keys::pending_user(&req.user)],
        "device" => st
            .redis
            .scan_prefix(&format!("lattice:pending:{}:", req.user))
            .await?
            .into_iter()
            .filter(|k| !k.contains(":topic:"))
            .collect(),
        "topic" => st
            .redis
            .scan_prefix(&format!("lattice:pending:{}:topic:", req.user))
            .await?,
        other => {
            return Err(ApiErr(
                LatticeError::format(format!("unknown scope: {other}")).with_reason("scope"),
            ))
        }
    };

    let cutoff = match req.before_ts.as_deref() {
        None => None,
        Some(s) => Some(parse_ts(s).ok_or_else(|| {
            ApiErr(
                LatticeError::format("before_ts must be RFC3339 or unix seconds")
                    .with_reason("before_ts"),
            )
        })?),
    };

    let mut removed = 0i64;
    for key in keys {
        match cutoff {
            // Whole-key cleanup
            None => {
                removed += st.redis.pending_len(&key).await.unwrap_or(0);
                st.redis.del(&key).await?;
            }
            // Time-based cleanup: pending scores are seq (⑥ §3.1), so time requires querying PG back
            Some(ts) => {
                for _ in 0..200 {
                    let batch = st.redis.pending_batch(&key, 500).await.unwrap_or_default();
                    if batch.is_empty() {
                        break;
                    }
                    let ids: Vec<String> = batch.iter().map(|(id, _)| id.clone()).collect();
                    let times: std::collections::HashMap<String, chrono::DateTime<chrono::Utc>> =
                        crate::store::pg::message_times(&st.db, &ids)
                            .await
                            .unwrap_or_default()
                            .into_iter()
                            .collect();
                    let mut purged = 0usize;
                    for (id, _) in &batch {
                        // Messages outside the 3-month window or already deleted return no time → treat as purgeable
                        if times.get(id).map(|t| *t < ts).unwrap_or(true) {
                            st.redis.pending_remove(&key, id).await.ok();
                            purged += 1;
                        }
                    }
                    removed += purged as i64;
                    if purged == 0 {
                        break;
                    }
                }
                if st.redis.pending_len(&key).await.unwrap_or(0) == 0 {
                    st.redis.del(&key).await.ok();
                }
            }
        }
    }
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "queue_purge",
        Some(&req.user),
        &json!({ "removed": removed, "reason": req.reason }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    Ok(Json(json!({ "removed": removed })).into_response())
}

/// `GET /v1/admin/stream`: SSE live stream (`online` 1s / `node` 2s / `deps` 5s + 30s `: ping`).
///
/// Data comes from three in-memory snapshots in the `live` module — **never computed inside a connection**: node lists `SCAN` Redis
/// and dependency health probes PG/Redis; computing per connection would multiply cost by 100 with 100 concurrent connections
/// (v0.13 fix, see ⑤ §8.5).
async fn stream(State(st): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    if st.metrics.sse_connections.get() as usize >= st.cfg.admin.sse_max_connections {
        return Err(ApiErr(
            LatticeError::rate("too many sse connections").with_reason("sse_limit"),
        ));
    }

    // The connection counter must be **returned when the connection ends**, otherwise after 100 connections it is 429 forever
    // (v0.13 fix: previously only `inc()` existed, no `dec()`). The guard lives in the stream's carried state and drops with it
    // when the stream ends (client disconnect / response dropped).
    let st2 = st.clone();
    let body = futures::stream::unfold((0u64, SseGuard::new(st.metrics.clone())), move |(seq, guard)| {
        let st3 = st2.clone();
        async move {
            // Send the first frame immediately: after connecting, nobody should wait 1s first
            if seq > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            let mut chunk = String::new();
            if seq % 30 == 29 {
                chunk.push_str(": ping\n\n");
            }
            chunk.push_str(&format!("id: {seq}\nevent: online\ndata: {}\n\n", st3.live.online()));
            if seq % 2 == 0 {
                chunk.push_str(&format!("event: node\ndata: {}\n\n", st3.live.nodes()));
            }
            if seq % 5 == 0 {
                chunk.push_str(&format!("event: deps\ndata: {}\n\n", st3.live.deps()));
            }
            Some((Ok::<_, std::convert::Infallible>(chunk), (seq + 1, guard)))
        }
    });

    let mut resp = axum::response::Response::new(axum::body::Body::from_stream(body));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/event-stream"),
    );
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    // nginx buffers text/event-stream by default, causing "pushed but the front end receives nothing"
    resp.headers_mut().insert(
        axum::http::HeaderName::from_static("x-accel-buffering"),
        axum::http::HeaderValue::from_static("no"),
    );
    Ok(resp)
}

/// SSE connection counter guard: returned on `Drop`, so disconnect or a dropped response both release it.
struct SseGuard(Arc<crate::observe::Metrics>);

impl SseGuard {
    fn new(metrics: Arc<crate::observe::Metrics>) -> Self {
        metrics.sse_connections.inc();
        Self(metrics)
    }
}

impl Drop for SseGuard {
    fn drop(&mut self) {
        self.0.sse_connections.dec();
    }
}

/// `GET /v1/admin/metrics`: Prometheus text (internal network only, ⑤ §8.1).
async fn metrics(State(st): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    let body = st.metrics.render();
    let mut resp = body.into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; version=0.0.4"),
    );
    Ok(resp)
}

// ---------------------------------------------------------------------------
// §8.2 Users / devices / quota / compliance delete
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct UserQuery {
    q: Option<String>,
    status: Option<String>,
    #[serde(flatten)]
    page: PageQuery,
}

async fn users(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Q(q): Q<UserQuery>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::User)?;
    let (page, size) = q.page.clamp();
    // `user` sees only its own row; ops/admin keep the global list (see `AuthUser::owner_scope`).
    let (rows, total) = crate::store::pg::list_users(
        &st.admin_db,
        user.owner_scope(),
        q.q.as_deref(),
        q.status.as_deref(),
        page,
        size,
    )
    .await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|u| {
            json!({
                "id": u.id, "username": u.username, "display_name": u.display_name,
                // v0.8 "user avatar": the admin list must render the avatar column (null = unset, the front end falls back to initials)
                "avatar": u.avatar,
                "status": u.status, "role": u.role, "quota": u.quota, "created_at": u.created_at,
            })
        })
        .collect();
    Ok(Json(json!({ "items": items, "total": total, "page": page, "page_size": size }))
        .into_response())
}

#[derive(Debug, Deserialize)]
struct CreateUserReq {
    username: String,
    password: String,
    display_name: Option<String>,
    /// Defaults to `user` (⑥ §2.3 DDL default).
    role: Option<String>,
}

/// **Write allowlist** for admin-plane roles: only `admin|ops|user` (⑤ §0.2, after the v0.7 rename).
///
/// The old value `viewer` is only tolerated on **read paths** for migration (`auth::jwt::Role::parse` degrades
/// it to `user`); write paths must reject it (422), otherwise the old name would be written back after the rename.
/// Missing (`raw = None`) falls back to least privilege: `user`.
fn writable_role(raw: Option<&str>) -> Result<&'static str, LatticeError> {
    let role = raw.unwrap_or("user").trim().to_ascii_lowercase();
    match role.as_str() {
        "admin" => Ok("admin"),
        "ops" => Ok("ops"),
        "user" => Ok("user"),
        _ => Err(LatticeError::format("invalid role")
            .with_detail("field", json!("role"))
            .with_detail("allowed", json!(["admin", "ops", "user"]))),
    }
}

/// `POST /v1/admin/users`: admin (⑤ §8.2) — create account.
///
/// Why on the admin plane instead of `POST /v1/users`: this platform has **no self-service signup** (⑤ §2 only has
/// `GET/PATCH /v1/users/{id}`). Accounts are created by administrators, the same source as "quota/role are changed by administrators",
/// avoiding the bypass where "anyone can register and can send messages immediately".
/// Default avatar for a new user: an abstract gradient SVG generated from the user id (no name/initials).
///
/// Product decision (2026-11-22): a new user immediately gets a good-looking random gradient avatar, not a name-based avatar.
/// Generation is deterministic (stable for the same id), adds no random dependency, and stores no external image; the server-generated
/// SVG data URL is written only here, while the user upload endpoint still rejects SVG (`validate_avatar` is not relaxed).
pub(crate) fn generated_gradient_avatar(seed: &str) -> String {
    const PALETTES: [(&str, &str, &str); 10] = [
        ("#FF8A65", "#FF4D8D", "#FFC46B"),
        ("#5B8CFF", "#7B61FF", "#54D6FF"),
        ("#22C55E", "#06B6D4", "#A3E635"),
        ("#F59E0B", "#EF4444", "#FDE68A"),
        ("#8B5CF6", "#EC4899", "#F0ABFC"),
        ("#0EA5E9", "#6366F1", "#22D3EE"),
        ("#14B8A6", "#0EA5E9", "#84CC16"),
        ("#F43F5E", "#FB7185", "#FBBF24"),
        ("#A855F7", "#3B82F6", "#2DD4BF"),
        ("#FB923C", "#F43F5E", "#A78BFA"),
    ];
    // FNV-1a: stable, dependency-free; different users get different palettes/angles/decoration positions.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in seed.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let (c1, c2, c3) = PALETTES[(h % PALETTES.len() as u64) as usize];
    let angle = (h / 7) % 360;
    let cx1 = 18 + (h / 11 % 70);
    let cy1 = 14 + (h / 13 % 60);
    let cx2 = 40 + (h / 17 % 55);
    let cy2 = 52 + (h / 19 % 45);
    let r1 = 34 + (h / 23 % 34);
    let r2 = 22 + (h / 29 % 26);
    let svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">
<defs>
<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1" gradientTransform="rotate({angle} 64 64)">
<stop offset="0" stop-color="{c1}"/><stop offset="1" stop-color="{c2}"/>
</linearGradient>
<radialGradient id="glow" cx="30%" cy="25%" r="75%">
<stop offset="0" stop-color="{c3}" stop-opacity=".72"/>
<stop offset="1" stop-color="{c3}" stop-opacity="0"/>
</radialGradient>
</defs>
<rect width="128" height="128" fill="url(#bg)"/>
<rect width="128" height="128" fill="url(#glow)"/>
<circle cx="{cx1}" cy="{cy1}" r="{r1}" fill="#fff" fill-opacity=".14"/>
<circle cx="{cx2}" cy="{cy2}" r="{r2}" fill="#fff" fill-opacity=".10"/>
<circle cx="100" cy="104" r="26" fill="#fff" fill-opacity=".07"/>
</svg>"##
    );
    format!("data:image/svg+xml;base64,{}", B64.encode(svg.as_bytes()))
}

async fn users_create(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    headers: HeaderMap,
    Json(req): Json<CreateUserReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;

    let username = req.username.trim().to_string();
    let ok_chars = username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if username.len() < 3 || username.len() > 64 || !ok_chars {
        return Err(ApiErr(
            LatticeError::format("invalid username")
                .with_detail("field", json!("username"))
                .with_detail("rule", json!("3-64 of [A-Za-z0-9._-]")),
        ));
    }

    // Password is only length-checked: complexity policy belongs to the upstream IdP/operations (② §6); the server does not reimplement it
    crate::auth::password::validate_password(&req.password).map_err(ApiErr)?;

    let role = writable_role(req.role.as_deref()).map_err(ApiErr)?;

    // Check before insert: the unique index also covers concurrency; this exists to return a readable 409 instead of a 500
    if crate::store::pg::user_by_username(&st.admin_db, &username)
        .await?
        .is_some()
    {
        return Err(ApiErr(
            LatticeError::conflict("username already exists").with_reason("username_taken"),
        ));
    }

    let hash = crate::auth::password::hash_password(&req.password)?;
    let created = match crate::store::pg::create_user(
        &st.admin_db,
        &username,
        &hash,
        req.display_name.as_deref(),
        role,
    )
    .await
    {
        Ok(u) => u,
        // Concurrent creation of the same name: the unique index error is 23505, mapped to 409 instead of 500
        Err(e) if e.to_string().contains("23505") => {
            return Err(ApiErr(
                LatticeError::conflict("username already exists").with_reason("username_taken"),
            ))
        }
        Err(e) => return Err(ApiErr(e)),
    };

    // A new user gets a generated abstract gradient avatar (no name/initials). Writing the avatar is best effort:
    // a failed write only WARNs and does not turn a successful creation into a 500; the response reflects what was persisted.
    let generated_avatar = generated_gradient_avatar(&created.id);
    let avatar = match crate::store::pg::set_user_profile(
        &st.admin_db,
        &created.id,
        None,
        Some(Some(generated_avatar.as_str())),
    )
    .await
    {
        Ok(Some(u)) => u.avatar,
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(user = %created.id, error = %e, "generated avatar persist failed");
            None
        }
    };

    // Write the audit only after the account is persisted (admin pool, longer statement_timeout) — same order as the existing
    // "create, then audit"; an audit write failure still returns 500 (never "audit failed but returned success"),
    // while keeping the existing boundary: in extreme cases the account exists and the caller gets 500, so verify and retry before recreating.
    // The audit write goes through the primary pool (`audit_emit` uses `st.db` / the NATS audit stream internally), decoupled from the create pool.
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "user.create",
        Some(&created.id),
        &json!({ "username": created.username, "role": created.role }),
        ip_of(&headers).as_deref(),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": created.id,
            "username": created.username,
            "display_name": created.display_name,
            "avatar": avatar,
            "status": created.status,
            "role": created.role,
            "created_at": created.created_at,
        })),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Account management completion: update user profile (admin|ops) + reset password (admin only)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct UpdateUserReq {
    /// New display name; empty string = clear (`users.display_name` allows null).
    ///
    /// `Option`: omitting the field = keep the display name (v0.8 supports "avatar-only" admin updates);
    /// give at least one of name/avatar, otherwise 422 `reason=no_fields`.
    #[serde(default)]
    display_name: Option<String>,
    /// New avatar; empty string = clear. Omitted = keep.
    /// Accepts an `https://` URL or `data:image/(png|jpeg|webp|gif);base64,...` (≤256KiB);
    /// other formats → 422 `details.field=avatar` (shares `validate_avatar` with the self-service endpoint).
    #[serde(default)]
    avatar: Option<String>,
    /// Trail for the dangerous operation (⑤ §8: reason is required and written to `audit_log.detail`).
    reason: String,
}

/// Unified validation for the required reason on dangerous operations (422 FORMAT + `details.reason=reason`).
fn required_reason(raw: &str) -> std::result::Result<&str, LatticeError> {
    let reason = raw.trim();
    if reason.is_empty() {
        return Err(LatticeError::format("reason is required").with_reason("reason"));
    }
    Ok(reason)
}

/// `PATCH /v1/admin/users/{id}`: administrator/operations update user profile (`display_name` / `avatar`).
///
/// - RBAC: `admin|ops` (ops boundary per the task: may maintain account data, but cannot reset passwords/create accounts/change roles);
/// - username/role/status/quota/capabilities are not on this endpoint: role has its own §8.2 endpoint,
///   username is the stable identifier for login and audit and **cannot be changed**, and the other fields each have dedicated endpoints;
/// - every field is optional (omitted = keep; empty = clear), but at least one is required, otherwise 422 `reason=no_fields`;
/// - writes `audit_log(action=user.update)`; **detail carries no avatar body** (a data URL can reach 256KiB),
///   only an `avatar_changed` boolean; returns the updated user row (`password_hash` is never returned).
async fn user_update(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<UpdateUserReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    let reason = required_reason(&req.reason).map_err(ApiErr)?;
    if req.display_name.is_none() && req.avatar.is_none() {
        return Err(ApiErr(
            LatticeError::format("at least one of display_name/avatar is required")
                .with_reason("no_fields"),
        ));
    }
    let target = crate::store::pg::user_by_id(&st.db, &id)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("user not found")))?;
    if target.status == "deleted" {
        return Err(ApiErr(LatticeError::not_found("user not found")));
    }

    // Display name: empty after trim = clear; omitted = keep
    let raw_name = req.display_name.map(|s| s.trim().to_string());
    let name_arg: Option<Option<&str>> = raw_name
        .as_deref()
        .map(|s| if s.is_empty() { None } else { Some(s) });
    // Avatar: shares the same validation as the self-service endpoint (empty clears / https / data URL ≤256KiB)
    let had_avatar_field = req.avatar.is_some();
    let next_avatar = validate_avatar(req.avatar.as_deref()).map_err(ApiErr)?;
    let avatar_changed = had_avatar_field && next_avatar != target.avatar;
    let avatar_arg: Option<Option<&str>> = if had_avatar_field {
        Some(next_avatar.as_deref())
    } else {
        None
    };

    let updated = crate::store::pg::set_user_profile(&st.db, &id, name_arg, avatar_arg)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("user not found")))?;
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "user.update",
        Some(&id),
        // Note: **do not record the avatar body**, only "changed or not" (a data URL can reach 256KiB)
        &json!({
            "display_name": updated.display_name,
            "previous_display_name": target.display_name,
            "avatar_changed": avatar_changed,
            "reason": reason,
        }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    Ok(Json(json!({
        "id": updated.id,
        "username": updated.username,
        "display_name": updated.display_name,
        "avatar": updated.avatar,
        "status": updated.status,
        "role": updated.role,
        "quota": updated.quota,
        "created_at": updated.created_at,
        "updated_at": updated.updated_at,
    }))
    .into_response())
}

#[derive(Debug, Deserialize)]
struct ResetPasswordReq {
    new_password: String,
    reason: String,
}

/// `POST /v1/admin/users/{id}/password`: administrator resets a user password (admin only, ⑤ §8.2).
///
/// Security semantics:
/// - rehash with argon2id (§17.11); the response only returns `{ok, user_id, sessions_revoked}` and **never echoes** the password/hash;
/// - immediately revoke **all** active device refresh tokens of the user (`devices.revoked_at`) and close online connections,
///   so the old refresh chain cannot renew; the access JWT is a stateless snapshot (⑤ §0.2) and lives at most one more TTL;
/// - writes `audit_log(action=user.password_reset)`; detail contains no password material.
async fn user_password_reset(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<ResetPasswordReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    let reason = required_reason(&req.reason).map_err(ApiErr)?;
    // Length baseline shared with admin account creation and self-service password change (auth::password::validate_password)
    crate::auth::password::validate_password(&req.new_password).map_err(ApiErr)?;
    let target = crate::store::pg::user_by_id(&st.db, &id)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("user not found")))?;
    if target.status == "deleted" {
        return Err(ApiErr(LatticeError::not_found("user not found")));
    }
    let hash = crate::auth::password::hash_password(&req.new_password)?;
    if !crate::store::pg::set_user_password(&st.db, &id, &hash).await? {
        return Err(ApiErr(LatticeError::not_found("user not found")));
    }
    let sessions_revoked = crate::store::pg::revoke_user_devices(&st.db, &id, None).await?;
    // Live WS connections are closed too: otherwise the old access token still works on an established connection
    for c in st.hub.of_user(&id) {
        let _ = c.tx.try_send(crate::state::shutdown_frame("logout"));
    }
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "user.password_reset",
        Some(&id),
        &json!({ "reason": reason, "sessions_revoked": sessions_revoked }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    Ok(Json(json!({
        "ok": true,
        "user_id": id,
        "sessions_revoked": sessions_revoked,
    }))
    .into_response())
}

#[derive(Debug, Deserialize)]
struct QuotaReq {
    msg_per_s: Option<u32>,
    bytes_per_s: Option<u64>,
    topics: Option<u32>,
    storage_bytes: Option<u64>,
    reason: Option<String>,
}

/// `POST /v1/admin/users/{id}/quota`: admin.
async fn quota(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<QuotaReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    let target = crate::store::pg::user_by_id(&st.db, &id)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("user not found")))?;
    let mut quota = if target.quota.as_object().map(|o| o.is_empty()).unwrap_or(true) {
        serde_json::to_value(st.quota()).unwrap_or(json!({}))
    } else {
        target.quota.clone()
    };
    if let Value::Object(map) = &mut quota {
        if let Some(v) = req.msg_per_s {
            map.insert("msg_per_s".into(), json!(v));
        }
        if let Some(v) = req.bytes_per_s {
            map.insert("bytes_per_s".into(), json!(v));
        }
        if let Some(v) = req.topics {
            map.insert("topics".into(), json!(v));
        }
        if let Some(v) = req.storage_bytes {
            map.insert("storage_bytes".into(), json!(v));
        }
    }
    crate::store::pg::set_user_quota(&st.db, &id, &quota).await?;
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "quota_update",
        Some(&id),
        &json!({ "quota": quota, "reason": req.reason }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    Ok(Json(json!({ "id": id, "quota": quota })).into_response())
}

#[derive(Debug, Deserialize)]
struct RoleReq {
    role: String,
    reason: Option<String>,
}

/// `POST /v1/admin/users/{id}/role`: admin (⑤ §8.2).
///
/// The role is written to `users.role` (⑥ §2.3, **authoritative**); the `role` in tokens is a snapshot and takes effect
/// at the latest after one TTL (900s) — for immediate effect, revoke the user's devices (⑤ §0.2 "role source").
async fn role_change(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<RoleReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    // Writes accept only admin|ops|user; the old value viewer is always 422 (compatibility is read-path only)
    let role = writable_role(Some(&req.role)).map_err(ApiErr)?;
    let target = crate::store::pg::user_by_id(&st.db, &id)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("user not found")))?;
    // Prevent demoting the last admin, which would lock the admin plane forever
    if target.role == "admin" && role != "admin" {
        let admins = crate::store::pg::count_users_by_role(&st.db, "admin").await?;
        if admins <= 1 {
            return Err(ApiErr(LatticeError::conflict("last admin cannot be demoted")
                .with_reason("last_admin")));
        }
    }
    let updated = crate::store::pg::set_user_role(&st.db, &id, role).await?;
    if !updated {
        return Err(ApiErr(LatticeError::not_found("user not found")));
    }
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "role.change",
        Some(&id),
        &json!({ "from": target.role, "to": role, "reason": req.reason }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    Ok(Json(json!({
        "id": id,
        "role": role,
        "previous": target.role,
        "effective_within_s": st.cfg.auth.jwt_ttl,
    }))
    .into_response())
}

async fn suspend(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    set_status(st, user, id, "suspended", headers).await
}

async fn resume(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    set_status(st, user, id, "active", headers).await
}

async fn set_status(
    st: Arc<AppState>,
    user: AuthUser,
    id: String,
    status: &str,
    headers: HeaderMap,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    let ok = crate::store::pg::set_user_status(&st.db, &id, status).await?;
    if !ok {
        return Err(ApiErr(LatticeError::not_found("user not found")));
    }
    if status == "suspended" {
        // In-flight connections are closed per policy (⑤ §8.2)
        for c in st.hub.of_user(&id) {
            let _ = c.tx.try_send(crate::state::shutdown_frame("logout"));
        }
    }
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        if status == "suspended" { "user_suspend" } else { "user_resume" },
        Some(&id),
        &json!({ "status": status }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    Ok(Json(json!({ "id": id, "status": status })).into_response())
}

#[derive(Debug, Deserialize)]
struct PurgeReq {
    #[serde(default)]
    reason: String,
    #[serde(default)]
    confirm_username: String,
}

/// `POST /v1/admin/users/{id}/purge`: compliance cascade delete, 202 + task id (admin, ⑤ §8.2).
async fn purge_start(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<PurgeReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    if req.reason.trim().is_empty() {
        return Err(ApiErr(LatticeError::format("reason is required").with_reason("reason")));
    }
    let target = crate::store::pg::user_by_id(&st.db, &id)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("user not found")))?;
    if req.confirm_username != target.username {
        return Err(ApiErr(
            LatticeError::format("confirm_username mismatch").with_reason("confirm_username"),
        ));
    }
    let counts = crate::store::pg::purge_counts(&st.db, &id).await?;
    crate::store::pg::soft_delete_user(&st.db, &id).await?;
    // Basic Redis cleanup (⑥ §3.4): two connection layers, three pending sets, subscription cache, rate-limit buckets, MQTT
    // session/WILL keys (user/device dimensions). Full-scope dimensions (upload sessions/media tunnels/risk-control observation keys)
    // continue in background cleanup, so admin requests are not slowed by scanning a large keyspace.
    st.redis
        .del(&lattice_core::keys::pending_user(&id))
        .await
        .ok();
    let redis_keys_deleted = match crate::jobs::purge_user_redis_keys_basic(&st, &id).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, user = %id, "purge: basic redis cleanup failed (background retry)");
            0
        }
    };
    for c in st.hub.of_user(&id) {
        let _ = c.tx.try_send(crate::state::shutdown_frame("logout"));
    }
    // Background cascade residual cleanup (objects + chunks + message/delivery rows + all Redis dimensions): idempotent, retryable;
    // progress in `lattice:purge:{user}`, visible as the `cleanup` field of `GET /users/{id}/purge`.
    {
        let bg = st.clone();
        let uid = id.clone();
        tokio::spawn(async move {
            match crate::jobs::purge_user_residuals(&bg, &uid, usize::MAX / 2).await {
                Ok(s) if s.complete => tracing::info!(
                    user = %uid,
                    messages = s.messages_deleted,
                    objects = s.objects_deleted,
                    redis_keys = s.redis_keys_deleted,
                    "purge: cascade cleanup complete (background)"
                ),
                Ok(s) => tracing::warn!(
                    user = %uid,
                    messages = s.messages_deleted,
                    objects = s.objects_deleted,
                    objects_failed = s.objects_failed,
                    "purge: cascade cleanup incomplete (will retry)"
                ),
                Err(e) => tracing::warn!(error = %e, user = %uid, "purge: cascade cleanup failed"),
            }
        });
    }
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "user_purge",
        Some(&id),
        &json!({
            "reason": req.reason,
            "progress": counts,
            "cleanup": "queued",
            "redis_keys_deleted": redis_keys_deleted,
        }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(json!({
            "task_id": lattice_core::ids::new_id(),
            "user_id": id,
            "progress": counts,
            "cleanup": {
                "phase": "queued",
                "redis_keys_deleted": redis_keys_deleted,
            },
        })),
    )
        .into_response())
}

/// `GET /v1/admin/users/{id}/purge`: delete task progress.
///
/// Returns three blocks (backward compatible: `progress` keeps the original PG/MinIO/Redis item counts):
/// - `progress`: raw purge_counts items (pg_messages/pg_devices/minio_objects);
/// - `cleanup`: background cascade cleanup progress (phase/messages_deleted/objects_deleted/..., null if none);
/// - `residual`: measured residual right now (PG messages/chunks/delivery rows + user status + recorded object key count).
async fn purge_progress(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    let counts = crate::store::pg::purge_counts(&st.db, &id).await?;
    let cleanup = crate::jobs::load_purge_progress(&st, &id)
        .await
        .map_err(ApiErr)?;
    let residual = crate::jobs::purge_residual_counts(&st, &id)
        .await
        .map_err(ApiErr)?;
    Ok(Json(json!({
        "user_id": id,
        "progress": counts,
        "cleanup": cleanup,
        "residual": residual,
    }))
    .into_response())
}

// ---------------------------------------------------------------------------
// Operations cleanup hooks (REMAINING E02 hard-delete window / E04 residual multipart GC)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct MaintenanceReq {
    #[serde(default)]
    reason: String,
}

/// `POST /v1/admin/maintenance/purge-cleanup`: manually run one hard-delete window round (admin).
///
/// Same implementation as the background job: processes only `status='deleted'` users past `[compliance]
/// purge_hard_delete_days`; residual cleanup completes first (objects first, rows after), then the user row goes.
/// For immediate operator execution / deterministic E2E; normal deployments let the background job do it on schedule.
async fn maintenance_purge_cleanup(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    headers: HeaderMap,
    Json(req): Json<MaintenanceReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    if req.reason.trim().is_empty() {
        return Err(ApiErr(LatticeError::format("reason is required").with_reason("reason")));
    }
    let summary = crate::jobs::purge_cleanup_once(&st).await.map_err(ApiErr)?;
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "purge.cleanup",
        None,
        &json!({
            "reason": req.reason,
            "window_days": st.cfg.compliance.effective_hard_delete_days(),
            "due": summary.due,
            "deleted": summary.deleted,
            "pending": summary.pending,
            "failed": summary.failed,
        }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    Ok(Json(json!({
        "window_days": st.cfg.compliance.effective_hard_delete_days(),
        "due": summary.due,
        "deleted": summary.deleted,
        "pending": summary.pending,
        "failed": summary.failed,
    }))
    .into_response())
}

/// `POST /v1/admin/maintenance/gc-multipart`: manually run one residual multipart GC round (admin).
///
/// Same implementation as background `lock:gc-multipart`; only unfinished uploads are aborted, completed objects untouched.
async fn maintenance_gc_multipart(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    headers: HeaderMap,
    Json(req): Json<MaintenanceReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    let summary = crate::jobs::gc_multipart_once(&st).await.map_err(ApiErr)?;
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "multipart.gc",
        None,
        &json!({
            "reason": req.reason,
            "age_hours": st.cfg.maintenance.multipart_gc_hours,
            "buckets": summary.buckets,
            "scanned_uploads": summary.scanned_uploads,
            "aged_uploads": summary.aged_uploads,
            "aborted": summary.aborted,
            "errors": summary.errors,
        }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    Ok(Json(json!({
        "enabled": summary.enabled,
        "age_hours": st.cfg.maintenance.multipart_gc_hours,
        "buckets": summary.buckets,
        "scanned_uploads": summary.scanned_uploads,
        "aged_uploads": summary.aged_uploads,
        "aborted": summary.aborted,
        "errors": summary.errors,
    }))
    .into_response())
}

#[derive(Debug, Deserialize)]
struct DeviceQuery {
    user: Option<String>,
    revoked: Option<bool>,
}

async fn devices(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Q(q): Q<DeviceQuery>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::User)?;
    // A per-account caller may not widen the filter to somebody else: `scope` always wins.
    let scope = user.owner_scope();
    let filter_user = if scope.is_some() { scope } else { q.user.as_deref() };
    let rows =
        crate::store::pg::list_devices_admin(&st.admin_db, scope, filter_user, q.revoked).await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|d| {
            json!({
                "id": d.id, "user_id": d.user_id, "name": d.name, "platform": d.platform,
                "fingerprint": d.fingerprint, "last_seen": d.last_seen, "revoked_at": d.revoked_at,
            })
        })
        .collect();
    Ok(Json(json!({ "items": items })).into_response())
}

/// `DELETE /v1/admin/devices/{id}`: revoke a device.
///
/// Ops/admin may revoke any device; the `user` tier may only revoke its **own** device
/// (self-service "sign out this device"), which is still an operation on its own content.
async fn device_revoke(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let dev = crate::store::pg::device_by_id(&st.db, &id)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("device not found")))?;
    if user.owner_scope().is_some() {
        if dev.user_id != user.user_id {
            return Err(ApiErr(
                LatticeError::forbidden("can only revoke your own devices").with_reason("rbac"),
            ));
        }
    } else {
        require_role(&user, crate::auth::Role::Ops)?;
    }
    crate::store::pg::revoke_device(&st.db, &id).await?;
    st.unregister_online(&dev.user_id, &dev.id).await;
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "device_revoke",
        Some(&id),
        &json!({ "user_id": dev.user_id }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    Ok(axum::http::StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// §8.3 Sessions and message retrieval
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ConvQuery {
    q: Option<String>,
    kind: Option<String>,
    #[serde(flatten)]
    page: PageQuery,
}

async fn conversations(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Q(q): Q<ConvQuery>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::User)?;
    let (page, size) = q.page.clamp();
    // `user` only sees conversations (including topics) it is a member of.
    let (rows, total) = crate::store::pg::list_conversations_admin(
        &st.admin_db,
        user.owner_scope(),
        q.q.as_deref(),
        q.kind.as_deref(),
        page,
        size,
    )
    .await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|c| json!({
            "id": c.id, "kind": c.kind, "name": c.name,
            "members": c.members, "last_seq": c.last_seq, "last_msg_at": c.last_msg_at,
        }))
        .collect();
    Ok(Json(json!({ "items": items, "total": total })).into_response())
}

async fn conversation_detail(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::User)?;
    let conv = crate::store::pg::conversation_by_id(&st.admin_db, &id)
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("conversation not found")))?;
    if let Some(scope) = user.owner_scope() {
        // 404 rather than 403: do not confirm that somebody else's conversation exists.
        if !crate::store::pg::is_conversation_member(&st.admin_db, &id, scope).await? {
            return Err(ApiErr(LatticeError::not_found("conversation not found")));
        }
    }
    let members = crate::store::pg::members_of(&st.admin_db, &id).await?;
    Ok(Json(json!({
        "id": conv.id, "kind": conv.kind, "name": conv.name, "created_at": conv.created_at,
        "members": members.iter().map(|m| json!({"user_id": m.user_id, "role": m.role})).collect::<Vec<_>>(),
    }))
    .into_response())
}

#[derive(Debug, Deserialize)]
struct MsgQuery {
    id: Option<String>,
    conv: Option<String>,
    user: Option<String>,
    state: Option<String>,
    #[serde(flatten)]
    page: PageQuery,
}

/// `GET /v1/admin/messages`: **metadata** search (payload never returned, ⑤ §8.3).
/// At massive message volume there must be at least one highly selective condition (⑤ §13 I2).
async fn messages(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Q(q): Q<MsgQuery>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::User)?;
    if q.id.is_none() && q.conv.is_none() && q.user.is_none() {
        return Err(ApiErr(
            LatticeError::format("at least one of id/conv/user is required")
                .with_reason("selectivity"),
        ));
    }
    if let Some(state) = q.state.as_deref() {
        parse_state(state)?;
    }
    if let Some(scope) = user.owner_scope() {
        // Explicitly asking for another account's messages is refused; filters on a
        // conversation/id simply resolve to "nothing" when the caller is not a participant.
        if let Some(who) = q.user.as_deref() {
            if who != scope {
                return Err(ApiErr(
                    LatticeError::forbidden("can only read your own messages").with_reason("rbac"),
                ));
            }
        }
    }
    let (page, size) = q.page.clamp();
    let rows = crate::store::pg::search_messages_admin(
        &st.admin_db,
        user.owner_scope(),
        q.id.as_deref(),
        q.conv.as_deref(),
        q.user.as_deref(),
        q.state.as_deref(),
        page,
        size,
    )
    .await?;
    let items: Vec<Value> = rows.iter().map(message_json).collect();
    Ok(Json(json!({ "items": items, "page": page, "page_size": size })).into_response())
}

/// `GET /v1/admin/messages/{id}/delivery`: delivery details (all-device view).
async fn delivery(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::User)?;
    if let Some(scope) = user.owner_scope() {
        // Delivery details of somebody else's message must look nonexistent.
        if !crate::store::pg::message_visible_to(&st.admin_db, &id, scope).await? {
            return Err(ApiErr(LatticeError::not_found("message not found")));
        }
    }
    let rows = crate::store::pg::delivery_of(&st.admin_db, &id).await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|d| json!({
            "to_user": d.to_user, "device": d.to_device, "state": d.state,
            "attempts": d.attempts, "last_at": d.last_at, "acked_at": d.acked_at,
        }))
        .collect();
    Ok(Json(json!({ "id": id, "deliveries": items })).into_response())
}

#[derive(Debug, Deserialize)]
struct ReplayReq {
    #[serde(default)]
    msg_ids: Vec<String>,
    #[serde(default)]
    reason: String,
}

/// `POST /v1/admin/replay`: dead-letter replay `{accepted, rejected[]}` (ops).
async fn replay(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    headers: HeaderMap,
    Json(req): Json<ReplayReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    if req.reason.trim().is_empty() {
        return Err(ApiErr(LatticeError::format("reason is required").with_reason("reason")));
    }
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for id in &req.msg_ids {
        match crate::store::pg::message_by_id(&st.db, id).await {
            Ok(Some(msg)) => {
                // Reset to routed and enqueue again (§4.1: dlq items can be manually replayed back to routed)
                for d in crate::store::pg::delivery_of(&st.db, id).await.unwrap_or_default() {
                    if d.state == "dlq" {
                        let _ = crate::store::pg::mark_delivery_state(&st.db, id, &d.to_device, "routed")
                            .await;
                        let _ = crate::routing::pending::enqueue_user(
                            &st,
                            &d.to_user,
                            msg.seq,
                            id,
                        )
                        .await;
                        // E19: admin DLQ replay also advances delivery_log state → delivery event stream
                        // (NATS mode has the background pipeline emit audit.log; Redis mode is a no-op and does not affect delivery decisions).
                        crate::routing::audit::spawn_delivery_event(
                            &st,
                            id,
                            &d.to_user,
                            &d.to_device,
                            "routed",
                        );
                    }
                }
                accepted.push(id.clone());
            }
            _ => rejected.push(id.clone()),
        }
    }
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "dlq_replay",
        None,
        &json!({ "accepted": accepted, "rejected": rejected, "reason": req.reason }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(json!({ "accepted": accepted, "rejected": rejected })),
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
struct DlqQuery {
    conv: Option<String>,
    user: Option<String>,
    #[serde(flatten)]
    page: PageQuery,
}

async fn dlq(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Q(q): Q<DlqQuery>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    let (page, size) = q.page.clamp();
    let rows = crate::store::pg::dlq_list(&st.admin_db, q.conv.as_deref(), q.user.as_deref(), page, size)
        .await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|d| json!({
            "msg_id": d.msg_id, "to_user": d.to_user, "device": d.to_device,
            "attempts": d.attempts, "last_at": d.last_at,
        }))
        .collect();
    Ok(Json(json!({ "items": items })).into_response())
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    actor: Option<String>,
    action: Option<String>,
    #[serde(flatten)]
    page: PageQuery,
}

/// `GET /v1/admin/audit`: audit search.
///
/// Note: the route appears in doc ② §3.2's implementation index and the console Audit page, but **doc ⑤ §8 does not define it** —
/// implemented in the ② shape, pending an entry in ⑤ (see README "documentation issues found while implementing").
async fn audit(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Q(q): Q<AuditQuery>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    let (page, size) = q.page.clamp();
    let (rows, total) =
        crate::store::pg::audit_list(&st.admin_db, q.actor.as_deref(), q.action.as_deref(), page, size)
            .await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|a| json!({
            "id": a.id, "actor": a.actor, "action": a.action, "target": a.target,
            "detail": a.detail, "created_at": a.created_at,
        }))
        .collect();
    Ok(Json(json!({ "items": items, "total": total })).into_response())
}

// ---------------------------------------------------------------------------
// §8.4 Plugins / formats / config / keys
// ---------------------------------------------------------------------------

async fn plugins(State(st): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    let rows = crate::store::pg::plugins_all(&st.admin_db).await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|p| json!({
            "id": p.id, "ns": p.ns, "version": p.version, "status": p.status,
            "canary_ratio": p.canary_ratio, "form": if p.sidecar_addr.is_some() { "sidecar" } else { "wasm" },
            "published_at": p.published_at,
        }))
        .collect();
    // Append the runtime state of wasm directory plugins (signature/load status); the existing `items` (PG-published plugins) fields/semantics are unchanged.
    Ok(Json(json!({
        "items": items,
        "wasm": crate::plugins::wasm_status(),
    }))
    .into_response())
}

#[derive(Debug, Deserialize)]
struct PluginActionReq {
    ns: String,
    version: i32,
    action: String,
    #[serde(default)]
    ratio: i32,
    #[serde(default)]
    reason: String,
}

/// `POST /v1/admin/plugins`: publish/rollback/canary (admin).
async fn plugin_action(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    headers: HeaderMap,
    Json(req): Json<PluginActionReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    if req.reason.trim().is_empty() {
        return Err(ApiErr(LatticeError::format("reason is required").with_reason("reason")));
    }
    if !matches!(req.action.as_str(), "publish" | "rollback" | "canary") {
        return Err(ApiErr(LatticeError::format("invalid action").with_reason("action")));
    }
    crate::store::pg::plugin_publish(&st.db, &req.ns, req.version, &req.action, req.ratio).await?;
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "plugin_action",
        Some(&req.ns),
        &json!({ "action": req.action, "version": req.version, "ratio": req.ratio, "reason": req.reason }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    // Refresh the runtime snapshot (used for canary decisions)
    if let Ok(rows) = crate::store::pg::plugins_all(&st.db).await {
        let entries: Vec<lattice_plugins::registry::PluginEntry> = rows
            .iter()
            .map(|p| lattice_plugins::registry::PluginEntry {
                ns: p.ns.clone(),
                version: p.version as u32,
                status: lattice_plugins::registry::PluginStatus::parse(&p.status)
                    .unwrap_or(lattice_plugins::registry::PluginStatus::Staging),
                canary_ratio: p.canary_ratio as u32,
                form: if p.sidecar_addr.is_some() { "sidecar".into() } else { "wasm".into() },
            })
            .collect();
        if let Ok(mut w) = st.plugins.write() {
            *w = entries;
        }
    }
    Ok(Json(json!({ "ns": req.ns, "version": req.version, "action": req.action })).into_response())
}

/// `GET /v1/admin/plugins/{ns}/stats`: latency/failure rate/peak memory (source: Prometheus).
async fn plugin_stats(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    Path(ns): Path<String>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    let body = st.metrics.render();
    Ok(Json(json!({
        "ns": ns,
        "window": "1h",
        "source": "prometheus_text",
        "raw_contains_plugin_metric": body.contains("lattice_plugin_call_duration_seconds"),
    }))
    .into_response())
}

#[derive(Debug, Deserialize)]
struct PluginInvokeReq {
    /// base64 of the input bytes (standard or URL-safe, padding optional).
    input_b64: String,
    /// Optionally override the entry export name (default is the manifest.entry/`process` resolved at registration).
    #[serde(default)]
    entry: Option<String>,
}

/// Decode invoke input (lenient base64; failure 422 `FORMAT` + `details.reason=input_b64`).
fn decode_invoke_input(raw: &str) -> ApiResult<Vec<u8>> {
    let s = raw.trim();
    let decoded = B64
        .decode(s)
        .or_else(|_| B64_NO_PAD.decode(s))
        .or_else(|_| B64_URL.decode(s))
        .or_else(|_| B64_URL_NO_PAD.decode(s));
    decoded.map_err(|_| {
        ApiErr(
            LatticeError::format("input_b64 is not valid base64 (standard or url-safe)")
                .with_reason("input_b64"),
        )
    })
}

/// `POST /v1/admin/plugins/{ns}/invoke` (admin; PL-10 invoke wiring).
///
/// Request: `{ "input_b64": "<base64>", "entry": "<optional export name>" }`
/// Success: `{ output_b64, output_bytes, elapsed_ms, plugin, version, entry, fuel_used }`
/// Failure: 422 (not_found / not_verified / bad_abi / missing_export / manifest) or
///       500 (circuit_open / timeout / trap / memory / fuel / busy / exit_code / internal),
///       body carries `details.reason` and `details.plugin`.
///
/// Audit: `plugin.wasm.invoke` records only plugin/entry/size/elapsed/result, **never raw input/output**.
async fn plugin_invoke(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    headers: HeaderMap,
    Path(ns): Path<String>,
    Json(req): Json<PluginInvokeReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    let input = decode_invoke_input(&req.input_b64)?;
    let entry = req
        .entry
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(entry) = entry {
        if entry.len() > 256 || !entry.chars().all(|c| c.is_ascii_graphic()) {
            return Err(ApiErr(
                LatticeError::format("entry must be <=256 printable ASCII chars")
                    .with_reason("entry"),
            ));
        }
    }
    let started = std::time::Instant::now();
    match crate::plugins::invoke(&ns, &input, entry) {
        Ok(out) => {
            tracing::info!(
                plugin = %out.plugin,
                version = out.version,
                entry = %out.entry,
                input_bytes = input.len(),
                output_bytes = out.output.len(),
                elapsed_ms = out.elapsed_ms,
                "wasm plugin invoked"
            );
            crate::routing::audit::audit_emit(
                &st,
                Some(&user.user_id),
                "plugin.wasm.invoke",
                Some(&ns),
                &json!({
                    "plugin": out.plugin,
                    "version": out.version,
                    "entry": out.entry,
                    "input_bytes": input.len(),
                    "output_bytes": out.output.len(),
                    "elapsed_ms": out.elapsed_ms,
                    "outcome": "ok",
                }),
                ip_of(&headers).as_deref(),
            )
            .await?;
            Ok(Json(json!({
                "plugin": out.plugin,
                "version": out.version,
                "entry": out.entry,
                "output_b64": B64.encode(&out.output),
                "output_bytes": out.output.len(),
                "elapsed_ms": out.elapsed_ms,
                "fuel_used": out.fuel_used,
            }))
            .into_response())
        }
        Err(fail) => {
            // Failures are audited too (only reason/size/elapsed); audit failure does not override the plugin error semantics (WARN level).
            let audit = json!({
                "plugin": ns,
                "entry": entry,
                "input_bytes": input.len(),
                "elapsed_ms": started.elapsed().as_millis() as u64,
                "outcome": fail.reason,
            });
            if let Err(e) = crate::routing::audit::audit_emit(
                &st,
                Some(&user.user_id),
                "plugin.wasm.invoke",
                Some(&ns),
                &audit,
                ip_of(&headers).as_deref(),
            )
            .await
            {
                tracing::warn!(plugin = %ns, reason = %fail.reason, error = %e, "plugin invoke audit failed");
            }
            let err = if fail.http_status == 422 {
                LatticeError::format(fail.message)
            } else {
                LatticeError::plugin(fail.message)
            };
            Err(ApiErr(
                err.with_reason(fail.reason)
                    .with_detail("plugin", json!(ns)),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// WASM plugin hot reload (PL-10 hot reload / ② §4.5)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct PluginWasmReloadReq {
    /// Hot-reload source: `all` (default)/`dir`/`pg`; only that source is re-read, the other keeps the previous snapshot.
    #[serde(default)]
    source: Option<String>,
}

/// Parse the body: empty body / `{}` = `all`; invalid JSON 422 `body`; invalid source 422 `source`.
fn parse_wasm_reload_source(body: &[u8]) -> ApiResult<crate::plugins::ReloadSource> {
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(crate::plugins::ReloadSource::All);
    }
    let req: PluginWasmReloadReq = serde_json::from_slice(body).map_err(|_| {
        ApiErr(
            LatticeError::format("body must be a JSON object like {\"source\":\"all|dir|pg\"}")
                .with_reason("body"),
        )
    })?;
    match req.source.as_deref() {
        None => Ok(crate::plugins::ReloadSource::All),
        Some(raw) => crate::plugins::ReloadSource::parse(raw).ok_or_else(|| {
            ApiErr(
                LatticeError::format(format!("invalid source `{raw}` (all|dir|pg)"))
                    .with_reason("source"),
            )
        }),
    }
}

/// `ReloadFailure` → ⑤ §0.5 error body (keeps `details.reason`; the 429 `Retry-After` is added by `ApiErr`).
fn wasm_reload_api_err(fail: crate::plugins::ReloadFailure) -> ApiErr {
    let err = match fail.http_status {
        403 => LatticeError::forbidden(fail.message),
        409 => LatticeError::conflict(fail.message),
        429 => LatticeError::rate(fail.message),
        422 => LatticeError::format(fail.message),
        _ => LatticeError::internal(fail.message),
    };
    ApiErr(err.with_reason(fail.reason))
}

/// `POST /v1/admin/plugins/wasm/reload` (admin; PL-10 hot reload).
///
/// Request: body optional / `{}` (= `source:"all"`) / `{"source":"all|dir|pg"}`.
/// Success 200: `{outcome, source, loaded, from_dir, from_pg, rejected, conflicts, retained,
/// skipped, generation, elapsed_ms, last_reload_at}` (**without** wasm bytes/signature/public key/payload).
/// Failure: 403 not admin; 409 a reload is already running; 429 hit the 1/s rate limit (with `Retry-After`);
///       422 invalid source / host not enabled; 500 `pg_query|dir_scan|host_init` (**old snapshot unchanged**).
/// Audit: `plugin.wasm.reload` (detail has only source/counts/codename/elapsed/result, no payload).
async fn plugin_wasm_reload(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    let source = parse_wasm_reload_source(&body)?;
    let started = std::time::Instant::now();
    match crate::plugins::reload(&st, source).await {
        Ok(out) => {
            crate::routing::audit::audit_emit(
                &st,
                Some(&user.user_id),
                "plugin.wasm.reload",
                Some("wasm"),
                &out.to_json(),
                ip_of(&headers).as_deref(),
            )
            .await?;
            Ok(Json(out.to_json()).into_response())
        }
        Err(fail) => {
            // Failures are audited too (only source/reason/status code/elapsed); audit failure does not override the reload error semantics (WARN).
            let audit = json!({
                "source": source.as_str(),
                "outcome": fail.reason,
                "http_status": fail.http_status,
                "elapsed_ms": started.elapsed().as_millis() as u64,
            });
            if let Err(e) = crate::routing::audit::audit_emit(
                &st,
                Some(&user.user_id),
                "plugin.wasm.reload",
                Some("wasm"),
                &audit,
                ip_of(&headers).as_deref(),
            )
            .await
            {
                tracing::warn!(
                    reason = fail.reason,
                    error = %e,
                    "plugin wasm reload audit failed"
                );
            }
            Err(wasm_reload_api_err(fail))
        }
    }
}

async fn formats(State(st): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Ops)?;
    let rows = crate::store::pg::formats_all(&st.admin_db).await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|f| json!({
            "id": f.id, "type": f.r#type, "mime": f.mime, "handler": f.handler,
            "detect_rules": f.detect_rules, "builtin": f.builtin,
        }))
        .collect();
    Ok(Json(json!({ "items": items })).into_response())
}

#[derive(Debug, Deserialize)]
struct FormatReq {
    r#type: String,
    mime: Option<String>,
    handler: Option<String>,
    #[serde(default)]
    detect_rules: Value,
}

/// `POST /v1/admin/formats`: register/update a format (admin).
async fn format_upsert(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    headers: HeaderMap,
    Json(req): Json<FormatReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    let row = crate::store::pg::format_upsert(
        &st.db,
        &req.r#type,
        req.mime.as_deref(),
        req.handler.as_deref().unwrap_or("plugin"),
        &req.detect_rules,
    )
    .await?;
    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "format_upsert",
        Some(&row.r#type),
        &json!({ "mime": row.mime, "handler": row.handler }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    Ok(Json(json!({ "id": row.id, "type": row.r#type, "handler": row.handler })).into_response())
}

/// `GET /v1/admin/config`: dynamic config snapshot + source markers (authority in PG).
async fn config_get(State(st): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    let rows = crate::store::pg::config_all(&st.admin_db).await?;
    let mut items = serde_json::Map::new();
    for (k, v) in rows {
        items.insert(k, json!({ "value": v, "source": "pg:dynamic_config" }));
    }
    Ok(Json(json!({ "items": items })).into_response())
}

#[derive(Debug, Deserialize)]
struct ConfigPatch {
    #[serde(default)]
    ratelimit: Option<Value>,
    #[serde(default)]
    plugins_enabled: Option<bool>,
    #[serde(default)]
    canary: Option<Value>,
    #[serde(default)]
    reason: String,
}

/// `PATCH /v1/admin/config`: dynamic config hot update (admin) → write PG + broadcast `lattice:cfg`.
async fn config_patch(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    headers: HeaderMap,
    Json(req): Json<ConfigPatch>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    if req.reason.trim().is_empty() {
        return Err(ApiErr(LatticeError::format("reason is required").with_reason("reason")));
    }
    let mut changed = Vec::new();

    if let Some(Value::Object(rl)) = &req.ratelimit {
        for (k, v) in rl {
            let key = format!("ratelimit.{k}");
            crate::store::pg::config_set(&st.db, &key, v, &user.user_id).await?;
            if let Ok(mut map) = st.dynamic.write() {
                map.insert(key.clone(), v.clone());
            }
            let _ = st
                .redis
                .publish(
                    &lattice_core::keys::channel_cfg(),
                    &json!({ "key": key, "value": v }).to_string(),
                )
                .await;
            changed.push(key);
        }
    }
    if let Some(v) = req.plugins_enabled {
        crate::store::pg::config_set(&st.db, "plugins.enabled", &json!(v), &user.user_id).await?;
        changed.push("plugins.enabled".to_string());
    }
    if let Some(v) = &req.canary {
        crate::store::pg::config_set(&st.db, "canary.ratio", v, &user.user_id).await?;
        changed.push("canary.ratio".to_string());
    }

    crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "config_update",
        None,
        &json!({ "changed": changed, "reason": req.reason }),
        ip_of(&headers).as_deref(),
    )
    .await?;
    Ok(Json(json!({ "changed": changed, "authority": "pg:dynamic_config" })).into_response())
}

#[derive(Debug, Deserialize)]
struct RotateReq {
    target: String,
    #[serde(default)]
    reason: String,
}

/// Label the rotation-failure metric by error reason (only diagnosable read-only causes are split out, the rest map to error).
fn rotate_result_label(e: &LatticeError) -> &'static str {
    match e
        .details
        .as_ref()
        .and_then(|d| d.get("reason"))
        .and_then(|v| v.as_str())
    {
        Some("key_dir_readonly") => "key_dir_readonly",
        _ => "error",
    }
}

/// `POST /v1/admin/keys/rotate`: real key rotation (⑤ §8.4 / PL-03 3.8).
///
/// Execution order for `target=jwt`:
/// 1. Writability probe + generate a new 2048bit RSA + write three `*.tmp` files ([`crate::auth::JwtKeys::stage_rotation`]):
///    a read-only Secret mount fails here with `details.reason=key_dir_readonly`,
///    at which point no audit is written and neither disk nor memory changed (**never swap memory only, which would resurrect the old key after restart or invalidate all new tokens**);
/// 2. Write `audit_log(action=keys_rotate)`: audit failure → abandon the commit (tmp files are cleaned by Drop);
/// 3. Commit: rename-replace `jwt.key.pem` / `jwt.key.prev.pem` / `jwt.keys.json` atomically,
///    and hot-swap the new snapshot into `AppState` (new keys sign immediately, old keys still verify within the window).
///
/// `target=kek|internal_ca` is not implemented on this node: it keeps the 202 contract but returns `implemented:false` explicitly,
/// **without pretending rotation succeeded**, and generates/modifies no key material.
async fn keys_rotate(
    State(st): State<Arc<AppState>>,
    user: AuthUser,
    headers: HeaderMap,
    Json(req): Json<RotateReq>,
) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    if req.reason.trim().is_empty() {
        return Err(ApiErr(
            LatticeError::format("reason is required").with_reason("reason"),
        ));
    }
    if !matches!(req.target.as_str(), "jwt" | "kek" | "internal_ca") {
        return Err(ApiErr(
            LatticeError::format("invalid target").with_reason("target"),
        ));
    }
    let ip = ip_of(&headers);

    // ---- kek / internal_ca: explicitly unimplemented (alert + metrics, never pretend success) ----
    if req.target != "jwt" {
        // Unimplemented targets change no key material; an audit failure returns 500 per existing semantics (no silent success).
        crate::routing::audit::audit_emit(
            &st,
            Some(&user.user_id),
            "keys_rotate",
            Some(&req.target),
            &json!({
                "reason": req.reason,
                "implemented": false,
                "note": "target not implemented on this node; no key material changed",
            }),
            ip.as_deref(),
        )
        .await?;
        st.metrics
            .key_rotate_total
            .with_label_values(&[req.target.as_str(), "not_implemented"])
            .inc();
        tracing::warn!(
            target = %req.target,
            actor = %user.user_id,
            reason = %req.reason,
            "key rotation requested for unimplemented target; nothing rotated"
        );
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({
                "target": req.target,
                "implemented": false,
                "status": "not_implemented",
                "message": "this node does not manage this key class yet; no key material was generated or changed",
            })),
        )
            .into_response());
    }

    // ---- target=jwt: real rotation (rotate serialized with previous-key expiry cleanup) ----
    let _rotate_guard = st.key_rotate_lock.lock().await;
    let keys = st.jwt_keys();
    let overlap_hours = keys.overlap_hours;
    let staged = match tokio::task::spawn_blocking(move || keys.stage_rotation()).await {
        Ok(Ok(staged)) => staged,
        Ok(Err(e)) => {
            st.metrics
                .key_rotate_total
                .with_label_values(&["jwt", rotate_result_label(&e)])
                .inc();
            tracing::warn!(
                actor = %user.user_id,
                reason = %req.reason,
                error = %e,
                "jwt key rotation staged-failed (no key material changed)"
            );
            return Err(ApiErr(e));
        }
        Err(e) => {
            st.metrics
                .key_rotate_total
                .with_label_values(&["jwt", "error"])
                .inc();
            return Err(ApiErr(crate::error::internal(format!(
                "jwt key rotation task failed: {e}"
            ))));
        }
    };

    // Rotation commits only after the audit succeeds (audit_log is the key-rotation trail; "rotated" cannot be backfilled later).
    // Strong semantics are preserved via `audit_emit`: in NATS mode publish waits for the JetStream ack (persisted into the
    // audit stream, so consumers always catch up); on the Redis bus or a publish failure, audit_emit writes PG synchronously. Only
    // when both paths `Err` does it return 500 and **not commit** — so there is no window of "keys rotated, audit missing".
    let detail = staged.audit_detail(req.reason.trim());
    let new_fp = staged.new_fingerprint().to_string();
    let old_fp = staged.old_fingerprint().to_string();
    let rotated_at = staged.rotated_at();
    let previous_until = staged.previous_until();
    if let Err(e) = crate::routing::audit::audit_emit(
        &st,
        Some(&user.user_id),
        "keys_rotate",
        Some("jwt"),
        &detail,
        ip.as_deref(),
    )
    .await
    {
        st.metrics
            .key_rotate_total
            .with_label_values(&["jwt", "audit_error"])
            .inc();
        tracing::error!(
            error = %e,
            actor = %user.user_id,
            "jwt key rotation aborted: audit write failed (nothing committed)"
        );
        return Err(ApiErr(e));
    }

    let new_keys = match tokio::task::spawn_blocking(move || staged.commit()).await {
        Ok(Ok(new_keys)) => new_keys,
        Ok(Err(e)) => {
            st.metrics
                .key_rotate_total
                .with_label_values(&["jwt", rotate_result_label(&e)])
                .inc();
            tracing::error!(
                error = %e,
                actor = %user.user_id,
                "jwt key rotation commit failed (recoverable on-disk state)"
            );
            return Err(ApiErr(e));
        }
        Err(e) => {
            st.metrics
                .key_rotate_total
                .with_label_values(&["jwt", "error"])
                .inc();
            return Err(ApiErr(crate::error::internal(format!(
                "jwt key rotation commit task failed: {e}"
            ))));
        }
    };
    // Hot swap: subsequent signing/verification requests see the new snapshot (the old key stays as previous for verification)
    st.install_jwt_keys(new_keys);
    st.metrics
        .key_rotate_total
        .with_label_values(&["jwt", "ok"])
        .inc();
    tracing::warn!(
        actor = %user.user_id,
        reason = %req.reason,
        current_fingerprint = %new_fp,
        previous_fingerprint = %old_fp,
        previous_until = %previous_until.to_rfc3339(),
        "jwt signing key rotated; dual-key overlap window active"
    );
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "target": "jwt",
            "implemented": true,
            "status": "rotated",
            "algorithm": "RS256",
            "key_bits": crate::auth::jwt::KEY_BITS,
            "rotated_at": rotated_at.to_rfc3339(),
            "previous_until": previous_until.to_rfc3339(),
            "overlap_hours": overlap_hours,
            "current_fingerprint": new_fp,
            "previous_fingerprint": old_fp,
        })),
    )
        .into_response())
}

/// `GET /v1/admin/keys`: returns fingerprints and validity windows only, **never private keys** (⑤ §8.4).
///
/// With no previous key, `previous`/`previous_until` are null and `items` has only current,
/// so it never fabricates a "parallel old key".
async fn keys(State(st): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Response> {
    require_role(&user, crate::auth::Role::Admin)?;
    let keys = st.jwt_keys();
    let now = chrono::Utc::now();
    let rotated_at = keys.rotated_at().map(|t| t.to_rfc3339());
    let previous_until = keys.previous_until().map(|t| t.to_rfc3339());
    let previous = match (keys.previous_fingerprint(), keys.previous_until()) {
        (Some(fp), Some(until)) => json!({
            "fingerprint": fp,
            "role": "previous",
            "until": until.to_rfc3339(),
            "active": until > now,
        }),
        _ => Value::Null,
    };
    let mut items = vec![json!({
        "fingerprint": keys.current_fingerprint(),
        "role": "current",
        "rotated_at": rotated_at,
    })];
    if let Some(prev) = previous.as_object() {
        items.push(Value::Object(prev.clone()));
    }
    Ok(Json(json!({
        "items": items,
        "ttl_seconds": keys.ttl,
        "algorithm": "RS256",
        "key_bits": crate::auth::jwt::KEY_BITS,
        "issuer": keys.issuer,
        "overlap_hours": keys.overlap_hours,
        "rotated_at": rotated_at,
        "previous_until": previous_until,
        "current": {
            "fingerprint": keys.current_fingerprint(),
            "role": "current",
            "rotated_at": rotated_at,
        },
        "previous": previous,
    }))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write allowlist: only the new values admin/ops/user (case/whitespace normalized), default = least privilege user.
    #[test]
    fn writable_role_accepts_only_new_values() {
        assert_eq!(writable_role(None).unwrap(), "user");
        assert_eq!(writable_role(Some("  Admin ")).unwrap(), "admin");
        assert_eq!(writable_role(Some("OPS")).unwrap(), "ops");
        assert_eq!(writable_role(Some("User")).unwrap(), "user");
    }

    /// Rename neither loosens nor exposes the old name: the old value viewer and unknown values must both be 422,
    /// and `allowed` in the error body lists only new values (user is no longer called viewer).
    #[test]
    fn writable_role_rejects_legacy_and_unknown() {
        for bad in ["viewer", "readonly", "root", ""] {
            let err = writable_role(Some(bad)).unwrap_err();
            assert_eq!(err.code, lattice_core::ErrorCode::Format, "role={bad:?}");
            let details = err.details.as_ref().expect("details");
            assert_eq!(details.get("allowed"), Some(&json!(["admin", "ops", "user"])));
            assert!(!err.to_string().contains("viewer"));
        }
    }
}

