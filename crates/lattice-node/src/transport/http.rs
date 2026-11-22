//! REST layer (the sole contract authority: document ⑤ §0–§8). This file covers only "how it is implemented".
//!
//! Route groups map one-to-one to the sections of ⑤, in an order that eases comparison with the document:
//! auth §1 / users+devices §2 / conversations §3 / messages §4 / uploads §5 / probes §6 / topics §7,
//! The admin plane §8 lives in [`crate::admin`], and WS in [`crate::transport::ws`].

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha1::Sha1;

use lattice_core::protocol::{DeliveryState, PRESIGN_TTL_SECS};
use lattice_core::{keys, LatticeError};

use crate::auth::jwt::Role;
use crate::auth::rbac::{self, AuthUser};
use crate::auth::{device as device_auth, password};
use crate::error::{self, Result};
use crate::state::AppState;

/// Generic `Idempotency-Key` middleware (REMAINING E12; contract ⑤ §0.3).
///
/// In `main.rs` it is attached to the whole HTTP router with
/// `axum::middleware::from_fn_with_state(state, idempotency::middleware)`; only "authenticated write requests with Content-Length" enter the cache path.
pub mod idempotency;

// ---------------------------------------------------------------------------
// Error → HTTP response (⑤ §0.5 / §0.6): implementation in crate::error::ApiErr
// ---------------------------------------------------------------------------

pub use crate::error::{ApiErr, ApiResult};

fn ok<T: IntoResponse>(v: T) -> ApiResult<Response> {
    Ok(v.into_response())
}

/// `/v1/messages` request-body limit guard (⑤ §4: ≤1MB; over the limit `413 TOO_LARGE` + `details.hint = use_ws_or_chunk`).
///
/// When `DefaultBodyLimit` rejects at the extractor stage it produces only axum's plain-text 413
/// (`Failed to buffer the request body: length limit exceeded`), and the client gets neither the error
/// code nor the hint to decide to switch to WS/chunks. Here we check `Content-Length` before buffering
/// and return a structured error per contract; `DefaultBodyLimit` remains as the fallback for chunked bodies without a length.
async fn messages_body_guard(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    const LIMIT: u64 = (lattice_core::protocol::INLINE_MAX_BYTES + 64 * 1024) as u64;
    if let Some(len) = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        if len > LIMIT {
            let e = LatticeError::too_large(format!(
                "request body {len} bytes exceeds {LIMIT} (messages is limited to 1MB)"
            ))
            .with_detail("hint", json!("use_ws_or_chunk"));
            return ApiErr(e).into_response();
        }
    }
    next.run(req).await
}

// ---------------------------------------------------------------------------
// Route table (one-to-one with ⑤ §1–§8; admin-plane mounting in crate::admin::routes)
// ---------------------------------------------------------------------------

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // §6 probes (no auth)
        .route("/v1/health", get(probes::health))
        .route("/v1/ready", get(probes::ready))
        // §1 auth
        .route("/v1/auth/login", post(auth::login))
        .route("/v1/auth/refresh", post(auth::refresh))
        .route("/v1/auth/logout", post(auth::logout))
        // §2 users and devices
        .route("/v1/me", get(users::me))
        // Self-service profile/password: the static segment `me` precedes `:id` (axum 0.7/matchit), so it never collides with `GET /v1/users/{id}`
        .route("/v1/users/me", get(users::get_me).patch(users::patch_me))
        .route("/v1/users/me/password", post(users::change_own_password))
        .route("/v1/users/:id", get(users::get_user).patch(users::patch_user))
        .route("/v1/users/:id/devices", get(users::list_devices))
        .route("/v1/devices/:id", delete(users::revoke_device))
        // §3 conversations
        .route("/v1/conversations", post(conversations::create).get(conversations::list))
        .route("/v1/conversations/:id", get(conversations::detail).patch(conversations::rename))
        .route("/v1/conversations/:id/read", post(conversations::mark_read))
        .route("/v1/conversations/:id/members", post(conversations::add_members))
        .route(
            "/v1/conversations/:id/members/:uid",
            delete(conversations::remove_member),
        )
        .route("/v1/conversations/:id/messages", get(conversations::history))
        // §4 messages (request body ≤ 1MB; over the limit 413 + hint=use_ws_or_chunk)
        .route(
            "/v1/messages",
            post(messages::send)
                .layer(DefaultBodyLimit::max(
                    lattice_core::protocol::INLINE_MAX_BYTES + 64 * 1024,
                ))
                .layer(axum::middleware::from_fn(messages_body_guard)),
        )
        .route("/v1/messages/:id", get(messages::meta))
        .route("/v1/messages/:id/download", get(messages::download))
        .route("/v1/chunks/:msg_id", get(messages::chunks))
        // §5 uploads
        .route("/v1/uploads", post(uploads::create))
        .route("/v1/uploads/:id", get(uploads::progress).delete(uploads::abort))
        .route("/v1/uploads/:id/complete", post(uploads::complete))
        .route("/v1/uploads/:id/parts", post(uploads::reissue))
        // §7 Topic
        .route("/v1/topics", get(topics::list))
        .route("/v1/topics/:t/subscribe", post(topics::subscribe))
        .route("/v1/topics/:t/unsubscribe", post(topics::unsubscribe))
        .route("/v1/topics/:t/history", get(topics::history))
        .route("/v1/topics/:t/publish", post(topics::publish))
        // §9.4 media plane: TURN short-lived credentials (coturn REST API convention; design §17.9)
        .route("/v1/media/turn-credentials", get(media::turn_credentials))
        // §9.7 media plane: recording search/download (PL-13 13.6; readable by admin/ops, user/anonymous 403/401)
        .route("/v1/media/recordings", get(media::recordings))
        .route("/v1/media/recordings/:id", get(media::recording_detail))
        .route(
            "/v1/media/recordings/:id/download",
            get(media::recording_download),
        )
        // Replay manifest (PL-13 13.6): returns only the frame-index JSON, never object bytes (not directly playable)
        .route(
            "/v1/media/recordings/:id/manifest",
            get(media::recording_manifest),
        )
        // §8 admin plane
        .merge(crate::admin::routes())
        // §12 plugin hub (user plane)
        .merge(crate::hub::routes())
}

// ---------------------------------------------------------------------------
// Common parameters
// ---------------------------------------------------------------------------

/// Lenient integer deserialization: accepts both JSON numbers and **numeric strings**.
///
/// Why it is needed: `#[serde(flatten)] PageQuery` (used by all 5 admin search endpoints) makes
/// `serde` take the "collect into a map first, then dispatch" path, and on that path `serde_urlencoded` hands every value
/// to the field as a string, so `?page=1` directly reports
/// `invalid type: string "1", expected i64` → axum returns a plain-text 400,
/// and every paginated list page in the console fails to load (R8, see README).
///
/// Not fixing it by "removing flatten", because each endpoint would then have to copy the `page/page_size` definitions again;
/// tolerating strings at the type level works for every `Query<T>` call site.
fn de_i64_lenient<'de, D>(d: D) -> std::result::Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Lenient;

    impl serde::de::Visitor<'_> for Lenient {
        type Value = i64;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an integer or a numeric string")
        }

        fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<i64, E> {
            Ok(v)
        }

        fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<i64, E> {
            Ok(v as i64)
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<i64, E> {
            v.trim()
                .parse::<i64>()
                .map_err(|_| E::custom(format!("expected an integer, got `{v}`")))
        }
    }

    d.deserialize_any(Lenient)
}

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    #[serde(default = "default_page", deserialize_with = "de_i64_lenient")]
    pub page: i64,
    #[serde(default = "default_page_size", deserialize_with = "de_i64_lenient")]
    pub page_size: i64,
}

fn default_page() -> i64 {
    1
}
fn default_page_size() -> i64 {
    50
}

impl PageQuery {
    pub fn clamp(&self) -> (i64, i64) {
        (self.page.max(1), self.page_size.clamp(1, 200))
    }
}

#[derive(Debug, Deserialize)]
pub struct CursorQuery {
    pub before_seq: Option<i64>,
    pub after_seq: Option<i64>,
    pub limit: Option<i64>,
}

// ---------------------------------------------------------------------------
// Query parameter extractor
// ---------------------------------------------------------------------------

/// Drop-in replacement for `Query<T>`: turns axum's default **plain-text 400** (`Failed to deserialize
/// query string: ...`) into the JSON error body this project's contract requires (⑤ §0.5: `code`/`message`/
/// `details`). The default neither tells the frontend which parameters are wrong nor can the console render it per language.
///
/// Usage: `Q(q): Q<AuditQuery>`, otherwise identical to `Query`.
pub struct Q<T>(pub T);

#[axum::async_trait]
impl<T, S> axum::extract::FromRequestParts<S> for Q<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiErr;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        axum::extract::Query::<T>::try_from_uri(&parts.uri)
            .map(|axum::extract::Query(v)| Q(v))
            .map_err(|e| {
                ApiErr(
                    LatticeError::format("invalid query parameters")
                        .with_reason("query")
                        .with_detail("detail", json!(e.body_text())),
                )
            })
    }
}

fn client_ip(headers: &HeaderMap, fallback: Option<std::net::SocketAddr>) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| fallback.map(|a| a.ip().to_string()))
}

// ---------------------------------------------------------------------------
// §6 probes
// ---------------------------------------------------------------------------

pub mod probes {
    use super::*;

    /// Liveness: 200 as long as the process responds; dependencies are not probed (⑤ §6).
    pub async fn health() -> ApiResult<Response> {
        ok(Json(json!({ "status": "ok" })))
    }

    /// Readiness: PG/Redis/bus liveness; PG (the only hard dependency) **completely unavailable** → 503 + `details.dep=pg`.
    ///
    /// Semantic baseline (⑤ §6 / after the E10 D1/D2/D3 fixes):
    /// - **PG unavailable = not ready**: message persistence/membership checks/seq allocation all depend on PG, so even a PG-only failure must
    ///   make the LB drain this node (the old implementation returned 503 only when PG+Redis were both unavailable → defect D1);
    /// - **Redis unavailable = `degraded`, still ready**: delivery uses the local stale cache / WAL fallback
    ///   (② §4.8), the same convention as the SSE `deps` event;
    /// - Liveness probing is **bounded**: Redis uses a dedicated short connection + 300ms timeout (`Redis::ping_ready`), and the PG probe
    ///   has its own short timeout; a failure of any dependency never drags the LB probe into a timeout (defect D2);
    /// - No cross-request caching/single-flight: each probe decides independently, so after dependencies recover the next request is
    ///   automatically ready again, and no "in-flight stuck command" can hang the probe forever (defect D3).
    pub async fn ready(State(st): State<Arc<AppState>>) -> ApiResult<Response> {
        /// PG probe limit: `select 1` is a millisecond operation; 2s only covers pool waits during a failure window.
        const PG_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
        let pg = matches!(
            tokio::time::timeout(
                PG_PROBE_TIMEOUT,
                sqlx::query_scalar::<_, i32>("select 1").fetch_one(&st.db)
            )
            .await,
            Ok(Ok(_))
        );
        let redis = st
            .redis
            .ping_ready(crate::store::redis::READY_PING_TIMEOUT)
            .await
            .is_ok();

        let bus = if st.bus.kind().as_str() == "nats" {
            if st.bus.healthy() { "ok" } else { "down" }
        } else if redis {
            "ok"
        } else {
            "degraded"
        };
        let deps = json!({
            "pg": if pg { "ok" } else { "down" },
            "redis": if redis { "ok" } else { "degraded" },
            "bus": bus,
        });

        // Draining/shutdown: the readiness probe fails immediately and the LB stops forwarding (PL-15 rolling upgrade).
        if st.draining.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "code": "INTERNAL",
                    "message": "node draining",
                    "details": { "reason": "draining" },
                    "ready": false,
                    "draining": true,
                    "deps": deps,
                    "node_id": st.node_id,
                    "version": crate::state::VERSION,
                })),
            )
                .into_response());
        }

        // PG is the only hard dependency: its failure alone must also return 503 (E10 D1; the old implementation required PG+Redis to fail together).
        if !pg {
            st.ready.store(false, std::sync::atomic::Ordering::Relaxed);
            let body = json!({
                "code": "INTERNAL",
                "message": "dependencies unavailable",
                "details": { "dep": "pg" },
                "ready": false,
                "deps": deps,
                "node_id": st.node_id,
                "version": crate::state::VERSION,
            });
            return Ok((StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response());
        }

        // Redis unavailability is merely degraded (still serviceable) and does not mark the node unready.
        st.ready.store(true, std::sync::atomic::Ordering::Relaxed);
        ok(Json(json!({
            "ready": true,
            "deps": deps,
            "node_id": st.node_id,
            "version": crate::state::VERSION,
        })))
    }
}

// ---------------------------------------------------------------------------
// §1 auth
// ---------------------------------------------------------------------------

pub mod auth {
    use super::*;

    /// refresh rotation-chain mapping: `refresh hash → device id` (Redis, short TTL).
    ///
    /// Why it is needed: refresh is **rotating**, and `devices.token_hash` keeps only the latest value;
    /// once an old token is used a second time there is no matching row left, so the server can only say "unknown" and cannot locate the chain per ⑤ §1.2's
    /// "same token used twice → 409 and revoke the entire refresh chain". Recording one mapping on successful login/refresh
    /// lets a replay recover the device and revoke the whole chain (compromise signal). When Redis is unavailable or the mapping expired, this degrades to
    /// returning only 409 (rotation semantics remain safe; only chain-wide revocation is lost, an acceptable degradation).
    const REFRESH_CHAIN_KEY: &str = "lattice:auth:refresh_chain";
    /// The mapping is kept for 7 days: covers common refresh use/replay windows; beyond that a replay only gets 409.
    const REFRESH_CHAIN_TTL_SECS: u64 = 7 * 24 * 3600;

    fn refresh_chain_key(hash: &str) -> String {
        format!("{REFRESH_CHAIN_KEY}:{hash}")
    }

    /// Record refresh hash → device (a failure does not block authentication: during Redis degradation only chain-wide revocation is lost).
    async fn remember_refresh_chain(st: &Arc<AppState>, hash: &str, device_id: &str) {
        if let Err(e) = st
            .redis
            .set_json(&refresh_chain_key(hash), device_id, REFRESH_CHAIN_TTL_SECS)
            .await
        {
            tracing::warn!(error = %e, "refresh chain mapping write failed (non-fatal)");
        }
    }

    /// Write the refresh-failure audit (⑤ §8.6 audit point: refresh failure): failures are non-fatal, WARN only.
    async fn audit_refresh_failure(
        st: &Arc<AppState>,
        user_id: Option<&str>,
        device_id: &str,
        reason: &str,
        action: &str,
        ip: Option<&str>,
    ) {
        if let Err(e) = crate::routing::audit::audit_emit(
            st,
            user_id,
            "refresh_failed",
            Some(device_id),
            &json!({ "reason": reason, "action": action }),
            ip,
        )
        .await
        {
            tracing::warn!(error = %e, device = %device_id, "refresh failure audit write failed (non-fatal)");
        }
    }

    /// Unified decision when refresh cannot be used (never leaks whether the token ever existed):
    /// - hash in the rotation chain and the device still active → **old-token replay**: revoke that device (the whole chain becomes non-renewable immediately) → 409;
    /// - hash in the rotation chain but the device already revoked (logout/admin reset/risk control) → 401 (⑤ §1.2 "revoked");
    /// - hash not in the chain (garbage/expired mapping) → 409 (rotation semantics), with no revocation and no audit write (so forged requests cannot spam the audit log).
    async fn refresh_rejected(st: &Arc<AppState>, hash: &str, ip: Option<&str>) -> ApiErr {
        let mapped = st.redis.get_json(&refresh_chain_key(hash)).await.ok().flatten();
        let Some(device_id) = mapped else {
            return ApiErr(
                LatticeError::conflict("refresh token already rotated").with_reason("refresh_replay"),
            );
        };
        match crate::store::pg::device_by_id(&st.db, &device_id).await {
            Ok(Some(d)) if d.revoked_at.is_none() => {
                // Compromise signal: a rotated old refresh appears again → revoke the entire refresh chain (⑤ §1.2).
                if let Err(e) = crate::store::pg::revoke_device(&st.db, &device_id).await {
                    tracing::warn!(error = %e, device = %device_id, "revoke device on refresh replay failed");
                }
                audit_refresh_failure(
                    st,
                    Some(&d.user_id),
                    &device_id,
                    "refresh_replay",
                    "chain_revoked",
                    ip,
                )
                .await;
                ApiErr(LatticeError::conflict(
                    "refresh token already rotated; refresh chain revoked",
                )
                .with_reason("refresh_replay"))
            }
            Ok(Some(d)) => {
                audit_refresh_failure(
                    st,
                    Some(&d.user_id),
                    &device_id,
                    "device_revoked",
                    "none",
                    ip,
                )
                .await;
                ApiErr(LatticeError::auth_fail("device revoked"))
            }
            Ok(None) => ApiErr(
                LatticeError::conflict("refresh token already rotated").with_reason("refresh_replay"),
            ),
            Err(e) => ApiErr(e),
        }
    }

    #[derive(Debug, Deserialize)]
    pub struct LoginReq {
        pub username: String,
        pub password: String,
        pub device_name: Option<String>,
        pub device_fp: Option<String>,
        pub platform: Option<String>,
    }

    /// `POST /v1/auth/login` (⑤ §1.1). Rate limits: 10/min per IP, 5/min per account (§17.13).
    pub async fn login(
        State(st): State<Arc<AppState>>,
        ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
        headers: HeaderMap,
        Json(req): Json<LoginReq>,
    ) -> ApiResult<Response> {
        let ip = client_ip(&headers, Some(addr)).unwrap_or_else(|| "0.0.0.0".into());
        let ip_key = format!("ip:{ip}");
        let acct_key = format!("acct:{}", req.username);

        let ip_hits = st.redis.bump_rate(&keys::ratelimit_login(&ip_key), 60).await.unwrap_or(0);
        let acct_hits = st.redis.bump_rate(&keys::ratelimit_login(&acct_key), 60).await.unwrap_or(0);
        if ip_hits > lattice_core::protocol::LOGIN_RATE_PER_IP as i64
            || acct_hits > lattice_core::protocol::LOGIN_RATE_PER_ACCOUNT as i64
        {
            return Err(ApiErr(
                LatticeError::rate("login rate limit exceeded").with_reason("login"),
            ));
        }

        let user = crate::store::pg::user_by_username(&st.db, &req.username)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::auth_fail("invalid credentials")))?;

        if user.status != "active" {
            return Err(ApiErr(LatticeError::auth_fail("account not active")));
        }
        if !password::verify_password(&req.password, &user.password_hash) {
            return Err(ApiErr(LatticeError::auth_fail("invalid credentials")));
        }

        let fp = req
            .device_fp
            .clone()
            .unwrap_or_else(|| format!("sha256:{}", lattice_core::ids::new_id()));
        let (refresh_token, refresh_hash) = password::new_refresh_token();
        let device = device_auth::resolve_device(
            &st.db,
            &user.id,
            &fp,
            req.device_name.as_deref(),
            req.platform.as_deref(),
            Some(&refresh_hash),
        )
        .await?;
        // Rotation-chain mapping (for replay detection): record this refresh hash → device so an old-token replay can revoke the whole chain.
        remember_refresh_chain(&st, &refresh_hash, &device.id).await;

        // Role value source = `users.role` (⑤ §0.2 "role source" / ⑥ §2.3), signed into the token as a snapshot
        let role = rbac::resolve_role(&st, &user.id, &user.role);
        // Key snapshot: after a hot key rotation, new tokens are signed with the new key immediately (reads copy only the Arc; no lock is held across await)
        let (access, ttl) = st.jwt_keys().issue(&user.id, &device.id, role)?;

        // The login audit stays **non-fatal**: a failed audit write must not fail the login (keeping the existing `.ok()` semantics).
        // Always go through the unified audit write entry: NATS mode writes the audit stream (durable consumer persists to PG), and failure automatically degrades to a direct PG write;
        // if both fail, only this audit line is lost and the login still succeeds (errors are ignored here and WARNed).
        if let Err(e) = crate::routing::audit::audit_emit(
            &st,
            Some(&user.id),
            "login",
            Some(&device.id),
            &json!({ "device_fp": fp, "ip": ip }),
            Some(&ip),
        )
        .await
        {
            tracing::warn!(error = %e, user = %user.id, "login audit write failed (non-fatal)");
        }

        ok(Json(json!({
            "access_jwt": access,
            "refresh_token": refresh_token,
            "expires_in": ttl,
            // device_fp is optional in the request; when the server generates it the client cannot know it,
            // yet WS hello must report a matching fingerprint (§17.11) → echo the authoritative value here (⑤ §1.1).
            "device": {
                "id": device.id,
                "fingerprint": device.fingerprint,
            },
            "user": {
                "id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                // v0.8 "user avatar": the user object in login/refresh responses already carries the avatar, so the client can render on the first screen
                "avatar": user.avatar,
                "capabilities": user.capabilities,
            }
        })))
    }

    #[derive(Debug, Deserialize)]
    pub struct RefreshReq {
        pub refresh_token: String,
    }

    /// `POST /v1/auth/refresh` (⑤ §1.2): rotating; a replay → 409 and revokes the entire refresh chain.
    pub async fn refresh(
        State(st): State<Arc<AppState>>,
        headers: HeaderMap,
        Json(req): Json<RefreshReq>,
    ) -> ApiResult<Response> {
        let ip = client_ip(&headers, None);
        let hash = password::hash_refresh(&req.refresh_token);
        let device = match crate::store::pg::device_by_token_hash(&st.db, &hash).await? {
            Some(d) => d,
            // No active row in the DB: old-token replay / device revoked / garbage token, see refresh_rejected.
            None => return Err(refresh_rejected(&st, &hash, ip.as_deref()).await),
        };

        let user = crate::store::pg::user_by_id(&st.db, &device.user_id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::auth_fail("user not found")))?;
        if user.status != "active" {
            return Err(ApiErr(LatticeError::auth_fail("account not active")));
        }

        let (new_token, new_hash) = password::new_refresh_token();
        if !crate::store::pg::rotate_device_token(&st.db, &device.id, &new_hash).await? {
            return Err(ApiErr(LatticeError::auth_fail("device revoked")));
        }
        // The new refresh enters the rotation chain immediately (only then can the next replay locate the device and revoke the whole chain).
        remember_refresh_chain(&st, &new_hash, &device.id).await;

        let role = rbac::resolve_role(&st, &user.id, &user.role);
        let (access, ttl) = st.jwt_keys().issue(&user.id, &device.id, role)?;
        ok(Json(json!({
            "access_jwt": access,
            "refresh_token": new_token,
            "expires_in": ttl,
            "user": {
                "id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                // v0.8 "user avatar": the user object in login/refresh responses already carries the avatar, so the client can render on the first screen
                "avatar": user.avatar,
                "capabilities": user.capabilities,
            }
        })))
    }

    /// `POST /v1/auth/logout`: revoke the current refresh; repeated calls still return 204 (⑤ §1.3).
    pub async fn logout(
        State(st): State<Arc<AppState>>,
        headers: HeaderMap,
        user: AuthUser,
    ) -> ApiResult<Response> {
        crate::store::pg::revoke_device(&st.db, &user.device_id).await?;
        // ⑤ §8.6 audit point: logout. Non-fatal (same as login: a failed audit write must not block logout in reverse).
        let ip = client_ip(&headers, None);
        if let Err(e) = crate::routing::audit::audit_emit(
            &st,
            Some(&user.user_id),
            "logout",
            Some(&user.device_id),
            &json!({}),
            ip.as_deref(),
        )
        .await
        {
            tracing::warn!(error = %e, device = %user.device_id, "logout audit write failed (non-fatal)");
        }
        Ok(StatusCode::NO_CONTENT.into_response())
    }
}

// ---------------------------------------------------------------------------
// §2 users and devices
// ---------------------------------------------------------------------------

pub mod users {
    use super::*;

    /// `GET /v1/users/{id}`: self or admin; `password_hash` is never returned (⑤ §2).
    pub async fn get_user(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
    ) -> ApiResult<Response> {
        if user.user_id != id && !user.is_admin() {
            return Err(ApiErr(LatticeError::forbidden("can only read self")));
        }
        let u = crate::store::pg::user_by_id(&st.db, &id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::not_found("user not found")))?;
        if u.status == "deleted" && !user.is_admin() {
            return Err(ApiErr(LatticeError::not_found("user not found")));
        }
        ok(Json(json!({
            "id": u.id,
            "username": u.username,
            "display_name": u.display_name,
            // v0.8: user rows uniformly return the avatar (null = not set); password_hash is never returned
            "avatar": u.avatar,
            "status": u.status,
            "capabilities": u.capabilities,
            "quota": if u.quota.as_object().map(|o| o.is_empty()).unwrap_or(false) {
                json!(st.quota())
            } else { u.quota.clone() },
            "created_at": u.created_at,
        })))
    }

    #[derive(Debug, Deserialize)]
    pub struct PatchUserReq {
        pub display_name: Option<String>,
        pub capabilities: Option<Value>,
    }

    /// `PATCH /v1/users/{id}`: self may change only `display_name`/`capabilities` (⑤ §2).
    pub async fn patch_user(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
        Json(req): Json<PatchUserReq>,
    ) -> ApiResult<Response> {
        if user.user_id != id && !user.is_admin() {
            return Err(ApiErr(LatticeError::forbidden("can only patch self")));
        }
        let updated = crate::store::pg::update_user(
            &st.db,
            &id,
            req.display_name.as_deref(),
            req.capabilities.as_ref(),
        )
        .await?
        .ok_or_else(|| ApiErr(LatticeError::not_found("user not found")))?;
        ok(Json(json!({
            "id": updated.id,
            "username": updated.username,
            "display_name": updated.display_name,
            "avatar": updated.avatar,
            "capabilities": updated.capabilities,
            "updated_at": updated.updated_at,
        })))
    }

    /// Unified response shape for the self-service profile: same fields as `GET /v1/users/{id}`, plus a `role`
    /// (the console account menu must show the role; `password_hash` is never returned, ⑤ §2).
    fn profile_json(st: &AppState, u: &crate::store::pg::User) -> Value {
        json!({
            "id": u.id,
            "username": u.username,
            "display_name": u.display_name,
            // v0.8 "user avatar": self-service profile reads and writes both carry the avatar (for account menu/profile dialog rendering)
            "avatar": u.avatar,
            "status": u.status,
            "role": u.role,
            "capabilities": u.capabilities,
            "quota": if u.quota.as_object().map(|o| o.is_empty()).unwrap_or(false) {
                json!(st.quota())
            } else {
                u.quota.clone()
            },
            "created_at": u.created_at,
            "updated_at": u.updated_at,
        })
    }

    /// `GET /v1/users/me`: own profile (reused by the self-service "my profile" page and the client account area).
    pub async fn get_me(State(st): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Response> {
        let u = crate::store::pg::user_by_id(&st.db, &user.user_id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::not_found("user not found")))?;
        ok(Json(profile_json(&st, &u)))
    }

    #[derive(Debug, Deserialize)]
    pub struct PatchMeReq {
        /// New display name; empty string = clear (`users.display_name` allows null).
        /// Omitting the field (`None`) = leave the display name unchanged; providing neither field → 422 `reason=no_fields`
        /// (avoids a pointless audit row from an empty write).
        #[serde(default)]
        pub display_name: Option<String>,
        /// New avatar; empty string = clear the avatar. Omitting the field (`None`) = unchanged.
        /// Accepts an `https://` URL or `data:image/(png|jpeg|webp|gif);base64,...` (≤256KiB);
        /// other formats get 422 `details.field=avatar` (validation in [`super::validate_avatar`]).
        #[serde(default)]
        pub avatar: Option<String>,
    }

    /// `PATCH /v1/users/me`: change own profile (`display_name` / `avatar`), writing
    /// `audit_log(action=self.update)`. Any logged-in role can change their own profile.
    ///
    /// The audit records only the `avatar_changed` boolean: the avatar is a base64 data URL (up to 256KiB), and writing the
    /// raw text into `audit_log.detail` would bloat storage and echo the image content in the audit page/CSV export;
    /// it is unnecessary and bad for redaction (⑤ §8.6 only requires recording "what changed").
    pub async fn patch_me(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        headers: HeaderMap,
        Json(req): Json<PatchMeReq>,
    ) -> ApiResult<Response> {
        // Read the current row first: used both for the 404 and to tell whether the avatar really changed (the audit records only a boolean)
        let before = crate::store::pg::user_by_id(&st.db, &user.user_id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::not_found("user not found")))?;
        if before.status == "deleted" {
            return Err(ApiErr(LatticeError::not_found("user not found")));
        }
        if req.display_name.is_none() && req.avatar.is_none() {
            return Err(ApiErr(
                LatticeError::format("at least one of display_name/avatar is required")
                    .with_reason("no_fields"),
            ));
        }

        // Display name: empty after trim = clear (keeping v0.7 behavior); omitted = unchanged
        let raw_name = req.display_name.map(|s| s.trim().to_string());
        let name_arg: Option<Option<&str>> = raw_name
            .as_deref()
            .map(|s| if s.is_empty() { None } else { Some(s) });
        // Avatar: validate/normalize (empty string → None to clear; invalid format → 422 details.field=avatar)
        let had_avatar_field = req.avatar.is_some();
        let next_avatar = validate_avatar(req.avatar.as_deref()).map_err(ApiErr)?;
        let avatar_changed = had_avatar_field && next_avatar != before.avatar;
        let avatar_arg: Option<Option<&str>> = if had_avatar_field {
            Some(next_avatar.as_deref())
        } else {
            None
        };

        let updated =
            crate::store::pg::set_user_profile(&st.db, &user.user_id, name_arg, avatar_arg)
                .await?
                .ok_or_else(|| ApiErr(LatticeError::not_found("user not found")))?;
        // A profile change is an account-level operation: the audit goes through the unified entry (NATS audit stream → durable consumer persists to PG;
        // when the Redis bus/publish fails, audit_emit writes PG directly). Failures return 500 per existing semantics.
        crate::routing::audit::audit_emit(
            &st,
            Some(&user.user_id),
            "self.update",
            Some(&user.user_id),
            // Note: **do not record the raw avatar**, only "whether it changed" (a data URL can reach 256KiB)
            &json!({ "display_name": updated.display_name, "avatar_changed": avatar_changed }),
            ip_of(&headers).as_deref(),
        )
        .await?;
        ok(Json(profile_json(&st, &updated)))
    }

    #[derive(Debug, Deserialize)]
    pub struct ChangePasswordReq {
        pub old_password: String,
        pub new_password: String,
    }

    /// `POST /v1/users/me/password`: change own password (old-password check + argon2id rehash).
    ///
    /// Session semantics (⑤ §2 self-service semantics): revoke the refresh tokens of **other devices** (the current device is kept;
    /// other devices must log in again), while the current device's access JWT is unchanged (stateless snapshot).
    /// A wrong old password returns 422 (not 401): this is a form error by an already-logged-in user, and
    /// the console would treat 401 as "session expired" and kick the user straight back to the login page.
    /// The failure counter reuses the login-failure key family/window/threshold (5/min per user, ⑤ §1.1 / §17.13)
    /// to prevent online brute-forcing of the old password; successes and failures both count, so it cannot be bypassed.
    pub async fn change_own_password(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        headers: HeaderMap,
        Json(req): Json<ChangePasswordReq>,
    ) -> ApiResult<Response> {
        let scope = format!("password:{}", user.user_id);
        let attempts = st.redis.bump_login_failure(&scope, 60).await.unwrap_or(0);
        if attempts > i64::from(lattice_core::protocol::LOGIN_RATE_PER_ACCOUNT) {
            return Err(ApiErr(
                LatticeError::rate("password change rate limit exceeded")
                    .with_reason("password"),
            ));
        }

        let me = crate::store::pg::user_by_id(&st.db, &user.user_id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::not_found("user not found")))?;
        if me.status != "active" {
            return Err(ApiErr(LatticeError::auth_fail("account not active")));
        }
        if !password::verify_password(&req.old_password, &me.password_hash) {
            return Err(ApiErr(
                LatticeError::format("old password mismatch")
                    .with_reason("old_password")
                    .with_detail("field", json!("old_password")),
            ));
        }
        password::validate_password(&req.new_password).map_err(ApiErr)?;
        if req.old_password == req.new_password {
            return Err(ApiErr(
                LatticeError::format("new password must differ from old password")
                    .with_reason("same_password")
                    .with_detail("field", json!("new_password")),
            ));
        }

        let hash = password::hash_password(&req.new_password)?;
        if !crate::store::pg::set_user_password(&st.db, &user.user_id, &hash).await? {
            return Err(ApiErr(LatticeError::not_found("user not found")));
        }
        let sessions_revoked =
            crate::store::pg::revoke_user_devices(&st.db, &user.user_id, Some(&user.device_id))
                .await?;
        // If other devices are still online, disconnect them directly (otherwise the old access token still works on existing connections)
        for c in st.hub.of_user(&user.user_id) {
            if c.device != user.device_id {
                let _ = c.tx.try_send(crate::state::shutdown_frame("logout"));
            }
        }
        // Changing one's own password is an account-security operation: the audit goes through the unified entry (NATS audit stream → consumer persists to PG;
        // when the Redis bus/publish fails, audit_emit writes PG directly). Failures return 500 per existing semantics.
        crate::routing::audit::audit_emit(
            &st,
            Some(&user.user_id),
            "self.password_change",
            Some(&user.user_id),
            &json!({ "sessions_revoked": sessions_revoked, "current_device_kept": true }),
            ip_of(&headers).as_deref(),
        )
        .await?;
        ok(Json(json!({
            "ok": true,
            "sessions_revoked": sessions_revoked,
            "current_device_kept": true,
        })))
    }

    /// `GET /v1/users/{id}/devices`: `revoked_at is null` means active (⑤ §2).
    pub async fn list_devices(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
    ) -> ApiResult<Response> {
        if user.user_id != id && !user.is_admin() {
            return Err(ApiErr(LatticeError::forbidden("can only read own devices")));
        }
        let rows = crate::store::pg::devices_of(&st.db, &id).await?;
        let items: Vec<Value> = rows
            .iter()
            .map(|d| {
                json!({
                    "id": d.id,
                    "name": d.name,
                    "platform": d.platform,
                    "fingerprint": d.fingerprint,
                    "last_seen": d.last_seen,
                    "revoked_at": d.revoked_at,
                })
            })
            .collect();
        ok(Json(json!({ "items": items })))
    }

    /// `DELETE /v1/devices/{id}`: revoke the device token (remote logout), 204 (⑤ §2).
    pub async fn revoke_device(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
    ) -> ApiResult<Response> {
        let dev = crate::store::pg::device_by_id(&st.db, &id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::not_found("device not found")))?;
        if dev.user_id != user.user_id && !user.is_admin() {
            return Err(ApiErr(LatticeError::forbidden("not owner")));
        }
        crate::store::pg::revoke_device(&st.db, &id).await?;
        st.unregister_online(&dev.user_id, &dev.id).await;
        Ok(StatusCode::NO_CONTENT.into_response())
    }

    /// `GET /v1/me`: identity + online devices + queue depth (client startup snapshot, ⑤ §2).
    pub async fn me(State(st): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Response> {
        let devices = st.online_devices(&user.user_id).await;
        let (depth, oldest) = crate::routing::pending::depth(&st, &user.user_id).await;
        // v0.14: add username/display_name — a cold-start client holding only a refresh token needs them to render the account area
        let row = crate::store::pg::user_by_id(&st.db, &user.user_id).await?;
        ok(Json(json!({
            "user_id": user.user_id,
            "username": row.as_ref().map(|u| u.username.clone()),
            "display_name": row.as_ref().and_then(|u| u.display_name.clone()),
            // v0.8: first-screen avatar rendering in the client account area (clients fall back to initials when unset)
            "avatar": row.as_ref().and_then(|u| u.avatar.clone()),
            "device_id": user.device_id,
            "role": user.role.as_str(),
            "node_id": st.node_id,
            "online_devices": devices,
            "pending": { "depth": depth, "oldest_seq": oldest },
            "server_ts": chrono::Utc::now(),
        })))
    }
}

// ---------------------------------------------------------------------------
// §3 conversations
// ---------------------------------------------------------------------------

pub mod conversations {
    use super::*;

    #[derive(Debug, Deserialize)]
    pub struct CreateReq {
        pub kind: String,
        pub name: Option<String>,
        #[serde(default)]
        pub member_ids: Vec<String>,
    }

    /// `POST /v1/conversations` (⑤ §3): for `kind=dm`, `member_ids` must have exactly one member and is idempotent.
    pub async fn create(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Json(req): Json<CreateReq>,
    ) -> ApiResult<Response> {
        if !matches!(req.kind.as_str(), "dm" | "group" | "topic") {
            return Err(ApiErr(
                LatticeError::format("invalid kind")
                    .with_detail("field", json!("kind"))
                    .with_reason("kind"),
            ));
        }
        if req.kind == "dm" {
            if req.member_ids.len() != 1 {
                return Err(ApiErr(
                    LatticeError::format("dm requires exactly one member")
                        .with_detail("field", json!("member_ids"))
                        .with_reason("member_ids"),
                ));
            }
            if let Some(existing) =
                crate::store::pg::find_dm(&st.db, &user.user_id, &req.member_ids[0]).await?
            {
                let members = crate::store::pg::members_of(&st.db, &existing.id).await?;
                return ok(Json(json!({
                    "id": existing.id, "kind": existing.kind, "name": existing.name,
                    "members": members.iter().map(|m| &m.user_id).collect::<Vec<_>>(),
                    "created_at": existing.created_at,
                })));
            }
        }
        let conv = crate::store::pg::create_conversation(
            &st.db,
            &req.kind,
            req.name.as_deref(),
            &user.user_id,
            &req.member_ids,
        )
        .await?;
        // Active member-cache invalidation (PL-17 hook): a new conversation id is unique and normally has no old cache entry,
        // but we still invalidate uniformly to keep the invariant "every member-write path invalidates" (defensive).
        st.invalidate_member_cache(&conv.id);
        let members = crate::store::pg::members_of(&st.db, &conv.id).await?;
        let resp = Json(json!({
            "id": conv.id,
            "kind": conv.kind,
            "name": conv.name,
            "members": members.iter().map(|m| &m.user_id).collect::<Vec<_>>(),
            "created_at": conv.created_at,
        }));
        Ok((StatusCode::CREATED, resp).into_response())
    }

    /// `GET /v1/conversations`: includes `last_seq`/`last_msg_at`/`unread` (derived from `read_watermark`).
    pub async fn list(State(st): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Response> {
        let rows = crate::store::pg::list_conversations(&st.db, &user.user_id).await?;
        let items: Vec<Value> = rows
            .iter()
            .map(|c| {
                json!({
                    "id": c.id, "kind": c.kind, "name": c.name,
                    "last_seq": c.last_seq, "last_msg_at": c.last_msg_at,
                    "unread": c.unread, "members": c.members,
                })
            })
            .collect();
        ok(Json(json!({ "items": items })))
    }

    /// `GET /v1/conversations/{id}`: details + members.
    pub async fn detail(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
    ) -> ApiResult<Response> {
        ensure_member(&st, &id, &user.user_id).await?;
        let conv = crate::store::pg::conversation_by_id(&st.db, &id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::not_found("conversation not found")))?;
        let members = crate::store::pg::members_of(&st.db, &id).await?;
        let items: Vec<Value> = members
            .iter()
            .map(|m| json!({ "user_id": m.user_id, "role": m.role, "joined_at": m.joined_at }))
            .collect();
        ok(Json(json!({
            "id": conv.id, "kind": conv.kind, "name": conv.name,
            "created_at": conv.created_at, "members": items,
        })))
    }

    #[derive(Debug, Deserialize)]
    pub struct RenameReq {
        pub name: String,
    }

    /// `PATCH /v1/conversations/{id}`: owner or admin member role.
    pub async fn rename(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
        Json(req): Json<RenameReq>,
    ) -> ApiResult<Response> {
        let role = crate::store::pg::member_role(&st.db, &id, &user.user_id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::forbidden("not a member").with_reason("not_member")))?;
        if role != "owner" && !user.is_admin() {
            return Err(ApiErr(LatticeError::forbidden("owner only")));
        }
        crate::store::pg::rename_conversation(&st.db, &id, &req.name).await?;
        ok(Json(json!({ "id": id, "name": req.name })))
    }

    #[derive(Debug, Deserialize)]
    pub struct AddMembersReq {
        pub user_ids: Vec<String>,
    }

    /// `POST /v1/conversations/{id}/members`: owner only.
    pub async fn add_members(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
        Json(req): Json<AddMembersReq>,
    ) -> ApiResult<Response> {
        let role = crate::store::pg::member_role(&st.db, &id, &user.user_id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::forbidden("not a member").with_reason("not_member")))?;
        if role != "owner" && !user.is_admin() {
            return Err(ApiErr(LatticeError::forbidden("owner only")));
        }
        let added = crate::store::pg::add_members(&st.db, &id, &req.user_ids).await?;
        // Active member-cache invalidation (PL-17 hook): after adding members, that conversation's membership/member-list cache is invalidated immediately,
        // without waiting for TTL convergence (new members can send immediately and the member list is visible immediately).
        st.invalidate_member_cache(&id);
        ok(Json(json!({ "added": added })))
    }

    /// `DELETE /v1/conversations/{id}/members/{uid}`: owner, or the member leaving themselves.
    pub async fn remove_member(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path((id, uid)): Path<(String, String)>,
    ) -> ApiResult<Response> {
        let role = crate::store::pg::member_role(&st.db, &id, &user.user_id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::forbidden("not a member").with_reason("not_member")))?;
        if uid != user.user_id && role != "owner" && !user.is_admin() {
            return Err(ApiErr(LatticeError::forbidden("owner only")));
        }
        crate::store::pg::remove_member(&st.db, &id, &uid).await?;
        // Active member-cache invalidation (PL-17 hook): after a member is removed or leaves, that conversation's cache is invalidated immediately, so
        // the removed user's next send must re-validate against PG (no more window where a stale positive cache lets them through).
        st.invalidate_member_cache(&id);
        Ok(StatusCode::NO_CONTENT.into_response())
    }

    #[derive(Debug, Deserialize)]
    pub struct ReadReq {
        pub seq: i64,
    }

    /// `POST /v1/conversations/{id}/read` (new in v0.5): idempotent, monotonically takes max, ignores regressions (⑤ §3).
    pub async fn mark_read(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
        Json(req): Json<ReadReq>,
    ) -> ApiResult<Response> {
        ensure_member(&st, &id, &user.user_id).await?;
        let wm = crate::store::pg::set_read(&st.db, &id, &user.user_id, &user.device_id, req.seq)
            .await?;
        // Multi-device read sync: broadcast to the user's other devices (§17.4-4; a UI dedup hint only, pending is not withdrawn)
        let frame = lattice_core::Frame::json(
            lattice_core::WsCommand::Receipt,
            &json!({ "id": id, "state": "delivered", "conv_id": id, "read_seq": wm }),
        );
        if let Ok(frame) = frame {
            for c in st.hub.of_user(&user.user_id) {
                if c.device != user.device_id {
                    let _ = c.tx.try_send(frame.clone());
                }
            }
        }
        ok(Json(json!({ "conv_id": id, "last_read_seq": wm })))
    }

    /// `GET /v1/conversations/{id}/messages`: cursor pagination (half-open interval, ⑤ §0.4).
    pub async fn history(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
        Query(q): Query<CursorQuery>,
    ) -> ApiResult<Response> {
        ensure_member(&st, &id, &user.user_id).await?;
        let limit = q.limit.unwrap_or(50).clamp(1, 200);
        let rows =
            crate::store::pg::history(&st.db, &id, q.before_seq, q.after_seq, limit).await?;
        let items: Vec<Value> = rows.iter().map(message_json).collect();
        let next = items
            .last()
            .and_then(|v| v.get("seq"))
            .and_then(|s| s.as_i64())
            .map(|s| json!({ "before_seq": s }));
        ok(Json(json!({ "items": items, "next_cursor": next })))
    }

    pub async fn ensure_member(st: &Arc<AppState>, conv: &str, user: &str) -> ApiResult<()> {
        match crate::store::pg::member_role(&st.db, conv, user).await? {
            Some(_) => Ok(()),
            None => Err(ApiErr(
                LatticeError::forbidden("not a member").with_reason("not_member"),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// §4 messages
// ---------------------------------------------------------------------------

pub fn message_json(m: &crate::store::pg::Message) -> Value {
    json!({
        "id": m.id,
        "conv_id": m.conv_id,
        "sender": m.sender,
        "env_type": m.env_type,
        "content_type": m.content_type,
        "size": m.size,
        "chunk_total": m.chunk_total,
        "seq": m.seq,
        "status": m.status,
        "created_at": m.created_at,
        "expires_at": m.expires_at,
        "payload_ref": m.payload_ref,
        "has_inline_payload": m.payload.is_some(),
    })
}

pub mod messages {
    use super::*;

    #[derive(Debug, Deserialize)]
    pub struct SendReq {
        pub id: Option<String>,
        pub r#type: Option<String>,
        pub conv_id: String,
        pub to_user: Option<String>,
        pub to_topic: Option<String>,
        #[serde(default)]
        pub to_devices: Vec<String>,
        pub encoding: Option<String>,
        pub ttl_seconds: Option<u32>,
        pub checksum_sha256: Option<String>,
        pub content_type: Option<String>,
        pub payload: Option<String>,
    }

    /// `POST /v1/messages`: HTTP uplink for small messages (≤1MB), semantically equivalent to the WS `envelope` (⑤ §4.1).
    pub async fn send(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Json(req): Json<SendReq>,
    ) -> ApiResult<Response> {
        let payload = req
            .payload
            .as_deref()
            .and_then(lattice_core::envelope::base64_decode)
            .unwrap_or_default();

        let mut env = lattice_core::Envelope {
            id: req.id.clone().unwrap_or_else(lattice_core::ids::new_id),
            r#type: req.r#type.clone().unwrap_or_else(|| "text".into()),
            content_type: req.content_type.clone().unwrap_or_default(),
            encoding: req.encoding.clone().unwrap_or_else(|| "utf8".into()),
            payload,
            conv_id: req.conv_id.clone(),
            ttl_seconds: req.ttl_seconds.unwrap_or(0),
            route: Some(lattice_core::RouteInfo {
                to_user: req.to_user.clone().unwrap_or_default(),
                to_topic: req.to_topic.clone().unwrap_or_default(),
                cc: Vec::new(),
                to_devices: req.to_devices.clone(),
            }),
            ..Default::default()
        };
        if let Some(c) = req.checksum_sha256.as_deref() {
            env.checksum_sha256 =
                lattice_core::envelope::base64_decode(c).unwrap_or_default();
        }

        let out = crate::pipeline::ingest(&st, &user.user_id, &user.device_id, env).await?;
        let body = Json(json!({
            "id": out.id,
            "conv_id": out.conv_id,
            "seq": out.seq,
            "state": out.state.as_str(),
            "duplicate": out.duplicate,
            "recipients": out.recipients,
        }));
        if out.duplicate {
            return ok(body);
        }
        Ok((StatusCode::CREATED, body).into_response())
    }

    /// `GET /v1/messages/{id}`: metadata + `delivery_summary` (⑤ §4.2).
    pub async fn meta(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
    ) -> ApiResult<Response> {
        let msg = crate::store::pg::message_by_id(&st.db, &id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::not_found("message not found")))?;
        conversations::ensure_member(&st, &msg.conv_id, &user.user_id).await?;
        let deliveries = crate::store::pg::delivery_of(&st.db, &id).await?;
        let mut by_user: std::collections::BTreeMap<String, Vec<Value>> = Default::default();
        for d in deliveries {
            by_user.entry(d.to_user).or_default().push(json!({
                "device": d.to_device,
                "state": d.state,
                "attempts": d.attempts,
                "last_at": d.last_at,
                "acked_at": d.acked_at,
            }));
        }
        let summary: Vec<Value> = by_user
            .into_iter()
            .map(|(u, devices)| json!({ "to_user": u, "devices": devices }))
            .collect();
        let mut body = message_json(&msg);
        body["delivery_summary"] = json!(summary);
        ok(Json(body))
    }

    /// `GET /v1/messages/{id}/download`: small messages return directly; large objects 302 → presigned (⑤ §4.3).
    pub async fn download(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
    ) -> ApiResult<Response> {
        let msg = crate::store::pg::message_by_id(&st.db, &id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::not_found("message not found")))?;
        conversations::ensure_member(&st, &msg.conv_id, &user.user_id).await?;

        if let Some(key) = msg.payload_ref.clone() {
            let url = st
                .s3
                .presign_get(&st.s3.cfg().bucket_large, &key, PRESIGN_TTL_SECS);
            let mut resp = StatusCode::FOUND.into_response();
            resp.headers_mut().insert(
                HeaderName::from_static("location"),
                HeaderValue::from_str(&url).unwrap_or(HeaderValue::from_static("")),
            );
            return ok(resp);
        }

        match msg.payload {
            Some(bytes) => {
                let ct = msg
                    .content_type
                    .clone()
                    .unwrap_or_else(|| "application/octet-stream".into());
                let mut resp = (StatusCode::OK, bytes).into_response();
                resp.headers_mut().insert(
                    HeaderName::from_static("content-type"),
                    HeaderValue::from_str(&ct).unwrap_or(HeaderValue::from_static("application/octet-stream")),
                );
                resp.headers_mut().insert(
                    HeaderName::from_static("content-disposition"),
                    HeaderValue::from_static("attachment"),
                );
                ok(resp)
            }
            None => Err(ApiErr(LatticeError::not_found("payload not available"))),
        }
    }

    #[derive(Debug, Deserialize)]
    pub struct ChunksQuery {
        pub missing: Option<String>,
    }

    /// `GET /v1/chunks/{msg_id}`: chunk list / presign (⑤ §4.4). Chunks themselves are not messages.
    pub async fn chunks(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(msg_id): Path<String>,
        Query(q): Query<ChunksQuery>,
    ) -> ApiResult<Response> {
        if lattice_core::ids::parse_chunk_id(&msg_id).is_some() {
            return Err(ApiErr(
                LatticeError::format("chunk ids are not addressable as messages")
                    .with_reason("chunk_id"),
            ));
        }
        // Chunks are **not messages rows** before reassembly (§17.2): we must not call message_by_id first and 404,
        // otherwise in-flight chunks could never be queried or asked for missing parts (E18-GAP). When a message row exists, use its conv;
        // otherwise use chunks_index.conv_id (written since migration 0011) for the membership check.
        let msg = crate::store::pg::message_by_id(&st.db, &msg_id).await?;
        let rows = crate::store::pg::chunks_of(&st.db, &msg_id).await?;
        if rows.is_empty() {
            return Err(ApiErr(LatticeError::not_found("message not found")));
        }
        let conv_id = msg
            .as_ref()
            .map(|m| m.conv_id.clone())
            .or_else(|| rows.iter().find_map(|r| r.conv_id.clone()))
            .ok_or_else(|| ApiErr(LatticeError::not_found("message not found")))?;
        conversations::ensure_member(&st, &conv_id, &user.user_id).await?;
        let wanted: Option<Vec<u32>> = q.missing.as_ref().map(|s| {
            s.split(',')
                .filter_map(|x| x.trim().parse::<u32>().ok())
                .collect()
        });
        let items: Vec<Value> = rows
            .iter()
            .filter(|r| wanted.as_ref().map(|w| w.contains(&(r.idx as u32))).unwrap_or(true))
            .map(|r| {
                json!({
                    "idx": r.idx,
                    "size": r.size,
                    "checksum": r.checksum.as_ref().map(|c| lattice_core::envelope::base64_encode(c)),
                    "storage_key": r.storage_key,
                    "presigned_url": r.storage_key.as_ref().map(|k| st.s3.presign_get(&st.s3.cfg().bucket_large, k, PRESIGN_TTL_SECS)),
                })
            })
            .collect();
        // The chunk-repair contract of ⑤ §9.3 uniformly uses `missing_index[]` (the same field name as WS request-chunks);
        // the server computes "which chunks are still missing" from chunks_index, so clients need no diffing.
        let got: Vec<u32> = rows.iter().map(|r| r.idx as u32).collect();
        let total = rows.first().map(|r| r.total as u32).unwrap_or(0);
        let missing_index = crate::pipeline::chunk::missing_indexes(total, &got);
        ok(Json(json!({
            "msg_id": msg_id,
            "total": total,
            "received": got.len(),
            "missing_index": missing_index,
            "items": items,
        })))
    }
}

// ---------------------------------------------------------------------------
// §5 uploads (MinIO Multipart presign)
// ---------------------------------------------------------------------------

pub mod uploads {
    use super::*;

    /// S3 part cap for a single Multipart upload (S3 protocol value 10000).
    ///
    /// Used to block requests with an "absurd declared size" before CreateMultipartUpload (4GB = 512 parts, still in range),
    /// so object storage never gets a session that can never complete.
    const S3_MAX_PARTS: i64 = 10_000;

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct UploadSession {
        pub upload_id: String,
        pub conv_id: String,
        pub user_id: String,
        pub name: String,
        pub size: i64,
        pub sha256: Option<String>,
        pub part_size: i64,
        pub part_count: i64,
        pub created_at: i64,
        #[serde(default)]
        pub completed_parts: Vec<i32>,
        /// E18: the **logical message id** and final object key pre-generated at create (reused by complete, ensuring idempotency and a unique object key).
        #[serde(default)]
        pub msg_id: Option<String>,
        #[serde(default)]
        pub object_key: Option<String>,
        /// E18: the uploadId returned by S3 `CreateMultipartUpload` — the locator key of `CompleteMultipartUpload`,
        /// and also the query key for the "authoritative completion progress" (ListParts).
        #[serde(default)]
        pub s3_upload_id: Option<String>,
    }

    /// Upload session key: **added by the implementation**, not registered in the ⑥ §3.1 key table (see README "documentation issues found during implementation").
    fn upload_key(id: &str) -> String {
        format!("lattice:upload:{id}")
    }

    #[derive(Debug, Deserialize)]
    pub struct CreateReq {
        pub size: i64,
        pub sha256: Option<String>,
        pub name: Option<String>,
        pub conv_id: String,
        pub part_size: Option<i64>,
    }

    /// Declared whole-object sha256: accepts `b64:<base64>`, 64-char hex, or plain base64 (the `b64:…` form of ⑤ §5.1).
    fn parse_declared_sha256(raw: &str) -> Option<Vec<u8>> {
        let s = raw.trim();
        if s.is_empty() {
            return None;
        }
        if let Some(rest) = s.strip_prefix("b64:") {
            return lattice_core::envelope::base64_decode(rest);
        }
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut out = Vec::with_capacity(32);
            for i in 0..32 {
                out.push(u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?);
            }
            return Some(out);
        }
        lattice_core::envelope::base64_decode(s)
    }

    fn hex_lower(raw: &[u8]) -> String {
        raw.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn s3_dep_err(msg: impl Into<String>) -> ApiErr {
        ApiErr(error::internal(msg).with_detail("dep", serde_json::json!("s3")))
    }

    fn normalize_etag(raw: &str) -> String {
        raw.trim().trim_matches('"').to_ascii_lowercase()
    }

    /// Presigned UploadPart URL list (at most 64 per response; the client renews on demand via `POST .../parts`).
    fn part_urls(
        st: &Arc<AppState>,
        bucket: &str,
        object_key: &str,
        s3_upload_id: &str,
        first: i64,
        last: i64,
    ) -> Vec<Value> {
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(PRESIGN_TTL_SECS as i64);
        (first..=last)
            .take(64)
            .map(|p| {
                json!({
                    "part": p,
                    "url": st.s3.presign_upload_part(bucket, object_key, s3_upload_id, p as u32, PRESIGN_TTL_SECS),
                    "expires_at": expires_at,
                })
            })
            .collect()
    }

    /// `POST /v1/uploads`: request an upload (⑤ §5.1). `part_size` is fixed at 8MB; any other value → 422.
    ///
    /// E18: create really starts an S3 Multipart upload, and `part_urls` are UploadPart presigned URLs for **that same Multipart upload**;
    /// therefore complete can use `CompleteMultipartUpload` to have object storage assemble the object server-side
    /// (4GB-scale data never enters node memory).
    pub async fn create(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Json(req): Json<CreateReq>,
    ) -> ApiResult<Response> {
        let fixed = lattice_core::protocol::UPLOAD_PART_BYTES as i64;
        if let Some(ps) = req.part_size {
            if ps != fixed {
                return Err(ApiErr(
                    LatticeError::format(format!("part_size must be {fixed}")).with_reason("part_size"),
                ));
            }
        }
        if req.size <= 0 {
            return Err(ApiErr(LatticeError::format("size must be > 0")));
        }
        let declared_sha = match req.sha256.as_deref() {
            Some(raw) if !raw.trim().is_empty() => match parse_declared_sha256(raw) {
                Some(v) => Some(lattice_core::envelope::base64_encode(&v)),
                None => {
                    return Err(ApiErr(
                        LatticeError::format("sha256 must be b64:<base64> or 64-hex")
                            .with_reason("sha256"),
                    ))
                }
            },
            _ => None,
        };
        let part_count = (req.size + fixed - 1) / fixed;
        if part_count > S3_MAX_PARTS {
            return Err(ApiErr(
                LatticeError::format(format!(
                    "size {} needs {part_count} parts > S3 multipart limit {S3_MAX_PARTS}",
                    req.size
                ))
                .with_reason("size")
                .with_detail("part_count", serde_json::json!(part_count))
                .with_detail("max_part_count", serde_json::json!(S3_MAX_PARTS)),
            ));
        }
        conversations::ensure_member(&st, &req.conv_id, &user.user_id).await?;

        let upload_id = lattice_core::ids::new_id();
        let msg_id = lattice_core::ids::new_id();
        let object_key = st.s3.object_key(&msg_id, 0);
        let bucket = st.s3.cfg().bucket_large.clone();
        let s3_upload_id = st
            .s3
            .create_multipart_upload(&bucket, &object_key)
            .await
            .map_err(|e| s3_dep_err(format!("create multipart upload failed: {e}")))?;

        let session = UploadSession {
            upload_id: upload_id.clone(),
            conv_id: req.conv_id.clone(),
            user_id: user.user_id.clone(),
            name: req.name.unwrap_or_else(|| "blob".into()),
            size: req.size,
            sha256: declared_sha,
            part_size: fixed,
            part_count,
            created_at: chrono::Utc::now().timestamp(),
            completed_parts: Vec::new(),
            msg_id: Some(msg_id),
            object_key: Some(object_key.clone()),
            s3_upload_id: Some(s3_upload_id.clone()),
        };
        crate::transport::http::uploads::persist(&st, &session).await?;

        let resp = Json(json!({
            "upload_id": upload_id,
            "part_size": fixed,
            "part_count": part_count,
            "part_urls": part_urls(&st, &bucket, &object_key, &s3_upload_id, 1, part_count),
            "expires_at": chrono::Utc::now() + chrono::Duration::seconds(PRESIGN_TTL_SECS as i64),
        }));
        Ok((StatusCode::CREATED, resp).into_response())
    }

    /// Redis session write (hash form: `lattice:upload:{id}`).
    pub async fn persist(st: &Arc<AppState>, s: &UploadSession) -> Result<()> {
        let body = serde_json::to_string(s)
            .map_err(|e| error::internal(format!("upload encode failed: {e}")))?;
        st.redis
            .set_json(&upload_key(&s.upload_id), &body, 86_400)
            .await
    }

    pub async fn load(st: &Arc<AppState>, id: &str) -> Result<Option<UploadSession>> {
        let raw = st.redis.get_json(&upload_key(id)).await?;
        Ok(raw.and_then(|s| serde_json::from_str::<UploadSession>(&s).ok()))
    }

    /// Calibrate the completion progress in Redis with MinIO `ListParts` (⑤ §5.3 "the authoritative fact lives in MinIO").
    ///
    /// Presigned PUTs go straight to object storage and bypass the node, so "which parts really finished" can only be asked of object storage;
    /// writing back to Redis on every part completion is not feasible (the node cannot observe the PUT), so calibrating on the read path suffices:
    /// both `GET /v1/uploads/{id}` and `reissue` calibrate first, so resuming and re-issuing unfinished parts rely on the real parts.
    async fn refresh_progress(st: &Arc<AppState>, s: &mut UploadSession) {
        let (Some(s3_upload_id), Some(object_key)) = (s.s3_upload_id.clone(), s.object_key.clone())
        else {
            return;
        };
        let bucket = st.s3.cfg().bucket_large.clone();
        match st.s3.list_parts(&bucket, &object_key, &s3_upload_id).await {
            Ok(parts) => {
                let mut nums: Vec<i32> = parts.iter().map(|p| p.part_number as i32).collect();
                nums.sort_unstable();
                nums.dedup();
                if nums != s.completed_parts {
                    s.completed_parts = nums;
                    if let Err(e) = persist(st, s).await {
                        tracing::warn!(upload_id = %s.upload_id, error = %e, "upload progress: persist refreshed progress failed");
                    }
                }
            }
            Err(e) => tracing::warn!(
                upload_id = %s.upload_id,
                error = %e,
                "upload progress: ListParts failed; serving cached progress"
            ),
        }
    }

    #[derive(Debug, Deserialize)]
    pub struct CompleteReq {
        pub parts: Vec<CompletePart>,
    }

    #[derive(Debug, Deserialize)]
    pub struct CompletePart {
        pub part: i32,
        pub etag: Option<String>,
    }

    /// `POST /v1/uploads/{id}/complete`: CompleteMultipartUpload assembles the object → verify the whole sha256 →
    /// generate a file Envelope and deliver it (⑤ §5.2).
    pub async fn complete(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
        Json(req): Json<CompleteReq>,
    ) -> ApiResult<Response> {
        let mut session = load(&st, &id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::not_found("upload not found")))?;
        if session.user_id != user.user_id {
            return Err(ApiErr(LatticeError::forbidden("not upload owner")));
        }
        refresh_progress(&st, &mut session).await;
        let (Some(s3_upload_id), Some(object_key), Some(msg_id)) = (
            session.s3_upload_id.clone(),
            session.object_key.clone(),
            session.msg_id.clone(),
        ) else {
            // Old sessions created before the migration have no Multipart upload, so the server cannot assemble the object: fail explicitly instead of a fake 201 success.
            return Err(ApiErr(
                LatticeError::conflict("upload session has no S3 multipart upload; re-create the upload")
                    .with_reason("multipart_missing"),
            ));
        };
        let bucket = st.s3.cfg().bucket_large.clone();

        // 1) Collect ETags of uploaded parts with ListParts as the authority; ETags in the request body are only cross-checked for consistency.
        let listed = st
            .s3
            .list_parts(&bucket, &object_key, &s3_upload_id)
            .await
            .map_err(|e| {
                if e.contains("HTTP 404") || e.contains("NoSuchUpload") {
                    ApiErr(
                        LatticeError::not_found("upload not found")
                            .with_detail("reason", serde_json::json!("multipart_no_such_upload")),
                    )
                } else {
                    s3_dep_err(format!("list parts failed: {e}"))
                }
            })?;
        let mut by_num: std::collections::BTreeMap<u32, String> = listed
            .iter()
            .map(|p| (p.part_number, p.etag.clone()))
            .collect();
        for p in &req.parts {
            if p.part <= 0 || (p.part as i64) > session.part_count {
                return Err(ApiErr(
                    LatticeError::format(format!(
                        "part {} out of range 1..={}",
                        p.part, session.part_count
                    ))
                    .with_reason("parts"),
                ));
            }
            let num = p.part as u32;
            if let Some(claimed) = p.etag.as_deref().map(str::trim).filter(|e| !e.is_empty()) {
                match by_num.get(&num) {
                    Some(authoritative) if normalize_etag(authoritative) != normalize_etag(claimed) => {
                        return Err(ApiErr(
                            LatticeError::format(format!("part {num} etag mismatch"))
                                .with_reason("parts"),
                        ));
                    }
                    Some(_) => {}
                    None => {
                        by_num.insert(num, claimed.to_string());
                    }
                }
            }
        }
        let missing: Vec<u32> = (1..=session.part_count as u32)
            .filter(|n| !by_num.contains_key(n))
            .collect();
        if !missing.is_empty() {
            return Err(ApiErr(
                LatticeError::format("upload incomplete: missing parts")
                    .with_reason("missing_parts")
                    .with_detail("missing", serde_json::json!(missing)),
            ));
        }
        let parts: Vec<(u32, String)> = by_num.into_iter().collect();

        // 2) Assemble the object server-side (CompleteMultipartUpload; zero-copy, no node memory).
        st.s3
            .complete_multipart_upload(&bucket, &object_key, &s3_upload_id, &parts)
            .await
            .map_err(|e| {
                if e.contains("HTTP 4") {
                    ApiErr(
                        LatticeError::format(format!("complete multipart upload failed: {e}"))
                            .with_reason("parts"),
                    )
                } else {
                    s3_dep_err(format!("complete multipart upload failed: {e}"))
                }
            })?;

        // 3) Whole verification (⑤ §5.2): a declared sha256 must match; when not declared, at least check that the actual byte count equals the declared size.
        //    Verification failure → delete the object + 422 FORMAT, leaving no object that "can 302 but has wrong content".
        let expected_bytes = session.size.max(0) as u64;
        let (actual, actual_len) = st
            .s3
            .object_sha256(&bucket, &object_key, expected_bytes)
            .await
            .map_err(|e| s3_dep_err(format!("verify uploaded object failed: {e}")))?;
        if actual_len != expected_bytes {
            let _ = st.s3.delete_object(&bucket, &object_key).await;
            let _ = st.redis.del(&upload_key(&id)).await;
            return Err(ApiErr(
                LatticeError::format(format!(
                    "uploaded object size {actual_len} != declared {}",
                    session.size
                ))
                .with_reason("size"),
            ));
        }
        if let Some(declared) = session.sha256.as_deref().and_then(parse_declared_sha256) {
            if actual.as_slice() != declared.as_slice() {
                let _ = st.s3.delete_object(&bucket, &object_key).await;
                let _ = st.redis.del(&upload_key(&id)).await;
                tracing::warn!(
                    upload_id = %id,
                    expected = %hex_lower(&declared),
                    actual = %hex_lower(&actual),
                    "upload complete: declared whole-object sha256 mismatch; object deleted"
                );
                return Err(ApiErr(
                    LatticeError::format("declared whole-object sha256 mismatch")
                        .with_reason("checksum")
                        .with_detail("expected", serde_json::json!(hex_lower(&declared)))
                        .with_detail("actual", serde_json::json!(hex_lower(&actual))),
                ));
            }
        }

        // 4) Generate the file Envelope (payload_ref → the real object; metadata.size = real byte count, for messages.size).
        let actual_size = actual_len as i64;
        let env = lattice_core::Envelope {
            id: msg_id.clone(),
            r#type: "file".into(),
            content_type: "application/octet-stream".into(),
            encoding: "raw".into(),
            payload: Vec::new(),
            conv_id: session.conv_id.clone(),
            metadata: {
                let mut m = std::collections::HashMap::new();
                m.insert("payload_ref".to_string(), object_key.clone());
                m.insert("name".to_string(), session.name.clone());
                m.insert("size".to_string(), actual_size.to_string());
                m
            },
            ..Default::default()
        };

        let out = crate::pipeline::ingest(&st, &user.user_id, &user.device_id, env).await?;
        let part_numbers: Vec<i32> = parts.iter().map(|(n, _)| *n as i32).collect();
        // Keep the direct PG write (not wired to audit_emit): this is a **data-plane** upload-complete event, not a management-plane mandatory-trace point,
        // and the existing semantics are already non-fatal `.ok()`; chunked uploads can be frequent, so a direct write avoids adding
        // NATS publish/ack latency on the data-plane hot path. For management/account-plane audits see the `routing::audit::audit_emit` call sites.
        crate::store::pg::audit(
            &st.db,
            Some(&user.user_id),
            "upload_complete",
            Some(&out.id),
            &json!({ "size": actual_size, "parts": part_numbers.len() }),
            None,
        )
        .await
        .ok();
        let _ = st.redis.del(&upload_key(&id)).await;

        Ok((
            StatusCode::CREATED,
            Json(json!({
                "id": out.id,
                "conv_id": out.conv_id,
                "seq": out.seq,
                "state": out.state.as_str(),
                "payload_ref": object_key,
            })),
        )
            .into_response())
    }

    /// `GET /v1/uploads/{id}`: progress (completed parts) → resume upload.
    ///
    /// E18: completion progress uses MinIO `ListParts` as the authority (presigned PUTs bypass the node); Redis is only a cache.
    pub async fn progress(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
    ) -> ApiResult<Response> {
        let mut s = load(&st, &id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::not_found("upload not found")))?;
        if s.user_id != user.user_id && !user.is_admin() {
            return Err(ApiErr(LatticeError::forbidden("not upload owner")));
        }
        refresh_progress(&st, &mut s).await;
        let mut completed = s.completed_parts.clone();
        completed.sort_unstable();
        completed.dedup();
        ok(Json(json!({
            "upload_id": s.upload_id,
            "size": s.size,
            "part_size": s.part_size,
            "part_count": s.part_count,
            "completed_parts": completed,
        })))
    }

    /// `POST /v1/uploads/{id}/parts`: re-issue presigned URLs for unfinished parts (idempotent).
    pub async fn reissue(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
    ) -> ApiResult<Response> {
        let mut s = load(&st, &id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::not_found("upload not found")))?;
        if s.user_id != user.user_id {
            return Err(ApiErr(LatticeError::forbidden("not upload owner")));
        }
        refresh_progress(&st, &mut s).await;
        let (Some(s3_upload_id), Some(object_key)) = (s.s3_upload_id.clone(), s.object_key.clone())
        else {
            return Err(ApiErr(
                LatticeError::conflict("upload session has no S3 multipart upload; re-create the upload")
                    .with_reason("multipart_missing"),
            ));
        };
        let bucket = st.s3.cfg().bucket_large.clone();
        let mut parts: Vec<Value> = Vec::new();
        for p in 1..=s.part_count {
            if s.completed_parts.contains(&(p as i32)) {
                continue;
            }
            parts.push(json!({
                "part": p,
                "url": st.s3.presign_upload_part(&bucket, &object_key, &s3_upload_id, p as u32, PRESIGN_TTL_SECS),
            }));
            if parts.len() >= 64 {
                break;
            }
        }
        ok(Json(json!({ "upload_id": id, "part_urls": parts })))
    }

    /// `DELETE /v1/uploads/{id}`: abandon the upload (abort S3 Multipart; leftover objects are cleaned up by gc-multipart as a fallback), 204 (⑤ §5.3).
    pub async fn abort(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
    ) -> ApiResult<Response> {
        let s = load(&st, &id)
            .await?
            .ok_or_else(|| ApiErr(LatticeError::not_found("upload not found")))?;
        if s.user_id != user.user_id && !user.is_admin() {
            return Err(ApiErr(LatticeError::forbidden("not upload owner")));
        }
        if let (Some(s3_upload_id), Some(object_key)) = (s.s3_upload_id.clone(), s.object_key.clone()) {
            let bucket = st.s3.cfg().bucket_large.clone();
            if let Err(e) = st
                .s3
                .abort_multipart_upload(&bucket, &object_key, &s3_upload_id)
                .await
            {
                tracing::warn!(upload_id = %id, error = %e, "abort multipart upload failed (gc-multipart will retry)");
            }
        }
        let _ = st.redis.del(&upload_key(&id)).await;
        Ok(StatusCode::NO_CONTENT.into_response())
    }
}
// ---------------------------------------------------------------------------
// §7 Topic
// ---------------------------------------------------------------------------

pub mod topics {
    use super::*;

    /// `GET /v1/topics`: my subscriptions + unread offset delta.
    pub async fn list(State(st): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Response> {
        let rows = crate::store::pg::subscriptions(&st.db, &user.user_id).await?;
        let items: Vec<Value> = rows
            .iter()
            .map(|(topic, offset, unread)| {
                json!({ "topic": topic, "last_offset": offset, "unread": unread })
            })
            .collect();
        ok(Json(json!({ "items": items })))
    }

    /// `POST /v1/topics/{t}/subscribe`: idempotent, returns 200.
    pub async fn subscribe(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(t): Path<String>,
    ) -> ApiResult<Response> {
        let subscribers = crate::routing::topic::subscribe(&st, &user.user_id, &t).await?;
        // Active member-cache invalidation (PL-17 hook): topic subscriptions also live in conversation_members,
        // so a successful subscribe invalidates that topic conversation's member cache (failures do not affect the response; the TTL covers it).
        if let Ok(Some(conv)) = crate::store::pg::topic_conv_id(&st.db, &t).await {
            st.invalidate_member_cache(&conv);
        }
        ok(Json(json!({
            "topic": t,
            "subscribed_at": chrono::Utc::now(),
            "subscribers": subscribers,
        })))
    }

    /// `POST /v1/topics/{t}/unsubscribe`: idempotent.
    pub async fn unsubscribe(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(t): Path<String>,
    ) -> ApiResult<Response> {
        crate::routing::topic::unsubscribe(&st, &user.user_id, &t).await?;
        // Active member-cache invalidation (PL-17 hook): after unsubscribing, that topic conversation's member cache is invalidated immediately.
        if let Ok(Some(conv)) = crate::store::pg::topic_conv_id(&st.db, &t).await {
            st.invalidate_member_cache(&conv);
        }
        ok(Json(json!({ "topic": t, "subscribed": false })))
    }

    #[derive(Debug, Deserialize)]
    pub struct HistoryQuery {
        pub after_offset: Option<i64>,
        pub limit: Option<i64>,
    }

    /// `GET /v1/topics/{t}/history`: broadcast history replay (§18 D6, per-user per-topic watermark).
    pub async fn history(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(t): Path<String>,
        Query(q): Query<HistoryQuery>,
    ) -> ApiResult<Response> {
        let rows =
            crate::routing::topic::history(&st, &user.user_id, &t, q.after_offset, q.limit.unwrap_or(50))
                .await?;
        let items: Vec<Value> = rows.iter().map(message_json).collect();
        ok(Json(json!({ "topic": t, "items": items })))
    }

    #[derive(Debug, Deserialize)]
    pub struct PublishReq {
        pub payload: Option<String>,
        pub r#type: Option<String>,
        pub content_type: Option<String>,
    }

    /// `POST /v1/topics/{t}/publish` (P3, admin/ops only, ⑤ §7).
    pub async fn publish(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(t): Path<String>,
        Json(req): Json<PublishReq>,
    ) -> ApiResult<Response> {
        user.require_act()?;
        // Allocate seq + store messages first, then fan out: a topic's offline queue stores only `seq → msg_id`, so
        // fanning out before persisting would leave offline users unable to find the message on catch-up redelivery (the root cause of the empty msg_id observed in PL-17).
        let seq = crate::routing::seq::next_seq(&st, &format!("topic:{t}")).await?;
        let conv_id = crate::store::pg::topic_conv_id(&st.db, &t)
            .await?
            .unwrap_or_else(|| format!("topic:{t}"));
        let env = lattice_core::Envelope {
            id: lattice_core::ids::new_id(),
            r#type: req.r#type.unwrap_or_else(|| "text".into()),
            content_type: req.content_type.unwrap_or_default(),
            payload: req
                .payload
                .as_deref()
                .and_then(lattice_core::envelope::base64_decode)
                .unwrap_or_default(),
            conv_id: conv_id.clone(),
            sender: user.user_id.clone(),
            seq: seq as u64,
            ..Default::default()
        };
        crate::store::pg::insert_message(
            &st.db,
            crate::store::pg::NewMessage {
                id: &env.id,
                conv_id: &conv_id,
                sender: &user.user_id,
                env_type: &env.r#type,
                content_type: None,
                size: env.payload.len() as i64,
                chunk_total: 1,
                payload: Some(env.payload.clone()),
                payload_ref: None,
                seq: seq as i64,
                expires_at: None,
            },
        )
        .await?;
        let out = crate::pipeline::policy::publish_to_topic(&st, &t, &env).await?;
        // Keep the direct PG write (not wired to audit_emit): topic publish is a **data-plane** message hot path, not a management-plane operation,
        // and the existing semantics are non-fatal `.ok()`; putting every published message into the audit stream would raise the audit volume to message volume,
        // so for throughput and Stream capacity we keep the direct write (② §4.8 audits target management/security operations).
        crate::store::pg::audit(
            &st.db,
            Some(&user.user_id),
            "topic_publish",
            Some(&t),
            &json!({ "msg_id": env.id }),
            None,
        )
        .await
        .ok();
        ok(Json(json!({
            "id": env.id, "topic": t, "seq": seq, "state": out.state.as_str()
        })))
    }
}

/// Convenience entry for unified role checks (used by the admin plane).
///
/// The role rename (viewer → user) changed only the name: `Role::User` is still the "read-only" tier,
/// mapping to `AuthUser::require_read`; the ops-handling and admin-change tiers are unchanged.
pub fn require_role(user: &AuthUser, need: Role) -> Result<()> {
    match need {
        Role::User => user.require_read(),
        Role::Ops => user.require_act(),
        Role::Admin => user.require_change(),
    }
}

/// Allowlist validation of `DeliveryState` (used by console filters, §17.3).
pub fn parse_state(raw: &str) -> Result<DeliveryState> {
    DeliveryState::parse(raw).ok_or_else(|| {
        LatticeError::format(format!("invalid state: {raw}")).with_reason("state")
    })
}

/// Client IP extraction (for admin-plane audits).
pub fn ip_of(headers: &HeaderMap) -> Option<String> {
    client_ip(headers, None)
}

// ---------------------------------------------------------------------------
// User avatar validation (v0.8; shared by `PATCH /v1/users/me` and `PATCH /v1/admin/users/{id}`)
// ---------------------------------------------------------------------------

/// UTF-8 byte cap of the whole avatar string (including the data URL prefix): 256 KiB.
///
/// Clarification: the limit applies to the **stored string**, not the decoded image bytes — the avatar is stored as a data URL in
/// the PG `users.avatar` text column, and base64 inflates by about 4/3 relative to the original image, so after picking an image the console
/// must compress it first and then check by "encoded data URL string length" (the frontend `compressAvatar` uses the same convention).
/// The DB migration `0008_user_avatar.sql` also has a 300 KiB fallback CHECK constraint.
pub const AVATAR_MAX_BYTES: usize = 256 * 1024;

/// Character cap for `https://` external-link avatars (overlong URLs serve no reasonable purpose and may break list layouts).
pub const AVATAR_URL_MAX_CHARS: usize = 2048;

/// Allowed inline image data URL prefixes (MIME allowlist).
///
/// Deliberately **does not** accept `data:image/svg+xml`: SVG can embed scripts, and the account menu/user list renders avatars
/// as `<img src>`; allowing SVG would open a script-execution surface in the console (stored XSS).
/// For the same reason it rejects other schemes such as `javascript:` / `file:` / `http:` (cleartext transport).
const AVATAR_DATA_URL_PREFIXES: [&str; 4] = [
    "data:image/png;base64,",
    "data:image/jpeg;base64,",
    "data:image/webp;base64,",
    "data:image/gif;base64,",
];

fn avatar_invalid(message: &str) -> LatticeError {
    LatticeError::format(message)
        .with_reason("avatar")
        .with_detail("field", json!("avatar"))
}

fn avatar_too_large(message: String) -> LatticeError {
    LatticeError::format(message)
        .with_reason("avatar_too_large")
        .with_detail("field", json!("avatar"))
        .with_detail("max_bytes", json!(AVATAR_MAX_BYTES))
}

/// Validate and normalize the avatar field (shared by the self-service and admin write endpoints; `Ok(None)` = clear the avatar).
///
/// Three-state semantics (matching [`crate::store::pg::set_user_profile`]):
/// - `raw = None` → `Ok(None)`: **omitted field = unchanged** (callers use this to distinguish "not submitted" from "clear");
/// - whitespace-only string → `Ok(None)`: explicitly clear the avatar;
/// - `https://...` → returned as-is (requires a non-empty host, no whitespace/control characters, ≤2048 chars);
/// - `data:image/(png|jpeg|webp|gif);base64,...` → whole string ≤256KiB, payload non-empty and
///   valid base64 (standard alphabet, padding optional), returned as-is;
/// - anything else (`http://`, `javascript:`, SVG, `file:`, invalid base64, ...) → 422 FORMAT,
///   `details.field=avatar` (the frontend uses this to focus the avatar input).
pub fn validate_avatar(raw: Option<&str>) -> Result<Option<String>> {
    let Some(raw) = raw else { return Ok(None) };
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > AVATAR_MAX_BYTES {
        return Err(avatar_too_large(format!(
            "avatar too large: {} bytes (limit {AVATAR_MAX_BYTES})",
            value.len()
        )));
    }
    if let Some(rest) = value.strip_prefix("https://") {
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        if host.is_empty()
            || value.chars().count() > AVATAR_URL_MAX_CHARS
            || value.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(avatar_invalid("invalid avatar url: expect https:// URL"));
        }
        return Ok(Some(value.to_string()));
    }
    if let Some(prefix) = AVATAR_DATA_URL_PREFIXES.iter().find(|p| value.starts_with(**p)) {
        let payload = &value[prefix.len()..];
        if payload.is_empty() {
            return Err(avatar_invalid("avatar data url has empty payload"));
        }
        let decoded = B64
            .decode(payload)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(payload))
            .map_err(|_| avatar_invalid("avatar data url payload is not valid base64"))?;
        if decoded.is_empty() {
            return Err(avatar_invalid("avatar data url has empty payload"));
        }
        return Ok(Some(value.to_string()));
    }
    Err(avatar_invalid(
        "invalid avatar: expect https:// URL or data:image/(png|jpeg|webp|gif);base64,...",
    ))
}

pub mod media {
    use super::*;

    /// `GET /v1/media/turn-credentials` (⑤ §9.7): issue coturn REST API short-lived credentials.
    ///
    /// Algorithm (coturn `static-auth-secret` convention):
    ///   username   = `<expiry_unix>:<user_id>`
    ///   credential = base64(HMAC-SHA1(secret, username))
    ///
    /// Requires login only (any role) and writes nothing; when TURN is not configured it returns `enabled=false` without an error —
    /// TURN is an optional acceleration path, and clients should naturally fall back to direct/tunnel (design §17.9).
    pub async fn turn_credentials(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
    ) -> ApiResult<Response> {
        let cfg = &st.cfg.media;
        if cfg.turn_uris.is_empty() || cfg.turn_secret.is_empty() {
            return ok(Json(json!({
                "enabled": false,
                "uris": [],
                "ttl": 0
            })));
        }
        // Design §17.9/⑤ §9.7: keep credentials short-lived, upper bound 600s; out-of-range config is truncated to the bound, never issuing long-lived credentials.
        let ttl = cfg.turn_ttl.clamp(1, 600);
        let expiry = chrono::Utc::now().timestamp() + ttl as i64;
        let username = format!("{expiry}:{}", user.user_id);
        let mut mac = Hmac::<Sha1>::new_from_slice(cfg.turn_secret.as_bytes())
            .map_err(|e| ApiErr(LatticeError::internal(format!("turn secret invalid: {e}"))))?;
        mac.update(username.as_bytes());
        let credential = B64.encode(mac.finalize().into_bytes());
        ok(Json(json!({
            "enabled": true,
            "uris": cfg.turn_uris,
            "username": username,
            "credential": credential,
            "ttl": ttl,
            "expires_at": chrono::DateTime::from_timestamp(expiry, 0)
                .map(|t| t.to_rfc3339())
                .unwrap_or_default()
        })))
    }

    // -----------------------------------------------------------------------
    // §9.7 recording search/download (remaining PL-13 13.6: previously only `[4B len][body]` segment objects, with no index/API)
    //
    // The data source is `media_recordings` (migration 0009): each time a segment object is finalized, the recording path idempotently inserts one
    // metadata row (`object_key` is unique; a replay overwrites without duplicating rows); here we only read the index and issue MinIO presigns on the spot.
    //
    // Permission (per the task card): **admin/ops only** (`Role::can_act`); user/viewer → 403,
    // anonymous/no token → 401 (produced by the `AuthUser` extractor), unknown id → 404.
    // Currently single-tenant: no per-user isolation, filtering only by `stream_id` (never leaking another stream's recordings).
    // -----------------------------------------------------------------------

    /// Presign TTL of the download URL (task card 300s; not single-use — the presign itself is short-lived,
    /// consistent with the 302 download semantics of ⑤ §4.3).
    pub const RECORDING_PRESIGN_TTL_SECS: u64 = 300;
    /// List default size / per-page cap (low cardinality, preventing a full-table pull).
    pub(crate) const RECORDING_PAGE_DEFAULT: i64 = 50;
    pub(crate) const RECORDING_PAGE_MAX: i64 = 200;

    /// Role gate for recording search/download: admin/ops only (`can_act`); failure uniformly returns 403 + `reason=rbac`.
    fn require_recording_reader(user: &AuthUser) -> Result<()> {
        require_role(user, Role::Ops)
    }

    fn recording_metric(st: &AppState, endpoint: &str, result: &str) {
        st.metrics
            .media_recording_api_total
            .with_label_values(&[endpoint, result])
            .inc();
    }

    /// Recording metadata → JSON (**no payload, no presigned URL**; detail/download append their own).
    ///
    /// `first_seq/last_seq/started_at/ended_at` being null means "the direct-write path has no frame sequence numbers" (the raw
    /// `stream-data` body contains no seq), not missing data; callers can simply sort by `created_at`.
    /// `manifest_key` is the replay-manifest object key (migration 0010); null = old row/manifest generation failed (the API returns 404),
    /// and old clients can simply ignore this new field.
    pub(crate) fn recording_json(row: &crate::store::pg::MediaRecordingRow) -> Value {
        json!({
            "id": row.id,
            "stream_id": row.stream_id,
            "node_id": row.node_id,
            "object_key": row.object_key,
            "manifest_key": row.manifest_key,
            "bucket": row.bucket,
            "first_seq": row.first_seq,
            "last_seq": row.last_seq,
            "frames": row.frames,
            "size_bytes": row.size_bytes,
            "created_at": row.created_at,
            "started_at": row.started_at,
            "ended_at": row.ended_at,
            // Reserved fields: no MP4/OGG muxing/transcoding in this round, so they are always null (exposing capability boundaries truthfully).
            "codec": row.codec,
            "format": row.format,
        })
    }

    /// External manifest path for the detail/manifest APIs: provided only when the index row records a manifest object;
    /// old rows (`manifest_key=null`) return null (never fabricating an accessible address; the manifest API returns 404 for null rows).
    pub(crate) fn manifest_url(row: &crate::store::pg::MediaRecordingRow) -> Option<String> {
        row.manifest_key
            .as_deref()
            .map(|_| format!("/v1/media/recordings/{}/manifest", row.id))
    }

    /// `GET /v1/media/recordings` query parameters.
    #[derive(Debug, Deserialize)]
    pub struct RecordingsQuery {
        /// Filter by stream (exact match; omitted = all recent recordings).
        pub stream_id: Option<String>,
        /// Items per page (default 50, max 200; out-of-range values converge automatically without an error).
        pub limit: Option<i64>,
        /// Cursor: the `next_before` from the previous page's response (a recording id); omitted = first page (newest).
        pub before: Option<String>,
    }

    /// `GET /v1/media/recordings[?stream_id=&limit=&before=]`: recording-segment metadata list.
    ///
    /// Descending (`created_at desc, id desc`) + cursor pagination (`before` = the last id of the previous page);
    /// returns `{items, limit, next_before}`, where `next_before=null` means there is no older page.
    pub async fn recordings(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Q(q): Q<RecordingsQuery>,
    ) -> ApiResult<Response> {
        if let Err(e) = require_recording_reader(&user) {
            recording_metric(&st, "list", "forbidden");
            return Err(ApiErr(e));
        }
        let limit = q
            .limit
            .unwrap_or(RECORDING_PAGE_DEFAULT)
            .clamp(1, RECORDING_PAGE_MAX);
        let stream_id = q
            .stream_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        // The cursor must point at a real recording row: an unknown cursor returns 422, so we never silently return the first page and let callers think they finished.
        let before = match q.before.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            None => None,
            Some(id) => match crate::store::pg::media_recording_by_id(&st.admin_db, id).await {
                Ok(Some(row)) => Some((row.created_at, id.to_string())),
                Ok(None) => {
                    recording_metric(&st, "list", "error");
                    return Err(ApiErr(
                        LatticeError::format(format!("unknown recording cursor: {id}"))
                            .with_reason("before")
                            .with_detail("field", json!("before")),
                    ));
                }
                Err(e) => {
                    recording_metric(&st, "list", "error");
                    return Err(ApiErr(e));
                }
            },
        };
        // Fetch one extra row to tell whether another page exists (no COUNT, avoiding a full table scan).
        let rows = match crate::store::pg::media_recordings_list(
            &st.admin_db,
            stream_id,
            limit + 1,
            before.as_ref().map(|(at, id)| (at, id.as_str())),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                recording_metric(&st, "list", "error");
                return Err(ApiErr(e));
            }
        };
        let has_more = rows.len() as i64 > limit;
        let items: Vec<Value> = rows
            .iter()
            .take(limit as usize)
            .map(recording_json)
            .collect();
        let next_before = if has_more {
            items
                .last()
                .and_then(|v| v.get("id"))
                .and_then(Value::as_str)
                .map(str::to_string)
        } else {
            None
        };
        recording_metric(&st, "list", "ok");
        ok(Json(json!({
            "items": items,
            "limit": limit,
            "next_before": next_before,
        })))
    }

    /// `GET /v1/media/recordings/{id}`: recording metadata + presigned download URL (TTL 300s).
    ///
    /// In addition to the existing fields (PL-13 13.6 replay manifest):
    /// - `manifest_url`: replay-manifest access path (new rows); old rows/manifest generation failure → null (the manifest API returns 404);
    /// - `format`: `"raw-frames"` (raw `[4B len][body]` frame container, **not** MP4/OGG);
    /// - `playable`: `false` (this node does no muxing/transcoding, so the downloaded `.bin` is not directly playable).
    pub async fn recording_detail(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
    ) -> ApiResult<Response> {
        if let Err(e) = require_recording_reader(&user) {
            recording_metric(&st, "detail", "forbidden");
            return Err(ApiErr(e));
        }
        let row = match crate::store::pg::media_recording_by_id(&st.admin_db, &id).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                recording_metric(&st, "detail", "not_found");
                return Err(ApiErr(LatticeError::not_found("recording not found")));
            }
            Err(e) => {
                recording_metric(&st, "detail", "error");
                return Err(ApiErr(e));
            }
        };
        let mut body = recording_json(&row);
        body["presigned_url"] = json!(st.s3.presign_get(
            &row.bucket,
            &row.object_key,
            RECORDING_PRESIGN_TTL_SECS
        ));
        body["presign_ttl_seconds"] = json!(RECORDING_PRESIGN_TTL_SECS);
        body["download_url"] = json!(format!("/v1/media/recordings/{}/download", row.id));
        // Replay manifest + capability boundary (PL-13 13.6): format/playable truthfully state "raw frame container, not playable";
        // manifest_url is given only for rows that recorded a manifest object (old rows are null, and the manifest API returns 404).
        body["manifest_url"] = json!(manifest_url(&row));
        body["format"] = json!(crate::routing::media_record::MANIFEST_FORMAT);
        body["playable"] = json!(false);
        recording_metric(&st, "detail", "ok");
        ok(Json(body))
    }

    /// `GET /v1/media/recordings/{id}/download`: 302 to a MinIO presigned GET (same semantics as ⑤ §4.3).
    ///
    /// 302 instead of a server-side fetch: objects can be large (segment 4MiB by default), and fetching through the server would pull the bytes through node memory/
    /// bandwidth; a presign lets the client connect directly to object storage (② §3.2 zero-copy large-object path).
    pub async fn recording_download(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
        headers: HeaderMap,
    ) -> ApiResult<Response> {
        if let Err(e) = require_recording_reader(&user) {
            recording_metric(&st, "download", "forbidden");
            return Err(ApiErr(e));
        }
        let row = match crate::store::pg::media_recording_by_id(&st.admin_db, &id).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                recording_metric(&st, "download", "not_found");
                return Err(ApiErr(LatticeError::not_found("recording not found")));
            }
            Err(e) => {
                recording_metric(&st, "download", "error");
                return Err(ApiErr(e));
            }
        };
        let url = st.s3.presign_get(
            &row.bucket,
            &row.object_key,
            RECORDING_PRESIGN_TTL_SECS,
        );
        // Audit (⑤ §8.4 management operations): records only object location/size, **no payload, no bytes**;
        // an audit failure does not affect the download (audit availability must not block the read path).
        crate::routing::audit::audit_emit(
            &st,
            Some(&user.user_id),
            "media.recording.download",
            Some(&row.id),
            &json!({
                "stream_id": row.stream_id,
                "bucket": row.bucket,
                "object_key": row.object_key,
                "size_bytes": row.size_bytes,
                "frames": row.frames,
            }),
            ip_of(&headers).as_deref(),
        )
        .await
        .ok();
        recording_metric(&st, "download", "ok");
        let mut resp = StatusCode::FOUND.into_response();
        resp.headers_mut().insert(
            HeaderName::from_static("location"),
            HeaderValue::from_str(&url).unwrap_or(HeaderValue::from_static("")),
        );
        // Capability-boundary response headers (PL-13 13.6): what is downloaded is the raw frame container `.bin`, **not directly playable**
        // (no MP4/OGG muxing/transcoding); frame boundaries are in `/manifest` (the manifest is already marked playable=false).
        resp.headers_mut().insert(
            HeaderName::from_static("x-lattice-media-playable"),
            HeaderValue::from_static("false"),
        );
        resp.headers_mut().insert(
            HeaderName::from_static("x-lattice-media-format"),
            HeaderValue::from_static(
                crate::routing::media_record::MANIFEST_FORMAT,
            ),
        );
        ok(resp)
    }

    /// `GET /v1/media/recordings/{id}/manifest`: fetch that segment's **replay manifest** (PL-13 13.6).
    ///
    /// - Data source: the MinIO object pointed to by the index row's `manifest_key` (migration 0010); **only the frame-index JSON is returned**
    ///   (`offset/len/seq`), **never object bytes/payload**;
    /// - Permissions match list/detail (admin/ops; user 403, anonymous 401);
    /// - Unknown id → 404; old rows (`manifest_key=null`, from the 0009 era)/missing manifest object → 404 not_found
    ///   (no manifest is fabricated); object-storage read failure → 500 (`details.dep=s3`);
    /// - Response headers likewise mark `x-lattice-media-playable:false` / `format:raw-frames` — the manifest describes
    ///   a raw frame container, **not a directly playable file** (no MP4/OGG muxing/transcoding).
    pub async fn recording_manifest(
        State(st): State<Arc<AppState>>,
        user: AuthUser,
        Path(id): Path<String>,
    ) -> ApiResult<Response> {
        if let Err(e) = require_recording_reader(&user) {
            recording_metric(&st, "manifest", "forbidden");
            return Err(ApiErr(e));
        }
        let row = match crate::store::pg::media_recording_by_id(&st.admin_db, &id).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                recording_metric(&st, "manifest", "not_found");
                return Err(ApiErr(LatticeError::not_found("recording not found")));
            }
            Err(e) => {
                recording_metric(&st, "manifest", "error");
                return Err(ApiErr(e));
            }
        };
        let Some(manifest_key) = row.manifest_key.as_deref() else {
            // Old row/manifest generation failure: answer 404 truthfully (never fabricate a manifest on the fly — then it could not be guaranteed consistent with the segment content).
            recording_metric(&st, "manifest", "not_found");
            return Err(ApiErr(
                LatticeError::not_found("recording manifest not found").with_reason("manifest_not_found"),
            ));
        };
        let bytes = match st.s3.get_bytes(&row.bucket, manifest_key).await {
            Ok(b) => b,
            Err(e) => {
                // Trade-off between a missing object (404) and a storage failure: MinIO's 404 proves the manifest really does not exist
                // (same convention as old rows → 404); other errors are dependency failures → 500.
                recording_metric(&st, "manifest", "error");
                tracing::warn!(
                    recording_id = %row.id,
                    bucket = %row.bucket,
                    key = %manifest_key,
                    error = %e,
                    "media recording manifest fetch failed"
                );
                return Err(ApiErr(
                    LatticeError::internal("manifest unavailable")
                        .with_detail("dep", json!("s3")),
                ));
            }
        };
        // Only check that "the object is not corrupted"; the response returns **the raw JSON bytes from storage** (no re-serialization):
        // - frame seq is u64 (> 2^53) and JSON numbers are exact; re-serializing is also exact, but it would change field order,
        //   and the manifest is a self-describing contract, so returning it as-is keeps it byte-identical to the MinIO object (E2E/clients can verify directly);
        // - the response body still contains only the frame index, no segment object bytes/payload.
        if let Err(e) = serde_json::from_slice::<Value>(&bytes) {
            // The manifest is written by the recording path (a generation failure never stores an object): a parse failure can only mean the object is corrupted/rewritten.
            recording_metric(&st, "manifest", "error");
            tracing::error!(
                recording_id = %row.id,
                key = %manifest_key,
                error = %e,
                "media recording manifest is not valid JSON (object corrupted?)"
            );
            return Err(ApiErr(
                LatticeError::internal("manifest corrupted").with_detail("dep", json!("s3")),
            ));
        }
        recording_metric(&st, "manifest", "ok");
        let mut resp = bytes.into_response();
        resp.headers_mut().insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        resp.headers_mut().insert(
            HeaderName::from_static("x-lattice-media-playable"),
            HeaderValue::from_static("false"),
        );
        resp.headers_mut().insert(
            HeaderName::from_static("x-lattice-media-format"),
            HeaderValue::from_static(crate::routing::media_record::MANIFEST_FORMAT),
        );
        ok(resp)
    }
}

#[cfg(test)]
mod query_params {
    use super::*;

    /// Reproduces the real shape of admin search parameters: filter fields + `#[serde(flatten)]` pagination.
    #[derive(Debug, Deserialize)]
    struct FilterQuery {
        q: Option<String>,
        kind: Option<String>,
        #[serde(flatten)]
        page: PageQuery,
    }

    fn parse(query: &str) -> FilterQuery {
        let uri: axum::http::Uri = format!("/x{query}").parse().expect("uri");
        let axum::extract::Query(v) = axum::extract::Query::<FilterQuery>::try_from_uri(&uri)
            .expect("query should parse");
        v
    }

    /// R8: with `flatten` + `serde_urlencoded`, `?page=1` used to report
    /// `invalid type: string "1", expected i64`, making every list page in the console return 400.
    #[test]
    fn flattened_page_accepts_numeric_strings() {
        let v = parse("?q=abc&kind=dm&page=3&page_size=20");
        assert_eq!(v.q.as_deref(), Some("abc"));
        assert_eq!(v.kind.as_deref(), Some("dm"));
        assert_eq!(v.page.clamp(), (3, 20));
    }

    #[test]
    fn page_defaults_when_absent() {
        assert_eq!(parse("").page.clamp(), (1, 50));
        assert_eq!(parse("?q=x").page.clamp(), (1, 50));
    }

    #[test]
    fn page_clamps_out_of_range() {
        assert_eq!(parse("?page=0&page_size=999").page.clamp(), (1, 200));
    }

    /// An invalid value is still an error (just switched to the contract error body) and must not be silently swallowed into a default.
    #[test]
    fn non_numeric_page_is_rejected() {
        let uri: axum::http::Uri = "/x?page=abc".parse().expect("uri");
        assert!(axum::extract::Query::<FilterQuery>::try_from_uri(&uri).is_err());
    }
}

#[cfg(test)]
mod avatar_rules {
    use super::*;

    /// Omitting the field = unchanged (not the same as "clear"): the three-state semantics are a prerequisite for audit/storage correctness.
    #[test]
    fn omitted_means_unchanged() {
        assert_eq!(validate_avatar(None).unwrap(), None);
    }

    /// A blank string = explicitly clear the avatar.
    #[test]
    fn blank_means_clear() {
        for blank in ["", "   ", "\t\n"] {
            assert_eq!(validate_avatar(Some(blank)).unwrap(), None, "raw={blank:?}");
        }
    }

    /// https external links are kept as-is (surrounding whitespace trimmed); unsafe schemes such as http/relative paths are all rejected.
    #[test]
    fn https_url_is_accepted_and_others_rejected() {
        let ok = validate_avatar(Some("  https://cdn.example.com/a/b.png?v=1  ")).unwrap();
        assert_eq!(ok.as_deref(), Some("https://cdn.example.com/a/b.png?v=1"));

        for bad in [
            "http://cdn.example.com/a.png",
            "//cdn.example.com/a.png",
            "/a.png",
            "https://",
            "https://?x=1",
            "https://cdn.example.com/a b.png",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html;base64,PHNjcmlwdD4=",
            "data:image/svg+xml;base64,PHN2Zz4=",
        ] {
            let err = validate_avatar(Some(bad)).unwrap_err();
            assert_eq!(err.code, lattice_core::ErrorCode::Format, "bad={bad:?}");
            assert_eq!(err.http_status(), 422, "bad={bad:?}");
            let details = err.details.as_ref().expect("details");
            assert_eq!(details.get("field"), Some(&json!("avatar")), "bad={bad:?}");
        }
    }

    /// All four allowed image MIME types are accepted; the data URL payload must be valid base64.
    #[test]
    fn allowed_data_url_mimes_are_accepted() {
        for mime in ["png", "jpeg", "webp", "gif"] {
            let raw = format!("data:image/{mime};base64,{}", B64.encode([1u8, 2, 3]));
            let ok = validate_avatar(Some(&raw)).unwrap();
            assert_eq!(ok.as_deref(), Some(raw.as_str()), "mime={mime}");
        }
        // Accept base64 without padding (some clients omit the trailing '=')
        assert!(validate_avatar(Some("data:image/png;base64,AQID")).is_ok());
        // Reject non-allowlisted MIME types (including case variants), so nothing "looks like an image but is executable"
        for bad_mime in ["image/jpg", "image/bmp", "image/avif", "IMAGE/PNG", "image/png "]
        {
            let raw = format!("data:image/{bad_mime};base64,{}", B64.encode([1u8, 2, 3]));
            assert!(
                validate_avatar(Some(&raw)).is_err(),
                "must reject mime={bad_mime}"
            );
        }
        // Valid prefix + invalid base64 / empty payload
        assert!(validate_avatar(Some("data:image/png;base64,%%%%")).is_err());
        assert!(validate_avatar(Some("data:image/png;base64,")).is_err());
    }

    /// Size cap: the whole string's UTF-8 byte count ≤ 256 KiB. Both sides of the boundary must be exact (a 1-byte difference must still be judged correctly).
    #[test]
    fn size_limit_is_enforced_on_encoded_string() {
        let prefix = "data:image/png;base64,";
        // Build a near-limit valid data URL using "QUJD" (decodes to 3 bytes, needs no padding)
        let chunk = "QUJD";
        let fit = (AVATAR_MAX_BYTES - prefix.len()) / chunk.len();
        let at_limit = format!("{prefix}{}", chunk.repeat(fit));
        assert!(at_limit.len() <= AVATAR_MAX_BYTES);
        assert!(validate_avatar(Some(&at_limit)).is_ok(), "exactly at the limit must pass");

        // One more chunk exceeds 256 KiB → FORMAT in the 413/422 convention (a field-level avatar validation error)
        let over = format!("{prefix}{}", chunk.repeat(fit + 1));
        assert!(over.len() > AVATAR_MAX_BYTES);
        let err = validate_avatar(Some(&over)).unwrap_err();
        assert_eq!(err.http_status(), 422);
        let details = err.details.as_ref().expect("details");
        assert_eq!(details.get("field"), Some(&json!("avatar")));
        assert_eq!(details.get("reason"), Some(&json!("avatar_too_large")));
        assert_eq!(details.get("max_bytes"), Some(&json!(AVATAR_MAX_BYTES)));
    }

    /// A separate length cap for URLs (2048 chars), so overlong external links cannot break list/audit columns.
    #[test]
    fn url_length_is_capped() {
        let long = format!("https://cdn.example.com/{}", "a".repeat(AVATAR_URL_MAX_CHARS));
        let err = validate_avatar(Some(&long)).unwrap_err();
        assert_eq!(err.code, lattice_core::ErrorCode::Format);
        assert_eq!(
            err.details.as_ref().and_then(|d| d.get("field")),
            Some(&json!("avatar"))
        );
    }
}

#[cfg(test)]
mod recording_api_tests {
    //! Pure-function contract of the recording search API (the `recording_json` shared by list/detail; no DB, no node).
    //!
    //! Key assertions: list metadata **carries no payload and no presigned URL** (URLs are issued on the spot only in detail),
    //! and the direct-write path's `first_seq/last_seq` are truthfully null (never faked as 0), with the reserved `codec/format` null.

    use super::*;
    use crate::store::pg::MediaRecordingRow;

    fn row(first_seq: Option<i64>, last_seq: Option<i64>) -> MediaRecordingRow {
        let at = chrono::Utc::now();
        MediaRecordingRow {
            id: "01JMEDIAREC0000000000000001".into(),
            stream_id: "st-rec-1".into(),
            node_id: "node-a".into(),
            object_key: "media/record/st-rec-1/node-a/00000000000000000042.bin".into(),
            manifest_key: Some(
                "media/manifest/record/st-rec-1/node-a/00000000000000000042.manifest.json"
                    .into(),
            ),
            first_seq,
            last_seq,
            frames: 12,
            size_bytes: 4096,
            bucket: "lattice-media".into(),
            created_at: at,
            started_at: first_seq.map(|_| at),
            ended_at: last_seq.map(|_| at),
            codec: None,
            format: None,
        }
    }

    #[test]
    fn list_json_is_metadata_only() {
        let v = media::recording_json(&row(Some(42), Some(53)));
        assert_eq!(v["id"], "01JMEDIAREC0000000000000001");
        assert_eq!(v["stream_id"], "st-rec-1");
        assert_eq!(v["node_id"], "node-a");
        assert_eq!(v["frames"], 12);
        assert_eq!(v["size_bytes"], 4096);
        assert_eq!(v["first_seq"], 42);
        assert_eq!(v["last_seq"], 53);
        assert_eq!(v["bucket"], "lattice-media");
        // The object key is metadata (not a URL); but payload and presigned URLs must not appear in the list
        assert!(v["object_key"].as_str().unwrap().ends_with(".bin"));
        assert!(v.get("presigned_url").is_none(), "list must not presign");
        assert!(v.get("payload").is_none(), "list must not carry payload");
        assert!(v.get("bytes").is_none(), "list must not carry object bytes");
        // Times are uniformly RFC3339 strings (parseable by clients)
        assert!(v["created_at"].as_str().unwrap().contains('T'));
        assert!(v["started_at"].as_str().unwrap().contains('T'));
    }

    #[test]
    fn direct_path_rows_expose_null_seq_not_fake_zero() {
        let v = media::recording_json(&row(None, None));
        assert!(v["first_seq"].is_null());
        assert!(v["last_seq"].is_null());
        assert!(v["started_at"].is_null());
        assert!(v["ended_at"].is_null());
        // Reserved fields: no MP4/OGG muxing in this round → always null, truthfully exposing the capability boundary
        assert!(v["codec"].is_null());
        assert!(v["format"].is_null());
        // But segment-level facts (frame count/byte count) are still exact
        assert_eq!(v["frames"], 12);
        assert_eq!(v["size_bytes"], 4096);
    }

    /// Pagination cursor semantics: `limit` out of range converges to [1,200]; default 50.
    #[test]
    fn page_limit_is_clamped() {
        let clamp = |n: Option<i64>| n.unwrap_or(media::RECORDING_PAGE_DEFAULT).clamp(1, media::RECORDING_PAGE_MAX);
        assert_eq!(clamp(None), 50);
        assert_eq!(clamp(Some(0)), 1);
        assert_eq!(clamp(Some(-5)), 1);
        assert_eq!(clamp(Some(25)), 25);
        assert_eq!(clamp(Some(200)), 200);
        assert_eq!(clamp(Some(10_000)), 200);
    }

    /// Replay manifest (PL-13 13.6): the list JSON adds `manifest_key` (old clients ignore new fields),
    /// and detail adds `manifest_url`/`format=raw-frames`/`playable=false` (truthfully exposing capability boundaries).
    #[test]
    fn manifest_fields_are_additive_and_marked_unplayable() {
        let r = row(Some(42), Some(53));
        // List: only one extra manifest_key (object key metadata, not a URL)
        let list = media::recording_json(&r);
        assert_eq!(
            list["manifest_key"],
            "media/manifest/record/st-rec-1/node-a/00000000000000000042.manifest.json"
        );
        assert!(list.get("manifest_url").is_none(), "manifest_url is only given in detail");
        assert_eq!(list["first_seq"], 42, "existing fields stay unchanged");
        // External manifest path in detail: present for new rows; null for old rows (manifest_key=null), never fabricated
        assert_eq!(
            media::manifest_url(&r),
            Some("/v1/media/recordings/01JMEDIAREC0000000000000001/manifest".to_string())
        );
        let mut legacy = row(Some(42), Some(53));
        legacy.manifest_key = None;
        assert_eq!(media::manifest_url(&legacy), None);
        assert!(media::recording_json(&legacy)["manifest_key"].is_null());
        // Format convention: the manifest describes a raw frame container (not MP4/OGG) and is not directly playable
        assert_eq!(crate::routing::media_record::MANIFEST_FORMAT, "raw-frames");
        assert_eq!(crate::routing::media_record::MANIFEST_VERSION, 1);
    }
}
