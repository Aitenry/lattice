//! Generic `Idempotency-Key` middleware (REMAINING E12; contract: document ⑤ §0.3 / design §17.5).
//!
//! Semantics (aligned with document ⑤ §0.3 and the E12 task card):
//!
//! - Scope = **caller + method + path + key**, never shared across users;
//! - The first request executes and its response (status code / key response headers / body ≤ `max_record_body`) is written to Redis,
//!   with a 24h TTL by default; a replay with the same key returns the first response directly, with `Idempotent-Replay: true`;
//! - Concurrent same key: the first request wins the single-flight lock via `SET NX` and executes; the rest immediately return
//!   `409 CONFLICT` + `details.reason = idempotency_in_progress` (+ `Retry-After: 1`);
//! - Same key but a different request body (or query) → `409 CONFLICT` + `details.reason = idempotency_conflict`;
//!   the historical name of this field in document ⑤ §0.3 is `idempotency_mismatch`, so the response also carries
//!   `details.contract_reason = idempotency_mismatch` for lenient parsing by clients built against the old document;
//! - **Zero behavior change when `Idempotency-Key` is absent** (pass through without reading the body or touching Redis);
//! - Redis unavailable: by default **degraded pass-through** (fail-open) with a WARN; with `LATTICE_IDEMPOTENCY_FAIL_OPEN=false`
//!   it returns `503` instead (`details.reason = idempotency_store`), for deployments that prefer "reject rather than execute twice";
//! - Not cached: non-2xx, streaming (`text/event-stream`), protocol upgrades, and 302/30x download redirects; GET/HEAD/OPTIONS
//!   and `Upgrade: websocket` are not handled either; `/v1/ws` is skipped naturally because it is a GET.
//!
//! Explicit boundaries (recorded truthfully; mirrored in the E12 report):
//!
//! 1. **Only write requests with `Content-Length` and ≤ `max_request_body` (1MiB by default) are handled**.
//!    chunked requests (no Content-Length) or oversized ones (e.g. a 20MiB hub bundle or a 50MiB source-package PUT)
//!    pass straight through — replaying a request requires fully buffering the body first, and buffering a 50MiB streaming upload
//!    is not worth it; the idempotency semantics of those uploads belong to the business layer (§12.4/§12.4.1 same-sha idempotency).
//! 2. **Unauthenticated write requests are not cached**: the scope requires "caller", so requests without a valid access JWT (e.g.
//!    `/v1/auth/login`, `/v1/auth/refresh`) pass through and the handler's own auth/rotation semantics apply;
//!    this also avoids the privilege-escalation risk of "a credential-free replay hitting someone else's response".
//! 3. **Prometheus metrics are wired**: `lattice_http_idempotency_total{result=hit|miss|conflict|
//!    in_progress|error}` (5 low-cardinality values, touched to 0 at startup); counting only, no new audit events
//!    (idempotency results go only to logs and metrics, never to audit_log).
//! 4. **No new audit events** (for performance/exposure reasons; idempotency results go only to logs and metrics, never to audit_log).
//!
//! All configuration comes from environment variables (no new config struct, avoiding conflicts with parallel changes in `config.rs`/`state.rs`):
//!
//! | Env var | Default | Description |
//! | --- | --- | --- |
//! | `LATTICE_IDEMPOTENCY_ENABLED` | `true` | Master switch; `false/0/off` disables it (zero behavior change) |
//! | `LATTICE_IDEMPOTENCY_TTL_SECS` | `policy.dedup_ttl` (default 86400) | First-response cache TTL |
//! | `LATTICE_IDEMPOTENCY_LOCK_TTL_SECS` | `30` | Single-flight lock TTL (1..=300) |
//! | `LATTICE_IDEMPOTENCY_MAX_REQUEST_BYTES` | `1048576` | Max request body size taking part in idempotency (1KiB..=8MiB) |
//! | `LATTICE_IDEMPOTENCY_MAX_RECORD_BYTES` | `65536` | Max cached response body size (1KiB..=1MiB) |
//! | `LATTICE_IDEMPOTENCY_FAIL_OPEN` | `true` | Pass through on Redis failure; false = 503 |

use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ApiErr, LatticeError};
use crate::state::AppState;
use crate::store::Redis;

/// Response header name of the idempotency cache (filled in on replay so the client can tell "this is a replay, not a new execution").
pub const REPLAY_HEADER: &str = "idempotent-replay";
/// Client request header (case-insensitive; axum/http already normalizes it).
pub const KEY_HEADER: &str = "idempotency-key";
/// Record version (bumped on structural change; an old record that fails to parse is treated as a miss).
pub const RECORD_VERSION: u8 = 1;
/// Response body buffer limit (far above `max_record_body`: going over only means "do not cache"; the body must never be dropped).
const RESPONSE_BUFFER_LIMIT: usize = 8 * 1024 * 1024;
/// Maximum allowed length of Idempotency-Key (ULID 26; headroom for non-ULID clients).
const MAX_KEY_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Configuration (env vars; no new Config fields)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdemConfig {
    pub enabled: bool,
    pub ttl_secs: u64,
    pub lock_ttl_secs: u64,
    pub max_request_body: usize,
    pub max_record_body: usize,
    pub fail_open: bool,
}

impl IdemConfig {
    /// Read from env vars; `default_ttl` is used when `LATTICE_IDEMPOTENCY_TTL_SECS` is unset,
    /// inheriting `[policy] dedup_ttl` (the 24h default of ⑤ §0.3 / design §17.5).
    pub fn from_env(default_ttl: u64) -> Self {
        let enabled = env_bool("LATTICE_IDEMPOTENCY_ENABLED", true);
        let ttl_secs = env_u64("LATTICE_IDEMPOTENCY_TTL_SECS", default_ttl.max(1)).clamp(1, 7 * 24 * 3600);
        let lock_ttl_secs =
            env_u64("LATTICE_IDEMPOTENCY_LOCK_TTL_SECS", 30).clamp(1, 300);
        let max_request_body = env_u64("LATTICE_IDEMPOTENCY_MAX_REQUEST_BYTES", 1024 * 1024)
            .clamp(1024, 8 * 1024 * 1024) as usize;
        let max_record_body = env_u64("LATTICE_IDEMPOTENCY_MAX_RECORD_BYTES", 64 * 1024)
            .clamp(1024, 1024 * 1024) as usize;
        let fail_open = env_bool("LATTICE_IDEMPOTENCY_FAIL_OPEN", true);
        IdemConfig {
            enabled,
            ttl_secs,
            lock_ttl_secs,
            max_request_body,
            max_record_body,
            fail_open,
        }
    }

    /// Default configuration for tests/no-AppState scenarios (identical to the production default).
    pub fn default_for_tests() -> Self {
        IdemConfig {
            enabled: true,
            ttl_secs: 86_400,
            lock_ttl_secs: 30,
            max_request_body: 1024 * 1024,
            max_record_body: 64 * 1024,
            fail_open: true,
        }
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

/// Process-level config cache: materialized once on the first write request from the then-current `policy.dedup_ttl` (env/config are not read again).
fn cached_config(st: &AppState) -> IdemConfig {
    static CACHE: OnceLock<IdemConfig> = OnceLock::new();
    *CACHE.get_or_init(|| IdemConfig::from_env(st.cfg.policy.dedup_ttl))
}

// ---------------------------------------------------------------------------
// Storage abstraction (Redis implementation + in-memory test implementation)
// ---------------------------------------------------------------------------

/// Idempotency-key store. Abstracted so the middleware core can be unit-tested **without Redis**.
#[async_trait::async_trait]
pub trait IdemStore: Send + Sync {
    /// Read the first-response cache (raw JSON).
    async fn get(&self, scope_hash: &str) -> crate::error::Result<Option<String>>;
    /// Acquire the concurrent single-flight lock; `true` = this request executes first.
    async fn begin(
        &self,
        scope_hash: &str,
        holder: &str,
        ttl_secs: u64,
    ) -> crate::error::Result<bool>;
    /// Write the first-response cache.
    async fn put(
        &self,
        scope_hash: &str,
        record: &str,
        ttl_secs: u64,
    ) -> crate::error::Result<()>;
    /// Release the single-flight lock (only the one held by the caller).
    async fn release(&self, scope_hash: &str, holder: &str) -> crate::error::Result<()>;
}

/// Redis implementation: key layout in [`crate::store::redis::Redis::idem_record_key`].
pub struct RedisIdemStore {
    redis: Redis,
}

impl RedisIdemStore {
    pub fn new(redis: Redis) -> Self {
        Self { redis }
    }
}

#[async_trait::async_trait]
impl IdemStore for RedisIdemStore {
    async fn get(&self, scope_hash: &str) -> crate::error::Result<Option<String>> {
        self.redis.idem_get(scope_hash).await
    }

    async fn begin(
        &self,
        scope_hash: &str,
        holder: &str,
        ttl_secs: u64,
    ) -> crate::error::Result<bool> {
        self.redis.idem_begin(scope_hash, holder, ttl_secs).await
    }

    async fn put(
        &self,
        scope_hash: &str,
        record: &str,
        ttl_secs: u64,
    ) -> crate::error::Result<()> {
        self.redis.idem_put(scope_hash, record, ttl_secs).await
    }

    async fn release(&self, scope_hash: &str, holder: &str) -> crate::error::Result<()> {
        self.redis.idem_release(scope_hash, holder).await
    }
}

// ---------------------------------------------------------------------------
// Response cache record
// ---------------------------------------------------------------------------

/// First-response snapshot (stored as JSON in Redis; fields stay backward compatible — new fields must be `#[serde(default)]`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdemRecord {
    /// Record version ([`RECORD_VERSION`]).
    pub v: u8,
    /// Original HTTP status code (returned as-is on replay, including 201/204).
    pub status: u16,
    /// Key response headers (allowlist in [`cacheable_header`]).
    pub headers: Vec<(String, String)>,
    /// body (base64; write-endpoint responses are usually small JSON, and binary is safe too).
    pub body_b64: String,
    /// First-request fingerprint (method + path + query + body_sha256), used to distinguish "same key, different request".
    #[serde(default)]
    pub fingerprint: String,
    /// Write time (unix seconds, for troubleshooting).
    #[serde(default)]
    pub created_at: i64,
}

impl IdemRecord {
    fn from_response(
        fingerprint: &str,
        status: StatusCode,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Self {
        let mut picked = Vec::new();
        for (name, value) in headers {
            let name_str = name.as_str();
            if !cacheable_header(name_str) {
                continue;
            }
            if let Ok(v) = value.to_str() {
                picked.push((name_str.to_string(), v.to_string()));
            }
        }
        IdemRecord {
            v: RECORD_VERSION,
            status: status.as_u16(),
            headers: picked,
            body_b64: B64.encode(body),
            fingerprint: fingerprint.to_string(),
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Replay response: original status code + cached key headers + `Idempotent-Replay: true`.
    fn into_response(&self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut builder = Response::builder().status(status);
        for (name, value) in &self.headers {
            if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
                builder = builder.header(n, v);
            }
        }
        builder = builder.header(REPLAY_HEADER, "true");
        let body = B64.decode(self.body_b64.as_bytes()).unwrap_or_default();
        builder
            .body(Body::from(body))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    }
}

/// Cache only response headers that "affect client semantics"; headers that must be recomputed per request such as `set-cookie`/`x-trace-id` are not cached.
fn cacheable_header(name: &str) -> bool {
    matches!(
        name,
        "content-type"
            | "content-disposition"
            | "location"
            | "etag"
            | "cache-control"
            | "last-modified"
            | "retry-after"
            | "x-ratelimit-limit"
            | "x-ratelimit-remaining"
            | "x-ratelimit-reset"
            | "x-quota-storage-used"
            | "x-quota-storage-limit"
            | "x-content-sha256"
            | "x-content-length"
            | "idempotent-reused"
    )
}

// ---------------------------------------------------------------------------
// Request scope / fingerprint
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Scope hash = `sha256(user \n method \n path \n key)` (document ⑤ §0.3 "caller + path + key").
pub fn scope_hash(user: &str, method: &Method, path: &str, key: &str) -> String {
    sha256_hex(format!("{user}\n{method}\n{path}\n{key}").as_bytes())
}

/// Request fingerprint = `sha256(method \n path \n query \n body_sha256)` (same key with a different body/query is used for 409).
pub fn request_fingerprint(method: &Method, path: &str, query: &str, body: &[u8]) -> String {
    let body_sha = sha256_hex(body);
    sha256_hex(format!("{method}\n{path}\n{query}\n{body_sha}").as_bytes())
}

/// Whether an HTTP method takes part in idempotency: only write operations (POST/PUT/PATCH/DELETE on the management/message planes).
pub fn is_idempotent_method(method: &Method) -> bool {
    method == Method::POST
        || method == Method::PUT
        || method == Method::PATCH
        || method == Method::DELETE
}

/// Parse the `Idempotency-Key` header: missing/blank/too long/illegal characters are all treated as "not provided" (zero behavior change).
pub fn parse_idempotency_key(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(KEY_HEADER)?.to_str().ok()?.trim();
    if raw.is_empty() || raw.len() > MAX_KEY_LEN {
        return None;
    }
    if !raw.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return None;
    }
    Some(raw)
}

/// Get the caller id from the bearer access JWT; invalid/missing → `None` (that request does not participate in the idempotency cache).
fn token_user(st: &AppState, headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    st.verify_jwt(token).ok().map(|claims| claims.sub)
}

// ---------------------------------------------------------------------------
// Middleware body
// ---------------------------------------------------------------------------

/// axum middleware entry (mounted in `main.rs` with `from_fn_with_state(state, idempotency::middleware)`).
pub async fn middleware(
    State(st): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let cfg = cached_config(&st);
    if !cfg.enabled {
        return next.run(req).await;
    }
    if !is_idempotent_method(req.method()) {
                return next.run(req).await; // GET/HEAD/OPTIONS (including /v1/ws, SSE, downloads)
    }
    let Some(key) = parse_idempotency_key(req.headers()).map(str::to_owned) else {
                return next.run(req).await; // Idempotency-Key missing: existing behavior is completely unchanged
    };
        // The scope requires "caller": write requests without a valid access JWT (login/refresh etc.) pass through;
        // never fabricate a scope from a user id, to avoid a credential-free replay hitting another user's response.
    let Some(user) = token_user(&st, req.headers()) else {
        tracing::debug!(
            path = %req.uri().path(),
            "idempotency: no valid bearer token, pass through (scope needs caller)"
        );
        return next.run(req).await;
    };
    let store: Arc<dyn IdemStore> = Arc::new(RedisIdemStore::new(st.redis.clone()));
        // Result counting (⑤ §0.3 / E12): hit|miss|conflict|in_progress|error are low-cardinality counters only.
    let metrics = Some(st.metrics.clone());
    run(store, cfg, metrics, user, key, req, |r| async move { next.run(r).await }).await
}

/// Report one idempotency result (low-cardinality label; tests/E2E assert on `lattice_http_idempotency_total`).
fn record_result(metrics: Option<&Arc<crate::observe::Metrics>>, result: &str) {
    if let Some(m) = metrics {
        m.http_idempotency_total.with_label_values(&[result]).inc();
    }
}

/// Middleware core (generic over `IdemStore` and `next`, so it can be unit-tested without a Redis/HTTP server).
async fn run<F, Fut>(
    store: Arc<dyn IdemStore>,
    cfg: IdemConfig,
    metrics: Option<Arc<crate::observe::Metrics>>,
    user: String,
    key: String,
    req: Request,
    next: F,
) -> Response
where
    F: FnOnce(Request) -> Fut,
    Fut: std::future::Future<Output = Response>,
{
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();

        // 1) Request-body bufferability guard (chunked/oversized pass straight through: the body is not consumed, behavior matches having no middleware).
    let content_length = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let Some(len) = content_length else {
        tracing::debug!(
            path = %path,
            "idempotency: missing content-length, pass through (chunked bodies are not buffered)"
        );
        return next(req).await;
    };
    if len > cfg.max_request_body as u64 {
        tracing::debug!(
            path = %path,
            len,
            max = cfg.max_request_body,
            "idempotency: request body exceeds buffer limit, pass through"
        );
        return next(req).await;
    }

        // 2) Buffer the request body and rebuild the Request (execution and replay both need the same body).
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, cfg.max_request_body).await {
        Ok(b) => b,
        Err(e) => {
                        // Content-Length does not match the actual body: reject as PROTOCOL (consistent with ⑤ §0.6).
            tracing::warn!(path = %path, error = %e, "idempotency: failed to buffer request body");
            return ApiErr(
                LatticeError::protocol("request body read failed")
                    .with_reason("idempotency_body"),
            )
            .into_response();
        }
    };
    let req = Request::from_parts(parts, Body::from(body_bytes.clone()));

    let scope = scope_hash(&user, &method, &path, &key);
    let fingerprint = request_fingerprint(&method, &path, &query, &body_bytes);

        // 3) First-response hit → replay (with Idempotent-Replay: true).
    match store.get(&scope).await {
        Ok(Some(raw)) => match serde_json::from_str::<IdemRecord>(&raw) {
            Ok(record) => {
                if record.fingerprint == fingerprint {
                    tracing::debug!(path = %path, user = %user, "idempotency: replay");
                    record_result(metrics.as_ref(), "hit");
                    return record.into_response();
                }
                tracing::info!(
                    path = %path,
                    user = %user,
                    "idempotency: conflict (different request under the same key)"
                );
                record_result(metrics.as_ref(), "conflict");
                return conflict_response("idempotency_conflict");
            }
            Err(e) => {
                                // Corrupt record (old version/partial write): continue as a miss and overwrite for self-healing later.
                tracing::warn!(path = %path, error = %e, "idempotency: corrupt record, treat as miss");
            }
        },
        Ok(None) => {}
        Err(e) => {
            return degraded(cfg, e, req, next, metrics).await;
        }
    }

        // 4) Concurrent single-flight for the same key: lock acquisition failure → 409 idempotency_in_progress (return immediately, no queueing).
    let holder = lattice_core::ids::new_id();
    match store.begin(&scope, &holder, cfg.lock_ttl_secs).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::info!(path = %path, user = %user, "idempotency: in progress (concurrent request)");
            record_result(metrics.as_ref(), "in_progress");
            return conflict_response("idempotency_in_progress");
        }
        Err(e) => {
            return degraded(cfg, e, req, next, metrics).await;
        }
    }

        // 4.1) double-check: there is a window between the `get` miss and the `begin` lock — the previous holder may have finished
        //      and written the cache after our get but before our begin. Read once more after taking the lock; on a hit, replay or
        //      report a conflict, avoiding "the same key executed twice" (the classic check-then-act race).
    match store.get(&scope).await {
        Ok(Some(raw)) => match serde_json::from_str::<IdemRecord>(&raw) {
            Ok(record) if record.fingerprint == fingerprint => {
                tracing::debug!(path = %path, user = %user, "idempotency: replay after lock (double-check)");
                release(&store, &scope, &holder).await;
                record_result(metrics.as_ref(), "hit");
                return record.into_response();
            }
            Ok(_) => {
                tracing::info!(path = %path, user = %user, "idempotency: conflict after lock (double-check)");
                release(&store, &scope, &holder).await;
                record_result(metrics.as_ref(), "conflict");
                return conflict_response("idempotency_conflict");
            }
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "idempotency: corrupt record after lock, proceed");
            }
        },
        Ok(None) => {}
        Err(e) => {
                        // Failure only after taking the lock (Redis blip): proceed and cache best-effort; do not reject the business request for this.
            tracing::warn!(error = %e, "idempotency: second lookup failed, proceed without replay");
            record_result(metrics.as_ref(), "error");
        }
    }

        // 5) Execute the first request (miss), then cache the response per the rules.
    record_result(metrics.as_ref(), "miss");
    let resp = next(req).await;
    finish(store, cfg, scope, holder, fingerprint, resp, metrics).await
}

/// Redis failure handling: fail-open by default (pass through + WARN); 503 when `fail_open=false`.
async fn degraded<F, Fut>(
    cfg: IdemConfig,
    error: LatticeError,
    req: Request,
    next: F,
    metrics: Option<Arc<crate::observe::Metrics>>,
) -> Response
where
    F: FnOnce(Request) -> Fut,
    Fut: std::future::Future<Output = Response>,
{
        // Idempotency store/lock failure (either fail-open or fail-closed counts): record result=error for alerting.
    record_result(metrics.as_ref(), "error");
    if cfg.fail_open {
        tracing::warn!(
            error = %error,
            path = %req.uri().path(),
            "idempotency: store unavailable, degraded pass-through (request executed without cache)"
        );
        return next(req).await;
    }
    tracing::error!(
        error = %error,
        path = %req.uri().path(),
        "idempotency: store unavailable and fail_open=false, rejecting with 503"
    );
    let e = LatticeError::internal("idempotency store unavailable")
        .with_reason("idempotency_store")
        .with_detail("dep", serde_json::json!("redis"));
    let trace = lattice_core::ids::new_id();
    let mut resp = (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(e.body(&trace)),
    )
        .into_response();
    resp.headers_mut().insert(
        HeaderName::from_static("x-trace-id"),
        HeaderValue::from_str(&trace).unwrap_or(HeaderValue::from_static("")),
    );
    resp.headers_mut()
        .insert(HeaderName::from_static("retry-after"), HeaderValue::from_static("1"));
    resp
}

/// Wrap-up after execution: a cacheable 2xx is written to the cache; the single-flight lock is released either way.
async fn finish(
    store: Arc<dyn IdemStore>,
    cfg: IdemConfig,
    scope: String,
    holder: String,
    fingerprint: String,
    resp: Response,
    metrics: Option<Arc<crate::observe::Metrics>>,
) -> Response {
    let (parts, body) = resp.into_parts();
    let status = parts.status;
    let content_type = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let cacheable = status.is_success() && !content_type.starts_with("text/event-stream");
    if !cacheable {
        release(&store, &scope, &holder).await;
        return Response::from_parts(parts, body);
    }

    let bytes = match axum::body::to_bytes(body, RESPONSE_BUFFER_LIMIT).await {
        Ok(b) => b,
        Err(e) => {
                        // Extreme case (write-endpoint response > 8MiB): returning it uncached as-is is no longer possible, so report INTERNAL.
            tracing::warn!(error = %e, "idempotency: response body too large to buffer");
            release(&store, &scope, &holder).await;
            return ApiErr(
                LatticeError::internal("response too large for idempotency cache")
                    .with_reason("idempotency_response"),
            )
            .into_response();
        }
    };

    if bytes.len() <= cfg.max_record_body {
        let record = IdemRecord::from_response(&fingerprint, status, &parts.headers, &bytes);
        match serde_json::to_string(&record) {
            Ok(raw) => {
                if let Err(e) = store.put(&scope, &raw, cfg.ttl_secs).await {
                    tracing::warn!(error = %e, "idempotency: failed to store response record");
                    record_result(metrics.as_ref(), "error");
                }
            }
            Err(e) => tracing::warn!(error = %e, "idempotency: failed to encode response record"),
        }
    } else {
        tracing::debug!(
            len = bytes.len(),
            max = cfg.max_record_body,
            "idempotency: response exceeds record limit, not cached"
        );
    }
    release(&store, &scope, &holder).await;
    Response::from_parts(parts, Body::from(bytes))
}

async fn release(store: &Arc<dyn IdemStore>, scope: &str, holder: &str) {
    if let Err(e) = store.release(scope, holder).await {
        tracing::warn!(error = %e, "idempotency: failed to release in-progress lock");
    }
}

/// 409 response (`idempotency_conflict` / `idempotency_in_progress`).
fn conflict_response(reason: &str) -> Response {
    let message = match reason {
        "idempotency_conflict" => {
            "idempotency key reused with a different request (body or query changed)"
        }
        "idempotency_in_progress" => "an identical idempotent request is already in progress",
        _ => "idempotency conflict",
    };
    let mut e = LatticeError::conflict(message).with_reason(reason);
    if reason == "idempotency_conflict" {
                // The historical name in document ⑤ §0.3 is idempotency_mismatch; emit both keys so clients can parse leniently.
        e = e.with_detail("contract_reason", serde_json::json!("idempotency_mismatch"));
    }
    let mut resp = ApiErr(e).into_response();
    if reason == "idempotency_in_progress" {
        resp.headers_mut()
            .insert(HeaderName::from_static("retry-after"), HeaderValue::from_static("1"));
    }
    resp
}

// ---------------------------------------------------------------------------
// Unit tests (no Redis / axum server: in-memory store + closure next)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use axum::http::header::CONTENT_TYPE;

    use super::*;

    #[derive(Default)]
    struct MemStore {
        records: Mutex<HashMap<String, String>>,
        locks: Mutex<HashSet<String>>,
        puts: AtomicUsize,
        fail: Mutex<bool>,
    }

    impl MemStore {
        fn failing() -> Self {
            let s = Self::default();
            *s.fail.lock().unwrap() = true;
            s
        }

        fn record_count(&self) -> usize {
            self.records.lock().unwrap().len()
        }

        fn lock_count(&self) -> usize {
            self.locks.lock().unwrap().len()
        }
    }

    fn err_redis() -> LatticeError {
        LatticeError::internal("redis unavailable").with_detail("dep", serde_json::json!("redis"))
    }

    #[async_trait::async_trait]
    impl IdemStore for MemStore {
        async fn get(&self, scope_hash: &str) -> crate::error::Result<Option<String>> {
            if *self.fail.lock().unwrap() {
                return Err(err_redis());
            }
            Ok(self.records.lock().unwrap().get(scope_hash).cloned())
        }

        async fn begin(
            &self,
            scope_hash: &str,
            _holder: &str,
            _ttl_secs: u64,
        ) -> crate::error::Result<bool> {
            if *self.fail.lock().unwrap() {
                return Err(err_redis());
            }
            Ok(self.locks.lock().unwrap().insert(scope_hash.to_string()))
        }

        async fn put(
            &self,
            scope_hash: &str,
            record: &str,
            _ttl_secs: u64,
        ) -> crate::error::Result<()> {
            if *self.fail.lock().unwrap() {
                return Err(err_redis());
            }
            self.puts.fetch_add(1, Ordering::Relaxed);
            self.records
                .lock()
                .unwrap()
                .insert(scope_hash.to_string(), record.to_string());
            Ok(())
        }

        async fn release(&self, scope_hash: &str, _holder: &str) -> crate::error::Result<()> {
            self.locks.lock().unwrap().remove(scope_hash);
            Ok(())
        }
    }

    fn request(method: &str, path: &str, key: Option<&str>, body: &'static [u8]) -> Request {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(axum::http::header::AUTHORIZATION, "Bearer test-token")
            .header(
                axum::http::header::CONTENT_LENGTH,
                body.len().to_string(),
            );
        if let Some(k) = key {
            builder = builder.header(KEY_HEADER, k);
        }
        builder.body(Body::from(body)).unwrap()
    }

        /// Read the current value of `lattice_http_idempotency_total{result=...}` (for test assertions).
    fn idem_count(metrics: &crate::observe::Metrics, result: &str) -> u64 {
        metrics
            .http_idempotency_total
            .with_label_values(&[result])
            .get()
    }

    fn json_ok(status: u16, body: &'static str) -> Response {
        Response::builder()
            .status(StatusCode::from_u16(status).unwrap())
            .header(CONTENT_TYPE, "application/json")
            .header("x-trace-id", "trace-of-first-call")
            .body(Body::from(body))
            .unwrap()
    }

    async fn body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn run_once(
        store: &Arc<MemStore>,
        cfg: IdemConfig,
        user: &str,
        key: &str,
        req: Request,
        body: &'static str,
        calls: &Arc<AtomicUsize>,
    ) -> Response {
        let store_dyn: Arc<dyn IdemStore> = store.clone();
        let calls = calls.clone();
        run(store_dyn, cfg, None, user.to_string(), key.to_string(), req, move |_r| async move {
            calls.fetch_add(1, Ordering::Relaxed);
            json_ok(201, body)
        })
        .await
    }

        // ---- pure functions ----

    #[test]
    fn method_and_key_filters() {
        assert!(is_idempotent_method(&Method::POST));
        assert!(is_idempotent_method(&Method::PUT));
        assert!(is_idempotent_method(&Method::PATCH));
        assert!(is_idempotent_method(&Method::DELETE));
        assert!(!is_idempotent_method(&Method::GET));
        assert!(!is_idempotent_method(&Method::HEAD));

        let mut headers = HeaderMap::new();
        assert_eq!(parse_idempotency_key(&headers), None);
        headers.insert(KEY_HEADER, HeaderValue::from_static("01J7Q3Z8Y2K4M6N8P0R2T4V6X8"));
        assert_eq!(
            parse_idempotency_key(&headers),
            Some("01J7Q3Z8Y2K4M6N8P0R2T4V6X8")
        );
        headers.insert(KEY_HEADER, HeaderValue::from_static("   "));
        assert_eq!(parse_idempotency_key(&headers), None);
        headers.insert(KEY_HEADER, HeaderValue::from_static("bad\tkey"));
        assert_eq!(parse_idempotency_key(&headers), None);
    }

    #[test]
    fn scope_and_fingerprint_are_scoped_and_body_sensitive() {
        let m = Method::POST;
        let s1 = scope_hash("user-a", &m, "/v1/admin/users", "k1");
        let s2 = scope_hash("user-b", &m, "/v1/admin/users", "k1");
        let s3 = scope_hash("user-a", &Method::PUT, "/v1/admin/users", "k1");
        let s4 = scope_hash("user-a", &m, "/v1/admin/users/x", "k1");
        let s5 = scope_hash("user-a", &m, "/v1/admin/users", "k2");
                assert_ne!(s1, s2, "the scope must include the user");
                assert_ne!(s1, s3, "the scope must include the method");
                assert_ne!(s1, s4, "the scope must include the path");
                assert_ne!(s1, s5, "the scope must include the key");

        let f1 = request_fingerprint(&m, "/v1/users", "", b"{\"a\":1}");
        let f2 = request_fingerprint(&m, "/v1/users", "", b"{\"a\":2}");
        let f3 = request_fingerprint(&m, "/v1/users", "", b"{\"a\":1}");
        let f4 = request_fingerprint(&m, "/v1/users", "?force=1", b"{\"a\":1}");
                assert_ne!(f1, f2, "a different body must yield a different fingerprint (the basis for 409)");
        assert_eq!(f1, f3);
                assert_ne!(f1, f4, "a different query must yield a different fingerprint");
    }

    #[test]
    fn record_filters_headers_and_roundtrips() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert("x-trace-id", HeaderValue::from_static("t-1"));
        headers.insert("set-cookie", HeaderValue::from_static("a=b"));
        headers.insert(
            "x-ratelimit-remaining",
            HeaderValue::from_static("99"),
        );
        let rec = IdemRecord::from_response("fp", StatusCode::CREATED, &headers, b"{\"ok\":true}");
        let names: Vec<&str> = rec.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"content-type"));
        assert!(names.contains(&"x-ratelimit-remaining"));
                assert!(!names.contains(&"x-trace-id"), "trace ids must not be cached and replayed");
        assert!(!names.contains(&"set-cookie"));

        let raw = serde_json::to_string(&rec).unwrap();
        let back: IdemRecord = serde_json::from_str(&raw).unwrap();
        assert_eq!(rec, back);
        assert_eq!(back.body_b64, B64.encode(b"{\"ok\":true}"));
    }

        // ---- core flow ----

    #[tokio::test]
    async fn miss_then_hit_replays_without_reexecuting() {
        let store = Arc::new(MemStore::default());
        let cfg = IdemConfig::default_for_tests();
        let calls = Arc::new(AtomicUsize::new(0));

        let resp1 = run_once(
            &store,
            cfg,
            "user-a",
            "key-1",
            request("POST", "/v1/admin/users", Some("key-1"), b"{\"username\":\"alice\"}"),
            "{\"id\":\"u1\"}",
            &calls,
        )
        .await;
        assert_eq!(resp1.status(), StatusCode::CREATED);
        assert_eq!(body_string(resp1).await, "{\"id\":\"u1\"}");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(store.record_count(), 1);
                assert_eq!(store.lock_count(), 0, "the single-flight lock must be released after completion");

        let resp2 = run_once(
            &store,
            cfg,
            "user-a",
            "key-1",
            request("POST", "/v1/admin/users", Some("key-1"), b"{\"username\":\"alice\"}"),
            "{\"id\":\"u1\"}",
            &calls,
        )
        .await;
                assert_eq!(resp2.status(), StatusCode::CREATED, "replay must preserve the original status code");
        assert_eq!(
            resp2.headers().get(REPLAY_HEADER).and_then(|v| v.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            resp2
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
                        "key response headers must be restored on replay"
        );
        assert_eq!(body_string(resp2).await, "{\"id\":\"u1\"}");
                assert_eq!(calls.load(Ordering::Relaxed), 1, "replay must not execute the handler again");
    }

    #[tokio::test]
    async fn same_key_different_body_is_conflict() {
        let store = Arc::new(MemStore::default());
        let cfg = IdemConfig::default_for_tests();
        let calls = Arc::new(AtomicUsize::new(0));

        let first = run_once(
            &store,
            cfg,
            "user-a",
            "key-1",
            request("POST", "/v1/admin/users", Some("key-1"), b"{\"n\":1}"),
            "{\"id\":\"u1\"}",
            &calls,
        )
        .await;
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = run_once(
            &store,
            cfg,
            "user-a",
            "key-1",
            request("POST", "/v1/admin/users", Some("key-1"), b"{\"n\":2}"),
            "{\"id\":\"u2\"}",
            &calls,
        )
        .await;
        assert_eq!(second.status(), StatusCode::CONFLICT);
        let body = body_string(second).await;
                assert!(body.contains("\"CONFLICT\""), "code must be CONFLICT: {body}");
        assert!(
            body.contains("idempotency_conflict"),
                        "reason must be idempotency_conflict: {body}"
        );
        assert!(
            body.contains("idempotency_mismatch"),
                        "and must also provide the historical reason from document ⑤ §0.3: {body}"
        );
                assert_eq!(calls.load(Ordering::Relaxed), 1, "a conflict must not execute twice");
    }

    #[tokio::test]
    async fn concurrent_same_key_gets_in_progress() {
        let store = Arc::new(MemStore::default());
        let cfg = IdemConfig::default_for_tests();
        let calls = Arc::new(AtomicUsize::new(0));

                // Simulate another concurrent request that already took the lock: occupy the lock for the scope first.
        let scope = scope_hash("user-a", &Method::POST, "/v1/admin/users", "key-1");
        assert!(store.begin(&scope, "other-holder", 30).await.unwrap());

        let resp = run_once(
            &store,
            cfg,
            "user-a",
            "key-1",
            request("POST", "/v1/admin/users", Some("key-1"), b"{}"),
            "{}",
            &calls,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(
            resp.headers().get("retry-after").and_then(|v| v.to_str().ok()),
            Some("1")
        );
        let body = body_string(resp).await;
        assert!(body.contains("idempotency_in_progress"), "{body}");
                assert_eq!(calls.load(Ordering::Relaxed), 0, "concurrent same-key requests must not execute the handler");
    }

    #[tokio::test]
    async fn missing_key_or_unsafe_method_passes_through() {
                // The "missing key / GET → pass through" decision lives at the middleware entry (needs AppState);
                // here we only verify the two pure functions it depends on; black-box behavior is covered by scripts/idempotency-e2e.mjs.
        let req = request("POST", "/v1/admin/users", None, b"{}");
        assert_eq!(
            parse_idempotency_key(req.headers()),
            None,
                        "a missing Idempotency-Key header must be judged as \"not provided\" (zero behavior change)"
        );
        assert!(!is_idempotent_method(&Method::GET));
        assert!(!is_idempotent_method(&Method::HEAD));
        assert!(!is_idempotent_method(&Method::OPTIONS));
        assert!(is_idempotent_method(&Method::POST));
    }

    #[tokio::test]
    async fn non_success_and_streaming_are_not_cached() {
        let store = Arc::new(MemStore::default());
        let cfg = IdemConfig::default_for_tests();

                // Non-2xx (500): not cached, so the next retry executes again.
        let store_dyn: Arc<dyn IdemStore> = store.clone();
        let resp = run(
            store_dyn,
            cfg,
            None,
            "user-a".into(),
            "k-500".into(),
            request("POST", "/v1/x", Some("k-500"), b"{}"),
            |_r| async move { json_ok(500, "{\"code\":\"INTERNAL\"}") },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
                assert_eq!(store.record_count(), 0, "5xx must not be cached");

                // Streaming response (text/event-stream): not cached (and an SSE stream must not be buffered).
        let store_dyn: Arc<dyn IdemStore> = store.clone();
        let resp = run(
            store_dyn,
            cfg,
            None,
            "user-a".into(),
            "k-sse".into(),
            request("POST", "/v1/x", Some("k-sse"), b"{}"),
            |_r| async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/event-stream")
                    .body(Body::from("data: x\n\n"))
                    .unwrap()
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
                assert_eq!(store.record_count(), 0, "SSE must not be cached");

                // 302 download redirect: not cached (keep re-issuing the presigned URL each time).
        let store_dyn: Arc<dyn IdemStore> = store.clone();
        let resp = run(
            store_dyn,
            cfg,
            None,
            "user-a".into(),
            "k-302".into(),
            request("POST", "/v1/x", Some("k-302"), b"{}"),
            |_r| async move {
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header("location", "https://minio/x")
                    .body(Body::empty())
                    .unwrap()
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FOUND);
                assert_eq!(store.record_count(), 0, "302 must not be cached");
    }

    #[tokio::test]
    async fn oversized_request_passes_through_without_buffering() {
        let store = Arc::new(MemStore::default());
        let mut cfg = IdemConfig::default_for_tests();
        cfg.max_request_body = 16;
        let calls = Arc::new(AtomicUsize::new(0));
        let body: &'static [u8] = b"this-body-is-longer-than-16-bytes";
        assert!(body.len() > cfg.max_request_body);

        let resp = run_once(
            &store,
            cfg,
            "user-a",
            "big-1",
            request("PUT", "/v1/hub/plugins/x/versions/1/blob", Some("big-1"), body),
            "{}",
            &calls,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
                assert_eq!(store.record_count(), 0, "oversized request bodies do not participate in the idempotency cache");
    }

    #[tokio::test]
    async fn oversized_response_returns_full_body_but_not_cached() {
        let store = Arc::new(MemStore::default());
        let mut cfg = IdemConfig::default_for_tests();
        cfg.max_record_body = 8;
        let big = "x".repeat(64);
        let big: &'static str = Box::leak(big.into_boxed_str());
        let store_dyn: Arc<dyn IdemStore> = store.clone();
        let resp = run(
            store_dyn,
            cfg,
            None,
            "user-a".into(),
            "big-resp".into(),
            request("POST", "/v1/x", Some("big-resp"), b"{}"),
            move |_r| async move { json_ok(200, big) },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
                assert_eq!(body_string(resp).await.len(), 64, "the complete body must be returned even above the cache limit");
        assert_eq!(store.record_count(), 0);
    }

    #[tokio::test]
    async fn redis_failure_is_fail_open_by_default_and_fail_closed_on_demand() {
        let store = Arc::new(MemStore::failing());
        let calls = Arc::new(AtomicUsize::new(0));

                // Default fail-open: pass through and execute; behavior is not broken by the idempotency layer.
        let resp = run_once(
            &store,
            IdemConfig::default_for_tests(),
            "user-a",
            "k-fail",
            request("POST", "/v1/admin/users", Some("k-fail"), b"{}"),
            "{\"ok\":true}",
            &calls,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        // fail_open=false: 503 + details.reason=idempotency_store.
        let mut cfg = IdemConfig::default_for_tests();
        cfg.fail_open = false;
        let store_dyn: Arc<dyn IdemStore> = store.clone();
        let resp = run(
            store_dyn,
            cfg,
            None,
            "user-a".into(),
            "k-fail-2".into(),
            request("POST", "/v1/admin/users", Some("k-fail-2"), b"{}"),
            |_r| async move { json_ok(201, "{}") },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_string(resp).await;
        assert!(body.contains("idempotency_store"), "{body}");
        assert!(body.contains("redis"), "{body}");
    }

        /// Simulate the race where "the previous holder finishes and writes the cache after our get miss but before our begin".
    struct RaceStore {
        _scope: String,
        raw: String,
        first_get: AtomicUsize,
        puts: AtomicUsize,
        releases: AtomicUsize,
    }

    impl RaceStore {
        fn new(scope: String, raw: String) -> Self {
            Self {
                _scope: scope,
                raw,
                first_get: AtomicUsize::new(0),
                puts: AtomicUsize::new(0),
                releases: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl IdemStore for RaceStore {
        async fn get(&self, _scope_hash: &str) -> crate::error::Result<Option<String>> {
                        // First read (before locking) misses; the read after locking (double-check) hits.
            if self.first_get.fetch_add(1, Ordering::Relaxed) == 0 {
                return Ok(None);
            }
            Ok(Some(self.raw.clone()))
        }

        async fn begin(
            &self,
            _scope_hash: &str,
            _holder: &str,
            _ttl_secs: u64,
        ) -> crate::error::Result<bool> {
            Ok(true)
        }

        async fn put(
            &self,
            _scope_hash: &str,
            _record: &str,
            _ttl_secs: u64,
        ) -> crate::error::Result<()> {
            self.puts.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn release(&self, _scope_hash: &str, _holder: &str) -> crate::error::Result<()> {
            self.releases.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn double_check_after_lock_prevents_duplicate_execution() {
        let scope = scope_hash("user-a", &Method::POST, "/v1/x", "race-key");
        let fingerprint = request_fingerprint(&Method::POST, "/v1/x", "", b"{}");
        let record = IdemRecord {
            v: RECORD_VERSION,
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body_b64: B64.encode("cached-body"),
            fingerprint,
            created_at: 0,
        };
        let store = Arc::new(RaceStore::new(scope, serde_json::to_string(&record).unwrap()));
        let calls = Arc::new(AtomicUsize::new(0));
        let store_dyn: Arc<dyn IdemStore> = store.clone();
        let calls2 = calls.clone();
        let resp = run(
            store_dyn,
            IdemConfig::default_for_tests(),
            None,
            "user-a".into(),
            "race-key".into(),
            request("POST", "/v1/x", Some("race-key"), b"{}"),
            move |_r| async move {
                calls2.fetch_add(1, Ordering::Relaxed);
                json_ok(201, "{\"executed\":true}")
            },
        )
        .await;
                assert_eq!(resp.status(), StatusCode::OK, "a double-check hit must replay the cached status code");
        assert_eq!(
            resp.headers().get(REPLAY_HEADER).and_then(|v| v.to_str().ok()),
            Some("true")
        );
        assert_eq!(body_string(resp).await, "cached-body");
                assert_eq!(calls.load(Ordering::Relaxed), 0, "the handler must not execute twice within the race window");
                assert_eq!(store.puts.load(Ordering::Relaxed), 0, "the replay path must not overwrite the cache");
                assert_eq!(store.releases.load(Ordering::Relaxed), 1, "the acquired lock must be released");
    }

    #[tokio::test]
    async fn results_are_reported_with_low_cardinality_metrics() {
        let metrics = crate::observe::Metrics::new();
                // Startup touch 0: the 5 result values exist before traffic arrives (E2E/alerts assert by name)
        for result in ["hit", "miss", "conflict", "in_progress", "error"] {
                        assert_eq!(idem_count(&metrics, result), 0, "at startup result={result} must be 0");
        }
        let store = Arc::new(MemStore::default());
        let cfg = IdemConfig::default_for_tests();

                // miss: the first request really executes
        let store_dyn: Arc<dyn IdemStore> = store.clone();
        let first = run(
            store_dyn,
            cfg,
            Some(metrics.clone()),
            "user-a".into(),
            "key-m".into(),
            request("POST", "/v1/admin/users", Some("key-m"), b"{\"n\":1}"),
            |_r| async move { json_ok(201, "{\"id\":\"u1\"}") },
        )
        .await;
        assert_eq!(first.status(), StatusCode::CREATED);
        assert_eq!(idem_count(&metrics, "miss"), 1);

                // hit: same key, same body → replay
        let store_dyn: Arc<dyn IdemStore> = store.clone();
        let second = run(
            store_dyn,
            cfg,
            Some(metrics.clone()),
            "user-a".into(),
            "key-m".into(),
            request("POST", "/v1/admin/users", Some("key-m"), b"{\"n\":1}"),
            |_r| async move { json_ok(201, "{\"id\":\"u1\"}") },
        )
        .await;
        assert_eq!(second.status(), StatusCode::CREATED);
        assert_eq!(
            second.headers().get(REPLAY_HEADER).and_then(|v| v.to_str().ok()),
            Some("true")
        );
        assert_eq!(idem_count(&metrics, "hit"), 1);

                // conflict: same key, different body
        let store_dyn: Arc<dyn IdemStore> = store.clone();
        let third = run(
            store_dyn,
            cfg,
            Some(metrics.clone()),
            "user-a".into(),
            "key-m".into(),
            request("POST", "/v1/admin/users", Some("key-m"), b"{\"n\":2}"),
            |_r| async move { json_ok(201, "{\"id\":\"u2\"}") },
        )
        .await;
        assert_eq!(third.status(), StatusCode::CONFLICT);
        assert_eq!(idem_count(&metrics, "conflict"), 1);

                // in_progress: concurrent same key (occupy the single-flight lock first)
        let scope = scope_hash("user-b", &Method::POST, "/v1/admin/users", "key-i");
        assert!(store.begin(&scope, "other-holder", 30).await.unwrap());
        let store_dyn: Arc<dyn IdemStore> = store.clone();
        let fourth = run(
            store_dyn,
            cfg,
            Some(metrics.clone()),
            "user-b".into(),
            "key-i".into(),
            request("POST", "/v1/admin/users", Some("key-i"), b"{}"),
            |_r| async move { json_ok(201, "{}") },
        )
        .await;
        assert_eq!(fourth.status(), StatusCode::CONFLICT);
        assert_eq!(idem_count(&metrics, "in_progress"), 1);

                // error: store unavailable (fail-open also counts as error, to signal that the idempotency layer is not in effect)
        let failing: Arc<dyn IdemStore> = Arc::new(MemStore::failing());
        let fifth = run(
            failing,
            cfg,
            Some(metrics.clone()),
            "user-c".into(),
            "key-e".into(),
            request("POST", "/v1/x", Some("key-e"), b"{}"),
            |_r| async move { json_ok(200, "{}") },
        )
        .await;
                assert_eq!(fifth.status(), StatusCode::OK, "default fail-open still passes through");
        assert_eq!(idem_count(&metrics, "error"), 1);

                // The metric is indeed exposed under the documented name
        assert!(
            metrics
                .render()
                .contains("lattice_http_idempotency_total"),
                        "the metric name must appear in the /metrics text"
        );
    }

    #[tokio::test]
    async fn scope_isolates_users_with_same_key() {
        let store = Arc::new(MemStore::default());
        let cfg = IdemConfig::default_for_tests();
        let calls = Arc::new(AtomicUsize::new(0));

        let _ = run_once(
            &store,
            cfg,
            "user-a",
            "shared-key",
            request("POST", "/v1/x", Some("shared-key"), b"{}"),
            "{\"who\":\"a\"}",
            &calls,
        )
        .await;
        let resp_b = run_once(
            &store,
            cfg,
            "user-b",
            "shared-key",
            request("POST", "/v1/x", Some("shared-key"), b"{}"),
            "{\"who\":\"b\"}",
            &calls,
        )
        .await;
                assert_eq!(resp_b.status(), StatusCode::CREATED, "the same key across users must not replay each other");
        assert!(
            resp_b.headers().get(REPLAY_HEADER).is_none(),
                        "user-b must not hit user-a's cache"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(store.record_count(), 2);
    }
}
