//! HTTP surface of the transfer service (design §6.10 / §17.17).
//!
//! Routes (public, behind the same edge that fronts the console):
//!
//! | Route | Purpose |
//! |---|---|
//! | `GET|HEAD /t/{token}` | capability-checked streaming download, `Range`/`If-Range` aware |
//! | `GET /healthz` | liveness (process only) |
//! | `GET /readyz` | readiness: at least one object-storage endpoint reachable |
//!
//! Plus a separate metrics listener (`/metrics`, `/healthz`) when `[transfer] metrics_listen`
//! is set. The service is stateless: tokens are self-contained HMAC capabilities, so any
//! replica can serve any download and Kubernetes/compose can scale it independently.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures::stream::{self, Stream, StreamExt};
use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use super::metrics::TransferMetrics;
use super::token::{Claims, TokenSigner};
use super::upstream::{BodySource, ObjectStore, UpstreamError};

/// Shared state of one transfer instance.
pub struct TransferService {
    signer: TokenSigner,
    store: Arc<ObjectStore>,
    metrics: Arc<TransferMetrics>,
    inflight: Arc<Semaphore>,
    /// Time to the upstream response head (not the whole body: a large download may run for
    /// minutes and must not be cut by a request deadline).
    open_timeout: Option<Duration>,
}

impl TransferService {
    pub fn new(
        signer: TokenSigner,
        store: Arc<ObjectStore>,
        metrics: Arc<TransferMetrics>,
        max_inflight: usize,
        open_timeout: Option<Duration>,
    ) -> Self {
        TransferService {
            signer,
            store,
            metrics,
            inflight: Arc::new(Semaphore::new(max_inflight.max(1))),
            open_timeout,
        }
    }

    pub fn metrics(&self) -> &Arc<TransferMetrics> {
        &self.metrics
    }

    pub fn store(&self) -> &Arc<ObjectStore> {
        &self.store
    }

    /// Main data-plane router.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/t/:token", get(download).head(download))
            .route("/healthz", get(health))
            .route("/readyz", get(ready))
            .with_state(self)
    }
}

/// Metrics listener router (separate port, no auth — same convention as the node `/metrics`).
pub fn metrics_router(metrics: Arc<TransferMetrics>) -> Router {
    Router::new()
        .route(
            "/metrics",
            get(move || {
                let metrics = metrics.clone();
                async move {
                    match metrics.render() {
                        Ok(body) => (
                            [(
                                header::CONTENT_TYPE,
                                "text/plain; version=0.0.4; charset=utf-8",
                            )],
                            body,
                        )
                            .into_response(),
                        Err(e) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("metrics encoding failed: {e}"),
                        )
                            .into_response(),
                    }
                }
            }),
        )
        .route("/healthz", get(health))
}

async fn health() -> &'static str {
    "ok"
}

async fn ready(State(svc): State<Arc<TransferService>>) -> Response {
    let probes = svc.store.probe().await;
    let healthy = probes.iter().filter(|(_, r)| r.is_ok()).count();
    let total = probes.len();
    let ok = healthy > 0;
    svc.metrics.ready.set(if ok { 1 } else { 0 });
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    // Internal endpoint names/errors stay in logs; the probe body is intentionally generic.
    (
        status,
        axum::Json(json!({
            "ready": ok,
            "endpoints_total": total,
            "endpoints_healthy": healthy,
        })),
    )
        .into_response()
}

async fn download(
    State(svc): State<Arc<TransferService>>,
    method: Method,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let started = Instant::now();
    let claims = match svc.signer.verify(&token, chrono::Utc::now().timestamp()) {
        Ok(c) => c,
        Err(super::token::TokenError::Expired) => {
            return counted(
                &svc,
                error(StatusCode::GONE, "token_expired", "download link expired"),
            );
        }
        Err(e) => {
            tracing::debug!(error = %e, "transfer token rejected");
            return counted(
                &svc,
                error(
                    StatusCode::NOT_FOUND,
                    "token_invalid",
                    "download link is invalid",
                ),
            );
        }
    };

    // Conditional GET: `If-None-Match` on the content hash. Checked before the upstream (and
    // before a permit is taken) so revalidation costs nothing.
    let etag = etag_of(&claims);
    if let (Some(etag), Some(inm)) = (etag.as_deref(), headers.get(header::IF_NONE_MATCH)) {
        if inm
            .to_str()
            .map(|v| !claims.h.is_empty() && v.contains(claims.h.as_str()))
            .unwrap_or(false)
        {
            let mut resp = StatusCode::NOT_MODIFIED.into_response();
            apply_common_headers(resp.headers_mut(), &claims, Some(etag), None, None);
            svc.metrics
                .requests
                .with_label_values(&[StatusCode::NOT_MODIFIED.as_str()])
                .inc();
            return resp;
        }
    }

    let permit = match svc.inflight.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("transfer concurrency cap reached");
            return counted(
                &svc,
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "busy",
                    "too many concurrent downloads, retry shortly",
                ),
            );
        }
    };

    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    // Stale validator: If-Range that does not match the current content means "send the whole
    // object", not "resume". Without this, a replaced object would return a wrong 206 slice.
    let effective_range = match (&range, headers.get(header::IF_RANGE), etag.as_deref()) {
        (Some(_), Some(if_range), Some(_)) => {
            let matches = if_range
                .to_str()
                .map(|v| !claims.h.is_empty() && v.contains(claims.h.as_str()))
                .unwrap_or(false);
            if matches {
                range.clone()
            } else {
                None
            }
        }
        _ => range.clone(),
    };

    let method_str = if method == Method::HEAD { "HEAD" } else { "GET" };
    let open = svc.store.open(
        method_str,
        &claims.b,
        &claims.k,
        effective_range.as_deref(),
        headers
            .get(header::IF_RANGE)
            .and_then(|v| v.to_str().ok()),
    );
    let opened = match svc.open_timeout {
        Some(t) => match timeout(t, open).await {
            Ok(r) => r,
            Err(_) => {
                svc.metrics
                    .requests
                    .with_label_values(&[StatusCode::GATEWAY_TIMEOUT.as_str()])
                    .inc();
                return error(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream_timeout",
                    "object storage did not answer in time",
                );
            }
        },
        None => open.await,
    };

    let upstream = match opened {
        Ok(u) => u,
        Err(UpstreamError::BadRequest(why)) => {
            return counted(
                &svc,
                error(StatusCode::BAD_REQUEST, "bad_range", &why),
            );
        }
        Err(UpstreamError::Unavailable(attempts)) => {
            for (endpoint, why) in &attempts {
                svc.metrics
                    .upstream_failures
                    .with_label_values(&[endpoint.as_str()])
                    .inc();
                tracing::warn!(endpoint = %endpoint, error = %why, "transfer upstream failed");
            }
            return counted(
                &svc,
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "upstream_unavailable",
                    "object storage unavailable",
                ),
            );
        }
        Err(UpstreamError::Upstream(why)) => {
            tracing::error!(error = %why, "transfer upstream error");
            return counted(
                &svc,
                error(
                    StatusCode::BAD_GATEWAY,
                    "upstream_error",
                    "object storage request failed",
                ),
            );
        }
    };

    let status_label = upstream.status.to_string();
    svc.metrics
        .open_seconds
        .with_label_values(&[status_label.as_str()])
        .observe(started.elapsed().as_secs_f64());

    match upstream.status {
        200..=299 | 304 => {}
        404 => {
            return counted(
                &svc,
                error(
                    StatusCode::NOT_FOUND,
                    "object_missing",
                    "object no longer exists",
                ),
            );
        }
        416 => {
            let mut resp = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
            let content_range = upstream
                .header("content-range")
                .map(str::to_string)
                .or_else(|| {
                    if claims.s > 0 {
                        Some(format!("bytes */{}", claims.s))
                    } else {
                        None
                    }
                });
            if let Some(cr) = content_range {
                if let Ok(v) = HeaderValue::from_str(&cr) {
                    resp.headers_mut().insert(header::CONTENT_RANGE, v);
                }
            }
            return counted(&svc, resp);
        }
        401 | 403 => {
            tracing::error!(
                status = upstream.status,
                endpoint = %upstream.endpoint,
                "object storage rejected the node credentials"
            );
            return counted(
                &svc,
                error(
                    StatusCode::BAD_GATEWAY,
                    "upstream_denied",
                    "object storage rejected the request",
                ),
            );
        }
        status => {
            tracing::error!(status, endpoint = %upstream.endpoint, "unexpected upstream status");
            return counted(
                &svc,
                error(
                    StatusCode::BAD_GATEWAY,
                    "upstream_status",
                    "object storage returned an unexpected status",
                ),
            );
        }
    }

    let status = StatusCode::from_u16(upstream.status).unwrap_or(StatusCode::OK);
    let content_type = if !claims.t.is_empty() {
        claims.t.clone()
    } else {
        upstream
            .header("content-type")
            .map(str::to_string)
            .unwrap_or_else(|| "application/octet-stream".into())
    };
    let content_length = upstream.content_length.or_else(|| {
        if claims.s > 0 {
            Some(claims.s)
        } else {
            None
        }
    });
    let upstream_etag = upstream.header("etag").map(str::to_string);
    let last_modified = upstream.header("last-modified").map(str::to_string);
    let content_range = upstream.header("content-range").map(str::to_string);

    let mut resp = status.into_response();
    apply_common_headers(
        resp.headers_mut(),
        &claims,
        upstream_etag.as_deref().or(etag.as_deref()),
        content_length,
        Some(&content_type),
    );
    if let Some(cr) = content_range {
        if let Ok(v) = HeaderValue::from_str(&cr) {
            resp.headers_mut().insert(header::CONTENT_RANGE, v);
        }
    }
    if let Some(lm) = last_modified {
        if let Ok(v) = HeaderValue::from_str(&lm) {
            resp.headers_mut().insert(header::LAST_MODIFIED, v);
        }
    }

    let Some(body) = upstream.body else {
        drop(permit);
        svc.metrics
            .requests
            .with_label_values(&[status.as_str()])
            .inc();
        return resp;
    };

    if method == Method::HEAD {
        drop(body);
        drop(permit);
        svc.metrics
            .requests
            .with_label_values(&[status.as_str()])
            .inc();
        return resp;
    }

    let guard = BodyGuard::new(permit, svc.metrics.clone());
    *resp.body_mut() = instrumented_body(body, guard, svc.metrics.clone());
    svc.metrics
        .requests
        .with_label_values(&[status.as_str()])
        .inc();
    resp
}

fn counted(svc: &TransferService, resp: Response) -> Response {
    svc.metrics
        .requests
        .with_label_values(&[resp.status().as_str()])
        .inc();
    resp
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (status, axum::Json(json!({ "code": code, "error": message }))).into_response()
}

fn etag_of(claims: &Claims) -> Option<String> {
    if claims.h.is_empty() {
        None
    } else {
        Some(format!("\"{}\"", claims.h))
    }
}

/// Headers shared by 200/206/304: integrity, cache class, disposition, sniffing.
fn apply_common_headers(
    headers: &mut HeaderMap,
    claims: &Claims,
    etag: Option<&str>,
    content_length: Option<u64>,
    content_type: Option<&str>,
) {
    if let Some(n) = content_length {
        if let Ok(v) = HeaderValue::from_str(&n.to_string()) {
            headers.insert(header::CONTENT_LENGTH, v);
        }
    }
    if let Some(content_type) = content_type {
        if let Ok(v) = HeaderValue::from_str(content_type) {
            headers.insert(header::CONTENT_TYPE, v);
        }
    }
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    if let Some(etag) = etag {
        if let Ok(v) = HeaderValue::from_str(etag) {
            headers.insert(header::ETAG, v);
        }
    }
    if !claims.h.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&claims.h) {
            headers.insert(HeaderName::from_static("x-content-sha256"), v);
        }
    }
    let cache = if claims.c == "public" {
        if claims.h.is_empty() {
            "public, max-age=300"
        } else {
            // Content-addressed by sha256: safe for a CDN to keep forever.
            "public, max-age=31536000, immutable"
        }
    } else {
        "private, no-store"
    };
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    if let Ok(v) = HeaderValue::from_str(&content_disposition(&claims.d, &claims.n)) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
}

/// `attachment`/`inline` + an ASCII fallback name + RFC 5987 UTF-8 name.
fn content_disposition(disposition: &str, filename: &str) -> String {
    let kind = if disposition.eq_ignore_ascii_case("inline") {
        "inline"
    } else {
        "attachment"
    };
    let name = if filename.trim().is_empty() {
        "download.bin"
    } else {
        filename.trim()
    };
    let ascii: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                if c == '"' || c == '\\' {
                    '_'
                } else {
                    c
                }
            } else {
                '_'
            }
        })
        .collect();
    format!(
        "{kind}; filename=\"{ascii}\"; filename*=UTF-8''{}",
        urlencoding::encode(name)
    )
}

/// Holds the in-flight permit and the `lattice_transfer_inflight` gauge for the whole body
/// stream; both are released when the stream ends **or the client disconnects** (stream drop).
struct BodyGuard {
    permit: Option<OwnedSemaphorePermit>,
    metrics: Arc<TransferMetrics>,
}

impl BodyGuard {
    fn new(permit: OwnedSemaphorePermit, metrics: Arc<TransferMetrics>) -> Self {
        metrics.inflight.inc();
        BodyGuard {
            permit: Some(permit),
            metrics,
        }
    }
}

impl Drop for BodyGuard {
    fn drop(&mut self) {
        self.metrics.inflight.dec();
        self.permit.take();
    }
}

fn instrumented_body(
    body: BodySource<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
    guard: BodyGuard,
    metrics: Arc<TransferMetrics>,
) -> Body {
    let stream: std::pin::Pin<Box<dyn Stream<Item = io::Result<bytes::Bytes>> + Send>> =
        Box::pin(body.into_stream());
    let counted = stream::unfold((stream, guard), move |(mut s, guard)| {
        let metrics = metrics.clone();
        async move {
            match s.next().await {
                Some(Ok(bytes)) => {
                    metrics.bytes.inc_by(bytes.len() as u64);
                    Some((Ok::<bytes::Bytes, io::Error>(bytes), (s, guard)))
                }
                Some(Err(e)) => Some((Err(e), (s, guard))),
                None => None,
            }
        }
    });
    Body::from_stream(counted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_is_ascii_safe_and_rfc5987() {
        let d = content_disposition("attachment", "任务规划-0.1.1.zip");
        assert!(d.starts_with("attachment; filename=\""));
        assert!(d.contains("filename*=UTF-8''"));
        assert!(!d.contains('\n'));
        // Every byte of the header value must be a valid header value.
        assert!(HeaderValue::from_str(&d).is_ok());
    }

    #[test]
    fn disposition_defaults_and_quotes() {
        let d = content_disposition("inline", "");
        assert!(d.starts_with("inline; filename=\"download.bin\""));
        let d = content_disposition("attachment", "a\"b\\c.zip");
        assert!(d.contains("filename=\"a_b_c.zip\""));
        assert!(HeaderValue::from_str(&d).is_ok());
    }
}
