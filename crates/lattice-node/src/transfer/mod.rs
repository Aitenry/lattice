//! Download transfer plane (design §6.10 / §17.17).
//!
//! ## Why this exists
//!
//! The first hub implementation answered downloads with `302 → <MinIO presigned URL>`. That
//! coupled every client to object storage: the URL host had to be reachable from the client
//! (`[s3] public_endpoint`), MinIO's availability became the download's availability, and the
//! plugin center leaked another service's internal address to desktop clients — remote clients
//! got `ECONNREFUSED 127.0.0.1:9000` while the console itself was perfectly reachable.
//!
//! The transfer plane separates **business API** from **content delivery**:
//!
//! - the node mints a short-lived HMAC capability token per object and answers `302` to
//!   `{public_base_url}/t/{token}` — no object-store URL, no bytes through the node;
//! - `lattice-transfer` (this module's [`run`]) is a stateless service: verify token, stream
//!   from the internal S3 endpoint(s) with `Range`/`If-Range`, propagate integrity headers;
//! - any number of replicas serve any token, so the plane scales horizontally behind the same
//!   LB as the console (HA without shared state or sticky sessions).
//!
//! ## Failure model
//!
//! | Condition | Answer |
//! |---|---|
//! | bad/forged token | `404 token_invalid` |
//! | expired token | `410 token_expired` |
//! | invalid `Range` | `400 bad_range` |
//! | all S3 endpoints down | `503 upstream_unavailable` (+ retryable) |
//! | object deleted | `404 object_missing` |
//! | S3 rejects credentials | `502 upstream_denied` (never leaked to the client) |
//! | concurrency cap hit | `503 busy` |
//!
//! The service never logs token strings or object bytes; it logs bucket/key/status/bytes and
//! per-endpoint failures at WARN.

pub mod metrics;
pub mod server;
pub mod token;
pub mod upstream;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use crate::config::{Config, TransferCfg};
use metrics::TransferMetrics;
use server::{metrics_router, TransferService};
use upstream::ObjectStore;

pub use token::{Claims, TokenError, TokenSigner};

/// Node-side signer construction (design §6.10).
///
/// `None` = transfer plane disabled, download handlers keep the legacy presigned-URL path.
/// Configuration is validated earlier (`Config::validate`), so a `Some` here is always usable.
pub fn build_signer(cfg: &TransferCfg) -> crate::error::Result<Option<Arc<TokenSigner>>> {
    if !cfg.enabled {
        return Ok(None);
    }
    let signer = TokenSigner::new(
        &cfg.secret,
        cfg.effective_token_ttl_secs(),
        &cfg.public_base_url,
    )
    .map_err(crate::error::internal)?;
    Ok(Some(Arc::new(signer)))
}

/// Run the standalone transfer service (bin `lattice-transfer`).
///
/// Reads the same TOML/environment as the node: `[transfer]` (secret/listen/limits) plus
/// `[s3]` (credentials, endpoint and optional failover endpoints).
pub async fn run(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let json = cfg.node.log == "json";
    crate::observe::init_tracing("transfer", json);

    let t = &cfg.transfer;
    if t.secret.as_bytes().len() < crate::config::MIN_TRANSFER_SECRET_BYTES {
        return Err(io_err(format!(
            "[transfer] secret must be at least {} bytes; inject LATTICE__TRANSFER__SECRET",
            crate::config::MIN_TRANSFER_SECRET_BYTES
        )));
    }
    if !t.listen.contains(':') {
        return Err(io_err("[transfer] listen must be host:port, e.g. 0.0.0.0:8090"));
    }
    if cfg.s3.access_key.is_empty() || cfg.s3.secret_key.is_empty() {
        return Err(io_err(
            "[s3] access_key/secret_key are required by the transfer service (streaming reads are signed)",
        ));
    }

    let signer = TokenSigner::verifier(&t.secret).map_err(io_err)?;
    let store = Arc::new(ObjectStore::new(
        cfg.s3.clone(),
        Duration::from_millis(t.connect_timeout_ms.max(100)),
        Duration::from_millis(t.read_timeout_ms.max(100)),
    ));
    let metrics = Arc::new(TransferMetrics::new());
    let open_timeout = if t.request_timeout_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(t.request_timeout_ms))
    };
    let service = Arc::new(TransferService::new(
        signer,
        store.clone(),
        metrics.clone(),
        t.effective_max_inflight(),
        open_timeout,
    ));

    // Metrics listener (separate port, unauthenticated like the node's `/metrics`).
    let metrics_addr = t.metrics_listen.trim();
    if !metrics_addr.is_empty() {
        let addr: SocketAddr = metrics_addr.parse()?;
        let listener = TcpListener::bind(addr).await?;
        let app = metrics_router(metrics.clone());
        tracing::info!(addr = %addr, "transfer metrics listening");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!(error = %e, "transfer metrics server stopped");
            }
        });
    }

    // Readiness refresher: keep `lattice_transfer_ready` meaningful even when nothing calls
    // `/readyz` (the Compose healthcheck only hits `/healthz`, while Prometheus alerts rely on
    // this gauge). It also logs endpoint transitions so an object-storage outage is visible
    // without waiting for a failing download.
    {
        let store = store.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut last_ok: Option<bool> = None;
            loop {
                let probes = store.probe().await;
                let ok = probes.iter().any(|(_, r)| r.is_ok());
                metrics.ready.set(if ok { 1 } else { 0 });
                if last_ok != Some(ok) {
                    if ok {
                        tracing::info!("object storage reachable from the transfer plane");
                    } else {
                        for (endpoint, result) in &probes {
                            if let Err(err) = result {
                                tracing::warn!(
                                    endpoint = %endpoint,
                                    error = %err,
                                    "object storage endpoint unreachable"
                                );
                            }
                        }
                    }
                }
                last_ok = Some(ok);
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        });
    }

    let addr: SocketAddr = t.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(
        addr = %addr,
        endpoints = ?store.endpoints(),
        max_inflight = t.effective_max_inflight(),
        "transfer data plane listening"
    );
    axum::serve(listener, service.router())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("transfer service stopped");
    Ok(())
}

fn io_err(msg: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        msg.into(),
    ))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    tracing::info!("shutdown signal received, draining transfer connections");
}

/// Everything a download endpoint knows about the object it is handing out.
pub struct DownloadSpec<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    pub filename: &'a str,
    pub content_type: &'a str,
    pub size: u64,
    pub sha256: &'a str,
    /// `attachment` (default) or `inline`.
    pub disposition: &'a str,
    /// `public` = shared/CDN caching allowed (published plugin packages); else `private`.
    pub cache: &'a str,
    pub user_id: &'a str,
    /// Legacy presign TTL, used only when the transfer plane is disabled.
    pub presign_ttl_secs: u64,
}

/// Build the download target for one object: a transfer capability URL when `[transfer]
/// enabled`, otherwise the legacy presigned object-store URL.
///
/// This is the **only** place the node decides how content is delivered, so the two paths
/// cannot drift across the hub/message/recording endpoints.
pub fn object_download_url(st: &crate::state::AppState, spec: DownloadSpec<'_>) -> String {
    match &st.transfer {
        Some(signer) => signer.url_for(Claims {
            v: 1,
            b: spec.bucket.to_string(),
            k: spec.key.to_string(),
            n: spec.filename.to_string(),
            t: spec.content_type.to_string(),
            s: spec.size,
            h: spec.sha256.to_string(),
            d: spec.disposition.to_string(),
            c: spec.cache.to_string(),
            e: 0,
            i: 0,
            u: spec.user_id.to_string(),
        }),
        None => st
            .s3
            .presign_get(spec.bucket, spec.key, spec.presign_ttl_secs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_transfer_has_no_signer() {
        let cfg = TransferCfg::default();
        assert!(build_signer(&cfg).unwrap().is_none());
    }

    #[test]
    fn enabled_transfer_requires_secret() {
        let cfg = TransferCfg {
            enabled: true,
            public_base_url: "http://127.0.0.1:8088".into(),
            secret: "short".into(),
            ..Default::default()
        };
        assert!(build_signer(&cfg).is_err());
    }

    #[test]
    fn enabled_transfer_signs_urls() {
        let cfg = TransferCfg {
            enabled: true,
            public_base_url: "http://127.0.0.1:8088/".into(),
            secret: "0123456789abcdef0123456789abcdef".into(),
            ..Default::default()
        };
        let signer = build_signer(&cfg).unwrap().unwrap();
        let url = signer.url_for(Claims {
            v: 1,
            b: "lattice-plugins".into(),
            k: "a/1/a.zip".into(),
            n: "a.zip".into(),
            t: "application/zip".into(),
            s: 1,
            h: "a".repeat(64),
            d: "attachment".into(),
            c: "public".into(),
            e: 0,
            i: 0,
            u: String::new(),
        });
        assert!(url.starts_with("http://127.0.0.1:8088/t/"), "{url}");
    }

    #[test]
    fn empty_public_base_yields_same_origin_location() {
        let cfg = TransferCfg {
            enabled: true,
            public_base_url: String::new(),
            secret: "0123456789abcdef0123456789abcdef".into(),
            ..Default::default()
        };
        let signer = build_signer(&cfg).unwrap().unwrap();
        let url = signer.url_for(Claims {
            v: 1,
            b: "lattice-plugins".into(),
            k: "a/1/a.zip".into(),
            n: "a.zip".into(),
            t: "application/zip".into(),
            s: 1,
            h: String::new(),
            d: "attachment".into(),
            c: "private".into(),
            e: 0,
            i: 0,
            u: String::new(),
        });
        assert!(url.starts_with("/t/"), "{url}");
        assert!(!url.contains("127.0.0.1"), "no host may be baked in: {url}");
        let token = url.strip_prefix("/t/").unwrap();
        assert!(signer
            .verify(token, chrono::Utc::now().timestamp())
            .is_ok());
    }

    // ----------------------------------------------------------------------
    // Streaming integration tests: axe the real Router against a fake S3.
    // ----------------------------------------------------------------------

    use crate::config::S3Cfg;
    use crate::transfer::metrics::TransferMetrics;
    use crate::transfer::server::TransferService;
    use crate::transfer::upstream::ObjectStore;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn service(endpoint: &str) -> Arc<TransferService> {
        let cfg = S3Cfg {
            endpoint: endpoint.into(),
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            ..Default::default()
        };
        let store = Arc::new(ObjectStore::new(
            cfg,
            Duration::from_secs(2),
            Duration::from_secs(5),
        ));
        Arc::new(TransferService::new(
            TokenSigner::verifier(SECRET).unwrap(),
            store,
            Arc::new(TransferMetrics::new()),
            8,
            None,
        ))
    }

    fn claims() -> Claims {
        Claims {
            v: 1,
            b: "lattice-plugins".into(),
            k: "task-planner/0.1.1/task-planner-0.1.1.zip".into(),
            n: "task-planner-0.1.1.zip".into(),
            t: "application/zip".into(),
            s: 20_097,
            h: "a".repeat(64),
            d: "attachment".into(),
            c: "public".into(),
            e: 0,
            i: 0,
            u: "01M5WBF9E39E0FQ9RBYH63D0BN".into(),
        }
    }

    /// Minimal fake S3: records the raw request, answers `status` + `headers` + `body`
    /// (no body for HEAD), always `Connection: close`.
    async fn fake_s3(
        status: &'static str,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> (String, Arc<tokio::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let seen_task = seen.clone();
        let body = Arc::new(body);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let seen = seen_task.clone();
                let body = body.clone();
                let headers = headers.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 2048];
                    loop {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    seen.lock().await.push(String::from_utf8_lossy(&buf).to_string());
                    let head_only = buf.starts_with(b"HEAD ");
                    let mut resp = format!("{status}\r\n");
                    for (k, v) in &headers {
                        resp.push_str(&format!("{k}: {v}\r\n"));
                    }
                    if head_only {
                        resp.push_str("Connection: close\r\n\r\n");
                        let _ = sock.write_all(resp.as_bytes()).await;
                    } else {
                        resp.push_str(&format!(
                            "Content-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        ));
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.write_all(&body).await;
                    }
                });
            }
        });
        (format!("http://{addr}"), seen)
    }

    /// Serve one `TransferService` on an ephemeral port for the duration of a test.
    async fn spawn_transfer(svc: Arc<TransferService>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, svc.router()).await;
        });
        addr
    }

    /// Raw HTTP/1.1 client: no extra dev-dependency, and it exercises the real hyper server
    /// (including streaming and header serialization). `Connection: close` makes
    /// `read_to_end` terminate after the response.
    async fn http_call(
        addr: SocketAddr,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
    ) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
        for (k, v) in extra {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        sock.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        sock.read_to_end(&mut raw).await.unwrap();
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response header terminator");
        let head = String::from_utf8_lossy(&raw[..split]).to_string();
        let body = raw[split + 4..].to_vec();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())))
            .collect();
        (status, headers, body)
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    #[tokio::test]
    async fn download_streams_with_range_and_integrity_headers() {
        let (endpoint, seen) = fake_s3(
            "HTTP/1.1 206 Partial Content",
            vec![
                ("Content-Type", "application/zip".into()),
                ("Content-Range", "bytes 0-3/20097".into()),
                ("ETag", "\"upstream-etag\"".into()),
            ],
            b"Wiki".to_vec(),
        )
        .await;
        let svc = service(&endpoint);
        let addr = spawn_transfer(svc).await;
        let token = TokenSigner::verifier(SECRET).unwrap().mint(claims());
        let (status, headers, body) =
            http_call(addr, "GET", &format!("/t/{token}"), &[("Range", "bytes=0-3")]).await;
        assert_eq!(status, 206);
        assert_eq!(
            header(&headers, "x-content-sha256"),
            Some(claims().h.as_str())
        );
        assert_eq!(header(&headers, "content-range"), Some("bytes 0-3/20097"));
        assert!(header(&headers, "cache-control")
            .unwrap()
            .contains("immutable"));
        assert!(header(&headers, "content-disposition")
            .unwrap()
            .contains("task-planner-0.1.1.zip"));
        assert_eq!(&body[..], b"Wiki");

        // The upstream request must be the internal presigned GET for this object, with the
        // client Range forwarded and the endpoint's own Host (signature covers Host).
        let raw = seen.lock().await.first().cloned().unwrap_or_default();
        assert!(
            raw.starts_with(
                "GET /lattice-plugins/task-planner/0.1.1/task-planner-0.1.1.zip?X-Amz-Algorithm="
            ),
            "{raw}"
        );
        assert!(raw.contains("X-Amz-Signature="), "{raw}");
        assert!(raw.contains("Range: bytes=0-3"), "{raw}");
        assert!(raw.contains(&format!(
            "Host: {}",
            endpoint.trim_start_matches("http://")
        )));
    }

    #[tokio::test]
    async fn head_returns_metadata_without_body() {
        let (endpoint, _seen) = fake_s3(
            "HTTP/1.1 200 OK",
            vec![
                ("Content-Type", "application/zip".into()),
                ("Content-Length", "20097".into()),
            ],
            Vec::new(),
        )
        .await;
        let svc = service(&endpoint);
        let addr = spawn_transfer(svc).await;
        let token = TokenSigner::verifier(SECRET).unwrap().mint(claims());
        let (status, headers, body) = http_call(addr, "HEAD", &format!("/t/{token}"), &[]).await;
        assert_eq!(status, 200);
        assert_eq!(header(&headers, "content-length"), Some("20097"));
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn invalid_token_is_404_and_never_reaches_s3() {
        // Port 1 is closed: any upstream attempt would surface as 503, so a 404 proves the
        // token check short-circuits before object storage.
        let svc = service("http://127.0.0.1:1");
        let addr = spawn_transfer(svc).await;
        let (status, _headers, _body) = http_call(addr, "GET", "/t/not-a-real-token", &[]).await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn upstream_404_maps_to_object_missing() {
        let (endpoint, _seen) = fake_s3("HTTP/1.1 404 Not Found", Vec::new(), Vec::new()).await;
        let svc = service(&endpoint);
        let addr = spawn_transfer(svc).await;
        let token = TokenSigner::verifier(SECRET).unwrap().mint(claims());
        let (status, _headers, _body) = http_call(addr, "GET", &format!("/t/{token}"), &[]).await;
        assert_eq!(status, 404);
    }
}
