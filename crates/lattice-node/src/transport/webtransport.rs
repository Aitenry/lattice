//! WebTransport (HTTP/3) browser media ingress gateway (PL-13 13.3; design §17.9 path ②).
//!
//! # Implementation status (PL-13 13.3: a browser-usable entry to the QUIC proxy skeleton — **bridge, not native WebRTC**)
//!
//! - Compile-time feature `webtransport` (**off** by default, implying `quic`) + runtime `[webtransport] enabled`
//!   (default `false`) dual switches; when not enabled there is zero UDP/TLS listening, zero tasks, and zero certificate reads.
//! - When enabled: a WebTransport server endpoint over HTTP/3 on TLS 1.3 (ALPN `h3`,
//!   `wtransport 0.7.2`) exposing the CONNECT path `/media`; the browser opens one **bidirectional stream** in that session,
//!   and the stream carries **the existing QUIC proxy protocol v1 TLV frames** (`[1B type][4B len BE][payload]`,
//!   type 1 = CONTROL JSON / type 2 = DATA media bytes), **fully isomorphic** with the QUIC client.
//! - **Bridge architecture** (the core trade-off of this implementation, see the next section): after accepting a WT session the gateway itself acts as a **local QUIC
//!   client**, connects to the listener at `[quic] bind`, opens a `bi` stream, and then connects the WT bidirectional stream to that QUIC bidirectional stream
//!   **frame by frame, verbatim** (neither CONTROL nor DATA is interpreted; only auth results and byte counts are observed).
//!
//! # Why a bridge (instead of rewriting registration/relay at the WT layer)
//!
//! The task card explicitly allows "the WT gateway acting as a local QUIC client, wiring WT byte streams to QUIC streams and reusing the existing
//! JWT/device/participant checks and TLV/relay logic". The benefits:
//!
//! 1. **Zero duplicated auth**: the register frame (with `access_jwt`/`device_fp`/join token) is handled by the existing
//!    `quic::handle_connection` → `validate_register` → `authenticate_register`; JWT verification (`AppState::verify_jwt`),
//!    `devices` table device binding, `stream-sig` session participant (a/b role) validation, and join token HMAC/single-use/expiry
//!    all run through **the same code**, so there is no second implementation and no convention drift;
//!    WT clients and QUIC clients get the same error `code`+`reason`.
//! 2. **Zero duplicated relay/rate-limit/caps**: the `stream_id` registry, A/B pairing, bidirectional relay, bye half-close,
//!    the 8Mbps per-stream token bucket (reusing `routing::media::allow_stream_bytes`), the per-node stream cap
//!    (reusing `[media] max_streams`), disconnect cleanup, and drain bye all execute in the QUIC layer; the WT layer only moves bytes.
//! 3. **WT ↔ QUIC interop for free**: A over WebTransport and B over QUIC (or vice versa) can still pair and relay,
//!    because they occupy the same registry and the same participant checks (E2E covers this case).
//!
//! Cost (stated truthfully): the media path takes one extra hop through a **local loopback QUIC** (UDP loopback, not cross-process;
//! two TLS hops per stream: browser↔WT, WT↔QUIC). This is the "minimal closed loop + zero duplicated implementation" trade-off; to remove
//! the hop later, the WT session could be registered directly into the QUIC registry (which requires decoupling the registry from `Connection` into a
//! transport-agnostic sink; that is a later refactor, out of scope here).
//!
//! # Protocol/paths (fixed conventions; E2E asserts on these)
//!
//! ```text
//! TLS 1.3 + ALPN "h3" (WebTransport over HTTP/3 CONNECT)
//! CONNECT  :path = /media          any other path → HTTP 404 (SessionRequest::not_found)
//! bidi stream 0 (browser open_bi / gateway accept_bi) carries QUIC proxy protocol v1 frames:
//!   [1B type][4B payload_len BE][payload], type 1=CONTROL(UTF-8 JSON ≤4KiB), 2=DATA(≤64KiB)
//! 1. a side: {"t":"register","v":1,"stream_id":..,"role":"a","access_jwt":..,"device_fp":..}
//!    ← {"t":"registered",..., "join_token":"qj1|...", "session_token":".."}
//! 2. b side: {"t":"register",...,"role":"b","token":"<join_token>"} → both ends {"t":"peer_ready"}
//! 3. DATA relayed verbatim in both directions (the server does not interpret the media format); bye/error frame semantics match QUIC exactly.
//! ```
//!
//! # Configuration (`[webtransport]`)
//!
//! `enabled=false` / `bind="0.0.0.0:4433"` / `cert` / `key` / `upstream` / `upstream_ca` /
//! `token_ttl_secs` / `idle_timeout_secs` / `path`. Off by default; **any configuration/certificate/port error
//! only WARNs and stays off**, never affecting node readiness or the existing QUIC/WS media paths.
//! `[webtransport] enabled=true` requires `[quic] enabled=true` (the bridge upstream) and it is recommended to set a UDP port
//! different from `[quic] bind` explicitly (both default to 4433; running both on one host requires changing one).
//!
//! # Metrics
//!
//! - `lattice_webtransport_sessions_active` (gauge): number of WT sessions being bridged;
//! - `lattice_webtransport_sessions_total{result}`: ok|path|handshake|auth|token|quota|
//!   bad_request|closed|error;
//! - `lattice_webtransport_auth_total{result}`: ok|expired|bad_jwt|device_mismatch|
//!   not_participant (**same convention** as `lattice_quic_auth_total`, counted by the bridge layer from observed upstream error frames;
//!   auth itself runs in the QUIC layer);
//! - `lattice_webtransport_bytes_total{direction}`: in/out (DATA payload bytes — the same media bytes
//!   counted by the QUIC relay).
//!
//! # Lifecycle
//!
//! The accept loop observes `AppState.draining` (shared by SIGTERM/admin drain) → stops accepting new CONNECTs →
//! waits for existing bridged sessions to be wrapped up by the QUIC drain `bye{reason:"shutdown"}` pass-through (bounded window) →
//! `endpoint.close(0,"shutdown")` stops serving and sends CONNECTION_CLOSE to leftover connections; the UDP socket is held by the
//! endpoint object and released when the process exits (same lifecycle as the QUIC endpoint). Where Windows has no POSIX
//! graceful signal semantics, SIGTERM = forced termination and the port is reclaimed by the kernel (E2E asserts both paths).
//!
//! # Gaps versus the design's final form (stated truthfully, no false claims)
//!
//! 1. **Not native WebRTC/SFU**: no ICE/DTLS/SCTP, no video/audio codecs or adaptive bitrate;
//!    the browser side gets "a byte stream relayed by the server", and the media format/container is up to the client (same as the WS tunnel).
//! 2. **No cross-node support**: the bridge upstream is fixed to the local QUIC listener, so A/B must land on the same node;
//!    LB HTTP/3 support and cross-node WT routing are not wired up.
//! 3. **Browser certificate trust**: dev self-signed requires the browser's `serverCertificateHashes` (W3C) or a locally trusted CA;
//!    CORS/`Origin` validation and HTTP/3 reverse proxying (LB) are out of scope; E2E uses a native client +
//!    a temporary CA to verify the protocol surface, which is not a browser compatibility test.
//! 4. **How auth information is presented**: the WT layer does not authenticate in CONNECT headers but follows the QUIC v1 first-frame register
//!    (by design the signaling layer issues tokens and the media plane binds them with JWTs), consistent with the existing QUIC client;
//!    `Authorization` header auth is an optional later enhancement.

use std::collections::HashMap;
use std::future::IntoFuture;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::{RecvStream as QuicRecv, SendStream as QuicSend};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::sync::Notify;

use wtransport::endpoint::IncomingSession;
use wtransport::tls::{Certificate, CertificateChain, PrivateKey};
use wtransport::{
    Connection as WtConnection, Endpoint as WtEndpoint, Identity, RecvStream as WtRecv,
    SendStream as WtSend, ServerConfig as WtServerConfig, VarInt,
};

use super::quic::{
    decode_header, encode_header, read_frame, ALPN, FRAME_CONTROL, FRAME_DATA, FRAME_HEADER,
};
use crate::config::{Config, WebTransportCfg};
use crate::observe::Metrics;
use crate::state::AppState;

/// WT session registration window cap (seconds): prevents a misconfiguration into a quasi-permanent "half-open" session.
const DRAIN_TIMEOUT_MIN_SECS: u64 = 2;
const DRAIN_TIMEOUT_MAX_SECS: u64 = 5;
/// Grace window during drain for the upstream QUIC drain to pass bye through to the browser side.
const DRAIN_SETTLE_GRACE: Duration = Duration::from_millis(500);
/// Keep-alive interval cap (consistent with the QUIC proxy: idle connections stay observable; the idle timeout comes from config).
const KEEP_ALIVE: Duration = Duration::from_secs(5);
/// WT-side close code: 0 = normal end (QUIC semantics: no error); 1 = protocol/internal error.
const WT_CLOSE_NORMAL: u32 = 0;
const WT_CLOSE_ERROR: u32 = 1;
/// Bidirectional pump wrap-up grace: after one side EOFs, the cap on waiting for the other side to send remaining data/bye (aligned with QUIC relay semantics).
const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// WebTransport gateway handle (`AppState.webtransport`).
///
/// Lifecycle: `build()` creates the HTTP/3 endpoint + the upstream QUIC client endpoint (synchronous, no spawn) →
/// `node::build` puts `Arc<WebTransportProxy>` into `AppState.webtransport` →
/// `spawn()` starts the accept loop and the draining watcher task. The endpoints close when `AppState` is dropped.
pub struct WebTransportProxy {
    /// HTTP/3 WebTransport server endpoint.
    endpoint: WtEndpoint<wtransport::endpoint::endpoint_side::Server>,
    local_addr: SocketAddr,
    /// Bridge upstream (local QUIC listener) address.
    upstream: SocketAddr,
    /// Upstream QUIC client endpoint (shared by all bridged sessions; connections/streams are exclusive per session).
    upstream_client: quinn::Endpoint,
    handshake_timeout: Duration,
    /// WT session registration window (`[webtransport] token_ttl_secs`): after CONNECT, the upstream `registered` (or an auth error)
    /// must be observed within the window; otherwise the gateway wraps up on its own, so half-open sessions do not hold resources for long.
    registration_window: Duration,
    metrics: Arc<Metrics>,
    /// `session_id -> session record`; len is the active session count (observable for E2E/troubleshooting).
    sessions: Mutex<HashMap<u64, Arc<SessionInfo>>>,
    next_session_id: AtomicU64,
    /// True when dev self-signed (in-memory only): an explicit warning is logged at startup.
    self_signed: bool,
    /// Bounded drain wait window ([2s,5s], same convention as the QUIC proxy).
    drain_timeout: Duration,
    draining: AtomicBool,
    /// Triggers the accept loop to exit.
    drain_notify: Notify,
    /// Drain runs only once (the SIGTERM hook/watcher task may fire simultaneously).
    drain_started: AtomicBool,
}

/// Metadata of a single bridged WT session (for troubleshooting/E2E; holds no stream handles).
///
/// The fields are currently only stored in the session table for `active_sessions()` counting and log troubleshooting and are not read yet;
/// `id/remote/started` are kept so a future recording bypass/audit can use them directly (without changing existing behavior).
#[allow(dead_code)]
struct SessionInfo {
    id: u64,
    remote: SocketAddr,
    started: Instant,
}

/// Session-level shared observations: used by both direction pumps and the wrap-up logic.
#[derive(Default)]
struct SessionObs {
    /// Whether the upstream `registered` was observed (= QUIC-layer auth passed).
    registered: AtomicBool,
    /// Whether `webtransport_auth_total` has already been counted as ok once.
    auth_ok_counted: AtomicBool,
    /// Session result (the first auth/protocol error takes effect); None = no error observed yet.
    session_result: Mutex<Option<&'static str>>,
    /// DATA payload bytes (in = browser→node, out = node→browser).
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl SessionObs {
    fn set_result_once(&self, result: &'static str) {
        if let Ok(mut r) = self.session_result.lock() {
            if r.is_none() {
                *r = Some(result);
            }
        }
    }

    fn result(&self) -> Option<&'static str> {
        self.session_result
            .lock()
            .ok()
            .and_then(|r| *r)
    }
}

/// Bidirectional pump result: normal half-close (EOF/bye) vs connection/protocol error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PumpOutcome {
    Graceful,
    Failed,
}

/// Load the HTTP/3 server TLS identity: PEM (cert+key configured together) or dev self-signed (both empty).
///
/// Returns `(identity, self_signed)`. The dev self-signed path generates with the repo's existing `rcgen 0.13` and injects it via
/// `Identity::new`, so wtransport's `self-signed` feature stays off (avoiding pulling a second
/// rcgen 0.14); the certificate is in memory only and replaced on restart.
async fn load_identity(wt: &WebTransportCfg) -> Result<(Identity, bool), String> {
    let cert_path = wt.cert.trim();
    let key_path = wt.key.trim();
    match (cert_path.is_empty(), key_path.is_empty()) {
        (true, true) => {
            let ck = rcgen::generate_simple_self_signed(vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
            ])
            .map_err(|e| format!("dev self-signed cert: {e}"))?;
            let cert = Certificate::from_der(ck.cert.der().to_vec())
                .map_err(|e| format!("dev self-signed cert der: {e}"))?;
            let key = PrivateKey::from_der_pkcs8(ck.key_pair.serialize_der());
            Ok((Identity::new(CertificateChain::single(cert), key), true))
        }
        (false, false) => {
            let identity = Identity::load_pemfiles(cert_path, key_path)
                .await
                .map_err(|e| format!("load PEM cert/key failed: {e}"))?;
            // Empty certificate chain = configuration error (the TLS handshake must fail): WARN at startup and stay off.
            if identity.certificate_chain().as_slice().is_empty() {
                return Err(format!("cert {cert_path} contains no PEM certificate"));
            }
            Ok((identity, false))
        }
        _ => Err("[webtransport] cert/key must be configured together or both left empty (empty = dev self-signed temporary certificate)".into()),
    }
}

/// When `[webtransport] upstream` is empty, derive it from `[quic] bind`: wildcard addresses become loopback (the gateway is local).
fn resolve_upstream(wt: &WebTransportCfg, quic_bind: &str) -> Result<SocketAddr, String> {
    let explicit = wt.upstream.trim();
    let raw = if explicit.is_empty() {
        quic_bind.trim()
    } else {
        explicit
    };
    let mut addr: SocketAddr = raw
        .parse()
        .map_err(|e| format!("invalid upstream address {raw:?}: {e}"))?;
    if addr.ip().is_unspecified() {
        addr.set_ip(match addr.ip() {
            IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        });
    }
    Ok(addr)
}

/// **dev only**: skip upstream certificate verification (used only when the QUIC upstream is the dev self-signed cert and no trust anchor is configured;
/// a loopback bridge scenario — production must configure `[webtransport] upstream_ca` or `[quic] cert`).
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build the bridging upstream QUIC client TLS configuration.
///
/// Trust anchor priority: `[webtransport] upstream_ca` > `[quic] cert` > both empty = QUIC dev self-signed,
/// where the loopback bridge skips verification (WARN, dev only). ALPN/frame protocol match the QUIC client exactly.
fn build_upstream_tls(cfg: &Config) -> Result<quinn::ClientConfig, String> {
    let wt = &cfg.webtransport;
    let ca_path = if !wt.upstream_ca.trim().is_empty() {
        Some(wt.upstream_ca.trim().to_string())
    } else if !cfg.quic.cert.trim().is_empty() {
        Some(cfg.quic.cert.trim().to_string())
    } else {
        None
    };
    let mut tls = match ca_path {
        Some(path) => {
            let data = std::fs::read(&path).map_err(|e| format!("read upstream CA {path}: {e}"))?;
            let mut roots = rustls::RootCertStore::empty();
            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut BufReader::new(data.as_slice()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("parse upstream CA {path}: {e}"))?;
            if certs.is_empty() {
                return Err(format!("upstream CA {path} contains no PEM certificate"));
            }
            for c in certs {
                roots.add(c).map_err(|e| format!("add upstream CA cert: {e}"))?;
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        None => {
            tracing::warn!(
                "[webtransport] bridge upstream is QUIC dev self-signed and no \
                 [webtransport] upstream_ca / [quic] cert configured; disabling upstream \
                 certificate verification for the loopback bridge (DEV ONLY, never in production)"
            );
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
                .with_no_client_auth()
        }
    };
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| format!("upstream quic client crypto: {e}"))?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    // One bridged session maps to exactly one upstream relay stream (consistent with QUIC protocol v1's "one connection, one stream").
    transport.max_concurrent_bidi_streams(1u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    client.transport_config(Arc::new(transport));
    Ok(client)
}

// ---------------------------------------------------------------------
// Build / start / drain
// ---------------------------------------------------------------------

/// Build the WebTransport gateway from config; any configuration/certificate/port problem **only WARNs and returns None**.
///
/// Difference from `[quic]` (deliberate): QUIC is an explicitly enabled media-plane proxy, so a bad config fails startup; WT is an optional
/// browser add-on entry, so a bad config must not affect node readiness or the existing QUIC/WS paths (a task-card requirement).
pub async fn build(cfg: &Config, metrics: Arc<Metrics>) -> Option<Arc<WebTransportProxy>> {
    let wt = &cfg.webtransport;
    if !wt.enabled {
        return None;
    }
    // 1) Bridge precondition: the upstream QUIC listener must be enabled (otherwise there is nothing to bridge to, and it must not silently degrade into an "empty-shell entry").
    if !cfg.quic.enabled {
        tracing::warn!(
            bind = %wt.bind,
            "[webtransport] enabled=true but [quic] enabled=false: the gateway bridges to the \
             local QUIC relay and has no upstream; WebTransport stays disabled (node ready unaffected)"
        );
        return None;
    }
    // 2) Listen address
    let addr: SocketAddr = match wt.bind.trim().parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(
                bind = %wt.bind,
                error = %e,
                "[webtransport] invalid bind address; WebTransport stays disabled (node ready unaffected)"
            );
            return None;
        }
    };
    // 3) HTTP/3 server TLS identity (PEM or dev self-signed)
    let (identity, self_signed) = match load_identity(wt).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                bind = %wt.bind,
                cert = %wt.cert,
                error = %e,
                "[webtransport] TLS certificate configuration invalid; WebTransport stays disabled \
                 (node ready / QUIC / WS unaffected)"
            );
            return None;
        }
    };
    // 4) Upstream bridge address and trust anchor
    let upstream = match resolve_upstream(wt, &cfg.quic.bind) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(
                upstream = %wt.upstream,
                error = %e,
                "[webtransport] invalid bridge upstream; WebTransport stays disabled"
            );
            return None;
        }
    };
    let upstream_tls = match build_upstream_tls(cfg) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "[webtransport] upstream trust configuration invalid; WebTransport stays disabled \
                 (node ready unaffected)"
            );
            return None;
        }
    };
    // 5) HTTP/3 server endpoint (TLS 1.3 + ALPN h3 + idle timeout)
    let idle = Duration::from_secs(wt.effective_idle_timeout_secs());
    let keep_alive_ms = (wt.effective_idle_timeout_secs() * 1000 / 3).clamp(500, KEEP_ALIVE.as_millis() as u64);
    let server = match WtServerConfig::builder()
        .with_bind_address(addr)
        .with_identity(identity)
        .max_idle_timeout(Some(idle))
    {
        Ok(b) => b.keep_alive_interval(Some(Duration::from_millis(keep_alive_ms))).build(),
        Err(e) => {
            tracing::warn!(
                idle_timeout_secs = wt.effective_idle_timeout_secs(),
                error = %e,
                "[webtransport] invalid idle timeout; WebTransport stays disabled"
            );
            return None;
        }
    };
    let endpoint = match WtEndpoint::server(server) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                bind = %addr,
                error = %e,
                "[webtransport] HTTP/3 UDP bind failed (port in use or config error?); \
                 WebTransport stays disabled (node ready unaffected)"
            );
            return None;
        }
    };
    let local_addr = match endpoint.local_addr() {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, "[webtransport] local_addr failed; WebTransport stays disabled");
            return None;
        }
    };
    // 6) Upstream QUIC client endpoint (shared by all bridged sessions; each session gets one connection/one bi stream)
    let mut upstream_client =
        match quinn::Endpoint::client("0.0.0.0:0".parse().expect("valid bind addr")) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "[webtransport] upstream QUIC client endpoint failed; disabled"
                );
                return None;
            }
        };
    upstream_client.set_default_client_config(upstream_tls);
    if self_signed {
        tracing::warn!(
            addr = %local_addr,
            "[webtransport] dev self-signed certificate in use (in-memory only; browsers need \
             serverCertificateHashes, do NOT use in production)"
        );
    }
    tracing::info!(
        addr = %local_addr,
        upstream = %upstream,
        path = %wt.effective_path(),
        self_signed,
        idle_timeout_s = wt.effective_idle_timeout_secs(),
        token_ttl_s = wt.effective_token_ttl_secs(),
        "webtransport: HTTP/3 gateway ready (PL-13 13.3, bridging to local QUIC relay)"
    );
    let handshake = Duration::from_secs(cfg.quic.effective_handshake_timeout_secs());
    Some(Arc::new(WebTransportProxy {
        endpoint,
        local_addr,
        upstream,
        upstream_client,
        handshake_timeout: handshake,
        registration_window: Duration::from_secs(wt.effective_token_ttl_secs()),
        metrics,
        sessions: Mutex::new(HashMap::new()),
        next_session_id: AtomicU64::new(1),
        self_signed,
        drain_timeout: Duration::from_secs(
            cfg.quic
                .effective_handshake_timeout_secs()
                .clamp(DRAIN_TIMEOUT_MIN_SECS, DRAIN_TIMEOUT_MAX_SECS),
        ),
        draining: AtomicBool::new(false),
        drain_notify: Notify::new(),
        drain_started: AtomicBool::new(false),
    }))
}

/// Start the accept loop + the `AppState.draining` watcher task (called before the node is ready).
pub fn spawn(proxy: Arc<WebTransportProxy>, state: Arc<AppState>) {
    // draining watcher task (reusing the AppState.draining flag shared by WS/admin/SIGTERM)
    {
        let proxy = proxy.clone();
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                if state.draining.load(Ordering::Relaxed) {
                    tracing::info!(
                        addr = %proxy.local_addr,
                        "webtransport: AppState.draining observed, draining HTTP/3 gateway"
                    );
                    proxy.drain().await;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
    }
    tokio::spawn(async move {
        tracing::info!(addr = %proxy.local_addr, "webtransport: HTTP/3 listener started");
        loop {
            if proxy.draining.load(Ordering::Acquire) {
                break;
            }
            tokio::select! {
                incoming = proxy.endpoint.accept().into_future() => {
                    // Drain was just set but accept already returned: refuse outright, never establish a new session.
                    if proxy.draining.load(Ordering::Acquire) {
                        incoming.refuse();
                        continue;
                    }
                    let proxy = proxy.clone();
                    let state = state.clone();
                    tokio::spawn(async move {
                        let result = run_session(proxy.clone(), state, incoming).await;
                        proxy.metrics
                            .webtransport_sessions_total
                            .with_label_values(&[result])
                            .inc();
                    });
                }
                _ = proxy.drain_notify.notified() => { break; }
            }
        }
        tracing::info!("webtransport: HTTP/3 listener stopped");
    });
}

impl WebTransportProxy {
    /// Listen address (for E2E/troubleshooting).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Bridge upstream address (for E2E/troubleshooting).
    pub fn upstream_addr(&self) -> SocketAddr {
        self.upstream
    }

    /// Current active bridged session count.
    pub fn active_sessions(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Dev self-signed (for logs/assertions only).
    pub fn is_self_signed(&self) -> bool {
        self.self_signed
    }

    /// Whether draining has begun (for E2E/troubleshooting).
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Drain (idempotent): stop accepting new CONNECTs → bounded wait for existing sessions to be wrapped up by the QUIC drain bye →
    /// close the endpoint (stop serving and send CONNECTION_CLOSE(0,"shutdown") to leftover connections; the UDP socket is released
    /// when the process exits, same lifecycle as the QUIC endpoint).
    pub async fn drain(&self) {
        if self.drain_started.swap(true, Ordering::AcqRel) {
            return;
        }
        self.draining.store(true, Ordering::Release);
        self.drain_notify.notify_one();
        tracing::info!(
            sessions = self.active_sessions(),
            timeout_ms = self.drain_timeout.as_millis() as u64,
            "webtransport: draining: stop accepting, waiting for registered sessions to finish"
        );
        tokio::time::sleep(DRAIN_SETTLE_GRACE).await;
        let deadline = tokio::time::Instant::now() + self.drain_timeout;
        while self.active_sessions() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.endpoint.close(VarInt::from_u32(WT_CLOSE_NORMAL), b"shutdown");
        let leftover = self.active_sessions();
        let _ = tokio::time::timeout(Duration::from_millis(500), self.endpoint.wait_idle()).await;
        self.sessions.lock().map(|mut s| s.clear()).ok();
        self.metrics.webtransport_sessions_active.set(0);
        tracing::info!(
            leftover_sessions = leftover,
            "webtransport: drain complete (HTTP/3 endpoint closed; UDP socket is released when the \
             endpoint object is dropped at process exit, same lifecycle as the QUIC endpoint)"
        );
    }

    fn next_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Decrement the gauge and remove the record when a session ends (idempotent).
    fn finish_session(&self, id: u64) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(&id);
            self.metrics
                .webtransport_sessions_active
                .set(sessions.len() as i64);
        }
    }
}

// ---------------------------------------------------------------------
// Session: HTTP/3 CONNECT → upstream QUIC connection → bidirectional frame bridging
// ---------------------------------------------------------------------

/// Handle one inbound CONNECT; the return value is the label for `lattice_webtransport_sessions_total{result}`.
async fn run_session(
    proxy: Arc<WebTransportProxy>,
    state: Arc<AppState>,
    incoming: IncomingSession,
) -> &'static str {
    // 1) HTTP/3 handshake + WebTransport CONNECT request (bounded wait, preventing slow attacks from consuming resources)
    let request = match tokio::time::timeout(
        proxy.handshake_timeout,
        incoming.into_future(),
    )
    .await
    {
        Ok(Ok(req)) => req,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "webtransport: HTTP/3 session handshake failed");
            return "handshake";
        }
        Err(_) => {
            tracing::debug!("webtransport: HTTP/3 session handshake timed out");
            return "handshake";
        }
    };
    // 2) Path allowlist: only `/media` (optionally with a query, e.g. ?stream_id=...)
    let request_path = request.path().to_string();
    let path_ok = {
        let path = request_path.split('?').next().unwrap_or("");
        path == state.cfg.webtransport.effective_path()
    };
    if !path_ok {
        tracing::debug!(
            path = %request_path,
            expected = %state.cfg.webtransport.effective_path(),
            "[webtransport] CONNECT path not allowed (404)"
        );
        // The 404 response itself is fast, but wtransport's `finish()` waits for the peer ACK; a misbehaving client may
        // exit/drop packets right after receiving the 404, leaving this task stuck in finish and delaying the session result metric. Add a short timeout.
        let _ = tokio::time::timeout(Duration::from_millis(500), request.not_found()).await;
        return "path";
    }
    let remote = request.remote_address();
    let conn = match tokio::time::timeout(proxy.handshake_timeout, request.accept()).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "webtransport: CONNECT accept failed");
            return "handshake";
        }
        Err(_) => return "handshake",
    };
    // 3) Session registration (active-session gauge / drain waiting / E2E observation)
    let id = proxy.next_session_id();
    if let Ok(mut sessions) = proxy.sessions.lock() {
        sessions.insert(
            id,
            Arc::new(SessionInfo { id, remote, started: Instant::now() }),
        );
        proxy
            .metrics
            .webtransport_sessions_active
            .set(sessions.len() as i64);
    }
    tracing::debug!(session = id, remote = %remote, "webtransport: session accepted, bridging to QUIC relay");
    let result = serve_session(proxy.clone(), conn, id).await;
    proxy.finish_session(id);
    tracing::debug!(session = id, result, "webtransport: session closed");
    result
}

/// Session body: accept the browser's bidirectional stream → connect the upstream QUIC → bridge frames both ways → wrap up (close both ends to propagate).
async fn serve_session(
    proxy: Arc<WebTransportProxy>,
    wt_conn: WtConnection,
    _session_id: u64,
) -> &'static str {
    // 4) The first bidirectional stream opened by the browser (QUIC proxy protocol v1 TLV runs over the WebTransport stream)
    let (wt_send, wt_recv) = match tokio::time::timeout(proxy.handshake_timeout, wt_conn.accept_bi())
        .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "webtransport: accept_bi failed");
            wt_conn.close(VarInt::from_u32(WT_CLOSE_ERROR), b"no stream");
            return "bad_request";
        }
        Err(_) => {
            wt_conn.close(VarInt::from_u32(WT_CLOSE_ERROR), b"no stream");
            return "bad_request";
        }
    };
    // 5) Upstream QUIC: connect to the local QUIC listener + open one bi stream (fully consistent with the QUIC client protocol)
    let connecting = match proxy
        .upstream_client
        .connect(proxy.upstream, "localhost")
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, upstream = %proxy.upstream, "webtransport: upstream connect failed");
            wt_conn.close(VarInt::from_u32(WT_CLOSE_ERROR), b"bridge unavailable");
            return "error";
        }
    };
    let quic_conn = match tokio::time::timeout(proxy.handshake_timeout, connecting).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, upstream = %proxy.upstream, "webtransport: upstream QUIC handshake failed");
            wt_conn.close(VarInt::from_u32(WT_CLOSE_ERROR), b"bridge unavailable");
            return "error";
        }
        Err(_) => {
            wt_conn.close(VarInt::from_u32(WT_CLOSE_ERROR), b"bridge timeout");
            return "error";
        }
    };
    let (quic_send, quic_recv) = match tokio::time::timeout(proxy.handshake_timeout, quic_conn.open_bi()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "webtransport: upstream open_bi failed");
            quic_conn.close(quinn::VarInt::from_u32(WT_CLOSE_ERROR), b"bridge open failed");
            wt_conn.close(VarInt::from_u32(WT_CLOSE_ERROR), b"bridge open failed");
            return "error";
        }
        Err(_) => {
            quic_conn.close(quinn::VarInt::from_u32(WT_CLOSE_ERROR), b"bridge open timeout");
            wt_conn.close(VarInt::from_u32(WT_CLOSE_ERROR), b"bridge open timeout");
            return "error";
        }
    };

    let obs = Arc::new(SessionObs::default());
    let metrics = proxy.metrics.clone();
    // Registration-window watchdog: the upstream registered / auth error must be observed within the window after CONNECT,
    // otherwise wrap up on our own (preventing a browser from establishing a session without registering and holding a half-open session and upstream connection for long).
    let cancel = Arc::new(Notify::new());
    {
        let obs = obs.clone();
        let cancel = cancel.clone();
        let window = proxy.registration_window;
        let wt_conn = wt_conn.clone();
        let quic_conn = quic_conn.clone();
        tokio::spawn(async move {
            tokio::time::sleep(window).await;
            if !obs.registered.load(Ordering::Acquire) && obs.result().is_none() {
                tracing::debug!("webtransport: session registration window elapsed before upstream register");
                wt_conn.close(VarInt::from_u32(WT_CLOSE_ERROR), b"register timeout");
                quic_conn.close(quinn::VarInt::from_u32(WT_CLOSE_ERROR), b"register timeout");
                cancel.notify_one();
            }
        });
    }

    // 6) Bidirectional frame bridging: WT→QUIC and QUIC→WT run as independent tasks (awaiting writes = natural backpressure)
    let wt_to_quic = tokio::spawn(pump_wt_to_quic(wt_recv, quic_send, obs.clone(), metrics.clone()));
    let quic_to_wt = tokio::spawn(pump_quic_to_wt(quic_recv, wt_send, obs.clone(), metrics.clone()));

    let graceful = supervise_pumps(&proxy, &cancel, wt_to_quic, quic_to_wt).await;

    // 7) Close propagation: use 0 (no error) for a normal finish and 1 for an error; both ends are closed, so either direction disconnecting is noticed by the peer.
    let wt_code = if graceful {
        VarInt::from_u32(WT_CLOSE_NORMAL)
    } else {
        VarInt::from_u32(WT_CLOSE_ERROR)
    };
    let quic_code = if graceful {
        quinn::VarInt::from_u32(WT_CLOSE_NORMAL)
    } else {
        quinn::VarInt::from_u32(WT_CLOSE_ERROR)
    };
    // Give finish a brief window to send data (quinn finish only marks locally, unlike wtransport finish which waits for an ACK).
    tokio::time::sleep(Duration::from_millis(100)).await;
    wt_conn.close(wt_code, if graceful { b"done" } else { b"bridge error" });
    quic_conn.close(quic_code, if graceful { b"done" } else { b"bridge error" });
    // Wait for the connection to really close (bounded; avoiding task leaks/registry residue)
    let _ = tokio::time::timeout(
        Duration::from_millis(500),
        async {
            tokio::join!(wt_conn.closed(), quic_conn.closed());
        },
    )
    .await;

    if let Some(result) = obs.result() {
        return result;
    }
    if obs.registered.load(Ordering::Acquire) {
        "ok"
    } else {
        "closed"
    }
}

/// Supervise the two pumps: one side half-closing normally → bounded wait for the other to finish; either side failing/draining/registration timeout → wrap up.
///
/// Semantics match QUIC relay half-close: A sending bye first ends only the A→B direction and B can keep sending data;
/// therefore the other side must not be aborted immediately after EOF (otherwise the peer sees a truncation instead of a normal EOF).
async fn supervise_pumps(
    proxy: &Arc<WebTransportProxy>,
    cancel: &Arc<Notify>,
    mut wt_to_quic: tokio::task::JoinHandle<PumpOutcome>,
    mut quic_to_wt: tokio::task::JoinHandle<PumpOutcome>,
) -> bool {
    let drain_watch = {
        let proxy = proxy.clone();
        async move {
            loop {
                if proxy.draining.load(Ordering::Acquire) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    tokio::pin!(drain_watch);
    tokio::select! {
        w = &mut wt_to_quic => {
            match w {
                Ok(PumpOutcome::Graceful) => {
                    match tokio::time::timeout(HALF_CLOSE_TIMEOUT, &mut quic_to_wt).await {
                        Ok(Ok(PumpOutcome::Graceful)) => true,
                        _ => { quic_to_wt.abort(); false }
                    }
                }
                _ => { quic_to_wt.abort(); false }
            }
        }
        q = &mut quic_to_wt => {
            match q {
                Ok(PumpOutcome::Graceful) => {
                    match tokio::time::timeout(HALF_CLOSE_TIMEOUT, &mut wt_to_quic).await {
                        Ok(Ok(PumpOutcome::Graceful)) => true,
                        _ => { wt_to_quic.abort(); false }
                    }
                }
                _ => { wt_to_quic.abort(); false }
            }
        }
        _ = cancel.notified() => {
            wt_to_quic.abort();
            quic_to_wt.abort();
            false
        }
        _ = &mut drain_watch => {
            // Node drain: the upstream QUIC drain passes bye through and FINs first, so give the pump a short wrap-up window;
            // on timeout abort directly and let the caller close both connections (bounded exit). Drain finishes with the normal close code.
            tokio::time::sleep(Duration::from_millis(300)).await;
            wt_to_quic.abort();
            quic_to_wt.abort();
            true
        }
    }
}

// ---------------------------------------------------------------------
// Frame bridging (forward each frame verbatim; only observe control frames for metrics, never interpret media payloads)
// ---------------------------------------------------------------------

/// Observe a CONTROL frame: only classifies metrics/result labels, without changing bytes.
fn observe_control(obs: &SessionObs, metrics: &Metrics, payload: &[u8], from_upstream: bool) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return;
    };
    let t = v.get("t").and_then(|t| t.as_str()).unwrap_or_default();
    if !from_upstream {
        // Browser side: register/bye/data are all validated by the upstream QUIC; here we only keep the extension point.
        let _ = t;
        return;
    }
    match t {
        "registered" => {
            if !obs.registered.swap(true, Ordering::AcqRel)
                && !obs.auth_ok_counted.swap(true, Ordering::AcqRel)
            {
                metrics
                    .webtransport_auth_total
                    .with_label_values(&["ok"])
                    .inc();
            }
        }
        "error" => {
            let code = v.get("code").and_then(|c| c.as_str()).unwrap_or_default();
            let reason = v.get("reason").and_then(|r| r.as_str()).unwrap_or_default();
            let (session_result, auth_label) = classify_error(code, reason);
            if let Some(label) = auth_label {
                metrics
                    .webtransport_auth_total
                    .with_label_values(&[label])
                    .inc();
            }
            obs.set_result_once(session_result);
        }
        _ => {}
    }
}

/// Upstream error frame → (session result label, optional auth result label).
///
/// Error-code semantics match the registration flow of `transport::quic` exactly (the bridge layer only transports, never re-judges);
/// this only classifies low-cardinality metrics; reason values are in `quic::AuthFailure::reason`.
fn classify_error(code: &str, reason: &str) -> (&'static str, Option<&'static str>) {
    match code {
        "AUTH_FAIL" => (
            "auth",
            Some(if reason == "expired" { "expired" } else { "bad_jwt" }),
        ),
        "FORBIDDEN" => (
            "auth",
            Some(match reason {
                "device_mismatch" => "device_mismatch",
                _ => "not_participant",
            }),
        ),
        "BAD_TOKEN" => ("token", None),
        "STREAM_QUOTA" => ("quota", None),
        "BAD_REQUEST" | "NO_SUCH_STREAM" | "PEER_TIMEOUT" => ("bad_request", None),
        _ => ("bad_request", None),
    }
}

/// Browser → upstream QUIC: read TLV frame by frame → write verbatim to the upstream QUIC (DATA counts as in bytes).
async fn pump_wt_to_quic(
    mut wt_recv: WtRecv,
    mut quic_send: QuicSend,
    obs: Arc<SessionObs>,
    metrics: Arc<Metrics>,
) -> PumpOutcome {
    let mut header = [0u8; FRAME_HEADER];
    loop {
        match wt_recv.read_exact(&mut header).await {
            Ok(()) => {}
            // FIN falls exactly on a frame boundary = normal half-close (the browser finishes the send direction after bye)
            Err(wtransport::error::StreamReadExactError::FinishedEarly(0)) => break,
            Err(_) => return PumpOutcome::Failed,
        }
        let (ty, len) = match decode_header(&header) {
            Ok(v) => v,
            Err(_) => return PumpOutcome::Failed,
        };
        let mut payload = vec![0u8; len];
        if len > 0 && wt_recv.read_exact(&mut payload).await.is_err() {
            return PumpOutcome::Failed;
        }
        if ty == FRAME_DATA {
            obs.bytes_in.fetch_add(len as u64, Ordering::Relaxed);
            metrics
                .webtransport_bytes_total
                .with_label_values(&["in"])
                .inc_by(len as u64);
        } else if ty == FRAME_CONTROL {
            observe_control(&obs, &metrics, &payload, false);
        }
        if quic_send.write_all(&header).await.is_err() {
            return PumpOutcome::Failed;
        }
        if len > 0 && quic_send.write_all(&payload).await.is_err() {
            return PumpOutcome::Failed;
        }
    }
    let _ = quic_send.finish();
    PumpOutcome::Graceful
}

/// Upstream QUIC → browser: read TLV frame by frame → write verbatim to the WT bidirectional stream (DATA counts as out bytes).
async fn pump_quic_to_wt(
    mut quic_recv: QuicRecv,
    mut wt_send: WtSend,
    obs: Arc<SessionObs>,
    metrics: Arc<Metrics>,
) -> PumpOutcome {
    loop {
        match read_frame(&mut quic_recv).await {
            Ok(None) => break, // normal upstream FIN
            Ok(Some((ty, payload))) => {
                if ty == FRAME_DATA {
                    obs.bytes_out.fetch_add(payload.len() as u64, Ordering::Relaxed);
                    metrics
                        .webtransport_bytes_total
                        .with_label_values(&["out"])
                        .inc_by(payload.len() as u64);
                } else if ty == FRAME_CONTROL {
                    observe_control(&obs, &metrics, &payload, true);
                }
                let header = encode_header(ty, payload.len());
                if wt_send.write_all(&header).await.is_err() {
                    return PumpOutcome::Failed;
                }
                if !payload.is_empty() && wt_send.write_all(&payload).await.is_err() {
                    return PumpOutcome::Failed;
                }
            }
            Err(_) => return PumpOutcome::Failed,
        }
    }
    let _ = wt_send.finish().await;
    PumpOutcome::Graceful
}

// ---------------------------------------------------------------------
// Unit tests (no PG/Redis/network peer; the dev self-signed endpoint binds 127.0.0.1:0)
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn enabled_cfg() -> Config {
        let mut cfg = Config::default();
        cfg.quic.enabled = true;
        cfg.quic.bind = "127.0.0.1:0".into();
        cfg.webtransport.enabled = true;
        cfg.webtransport.bind = "127.0.0.1:0".into();
        cfg
    }

    #[test]
    fn upstream_derivation_wildcard_to_loopback() {
        let mut wt = WebTransportCfg::default();
        let a = resolve_upstream(&wt, "0.0.0.0:4433").unwrap();
        assert_eq!(a, "127.0.0.1:4433".parse::<SocketAddr>().unwrap());
        // An explicit upstream takes priority
        wt.upstream = "127.0.0.1:18445".into();
        let b = resolve_upstream(&wt, "0.0.0.0:4433").unwrap();
        assert_eq!(b, "127.0.0.1:18445".parse::<SocketAddr>().unwrap());
        // An invalid address errors out (build WARNs + shuts down)
        wt.upstream = "not-an-addr".into();
        assert!(resolve_upstream(&wt, "0.0.0.0:4433").is_err());
        // [::] wildcard → IPv6 loopback
        wt.upstream = String::new();
        let c = resolve_upstream(&wt, "[::]:4433").unwrap();
        assert_eq!(c.ip(), IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn error_mapping_matches_quic_reason_labels() {
        // Label spellings must exactly match lattice_quic_auth_total's result (E2E asserts by name)
        assert_eq!(classify_error("AUTH_FAIL", "expired"), ("auth", Some("expired")));
        assert_eq!(classify_error("AUTH_FAIL", "bad_jwt"), ("auth", Some("bad_jwt")));
        assert_eq!(
            classify_error("FORBIDDEN", "device_mismatch"),
            ("auth", Some("device_mismatch"))
        );
        assert_eq!(
            classify_error("FORBIDDEN", "not_participant"),
            ("auth", Some("not_participant"))
        );
        assert_eq!(classify_error("BAD_TOKEN", "token"), ("token", None));
        assert_eq!(classify_error("STREAM_QUOTA", ""), ("quota", None));
        assert_eq!(classify_error("BAD_REQUEST", ""), ("bad_request", None));
        assert_eq!(classify_error("NO_SUCH_STREAM", ""), ("bad_request", None));
    }

    #[test]
    fn frame_protocol_is_shared_with_quic() {
        // The bridge layer reuses quic's frame header definitions: there is only one definition of type/length caps
        let h = encode_header(FRAME_DATA, 64 * 1024);
        assert_eq!(decode_header(&h), Ok((FRAME_DATA, 64 * 1024)));
        assert!(decode_header(&encode_header(FRAME_DATA, 64 * 1024 + 1)).is_err());
        assert!(decode_header(&encode_header(FRAME_CONTROL, 4097)).is_err());
        assert!(decode_header(&encode_header(9, 1)).is_err());
    }

    #[test]
    fn session_obs_result_is_first_wins_and_registered_flag() {
        let obs = SessionObs::default();
        assert!(obs.result().is_none());
        obs.set_result_once("auth");
        obs.set_result_once("closed");
        assert_eq!(obs.result(), Some("auth"));
        assert!(!obs.registered.load(Ordering::Acquire));
        obs.registered.store(true, Ordering::Release);
        assert!(obs.registered.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn build_disabled_is_zero_side_effect() {
        // Off by default: returns None, creates no endpoint and reads no certificates (pure config decision).
        let cfg = Config::default();
        assert!(build(&cfg, Metrics::new()).await.is_none());
    }

    #[tokio::test]
    async fn build_without_quic_upstream_warns_and_returns_none() {
        // WT enabled but QUIC disabled: nowhere to bridge → WARN + shut down (node readiness unaffected)
        let mut cfg = Config::default();
        cfg.webtransport.enabled = true;
        cfg.webtransport.bind = "127.0.0.1:0".into();
        assert!(build(&cfg, Metrics::new()).await.is_none());
    }

    #[tokio::test]
    async fn build_bad_cert_returns_none_without_panicking() {
        // Certificate configuration error (cert without key / file missing): WARN only, returns None.
        let mut cfg = enabled_cfg();
        cfg.webtransport.cert = "/nonexistent/wt.crt".into();
        assert!(build(&cfg, Metrics::new()).await.is_none());
        let mut cfg = enabled_cfg();
        cfg.webtransport.cert = "/nonexistent/wt.crt".into();
        cfg.webtransport.key = "/nonexistent/wt.key".into();
        assert!(build(&cfg, Metrics::new()).await.is_none());
    }

    #[tokio::test]
    async fn build_bad_bind_returns_none() {
        let mut cfg = enabled_cfg();
        cfg.webtransport.bind = "not-an-addr".into();
        assert!(build(&cfg, Metrics::new()).await.is_none());
    }

    #[tokio::test]
    async fn build_dev_self_signed_binds_ephemeral_endpoint() {
        // dev self-signed + [quic] enabled: an HTTP/3 endpoint should be built (127.0.0.1:0) and marked self_signed.
        let proxy = build(&enabled_cfg(), Metrics::new())
            .await
            .expect("dev self-signed gateway should build");
        assert!(proxy.is_self_signed());
        assert_ne!(proxy.local_addr().port(), 0);
        assert_eq!(proxy.active_sessions(), 0);
        assert!(!proxy.is_draining());
        // The upstream address is derived from [quic] bind (127.0.0.1:0 stays as-is; build only, no connection)
        assert_eq!(proxy.upstream_addr().port(), 0);
    }

    #[tokio::test]
    async fn drain_closes_endpoint_and_is_idempotent() {
        let proxy = build(&enabled_cfg(), Metrics::new())
            .await
            .expect("gateway");
        timeout_drain(&proxy).await;
        assert!(proxy.is_draining());
        // Idempotent: a second drain neither panics nor logs twice
        proxy.drain().await;
        assert_eq!(proxy.active_sessions(), 0);
    }

    async fn timeout_drain(proxy: &Arc<WebTransportProxy>) {
        tokio::time::timeout(Duration::from_secs(5), proxy.drain())
            .await
            .expect("drain should finish within bounded window");
    }
}
