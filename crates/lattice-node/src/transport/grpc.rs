//! Internal gRPC (⑤ §10, mTLS; design §17.13).
//!
//! Services: `lattice.internal.v1.NodeInternal`
//! - `Route`: **last-resort fallback** — deliver an envelope directly between nodes when both NATS and Redis are unavailable;
//! - `FetchChunks`: pull missing chunks between nodes (streamed), sourced from PG `chunks_index` + MinIO;
//! - `Heartbeat`: node liveness/information exchange;
//! - `WatermarkSync`: seq watermark reconciliation (with PG `conv_seq_watermark` as the authority).
//!
//! Transport: `[grpc]` config; production must set `tls_cert/tls_key/tls_client_ca` (mTLS);
//! configuring only cert/key is one-way TLS, and configuring none of them is **plaintext and dev-only** (warned at startup).
//! The listen address should only be exposed on the internal network/behind the LB, never publicly.
//!
//! Explicit boundaries: mTLS currently validates only "the client certificate is trusted"; it does **not map the certificate CN to node_id**
//! (node identity is still not bound to the certificate); the `PluginSidecar` service only generates a client stub, and the node does not host the sidecar
//! (the plugin runtime owns the sidecar).

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use prost::Message as _;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};
use tonic::{Request, Response, Status};

use crate::config::GrpcCfg;
use crate::state::AppState;
use crate::store::RouteEnvelope;

pub mod internal {
    tonic::include_proto!("lattice.internal.v1");
}

use internal::node_internal_server::{NodeInternal, NodeInternalServer};
use internal::{
    ChunkStream, FetchReq, NodeInfo, RouteAck, RouteReq, WatermarkAck, WatermarkReq,
};
/// Timeout for one internal call (⑤ §10 table); observed by the caller (gRPC client); the server only handles semantics.
pub fn timeout_ms(method: &str) -> u64 {
    match method {
        "Route" => 2_000,
        "FetchChunks" => 10_000,
        "Heartbeat" => 1_000,
        "WatermarkSync" => 3_000,
        "PluginSidecar.Process" => 500,
        _ => 1_000,
    }
}

/// Failure behavior (⑤ §10): only `Route` needs "retry twice → move to pending + P2 alert".
pub fn retry_budget(method: &str) -> u32 {
    match method {
        "Route" => 2,
        _ => 0,
    }
}

/// Read one DER TLV: returns (tag, value_start, value_end, next).
fn der_tlv(buf: &[u8], pos: usize) -> Option<(u8, usize, usize, usize)> {
    let tag = *buf.get(pos)?;
    let first = *buf.get(pos + 1)?;
    let (len, start) = if first & 0x80 == 0 {
        (first as usize, pos + 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for k in 0..n {
            len = (len << 8) | (*buf.get(pos + 2 + k)? as usize);
        }
        (len, pos + 2 + n)
    };
    let end = start.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some((tag, start, end, end))
}

/// Find the string value of the CN (OID 2.5.4.3) inside a Subject DER.
fn cn_in_subject(subject: &[u8]) -> Option<String> {
    const OID: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x03];
    let pos = subject.windows(OID.len()).position(|w| w == OID)?;
    let mut i = pos + OID.len();
    let tag = *subject.get(i)?;
    if !matches!(tag, 0x0c | 0x13 | 0x16) {
        return None;
    }
    i += 1;
    let (_, start, end, _) = der_tlv(subject, i - 1)?;
    if end > subject.len() || end <= start {
        return None;
    }
    String::from_utf8(subject[start..end].to_vec()).ok()
}

/// Extract the **Subject** CommonName (2.5.4.3) from a DER-encoded X.509 certificate.
///
/// No x509 parsing dependency: walk the fields Certificate SEQUENCE → tbsCertificate SEQUENCE down to
/// subject (the 4th SEQUENCE: signature/issuer/validity/subject), then read the CN. Take only the Subject
/// rather than the first CN in the whole document — otherwise the issuer (internal CA) CN would match first and misidentify the client identity as the CA.
pub fn certificate_common_name(der: &[u8]) -> Option<String> {
    let (tag, cert_start, cert_end, _) = der_tlv(der, 0)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, tbs_start, tbs_end, _) = der_tlv(der, cert_start)?;
    if tag != 0x30 || tbs_end > cert_end {
        return None;
    }
    let mut pos = tbs_start;
    let mut seqs = 0;
    while pos < tbs_end {
        let (tag, start, end, next) = der_tlv(der, pos)?;
        if tag == 0x30 {
            seqs += 1;
            // 1=signatureAlgorithm, 2=issuer, 3=validity, 4=subject
            if seqs == 4 {
                return cn_in_subject(&der[start..end]);
            }
        }
        pos = next;
    }
    None
}

/// Get the CN of the mTLS client certificate (only available on server-side TLS connections; returns None without a certificate).
fn peer_common_name(req: &Request<RouteReq>) -> Option<String> {
    let certs = req.peer_certs()?;
    let leaf = certs.first()?;
    certificate_common_name(leaf.as_ref())
}

/// Reject one `Route` (accepted=false + reason; no gRPC error code is used because the caller treats it as "not delivered").
fn reject(reason: impl Into<String>) -> Response<RouteAck> {
    Response::new(RouteAck {
        accepted: false,
        reason: reason.into(),
    })
}

struct GrpcSvc {
    state: Arc<AppState>,
}

#[tonic::async_trait]
impl NodeInternal for GrpcSvc {
    async fn route(&self, req: Request<RouteReq>) -> Result<Response<RouteAck>, Status> {
        let st = &self.state;
                // Node identity binding: the mTLS client certificate CN must be a known node_id in the Redis node registry.
                // Validated only when require_known_node_cn is explicitly enabled (default false, for compatibility with old deployments).
        let mut verified_cn: Option<String> = None;
        if st.cfg.grpc.require_known_node_cn {
            let Some(cn) = peer_common_name(&req) else {
                return Ok(reject("missing_client_cn"));
            };
            let known = match st.redis.nodes().await {
                Ok(nodes) => nodes.iter().any(|(id, _)| id == &cn),
                Err(e) => {
                    tracing::warn!(error = %e, "grpc route: node registry unavailable for CN check");
                    return Ok(reject("node_registry_unavailable"));
                }
            };
            if !known {
                tracing::warn!(peer_cn = %cn, "grpc route rejected: client cert CN is not a known node_id");
                return Ok(reject("unknown_node_cn"));
            }
            verified_cn = Some(cn);
        }
        let req = req.into_inner();
                // Field-level binding: RouteReq.caller_node must match the certificate CN (or must be present, per config).
        if let Some(cn) = verified_cn.as_deref() {
            if req.caller_node.is_empty() {
                if st.cfg.grpc.require_caller_node {
                    return Ok(reject("missing_caller_node"));
                }
            } else if req.caller_node != cn {
                tracing::warn!(
                    peer_cn = %cn,
                    caller_node = %req.caller_node,
                    "grpc route rejected: caller_node does not match client cert CN"
                );
                return Ok(reject("peer_cn_mismatch"));
            }
            tracing::debug!(peer_cn = %cn, "grpc route: client cert CN verified against node registry");
        }
        if !req.target_node.is_empty() && req.target_node != st.node_id {
            return Ok(reject("wrong_node"));
        }
        let env = match lattice_core::Envelope::decode(req.envelope.as_slice()) {
            Ok(env) => env,
            Err(e) => return Ok(reject(format!("bad_envelope:{e}"))),
        };
        let route = env.route();
        let out_cmd = if req.frame_cmd == 0
            || req.frame_cmd == lattice_core::WsCommand::Envelope.to_u8() as u32
        {
            lattice_core::WsCommand::Envelope
        } else {
            match lattice_core::WsCommand::from_u8(req.frame_cmd as u8) {
                Some(lattice_core::WsCommand::StreamSig) => lattice_core::WsCommand::StreamSig,
                _ => return Ok(reject("unsupported_frame_cmd")),
            }
        };
        let frame = lattice_core::Frame::new(
            out_cmd,
            bytes::Bytes::from(env.encode_body()),
        );
                // Targets of generic frames (currently only stream-sig) live in RouteReq: stream-sig's locator fields are in the JSON
                // payload, not in Envelope.route; Envelope still uses route inside the body.
        let envelope_mode = req.frame_cmd == 0
            || req.frame_cmd == lattice_core::WsCommand::Envelope.to_u8() as u32;
        let (to_user, to_devices) = if envelope_mode {
            if route.to_user.is_empty() {
                return Ok(reject("missing_to_user"));
            }
            (route.to_user.clone(), route.to_devices.clone())
        } else {
            if req.target_user.is_empty() {
                return Ok(reject("missing_to_user"));
            }
            (req.target_user.clone(), req.target_devices.clone())
        };
                // E20-G4: the consumer dedups by `(env_id, user, device)`. The gRPC fallback and NATS Stream replay may each
                // deliver once; the first arrival claims the slot and a duplicate arrival is treated as "already delivered" (accepted) so the sender stops retrying.
        let env_id = env.id.clone();
        let delivered = if to_devices.is_empty() {
            st.hub.send_to_user(&to_user, frame)
        } else {
            let mut count = 0usize;
            for d in &to_devices {
                if !crate::routing::online::claim_delivery(&env_id, &to_user, d) {
                    tracing::debug!(
                        env_id = %env_id,
                        user = %crate::observe::Metrics::user_hash(&to_user),
                        device = %d,
                        "duplicate gRPC route delivery suppressed (E20-G4 env_id dedupe)"
                    );
                                        count += 1; // already delivered: still reply accepted to avoid a retry storm at the sender
                    continue;
                }
                if st.hub.send_to_device(&to_user, d, frame.clone()) {
                    count += 1;
                } else {
                    crate::routing::online::release_delivery(&env_id, &to_user, d);
                }
            }
            count
        };
        st.metrics
            .msgs_total
            .with_label_values(&["grpc_route", &env.r#type, if delivered > 0 { "routed" } else { "dropped" }])
            .inc();
        Ok(Response::new(RouteAck {
            accepted: delivered > 0,
            reason: if delivered > 0 {
                String::new()
            } else {
                "offline_or_backpressure".into()
            },
        }))
    }

    type FetchChunksStream =
        Pin<Box<dyn Stream<Item = Result<ChunkStream, Status>> + Send + 'static>>;

    async fn fetch_chunks(
        &self,
        req: Request<FetchReq>,
    ) -> Result<Response<Self::FetchChunksStream>, Status> {
        let req = req.into_inner();
        let rows = crate::store::pg::chunks_of(&self.state.db, &req.msg_id)
            .await
            .map_err(|e| Status::internal(format!("chunks query failed: {e}")))?;
        let wanted = if req.missing.is_empty() {
            None
        } else {
            Some(req.missing.clone())
        };
        let bucket = self.state.s3.cfg().bucket_large.clone();
        let mut out = Vec::new();
        for row in rows {
            if wanted
                .as_ref()
                .map(|w| !w.contains(&(row.idx as u32)))
                .unwrap_or(false)
            {
                continue;
            }
            let data = match row.storage_key.as_deref() {
                Some(key) => self
                    .state
                    .s3
                    .get_bytes(&bucket, key)
                    .await
                    .map_err(|e| Status::unavailable(format!("chunk object fetch failed: {e}")))?,
                None => Vec::new(),
            };
            out.push(Ok(ChunkStream {
                idx: row.idx as u32,
                data,
                checksum: row.checksum.unwrap_or_default(),
            }));
        }
        Ok(Response::new(Box::pin(tokio_stream::iter(out))))
    }

    async fn heartbeat(&self, req: Request<NodeInfo>) -> Result<Response<NodeInfo>, Status> {
        let st = &self.state;
        let _ = req.into_inner();
        Ok(Response::new(NodeInfo {
            node_id: st.node_id.clone(),
            version: crate::state::VERSION.to_string(),
            connections: st.hub.all().len() as u32,
            protocol_version: st.cfg.protocol_range().1 as u32,
            seq_watermark: std::collections::HashMap::new(),
        }))
    }

    async fn watermark_sync(
        &self,
        req: Request<WatermarkReq>,
    ) -> Result<Response<WatermarkAck>, Status> {
        let req = req.into_inner();
        let mut authoritative = std::collections::HashMap::new();
        for (conv, seq) in req.seq_watermark {
            let pg = crate::store::pg::get_seq_watermark(&self.state.db, &conv)
                .await
                .map_err(|e| Status::internal(format!("watermark query failed: {e}")))?;
            authoritative.insert(conv, seq.max(pg.max(0) as u64));
        }
        Ok(Response::new(WatermarkAck {
            ok: true,
            authoritative,
        }))
    }
}

/// Start the internal gRPC (with `[grpc] enabled=false` it only logs one line).
pub fn spawn(st: Arc<AppState>) {
    if !st.cfg.grpc.enabled {
        tracing::info!("internal grpc disabled by config (grpc.enabled=false)");
        return;
    }
    tokio::spawn(async move {
        if let Err(e) = serve(st.clone()).await {
            tracing::error!(error = %e, "internal grpc server failed");
        }
    });
}

async fn serve(st: Arc<AppState>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg = st.cfg.grpc.clone();
    let addr: std::net::SocketAddr = cfg.bind.parse()?;
    let svc = NodeInternalServer::new(GrpcSvc { state: st.clone() });
    let mut builder = Server::builder();
    if !cfg.tls_cert.is_empty() && !cfg.tls_key.is_empty() {
        let cert = tokio::fs::read(&cfg.tls_cert).await?;
        let key = tokio::fs::read(&cfg.tls_key).await?;
        let mut tls = ServerTlsConfig::new().identity(Identity::from_pem(cert, key));
        let mtls = !cfg.tls_client_ca.is_empty();
        if mtls {
            let ca = tokio::fs::read(&cfg.tls_client_ca).await?;
            tls = tls.client_ca_root(Certificate::from_pem(ca));
        }
        builder = builder.tls_config(tls)?;
        tracing::info!(addr = %addr, mtls, "internal grpc listening (tls)");
    } else {
        tracing::warn!(addr = %addr, "internal grpc listening WITHOUT TLS (dev only)");
    }
    let drain = st.clone();
    builder
        .add_service(svc)
        .serve_with_shutdown(addr, async move {
            while !drain.draining.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        })
        .await?;
    Ok(())
}

/// Only frames carrying an `Envelope` can use the `Route` fallback: other frames (ack/receipt/chunk signaling etc.)
/// have no dedicated gRPC method and are left to pending/reconnect logic; they must not pretend to have been delivered.
pub fn fallback_frame_supported(frame_cmd: u8) -> bool {
    matches!(
        lattice_core::WsCommand::from_u8(frame_cmd),
        Some(lattice_core::WsCommand::Envelope) | Some(lattice_core::WsCommand::StreamSig)
    )
}

/// Get the peer's advertised gRPC address from the node heartbeat (`lattice:node:{id}` JSON).
///
/// Returns `None` when the heartbeat has no `grpc_addr` (not advertised/old node) — better no fallback
/// than guessing an address and delivering the message to the wrong node. `nodes` comes from `Redis::nodes()`: `(node_id, json)`.
/// The static table `[grpc] peers` is the second source when Redis is unavailable: `auto` tries heartbeats first then the static table,
/// `static` uses only the static table (no Redis lookup).
pub fn parse_peer_grpc_addr(
    target: &str,
    nodes: &[(String, String)],
    cfg: &GrpcCfg,
) -> Option<String> {
    if target.is_empty() {
        return None;
    }
    let static_only = cfg.discovery.eq_ignore_ascii_case("static");
    if !static_only {
        for (node_id, raw) in nodes {
            if node_id != target {
                continue;
            }
            let value: serde_json::Value = serde_json::from_str(raw).ok()?;
                        // The key and the node_id inside the content must match: prevents a dirty key/migration residue from delivering to the wrong node.
            if let Some(inner_id) = value.get("node_id").and_then(|v| v.as_str()) {
                if inner_id != target {
                    continue;
                }
            }
            if let Some(announced) = value
                .get("grpc_addr")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                return Some(announced.to_string());
            }
        }
    }
    cfg.peers
        .get(target)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// `Route` fallback: after a bus publish fails, deliver directly to the target node over gRPC.
///
/// Routing basis: the target node's Redis heartbeat `grpc_addr` (see `Hub::heartbeat`). Timeout 2s,
/// 2 retries (⑤ §10); both success and failure emit the `lattice_grpc_route_fallback_total` metric,
/// used by PL-13's "bus failure is the norm" alert.
pub async fn route_fallback(state: &AppState, target_node: &str, env: &RouteEnvelope) -> bool {
    let cfg = &state.cfg.grpc;
    if !cfg.enabled || !cfg.fallback || target_node.is_empty() {
        return false;
    }
    if !fallback_frame_supported(env.frame_cmd) {
        tracing::debug!(
            target_node,
            frame_cmd = env.frame_cmd,
            "route fallback skipped: frame type has no gRPC Route representation"
        );
        return false;
    }
    let Some(body) = lattice_core::envelope::base64_decode(&env.body_b64) else {
        tracing::warn!(target_node, "route fallback skipped: invalid body_b64");
        state
            .metrics
            .grpc_fallback_total
            .with_label_values(&["Route", "error"])
            .inc();
        return false;
    };
        // Static peer mode does not query Redis; auto mode waits at most 500ms (a half-dead Redis must not hold up the fallback).
    let nodes = if cfg.discovery.eq_ignore_ascii_case("static") {
        Vec::new()
    } else {
        match tokio::time::timeout(Duration::from_millis(500), state.redis.nodes()).await {
            Ok(Ok(nodes)) => nodes,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, target_node, "route fallback: node registry unavailable, trying static peers");
                Vec::new()
            }
            Err(_) => {
                tracing::warn!(target_node, "route fallback: node registry lookup timed out, trying static peers");
                Vec::new()
            }
        }
    };
    let Some(addr) = parse_peer_grpc_addr(target_node, &nodes, cfg) else {
        tracing::warn!(
            target_node,
            "route fallback skipped: no peer address (set [grpc] advertise or [grpc] peers)"
        );
        state
            .metrics
            .grpc_fallback_total
            .with_label_values(&["Route", "error"])
            .inc();
        return false;
    };
    let req = RouteReq {
        target_node: target_node.to_string(),
        envelope: body,
        conn_id: String::new(),
        priority: 0,
        caller_node: state.node_id.clone(),
        frame_cmd: if env.frame_cmd == lattice_core::WsCommand::Envelope.to_u8() {
            0
        } else {
            env.frame_cmd as u32
        },
        target_user: env.target_user.clone(),
        target_devices: vec![env.target_device.clone()],
    };
    let attempts = retry_budget("Route") + 1;
    let mut last_error = String::new();
    for attempt in 0..attempts {
        match call_route(cfg, &addr, req.clone()).await {
            Ok(ack) if ack.accepted => {
                state
                    .metrics
                    .grpc_fallback_total
                    .with_label_values(&["Route", "ok"])
                    .inc();
                tracing::warn!(
                    target_node,
                    addr,
                    attempt,
                    "bus publish failed; delivered via gRPC Route fallback"
                );
                return true;
            }
            Ok(ack) => {
                last_error = format!("rejected:{}", ack.reason);
                                // On an explicit server rejection (wrong_node/closed/backpressure) retrying is pointless; leave it to pending.
                break;
            }
            Err(e) => {
                last_error = e;
                if attempt + 1 < attempts {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
    state
        .metrics
        .grpc_fallback_total
        .with_label_values(&["Route", "error"])
        .inc();
    tracing::error!(
        target_node,
        addr,
        error = %last_error,
        "gRPC Route fallback failed; message left to pending/retry"
    );
    false
}

/// Establish an outbound gRPC connection (plaintext or mTLS; the client certificate defaults to reusing the server certificate pair).
async fn connect_route_client(
    cfg: &GrpcCfg,
    addr: &str,
) -> Result<internal::node_internal_client::NodeInternalClient<Channel>, String> {
    let use_tls = !cfg.tls_cert.is_empty() && !cfg.tls_key.is_empty();
    let scheme = if use_tls { "https" } else { "http" };
    let mut endpoint = Endpoint::from_shared(format!("{scheme}://{addr}"))
        .map_err(|e| format!("bad grpc endpoint {addr}: {e}"))?
        .connect_timeout(Duration::from_millis(timeout_ms("Route")))
        .timeout(Duration::from_millis(timeout_ms("Route")));
    if use_tls {
        let ca_path = if cfg.tls_client_ca.is_empty() {
            &cfg.tls_cert
        } else {
            &cfg.tls_client_ca
        };
        let ca = tokio::fs::read(ca_path)
            .await
            .map_err(|e| format!("read grpc CA {ca_path}: {e}"))?;
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .domain_name(cfg.tls_domain.clone());
        let (cert_path, key_path) = if cfg.client_cert.is_empty() || cfg.client_key.is_empty() {
            (&cfg.tls_cert, &cfg.tls_key)
        } else {
            (&cfg.client_cert, &cfg.client_key)
        };
        let cert = tokio::fs::read(cert_path)
            .await
            .map_err(|e| format!("read grpc client cert {cert_path}: {e}"))?;
        let key = tokio::fs::read(key_path)
            .await
            .map_err(|e| format!("read grpc client key {key_path}: {e}"))?;
        tls = tls.identity(Identity::from_pem(cert, key));
        endpoint = endpoint
            .tls_config(tls)
            .map_err(|e| format!("grpc tls config: {e}"))?;
    }
    let channel = endpoint
        .connect()
        .await
        .map_err(|e| format!("grpc connect {addr}: {e}"))?;
    Ok(internal::node_internal_client::NodeInternalClient::new(
        channel,
    ))
}

/// Call `Route` once (connection timeout/request timeout are handled by the endpoint, both 2s).
async fn call_route(cfg: &GrpcCfg, addr: &str, req: RouteReq) -> Result<RouteAck, String> {
    let mut client = connect_route_client(cfg, addr).await?;
    let ack = client
        .route(Request::new(req))
        .await
        .map_err(|e| format!("grpc Route failed: {e}"))?;
    Ok(ack.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_supports_envelope_and_stream_sig() {
        assert!(fallback_frame_supported(
            lattice_core::WsCommand::Envelope.to_u8()
        ));
                // The stream-sig body is also Envelope-encoded, so carrying target_user/devices in RouteReq is enough for the fallback
        assert!(fallback_frame_supported(
            lattice_core::WsCommand::StreamSig.to_u8()
        ));
        for cmd in [
            lattice_core::WsCommand::Ack,
            lattice_core::WsCommand::Receipt,
            lattice_core::WsCommand::Ping,
        ] {
            assert!(!fallback_frame_supported(cmd.to_u8()), "{cmd:?}");
        }
    }

    #[test]
    fn peer_addr_discovery_requires_announcement() {
        let nodes = vec![
            (
                "node-a".to_string(),
                r#"{"node_id":"node-a","grpc_addr":"10.0.0.1:9090"}"#.to_string(),
            ),
            (
                "node-b".to_string(),
                r#"{"node_id":"node-b","grpc_addr":""}"#.to_string(),
            ),
            (
                "node-c".to_string(),
                r#"{"node_id":"other","grpc_addr":"10.0.0.3:9090"}"#.to_string(),
            ),
        ];
        let mut cfg = GrpcCfg::default();
        assert_eq!(
            parse_peer_grpc_addr("node-a", &nodes, &cfg).as_deref(),
            Some("10.0.0.1:9090")
        );
        assert!(parse_peer_grpc_addr("node-b", &nodes, &cfg).is_none());
        assert!(parse_peer_grpc_addr("node-c", &nodes, &cfg).is_none());
        assert!(parse_peer_grpc_addr("", &nodes, &cfg).is_none());
        assert!(parse_peer_grpc_addr("missing", &nodes, &cfg).is_none());

                // Static table: peers can still be discovered when the Redis registry is missing/unavailable; static mode does not read heartbeats
        cfg.discovery = "static".into();
        cfg.peers.insert("node-x".into(), "10.9.9.9:9090".into());
        assert_eq!(
            parse_peer_grpc_addr("node-x", &nodes, &cfg).as_deref(),
            Some("10.9.9.9:9090")
        );
        assert!(parse_peer_grpc_addr("node-a", &nodes, &cfg).is_none());
                // auto mode: heartbeats first, falling back to the static table when missing
        cfg.discovery = "auto".into();
        assert_eq!(
            parse_peer_grpc_addr("node-a", &nodes, &cfg).as_deref(),
            Some("10.0.0.1:9090")
        );
        assert_eq!(
            parse_peer_grpc_addr("node-x", &nodes, &cfg).as_deref(),
            Some("10.9.9.9:9090")
        );
    }

    #[test]
    fn extracts_client_cert_common_name() {
                // Self-signed CA leaf certificate (DER) generated by scripts/gen-grpc-certs.py --client-cn node-a
        const CERT_B64: &str = "MIIDFzCCAf+gAwIBAgIUMDW1Dt1Bl218aoY/Q3BNV0aL2I8wDQYJKoZIhvcNAQELBQAwIjEgMB4GA1UEAwwXTGF0dGljZSBJbnRlcm5hbCBEZXYgQ0EwHhcNMjYxMTIxMDkyNzAwWhcNMjYxMjIxMDkzMjAwWjARMQ8wDQYDVQQDDAZub2RlLWEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCRv+d3iqZd1x3Tg11L7j5dnxGF+XhYFGnHG+0blc2vuc/Zc7ulNMUuv7ly6eM2lwGh82fggQW8XzhWd8TuDia/2SR3pk6bpk5RSW8zjemY5fk+4CYsLfshvRWJ0kaIfE424aGCavwWDzID7yg+UpTtbJm9CC/Btf5BQI0CoQAPtpk4jsp4mOAIZnBlHwmpVXbNvuuXXV/cpihZyx2gTMx8DfMzj4Av4bMuFTfMON3Yqhag5rYw0Z1GcIgj023ucaJ9bx2UIvH9cWiof8xcYTLpJep/2Kgwqh9HBj5pVcPWZIENLnyMLTmwPnzIOqGuFqVZbIZ8nsoBxV/likAxqB+rAgMBAAGjVjBUMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFE/ZesXZxibPx2FjNfwvFYtBF2QiMA0GCSqGSIb3DQEBCwUAA4IBAQAejw8tCL/PAiNUrFAN12Xuu//X4MM+FfAzar1pM+6u+fLFG0R2rNyN3t+4gvW0Zte6UwWgCgu+9LXEDeFfSABmRmFT6xgI30cyWLJIjCamjAvDlshgfedmv47BJepQowUUltNkjS1DmVWaX7ZAdXQThzFwxJ15DsAS1OYAAsb0lOfCFRPXBFixtlk3iJW7s6i4twEoGWXu7xAtzQtyW9vqNC5GSqu645zZNvgRbK+ljJjT7jaPAqlgn2k9RpfyLIxHIhaYv/H3jQR72YjaLqPqpQq2QXJ6Kbrp9eul/fRXELGUlUgFMbRYXVzsYLG0fr0OMJWb9ZojDwA9DLzVp2v0";
        let der = lattice_core::envelope::base64_decode(CERT_B64).expect("fixture base64");
        assert_eq!(certificate_common_name(&der).as_deref(), Some("node-a"));
                // Empty/garbage input neither panics nor returns a fabricated CN
        assert!(certificate_common_name(&[]).is_none());
        assert!(certificate_common_name(b"not-a-cert").is_none());
    }

    #[test]
    fn timeouts_match_contract() {
        assert_eq!(timeout_ms("Route"), 2000);
        assert_eq!(timeout_ms("FetchChunks"), 10000);
        assert_eq!(timeout_ms("Heartbeat"), 1000);
        assert_eq!(timeout_ms("WatermarkSync"), 3000);
        assert_eq!(timeout_ms("PluginSidecar.Process"), 500);
        assert_eq!(retry_budget("Route"), 2);
        assert_eq!(retry_budget("Heartbeat"), 0);
    }

    #[test]
    fn proto_stubs_compile_and_roundtrip() {
        let info = NodeInfo {
            node_id: "node-a".into(),
            version: "0.1.0".into(),
            connections: 3,
            protocol_version: 1,
            seq_watermark: std::collections::HashMap::new(),
        };
        let bytes = info.encode_to_vec();
        let decoded = NodeInfo::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded.node_id, "node-a");
        assert_eq!(decoded.connections, 3);
    }
}
