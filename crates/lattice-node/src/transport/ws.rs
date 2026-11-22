//! WebSocket primary channel (② §3.1; see ⑤ §9 / §17.10 for the frame protocol and command set).
//!
//! Lifecycle: `TLS → Upgrade → first frame hello → register conn:* → reply hello → redelivery → frame loop → disconnect cleanup`.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;

use lattice_core::protocol::{MAX_CONNS_PER_IP, MAX_CONNS_PER_USER, SERVER_DEAD_SECS};
use lattice_core::{Frame, FrameCodec, WsCommand};

use crate::auth::rbac;
use crate::auth::rbac::AuthUser;
use crate::error::LatticeError;
use crate::state::{conn_channel, AppState, Caps, Conn};

#[derive(Debug, Deserialize)]
struct ProtoRange {
    #[serde(default = "min_default")]
    min: u8,
    #[serde(default = "min_default")]
    max: u8,
}

fn min_default() -> u8 {
    lattice_core::protocol::MIN_SUPPORTED_PROTOCOL
}

#[derive(Debug, Deserialize)]
struct HelloBody {
    access_jwt: Option<String>,
    device_fp: Option<String>,
    #[serde(default = "default_range")]
    protocol: ProtoRange,
    profile: Option<String>,
    #[serde(default)]
    caps: Caps,
    chunk_limit: Option<u64>,
}

fn default_range() -> ProtoRange {
    ProtoRange { min: min_default(), max: lattice_core::protocol::PROTOCOL_VERSION }
}

#[derive(Debug, Serialize)]
struct HelloAck {
    node_id: String,
    server_ts: String,
    protocol: ProtoRangeOut,
    quota: QuotaOut,
    chunk: ChunkOut,
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProtoRangeOut {
    min: u8,
    max: u8,
}

#[derive(Debug, Serialize)]
struct QuotaOut {
    msg_per_s: u32,
    bytes_per_s: u64,
    topics: u32,
    chunk_threshold_max: u64,
}

#[derive(Debug, Serialize)]
struct ChunkOut {
    inline: usize,
    threshold_max: u64,
    part: usize,
}

/// `GET /v1/ws` (upgrade on the same port, passed through by the LB).
pub async fn handler(
    ws: WebSocketUpgrade,
    State(st): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
        // Draining: reject new connections (fallback once the LB has drained; the client should reconnect to another node).
    if st.draining.load(Ordering::Relaxed) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "code": "INTERNAL",
                "message": "node draining",
                "details": { "reason": "draining" }
            })),
        )
            .into_response();
    }
    ws.max_message_size(lattice_core::protocol::FRAME_MAX_BYTES + 64)
        .on_upgrade(move |socket| session(socket, st, addr, headers))
}

async fn session(socket: WebSocket, st: Arc<AppState>, addr: SocketAddr, headers: HeaderMap) {
    let remote_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string());

    let (mut sink, mut stream) = socket.split();

        // Connection caps: 100 per IP (§17.13)
    if st.hub.ip_conn_count(&remote_ip) >= MAX_CONNS_PER_IP {
        let _ = sink
            .send(Message::Binary(
                Frame::error(lattice_core::ErrorCode::Quota, "too many connections from ip", None)
                    .encode()
                    .to_vec(),
            ))
            .await;
        return;
    }

        // 1) The first frame must be hello (⑤ §9.2)
    let first = tokio::time::timeout(Duration::from_secs(10), stream.next()).await;
    let hello_frame = match first {
        Ok(Some(Ok(Message::Binary(bin)))) => match FrameCodec::read(&mut bin.as_ref()).await {
            Ok(Some(f)) if f.cmd == WsCommand::Hello => f,
            Ok(Some(_)) => {
                close_with_error(&mut sink, lattice_core::ErrorCode::Protocol, "first frame must be hello", None).await;
                return;
            }
            _ => {
                close_with_error(&mut sink, lattice_core::ErrorCode::Protocol, "malformed frame", None).await;
                return;
            }
        },
        _ => {
                        // No frame / not binary: do not send an error frame, just close (handshake incomplete)
            return;
        }
    };

    let hello: HelloBody = match serde_json::from_slice(&hello_frame.body) {
        Ok(h) => h,
        Err(_) => {
            close_with_error(&mut sink, lattice_core::ErrorCode::Protocol, "bad hello", None).await;
            return;
        }
    };

        // The client's self-reported profile is only used for log troubleshooting (⑤ §9.2 defines no semantics; it does not affect auth/quota)
    if let Some(profile) = hello.profile.as_deref() {
        tracing::debug!(profile, remote_ip = %remote_ip, "ws hello profile");
    }

        // 2) Version negotiation: the server accepts [max(min_supported, N-1), N] (§17.12)
    let (srv_min, srv_max) = st.cfg.protocol_range();
    if hello.protocol.max < srv_min || hello.protocol.min > srv_max {
        close_with_error(
            &mut sink,
            lattice_core::ErrorCode::Protocol,
            "protocol version not supported",
            None,
        )
        .await;
        return;
    }

        // 3) Authentication: hello.access_jwt or the Authorization header (§17.11)
    let auth: AuthUser = match authenticate(&st, &headers, hello.access_jwt.as_deref()) {
        Ok(a) => a,
        Err(e) => {
            close_with_error(&mut sink, e.code, &e.message, None).await;
            return;
        }
    };

        // 4) Device fingerprint (§17.11: mismatch → force re-login)
    let device = match crate::store::pg::device_by_id(&st.db, &auth.device_id).await {
        Ok(Some(d)) => d,
        _ => {
            close_with_error(&mut sink, lattice_core::ErrorCode::AuthFail, "device unknown", None).await;
            return;
        }
    };
    let reported = hello.device_fp.clone().unwrap_or_default();
    if let Err(e) = crate::auth::device::verify_fingerprint(
        device.fingerprint.as_deref(),
        &reported,
        st.cfg.auth.fingerprint_required,
    ) {
                // ② §6 "Authentication": fingerprint mismatch → force re-login (token revoked) + ⑤ §8.6 audit trail.
                // Triggered only for a real fp_mismatch (legacy devices with no fingerprint in the DB are still allowed → no 401).
        let reason = e
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|v| v.as_str());
        if e.code == lattice_core::ErrorCode::AuthFail && reason == Some("fp_mismatch") {
            crate::auth::device::revoke_on_fingerprint_mismatch(
                &st,
                &auth.user_id,
                &device.id,
                device.fingerprint.as_deref(),
                &reported,
                Some(&remote_ip),
            )
            .await;
        }
        close_with_error(&mut sink, e.code, &e.message, None).await;
        return;
    }

        // 5) 10-connection cap per user (§17.13)
    if st.hub.user_conn_count(&auth.user_id) >= MAX_CONNS_PER_USER {
        close_with_error(&mut sink, lattice_core::ErrorCode::Quota, "too many connections", None).await;
        return;
    }

        // 6) Register the connection + online index
    let (tx, mut rx) = conn_channel();
    let conn = Conn {
        id: 0,
        user: auth.user_id.clone(),
        device: device.id.clone(),
        tx,
        caps: hello.caps.clone(),
        connected_at: Instant::now(),
        remote_ip: remote_ip.clone(),
        protocol: hello.protocol.max,
        node_id: st.node_id.clone(),
    };
    let conn_id = st.hub.register(conn);
    st.register_online(&auth.user_id, &device.id).await.ok();
    st.metrics
        .protocol_version
        .with_label_values(&[&hello.protocol.max.to_string()])
        .inc();
    let _ = st.bus.publish_online(&auth.user_id, &device.id).await;

        // 7) hello ack (authoritative chunk threshold, overriding the client's local config; §18 D1)
    let ack = HelloAck {
        node_id: st.node_id.clone(),
        server_ts: chrono::Utc::now().to_rfc3339(),
        protocol: ProtoRangeOut { min: srv_min, max: srv_max },
        quota: QuotaOut {
            msg_per_s: st.cfg.policy.msg_per_s,
            bytes_per_s: st.cfg.policy.bytes_per_s,
            topics: st.cfg.policy.topics_per_user,
            chunk_threshold_max: authoritative_chunk_limit(&st, hello.chunk_limit),
        },
        chunk: ChunkOut {
            inline: st.cfg.policy.inline_threshold,
            threshold_max: authoritative_chunk_limit(&st, hello.chunk_limit),
            part: st.cfg.policy.chunk_part,
        },
        mode: match st.mode() {
            lattice_core::Mode::ZeroKnowledge => "zero-knowledge".into(),
            lattice_core::Mode::Inspectable => "inspectable".into(),
        },
        session: Some(conn_id.to_string()),
    };
    if let Ok(f) = Frame::json(WsCommand::Hello, &ack) {
        let _ = sink.send(Message::Binary(f.encode().to_vec())).await;
    }

        // 8) Downlink writer task
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if sink.send(Message::Binary(frame.encode().to_vec())).await.is_err() {
                break;
            }
        }
    });

        // 9) Online redelivery (done by the node holding lock:deliver, see crossnode)
    {
        let st2 = st.clone();
        let user = auth.user_id.clone();
        let dev = device.id.clone();
        tokio::spawn(async move {
            let task = format!("deliver:{user}:{dev}");
            if st2.redis.acquire_lock(&task, &st2.node_id, 30_000).await.unwrap_or(false) {
                let _ = crate::routing::pending::drain_device(&st2, &user, &dev).await;
                let _ = crate::routing::pending::drain_topics(&st2, &user, &dev).await;
                let _ = st2.redis.release_lock(&task, &st2.node_id).await;
            }
        });
    }

        // 10) Read loop (90s without any frame → disconnect, §17.8)
    let idle = Duration::from_secs(SERVER_DEAD_SECS);
    let mut last_seen = Instant::now();
    loop {
        let next = tokio::time::timeout(idle, stream.next()).await;
        match next {
            Err(_) => {
                                // 90s without any frame: disconnect (no guarantee a frame can still be written; just exit the loop)
                tracing::info!(conn_id, "idle timeout, closing");
                break;
            }
            Ok(None) => break,
            Ok(Some(Err(_))) => break,
            Ok(Some(Ok(Message::Close(_)))) => break,
            Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => {
                last_seen = Instant::now();
                continue;
            }
            Ok(Some(Ok(Message::Binary(bin)))) => {
                last_seen = Instant::now();
                let frame = match FrameCodec::read(&mut bin.as_ref()).await {
                    Ok(Some(f)) => f,
                    Ok(None) => break,
                    Err(e) => {
                                                // Unknown cmd → error and ignore that frame, without closing the connection (⑤ §9.6)
                        st.hub.send_to_device(
                            &auth.user_id,
                            &device.id,
                            Frame::error(e.code, &e.message, None),
                        );
                        continue;
                    }
                };
                if let Err(e) = dispatch(&st, &auth, &device.id, frame).await {
                    st.hub.send_to_device(
                        &auth.user_id,
                        &device.id,
                        Frame::error(e.code, &e.message, None),
                    );
                    if matches!(e.code, lattice_core::ErrorCode::AuthFail) {
                        break;
                    }
                }
            }
            Ok(Some(Ok(_))) => continue,
        }
    }

    let _ = last_seen;
        // 11) Cleanup: delete only this device's routing key + the local connection (② §3.1)
    st.hub.unregister(conn_id);
    st.unregister_online(&auth.user_id, &device.id).await;
    crate::store::pg::touch_device(&st.db, &device.id).await.ok();
    writer.abort();
    tracing::info!(conn_id, user = %crate::observe::Metrics::user_hash(&auth.user_id), "ws closed");
}

/// Placeholder: the timeout path no longer writes frames (the connection is about to close); the signature is kept for documentation.

async fn close_with_error(
    sink: &mut futures::stream::SplitSink<WebSocket, Message>,
    code: lattice_core::ErrorCode,
    message: &str,
    envelope_id: Option<&str>,
) {
    let frame = Frame::error(code, message, envelope_id);
    let _ = sink.send(Message::Binary(frame.encode().to_vec())).await;
    let _ = sink
        .send(Message::Close(Some(CloseFrame {
            code: 1002,
            reason: message.to_string().into(),
        })))
        .await;
}

/// Server-authoritative chunk threshold = min(deployment config, client-reported cap) (§18 D1).
fn authoritative_chunk_limit(st: &Arc<AppState>, client_limit: Option<u64>) -> u64 {
    let cfg = st.cfg.policy.chunk_threshold_max;
    match client_limit {
        Some(v) if v > 0 => cfg.min(v),
        _ => cfg,
    }
}

fn authenticate(
    st: &Arc<AppState>,
    headers: &HeaderMap,
    from_hello: Option<&str>,
) -> Result<AuthUser, LatticeError> {
    if let Some(token) = from_hello {
        let claims = st.verify_jwt(token)?;
        let role = rbac::resolve_role(st, &claims.sub, &claims.role);
        return Ok(AuthUser { user_id: claims.sub, device_id: claims.dev, role });
    }
    rbac::authenticate(st, headers)
}

/// Frame dispatch (the 13 commands of ⑤ §9.3).
async fn dispatch(
    st: &Arc<AppState>,
    auth: &AuthUser,
    device: &str,
    frame: Frame,
) -> Result<(), LatticeError> {
    match frame.cmd {
        WsCommand::Ping => {
            st.hub
                .send_to_device(&auth.user_id, device, Frame::new(WsCommand::Pong, bytes::Bytes::new()));
        }
        WsCommand::Pong => {}
        WsCommand::Keepalive => {
                        // Renew + seq watermark reconciliation (§17.8 / IN8)
            st.redis
                .touch_conn(&auth.user_id, device, &st.node_id, st.cfg.policy.conn_ttl)
                .await
                .ok();
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&frame.body) {
                if let Some(wm) = v.get("seq_watermark").and_then(|x| x.as_object()) {
                    for (conv, seq) in wm {
                        if let Some(seq) = seq.as_i64() {
                                                        // The client declares "I have received seq for this conversation": clear the pending entries
                                                        // already acknowledged for the same conversation, shrinking the at-least-once duplicate window (⑤ §9.4).
                            let removed = crate::routing::pending::ack_through(
                                st.as_ref(),
                                &auth.user_id,
                                device,
                                conv,
                                seq,
                            )
                            .await;
                            if removed > 0 {
                                tracing::debug!(conv, seq, removed, "keepalive watermark pruned pending");
                            }
                        }
                    }
                }
            }
        }
        WsCommand::Envelope => {
            let env = lattice_core::Envelope::decode_body(&frame.body)?;
            let out = crate::pipeline::ingest(st, &auth.user_id, device, env).await?;
                        // Receipt to the sender (`sent → routed|persisted`, §17.3)
            let receipt = Frame::json(
                WsCommand::Receipt,
                &json!({ "id": out.id, "state": out.state.as_str(), "conv_id": out.conv_id, "seq": out.seq }),
            )?;
            st.hub.send_to_device(&auth.user_id, device, receipt);
        }
        WsCommand::Chunk => {
            let env = lattice_core::Envelope::decode_body(&frame.body)?;
            let out = crate::pipeline::ingest(st, &auth.user_id, device, env).await?;
            let ack = Frame::json(
                WsCommand::Ack,
                &json!({ "id": out.id, "state": "delivered" }),
            )?;
            st.hub.send_to_device(&auth.user_id, device, ack);
            st.metrics
                .chunk_retrans_total
                .with_label_values(&["chunk_in"])
                .inc();
        }
        WsCommand::Ack => {
                        // Device-level ACK: dequeue + update delivery_log + send a receipt back to the sender
            let v: serde_json::Value = serde_json::from_slice(&frame.body)
                .map_err(|e| LatticeError::protocol(format!("bad ack body: {e}")))?;
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_string();
            if id.is_empty() {
                return Err(LatticeError::protocol("ack.id required"));
            }
            crate::routing::pending::ack_remove(st, &auth.user_id, device, &id).await;
            crate::store::pg::mark_delivery_state(&st.db, &id, device, "acked").await?;
                        // E19 / PL-11 11.7: delivery-state progress (acked) is written to the audit stream as an observation event (non-blocking, not part of delivery decisions).
            crate::routing::audit::spawn_delivery_event(
                st.as_ref(),
                &id,
                &auth.user_id,
                device,
                "acked",
            );
            if let Some(msg) = crate::store::pg::message_by_id(&st.db, &id).await? {
                let receipt = Frame::json(
                    WsCommand::Receipt,
                    &json!({ "id": id, "state": "acked", "conv_id": msg.conv_id }),
                )?;
                st.hub.send_to_device(&msg.sender, device, receipt.clone());
                st.hub.send_to_user(&msg.sender, receipt);
            }
        }
        WsCommand::RequestChunks => {
                        // ⑤ §9.3: body `{id, missing_index[]}` (bidirectional) — the receiver reports missing chunks and the server returns the authoritative missing list.
                        // E18: ① validate conversation membership (consistent with GET /v1/chunks, preventing unauthorized reads of chunk metadata);
                        //      ② the response semantics changed to the contract field `missing_index` (computed by the server from chunks_index),
                        //         so clients no longer need to diff `items` themselves.
            let v: serde_json::Value = serde_json::from_slice(&frame.body)
                .map_err(|e| LatticeError::protocol(format!("bad request-chunks body: {e}")))?;
            let raw_id = v.get("id").and_then(|x| x.as_str()).unwrap_or_default();
            if raw_id.is_empty() {
                return Err(LatticeError::protocol("request-chunks.id required"));
            }
                        // Allow receivers to start with a chunk id (`<id>.c<i>`): normalize it to the logical message id.
            let msg_id = lattice_core::ids::parse_chunk_id(raw_id)
                .map(|(m, _)| m.to_string())
                .unwrap_or_else(|| raw_id.to_string());
            let rows = crate::store::pg::chunks_of(&st.db, &msg_id).await?;
            if rows.is_empty() {
                return Err(LatticeError::not_found("message not found"));
            }
                        // Conversation ownership: prefer chunks_index.conv_id (written since migration 0011); for old rows fall back to the messages row;
                        // if neither exists → do not leak existence, treat as not_found.
            let conv_id = match rows.iter().find_map(|r| r.conv_id.clone()) {
                Some(conv) => conv,
                None => match crate::store::pg::message_by_id(&st.db, &msg_id).await? {
                    Some(m) => m.conv_id,
                    None => return Err(LatticeError::not_found("message not found")),
                },
            };
            crate::pipeline::wal_degrade::ensure_member(st, &conv_id, &auth.user_id).await?;
            let total = rows.first().map(|r| r.total as u32).unwrap_or(0);
            let got: Vec<u32> = rows.iter().map(|r| r.idx as u32).collect();
            let missing_index = crate::pipeline::chunk::missing_indexes(total, &got);
            st.metrics
                .chunk_retrans_total
                .with_label_values(&["request"])
                .inc();
            st.hub.send_to_device(
                &auth.user_id,
                device,
                Frame::json(
                    WsCommand::RequestChunks,
                    &json!({
                        "id": msg_id,
                        "total": total,
                        "received": got.len(),
                        "missing_index": missing_index,
                    }),
                )?,
            );
        }
        WsCommand::StreamSig => {
                        // Media negotiation signaling: forward to the target user/device; offers maintain the WS tunnel session (⑤ §9.3)
            crate::routing::media::on_signal(st.as_ref(), auth, device, &frame).await?;
        }
        WsCommand::StreamData => {
                        // WS binary tunnel (§17.9-3 fallback): only two devices inside a conversation may exchange raw bytes
            crate::routing::media::on_data(st.as_ref(), auth, device, &frame).await?;
        }
        WsCommand::Byef => {
            tracing::info!(user = %crate::observe::Metrics::user_hash(&auth.user_id), "client byef");
        }
        WsCommand::Receipt => {}
        WsCommand::Error => {}
        WsCommand::Hello => {
                        // Duplicate hello → PROTOCOL (first-frame constraint)
            return Err(LatticeError::protocol("duplicate hello"));
        }
    }
    Ok(())
}

/// Graceful shutdown: send `byef reason=shutdown` to all connections and stop registering (② §7.2).
pub async fn drain_all(st: &Arc<AppState>) {
    st.draining.store(true, Ordering::Relaxed);
    for c in st.hub.all() {
        let _ = c.tx.try_send(crate::state::shutdown_frame("shutdown"));
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_range_check() {
                // Server [1,1]
        let (min, max) = (1u8, 1u8);
        let ok = |cmin: u8, cmax: u8| !(cmax < min || cmin > max);
        assert!(ok(1, 1));
                assert!(!ok(2, 3), "should reject when the client only supports higher versions");
                assert!(!ok(0, 0), "version 0 is not supported");
    }

    #[test]
    fn hello_ack_field_names() {
        let ack = HelloAck {
            node_id: "n1".into(),
            server_ts: "2025-07-01T08:30:00.000Z".into(),
            protocol: ProtoRangeOut { min: 1, max: 1 },
            quota: QuotaOut { msg_per_s: 100, bytes_per_s: 26214400, topics: 100, chunk_threshold_max: 33554432 },
            chunk: ChunkOut { inline: 1048576, threshold_max: 33554432, part: 262144 },
            mode: "zero-knowledge".into(),
            session: Some("1".into()),
        };
        let v: serde_json::Value = serde_json::to_value(&ack).unwrap();
        assert_eq!(v["protocol"]["max"], 1);
        assert_eq!(v["quota"]["chunk_threshold_max"], 33554432);
        assert_eq!(v["chunk"]["part"], 262144);
        assert_eq!(v["mode"], "zero-knowledge");
    }
}
