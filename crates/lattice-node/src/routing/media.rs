//! Media-plane signaling and WS tunnels (design §17.9; ⑤ §9.3 `stream-sig` / `stream-data`).
//!
//! The platform **does not relay media itself** (WebRTC direct / QUIC proxy is negotiated by clients); this does only two things:
//!
//! 1. **Signaling relay** (`stream-sig`, body is an Envelope protobuf): deliver the negotiation envelope as-is to the target user/
//!    device. Signaling is **transient** — if the target is offline or the queue is full, drop it (no pending, no redelivery), because
//!    after the 10s media negotiation timeout the client falls back to the next path (design §17.9). The server forcibly overrides `sender`
//!    with the authenticated identity to prevent spoofing.
//! 2. **WS binary tunnel** (`stream-data`, the last fallback in design §17.9-3): after an offer binds the
//!    `stream_id` to both parties' `(user, device)` in Redis (`lattice:stream:{id}`, TTL 120s),
//!    the server relays raw bytes only between the two devices in that session; other connections cannot use `stream_id` to peek/inject.
//!
//! `stream-data` body format (⑤ §9.3, clarified since v0.16):
//! ```text
//! [1B ver=1][1B flags=0][2B stream_id_len BE][stream_id utf8][payload...]
//! ```
//! The whole body is ≤ 64KB (design §17.10); the server **does not interpret** the payload and relays it as-is (header included, so the receiver
//! can demultiplex by `stream_id`).
//!
//! Explicitly not done: QUIC/SFU, bitrate adaptation, cross-node end-to-end encryption for tunnels; cross-node tunnels still use the
//! route/broadcast bus (at-most-once; dropped frames are recovered by the upper-layer codec).
//!
//! **Media recording side path (PL-13 13.6, bus upgrade; OGG Opus muxing/playback manifest/Envelope added in v0.19)**:
//! Enabled only when `[media] record_enabled=true`; asynchronously persists raw WS tunnel `stream-data` frames to object storage.
//! The forwarding hot path only does one bounded-queue `try_send`; recording never blocks/slows forwarding. The persistence path depends on the bus type
//! (see `spawn_recorder`):
//! - `bus.kind=nats`: tee → `LATTICE_MEDIA` (`media.record.{stream_id}`, JetStream publish+ack)
//!   → this node's durable consumer `media-record-{node_id}` → aggregate segments by stream → MinIO;
//!   on publish failure/unavailability the producer **degrades to direct write** (no dropped frames). Protocol/idempotency/degradation details in
//!   `routing/media_record.rs`;
//! - `bus.kind=redis-pubsub`: no persistent/acked recording stream, so local direct write (the original minimal verifiable behavior).
//!
//! **Playable muxing (v0.19, E21 wrap-up)**: after a recording segment is persisted, `routing/media_playback.rs` handles it —
//! if the offer **explicitly opts in** with `record_format="ogg-opus"` (optionally with `codec="opus"`) and every frame payload in the segment passes Opus packet-structure validation, it is **losslessly**
//! muxed into a playable **OGG Opus** object (`media/playback/record/.../*.ogg`); the manifest's
//! `format/playable/codec` become `ogg-opus/true/opus` and a `playback{}` block is appended, while a
//! `*.playback.json` playback Envelope is written and a WS `envelope` message is pushed to online devices at both ends of the stream. Without `record_format`/
//! non-opus / invalid packet structure, it stays `raw-frames + playable=false`, and the manifest records the reason
//! explicitly in `playback_gap` (**never faking playability**).
//!
//! **Explicitly not done** (remaining gaps to the design §17.9 final form, stated honestly): no MP4/fMP4, no transcoding/
//! H.264/AV1, no keyframe index; playback object download/detail fields (`transport/http.rs`) and lifecycle reclamation
//! (`jobs.rs`) are not wired (see the GAP list at the top of `routing/media_playback.rs`).

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lattice_core::{Frame, WsCommand};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::auth::rbac::AuthUser;
use crate::error::LatticeError;
use crate::observe::Metrics;
use crate::state::AppState;

/// TTL for `lattice:stream:{id}`: 10s negotiation timeout + active tunnel renewal; expires automatically after 120s idle.
const STREAM_SESSION_TTL_SECS: u64 = 120;
/// Single `stream-data` frame cap (⑤ §9.3 / design §17.10).
pub const STREAM_DATA_MAX: usize = 64 * 1024;
const STREAM_ID_MAX: usize = 64;

/// `stream-sig` payload (JSON). Everything except the fields below is passed through; the server does not parse it.
#[derive(Debug, Clone, Deserialize)]
pub struct SignalPayload {
    pub stream_id: String,
    pub action: String,
    pub to_user: String,
    #[serde(default)]
    pub to_devices: Vec<String>,
    /// **Optional** recording container opt-in (v0.19): only `"ogg-opus"` muxes this stream's recording segment into a playable
    /// OGG Opus file after persistence (see `routing/media_playback.rs`). Default = no muxing (v0.18 behavior unchanged).
    #[serde(default)]
    pub record_format: Option<String>,
    /// **Optional** codec hint (v0.19, for recording muxing; part of design §17.9 "other fields pass through").
    ///
    /// Affects only recording side-path muxing (see `routing/media_playback.rs`); when absent, behavior is exactly v0.18
    /// (raw-frames / playable=false). The server neither rejects nor rewrites signaling based on it; it is recording metadata only.
    /// Note: a bare `codec` without `record_format` does **not** trigger muxing (codec is pass-through only).
    #[serde(default)]
    pub codec: Option<String>,
    /// Optional original sample rate (default 48000; only written into OpusHead's input sample rate field).
    #[serde(default)]
    pub sample_rate: Option<u32>,
    /// Optional channel count (default 1; valid 1..=2; out of range records `playback_gap=codec_hint_invalid`).
    #[serde(default)]
    pub channels: Option<u8>,
}

/// Per-tunnel media bitrate token bucket (design §17.9: 8Mbps per stream, not counted against the message quota).
///
/// In-process state: the tunnel session itself is in Redis (TTL 120s); this only limits burst volume;
/// bucket capacity is 500ms of quota with a minimum of 4KiB, so small frames are not wrongly rejected by an initially empty bucket.
#[derive(Debug, Clone)]
pub struct StreamBucket {
    pub tokens: f64,
    pub last: Instant,
}

impl StreamBucket {
    fn allow(&mut self, bytes: usize, bytes_per_sec: f64, burst: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * bytes_per_sec).min(burst);
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}

/// Per-node concurrent stream cap (§17.9): checked only when an offer creates a session; over the cap returns `RATE/stream_quota`.
///
/// **best-effort**: on Redis read timeout/failure, allow (log warn) — throttling statistics being unavailable must not
/// take down the whole media signaling plane (prefer availability during Redis degradation; the cap applies again once Redis recovers).
async fn enforce_stream_cap(state: &AppState, stream_id: &str) -> Result<(), LatticeError> {
    let max = state.cfg.media.max_streams;
    if max == 0 {
        return Ok(());
    }
    let redis = &state.redis;
    let probe = async {
        // A renegotiation offer for the same stream is not a new stream, so a renegotiation after hitting the cap is not rejected
        if let Ok(Some(_)) = redis.stream_session_get(stream_id).await {
            return Ok::<Option<usize>, LatticeError>(None);
        }
        redis
            .count_stream_sessions()
            .await
            .map(Some)
            .map_err(|e| LatticeError::internal(format!("stream session count failed: {e}")))
    };
    match tokio::time::timeout(Duration::from_millis(500), probe).await {
        Ok(Ok(None)) => Ok(()),
        Ok(Ok(Some(active))) if active >= max => {
            tracing::warn!(active, max, stream_id, "media stream limit reached; offer rejected");
            Err(LatticeError::rate("media stream limit exceeded").with_reason("stream_quota"))
        }
        Ok(Ok(Some(_))) => Ok(()),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, stream_id, "media stream cap check failed; allow offer (degraded)");
            Ok(())
        }
        Err(_) => {
            tracing::warn!(stream_id, "media stream cap check timed out; allow offer (degraded)");
            Ok(())
        }
    }
}

/// Tunnel frame bitrate check (§17.9: 8Mbps per stream); over the limit drops the frame and counts it (does not disconnect).
pub fn allow_stream_bytes(state: &AppState, stream_id: &str, bytes: usize) -> bool {
    let bps = state.cfg.media.stream_bitrate_bps;
    if bps == 0 {
        return true;
    }
    let bytes_per_sec = bps as f64 / 8.0;
    let burst = (bytes_per_sec * 0.5).max(4096.0);
    let mut buckets = match state.stream_buckets.lock() {
        Ok(b) => b,
        Err(_) => return true,
    };
    if buckets.len() > 4096 {
        buckets.retain(|_, b| b.last.elapsed() < Duration::from_secs(120));
    }
    let bucket = buckets
        .entry(stream_id.to_string())
        .or_insert_with(|| StreamBucket {
            tokens: burst,
            last: Instant::now(),
        });
    bucket.allow(bytes, bytes_per_sec, burst)
}

fn format_err(msg: &str) -> LatticeError {
    LatticeError::format(msg.to_string()).with_reason("stream")
}

/// Validate the signaling payload; the `action` allowlist and stream_id charset are enforced here.
pub fn validate_signal(raw: &[u8]) -> Result<SignalPayload, LatticeError> {
    let p: SignalPayload = serde_json::from_slice(raw)
        .map_err(|e| format_err(&format!("bad stream-sig payload: {e}")))?;
    if p.stream_id.is_empty() || p.stream_id.len() > STREAM_ID_MAX {
        return Err(format_err("stream_id length out of range"));
    }
    if !p
        .stream_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(format_err("stream_id has invalid characters"));
    }
    if !matches!(
        p.action.as_str(),
        "offer" | "answer" | "candidate" | "fallback" | "bye"
    ) {
        return Err(format_err("unknown stream-sig action"));
    }
    if p.to_user.is_empty() || p.to_devices.len() > 4 {
        return Err(format_err("invalid stream-sig target"));
    }
    Ok(p)
}

/// `stream-data` header parse result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataHeader<'a> {
    pub stream_id: &'a str,
    pub payload: &'a [u8],
}

/// Parse and validate a `stream-data` body (version/length/total size).
pub fn parse_data_body(body: &[u8]) -> Result<DataHeader<'_>, LatticeError> {
    if body.len() > STREAM_DATA_MAX {
        return Err(format_err("stream-data frame too large"));
    }
    if body.len() < 4 || body[0] != 1 {
        return Err(format_err("bad stream-data header"));
    }
    let id_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if id_len == 0 || id_len > STREAM_ID_MAX || body.len() < 4 + id_len {
        return Err(format_err("bad stream-data stream_id"));
    }
    let stream_id = std::str::from_utf8(&body[4..4 + id_len])
        .map_err(|_| format_err("stream_id is not utf8"))?;
    Ok(DataHeader {
        stream_id,
        payload: &body[4 + id_len..],
    })
}

/// Send a frame to the target user/device (local direct + cross-node bus); returns the number of devices delivered locally.
///
/// Signaling and tunnels are transient data: dropped when the target is offline or the queue is full; never written to pending.
async fn relay(
    state: &AppState,
    target_user: &str,
    target_devices: &[String],
    cmd: WsCommand,
    body: &[u8],
) -> usize {
    use crate::routing::online::Decision;
    match crate::routing::online::decide(state, target_user, target_devices).await {
        Decision::Offline => 0,
        Decision::Local(devices) => {
            let frame = Frame::new(cmd, bytes::Bytes::copy_from_slice(body));
            devices
                .iter()
                .filter(|d| state.hub.send_to_device(target_user, d, frame.clone()))
                .count()
        }
        Decision::Remote(remote) => {
            let mut sent = 0;
            for (node, devices) in remote {
                if let Err(e) = crate::routing::online::forward(
                    state,
                    &node,
                    target_user,
                    &devices,
                    cmd.to_u8(),
                    body.to_vec(),
                )
                .await
                {
                    tracing::warn!(error = %e, "stream relay forward failed");
                } else {
                    sent += devices.len();
                }
            }
            sent
        }
        Decision::Mixed(local, remote) => {
            let frame = Frame::new(cmd, bytes::Bytes::copy_from_slice(body));
            let mut sent = local
                .iter()
                .filter(|d| state.hub.send_to_device(target_user, d, frame.clone()))
                .count();
            for (node, devices) in remote {
                if crate::routing::online::forward(
                    state,
                    &node,
                    target_user,
                    &devices,
                    cmd.to_u8(),
                    body.to_vec(),
                )
                .await
                .is_ok()
                {
                    sent += devices.len();
                }
            }
            sent
        }
    }
}

/// Record/refresh a tunnel session: `a` = initiator (offer sender), `b` = peer (the single device in to_devices).
async fn remember_session(
    state: &AppState,
    stream_id: &str,
    a_user: &str,
    a_device: &str,
    b_user: &str,
    b_device: &str,
) {
    let fields = [
        ("a_user", a_user),
        ("a_device", a_device),
        ("b_user", b_user),
        ("b_device", b_device),
    ];
    let write = state
        .redis
        .stream_session_put(stream_id, &fields, STREAM_SESSION_TTL_SECS);
    match tokio::time::timeout(Duration::from_millis(500), write).await {
        Ok(Err(e)) => tracing::warn!(error = %e, stream_id, "stream session write failed"),
        Err(_) => tracing::warn!(stream_id, "stream session write timed out (redis degraded)"),
        Ok(Ok(())) => {}
    }
}

/// `stream-sig`: relay the negotiation envelope to the target; offer/bye maintain the tunnel session mapping.
pub async fn on_signal(
    state: &AppState,
    auth: &AuthUser,
    device: &str,
    frame: &Frame,
) -> Result<(), LatticeError> {
    let mut env = lattice_core::Envelope::decode_body(&frame.body)?;
    if env.r#type != "stream-sig" {
        return Err(format_err("stream-sig envelope type mismatch"));
    }
    let signal = validate_signal(&env.payload)?;
    // Identity is hardcoded by the server: clients cannot spoof the sender (⑤ §9.3)
    env.sender = auth.user_id.clone();
    let body = env.encode_body();

    // Recording muxing hints (v0.19, see `routing/media_playback.rs`): an offer may carry an optional
    // `record_format` (explicit opt-in, the only valid value is ogg-opus) + `codec/sample_rate/channels`,
    // used only for recording-side-path OGG Opus muxing and playback Envelope delivery targets; absent = zero side effects
    // (v0.18 behavior unchanged), and signaling relay/session semantics are not changed.
    if signal.action == "offer" {
        let hint_state = match crate::routing::media_playback::codec_hint_from_fields(
            signal.record_format.as_deref(),
            signal.codec.as_deref(),
            signal.sample_rate,
            signal.channels,
        ) {
            Ok(None) => crate::routing::media_playback::HintState::None,
            Ok(Some(h)) => crate::routing::media_playback::HintState::Known(h),
            Err(gap) => crate::routing::media_playback::HintState::Invalid(gap),
        };
        // Participants = both ends of the offer (the playback Envelope is pushed only to **online devices on this node**; transient semantics same as stream-sig).
        let mut participants = vec![(auth.user_id.clone(), device.to_string())];
        if let Some(peer) = signal.to_devices.first() {
            participants.push((signal.to_user.clone(), peer.clone()));
        }
        crate::routing::media_playback::remember_signal(
            &signal.stream_id,
            hint_state,
            &participants,
        );
    }

    if signal.action == "bye" {
        // Either side may send bye; whoever does clears the session (asynchronous, does not block signaling relay)
        let redis = state.redis.clone();
        let sid = signal.stream_id.clone();
        tokio::spawn(async move {
            let _ = redis.stream_session_del(&sid).await;
        });
        if let Ok(mut buckets) = state.stream_buckets.lock() {
            buckets.remove(&signal.stream_id);
        }
        // Recording side path: bye finalizes the stream's last segment immediately (asynchronous, non-blocking;
        // a no-op when the recorder is off). A bye from either sender finalizes.
        if let Some(rec) = &state.recorder {
            rec.finalize(&signal.stream_id);
        }
    }
    if signal.action == "offer" && signal.to_devices.len() == 1 {
        enforce_stream_cap(state, &signal.stream_id).await?;
    }

    let sent = relay(
        state,
        &signal.to_user,
        &signal.to_devices,
        WsCommand::StreamSig,
        &body,
    )
    .await;

    if signal.to_devices.len() == 1 {
        let peer_device = &signal.to_devices[0];
        if signal.action == "offer" {
            remember_session(
                state,
                &signal.stream_id,
                &auth.user_id,
                device,
                &signal.to_user,
                peer_device,
            )
            .await;
        } else if signal.action != "bye" {
            // answer/candidate/fallback renew the session, avoiding mid-session expiry for long sessions (bounded; does not stall signaling when Redis is half-dead)
            let _ = tokio::time::timeout(
                Duration::from_millis(500),
                state
                    .redis
                    .stream_session_touch(&signal.stream_id, STREAM_SESSION_TTL_SECS),
            )
            .await;
        }
    }

    if sent == 0 {
        // Transient signaling: drop when the target is offline (the client falls back to the next path after 10s, design §17.9)
        tracing::debug!(
            stream_id = %signal.stream_id,
            action = %signal.action,
            "stream-sig target offline, dropped"
        );
    }
    Ok(())
}

/// `stream-data`: only the two devices in the session may exchange data; relayed as-is to the peer.
pub async fn on_data(
    state: &AppState,
    auth: &AuthUser,
    device: &str,
    frame: &Frame,
) -> Result<(), LatticeError> {
    let parsed = parse_data_body(&frame.body)?;
    let Some(session) = state
        .redis
        .stream_session_get(parsed.stream_id)
        .await
        .map_err(|e| format_err(&format!("stream session lookup failed: {e}")))?
    else {
        // No session established by an offer: reject, so the channel cannot be used as an arbitrary message relay
        if let Ok(mut buckets) = state.stream_buckets.lock() {
            buckets.remove(parsed.stream_id);
        }
        return Err(format_err("unknown stream session").with_reason("stream_session"));
    };

    let a = (
        session.get("a_user").map(String::as_str),
        session.get("a_device").map(String::as_str),
    );
    let b = (
        session.get("b_user").map(String::as_str),
        session.get("b_device").map(String::as_str),
    );
    let peer = if a == (Some(auth.user_id.as_str()), Some(device)) {
        b
    } else if b == (Some(auth.user_id.as_str()), Some(device)) {
        a
    } else {
        return Err(format_err("sender not in stream session").with_reason("stream_session"));
    };
    let (Some(peer_user), Some(peer_device)) = peer else {
        return Err(format_err("stream session is incomplete"));
    };
    if peer_user.is_empty() || peer_device.is_empty() {
        return Err(format_err("stream session is incomplete"));
    }

    if !allow_stream_bytes(state, parsed.stream_id, frame.body.len()) {
        state
            .metrics
            .backpressure_dropped_total
            .with_label_values(&["stream-data"])
            .inc();
        tracing::debug!(
            stream_id = %parsed.stream_id,
            bytes = frame.body.len(),
            "stream-data over bitrate, dropped"
        );
        return Ok(());
    }
    let _ = state
        .redis
        .stream_session_touch(parsed.stream_id, STREAM_SESSION_TTL_SECS)
        .await;
    // Recording side path: after "session/rate-limit checks both pass", tee the raw frame body (including the stream_id header),
    // before the actual forwarding — try_send is synchronous and non-blocking, adding no await point to forwarding;
    // when the queue is full, drop the frame and count `lattice_media_record_dropped_total` (recording never blocks/slows forwarding).
    // Conventions: what is recorded is the frame "that passed this node's admission and rate limiting and is about to be forwarded"; if delivery to the peer fails,
    // this frame is still recorded (recording does not guarantee exact agreement with the receiver).
    if let Some(rec) = &state.recorder {
        rec.tee(parsed.stream_id, frame.body.clone());
    }
    relay(
        state,
        peer_user,
        &[peer_device.to_string()],
        WsCommand::StreamData,
        &frame.body,
    )
    .await;
    Ok(())
}

/// Redis session snapshot (for tests and troubleshooting).
pub type StreamSession = HashMap<String, String>;

// ===========================================================================
// Media recording side path (PL-13 13.6; still not the final design §17.9 form after the bus upgrade)
// ===========================================================================
//
// ## What is recorded
//
// Only the **raw frame body** on the **WS tunnel fallback path** (`stream-data`) that passes session authentication and per-stream rate limiting
// at this node's ingress:
// ```text
// [1B ver=1][1B flags=0][2B stream_id_len BE][stream_id utf8][payload...]
// ```
// Byte-for-byte identical to the WS tunnel body (including the `stream_id` header, so the consumer can demultiplex by stream); it does not parse/
// decode/transcode the payload. When forwarding across nodes, only the **ingress node** records this copy (the target node's
// `on_data` is not called), with no cross-node dedup.
//
// ## Two persistence paths (`spawn_recorder` chooses by the runtime `bus.kind()`)
//
// 1. **Bus path** (`bus.kind=nats`, the minimal reliable form of design §17.9):
//    a background producer wraps frames into `MediaRecordMsg{node_id,stream_id,seq,body_b64,ts}`
//    and publishes to `media.record.{stream_id}` (JetStream publish **waiting for ack**, `LATTICE_MEDIA`);
//    this node's durable pull consumer `media-record-{node_id}` (explicit ack) processes only
//    messages with `node_id==self`, aggregates segments by stream, and **acks after successful persistence**.
//    Details (protocol/idempotency key/degradation/DLQ) are in the comment at the top of `routing/media_record.rs`.
// 2. **Direct-write path** (`bus.kind=redis-pubsub`, or the degradation used when the bus producer's publish fails):
//    in-process bounded queue → aggregate by stream → `put_bytes` directly to MinIO (this file's `Recorder`).
//
// Segment object content format (same on both paths; **the only added metadata is frame boundaries**):
// ```text
// [4B BE frame_body_len][frame_body] repeated N times
// ```
// Why not raw concatenation: the `stream-data` body itself has no payload length field, so after raw concatenation **frame boundaries
// cannot be recovered from the file**; `[len][body]` is a self-describing boundary that does not touch frame content, so later muxing consumers can split frames.
//
// ## What is not done (gaps to the design's final form; do not conclude from the above that recording/playback is fully available)
//
// 1. **No MP4/fMP4, no transcoding/H.264/AV1, no keyframe index**; v0.19 only adds **OGG Opus**
//    as one playable container (and only when the offer explicitly opts in with `record_format="ogg-opus"`, see `routing/media_playback.rs`);
// 2. Muxing consumer semantics: the `LATTICE_MEDIA` consumer is still "aggregate by frame boundary + persist to object storage";
//    muxing is a **side-path derivation after persistence** (`media/playback/` prefix; failures only record a GAP and do not affect the segment/index);
// 3. Does not write message/delivery_log and does not consume the message quota (the media plane never counted against quota anyway);
// 4. Playback **download/detail APIs** are not wired: `GET /v1/media/recordings/{id}/download` still only 302s to the
//    original `.bin`; playable objects are located via manifest `playback.object_key` (direct object-storage fetch),
//    and `transport/http.rs` hardcodes `playable=false/format=raw-frames` — a known GAP;
// 5. Lifecycle reclamation does not cover the `media/playback/` prefix (`jobs.rs` is outside this task's write scope);
// 6. No cross-node aggregation: multiple nodes each write their own ingress frames (the bus consumer processes only this node's frames);
// 7. No timestamps/loss markers: only body is persisted; frame gaps and loss are recovered by the upper-layer codec (Opus granule accumulates
//    per-packet RFC 6716 frame duration, independent of capture timestamps).
//
// ## Does not block forwarding (this task's acceptance point)
//
// `on_data` does exactly one `try_send` (bounded queue 1024):
// - Queue full / recorder exited → drop the frame and count `lattice_media_record_dropped_total`;
// - All `await`s for object-storage persistence/bus publish+ack happen in background tasks; write/publish failures only warn +
//   metric (publish failure degrades to direct write to avoid loss), **never affecting tunnel forwarding**.
//
// ## Lifecycle and cleanup
//
// - Segment rotation: after append, persist the object when `len >= record_segment_bytes` (frame-aligned, never splits a frame);
// - bye: `finalize(stream_id)` in `on_signal` persists the remaining buffer as the last segment and removes it
//   from the map (either side's bye suffices); the bus path also sends a final control message so the consumer
//   flushes immediately (the durable consumer then persists idempotently by seq);
// - Idle: a stream with no new frames for 2s is flushed once, so buffers do not linger;
// - Node draining: with `draining=true`, each tick flush is best-effort (main's drain window is only 1s;
//   **SIGKILL / immediate process exit does not guarantee a flush**; this is the "best-effort" boundary — unacked bus messages are redelivered after restart
//   by the durable consumer, but **frames still in the recorder queue, not yet sent out**, are lost with the process);
// - Unbounded-growth protection: per-stream buffer ≤ one segment (+1 frame); when total process buffer exceeds
//   `RECORD_MAX_BUFFERED_BYTES`, force-flush the oldest stream; empty idle streams are removed from the map, and
//   the map entry count has an additional cap.

/// recorder bounded queue capacity (task card conventions: 1024). Drops frames when full, never awaits.
pub const RECORD_QUEUE: usize = 1024;
/// How long a stream may go without new frames before it is flushed (prevents buffers lingering).
pub(crate) const RECORD_IDLE_FLUSH: Duration = Duration::from_secs(2);
/// recorder main-loop tick: idle flush / draining check period.
pub(crate) const RECORD_TICK: Duration = Duration::from_millis(250);
/// Process-wide recording buffer cap (prevents many streams from holding half-full segments in memory); above it, force-flush the oldest stream.
pub(crate) const RECORD_MAX_BUFFERED_BYTES: usize = 64 * 1024 * 1024;
/// Maximum number of streams tracked in-process (one map entry per stream; empty buffers are tiny); above it, remove the oldest empty entry.
pub(crate) const RECORD_MAX_TRACKED_STREAMS: usize = 4096;

/// recorder input message: data frame + bye-triggered finalize.
#[derive(Debug)]
pub enum RecordMsg {
    Data { stream_id: String, body: bytes::Bytes },
    Finalize { stream_id: String },
}

/// Recording delivery handle held by `on_data`/`on_signal` (`AppState.recorder`).
///
/// Only `try_send`, no async methods: callers (the forwarding hot path) are never made to wait for recording.
pub struct MediaRecorder {
    tx: mpsc::Sender<RecordMsg>,
    metrics: Arc<Metrics>,
}

impl MediaRecorder {
    pub fn new(tx: mpsc::Sender<RecordMsg>, metrics: Arc<Metrics>) -> Self {
        Self { tx, metrics }
    }

    /// Non-blocking tee of one raw `stream-data` body.
    ///
    /// Queue full/channel closed → drop the frame and count `lattice_media_record_dropped_total`;
    /// never awaits, never retries (recording is a side path; availability beats completeness).
    pub fn tee(&self, stream_id: &str, body: bytes::Bytes) {
        let msg = RecordMsg::Data { stream_id: stream_id.to_string(), body };
        if self.tx.try_send(msg).is_err() {
            self.metrics.media_record_dropped_total.inc();
            tracing::debug!(stream_id, "media record tee dropped (queue full or recorder closed)");
        }
    }

    /// bye trigger: make the recorder finalize this stream immediately (persist the remaining segment + remove from memory).
    ///
    /// Also non-blocking; when the queue is full, drop this "finalize immediately" hint (the recorder's idle flush covers it).
    pub fn finalize(&self, stream_id: &str) {
        let msg = RecordMsg::Finalize { stream_id: stream_id.to_string() };
        if self.tx.try_send(msg).is_err() {
            tracing::debug!(stream_id, "media record finalize dropped (queue full or recorder closed)");
        }
    }
}

/// Recording buffer for a single stream (aggregated by stream_id).
struct StreamSegment {
    /// Concatenated `[4B len][body]...` buffer; grows at most to one segment (+ the last frame).
    buffer: Vec<u8>,
    last_at: Instant,
}

impl StreamSegment {
    fn new() -> Self {
        Self { buffer: Vec::new(), last_at: Instant::now() }
    }
}

/// Append a frame to the segment buffer: `[4B BE body_len][body]` (adds only the boundary; body as-is).
///
/// `crate`-visible: the bus consumer (`routing/media_record.rs`) reuses the same container logic,
/// guaranteeing the objects produced by both paths (direct write / bus consumer) are byte-for-byte identical.
pub(crate) fn append_record_frame(buffer: &mut Vec<u8>, body: &[u8]) {
    // body ≤ STREAM_DATA_MAX=64KiB (validated by parse_data_body), u32 is sufficient.
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    buffer.extend_from_slice(&len.to_be_bytes());
    buffer.extend_from_slice(body);
}

/// Decide whether to persist a segment after appending (`>=`, frame-aligned: a frame is never split across two objects).
pub(crate) fn segment_full(buffer_len: usize, segment_bytes: usize) -> bool {
    buffer_len >= segment_bytes.max(1)
}

/// Recording object key: `media/record/{stream_id}/{utc-seconds}-{seq}.bin`.
///
/// `seq` is the recorder's in-process global monotonic sequence (allocated at flush); keys are unique within a process and increase
/// in write order; after a process restart it starts from 0, but the `utc-seconds` differ, so normal operation does not overwrite.
///
/// Used only by the **direct-write degradation path** (including Redis bus mode); the bus consumer path's key is decided
/// by `bus_record_object_key` in `routing/media_record.rs` from the segment's first seq (replay-idempotent).
pub(crate) fn record_object_key(stream_id: &str, utc_secs: i64, seq: u64) -> String {
    format!("media/record/{stream_id}/{utc_secs}-{seq}.bin")
}

/// Write one buffer as an object (with a full key); metrics are recorded on success/failure, **never backpressuring forwarding**.
///
/// Shared by the direct-write path and the bus consumer: on `Err` the caller decides "drop (direct write, best-effort semantics)" or
/// "keep the buffer for retry/DLQ (bus consumer, at-least-once semantics)".
pub(crate) async fn put_segment(
    state: &AppState,
    bucket: &str,
    stream_id: &str,
    key: &str,
    bytes: Vec<u8>,
) -> std::result::Result<(), String> {
    if bytes.is_empty() {
        return Ok(());
    }
    match state.s3.put_bytes(bucket, key, &bytes).await {
        Ok(()) => {
            state.metrics.media_record_segments_total.inc();
            state.metrics.media_record_bytes_total.inc_by(bytes.len() as u64);
            tracing::info!(
                stream_id,
                key = %key,
                bytes = bytes.len(),
                "media record segment written"
            );
            Ok(())
        }
        Err(e) => {
            state.metrics.media_record_errors_total.inc();
            Err(e)
        }
    }
}

/// Direct-write path persists one segment: build the `{utc-seconds}-{seq}.bin` key then [`put_segment`]; failures only warn.
///
/// After a successful write, synchronously write a recording index row (PL-13 13.6 search/download): the direct-write path's raw `stream-data`
/// body **has no frame seq**, so the index's `first_seq/last_seq/started_at/ended_at` are NULL, and the
/// frame count is counted from `[4B len][body]` boundaries; index failures only WARN and do not affect recording/forwarding (see
/// `routing/media_record.rs::index_segment`).
async fn write_segment(
    state: &AppState,
    bucket: &str,
    stream_id: &str,
    seq: u64,
    bytes: Vec<u8>,
) {
    if bytes.is_empty() {
        return;
    }
    let key = record_object_key(stream_id, chrono::Utc::now().timestamp(), seq);
    let bytes_len = bytes.len();
    let frames = crate::routing::media_record::count_segment_frames(&bytes);
    if let Err(e) = put_segment(state, bucket, stream_id, &key, bytes).await {
        tracing::warn!(
            stream_id,
            key = %key,
            bytes = bytes_len,
            error = %e,
            "media record segment write failed; segment dropped (forwarding unaffected)"
        );
        return;
    }
    crate::routing::media_record::index_segment(
        state,
        bucket,
        stream_id,
        &key,
        bytes_len,
        crate::routing::media_record::SegmentIndexMeta {
            first_seq: None,
            last_seq: None,
            frames,
            started_at: None,
            ended_at: None,
        },
    )
    .await;
}

/// recorder aggregation state (owned by the background task, lock-free).
///
/// Two uses:
/// - **Direct-write path** (Redis bus / NATS publish degradation): `spawn_direct_recorder` owns one instance,
///   aggregates received frames by stream, and persists when full/idle/bye (this file's original behavior, the 43/43 E2E conventions);
/// - **Bus producer's degradation write end** (`routing/media_record.rs::spawn_bus_producer`): frames are fed only when
///   `publish_media` fails, guaranteeing "no dropped frames even when NATS is unavailable".
pub(crate) struct Recorder {
    state: Arc<AppState>,
    bucket: String,
    segment_bytes: usize,
    streams: HashMap<String, StreamSegment>,
    /// In-process global segment sequence (allocated at persist time; keys use `{utc-seconds}-{seq}.bin`).
    next_seq: u64,
    /// Total buffered bytes across all streams (prevents unbounded totals).
    buffered_bytes: usize,
}

impl Recorder {
    pub(crate) fn new(state: Arc<AppState>) -> Self {
        let bucket = state.cfg.media.effective_record_bucket(&state.cfg.s3);
        let segment_bytes = state.cfg.media.effective_record_segment_bytes();
        Self {
            state,
            bucket,
            segment_bytes,
            streams: HashMap::new(),
            next_seq: 0,
            buffered_bytes: 0,
        }
    }

    /// Receive a frame: append → rotate/persist when full → force-flush the oldest stream when the total exceeds the limit.
    pub(crate) async fn on_data(&mut self, stream_id: String, body: &[u8]) {
        let segment_bytes = self.segment_bytes;
        let seg = self.streams.entry(stream_id.clone()).or_insert_with(StreamSegment::new);
        append_record_frame(&mut seg.buffer, body);
        seg.last_at = Instant::now();
        let appended = 4 + body.len();
        self.buffered_bytes += appended;
        if segment_full(seg.buffer.len(), segment_bytes) {
            let bytes = std::mem::take(&mut seg.buffer);
            let seq = self.next_seq;
            self.next_seq += 1;
            self.buffered_bytes -= bytes.len();
            write_segment(&self.state, &self.bucket, &stream_id, seq, bytes).await;
        } else if self.buffered_bytes > RECORD_MAX_BUFFERED_BYTES {
            // Multiple streams half-full push memory past the limit: force-flush the oldest stream (possibly including the one just received).
            self.flush_oldest().await;
        }
    }

    /// bye: persist the remaining buffer as the last segment and remove it from the map (the stream then uses no memory).
    pub(crate) async fn finalize(&mut self, stream_id: &str) {
        let Some(seg) = self.streams.remove(stream_id) else { return };
        self.buffered_bytes -= seg.buffer.len();
        if seg.buffer.is_empty() {
            return;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        write_segment(&self.state, &self.bucket, stream_id, seq, seg.buffer).await;
    }

    /// Idle flush: persist streams with no new frames for 2s; remove empty idle entries from the map (prevents unbounded map growth).
    pub(crate) async fn flush_idle(&mut self) {
        let due: Vec<String> = self
            .streams
            .iter()
            .filter(|(_, s)| !s.buffer.is_empty() && s.last_at.elapsed() >= RECORD_IDLE_FLUSH)
            .map(|(id, _)| id.clone())
            .collect();
        for id in due {
            if let Some(seg) = self.streams.get_mut(&id) {
                if seg.buffer.is_empty() {
                    continue;
                }
                let bytes = std::mem::take(&mut seg.buffer);
                let seq = self.next_seq;
                self.next_seq += 1;
                self.buffered_bytes -= bytes.len();
                write_segment(&self.state, &self.bucket, &id, seq, bytes).await;
            }
        }
        // Idle entries with no buffer no longer need tracking (seq is global, so removing an entry cannot cause key collisions).
        self.streams
            .retain(|_, s| !s.buffer.is_empty() || s.last_at.elapsed() < RECORD_IDLE_FLUSH);
        self.enforce_stream_cap();
    }

    /// Force-flush the oldest (smallest last_at) non-empty stream; a fallback for exceeding the total buffer cap.
    async fn flush_oldest(&mut self) {
        let Some(id) = self
            .streams
            .iter()
            .filter(|(_, s)| !s.buffer.is_empty())
            .min_by_key(|(_, s)| s.last_at)
            .map(|(id, _)| id.clone())
        else {
            return;
        };
        if let Some(seg) = self.streams.get_mut(&id) {
            let bytes = std::mem::take(&mut seg.buffer);
            if bytes.is_empty() {
                return;
            }
            let seq = self.next_seq;
            self.next_seq += 1;
            self.buffered_bytes -= bytes.len();
            write_segment(&self.state, &self.bucket, &id, seq, bytes).await;
        }
    }

    /// Node draining/recorder shutdown: best-effort write out all non-empty buffers (failures only warn).
    pub(crate) async fn flush_all(&mut self) {
        let ids: Vec<String> = self
            .streams
            .iter()
            .filter(|(_, s)| !s.buffer.is_empty())
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            if let Some(seg) = self.streams.get_mut(&id) {
                if seg.buffer.is_empty() {
                    continue;
                }
                let bytes = std::mem::take(&mut seg.buffer);
                let seq = self.next_seq;
                self.next_seq += 1;
                self.buffered_bytes -= bytes.len();
                write_segment(&self.state, &self.bucket, &id, seq, bytes).await;
            }
        }
    }

    /// Fallback for tracked entry count: remove the oldest empty entries above the cap (the idle cleanup covers the normal path).
    fn enforce_stream_cap(&mut self) {
        if self.streams.len() <= RECORD_MAX_TRACKED_STREAMS {
            return;
        }
        let mut empties: Vec<(String, Instant)> = self
            .streams
            .iter()
            .filter(|(_, s)| s.buffer.is_empty())
            .map(|(id, s)| (id.clone(), s.last_at))
            .collect();
        empties.sort_by_key(|(_, at)| *at);
        let drop_n = self.streams.len() - RECORD_MAX_TRACKED_STREAMS;
        for (id, _) in empties.into_iter().take(drop_n) {
            self.streams.remove(&id);
        }
    }
}

/// Start the background recording task (called by `node::build` when `[media] record_enabled=true`).
///
/// The task holds `Arc<AppState>` (accessing s3/cfg/metrics/draining), so its exit path does not depend on
/// the channel closing: during the node drain window it polls `draining` to flush best-effort (SIGKILL is not guaranteed).
///
/// **Path selection** (PL-13 13.6 bus upgrade):
/// - `bus.kind = nats` (and `[bus] jetstream=true`): use `media.record.{stream_id}` →
///   `LATTICE_MEDIA` → durable consumer → MinIO (`routing/media_record.rs`); publish failures
///   automatically degrade to direct write (no dropped frames);
/// - `bus.kind = redis-pubsub`: no persistent/acked recording stream, so local direct write directly (original behavior,
///   existing `scripts/media-record-e2e.mjs` 43/43 unchanged).
pub fn spawn_recorder(state: Arc<AppState>, rx: mpsc::Receiver<RecordMsg>) {
    match state.bus.kind() {
        crate::store::BusKind::Nats => {
            crate::routing::media_record::spawn_bus_producer(state, rx)
        }
        crate::store::BusKind::RedisPubSub => spawn_direct_recorder(state, rx),
    }
}

/// Direct-write recorder main loop (original path on the Redis bus / `bus.kind != nats`).
///
/// Preserves original semantics: bounded mpsc (1024) → aggregate by stream → persist to Object Storage when full/idle/bye/draining.
fn spawn_direct_recorder(state: Arc<AppState>, mut rx: mpsc::Receiver<RecordMsg>) {
    tokio::spawn(async move {
        let mut rec = Recorder::new(state.clone());
        tracing::info!(
            bucket = %rec.bucket,
            segment_bytes = rec.segment_bytes,
            queue = RECORD_QUEUE,
            "media record tee enabled (direct object-store write; bus has no media stream)"
        );
        loop {
            match tokio::time::timeout(RECORD_TICK, rx.recv()).await {
                Ok(Some(RecordMsg::Data { stream_id, body })) => {
                    // The bus does not support the recording stream (redis-pubsub) → by design do not publish, write directly;
                    // metrics use publish_total{result=direct}, aligned with the bus mode's ok/fallback.
                    state
                        .metrics
                        .media_record_publish_total
                        .with_label_values(&["direct"])
                        .inc();
                    rec.on_data(stream_id, &body).await
                }
                Ok(Some(RecordMsg::Finalize { stream_id })) => rec.finalize(&stream_id).await,
                Ok(None) => {
                    // All senders released (unit test / runtime shutdown): flush best-effort then exit.
                    rec.flush_all().await;
                    tracing::info!("media recorder channel closed, flushed");
                    return;
                }
                Err(_) => {
                    rec.flush_idle().await;
                    // Node draining: main leaves only a 1s window; flush incomplete segments best-effort within it.
                    if state.draining.load(Ordering::Relaxed) {
                        rec.flush_all().await;
                    }
                }
            }
        }
    });
}

/// Build the recording side-path handle and receiver (returns `None` when `record_enabled=false`, zero side effects).
///
/// Called by `node::build`: create the channel/handle and put it into `AppState`, then `spawn_recorder`.
pub fn build_recorder(
    cfg: &crate::config::MediaCfg,
    metrics: Arc<Metrics>,
) -> (Option<Arc<MediaRecorder>>, Option<mpsc::Receiver<RecordMsg>>) {
    if !cfg.record_enabled {
        return (None, None);
    }
    let (tx, rx) = mpsc::channel(RECORD_QUEUE);
    (Some(Arc::new(MediaRecorder::new(tx, metrics))), Some(rx))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(json: &str) -> Result<SignalPayload, LatticeError> {
        validate_signal(json.as_bytes())
    }

    #[test]
    fn stream_bucket_enforces_bitrate() {
        // 1000 B/s, burst 4096: allow 4KB first, then sustained sends must be rejected
        let mut b = StreamBucket {
            tokens: 4096.0,
            last: Instant::now(),
        };
        assert!(b.allow(4096, 1000.0, 4096.0));
        assert!(!b.allow(4096, 1000.0, 4096.0));
        // Waiting 100ms refills only 100B, still not enough to send 4KB
        std::thread::sleep(Duration::from_millis(100));
        assert!(!b.allow(4096, 1000.0, 4096.0));
    }

    #[test]
    fn signal_validation_accepts_documented_actions() {
        for action in ["offer", "answer", "candidate", "fallback", "bye"] {
            let raw = format!(
                r#"{{"stream_id":"s-1","action":"{action}","to_user":"u2","to_devices":["d2"]}}"#
            );
            let p = signal(&raw).expect(action);
            assert_eq!(p.stream_id, "s-1");
            assert_eq!(p.to_devices, vec!["d2".to_string()]);
        }
    }

    #[test]
    fn signal_validation_rejects_bad_input() {
        assert!(signal(r#"{"stream_id":"","action":"offer","to_user":"u"}"#).is_err());
        assert!(signal(r#"{"stream_id":"s 1","action":"offer","to_user":"u"}"#).is_err());
        assert!(signal(r#"{"stream_id":"s1","action":"publish","to_user":"u"}"#).is_err());
        assert!(signal(r#"{"stream_id":"s1","action":"offer","to_user":""}"#).is_err());
        assert!(signal("not-json").is_err());
    }

    #[test]
    fn data_body_roundtrip() {
        let mut body = vec![1u8, 0u8];
        body.extend_from_slice(&3u16.to_be_bytes());
        body.extend_from_slice(b"s-1");
        body.extend_from_slice(b"opus-frame");
        let parsed = parse_data_body(&body).unwrap();
        assert_eq!(parsed.stream_id, "s-1");
        assert_eq!(parsed.payload, b"opus-frame");
    }

    #[test]
    fn data_body_rejects_bad_header_and_oversize() {
        assert!(parse_data_body(&[]).is_err());
        assert!(parse_data_body(&[2, 0, 0, 2, b's', b'1']).is_err());
        assert!(parse_data_body(&[1, 0, 0, 0]).is_err());
        assert!(parse_data_body(&[1, 0, 0, 5, b'a']).is_err());
        let mut huge = vec![1u8, 0, 0, 2];
        huge.extend_from_slice(b"s1");
        huge.resize(STREAM_DATA_MAX + 1, 0);
        assert!(parse_data_body(&huge).is_err());
    }

    // ---- Recording side path: segment format / rotation / key / non-blocking tee ----

    fn data_body(id: &str, payload: &[u8]) -> Vec<u8> {
        let id = id.as_bytes();
        let mut body = vec![1u8, 0u8, (id.len() >> 8) as u8, (id.len() & 0xff) as u8];
        body.extend_from_slice(id);
        body.extend_from_slice(payload);
        body
    }

    #[test]
    fn record_segment_is_length_prefixed_raw_bodies() {
        let bodies = [
            data_body("st-1", b"frame-one"),
            data_body("st-1", b"frame-two!"),
            data_body("st-1", b"x"),
        ];
        let mut buffer = Vec::new();
        for b in &bodies {
            append_record_frame(&mut buffer, b);
        }
        // Byte-check the container: `[4B BE len][body]` repeated, body as-is (including ver/flags/stream_id header)
        let mut expect = Vec::new();
        for b in &bodies {
            expect.extend_from_slice(&(b.len() as u32).to_be_bytes());
            expect.extend_from_slice(b);
        }
        assert_eq!(buffer, expect);

        // The consumer can split frames from length prefixes alone, and the split body parses back to stream_id/payload via parse_data_body
        let mut off = 0;
        let mut parsed = Vec::new();
        while off < buffer.len() {
            let len = u32::from_be_bytes([
                buffer[off],
                buffer[off + 1],
                buffer[off + 2],
                buffer[off + 3],
            ]) as usize;
            off += 4;
            parsed.push(buffer[off..off + len].to_vec());
            off += len;
        }
        assert_eq!(parsed, bodies);
        assert_eq!(parse_data_body(&parsed[1]).unwrap().stream_id, "st-1");
    }

    #[test]
    fn record_segment_rotates_at_limit() {
        assert!(!segment_full(63, 64));
        assert!(segment_full(64, 64));
        // 0 already falls back to the default 4MiB in config; handle defensively as >=1 here so it never spins
        assert!(segment_full(1, 0));
        // Frame alignment: appending may slightly exceed the limit (at most one frame + 4B prefix); a frame must not be split
        let body = data_body("s", &[0u8; 100]);
        let mut buf = Vec::new();
        append_record_frame(&mut buf, &body);
        assert_eq!(buf.len(), body.len() + 4);
        assert!(segment_full(buf.len(), 64));
    }

    #[test]
    fn record_object_key_layout() {
        let k = record_object_key("st-abc_1.2:x", 1_766_000_000, 7);
        assert_eq!(k, "media/record/st-abc_1.2:x/1766000000-7.bin");
        assert!(k.starts_with("media/record/"));
        assert!(k.ends_with("-7.bin"));
        // The sequence must appear in the file name (multiple segments in the same second must not overwrite each other)
        assert_ne!(
            record_object_key("s", 1, 0),
            record_object_key("s", 1, 1)
        );
    }

    #[test]
    fn record_tee_drops_when_queue_full_without_blocking() {
        let metrics = Metrics::new();
        let (tx, mut rx) = mpsc::channel(1);
        let rec = MediaRecorder::new(tx, metrics.clone());
        rec.tee("st-1", bytes::Bytes::from_static(b"one"));
        // Channel full: the second tee must return immediately (not block the thread) and count a dropped frame
        rec.tee("st-1", bytes::Bytes::from_static(b"two"));
        assert_eq!(metrics.media_record_dropped_total.get(), 1);
        // Only the first frame is in the queue, with stream id/body as-is
        match rx.try_recv().unwrap() {
            RecordMsg::Data { stream_id, body } => {
                assert_eq!(stream_id, "st-1");
                assert_eq!(&body[..], b"one");
            }
            other => panic!("unexpected msg: {other:?}"),
        }
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn record_tee_counts_drop_after_recorder_closed() {
        let metrics = Metrics::new();
        let (tx, rx) = mpsc::channel(4);
        drop(rx); // recorder task has exited
        let rec = MediaRecorder::new(tx, metrics.clone());
        rec.tee("st-1", bytes::Bytes::new());
        rec.finalize("st-1");
        assert_eq!(metrics.media_record_dropped_total.get(), 1);
    }

    #[test]
    fn record_finalize_is_delivered_through_queue() {
        let metrics = Metrics::new();
        let (tx, mut rx) = mpsc::channel(4);
        let rec = MediaRecorder::new(tx, metrics);
        rec.tee("st-9", bytes::Bytes::from_static(b"a"));
        rec.finalize("st-9");
        match rx.try_recv().unwrap() {
            RecordMsg::Data { stream_id, .. } => assert_eq!(stream_id, "st-9"),
            other => panic!("unexpected: {other:?}"),
        }
        match rx.try_recv().unwrap() {
            RecordMsg::Finalize { stream_id } => assert_eq!(stream_id, "st-9"),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
