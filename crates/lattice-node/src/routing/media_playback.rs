//! Media playback muxing (PL-13 / REAMINING E21 wrap-up; design §17.9 advances the recording boundary from "raw frame segments" to
//! **a playable container + playback manifest/Envelope**).
//!
//! ## Position
//!
//! The recording side path in `routing/media.rs` persists raw WS tunnel `stream-data` frames as
//! `[4B BE len][stream-data body]...` segment objects; `routing/media_record.rs` writes alongside them a
//! **playback manifest** (frame index, `format="raw-frames"`, `playable=false`). This module fills the two
//! remaining E21 gaps:
//!
//! 1. **Playable container**: when offer signaling **explicitly opts in** (`record_format="ogg-opus"`, see below) and every
//!    frame payload in the segment passes Opus packet-structure validation, the same payload is losslessly muxed into
//!    **OGG Opus** (RFC 3533 container / RFC 7845 encoding / RFC 6716 packet structure), written as a separate object
//!    `media/playback/record/{...}.ogg` — a **truly playable** file (decodable by ffmpeg/VLC and other standard
//!    players), not "raw bytes named .ogg".
//! 2. **Playback manifest/Envelope**: after muxing succeeds
//!    - the manifest's top-level `format/playable/codec` become `ogg-opus/true/opus` truthfully,
//!      and a `playback{...}` block is appended (container object key/bytes/frame count/duration/sample rate/channels + inline `envelope`);
//!    - a `media/playback/record/{...}.playback.json` **playback envelope** message is written
//!      (`type="media-playback"`, searchable: the key is deterministically derived from the segment object key);
//!    - a WS `envelope` is pushed to online devices at both ends of the stream (`lattice_core::Envelope`, type=`media`,
//!      metadata `event=playback.ready`) — i.e. "the playback message after recording completes".
//!
//! ## Codec hint contract (v0.19; the server never guesses codec / never muxes by default)
//!
//! The `stream-sig` payload is still "validate locating fields + pass the rest through" (design §17.9); the new **optional hints**
//! only affect recording muxing, and when absent, behavior is exactly v0.18 (raw-frames / playable=false):
//! ```json
//! { "stream_id":"s1","action":"offer","to_user":"u2","to_devices":["d2"],
//!   "record_format":"ogg-opus", "codec":"opus", "sample_rate":48000, "channels":1 }
//! ```
//! - `record_format`: **explicit opt-in** (absent = no muxing). Recording output semantics change from "raw frame container" to
//!   "playable container", so the initiator must declare it explicitly; the only valid value is `"ogg-opus"`; other values →
//!   `playback_gap.reason="record_format_not_supported"` (never faked).
//! - `codec`: optional when `record_format` is present (default `opus`); `opus`/`audio/opus`/`ogg-opus`
//!   normalize to `opus`; any other value is recorded truthfully as "unsupported codec"
//!   (manifest `playable=false` + `playback_gap.reason="codec_not_supported"`).
//!   **A bare `codec` without `record_format` does not trigger muxing** (`codec` is pass-through metadata only;
//!   the existing client contract is unchanged).
//! - `sample_rate`: default 48000; valid 8000..=48000 (Opus is always 48kHz internally; this writes OpusHead's
//!   original sample rate field, informational only); out of range → `playback_gap.reason="codec_hint_invalid"`.
//! - `channels`: default 1; valid 1..=2; out of range → `codec_hint_invalid`.
//! - Payload contract: with `record_format="ogg-opus"`, each `stream-data` frame payload must be
//!   **exactly one** Opus packet (RFC 6716 §3); otherwise the segment is not muxed (explicit gap, no faked playability).
//!
//! ## Explicitly not done (do not conclude that E21 is fully closed)
//!
//! 1. **MP4/fMP4, H.264/AV1, transcoding** are not done: only one container, OGG Opus, and **no transcoding** (the payload
//!    goes into the container as-is); a non-opus `codec` only records metadata + GAP.
//! 2. **Container quality**: Opus packet structure validation covers only the RFC 6716 §3 **frame framing check** (TOC/frame count/length fields),
//!    not entropy-decode validation — payload semantic correctness is the client encoder's responsibility; the server does not validate or re-encode.
//! 3. **Playback object download** has no API yet: `transport/http.rs` is outside this task's write scope (see the GAP report);
//!    the existing `/v1/media/recordings/{id}/download` still only 302s to the raw `.bin`; playback objects must be
//!    fetched directly via the object-storage key (manifest `playback.object_key`), or the API layer can add
//!    `playback_url` later. **The manifest API already exposes all `playback` metadata**.
//! 4. **Lifecycle reclamation** is not wired (`jobs.rs` is outside the write scope): muxing outputs under the `media/playback/` prefix
//!    are currently not deleted by recording GC (segments/manifests are), recorded as a known GAP.
//! 5. The playback Envelope is pushed only to **online devices on this node** at both ends (cross-node media signaling already has route/broadcast
//!    forwarding; playback messages are not cross-node; offline devices get no redelivery — consistent with stream-sig transient semantics).
//! 6. The reserved `media_recordings.codec/format` columns are not written (`store/pg.rs` is outside the write scope).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::state::AppState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Playback manifest/envelope structure version (increment only on breaking changes).
pub const PLAYBACK_VERSION: u32 = 1;
/// Format name of the playable container (manifest `format` / `playback.format`).
pub const PLAYBACK_FORMAT_OGG_OPUS: &str = "ogg-opus";
/// Valid offer `record_format` value (the only supported explicit opt-in; same value as [`PLAYBACK_FORMAT_OGG_OPUS`]).
pub const RECORD_FORMAT_OGG_OPUS: &str = "ogg-opus";
/// Opus codec normalization value.
pub const PLAYBACK_CODEC_OPUS: &str = "opus";
/// `type` of the playback envelope.
pub const PLAYBACK_ENVELOPE_TYPE: &str = "media-playback";
/// Muxing output object prefix: `media/playback/record/{stream_id}/{...}.ogg`.
///
/// **Separate tree** from `media/record/` (segments) and `media/manifest/record/` (frame index manifests):
/// existing E2E counts objects by prefix, and mixing them would change those conventions; the manifest API locates by deterministic key.
pub const PLAYBACK_PREFIX: &str = "media/playback/record/";

/// Codec hint retention: recording flush may lag after bye (idle flush 2s / durable consumer
/// redelivery), so hints are not deleted at bye; TTL + capacity caps converge them (in-process, lock-free hot path).
const HINT_TTL: Duration = Duration::from_secs(600);
const HINT_MAX_STREAMS: usize = 4096;
/// Opus decoding sample rate (RFC 7845: Opus is always 48kHz internally; granule counts at 48kHz).
const OPUS_RATE: u32 = 48_000;
/// At most 255 lacing segments per OGG page (RFC 3533) → packet cap 255*255 bytes/page.
const OGG_MAX_PAGE_PACKET: usize = 255 * 255;
/// OpusHead pre-skip: what is recorded are packets **mid-stream** (encoder delay unknown), so write 0 truthfully (no faking
/// encoder delay; players will drop leading samples per 0).
pub const OPUS_PRE_SKIP: u16 = 0;

// ---------------------------------------------------------------------------
// Codec hints (carried by the offer; used for recording muxing)
// ---------------------------------------------------------------------------

/// Normalized codec hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecHint {
    /// Normalized codec name (`opus`, etc.; unknown values are kept as lowercase originals).
    pub codec: String,
    /// Original sample rate (OpusHead's input sample rate field; Opus decoding is always 48kHz).
    pub sample_rate: u32,
    /// Channel count (1/2).
    pub channels: u8,
}

impl CodecHint {
    /// Whether this is OGG Opus muxing supported by this module.
    pub fn is_opus(&self) -> bool {
        self.codec == PLAYBACK_CODEC_OPUS
    }
}

/// Normalize the offer's `record_format/codec/sample_rate/channels` into [`CodecHint`].
///
/// - `Ok(None)`: the offer has no `record_format` (explicit opt-in) → no muxing; `codec` is pass-through metadata only
///   (the existing clients'/E2E's `codec:"opus"` triggers no recording behavior change);
/// - `Ok(Some(hint))`: valid opt-in (support is decided by [`CodecHint::is_opus`]);
/// - `Err(gap)`: invalid opt-in value / out-of-range parameter → the manifest records an explicit `playback_gap` when recording.
pub fn codec_hint_from_fields(
    record_format: Option<&str>,
    codec: Option<&str>,
    sample_rate: Option<u32>,
    channels: Option<u8>,
) -> Result<Option<CodecHint>, PlaybackGap> {
    let Some(fmt) = record_format.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let declared_codec = codec
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(normalize_codec);
    if !fmt.eq_ignore_ascii_case(RECORD_FORMAT_OGG_OPUS) {
        return Err(PlaybackGap::new(
            "record_format_not_supported",
            declared_codec,
            Some(format!(
                "record_format `{fmt}` is not supported (only `{RECORD_FORMAT_OGG_OPUS}`)"
            )),
        ));
    }
    let normalized = declared_codec.unwrap_or_else(|| PLAYBACK_CODEC_OPUS.to_string());
    let rate = sample_rate.unwrap_or(OPUS_RATE);
    let ch = channels.unwrap_or(1);
    if !(8_000..=OPUS_RATE).contains(&rate) {
        return Err(PlaybackGap::new(
            "codec_hint_invalid",
            Some(normalized),
            Some(format!("sample_rate {rate} out of range 8000..=48000")),
        ));
    }
    if !(1..=2).contains(&ch) {
        return Err(PlaybackGap::new(
            "codec_hint_invalid",
            Some(normalized),
            Some(format!("channels {ch} out of range 1..=2")),
        ));
    }
    Ok(Some(CodecHint {
        codec: normalized,
        sample_rate: rate,
        channels: ch,
    }))
}

fn normalize_codec(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    match lower.as_str() {
        "opus" | "audio/opus" | "audio/ogg" | "ogg-opus" | "audio/ogg;codecs=opus" => {
            PLAYBACK_CODEC_OPUS.to_string()
        }
        _ => lower,
    }
}

// ---------------------------------------------------------------------------
// Hint registry (in-process; by design the ingress node is the recording node, see the recording conventions in media.rs)
// ---------------------------------------------------------------------------

/// Parse result for one stream at offer time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintState {
    /// The offer explicitly carried no codec hint → no muxing.
    None,
    /// Hint is valid (`Known.is_opus()` decides whether muxing is possible).
    Known(CodecHint),
    /// Hint is invalid (e.g. channels=5) → record an explicit GAP.
    Invalid(PlaybackGap),
}

#[derive(Debug, Clone)]
struct HintEntry {
    hint: HintState,
    /// `(user, device)` at both ends of the offer: push targets for the playback Envelope (online devices on this node only).
    participants: Vec<(String, String)>,
    at: Instant,
}

fn registry() -> &'static Mutex<HashMap<String, HintEntry>> {
    static REG: OnceLock<Mutex<HashMap<String, HintEntry>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_registry() -> std::sync::MutexGuard<'static, HashMap<String, HintEntry>> {
    match registry().lock() {
        Ok(g) => g,
        Err(poisoned) => {
            // One bad entry must not poison the whole hint table (recording is a side path): clear the poisoning and continue.
            let mut guard = poisoned.into_inner();
            guard.clear();
            guard
        }
    }
}

/// Record a stream's offer hints and participants (called by the `action=offer` branch of `media.rs::on_signal`).
///
/// An empty `participants` means "update hints only, leave known participants untouched" (defensive; a normal offer always has both ends).
pub fn remember_signal(
    stream_id: &str,
    hint: HintState,
    participants: &[(String, String)],
) {
    let now = Instant::now();
    let mut reg = lock_registry();
    // Capacity/TTL convergence: clear expired entries first, then drop the oldest when still over the cap (losing a hint only degrades to no muxing, never affects recording).
    reg.retain(|_, e| now.duration_since(e.at) < HINT_TTL);
    if reg.len() >= HINT_MAX_STREAMS && !reg.contains_key(stream_id) {
        if let Some(oldest) = reg
            .iter()
            .min_by_key(|(_, e)| e.at)
            .map(|(k, _)| k.clone())
        {
            reg.remove(&oldest);
        }
    }
    let entry = reg.entry(stream_id.to_string()).or_insert_with(|| HintEntry {
        hint: HintState::None,
        participants: Vec::new(),
        at: now,
    });
    entry.hint = hint;
    entry.at = now;
    if !participants.is_empty() {
        entry.participants = participants.to_vec();
    }
}

/// Fetch a stream's hint state (None = the stream never had offer hints / expired).
pub fn hint_for(stream_id: &str) -> Option<HintState> {
    let reg = lock_registry();
    reg.get(stream_id).map(|e| e.hint.clone())
}

/// Fetch the offer participants at both ends (push targets for the playback Envelope).
pub fn participants_for(stream_id: &str) -> Vec<(String, String)> {
    let reg = lock_registry();
    reg.get(stream_id)
        .map(|e| e.participants.clone())
        .unwrap_or_default()
}

/// Clear the registry (for unit tests; not needed at runtime — TTL/capacity caps converge it).
#[cfg(test)]
pub fn clear_registry() {
    lock_registry().clear();
}

// ---------------------------------------------------------------------------
// Explicit GAP / result types
// ---------------------------------------------------------------------------

/// **Explicit GAP** when muxing does not succeed (written into the manifest's `playback_gap`; never fakes playability).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlaybackGap {
    /// Machine-readable reason:
    /// `codec_not_supported` / `codec_hint_invalid` / `empty_segment` /
    /// `opus_packet_invalid` / `opus_packet_too_large` / `playback_write_failed` /
    /// `envelope_write_failed`.
    pub reason: String,
    /// Codec declared by the client (after normalization; null if none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codec: Option<String>,
    /// Human-readable detail (frame number/reason; no payload).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl PlaybackGap {
    pub fn new(reason: &str, codec: Option<String>, detail: Option<String>) -> Self {
        Self {
            reason: reason.to_string(),
            codec,
            detail,
        }
    }
}

/// Playback muxing result (consumed by `routing/media_record.rs::write_segment_manifest`).
#[derive(Debug)]
pub enum PlaybackOutcome {
    /// The stream has no codec hint (v0.18 behavior: raw-frames, no new manifest fields).
    NotRequested,
    /// Muxing succeeded: the OGG Opus object + playback envelope are persisted.
    Packaged(Box<PlaybackArtifact>),
    /// Muxing is not feasible: the manifest records an explicit GAP (never fakes playability).
    Gap(PlaybackGap),
}

/// Muxing output (used for the manifest `playback` field + WS Envelope push).
#[derive(Debug)]
pub struct PlaybackArtifact {
    /// `playback` metadata written into the manifest (including the inline envelope).
    pub info: PlaybackInfo,
    /// Serialized `lattice_core::Envelope` protobuf (WS `envelope` frame body).
    pub envelope_pb: Vec<u8>,
}

/// `playback` metadata in the manifest (complete location info for the playable container; no payload).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlaybackInfo {
    /// `"ogg-opus"`.
    pub format: &'static str,
    /// `"opus"`.
    pub codec: &'static str,
    /// Always `true` (this structure is written only when OGG muxing truly completes).
    pub playable: bool,
    /// Muxing output object key (`media/playback/record/.../*.ogg`).
    pub object_key: String,
    /// Bucket containing the object (= the recording bucket).
    pub bucket: String,
    /// Container byte size.
    pub bytes: usize,
    /// Opus packet count in the container (= frame count in the segment).
    pub frames: usize,
    /// Total decoded sample count (48kHz).
    pub sample_count: u32,
    /// Duration (milliseconds, converted from the 48kHz sample count; rounded down).
    pub duration_ms: u64,
    /// OpusHead's original sample rate field (informational).
    pub sample_rate: u32,
    /// OpusHead's channel count.
    pub channels: u8,
    /// OpusHead pre-skip (recording a mid-stream, truthfully 0).
    pub pre_skip: u16,
    /// OGG logical stream serial (deterministically derived from the segment object key → replay overwrites with identical bytes).
    pub ogg_serial: u32,
    /// Playback envelope message object key (`.../*.playback.json`).
    pub envelope_key: String,
    /// Inline playback envelope (the client can get the playback message from the manifest without a second object fetch).
    pub envelope: PlaybackEnvelope,
}

/// JSON structure of the playback envelope (`type="media-playback"`).
///
/// Persisted as a JSON object under a deterministic key and inlined in the manifest's `playback.envelope`;
/// additionally pushed to online devices at both ends as a `lattice_core::Envelope` (protobuf, type=`media`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlaybackEnvelope {
    pub version: u32,
    /// Always `"media-playback"`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// Deterministic ULID (derived from the segment object key + created_at; replay yields the same id → idempotent).
    pub id: String,
    pub stream_id: String,
    pub node_id: String,
    /// Object key of the muxed source segment (`media/record/...bin`).
    pub segment_object_key: String,
    /// Playback manifest object key for that segment.
    pub manifest_key: String,
    /// Playable container object key.
    pub playback_object_key: String,
    pub format: &'static str,
    pub codec: &'static str,
    pub playable: bool,
    pub bytes: usize,
    pub frames: usize,
    pub sample_count: u32,
    pub duration_ms: u64,
    pub sample_rate: u32,
    pub channels: u8,
    pub pre_skip: u16,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Object keys (deterministic derivation; replay overwrites the same object → idempotent)
// ---------------------------------------------------------------------------

/// "Stem" of a segment object key: `media/record/{stream}/{node}/{seg}.bin` → `{stream}/{node}/{seg}`.
fn object_stem(object_key: &str) -> &str {
    let stripped = object_key
        .strip_prefix("media/record/")
        .unwrap_or(object_key);
    stripped.strip_suffix(".bin").unwrap_or(stripped)
}

/// Playable container object key: `media/playback/record/{stem}.ogg`.
pub fn playback_object_key(segment_object_key: &str) -> String {
    format!("{PLAYBACK_PREFIX}{}.ogg", object_stem(segment_object_key))
}

/// Playback envelope message object key: `media/playback/record/{stem}.playback.json`.
pub fn playback_envelope_key(segment_object_key: &str) -> String {
    format!(
        "{PLAYBACK_PREFIX}{}.playback.json",
        object_stem(segment_object_key)
    )
}

/// OGG logical stream serial: FNV-1a of the segment object key (deterministic → identical bytes on replay).
fn deterministic_serial(segment_object_key: &str) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for b in segment_object_key.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    // 0 is also valid (it is just a serial); no special handling.
    hash
}

/// Deterministic ULID (48-bit millisecond timestamp + 80-bit content hash): replaying the same segment → the same envelope id.
fn deterministic_ulid(segment_object_key: &str, created_at: DateTime<Utc>) -> String {
    const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let ms = created_at.timestamp_millis().max(0) as u64;
    // 80-bit tail: first 10 bytes of sha256(object_key) (deterministic; not used for security).
    let digest = lattice_core::envelope::sha256_hex(segment_object_key.as_bytes());
    let mut bytes = [0u8; 16];
    // 48-bit timestamp (big-endian)
    bytes[0] = (ms >> 40) as u8;
    bytes[1] = (ms >> 32) as u8;
    bytes[2] = (ms >> 24) as u8;
    bytes[3] = (ms >> 16) as u8;
    bytes[4] = (ms >> 8) as u8;
    bytes[5] = ms as u8;
    // 80-bit content hash (big-endian)
    for (i, chunk) in digest.as_bytes().chunks(2).take(10).enumerate() {
        let hi = hex_val(chunk[0]);
        let lo = hex_val(*chunk.get(1).unwrap_or(&b'0'));
        bytes[6 + i] = (hi << 4) | lo;
    }
    // 128-bit big-endian value → encode in 5-bit groups after left-padding to 130 bits (standard ULID Crockford Base32).
    let value = u128::from_be_bytes(bytes);
    let mut out = String::with_capacity(26);
    for i in 0..26u32 {
        let shift = 125i32 - (i as i32) * 5;
        let idx = if shift < 0 {
            0u8
        } else {
            ((value >> shift as u32) & 0x1F) as u8
        };
        out.push(CROCKFORD[idx as usize] as char);
    }
    debug_assert!(
        lattice_core::ids::is_ulid(&out),
        "deterministic ulid invalid: {out}"
    );
    out
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Opus packet structure validation (RFC 6716 §3; frame framing only, no entropy decoding)
// ---------------------------------------------------------------------------

/// Frame duration of one Opus packet (milliseconds, RFC 6716 table 2).
fn opus_config_frame_ms(config: u8) -> f64 {
    match config {
        0 | 4 | 8 => 10.0,
        1 | 5 | 9 => 20.0,
        2 | 6 | 10 => 40.0,
        3 | 7 | 11 => 60.0,
        12 | 14 => 10.0,
        13 | 15 => 20.0,
        16..=31 => match (config - 16) % 4 {
            0 => 2.5,
            1 => 5.0,
            2 => 10.0,
            _ => 20.0,
        },
        _ => 0.0,
    }
}

/// Validate that a payload is **exactly one** Opus packet and return its PCM sample count (48kHz).
///
/// `Err(&'static str)` returns a short machine-readable reason (written into `playback_gap.detail`).
pub fn opus_packet_samples(packet: &[u8]) -> Result<u32, &'static str> {
    if packet.is_empty() {
        return Err("empty_packet");
    }
    let toc = packet[0];
    let config = toc >> 3;
    let code = toc & 0x03;
    let frame_count: u32 = match code {
        0 => 1,
        1 => 2,
        2 => 2,
        _ => {
            if packet.len() < 2 {
                return Err("code3_missing_count");
            }
            let count = (packet[1] & 0x3F) as u32;
            if count == 0 || count > 48 {
                return Err("code3_bad_count");
            }
            count
        }
    };
    validate_opus_framing(packet, code, frame_count)?;
    let frame_ms = opus_config_frame_ms(config);
    if frame_ms <= 0.0 {
        return Err("bad_config");
    }
    // samples = frame_ms(ms) * 48 samples/ms * frame_count
    let samples = (frame_ms * 48.0 * frame_count as f64).round() as u32;
    if samples == 0 {
        return Err("bad_duration");
    }
    Ok(samples)
}

/// Validate that in-packet frame length fields agree with the packet length (RFC 6716 §3.2; framing rules for codes 0/1/2/3).
fn validate_opus_framing(packet: &[u8], code: u8, frame_count: u32) -> Result<(), &'static str> {
    let len = packet.len();
    match code {
        0 => Ok(()),
        1 => {
            // Two equal-length frames: the data after TOC must be >0 and even.
            let data = len - 1;
            if data == 0 || data % 2 != 0 {
                Err("code1_bad_framing")
            } else {
                Ok(())
            }
        }
        2 => {
            // TOC + frame length(1..2 bytes) + two equal-length frames.
            if len < 3 {
                return Err("code2_too_short");
            }
            let (frame_len, header) = parse_opus_frame_len(packet, 1)?;
            let data = len - header;
            if frame_len == 0 || data != frame_len * 2 {
                Err("code2_bad_framing")
            } else {
                Ok(())
            }
        }
        _ => {
            // code 3: frame count + optional padding + (lengths of the first N-1 frames when VBR) + frame data.
            let mut pos = 2usize;
            if len < pos {
                return Err("code3_too_short");
            }
            let mut padding = 0usize;
            if packet[1] & 0x40 != 0 {
                loop {
                    if pos >= len {
                        return Err("code3_bad_padding");
                    }
                    let b = packet[pos];
                    pos += 1;
                    padding += b as usize;
                    if b != 255 {
                        break;
                    }
                }
            }
            if padding > len - pos {
                return Err("code3_bad_padding");
            }
            let data_end = len - padding;
            let vbr = packet[1] & 0x80 != 0;
            let mut declared = 0usize;
            if vbr {
                for _ in 0..frame_count.saturating_sub(1) {
                    let (frame_len, header) = parse_opus_frame_len(packet, pos)?;
                    pos = header;
                    declared = declared.saturating_add(frame_len);
                    if pos > data_end {
                        return Err("code3_bad_vbr_len");
                    }
                }
            }
            let data = data_end.saturating_sub(pos);
            if data == 0 {
                return Err("code3_empty_data");
            }
            if vbr {
                if declared >= data {
                    return Err("code3_bad_vbr_len");
                }
            } else if data % frame_count as usize != 0 {
                return Err("code3_bad_framing");
            }
            Ok(())
        }
    }
}

/// Parse Opus's 1/2-byte frame length (RFC 6716 §3.2.1): `b<252` → `len=b, next=b+1`;
/// otherwise `len=b+4*next, next=b+2`. Returns `(frame_len, next byte position)`.
fn parse_opus_frame_len(packet: &[u8], at: usize) -> Result<(usize, usize), &'static str> {
    let Some(&b0) = packet.get(at) else {
        return Err("frame_len_missing");
    };
    if b0 < 252 {
        return Ok((b0 as usize, at + 1));
    }
    let Some(&b1) = packet.get(at + 1) else {
        return Err("frame_len_missing");
    };
    Ok((b0 as usize + 4 * b1 as usize, at + 2))
}

// ---------------------------------------------------------------------------
// OGG muxing (RFC 3533 pages + RFC 7845 Opus headers)
// ---------------------------------------------------------------------------

const OGG_CRC_POLY: u32 = 0x04C1_1DB7;

const fn make_ogg_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut r = (i as u32) << 24;
        let mut j = 0;
        while j < 8 {
            r = if r & 0x8000_0000 != 0 {
                (r << 1) ^ OGG_CRC_POLY
            } else {
                r << 1
            };
            j += 1;
        }
        table[i] = r;
        i += 1;
    }
    table
}

static OGG_CRC_TABLE: [u32; 256] = make_ogg_crc_table();

/// OGG page CRC-32 (poly 0x04C11DB7, init 0, no reflection, xorout 0; RFC 3533 §6).
pub fn ogg_crc32(data: &[u8]) -> u32 {
    let mut crc = 0u32;
    for &b in data {
        crc = (crc << 8) ^ OGG_CRC_TABLE[(((crc >> 24) as u8) ^ b) as usize];
    }
    crc
}

/// Write one OGG page containing exactly one packet.
///
/// - `header_type`: 0x02=BOS, 0x04=EOS, 0=normal;
/// - `granule`: PCM sample position at packet end (48kHz; 0 for BOS/header pages);
/// - returns `Err("packet_too_large")` when a single packet exceeds 255*255 bytes (this module does not split packets across pages — normal Opus
///   packets are far below that cap, and an oversized "payload" could not have been a valid Opus packet anyway).
fn write_ogg_page(
    out: &mut Vec<u8>,
    header_type: u8,
    granule: u64,
    serial: u32,
    seq: u32,
    packet: &[u8],
) -> Result<(), &'static str> {
    if packet.len() > OGG_MAX_PAGE_PACKET {
        return Err("packet_too_large");
    }
    // lacing: one 255 per 255 bytes; tail &lt;255 (append a 0 when exactly a multiple of 255).
    let mut lacing: Vec<u8> = Vec::with_capacity(packet.len() / 255 + 1);
    let mut rem = packet.len();
    while rem >= 255 {
        lacing.push(255);
        rem -= 255;
    }
    lacing.push(rem as u8);
    if lacing.len() > 255 {
        return Err("packet_too_large");
    }
    let start = out.len();
    out.extend_from_slice(b"OggS");
    out.push(0); // version
    out.push(header_type);
    out.extend_from_slice(&granule.to_le_bytes());
    out.extend_from_slice(&serial.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]); // CRC placeholder
    out.push(lacing.len() as u8);
    out.extend_from_slice(&lacing);
    out.extend_from_slice(packet);
    let crc = ogg_crc32(&out[start..]);
    let crc_off = start + 22;
    out[crc_off..crc_off + 4].copy_from_slice(&crc.to_le_bytes());
    Ok(())
}

/// Muxing output (internal structure; tests and E2E use its fields to check the container).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OggOpusFile {
    /// Complete OGG Opus file bytes.
    pub bytes: Vec<u8>,
    /// Number of audio packets.
    pub packets: usize,
    /// Total decoded sample count (48kHz).
    pub sample_count: u32,
    /// Duration (milliseconds, `sample_count/48` rounded down).
    pub duration_ms: u64,
    /// Logical stream serial.
    pub serial: u32,
    /// pre-skip (always [`OPUS_PRE_SKIP`]).
    pub pre_skip: u16,
}

/// Losslessly mux the raw frame payloads of a recording segment into OGG Opus.
///
/// `segment` is the `[4B BE len][stream-data body]...` container (`routing/media.rs` recording format);
/// this takes only each frame's payload (skipping the `[ver][flags][stream_id]` header), validates each packet's Opus structure, and writes
/// OGG pages. **No transcoding, no re-encoding, no payload byte changes**.
///
/// When `Err(PlaybackGap)` is returned, the manifest records an explicit GAP (no "playable" artifact is produced).
pub fn mux_ogg_opus(
    segment_object_key: &str,
    stream_id: &str,
    segment: &[u8],
    hint: &CodecHint,
) -> Result<OggOpusFile, PlaybackGap> {
    let gap = |reason: &str, detail: String| PlaybackGap::new(reason, Some(hint.codec.clone()), Some(detail));
    let mut payloads: Vec<&[u8]> = Vec::new();
    let mut off = 0usize;
    while off + 4 <= segment.len() {
        let len = u32::from_be_bytes([
            segment[off],
            segment[off + 1],
            segment[off + 2],
            segment[off + 3],
        ]) as usize;
        off += 4;
        if len > segment.len() - off {
            return Err(gap(
                "opus_packet_invalid",
                format!("frame {}: truncated length prefix", payloads.len()),
            ));
        }
        let body = &segment[off..off + len];
        off += len;
        let parsed = crate::routing::media::parse_data_body(body).map_err(|e| {
            gap(
                "opus_packet_invalid",
                format!("frame {}: bad stream-data header: {e}", payloads.len()),
            )
        })?;
        if parsed.stream_id != stream_id {
            return Err(gap(
                "opus_packet_invalid",
                format!(
                    "frame {}: stream_id mismatch ({} vs {stream_id})",
                    payloads.len(),
                    parsed.stream_id
                ),
            ));
        }
        payloads.push(parsed.payload);
    }
    if payloads.is_empty() {
        return Err(gap("empty_segment", "segment has no frames".to_string()));
    }
    // Per-packet structure validation + sample accumulation (validate first; any invalid frame means no container is produced).
    let mut sample_count: u64 = 0;
    for (idx, payload) in payloads.iter().enumerate() {
        let samples = opus_packet_samples(payload).map_err(|reason| {
            gap(
                "opus_packet_invalid",
                format!("frame {idx}: {reason} (len={})", payload.len()),
            )
        })?;
        sample_count += samples as u64;
    }
    if sample_count == 0 || sample_count > u32::MAX as u64 {
        return Err(gap("opus_packet_invalid", "invalid total duration".to_string()));
    }
    let sample_count = sample_count as u32;

    let serial = deterministic_serial(segment_object_key);
    let mut out = Vec::with_capacity(
        payloads.iter().map(|p| p.len() + 64).sum::<usize>() + 256,
    );
    let mut seq = 0u32;
    // Page 0: OpusHead (BOS, granule=0)
    let mut head = Vec::with_capacity(19);
    head.extend_from_slice(b"OpusHead");
    head.push(1); // version
    head.push(hint.channels);
    head.extend_from_slice(&OPUS_PRE_SKIP.to_le_bytes());
    head.extend_from_slice(&hint.sample_rate.to_le_bytes());
    head.extend_from_slice(&0i16.to_le_bytes()); // output gain
    head.push(0); // mapping family 0 (mono/stereo)
    write_ogg_page(&mut out, 0x02, 0, serial, seq, &head).map_err(|e| {
        gap("opus_packet_invalid", format!("OpusHead page: {e}"))
    })?;
    seq += 1;
    // Page 1: OpusTags (vendor=lattice-node, no user comments)
    let vendor = b"lattice-node";
    let mut tags = Vec::with_capacity(8 + 4 + vendor.len() + 4);
    tags.extend_from_slice(b"OpusTags");
    tags.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    tags.extend_from_slice(vendor);
    tags.extend_from_slice(&0u32.to_le_bytes());
    write_ogg_page(&mut out, 0, 0, serial, seq, &tags)
        .map_err(|e| gap("opus_packet_invalid", format!("OpusTags page: {e}")))?;
    seq += 1;
    // Audio pages: one packet per page (granule = cumulative samples through that packet's end; EOS on the last packet).
    let mut cumulative: u64 = 0;
    for (idx, payload) in payloads.iter().enumerate() {
        let samples = opus_packet_samples(payload)
            .map_err(|reason| gap("opus_packet_invalid", format!("frame {idx}: {reason}")))?;
        cumulative += samples as u64;
        let is_last = idx + 1 == payloads.len();
        let header_type = if is_last { 0x04 } else { 0x00 };
        if let Err(e) = write_ogg_page(&mut out, header_type, cumulative, serial, seq, payload) {
            return Err(gap(
                "opus_packet_too_large",
                format!("frame {idx}: {e} (len={})", payload.len()),
            ));
        }
        seq += 1;
    }
    Ok(OggOpusFile {
        bytes: out,
        packets: payloads.len(),
        sample_count,
        duration_ms: (sample_count as u64) * 1000 / OPUS_RATE as u64,
        serial,
        pre_skip: OPUS_PRE_SKIP,
    })
}

// ---------------------------------------------------------------------------
// Muxing + playback Envelope persistence
// ---------------------------------------------------------------------------

/// Mux one segment (called by `routing/media_record.rs::write_segment_manifest`).
///
/// Flow (all best-effort; failures only return a GAP and **never affect already-persisted segments/manifests/indexes**):
/// 1. Read the stream's codec hint (no hint → [`PlaybackOutcome::NotRequested`], behavior same as v0.18);
/// 2. non-opus / invalid hint / invalid packet structure → [`PlaybackOutcome::Gap`] (the manifest states it truthfully);
/// 3. `mux_ogg_opus` → write `...ogg` → build the playback envelope → write `...playback.json` →
///    return [`PlaybackOutcome::Packaged`].
#[allow(clippy::too_many_arguments)]
pub async fn package_segment(
    state: &AppState,
    bucket: &str,
    stream_id: &str,
    segment_object_key: &str,
    manifest_key: &str,
    segment: &[u8],
    created_at: DateTime<Utc>,
) -> PlaybackOutcome {
    let Some(state_hint) = hint_for(stream_id) else {
        return PlaybackOutcome::NotRequested;
    };
    let hint = match state_hint {
        HintState::None => return PlaybackOutcome::NotRequested,
        HintState::Invalid(gap) => return PlaybackOutcome::Gap(gap),
        HintState::Known(hint) => hint,
    };
    if !hint.is_opus() {
        return PlaybackOutcome::Gap(PlaybackGap::new(
            "codec_not_supported",
            Some(hint.codec.clone()),
            Some(format!(
                "codec `{}` is not supported by the built-in muxer (only `opus` -> ogg-opus)",
                hint.codec
            )),
        ));
    }
    let ogg = match mux_ogg_opus(segment_object_key, stream_id, segment, &hint) {
        Ok(f) => f,
        Err(gap) => return PlaybackOutcome::Gap(gap),
    };
    let object_key = playback_object_key(segment_object_key);
    if let Err(e) = state.s3.put_bytes(bucket, &object_key, &ogg.bytes).await {
        tracing::warn!(
            stream_id,
            key = %object_key,
            bytes = ogg.bytes.len(),
            error = %e,
            "media playback container write failed (playback skipped; segment/manifest unaffected)"
        );
        return PlaybackOutcome::Gap(PlaybackGap::new(
            "playback_write_failed",
            Some(hint.codec.clone()),
            Some(format!("object store put failed: {e}")),
        ));
    }

    let envelope = PlaybackEnvelope {
        version: PLAYBACK_VERSION,
        kind: PLAYBACK_ENVELOPE_TYPE,
        id: deterministic_ulid(segment_object_key, created_at),
        stream_id: stream_id.to_string(),
        node_id: state.node_id.clone(),
        segment_object_key: segment_object_key.to_string(),
        manifest_key: manifest_key.to_string(),
        playback_object_key: object_key.clone(),
        format: PLAYBACK_FORMAT_OGG_OPUS,
        codec: PLAYBACK_CODEC_OPUS,
        playable: true,
        bytes: ogg.bytes.len(),
        frames: ogg.packets,
        sample_count: ogg.sample_count,
        duration_ms: ogg.duration_ms,
        sample_rate: hint.sample_rate,
        channels: hint.channels,
        pre_skip: ogg.pre_skip,
        created_at,
    };
    let envelope_key = playback_envelope_key(segment_object_key);
    let envelope_json = match serde_json::to_vec(&envelope) {
        Ok(v) => v,
        Err(e) => {
            // Theoretically impossible (all fields are serializable); defensively clean up the written container to avoid orphan objects.
            let _ = state.s3.delete_object(bucket, &object_key).await;
            tracing::warn!(stream_id, error = %e, "media playback envelope serialize failed");
            return PlaybackOutcome::Gap(PlaybackGap::new(
                "envelope_write_failed",
                Some(hint.codec.clone()),
                Some(format!("serialize failed: {e}")),
            ));
        }
    };
    if let Err(e) = state
        .s3
        .put_bytes(bucket, &envelope_key, &envelope_json)
        .await
    {
        let _ = state.s3.delete_object(bucket, &object_key).await;
        tracing::warn!(
            stream_id,
            key = %envelope_key,
            error = %e,
            "media playback envelope write failed (playback skipped)"
        );
        return PlaybackOutcome::Gap(PlaybackGap::new(
            "envelope_write_failed",
            Some(hint.codec.clone()),
            Some(format!("object store put failed: {e}")),
        ));
    }

    // WS playback Envelope: `lattice_core::Envelope` (type=media; event=playback.ready).
    let mut metadata = HashMap::new();
    metadata.insert("event".to_string(), "playback.ready".to_string());
    metadata.insert("stream_id".to_string(), stream_id.to_string());
    metadata.insert("format".to_string(), PLAYBACK_FORMAT_OGG_OPUS.to_string());
    metadata.insert("codec".to_string(), PLAYBACK_CODEC_OPUS.to_string());
    metadata.insert("playable".to_string(), "true".to_string());
    metadata.insert("playback_object_key".to_string(), object_key.clone());
    metadata.insert("manifest_key".to_string(), manifest_key.to_string());
    let pb_envelope = lattice_core::Envelope {
        id: envelope.id.clone(),
        r#type: "media".to_string(),
        content_type: "application/vnd.lattice.media-playback+json".to_string(),
        encoding: "utf8".to_string(),
        metadata,
        payload: envelope_json,
        created_at: envelope.created_at.timestamp().max(0) as u64,
        sender: String::new(),
        conv_id: format!("stream:{stream_id}"),
        ..Default::default()
    };
    let envelope_pb = pb_envelope.encode_body();

    tracing::info!(
        stream_id,
        key = %object_key,
        envelope_key = %envelope_key,
        bytes = ogg.bytes.len(),
        frames = ogg.packets,
        duration_ms = ogg.duration_ms,
        sample_rate = hint.sample_rate,
        channels = hint.channels,
        "media playback container packaged (ogg-opus)"
    );
    PlaybackOutcome::Packaged(Box::new(PlaybackArtifact {
        info: PlaybackInfo {
            format: PLAYBACK_FORMAT_OGG_OPUS,
            codec: PLAYBACK_CODEC_OPUS,
            playable: true,
            object_key,
            bucket: bucket.to_string(),
            bytes: ogg.bytes.len(),
            frames: ogg.packets,
            sample_count: ogg.sample_count,
            duration_ms: ogg.duration_ms,
            sample_rate: hint.sample_rate,
            channels: hint.channels,
            pre_skip: ogg.pre_skip,
            ogg_serial: ogg.serial,
            envelope_key,
            envelope,
        },
        envelope_pb,
    }))
}

/// Push the playback Envelope to **online devices on this node** at both ends of the stream; returns the number of devices successfully enqueued.
///
/// Transient semantics same as `stream-sig`: offline target/queue full → drop (no pending, no redelivery).
pub fn broadcast_envelope(state: &AppState, stream_id: &str, envelope_pb: &[u8]) -> usize {
    let participants = participants_for(stream_id);
    if participants.is_empty() {
        tracing::debug!(stream_id, "media playback envelope: no participants recorded; not pushed");
        return 0;
    }
    let frame = lattice_core::Frame::new(
        lattice_core::WsCommand::Envelope,
        bytes::Bytes::copy_from_slice(envelope_pb),
    );
    let mut sent = 0usize;
    for (user, device) in &participants {
        if state.hub.send_to_device(user, device, frame.clone()) {
            sent += 1;
        }
    }
    tracing::debug!(
        stream_id,
        sent,
        total = participants.len(),
        "media playback envelope pushed to stream participants"
    );
    sent
}

// ===========================================================================
// Unit tests: Opus structure validation / OGG container structure / key determinism / hint normalization / GAP conventions
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a structurally valid Opus code-0 packet (config 15 = Hybrid FB 20ms; 20ms*48=960 samples).
    fn opus_code0(payload_len: usize) -> Vec<u8> {
        let mut p = vec![0x78u8]; // TOC: config=15, stereo=0, code=0
        p.extend(std::iter::repeat(0xAAu8).take(payload_len));
        p
    }

    fn data_body(id: &str, payload: &[u8]) -> Vec<u8> {
        let id = id.as_bytes();
        let mut body = vec![1u8, 0u8, (id.len() >> 8) as u8, (id.len() & 0xff) as u8];
        body.extend_from_slice(id);
        body.extend_from_slice(payload);
        body
    }

    fn segment_of(id: &str, payloads: &[Vec<u8>]) -> Vec<u8> {
        let mut seg = Vec::new();
        for p in payloads {
            let body = data_body(id, p);
            seg.extend_from_slice(&(body.len() as u32).to_be_bytes());
            seg.extend_from_slice(&body);
        }
        seg
    }

    fn hint() -> CodecHint {
        CodecHint {
            codec: PLAYBACK_CODEC_OPUS.to_string(),
            sample_rate: OPUS_RATE,
            channels: 1,
        }
    }

    // ---- Opus packet structure (RFC 6716 §3)----

    #[test]
    fn opus_duration_table_matches_spec() {
        // config 15 = Hybrid FB 20ms
        assert_eq!(opus_packet_samples(&opus_code0(10)).unwrap(), 960);
        // config 16 = CELT NB 2.5ms
        let mut p = opus_code0(1);
        p[0] = 16 << 3;
        assert_eq!(opus_packet_samples(&p).unwrap(), 120);
        // config 3 = SILK NB 60ms
        p[0] = 3 << 3;
        assert_eq!(opus_packet_samples(&p).unwrap(), 2880);
        // code 1 → two frames
        p[0] = (15 << 3) | 0x01;
        let mut two = vec![p[0]];
        two.extend(std::iter::repeat(0x11u8).take(4));
        assert_eq!(opus_packet_samples(&two).unwrap(), 1920);
        // code 3 → 3 20ms frames (non-VBR: 6 data bytes after TOC+count, 2 bytes per frame)
        let mut three = vec![(15u8 << 3) | 0x03, 3u8];
        three.extend(std::iter::repeat(0x22u8).take(6));
        assert_eq!(three.len(), 8);
        assert_eq!(opus_packet_samples(&three).unwrap(), 2880);
    }

    #[test]
    fn opus_rejects_bad_framing() {
        assert!(opus_packet_samples(&[]).is_err());
        // code 1 odd length
        let mut odd = vec![(15u8 << 3) | 1, 1, 2, 3];
        assert_eq!(opus_packet_samples(&odd), Err("code1_bad_framing"));
        // code 2 frame length mismatch
        let bad2 = vec![(15u8 << 3) | 2, 5, 1, 2, 3, 4];
        assert!(opus_packet_samples(&bad2).is_err());
        odd.clear();
        // code 3 (low 2 TOC bits = 0b11) count=0 → invalid
        assert_eq!(
            opus_packet_samples(&[0x7B, 0x00]),
            Err("code3_bad_count")
        );
    }

    #[test]
    fn opus_accepts_vbr_code3() {
        // code3 VBR 2 frames: count=2, VBR=1, padding=0; frame 0 length 3, frame 1 the remaining 4 bytes
        let mut p = vec![(15u8 << 3) | 0x03, 0x02 | 0x80, 3u8];
        p.extend(std::iter::repeat(0x33u8).take(3 + 4));
        assert_eq!(opus_packet_samples(&p).unwrap(), 1920);
    }

    // ---- OGG container structure ----

    /// Test parser (field reads **independent of the muxing implementation**, used to check the written bytes).
    fn parse_ogg(bytes: &[u8]) -> Vec<(u8, u64, u32, u32, Vec<u8>)> {
        let mut pages = Vec::new();
        let mut off = 0usize;
        while off < bytes.len() {
            assert_eq!(&bytes[off..off + 4], b"OggS", "bad page magic");
            let htype = bytes[off + 5];
            let granule = u64::from_le_bytes(bytes[off + 6..off + 14].try_into().unwrap());
            let serial = u32::from_le_bytes(bytes[off + 14..off + 18].try_into().unwrap());
            let seq = u32::from_le_bytes(bytes[off + 18..off + 22].try_into().unwrap());
            let crc = u32::from_le_bytes(bytes[off + 22..off + 26].try_into().unwrap());
            let nseg = bytes[off + 26] as usize;
            let lacing = &bytes[off + 27..off + 27 + nseg];
            let body_len: usize = lacing.iter().map(|&l| l as usize).sum();
            let body_off = off + 27 + nseg;
            let body = bytes[body_off..body_off + body_len].to_vec();
            // Recompute CRC (zero the page header CRC field first).
            let mut page = bytes[off..body_off + body_len].to_vec();
            page[22..26].fill(0);
            assert_eq!(ogg_crc32(&page), crc, "page {seq} crc mismatch");
            pages.push((htype, granule, serial, seq, body));
            off = body_off + body_len;
        }
        pages
    }

    #[test]
    fn ogg_crc_matches_reference_page() {
        // Real OGG Opus first-page (OpusHead) bytes and CRC generated by ffmpeg 9.0.2, as an independent vector.
        let hex = "4f676753000200000000000000005942e402000000005916531d01134f707573486561640101380180bb0000000000";
        let mut page = Vec::new();
        for chunk in hex.as_bytes().chunks(2) {
            page.push(u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap());
        }
        let expect = u32::from_le_bytes(page[22..26].try_into().unwrap());
        page[22..26].fill(0);
        assert_eq!(ogg_crc32(&page), expect);
    }

    #[test]
    fn muxes_packets_into_valid_ogg_opus() {
        let payloads: Vec<Vec<u8>> = (0..12).map(|i| opus_code0(20 + i)).collect();
        let seg = segment_of("st-ogg", &payloads);
        let out = mux_ogg_opus("media/record/st-ogg/node-a/00042.bin", "st-ogg", &seg, &hint())
            .expect("mux should succeed");
        assert_eq!(out.packets, 12);
        assert_eq!(out.sample_count, 12 * 960);
        assert_eq!(out.duration_ms, 240);
        assert_eq!(&out.bytes[..4], b"OggS");

        let pages = parse_ogg(&out.bytes);
        // OpusHead + OpusTags + 12 audio pages (one packet per page)
        assert_eq!(pages.len(), 14);
        assert_eq!(pages[0].0 & 0x02, 0x02, "the first page must be BOS");
        assert_eq!(pages[0].1, 0);
        assert_eq!(&pages[0].4[..8], b"OpusHead");
        assert_eq!(pages[0].4[8], 1, "OpusHead version");
        assert_eq!(pages[0].4[9], 1, "channels");
        assert_eq!(u16::from_le_bytes([pages[0].4[10], pages[0].4[11]]), 0, "pre_skip=0");
        assert_eq!(
            u32::from_le_bytes([pages[0].4[12], pages[0].4[13], pages[0].4[14], pages[0].4[15]]),
            48_000,
            "input sample rate"
        );
        assert_eq!(&pages[1].4[..8], b"OpusTags");
        // Audio pages: payload bytes identical, granule accumulated, last page EOS
        let mut cumulative = 0u64;
        for (i, page) in pages[2..].iter().enumerate() {
            cumulative += 960;
            assert_eq!(page.1, cumulative, "granule page {i}");
            assert_eq!(&page.4, &payloads[i], "payload bytes preserved");
            let is_last = i + 1 == payloads.len();
            assert_eq!(page.0 & 0x04 != 0, is_last, "EOS flag page {i}");
        }
        // All pages share the same serial, seq is contiguous
        let serial = pages[0].2;
        for (i, page) in pages.iter().enumerate() {
            assert_eq!(page.2, serial);
            assert_eq!(page.3 as usize, i);
        }
    }

    #[test]
    fn ogg_mux_is_deterministic() {
        let payloads = vec![opus_code0(8), opus_code0(9)];
        let seg = segment_of("st-det", &payloads);
        let a = mux_ogg_opus("media/record/st-det/n/1.bin", "st-det", &seg, &hint()).unwrap();
        let b = mux_ogg_opus("media/record/st-det/n/1.bin", "st-det", &seg, &hint()).unwrap();
        assert_eq!(a.bytes, b.bytes, "replaying the same segment must produce a byte-identical container");
        let c = mux_ogg_opus("media/record/st-det/n/2.bin", "st-det", &seg, &hint()).unwrap();
        assert_ne!(a.serial, c.serial, "different segments have different serials (deterministic derivation)");
    }

    #[test]
    fn mux_rejects_non_opus_payloads_with_gap() {
        let seg = segment_of("st-bad", &[vec![0xFFu8; 32]]); // code 1 odd length → invalid structure
        let err = mux_ogg_opus("media/record/st-bad/n/1.bin", "st-bad", &seg, &hint()).unwrap_err();
        assert_eq!(err.reason, "opus_packet_invalid");
        assert_eq!(err.codec.as_deref(), Some("opus"));

        // Empty segment → empty_segment
        let err = mux_ogg_opus("media/record/st-empty/n/1.bin", "st-empty", &[], &hint())
            .unwrap_err();
        assert_eq!(err.reason, "empty_segment");

        // stream_id mismatch → reject (defensive)
        let seg = segment_of("other", &[opus_code0(4)]);
        let err = mux_ogg_opus("media/record/st-mismatch/n/1.bin", "st-mismatch", &seg, &hint())
            .unwrap_err();
        assert_eq!(err.reason, "opus_packet_invalid");
        assert!(err.detail.unwrap_or_default().contains("stream_id mismatch"));
    }

    // ---- key / envelope / hint normalization ----

    #[test]
    fn keys_are_deterministic_and_derived_from_segment_key() {
        let seg = "media/record/st-1/node-a/00000000000000000042.bin";
        assert_eq!(
            playback_object_key(seg),
            "media/playback/record/st-1/node-a/00000000000000000042.ogg"
        );
        assert_eq!(
            playback_envelope_key(seg),
            "media/playback/record/st-1/node-a/00000000000000000042.playback.json"
        );
        assert_eq!(playback_object_key(seg), playback_object_key(seg));
        assert_ne!(
            playback_object_key(seg),
            playback_object_key("media/record/st-1/node-a/00000000000000000043.bin")
        );
    }

    #[test]
    fn deterministic_ulid_is_valid_and_stable() {
        let key = "media/record/st-1/node-a/00000000000000000042.bin";
        let at = DateTime::from_timestamp(1_766_000_000, 0).unwrap();
        let a = deterministic_ulid(key, at);
        let b = deterministic_ulid(key, at);
        assert_eq!(a, b);
        assert_eq!(a.len(), 26);
        assert!(lattice_core::ids::is_ulid(&a), "invalid ulid: {a}");
        assert_eq!(lattice_core::ids::ms_of(&a), Some(1_766_000_000_000));
    }

    #[test]
    fn codec_hint_requires_explicit_record_format_opt_in() {
        // codec only, no record_format → no muxing (existing clients/E2E's codec:"opus" semantics unchanged)
        assert_eq!(
            codec_hint_from_fields(None, Some("opus"), None, None).unwrap(),
            None
        );
        assert!(codec_hint_from_fields(Some("  "), Some("opus"), Some(48000), Some(1))
            .unwrap()
            .is_none());
        // explicit opt-in + opus alias normalization (codec defaults to opus)
        for raw in [
            Some("opus"),
            Some("OPUS"),
            Some("audio/opus"),
            Some("ogg-opus"),
            None,
        ] {
            let h = codec_hint_from_fields(Some("ogg-opus"), raw, None, None)
                .unwrap()
                .unwrap();
            assert!(h.is_opus(), "raw={raw:?}");
            assert_eq!(h.sample_rate, 48_000);
            assert_eq!(h.channels, 1);
        }
        // unsupported record_format → explicit GAP (not faked)
        let g = codec_hint_from_fields(Some("mp4"), Some("h264"), None, None).unwrap_err();
        assert_eq!(g.reason, "record_format_not_supported");
        // opt-in + non-opus codec → hint is valid but "unsupported" (the manifest records codec_not_supported after recording)
        let h = codec_hint_from_fields(Some("ogg-opus"), Some("h264"), Some(48_000), Some(2))
            .unwrap()
            .unwrap();
        assert!(!h.is_opus());
        assert_eq!(h.codec, "h264");
        // invalid parameters → codec_hint_invalid
        let g = codec_hint_from_fields(Some("ogg-opus"), Some("opus"), Some(48000), Some(7))
            .unwrap_err();
        assert_eq!(g.reason, "codec_hint_invalid");
        let g = codec_hint_from_fields(Some("ogg-opus"), None, Some(1), Some(1)).unwrap_err();
        assert_eq!(g.reason, "codec_hint_invalid");
    }

    #[test]
    fn registry_roundtrip_and_participants() {
        clear_registry();
        remember_signal(
            "st-reg",
            HintState::Known(hint()),
            &[
                ("u-a".to_string(), "d-a".to_string()),
                ("u-b".to_string(), "d-b".to_string()),
            ],
        );
        assert_eq!(hint_for("st-reg"), Some(HintState::Known(hint())));
        assert_eq!(participants_for("st-reg").len(), 2);
        // Updating hints only does not touch participants
        remember_signal("st-reg", HintState::None, &[]);
        assert_eq!(hint_for("st-reg"), Some(HintState::None));
        assert_eq!(participants_for("st-reg").len(), 2);
        assert_eq!(hint_for("st-unknown"), None);
        clear_registry();
    }
}
