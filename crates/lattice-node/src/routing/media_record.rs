//! Media recording over the bus (PL-13 13.6 / design §17.9 recording path): `media.record.*` producer + durable
//! consumer → MinIO.
//!
//! This module upgrades `routing/media.rs`'s "in-process queue direct write to object storage" to enter object storage **via the bus**,
//! while preserving three existing guarantees: "never block forwarding / degrade to direct write on publish failure / Redis-only bus direct write".
//!
//! # producer (`spawn_bus_producer`, scheduled by `routing/media.rs::spawn_recorder` when `bus.kind=nats`)
//!
//! - The `on_data` tee still does only one bounded `try_send` (1024; drop frame + `dropped_total` when full),
//!   so the forwarding hot path has **no new await**;
//! - A background task wraps frames into [`MediaRecordMsg`] (`{node_id, stream_id, seq, body_b64, ts}`) and
//!   `publish_media` to `media.record.{stream_id}` (`LATTICE_MEDIA`, JetStream **publish+ack**);
//! - `seq` is allocated by [`next_record_seq`]: **monotonically increasing per stream, no rollback across process restarts** (millisecond timestamp high bits +
//!   in-process sequence); the consumer uses it for idempotency (see below);
//! - On publish failure/timeout/bus unavailable (including `[degrade] inject_bus_failure` fault injection) →
//!   [`crate::routing::media::Recorder`] **writes object storage directly** (no dropped frames), counted as
//!   `lattice_media_record_publish_total{result=fallback}`;
//! - `stream-sig bye` → `RecordMsg::Finalize` → send a `final=true` control message (empty body)
//!   asking the consumer to flush the stream's incomplete segment immediately; on publish failure degrade to `Recorder::finalize`.
//!
//! # consumer (`spawn_consumer`, started by `node::build` when `record_enabled && bus.kind=nats`)
//!
//! - At node startup, create a durable **pull** consumer `media-record-{node_id}` (filter `media.record.>`,
//!   DeliverAll, explicit ack, `[media] record_bus_ack_wait_ms/record_bus_max_deliver`);
//!   after a node restart it resumes consuming unacked messages from the last ack;
//! - Process only messages with `node_id == self`: ingress frames from other nodes are acked and dropped
//!   (`consume_total{result=other_node}`), so this node persists only into its own object namespace;
//! - Aggregate `[4B BE len][body]` segments by stream (reusing `media.rs`'s
//!   `append_record_frame`/`segment_full`/`put_segment`), and **ack only after a successful write**
//!   (write object → write Redis watermark → ack last; a crash at any point can replay to convergence);
//! - Idempotency: the object key is determined by the **segment's first seq** (`media/record/{stream}/{node}/{first_seq}.bin`),
//!   and segment boundaries depend only on frame order, so replaying "object written but crashed before ack" produces **the same object**
//!   (overwrite, no duplicate object); messages with `seq <= watermark` are dropped and acked directly
//!   (`consume_total{result=duplicate}`); the watermark is stored in Redis
//!   `lattice:media:record:{node}:wm:{stream}` (7d TTL, non-authoritative: loss only writes the same-named object once more);
//! - Failure handling: object storage briefly unavailable → keep buffer + delivery handle, retry on tick
//!   (`consume_total{result=retry}`); after `MAX_FLUSH_ATTEMPTS` retries still failing → terminate +
//!   `consume_total{result=dlq}` + ERROR log (the message is still within the 1h Stream retention and can be replayed manually);
//!   malformed messages (invalid JSON/fields/over 64KiB/bad base64) → terminate immediately + `result=poison`;
//! - lag: each delivery carries the server's `pending`, refreshing `lattice_media_record_consumer_lag`.
//!
//! # Degradation matrix (module-relevant)
//!
//! | Scenario | producer | consumer | Data |
//! | --- | --- | --- | --- |
//! | `bus.kind=nats` + JetStream available | publish+ack | durable consume → MinIO | no loss (at-least-once, idempotent by seq) |
//! | NATS publish failure/timeout/JetStream=false | `result=fallback` → direct write to MinIO | no message to consume | no dropped frames (may be cross-path out of order, see boundaries) |
//! | NATS unavailable at startup (`node::build` falls back to RedisBus) | `bus.kind=redis-pubsub` → `result=direct` direct write | not started | no dropped frames |
//! | `record_enabled=false` | no queue/no task | not started | zero side effects |
//!
//! # Boundaries (report conventions; does not mean design §17.9 is complete)
//!
//! 1. **Playable muxing (v0.19 E21 wrap-up, see `routing/media_playback.rs`)**: when the offer **explicitly opts in** with `record_format="ogg-opus"`
//!    (optionally with `codec="opus"`) and every frame payload in the segment passes Opus packet-structure validation, the recording segment, after persistence, is **losslessly**
//!    muxed into a playable OGG Opus object (`media/playback/record/.../*.ogg`), and the manifest's
//!    `format/playable/codec` become `ogg-opus/true/opus`, with `playback{}` and a
//!    `*.playback.json` playback Envelope appended; without hints/non-opus/invalid structure it stays raw-frames +
//!    an explicit `playback_gap` GAP (**never faking playability**). **MP4/fMP4, transcoding, H.264/AV1 are still not done**;
//!    playback object API download/detail fields and `media/playback/` lifecycle reclamation are also not wired (see the next item).
//!    Without a `record_format` opt-in, object content is still "frame boundaries + raw WS tunnel body", and the manifest contains only a frame index
//!    (`format="raw-frames"`, `playable=false`); manifest/muxing generation failures only WARN
//!    and do not affect recording forwarding or segment persistence.
//! 2. `LATTICE_MEDIA` retention is 1h: frames are lost when the consumer is down for over 1h (production should raise max_age or create a
//!    longer-retention Stream; not done this round); the DLQ is only an ERROR log + metrics, with no separate DLQ table;
//! 3. During degradation switch windows, frames may be out of order across paths: the bus path persists in seq order, the direct-write path by local seq,
//!    and the two paths use different object keys (`{first_seq}` vs `{utc-seconds}-{local_seq}`); cross-path ordering is not guaranteed,
//!    but "every frame is persisted at least once"; after a publish timeout the message may already be in the Stream while a direct write is also triggered → that window may duplicate a frame
//!    (the producer does not retry publishes; duplicates are covered at the object level by seq idempotency, but byte-level exactly-once is not guaranteed);
//! 4. The watermark is in Redis: after Redis data loss (flush/eviction), a restart replay may overwrite the same-named object (overwrite, no new object),
//!    without dropping frames; "late replay" after the 7d watermark TTL likewise overwrites;
//! 5. Multiple nodes each consume the full recording stream and process only frames for their own `node_id`: no cross-node recording aggregation/dedup;
//! 6. Frames still in the producer queue, **not yet sent**, are lost on process `SIGKILL` (the queue is in memory; unacked
//!    bus messages are redelivered by the durable consumer) — this is the existing boundary of "forwarding never blocks, recording is best-effort";
//! 7. **Lifecycle reclamation** (`[media] record_retention_days`, default 0 = no reclamation) is in `jobs.rs`:
//!    after startup and every 6h, delete expired segment/manifest objects and index rows (batch ≤1000); reclamation is by index row
//!    `created_at` only, **orphan objects without an index row are not scanned** (the index is best-effort, see the index section),
//!    so orphan objects need operational prefix cleanup (the ⑥ §4 mark-and-sweep scan is not done); the `media/playback/` prefix is likewise
//!    not included in reclamation (`jobs.rs` is outside v0.19's write scope; recorded as a GAP).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;

use crate::error::Result;
use crate::routing::media::{
    append_record_frame, put_segment, segment_full, Recorder, RecordMsg, RECORD_IDLE_FLUSH,
    RECORD_MAX_BUFFERED_BYTES, RECORD_MAX_TRACKED_STREAMS, RECORD_QUEUE, RECORD_TICK,
};
use crate::routing::media_playback::{self, PlaybackGap, PlaybackInfo, PlaybackOutcome};
use crate::state::AppState;
use crate::store::bus::{BusKind, MediaDelivery, MediaRecordMsg, MediaSubscription};

/// Idempotency watermark (Redis) TTL: covers node restarts/short downtime; after expiry, replay only overwrites the same-named object, no frame loss.
pub const RECORD_WATERMARK_TTL_SECS: u64 = 7 * 24 * 3600;
/// How many consecutive failures to persist one segment before giving up (terminate → DLQ).
pub const RECORD_FLUSH_MAX_ATTEMPTS: u32 = 5;

/// In-process counter used by the producer to allocate recording frame seq (high bits are the millisecond timestamp; low bits increment to avoid same-millisecond collisions).
static RECORD_SEQ: AtomicU64 = AtomicU64::new(0);
/// Last allocated seq (ensures strict monotonicity against clock rollback).
static RECORD_SEQ_LAST: AtomicU64 = AtomicU64::new(0);

/// Allocate a recording frame seq: **monotonically increasing per stream, no rollback across process restarts**.
///
/// Encoding: `unix_millis << 20 | (in-process increment & 0xFFFFF)` — advances as milliseconds advance;
/// increments within the same millisecond; if the system clock rolls back (`now <= last`), degrade to `last + 1` to keep strict monotonicity
/// (seq is used only for idempotency/ordering, not precise time, so rollback does not break correctness).
pub fn next_record_seq() -> u64 {
    let ms = (chrono::Utc::now().timestamp_millis().max(1) as u64) << 20;
    let bump = RECORD_SEQ.fetch_add(1, Ordering::Relaxed) & 0xF_FFFF;
    let candidate = ms | bump;
    let mut last = RECORD_SEQ_LAST.load(Ordering::Relaxed);
    loop {
        let next = candidate.max(last.saturating_add(1));
        match RECORD_SEQ_LAST.compare_exchange_weak(
            last,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(current) => last = current,
        }
    }
}

/// Segment object key on the bus path: `media/record/{stream_id}/{node_id}/{first_seq:020}.bin`.
///
/// - Includes `node_id`: in a multi-node cluster each node persists only its own ingress frames, without overwriting others;
/// - Uses the **segment's first seq** rather than persistence time: replay (same starting frame + same segment limit) computes the same key and
///   the same bytes, and overwrite-write suffices, **producing no duplicate objects** (the core of key/seq idempotency);
/// - Fixed 20-digit decimal makes it easy for E2E to sort by key and reconstruct frame order.
pub fn bus_record_object_key(stream_id: &str, node_id: &str, first_seq: u64) -> String {
    format!(
        "media/record/{stream_id}/{}/{:020}.bin",
        sanitize_object_token(node_id),
        first_seq
    )
}

/// node_id sanitization in object keys: keep only `[A-Za-z0-9._-]`, replacing other characters with `_`.
pub(crate) fn sanitize_object_token(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Handling after a persist failure (pure function, for unit-testing DLQ boundaries).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteRetry {
    /// Below the cap: keep buffer + delivery handle, retry after a tick.
    Retry,
    /// At the cap: terminate the delivery handle and drop the segment (DLQ: ERROR log + metric).
    Dlq,
}

/// `attempts` is the **number of failures so far** (including this failure).
pub fn classify_write_failure(attempts: u32) -> WriteRetry {
    if attempts >= RECORD_FLUSH_MAX_ATTEMPTS.max(1) {
        WriteRetry::Dlq
    } else {
        WriteRetry::Retry
    }
}

// ---------------------------------------------------------------------------
// Playback manifest (PL-13 13.6 playback manifest + lifecycle reclamation)
// ---------------------------------------------------------------------------
//
// A segment object is a raw frame container repeated as `[4B BE len][body]`: without a manifest, clients must parse from the start
// themselves to know frame boundaries. Here every segment also gets a **manifest object** (frame index only, no payload):
//
// ```text
// key : media/manifest/record/{stream_id}/{node_id}/{segment identifier}.manifest.json
//       (deterministically derived from the segment object_key: `media/record/` → `media/manifest/record/`,
//        `.bin` → `.manifest.json`; replay overwrites the same-named object → idempotent)
// body: {version:1, stream_id, node_id, object_key, size,
//        frames:[{seq,offset,len,ts?}], frames_total, total_bytes, created_at,
//        codec:null, format:"raw-frames", playable:false, frames_truncated}
// ```
//
// `offset` is the **frame body's start offset within the segment object** (excluding the 4B BE length prefix), `len` is the body byte count:
// `segment[offset..offset+len]` is that frame's body (the raw `stream-data` body including the stream_id header),
// `segment[offset-4..offset]` is the BE length prefix. On the bus path `seq` is exact; the direct-write path's raw body
// has no frame seq → `seq:null` (not fabricated; consistent with the index table's `first_seq` conventions).
//
// **Why the manifest is not under the `media/record/{stream}/` prefix**: the existing recording E2E (`media-record`
// 43/43, `media-record-bus` 148/148) counts/parses **every object** under that prefix as a segment;
// mixing manifests in would change their object-count conventions; the separate `media/manifest/` prefix keeps "segment objects" and "manifest objects"
// from interfering (the manifest location is opaque to clients: the API locates it via the index row's `manifest_key`).
//
// Constraints:
// - Generation failures (read-back failure/serialization/write failure) only WARN + `lattice_media_record_manifest_total`
//   {result=error}`, never affecting already-persisted segments, the index, or forwarding (a side path like the index);
// - Large-segment limits: frames ≤ [`MANIFEST_MAX_FRAMES`], JSON size ≤ [`MANIFEST_MAX_BYTES`];
//   over the limit, write only the first N frames + `frames_truncated:true` (`frames_total` still reports the true frame count);
// - Idempotent: the manifest key is derived from object_key, so replay overwrites the same key/same content (the same segment's frame sequence is deterministic);
// - No MP4/OGG muxing/transcoding → `format:"raw-frames"`, `playable:false` (not a playable file).

/// Manifest structure version (clients choose parsing conventions from it; increment only on breaking changes).
pub const MANIFEST_VERSION: u32 = 1;
/// Object format described by the manifest: raw frame container (`[4B BE len][body]...`), **not MP4/OGG**.
pub const MANIFEST_FORMAT: &str = "raw-frames";
/// Maximum frames indexed per manifest (beyond it, only the first N frames are written + `frames_truncated:true`).
pub const MANIFEST_MAX_FRAMES: usize = 2048;
/// JSON byte cap per manifest (beyond it, truncate the frame index too, avoiding huge manifest objects for large segments).
pub const MANIFEST_MAX_BYTES: usize = 256 * 1024;
/// Budget estimate per frame index entry (JSON ~40–80B; worst case ~100B with large seq/ts numbers) → used to brake early.
const MANIFEST_FRAME_BUDGET_BYTES: usize = 96;

/// One frame index entry in the manifest (`offset/len` point to the frame body within the segment object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestFrame {
    /// Frame seq (exact on the bus path); the direct-write path has no frame seq → `null` (not fabricated).
    pub seq: Option<u64>,
    /// Start offset of the frame body within the segment object (excluding the 4B BE length prefix).
    pub offset: usize,
    /// Frame body byte count (= the value of the 4B length prefix).
    pub len: usize,
    /// Frame arrival time (unix ms; present on the bus path, absent on the direct-write path → field omitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<i64>,
}

/// Playback manifest JSON structure; serialized and written to the `manifest_key` object.
#[derive(Debug, Serialize)]
pub struct SegmentManifest<'a> {
    pub version: u32,
    pub stream_id: &'a str,
    pub node_id: &'a str,
    /// Corresponding segment object key (for downloading the raw `.bin`; the manifest only describes it, never copies the payload).
    pub object_key: &'a str,
    /// Segment object byte count (the full object size this manifest covers).
    pub size: usize,
    /// Frame index (may be truncated by [`MANIFEST_MAX_FRAMES`]/[`MANIFEST_MAX_BYTES`]).
    pub frames: Vec<ManifestFrame>,
    /// **True** frame count in the segment (exact even when frames is truncated).
    pub frames_total: usize,
    /// Whether the frame index is truncated (true = only the first N frames are indexed; clients must continue parsing the remaining bytes themselves).
    pub frames_truncated: bool,
    /// = `size` (total byte count given explicitly for client validation).
    pub total_bytes: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Reserved: codec (`null` = not muxed/unknown; from v0.19, `"opus"` when OGG Opus muxing succeeded).
    pub codec: Option<&'a str>,
    /// Object format: `"raw-frames"` (default, raw frame container) or `"ogg-opus"` (v0.19 playable muxing).
    pub format: &'a str,
    /// Whether directly playable: `true` only when **OGG Opus muxing truly succeeded** (never faked).
    pub playable: bool,
    /// Playable muxing info (v0.19, see `routing/media_playback.rs`): present only when the offer carried a valid codec
    /// hint and muxing succeeded; default = raw frame container (exactly the v0.18 manifest, backward compatible).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playback: Option<PlaybackInfo>,
    /// **Explicit GAP** when muxing did not succeed (a codec hint exists but playback is impossible, e.g. unsupported codec/invalid packet structure/
    /// object write failure); no "playable" field is faked on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playback_gap: Option<PlaybackGap>,
}

/// Segment object key → manifest object key (**deterministic derivation**; replay overwrites the same object → idempotent).
///
/// `media/record/{stream}/{node}/{seg}.bin` → `media/manifest/record/{stream}/{node}/{seg}.manifest.json`;
/// non-standard key (defensive) → `media/manifest/record/{object_key}.manifest.json` (still unique and cleanable).
pub fn manifest_object_key(object_key: &str) -> String {
    let stripped = object_key.strip_prefix("media/record/").unwrap_or(object_key);
    let base = stripped.strip_suffix(".bin").unwrap_or(stripped);
    format!("media/manifest/record/{base}.manifest.json")
}

/// Whether the frame-index budget allows one more frame (dual limits: entry count + JSON size).
fn manifest_frame_budget_ok(indexed: usize) -> bool {
    indexed < MANIFEST_MAX_FRAMES
        && (indexed + 1) * MANIFEST_FRAME_BUDGET_BYTES + 512 <= MANIFEST_MAX_BYTES
}

/// Parse the frame index from the segment container (the direct-write path has no in-memory frame metadata → read the object back and parse).
///
/// Returns `(frame index, true total frame count)`: the index brakes early within the [`MANIFEST_MAX_FRAMES`]/[`MANIFEST_MAX_BYTES`]
/// budget (affects only manifest size, not `frames_total`'s exact count);
/// on boundary corruption (length beyond the remaining bytes) it stops (indexing only confirmed complete frames; no panic/overrun).
pub fn frames_from_segment(bytes: &[u8]) -> (Vec<ManifestFrame>, usize) {
    let mut frames = Vec::new();
    let mut off = 0usize;
    let mut total = 0usize;
    while off + 4 <= bytes.len() {
        let len = u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
            as usize;
        off += 4;
        if len > bytes.len() - off {
            break;
        }
        total += 1;
        if manifest_frame_budget_ok(frames.len()) {
            frames.push(ManifestFrame {
                seq: None,
                offset: off,
                len,
                ts: None,
            });
        }
        off += len;
    }
    (frames, total)
}

/// Build the manifest (with two-layer truncation defense): `total` is the true segment frame count (None = frames is complete).
///
/// Layer one: the caller ([`frames_from_segment`]/consumer) already braked early within budget;
/// layer two: if serialization still exceeds [`MANIFEST_MAX_BYTES`] (abnormally large seq/ts numbers), trim proportionally
/// from the tail and set `frames_truncated=true` (bounding the manifest object size so clients can rely on `frames_total`
/// to tell whether it was truncated).
pub fn build_manifest<'a>(
    stream_id: &'a str,
    node_id: &'a str,
    object_key: &'a str,
    size_bytes: usize,
    frames: Vec<ManifestFrame>,
    total_frames: Option<usize>,
    created_at: chrono::DateTime<chrono::Utc>,
) -> SegmentManifest<'a> {
    let frames_total = total_frames.unwrap_or(frames.len());
    let frames_truncated = frames_total > frames.len();
    let mut manifest = SegmentManifest {
        version: MANIFEST_VERSION,
        stream_id,
        node_id,
        object_key,
        size: size_bytes,
        frames,
        frames_total,
        frames_truncated,
        total_bytes: size_bytes,
        created_at,
        codec: None,
        format: MANIFEST_FORMAT,
        playable: false,
        playback: None,
        playback_gap: None,
    };
    // Layer two: in extreme cases (oversized seq/ts numbers) cut to the cap; shrink proportionally to avoid O(n²).
    while manifest.frames.len() > 1 {
        let len = serde_json::to_vec(&manifest).map(|v| v.len()).unwrap_or(usize::MAX);
        if len <= MANIFEST_MAX_BYTES {
            break;
        }
        manifest.frames.truncate(manifest.frames.len() * 7 / 8);
        manifest.frames_truncated = true;
    }
    manifest
}

/// Write the playback manifest object for one segment; returns the manifest key on success, and only WARNs + returns `None` on failure.
///
/// The manifest is a **side path** (same level as the index): generation/write failures never backpressure recording forwarding or already-persisted segments;
/// the index row is still written (`manifest_key=NULL`; the manifest API returns 404 not_found for that segment).
///
/// **v0.19 playable muxing**: `segment` is the segment's raw container bytes (playable muxing needs frame payloads; the caller
/// already holds them, avoiding reading the object back). Muxing failure/non-structured content only writes `playback_gap` (never fakes playability);
/// on success the manifest's `format/playable/codec` become ogg-opus/true/opus and `playback` is appended,
/// then a playback Envelope is pushed to online devices at both offer ends (WS `envelope`, transient semantics).
#[allow(clippy::too_many_arguments)]
pub async fn write_segment_manifest(
    state: &AppState,
    bucket: &str,
    stream_id: &str,
    object_key: &str,
    size_bytes: usize,
    frames: Vec<ManifestFrame>,
    frames_total: usize,
    created_at: chrono::DateTime<chrono::Utc>,
    segment: Option<&[u8]>,
) -> Option<String> {
    let manifest_key = manifest_object_key(object_key);
    // Playable muxing (side path): no record_format opt-in → NotRequested (zero side effects, same behavior as v0.18).
    let playback = match segment {
        Some(bytes) => {
            media_playback::package_segment(
                state, bucket, stream_id, object_key, &manifest_key, bytes, created_at,
            )
            .await
        }
        None => PlaybackOutcome::NotRequested,
    };
    let mut manifest = build_manifest(
        stream_id,
        &state.node_id,
        object_key,
        size_bytes,
        frames,
        Some(frames_total),
        created_at,
    );
    let mut push_envelope: Option<Vec<u8>> = None;
    // codec is stored as an owned String (manifest.codec is a borrowed field; the GAP struct is moved into the manifest).
    let mut playback_codec: Option<String> = None;
    match playback {
        PlaybackOutcome::NotRequested => {}
        PlaybackOutcome::Gap(gap) => {
            // Explicit GAP: codec recorded truthfully, playable/format stay raw-frames (not faked).
            playback_codec = gap.codec.clone();
            tracing::debug!(
                stream_id,
                key = %object_key,
                reason = %gap.reason,
                detail = gap.detail.as_deref().unwrap_or(""),
                "media playback packaging skipped (explicit gap)"
            );
            manifest.playback_gap = Some(gap);
        }
        PlaybackOutcome::Packaged(artifact) => {
            let artifact = *artifact;
            manifest.format = media_playback::PLAYBACK_FORMAT_OGG_OPUS;
            manifest.playable = true;
            playback_codec = Some(media_playback::PLAYBACK_CODEC_OPUS.to_string());
            push_envelope = Some(artifact.envelope_pb);
            manifest.playback = Some(artifact.info);
        }
    }
    manifest.codec = playback_codec.as_deref();
    let truncated = manifest.frames_truncated;
    let indexed_frames = manifest.frames.len();
    let body = match serde_json::to_vec(&manifest) {
        Ok(b) => b,
        Err(e) => {
            state
                .metrics
                .media_record_manifest_total
                .with_label_values(&["error"])
                .inc();
            tracing::warn!(
                stream_id,
                key = %object_key,
                error = %e,
                "media record manifest serialize failed (manifest is best-effort; recording unaffected)"
            );
            return None;
        }
    };
    match state.s3.put_bytes(bucket, &manifest_key, &body).await {
        Ok(()) => {
            state
                .metrics
                .media_record_manifest_total
                .with_label_values(&["ok"])
                .inc();
            tracing::debug!(
                stream_id,
                key = %object_key,
                manifest_key = %manifest_key,
                frames = indexed_frames,
                frames_total,
                truncated,
                bytes = body.len(),
                playable = manifest.playable,
                format = manifest.format,
                "media record manifest written"
            );
            // The playback Envelope push happens after the manifest is persisted: when the client gets the message, the manifest is already fetchable.
            if let Some(pb) = push_envelope {
                media_playback::broadcast_envelope(state, stream_id, &pb);
            }
            Some(manifest_key)
        }
        Err(e) => {
            state
                .metrics
                .media_record_manifest_total
                .with_label_values(&["error"])
                .inc();
            tracing::warn!(
                stream_id,
                key = %object_key,
                manifest_key = %manifest_key,
                error = %e,
                "media record manifest write failed (manifest is best-effort; recording unaffected)"
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Segment index (PL-13 13.6 search/download; `media_recordings` table, migration 0009)
// ---------------------------------------------------------------------------
//
// Recording objects contain only "frame boundaries + raw body"; without an index there is **no way to list which segments a stream recorded**, and no download entry point.
// Here a metadata index row is added "after the object is persisted" (idempotency key = object_key unique), shared by both persistence paths:
//
// - bus consumer (`Consumer::flush_stream` in this file): knows the exact segment first/last frame seq and frame count;
// - direct-write recorder (`routing/media.rs::write_segment`): the raw `stream-data` body has **no frame
//   seq**, only the `{utc-seconds}-{flush seq}` object key, so seq/time ranges are written as NULL (no fabricated seq),
//   and the frame count is counted from `[4B len][body]` boundaries.
//
// The index is a **search side path**: write failures only WARN + `lattice_media_record_index_total{result=error}`,
// never backpressuring/affecting recording forwarding or already-persisted objects (consistent with the tee's non-blocking semantics).

/// Index metadata for one segment (`first_seq/last_seq` None = the direct-write path has no frame seq).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentIndexMeta {
    /// Segment first frame seq (exact on the bus path; None on the direct-write path).
    pub first_seq: Option<u64>,
    /// Segment last frame seq (exact on the bus path; None on the direct-write path).
    pub last_seq: Option<u64>,
    /// Frame count in the segment (number of `[4B BE len][body]` repeats).
    pub frames: usize,
    /// Segment first frame arrival time (None on the direct-write path).
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Segment last frame arrival time (None on the direct-write path).
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Count frames in a `[4B BE len][body]` container (the direct-write path's index metadata source).
///
/// A normal segment (what `put_segment` writes is this module's `append_record_frame` output) counts all frames exactly;
/// on boundary corruption (length beyond the remaining bytes), returns the count of **confirmed complete** frames (no panic, no out-of-bounds read).
pub fn count_segment_frames(bytes: &[u8]) -> usize {
    let mut off = 0usize;
    let mut frames = 0usize;
    while off + 4 <= bytes.len() {
        let len = u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
            as usize;
        off += 4;
        if len > bytes.len() - off {
            break;
        }
        off += len;
        frames += 1;
    }
    frames
}

/// Idempotently write one recording index row (**must be called after the object is persisted**; failures only WARN and do not affect recording forwarding).
///
/// Direct-write path entry (`routing/media.rs::write_segment`): the caller has only object key/byte count and **no**
/// in-memory frame metadata, so this reads the object back once to parse `[4B len][body]` boundaries and generate the manifest
/// (the direct-write path has no frame seq → frame index `seq:null`, not fabricated), then writes the manifest + index row (with
/// `manifest_key`). A manifest failure does not affect index row writing (`manifest_key=NULL`).
///
/// - `Ok(true)` (new row) → `lattice_media_record_index_total{result=ok}`;
/// - `Ok(false)` (`object_key` already exists = replay overwriting the same object) → `result=dup`, no duplicate row;
/// - `Err` (PG unavailable, etc.) → `result=error` + WARN; the index may be lost (no retry: object and watermark are in place,
///   and replay re-runs the same insert for the same `object_key`, converging naturally).
pub async fn index_segment(
    state: &AppState,
    bucket: &str,
    stream_id: &str,
    object_key: &str,
    size_bytes: usize,
    meta: SegmentIndexMeta,
) {
    // Read the segment back to build the true frame index (parse boundaries only, no body copy); failure only WARN, manifest omitted.
    let manifest_key = match state.s3.get_bytes(bucket, object_key).await {
        Ok(bytes) => {
            let size = bytes.len().max(size_bytes);
            let (frames, frames_total) = frames_from_segment(&bytes);
            write_segment_manifest(
                state,
                bucket,
                stream_id,
                object_key,
                size,
                frames,
                frames_total,
                // The direct-write path has no frame arrival time (the raw body carries no ts): created_at uses the index write time.
                chrono::Utc::now(),
                // For playable muxing: the read-back segment bytes (payload extraction; failures only record a GAP).
                Some(&bytes),
            )
            .await
        }
        Err(e) => {
            state
                .metrics
                .media_record_manifest_total
                .with_label_values(&["error"])
                .inc();
            tracing::warn!(
                stream_id,
                key = %object_key,
                error = %e,
                "media record manifest skipped: segment read-back failed (manifest is best-effort)"
            );
            None
        }
    };
    index_segment_row(
        state,
        bucket,
        stream_id,
        object_key,
        size_bytes,
        meta,
        manifest_key.as_deref(),
    )
    .await;
}

/// Index row write (shared by the bus consumer and the direct-write path): `manifest_key` is generated by the caller (may be None).
#[allow(clippy::too_many_arguments)]
async fn index_segment_row(
    state: &AppState,
    bucket: &str,
    stream_id: &str,
    object_key: &str,
    size_bytes: usize,
    meta: SegmentIndexMeta,
    manifest_key: Option<&str>,
) {
    let record = crate::store::pg::NewMediaRecording {
        stream_id,
        node_id: &state.node_id,
        object_key,
        manifest_key,
        first_seq: meta.first_seq,
        last_seq: meta.last_seq,
        // Empty segments never reach here (put_segment returns early for empty bytes); defensively clamp to 1 to satisfy the table constraint.
        frames: meta.frames.max(1),
        size_bytes,
        bucket,
        started_at: meta.started_at,
        ended_at: meta.ended_at,
    };
    // Skip inside the PG local circuit-breaker window: the index is a search side path, and "every segment persist waits for pool acquire timeout"
    // must not slow consumer flush/ack (recording forwarding itself does not depend on the index).
    if crate::store::pg::is_degraded() {
        tracing::debug!(
            stream_id,
            key = %object_key,
            "media record segment index skipped: pg degraded (best-effort index)"
        );
        return;
    }
    match crate::store::pg::media_recording_insert(&state.db, record).await {
        Ok(true) => {
            state
                .metrics
                .media_record_index_total
                .with_label_values(&["ok"])
                .inc();
            tracing::debug!(
                stream_id,
                key = %object_key,
                manifest_key = manifest_key.unwrap_or(""),
                frames = meta.frames,
                bytes = size_bytes,
                "media record segment indexed"
            );
        }
        Ok(false) => {
            state
                .metrics
                .media_record_index_total
                .with_label_values(&["dup"])
                .inc();
            tracing::debug!(
                stream_id,
                key = %object_key,
                "media record segment index already present (replay overwrite; no duplicate row)"
            );
        }
        Err(e) => {
            state
                .metrics
                .media_record_index_total
                .with_label_values(&["error"])
                .inc();
            tracing::warn!(
                stream_id,
                key = %object_key,
                error = %e,
                "media record segment index insert failed (index is best-effort; recording unaffected)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// producer
// ---------------------------------------------------------------------------

/// Start the bus producer background task (scheduled by `media::spawn_recorder` when `bus.kind=nats`).
///
/// Isomorphic to the direct-write recorder: same queue capacity/idle flush/drain semantics; the only difference is "frames go to the bus first,
/// and only fall back to direct write when they cannot be sent". The task holds `Arc<AppState>`, so its exit path does not depend on the channel closing.
pub fn spawn_bus_producer(state: Arc<AppState>, mut rx: tokio::sync::mpsc::Receiver<RecordMsg>) {
    tokio::spawn(async move {
        // Degradation write end: frames that fail to publish go straight to the original direct-write aggregator (object keys use the direct-write format).
        let mut fallback = Recorder::new(state.clone());
        tracing::info!(
            stream = crate::store::nats::STREAM_MEDIA,
            subject = crate::store::nats::SUBJECT_MEDIA_WILDCARD,
            bucket = %state.cfg.media.effective_record_bucket(&state.cfg.s3),
            segment_bytes = state.cfg.media.effective_record_segment_bytes(),
            queue = RECORD_QUEUE,
            "media record bus producer enabled (publish failure falls back to direct object write)"
        );
        loop {
            match tokio::time::timeout(RECORD_TICK, rx.recv()).await {
                Ok(Some(RecordMsg::Data { stream_id, body })) => {
                    let seq = next_record_seq();
                    let msg = MediaRecordMsg::data(
                        &state.node_id,
                        &stream_id,
                        seq,
                        &body,
                        chrono::Utc::now().timestamp_millis(),
                    );
                    match publish_record(&state, &msg).await {
                        Ok(()) => {
                            state
                                .metrics
                                .media_record_publish_total
                                .with_label_values(&["ok"])
                                .inc();
                        }
                        Err(e) => {
                            // Publish failure/timeout/bus unavailable: degrade to direct write to keep "no dropped frames".
                            state
                                .metrics
                                .media_record_publish_total
                                .with_label_values(&["fallback"])
                                .inc();
                            tracing::warn!(
                                stream_id = %stream_id,
                                seq,
                                error = %e,
                                "media record bus publish failed; writing segment directly (degraded)"
                            );
                            fallback.on_data(stream_id, &body).await;
                        }
                    }
                }
                Ok(Some(RecordMsg::Finalize { stream_id })) => {
                    let seq = next_record_seq();
                    let msg = MediaRecordMsg::finalize(
                        &state.node_id,
                        &stream_id,
                        seq,
                        chrono::Utc::now().timestamp_millis(),
                    );
                    match publish_record(&state, &msg).await {
                        Ok(()) => {
                            state
                                .metrics
                                .media_record_publish_total
                                .with_label_values(&["ok"])
                                .inc();
                        }
                        Err(e) => {
                            state
                                .metrics
                                .media_record_publish_total
                                .with_label_values(&["fallback"])
                                .inc();
                            tracing::warn!(
                                stream_id = %stream_id,
                                error = %e,
                                "media record finalize marker publish failed; finalizing direct path"
                            );
                        }
                    }
                    // During the degradation window some frames may already have taken the direct-write path: finalize the local buffer best-effort regardless of publish success.
                    fallback.finalize(&stream_id).await;
                }
                Ok(None) => {
                    // All senders released (unit test / runtime shutdown): flush best-effort then exit.
                    fallback.flush_all().await;
                    tracing::info!("media record bus producer channel closed, flushed direct fallback");
                    return;
                }
                Err(_) => {
                    fallback.flush_idle().await;
                    // Node draining: main leaves only a 1s window; write the degradation buffer out best-effort.
                    if state.draining.load(Ordering::Relaxed) {
                        fallback.flush_all().await;
                    }
                }
            }
        }
    });
}

/// Publish one recording message (strict JetStream publish+ack); supports `[degrade] inject_bus_failure` fault injection.
async fn publish_record(state: &AppState, msg: &MediaRecordMsg) -> Result<()> {
    if state.cfg.degrade.inject_bus_failure {
        return Err(crate::error::internal(
            "media record publish skipped: [degrade] inject_bus_failure=true (fault injection)",
        ));
    }
    state.bus.publish_media(msg).await
}

// ---------------------------------------------------------------------------
// consumer
// ---------------------------------------------------------------------------

/// Start the recording consumer (durable pull consumer → aggregate by stream → object storage).
///
/// - `record_enabled=false`: not started (zero side effects);
/// - `bus.kind != nats`: no persistent/acked recording stream, not started (the producer already writes object storage directly);
/// - Consumer creation/subscription failures only WARN: producer publish failures degrade to direct write, and once the consumer recovers (the bus layer's
///   inner rebuild loop) it continues consuming unacked messages within the Stream retention.
pub fn spawn_consumer(state: Arc<AppState>) {
    if !state.cfg.media.record_enabled {
        tracing::debug!("media record consumer not started: [media] record_enabled=false");
        return;
    }
    if state.bus.kind() != BusKind::Nats {
        tracing::info!(
            bus = state.bus.kind().as_str(),
            "media record consumer not started: bus backend has no durable media stream \
             (recording writes directly to object storage)"
        );
        return;
    }
    let node_id = state.node_id.clone();
    let consumer_name = crate::store::nats::media_record_consumer_name(&node_id);
    // Consumer quiet period/limits all come from `[media] record_bus_*` (E2E lowers ack_wait to speed up restart redelivery).
    let ack_wait = state.cfg.media.effective_record_bus_ack_wait();
    let max_deliver = state.cfg.media.effective_record_bus_max_deliver();
    let retry_delay = state.cfg.media.effective_record_bus_retry_delay();
    tokio::spawn(async move {
        match state
            .bus
            .subscribe_media(&node_id, ack_wait, max_deliver, retry_delay)
            .await
        {
            Ok(sub) => {
                tracing::info!(
                    node_id = %node_id,
                    stream = crate::store::nats::STREAM_MEDIA,
                    consumer = %consumer_name,
                    filter = crate::store::nats::SUBJECT_MEDIA_WILDCARD,
                    ack_wait_ms = ack_wait.as_millis() as u64,
                    max_deliver,
                    retry_delay_ms = retry_delay.as_millis() as u64,
                    "media record consumer started (durable pull consumer → segment objects)"
                );
                let MediaSubscription { mut rx, sub } = sub;
                // Handle alive = subscription valid; drop aborts the background consumption task (ends naturally on process exit).
                let _keep_alive = sub;
                let mut consumer = Consumer::new(state.clone());
                loop {
                    match tokio::time::timeout(RECORD_TICK, rx.recv()).await {
                        Ok(Some(delivery)) => consumer.on_delivery(delivery).await,
                        Ok(None) => {
                            consumer.flush_all().await;
                            tracing::info!("media record consumer channel closed, flushed");
                            return;
                        }
                        Err(_) => {
                            consumer.flush_idle().await;
                            // Node draining: main leaves only a 1s window; write incomplete segments out best-effort
                            // (unwritten messages are unacked and redelivered by the durable consumer within at most 30s).
                            if state.draining.load(Ordering::Relaxed) {
                                consumer.flush_all().await;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                // Deterministically unavailable (JetStream off/non-NATS, etc.): the producer's publish would also fail and write directly;
                // no retry here (the bus implementation has a separate consumer rebuild loop covering "runtime flapping").
                tracing::warn!(
                    node_id = %node_id,
                    error = %e,
                    "media record consumer not started; producer falls back to direct object writes"
                );
            }
        }
    });
}

/// Consumer buffer for one stream: one incomplete segment + the deliveries covering it (ack only after a successful write).
struct ConsumerStream {
    /// Concatenated `[4B BE len][body]...` buffer.
    buffer: Vec<u8>,
    /// Deliveries covering the current buffer (including duplicate-delivery handles); all acked after a successful flush.
    deliveries: Vec<MediaDelivery>,
    /// Current segment first frame seq (determines the object key and replay idempotency).
    start_seq: u64,
    /// Maximum seq in the buffer (for duplicate-delivery detection).
    last_seq: u64,
    /// **Unique frame count** in the buffer (the `ok` consume metric accumulates from it).
    frames: usize,
    last_at: Instant,
    /// Segment first frame arrival time (recording index `started_at`; the direct-write path has no such info).
    first_frame_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Segment last frame arrival time (recording index `ended_at`).
    last_frame_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Frame index within the current segment (seq/offset/len/ts; the manifest's data source; written with the object on persist).
    frame_meta: Vec<ManifestFrame>,
    /// Consecutive persist failure count (`RECORD_FLUSH_MAX_ATTEMPTS` → DLQ).
    write_attempts: u32,
}

impl ConsumerStream {
    fn new(start_seq: u64) -> Self {
        Self {
            buffer: Vec::new(),
            deliveries: Vec::new(),
            start_seq,
            last_seq: start_seq,
            frames: 0,
            last_at: Instant::now(),
            first_frame_at: None,
            last_frame_at: None,
            frame_meta: Vec::new(),
            write_attempts: 0,
        }
    }
}

/// Recording consumer aggregation state (owned by the background task, lock-free).
struct Consumer {
    state: Arc<AppState>,
    bucket: String,
    segment_bytes: usize,
    streams: HashMap<String, ConsumerStream>,
    buffered_bytes: usize,
    /// Highest persisted seq per stream (in-memory cache of the Redis watermark; a `None` value means "queried and empty" and is also not cached,
    /// avoiding permanently caching an empty watermark when Redis is briefly unavailable).
    watermarks: HashMap<String, u64>,
}

impl Consumer {
    fn new(state: Arc<AppState>) -> Self {
        let bucket = state.cfg.media.effective_record_bucket(&state.cfg.s3);
        let segment_bytes = state.cfg.media.effective_record_segment_bytes();
        Self {
            state,
            bucket,
            segment_bytes,
            streams: HashMap::new(),
            buffered_bytes: 0,
            watermarks: HashMap::new(),
        }
    }

    fn metrics(&self) -> &crate::observe::Metrics {
        &self.state.metrics
    }

    fn count(&self, result: &str) {
        self.metrics()
            .media_record_consume_total
            .with_label_values(&[result])
            .inc();
    }

    fn count_by(&self, result: &str, n: u64) {
        self.metrics()
            .media_record_consume_total
            .with_label_values(&[result])
            .inc_by(n);
    }

    /// Receive one delivery: validate → node filter → idempotency → buffer → persist when full; failures are handled per DLQ conventions.
    async fn on_delivery(&mut self, mut delivery: MediaDelivery) {
        // lag: server pending (how many messages this consumer still has undelivered).
        self.metrics()
            .media_record_consumer_lag
            .set(delivery.pending as i64);

        let msg: MediaRecordMsg = match serde_json::from_slice(&delivery.payload) {
            Ok(m) => m,
            Err(e) => {
                // A malformed message never succeeds no matter how many retries: terminate immediately (DLQ) to avoid poisoning the consumer.
                self.count("poison");
                tracing::error!(
                    delivered = delivery.delivered,
                    payload_len = delivery.payload.len(),
                    reason = %format!("invalid media record payload: {e}"),
                    "media record dlq: undecodable payload terminated"
                );
                let _ = delivery.term().await;
                return;
            }
        };
        if let Err(reason) = msg.validate() {
            self.count("poison");
            tracing::error!(
                delivered = delivery.delivered,
                node_id = %msg.node_id,
                stream_id = %msg.stream_id,
                reason = %format!("invalid media record message: {reason}"),
                "media record dlq: invalid media record message terminated"
            );
            let _ = delivery.term().await;
            return;
        }

        // Process only this node's ingress frames; frames from other nodes are acked and dropped (each node's durable consumer sees everything).
        if msg.node_id != self.state.node_id {
            self.count("other_node");
            tracing::debug!(
                node_id = %msg.node_id,
                stream_id = %msg.stream_id,
                seq = msg.seq,
                "media record: frame from another node ignored (acked)"
            );
            let _ = delivery.ack().await;
            return;
        }

        // final control message: flush the stream immediately (the last segment after bye does not wait for idle flush).
        if msg.last {
            self.flush_stream(&msg.stream_id).await;
            let _ = delivery.ack().await;
            return;
        }

        let body = match msg.frame_body() {
            Ok(b) if !b.is_empty() => b,
            Ok(_) => {
                self.count("poison");
                tracing::error!(stream_id = %msg.stream_id, seq = msg.seq, "media record dlq: empty frame body");
                let _ = delivery.term().await;
                return;
            }
            Err(e) => {
                self.count("poison");
                tracing::error!(
                    stream_id = %msg.stream_id,
                    seq = msg.seq,
                    reason = %e,
                    "media record dlq: bad frame body"
                );
                let _ = delivery.term().await;
                return;
            }
        };

        // Idempotency ①: seq not above the persisted watermark → duplicate delivery (restart replay/ack-failure redelivery); drop and ack.
        let watermark = self.watermark(&msg.stream_id).await;
        if msg.seq <= watermark {
            self.count("duplicate");
            tracing::debug!(
                stream_id = %msg.stream_id,
                seq = msg.seq,
                watermark,
                "media record: duplicate frame dropped (already persisted)"
            );
            let _ = delivery.ack().await;
            return;
        }

        // Idempotency ②: duplicate delivery within the same segment (the server redelivers unacked messages after ack_wait expires):
        // the frame is appended only once; the delivery handle is attached to the segment and acked together after a successful write.
        let duplicate_in_buffer = self
            .streams
            .get(&msg.stream_id)
            .is_some_and(|seg| !seg.buffer.is_empty() && msg.seq <= seg.last_seq);
        if duplicate_in_buffer {
            self.count("duplicate");
            if let Some(seg) = self.streams.get_mut(&msg.stream_id) {
                seg.deliveries.push(delivery);
            }
            return;
        }

        let appended = 4 + body.len();
        let stream_id = msg.stream_id.clone();
        {
            let seg = self
                .streams
                .entry(stream_id.clone())
                .or_insert_with(|| ConsumerStream::new(msg.seq));
            // Frame body start offset within the segment object (excluding the 4B length prefix): the manifest's offset conventions.
            let body_offset = seg.buffer.len() + 4;
            append_record_frame(&mut seg.buffer, &body);
            seg.last_seq = msg.seq;
            let frame_at = chrono::Utc::now();
            if seg.frames == 0 {
                seg.first_frame_at = Some(frame_at);
            }
            seg.last_frame_at = Some(frame_at);
            seg.frames += 1;
            // Playback manifest frame index: seq/arrival time come from the bus message (exact), offset/len from this segment buffer.
            seg.frame_meta.push(ManifestFrame {
                seq: Some(msg.seq),
                offset: body_offset,
                len: body.len(),
                ts: Some(msg.ts),
            });
            seg.last_at = Instant::now();
            // A new frame arrived: previous failure counts no longer mean "the current segment is stuck"; restart from this failure.
            seg.write_attempts = 0;
            seg.deliveries.push(delivery);
        }
        self.buffered_bytes += appended;

        if segment_full(
            self.streams
                .get(&stream_id)
                .map(|s| s.buffer.len())
                .unwrap_or(0),
            self.segment_bytes,
        ) {
            self.flush_stream(&stream_id).await;
        } else if self.buffered_bytes > RECORD_MAX_BUFFERED_BYTES {
            // Multiple streams half-full push memory past the limit: force-flush the oldest stream (possibly including the one just received).
            self.flush_oldest().await;
        }
    }

    /// Read a stream's idempotency watermark (memory cache → Redis); read failures are **not cached**, retried next time.
    async fn watermark(&mut self, stream_id: &str) -> u64 {
        if let Some(w) = self.watermarks.get(stream_id) {
            return *w;
        }
        match self
            .state
            .redis
            .media_record_watermark_get(&self.state.node_id, stream_id)
            .await
        {
            Ok(Some(w)) => {
                self.watermarks.insert(stream_id.to_string(), w);
                w
            }
            Ok(None) => 0,
            Err(e) => {
                // Redis half-dead: degrade to "no watermark" (replay may overwrite the same-named object once more, no frame loss); not cached.
                tracing::warn!(
                    stream_id,
                    error = %e,
                    "media record watermark read failed; treating as fresh stream (dedupe degraded)"
                );
                0
            }
        }
    }

    /// Flush a stream's incomplete segment: write object → write manifest → index → record watermark → ack deliveries;
    /// failures keep the buffer for retry / exhaust to DLQ.
    async fn flush_stream(&mut self, stream_id: &str) {
        let Some(mut seg) = self.streams.remove(stream_id) else {
            return;
        };
        self.buffered_bytes -= seg.buffer.len();
        if seg.buffer.is_empty() {
            // Empty final/empty segment: just ack the attached duplicate deliveries (no object to write).
            for mut d in seg.deliveries {
                let _ = d.ack().await;
            }
            return;
        }
        let key = bus_record_object_key(stream_id, &self.state.node_id, seg.start_seq);
        if let Err(e) = put_segment(
            &self.state,
            &self.bucket,
            stream_id,
            &key,
            seg.buffer.clone(),
        )
        .await
        {
            // put_segment already counts errors_total internally; here only "retry or DLQ" is decided.
            let attempts = seg.write_attempts + 1;
            let frames = seg.frames as u64;
            match classify_write_failure(attempts) {
                WriteRetry::Retry => {
                    self.count("retry");
                    tracing::warn!(
                        stream_id,
                        key = %key,
                        attempts,
                        attempts_max = RECORD_FLUSH_MAX_ATTEMPTS,
                        error = %e,
                        "media record segment write failed; keeping buffer for retry"
                    );
                    let mut seg = seg;
                    seg.write_attempts = attempts;
                    seg.last_at = Instant::now();
                    self.buffered_bytes += seg.buffer.len();
                    self.streams.insert(stream_id.to_string(), seg);
                }
                WriteRetry::Dlq => {
                    self.count_by("dlq", frames.max(1));
                    tracing::error!(
                        stream_id,
                        key = %key,
                        attempts,
                        frames,
                        error = %e,
                        "media record dlq: segment write retries exhausted; frames terminated \
                         (still in LATTICE_MEDIA retention, replayable by stream/seq)"
                    );
                    for mut d in seg.deliveries {
                        let _ = d.term().await;
                    }
                }
            }
            return;
        }

        // Object persisted: write the **playback manifest** (side path, failures only WARN) → then the recording index row
        // (only a successful manifest write yields manifest_key; on failure that column is NULL and the manifest API returns 404 for the segment).
        // Idempotency key = object_key: replay overwrites the same object/same manifest key, and the index ignores unique conflicts,
        // producing no duplicate rows (manifest overwrite content is deterministic and byte-identical).
        //
        // created_at takes the **segment first frame's producer timestamp** (`MediaRecordMsg.ts`, replayed as-is with the bus message):
        // replaying the same batch of messages → byte-identical manifest (truly verifiable overwrite idempotency), rather than the time of each write.
        let manifest_created_at = seg
            .frame_meta
            .first()
            .and_then(|f| f.ts)
            .and_then(chrono::DateTime::from_timestamp_millis)
            .unwrap_or_else(chrono::Utc::now);
        let manifest_key = write_segment_manifest(
            &self.state,
            &self.bucket,
            stream_id,
            &key,
            seg.buffer.len(),
            std::mem::take(&mut seg.frame_meta),
            seg.frames,
            manifest_created_at,
            // For playable muxing: this segment's raw container bytes (payload extraction; failures only record a GAP, not affecting persistence/index).
            Some(&seg.buffer),
        )
        .await;
        index_segment_row(
            &self.state,
            &self.bucket,
            stream_id,
            &key,
            seg.buffer.len(),
            SegmentIndexMeta {
                first_seq: Some(seg.start_seq),
                last_seq: Some(seg.last_seq),
                frames: seg.frames,
                started_at: seg.first_frame_at,
                ended_at: seg.last_frame_at,
            },
            manifest_key.as_deref(),
        )
        .await;

        // Success: record the watermark (Redis) first, then ack. This ordering ensures "crash after object write, before ack" replays by watermark
        // dropping old seqs → no duplicate persistence; even if the watermark write fails, replay overwrites the same key (identical content).
        self.watermarks
            .insert(stream_id.to_string(), seg.last_seq);
        if let Err(e) = self
            .state
            .redis
            .media_record_watermark_set(
                &self.state.node_id,
                stream_id,
                seg.last_seq,
                RECORD_WATERMARK_TTL_SECS,
            )
            .await
        {
            tracing::warn!(
                stream_id,
                seq = seg.last_seq,
                error = %e,
                "media record watermark write failed (idempotency degraded; object already written)"
            );
        }
        self.count_by("ok", seg.frames as u64);
        for mut d in seg.deliveries {
            if let Err(e) = d.ack().await {
                // ack failure → the server redelivers after ack_wait; redelivery is deduped by watermark, so no duplicate persistence.
                tracing::warn!(
                    stream_id,
                    seq = seg.last_seq,
                    error = %e,
                    "media record ack failed (will redeliver; dedupe by watermark)"
                );
            }
        }
    }

    /// Idle flush: persist streams with no new frames for 2s (same conventions as the direct-write recorder).
    async fn flush_idle(&mut self) {
        let due: Vec<String> = self
            .streams
            .iter()
            .filter(|(_, s)| !s.buffer.is_empty() && s.last_at.elapsed() >= RECORD_IDLE_FLUSH)
            .map(|(id, _)| id.clone())
            .collect();
        for id in due {
            self.flush_stream(&id).await;
        }
        self.enforce_stream_cap();
    }

    /// Force-flush the oldest (smallest last_at) non-empty stream; a fallback for total buffer overflow.
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
        self.flush_stream(&id).await;
    }

    /// Node draining/consumer shutdown: write out all non-empty buffers best-effort (failures follow retry/DLQ conventions).
    async fn flush_all(&mut self) {
        let ids: Vec<String> = self
            .streams
            .iter()
            .filter(|(_, s)| !s.buffer.is_empty())
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.flush_stream(&id).await;
        }
    }

    /// Fallback for tracked entry count: remove the oldest empty entries above the cap (the normal path has no empty entries).
    fn enforce_stream_cap(&mut self) {
        if self.streams.len() <= RECORD_MAX_TRACKED_STREAMS {
            return;
        }
        let drop_n = self.streams.len() - RECORD_MAX_TRACKED_STREAMS;
        let mut empties: Vec<(String, Instant)> = self
            .streams
            .iter()
            .filter(|(_, s)| s.buffer.is_empty())
            .map(|(id, s)| (id.clone(), s.last_at))
            .collect();
        empties.sort_by_key(|(_, at)| *at);
        for (id, _) in empties.into_iter().take(drop_n) {
            self.streams.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn data_body(id: &str, payload: &[u8]) -> Vec<u8> {
        let id = id.as_bytes();
        let mut body = vec![1u8, 0u8, (id.len() >> 8) as u8, (id.len() & 0xff) as u8];
        body.extend_from_slice(id);
        body.extend_from_slice(payload);
        body
    }

    #[test]
    fn record_seq_is_monotonic_and_positive() {
        let mut prev = 0;
        for _ in 0..1024 {
            let seq = next_record_seq();
            assert!(seq > 0);
            assert!(seq > prev, "seq must be strictly increasing: {prev} -> {seq}");
            prev = seq;
        }
        // High bits are the millisecond timestamp: same magnitude as the current time (for observability, not precise time)
        let now_ms = chrono::Utc::now().timestamp_millis().max(1) as u64;
        let seq_ms = next_record_seq() >> 20;
        assert!(
            seq_ms.abs_diff(now_ms) < 60_000,
            "seq high bits should track unix millis: seq_ms={seq_ms} now={now_ms}"
        );
    }

    #[test]
    fn bus_record_object_key_is_stable_and_idempotent() {
        let k = bus_record_object_key("st-1", "node-a", 42);
        assert_eq!(k, "media/record/st-1/node-a/00000000000000000042.bin");
        assert!(k.starts_with("media/record/"));
        assert!(k.ends_with(".bin"));
        // Idempotency key: the same (stream,node,first seq) always yields the same key (replay overwrite, no duplicate objects)
        assert_eq!(
            k,
            bus_record_object_key("st-1", "node-a", 42),
            "object key must be deterministic for replay idempotency"
        );
        // Keys for different segments must differ (otherwise a later segment overwrites an earlier one)
        assert_ne!(
            k,
            bus_record_object_key("st-1", "node-a", 43)
        );
        // Keys for different nodes/streams must be isolated (multiple nodes each write their own ingress frames)
        assert_ne!(
            k,
            bus_record_object_key("st-1", "node-b", 42)
        );
        assert_ne!(
            k,
            bus_record_object_key("st-2", "node-a", 42)
        );
        // Fixed 20-digit decimal: E2E can reconstruct frame order from key lexicographic order
        let a = bus_record_object_key("s", "n", 9);
        let b = bus_record_object_key("s", "n", 10);
        assert!(a < b);
    }

    #[test]
    fn object_token_sanitizes_node_id() {
        // node_id may contain `/`, `:` and other characters (object key separators/special characters); must be sanitized
        assert_eq!(sanitize_object_token("media-bus_node.1"), "media-bus_node.1");
        assert_eq!(sanitize_object_token("a/b:c d"), "a_b_c_d");
        // Sanitized output still satisfies the key prefix/suffix contract
        let k = bus_record_object_key("st-1", "a/b:c", 7);
        assert!(k.starts_with("media/record/st-1/"));
        assert!(k.ends_with(".bin"));
        assert!(!k.contains("/a/b"));
    }

    #[test]
    fn write_failure_classification_never_retries_forever() {
        use WriteRetry::*;
        assert_eq!(classify_write_failure(0), Retry);
        assert_eq!(classify_write_failure(1), Retry);
        assert_eq!(classify_write_failure(RECORD_FLUSH_MAX_ATTEMPTS - 1), Retry);
        assert_eq!(classify_write_failure(RECORD_FLUSH_MAX_ATTEMPTS), Dlq);
        assert_eq!(classify_write_failure(RECORD_FLUSH_MAX_ATTEMPTS + 9), Dlq);
        // Cap at least 1: 0 attempts must not go straight to DLQ (otherwise one object-storage blip loses a whole segment)
        assert_eq!(RECORD_FLUSH_MAX_ATTEMPTS.max(1), RECORD_FLUSH_MAX_ATTEMPTS);
    }

    #[test]
    fn segment_partition_from_a_fixed_start_is_deterministic() {
        // Replay idempotency premise: given "the same frame sequence starting at the segment's first seq" and the same segment limit,
        // segment boundaries must be fully deterministic (⇒ object key/content deterministic).
        let segment_bytes = 128;
        let bodies: Vec<Vec<u8>> = (0..10)
            .map(|i| data_body("st-1", format!("frame-{i}").as_bytes()))
            .collect();
        // Returns (frames per segment, bytes) for each segment
        let partition = |bodies: &[Vec<u8>]| {
            let mut out: Vec<(usize, Vec<u8>)> = Vec::new();
            let mut buf = Vec::new();
            let mut frames = 0;
            for body in bodies {
                append_record_frame(&mut buf, body);
                frames += 1;
                if segment_full(buf.len(), segment_bytes) {
                    out.push((frames, std::mem::take(&mut buf)));
                    frames = 0;
                }
            }
            if !buf.is_empty() {
                out.push((frames, buf));
            }
            out
        };
        let a = partition(&bodies);
        let b = partition(&bodies);
        assert_eq!(a, b, "same frames + same limit must yield same segments");
        assert!(a.len() >= 2, "small segment limit should rotate: {}", a.len());
        // Each frame appears exactly once within a segment (no loss/duplication); frame count and bytes agree
        let total_frames: usize = a
            .iter()
            .map(|(n, bytes)| {
                let mut off = 0;
                let mut frames = 0;
                while off + 4 <= bytes.len() {
                    let len = u32::from_be_bytes([
                        bytes[off],
                        bytes[off + 1],
                        bytes[off + 2],
                        bytes[off + 3],
                    ]) as usize;
                    off += 4 + len;
                    frames += 1;
                }
                assert_eq!(off, bytes.len(), "segment boundary must be exact");
                assert_eq!(frames, *n);
                frames
            })
            .sum();
        assert_eq!(total_frames, bodies.len());
    }

    #[test]
    fn media_record_msg_final_marker_has_no_body() {
        let msg = MediaRecordMsg::finalize("n", "st-1", 1, 0);
        assert!(msg.last);
        assert!(msg.body_b64.is_empty());
        assert!(msg.validate().is_ok());
        // final control messages are not data frames: an empty body must not be persisted to the object as an empty frame
        assert!(msg.frame_body().unwrap().is_empty());
    }

    #[test]
    fn media_record_msg_roundtrip_body_bytes() {
        let body = data_body("st-9", b"opus-bytes");
        let msg = MediaRecordMsg::data("n1", "st-9", 7, &body, 1234);
        let s = serde_json::to_vec(&msg).unwrap();
        let back: MediaRecordMsg = serde_json::from_slice(&s).unwrap();
        assert_eq!(back.frame_body().unwrap(), body);
        // base64 is the standard alphabet (E2E/external producers encode with STANDARD)
        assert_eq!(
            back.body_b64,
            base64::engine::general_purpose::STANDARD.encode(&body)
        );
    }

    /// The indexed frame count must match the true segment container (the direct-write path's index metadata relies on it, without parsing bodies).
    #[test]
    fn count_segment_frames_matches_appended_frames() {
        let bodies: Vec<Vec<u8>> = (0..12)
            .map(|i| data_body("st-idx", format!("frame-{i}").as_bytes()))
            .collect();
        let mut buffer = Vec::new();
        for body in &bodies {
            append_record_frame(&mut buffer, body);
        }
        assert_eq!(count_segment_frames(&buffer), bodies.len());
        // Single-frame / empty-buffer boundaries
        let mut one = Vec::new();
        append_record_frame(&mut one, &data_body("s", b"x"));
        assert_eq!(count_segment_frames(&one), 1);
        assert_eq!(count_segment_frames(&[]), 0);
    }

    /// On boundary corruption, return only the count of **confirmed complete** frames: never panic, never count a partial frame
    /// (the index may miss one exact entry, but must not OOM/overrun).
    #[test]
    fn count_segment_frames_tolerates_truncated_boundary() {
        let mut buffer = Vec::new();
        for i in 0..3 {
            append_record_frame(&mut buffer, &data_body("st", format!("f{i}").as_bytes()));
        }
        assert_eq!(count_segment_frames(&buffer), 3);
        // Truncate some bytes from the last frame's tail: the last frame is no longer complete → count only the first 2 frames
        let truncated = &buffer[..buffer.len() - 3];
        assert_eq!(count_segment_frames(truncated), 2);
        // Only a fragment smaller than 4B → 0 frames
        assert_eq!(count_segment_frames(&buffer[..2]), 0);
        // The length prefix claims an oversized value: no overrun, no panic; return the confirmed frame count
        let mut bogus = Vec::new();
        append_record_frame(&mut bogus, b"ok");
        bogus.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(count_segment_frames(&bogus), 1);
    }

    /// Index metadata: the bus path carries exact seq/time ranges; the direct-write path has seq/time None (no fabricated seq).
    #[test]
    fn segment_index_meta_distinguishes_bus_and_direct_paths() {
        let bus = SegmentIndexMeta {
            first_seq: Some(100),
            last_seq: Some(111),
            frames: 12,
            started_at: Some(chrono::Utc::now()),
            ended_at: Some(chrono::Utc::now()),
        };
        assert_eq!(bus.first_seq, Some(100));
        assert_eq!(bus.last_seq, Some(111));
        assert_eq!(bus.frames, 12);
        let direct = SegmentIndexMeta {
            first_seq: None,
            last_seq: None,
            frames: 3,
            started_at: None,
            ended_at: None,
        };
        assert!(direct.first_seq.is_none() && direct.last_seq.is_none());
        assert_eq!(direct.frames, 3);
    }

    /// manifest key: **deterministically derived** from the segment object_key (replay overwrites the same object → idempotent),
    /// and falls under a separate `media/manifest/` prefix (does not change existing E2E's object-count conventions for `media/record/`).
    #[test]
    fn manifest_object_key_is_deterministic_and_separate_prefix() {
        let obj = bus_record_object_key("st-1", "node-a", 42);
        let mk = manifest_object_key(&obj);
        assert_eq!(
            mk,
            "media/manifest/record/st-1/node-a/00000000000000000042.manifest.json"
        );
        // Replay yields the same manifest key (overwrites the same object)
        assert_eq!(mk, manifest_object_key(&obj));
        // No longer under the segment object prefix: existing E2E counting segments by `media/record/{stream}/` is unaffected
        assert!(!mk.starts_with("media/record/"));
        // The direct-write path key (`{utc-seconds}-{seq}.bin`) can also be derived
        assert_eq!(
            manifest_object_key("media/record/st-1/node-a/1700000000-3.bin"),
            "media/manifest/record/st-1/node-a/1700000000-3.manifest.json"
        );
    }

    /// The frame index must be able to reconstruct **every frame body** from the segment object via offset/len (byte-identical to what was persisted).
    #[test]
    fn frames_from_segment_reconstructs_each_body() {
        let bodies: Vec<Vec<u8>> = (0..12)
            .map(|i| data_body("st-manifest", format!("frame-{i}").as_bytes()))
            .collect();
        let mut segment = Vec::new();
        for body in &bodies {
            append_record_frame(&mut segment, body);
        }
        let (frames, total) = frames_from_segment(&segment);
        assert_eq!(total, 12);
        assert_eq!(frames.len(), 12);
        for (i, f) in frames.iter().enumerate() {
            // The direct-write path has no frame seq/arrival time → null (not fabricated)
            assert!(f.seq.is_none());
            assert!(f.ts.is_none());
            assert_eq!(
                &segment[f.offset..f.offset + f.len],
                bodies[i].as_slice(),
                "offset/len must reconstruct frame {i}"
            );
            // offset points to the body start → the preceding 4B are that frame's BE length prefix
            let prefix = u32::from_be_bytes([
                segment[f.offset - 4],
                segment[f.offset - 3],
                segment[f.offset - 2],
                segment[f.offset - 1],
            ]) as usize;
            assert_eq!(prefix, f.len);
        }
        // Boundary corruption (truncate the last frame's tail) → index only confirmed complete frames; no panic/overrun
        let truncated = &segment[..segment.len() - 2];
        let (frames, total) = frames_from_segment(truncated);
        assert_eq!(total, 11);
        assert_eq!(frames.len(), 11);
    }

    /// Large-segment limit: when frame count exceeds `MANIFEST_MAX_FRAMES`, write only the first N frames + `frames_truncated:true`;
    /// `frames_total`/`total_bytes` remain exact (clients use them to know there is unindexed data).
    #[test]
    fn manifest_truncates_large_segment_and_reports_totals() {
        let mut segment = Vec::new();
        for i in 0..(MANIFEST_MAX_FRAMES + 500) {
            append_record_frame(&mut segment, format!("f{i}").as_bytes());
        }
        let (frames, total) = frames_from_segment(&segment);
        assert_eq!(total, MANIFEST_MAX_FRAMES + 500);
        assert_eq!(frames.len(), MANIFEST_MAX_FRAMES, "frame index is bounded");
        let m = build_manifest(
            "st-1",
            "node-a",
            "media/record/st-1/node-a/7.bin",
            segment.len(),
            frames,
            Some(total),
            chrono::Utc::now(),
        );
        assert!(m.frames_truncated);
        assert_eq!(m.frames_total, MANIFEST_MAX_FRAMES + 500);
        assert_eq!(m.total_bytes, segment.len());
        let bytes = serde_json::to_vec(&m).unwrap();
        assert!(
            bytes.len() <= MANIFEST_MAX_BYTES,
            "manifest object size must be bounded: {}",
            bytes.len()
        );
    }

    /// manifest JSON shape: version/object location/format conventions fixed, and **explicitly marked non-playable**.
    #[test]
    fn manifest_json_marks_raw_frames_not_playable() {
        let bodies = [
            data_body("st-manifest", b"a"),
            data_body("st-manifest", b"bb"),
            data_body("st-manifest", b"ccc"),
        ];
        let mut segment = Vec::new();
        for body in &bodies {
            append_record_frame(&mut segment, body);
        }
        let (frames, total) = frames_from_segment(&segment);
        let object_key = "media/record/st-manifest/node-a/00000000000000000007.bin";
        let m = build_manifest(
            "st-manifest",
            "node-a",
            object_key,
            segment.len(),
            frames,
            Some(total),
            chrono::Utc::now(),
        );
        let v: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap();
        assert_eq!(v["version"], MANIFEST_VERSION);
        assert_eq!(v["stream_id"], "st-manifest");
        assert_eq!(v["node_id"], "node-a");
        assert_eq!(v["object_key"], object_key);
        assert_eq!(v["size"], segment.len());
        assert_eq!(v["total_bytes"], segment.len());
        // Capability boundaries stated truthfully: raw frame container, not directly playable, no codec info
        assert_eq!(v["format"], "raw-frames");
        assert_eq!(v["playable"], false);
        assert!(v["codec"].is_null());
        // Frame index: on the direct-write path seq is null in JSON (not 0/fake); offset/len are exact
        let frames_json = v["frames"].as_array().unwrap();
        assert_eq!(frames_json.len(), 3);
        for (i, f) in frames_json.iter().enumerate() {
            assert!(f["seq"].is_null());
            assert!(f.get("ts").is_none(), "the direct-write path has no arrival time → ts field omitted");
            assert_eq!(
                &segment[f["offset"].as_u64().unwrap() as usize
                    ..f["offset"].as_u64().unwrap() as usize + f["len"].as_u64().unwrap() as usize],
                bodies[i].as_slice()
            );
        }
        assert_eq!(v["frames_total"], 3);
        assert_eq!(v["frames_truncated"], false);
        assert!(v["created_at"].as_str().unwrap().contains('T'));
    }
}
