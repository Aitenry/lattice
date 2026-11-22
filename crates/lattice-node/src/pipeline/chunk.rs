//! Chunk management (② §4.3). Ownership rules (§17.2):
//!
//! | Object | messages | seq | chunks_index | Idempotency key |
//! | --- | --- | --- | --- | --- |
//! | Logical message | 1 row (after reassembly validation passes) | allocated once | N rows | `id` |
//! | Chunk envelope | **not stored** | **not allocated** | 1 row/chunk | `<id>.c<i>` |
//!
//! Hence there is no `GET /v1/messages/{id}.c0` — chunk ids appear only in `chunks_index` and transport frames (⑤ §4.4).
//!
//! **Reassembly (E18, §17.2)**: when a chunk arrives, only register `chunks_index` and put the payload into the **in-process buffer**
//! (§18 D1: WS chunks aggregate in memory; network chunks have `chunks_index.storage_key` = null, see migration 0002);
//! once all chunks are present, stitch them back by `index` and verify the whole `checksum_sha256` (carried by the head chunk, §17.6); only after it passes:
//!   1) write the complete payload as a MinIO object (object key `{yyyy}/{mm}/{dd}/{id}/c0.bin`, ⑥ §4.1);
//!   2) produce the **logical message Envelope** (`payload_ref` + `metadata.size`, payload no longer inlined) and run it through the normal pipeline
//!      — allocate seq once, store 1 `messages` row, deliver per §17.4;
//! Verification failure / buffer loss → delete the `chunks_index` rows and release the chunk dedup claims, and reply an explicit error frame (terminal, no partial state).
//!
//! **Boundary (what really remains)**: the buffer is in-process (design D1's "in-memory aggregation"), so a node restart loses payloads whose aggregation
//! was incomplete; the `chunks_index` rows are still cleaned up by `lock:chunk-clean` after 24h. When a new chunk arrives, "index row present
//! but no buffer" is detected and cleaned up as terminal; the client can retransmit the same set of chunk ids (no partial messages are produced).

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lattice_core::Envelope;

use crate::error::{self, Result};
use crate::state::AppState;

/// Total byte cap of the in-process reassembly buffer (§18 D1's 32MB/message + concurrency headroom; over the limit is rejected explicitly instead of queueing into OOM).
const MAX_BUFFERED_BYTES: usize = 96 * 1024 * 1024;
/// Cap on the number of logical messages being aggregated at the same time.
const MAX_PENDING_MESSAGES: usize = 512;
/// Lifetime of an unfinished aggregation buffer (aligned with the 24h of ⑥ §2.6 `chunk-clean`; lazily cleaned up).
const PENDING_TTL: Duration = Duration::from_secs(24 * 3600);

/// A logical message currently being aggregated.
#[derive(Debug)]
struct Pending {
    conv_id: String,
    total: u32,
    parts: BTreeMap<u32, Vec<u8>>,
        /// Header-field template: type/content_type/route/ttl/metadata etc. of the chunk envelope (payload already cleared).
    template: Envelope,
        /// Whole `checksum_sha256` (carried by the head chunk; empty = not provided by the client, treated as no verification).
    checksum: Vec<u8>,
    bytes: usize,
    created: Instant,
}

/// In-process reassembly buffer (the `Mutex` critical section only does memory reads/writes and never crosses an await).
#[derive(Debug)]
struct Reassembly {
    pending: HashMap<String, Pending>,
    buffered_bytes: usize,
    max_bytes: usize,
    max_messages: usize,
    ttl: Duration,
}

impl Reassembly {
    fn new(max_bytes: usize, max_messages: usize, ttl: Duration) -> Self {
        Reassembly {
            pending: HashMap::new(),
            buffered_bytes: 0,
            max_bytes,
            max_messages,
            ttl,
        }
    }

        /// Lazily purge aggregations unfinished for more than 24h (in-process memory protection).
    fn purge_stale(&mut self, now: Instant) {
        let ttl = self.ttl;
        let mut freed = 0usize;
        self.pending.retain(|msg_id, p| {
            if now.duration_since(p.created) > ttl {
                freed += p.bytes;
                tracing::warn!(msg_id, bytes = p.bytes, "dropping stale chunk reassembly buffer (>24h)");
                false
            } else {
                true
            }
        });
        self.buffered_bytes = self.buffered_bytes.saturating_sub(freed);
    }

        /// Insert one chunk. `total/conv_id/whole checksum` must match the existing aggregation; over the memory cap → RATE.
    fn insert(&mut self, env: &Envelope, msg_id: &str, idx: u32, total: u32) -> Result<bool> {
        let payload_len = env.payload.len();
        if let Some(p) = self.pending.get_mut(msg_id) {
            if p.total != total {
                return Err(error::LatticeError::format(format!(
                    "chunk total mismatch: {} vs {total}",
                    p.total
                ))
                .with_reason("chunk_total"));
            }
            if p.conv_id != env.conv_id {
                return Err(error::LatticeError::format("chunk conv_id mismatch")
                    .with_reason("chunk_conv"));
            }
            if !p.checksum.is_empty()
                && !env.checksum_sha256.is_empty()
                && p.checksum != env.checksum_sha256
            {
                return Err(error::LatticeError::format(
                    "chunk envelope declares a different whole-message checksum",
                )
                .with_reason("checksum"));
            }
            if p.checksum.is_empty() && !env.checksum_sha256.is_empty() {
                p.checksum = env.checksum_sha256.clone();
            }
            if let Some(old) = p.parts.remove(&idx) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(old.len());
                p.bytes = p.bytes.saturating_sub(old.len());
            }
            if self.buffered_bytes + payload_len > self.max_bytes {
                return Err(error::LatticeError::rate("chunk reassembly buffer full")
                    .with_reason("reassembly_full"));
            }
            self.buffered_bytes += payload_len;
            p.bytes += payload_len;
            p.parts.insert(idx, env.payload.clone());
            return Ok(false);
        }

        if self.pending.len() >= self.max_messages {
            return Err(error::LatticeError::rate("too many concurrent chunk reassemblies")
                .with_reason("reassembly_full"));
        }
        if self.buffered_bytes + payload_len > self.max_bytes {
            return Err(error::LatticeError::rate("chunk reassembly buffer full")
                .with_reason("reassembly_full"));
        }
        let mut template = env.clone();
        template.payload.clear();
        template.chunks = None;
        let mut parts = BTreeMap::new();
        parts.insert(idx, env.payload.clone());
        self.buffered_bytes += payload_len;
        self.pending.insert(
            msg_id.to_string(),
            Pending {
                conv_id: env.conv_id.clone(),
                total,
                parts,
                template,
                checksum: env.checksum_sha256.clone(),
                bytes: payload_len,
                created: Instant::now(),
            },
        );
        Ok(false)
    }

        /// Take the aggregation that is ready to reassemble (completeness decided by DB row count, then `take`).
    fn take(&mut self, msg_id: &str) -> Option<Pending> {
        let p = self.pending.remove(msg_id)?;
        self.buffered_bytes = self.buffered_bytes.saturating_sub(p.bytes);
        Some(p)
    }

        /// Drop one chunk's buffer (used to roll back a failed DB write).
    fn remove_chunk(&mut self, msg_id: &str, idx: u32) {
        if let Some(p) = self.pending.get_mut(msg_id) {
            if let Some(old) = p.parts.remove(&idx) {
                p.bytes = p.bytes.saturating_sub(old.len());
                self.buffered_bytes = self.buffered_bytes.saturating_sub(old.len());
            }
            if p.parts.is_empty() {
                self.pending.remove(msg_id);
            }
        }
    }
}

fn global() -> &'static Mutex<Reassembly> {
    static BUFFER: std::sync::OnceLock<Mutex<Reassembly>> = std::sync::OnceLock::new();
    BUFFER.get_or_init(|| {
        Mutex::new(Reassembly::new(
            MAX_BUFFERED_BYTES,
            MAX_PENDING_MESSAGES,
            PENDING_TTL,
        ))
    })
}

fn lock() -> std::sync::MutexGuard<'static, Reassembly> {
        // The buffer holds memory data only and the critical section cannot panic; keep using the inner value even if poisoned (do not let one bad path poison the upload hot path).
    global().lock().unwrap_or_else(|e| e.into_inner())
}

/// Chunk arrival: register `chunks_index` (unique `(msg_id, idx)`) and put it into the aggregation buffer;
/// **when chunks are complete**, finish reassembly, verify the whole, write the object, and produce the logical message (allocate seq once + deliver).
///
/// Returns `true` when this call completed reassembly and dispatched the logical message.
pub async fn accept_chunk(
    state: &AppState,
    env: &lattice_core::Envelope,
    storage_key: Option<&str>,
) -> Result<bool> {
    let chunks = env
        .chunks
        .as_ref()
        .ok_or_else(|| error::format("chunk frame without chunks info"))?;
    let (msg_id, idx) = lattice_core::ids::parse_chunk_id(&env.id)
        .ok_or_else(|| error::LatticeError::format("chunk id must be <id>.c<i>").with_reason("id"))?;
    if idx != chunks.index {
        return Err(error::LatticeError::format("chunk id/index mismatch").with_reason("id"));
    }
    if (chunks.size as usize) < env.payload.len() {
        return Err(error::LatticeError::format(format!(
            "chunk.size {} smaller than payload {}",
            chunks.size,
            env.payload.len()
        ))
        .with_reason("chunk_size"));
    }
        // Chunk-level xxhash64 (§6.2): if provided it must match; a bad chunk is rejected at the door (no chunks_index registration).
    if !chunks.checksum.is_empty() {
        let actual = lattice_core::envelope::xxhash64(&env.payload);
        if actual.as_slice() != chunks.checksum.as_slice() {
            return Err(error::LatticeError::format("chunk checksum mismatch")
                .with_reason("chunk_checksum")
                .with_detail("index", serde_json::json!(idx)));
        }
    }
    let msg_id_owned = msg_id.to_string();
    let total = chunks.total;

        // 1) Insert into the in-process buffer first (with the memory cap check), then write the DB: a DB failure can roll back the buffer.
    {
        let mut buf = lock();
        buf.purge_stale(Instant::now());
        buf.insert(env, &msg_id_owned, idx, total)?;
    }

        // 2) Register chunks_index (unique `(msg_id, idx)`, idempotent for duplicate chunks).
    if let Err(e) = crate::store::pg::upsert_chunk(
        &state.db,
        &msg_id_owned,
        Some(env.conv_id.as_str()),
        total as i32,
        idx as i32,
        chunks.size as i64,
        if chunks.checksum.is_empty() {
            None
        } else {
            Some(chunks.checksum.clone())
        },
        storage_key,
    )
    .await
    {
        lock().remove_chunk(&msg_id_owned, idx);
        return Err(e);
    }

        // 3) Completeness is decided by DB row count (§17.2's persistence fact); not complete → ACK only.
    let rows = crate::store::pg::chunks_of(&state.db, &msg_id_owned).await?;
    if (rows.len() as u32) < total {
        return Ok(false);
    }

    let Some(pending) = lock().take(&msg_id_owned) else {
                // A concurrent path already took it: the logical message is already stored → idempotent success; otherwise the buffer was lost (process restart).
        if crate::store::pg::message_by_id(&state.db, &msg_id_owned)
            .await?
            .is_some()
        {
            return Ok(false);
        }
        cleanup_incomplete(state, &msg_id_owned, total).await;
        return Err(error::LatticeError::format(
            "chunk reassembly buffer lost (node restart?); retransmit all chunks",
        )
        .with_reason("reassembly_lost"));
    };
    if pending.parts.len() != total as usize {
        cleanup_incomplete(state, &msg_id_owned, total).await;
        return Err(error::LatticeError::format(
            "chunk reassembly incomplete; retransmit all chunks",
        )
        .with_reason("reassembly_lost"));
    }

        // 4) Whole verification (§17.6: sha256 carried by the head chunk; not provided is treated as no verification).
    if !whole_checksum_matches(&pending.checksum, &pending.parts) {
        let removed = crate::store::pg::delete_chunks(&state.db, &msg_id_owned)
            .await
            .unwrap_or(0);
        release_dedup_claims(state, &msg_id_owned, total, false).await;
        state
            .metrics
            .chunk_retrans_total
            .with_label_values(&["checksum_failed"])
            .inc();
        tracing::warn!(
            msg_id = %msg_id_owned,
            removed,
            "chunk reassembly whole-checksum mismatch; chunks_index cleared (terminal failure)"
        );
        return Err(
            error::LatticeError::format("reassembled payload checksum mismatch")
                .with_reason("checksum"),
        );
    }

        // 5) Stitch the complete payload → write the MinIO object (§17.2 logical message = payload_ref, not stored in PG).
    let mut payload = Vec::with_capacity(pending.bytes);
    for p in pending.parts.into_values() {
        payload.extend_from_slice(&p);
    }
    let bucket = state.s3.cfg().bucket_large.clone();
    let object_key = state.s3.object_key(&msg_id_owned, 0);
    if let Err(e) = state.s3.put_bytes(&bucket, &object_key, &payload).await {
        cleanup_incomplete(state, &msg_id_owned, total).await;
        return Err(error::internal(format!("reassembled object write failed: {e}"))
            .with_detail("dep", serde_json::json!("s3")));
    }

        // 6) Produce the logical message Envelope and run the normal pipeline (allocate seq once, store messages, deliver per §17.4).
    let mut logical = pending.template;
    logical.id = msg_id_owned.clone();
    logical.payload = Vec::new();
    logical.chunks = None;
        logical.seq = 0; // allocated centrally by ingest (§17.2 "allocate once when reassembly validation passes")
    logical.checksum_sha256 = pending.checksum.clone();
    logical
        .metadata
        .insert("payload_ref".to_string(), object_key.clone());
    logical
        .metadata
        .insert("size".to_string(), payload.len().to_string());
    logical
        .metadata
        .insert("chunk_total".to_string(), total.to_string());
    let sender = logical.sender.clone();
    let size = payload.len();

    state
        .metrics
        .chunk_retrans_total
        .with_label_values(&["reassembled"])
        .inc();
        // Mutual recursion (ingest → accept_chunk → ingest) must be boxed once, otherwise the future size is unbounded.
    match Box::pin(crate::pipeline::ingest(state, &sender, "", logical)).await {
        Ok(out) => {
            tracing::info!(
                msg_id = %msg_id_owned,
                seq = out.seq,
                size,
                total,
                "chunks complete: logical message reassembled and dispatched"
            );
            Ok(true)
        }
        Err(e) => {
                        // Roll back object + index rows + dedup claims: the client can retransmit the whole set with the same chunk ids.
            let _ = state.s3.delete_object(&bucket, &object_key).await;
            cleanup_incomplete(state, &msg_id_owned, total).await;
            Err(e)
        }
    }
}

/// Whole verification: sha256 over the payloads concatenated in `index` order (empty expected = no verification provided).
fn whole_checksum_matches(expected: &[u8], parts: &BTreeMap<u32, Vec<u8>>) -> bool {
    if expected.is_empty() {
        return true;
    }
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts.values() {
        h.update(p);
    }
    h.finalize().as_slice() == expected
}

/// Terminal cleanup of a failed reassembly: delete the `chunks_index` rows and release the chunk (and logical-message) dedup claims.
async fn cleanup_incomplete(state: &AppState, msg_id: &str, total: u32) {
    let removed = crate::store::pg::delete_chunks(&state.db, msg_id)
        .await
        .unwrap_or(0);
    release_dedup_claims(state, msg_id, total, true).await;
    tracing::warn!(
        msg_id,
        total,
        removed,
        "chunk reassembly failed: chunks_index cleared and dedup claims released (client may retransmit)"
    );
}

/// Release the Redis dedup claims for the chunk ids (and optionally the logical message id) so retransmits are not mistaken for duplicates.
async fn release_dedup_claims(
    state: &AppState,
    msg_id: &str,
    total: u32,
    include_logical: bool,
) {
    for i in 0..total {
        crate::pipeline::wal_degrade::release_dedup_claim(
            state,
            &lattice_core::ids::chunk_id(msg_id, i),
        )
        .await;
    }
    if include_logical {
        crate::pipeline::wal_degrade::release_dedup_claim(state, msg_id).await;
    }
}

/// Completeness check: returns `Some(number of chunks received)` when reassembly is possible (kept for diagnostics/tests).
pub async fn reassembly_status(state: &AppState, msg_id: &str, total: u32) -> Result<Option<Vec<u32>>> {
    let rows = crate::store::pg::chunks_of(&state.db, msg_id).await?;
    let mut got: Vec<u32> = rows.iter().map(|r| r.idx as u32).collect();
    got.sort_unstable();
    got.dedup();
    if got.len() as u32 == total && total > 0 {
        Ok(Some(got))
    } else {
        Ok(None)
    }
}

/// Missing-chunk list (shared by receiver-side `request-chunks` and `GET /v1/chunks`, ⑤ §9.3).
pub fn missing_indexes(total: u32, got: &[u32]) -> Vec<u32> {
    (0..total).filter(|i| !got.contains(i)).collect()
}

/// Whole verification (§6.2: sha256 lives in the head chunk, verified at the reassembly side).
pub fn verify_whole(expected: &[u8], parts: &[Vec<u8>]) -> bool {
    if expected.is_empty() {
        return true;
    }
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().as_slice() == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk_env(msg_id: &str, total: u32, index: u32, payload: Vec<u8>) -> Envelope {
        Envelope {
            id: lattice_core::ids::chunk_id(msg_id, index),
            r#type: "binary".into(),
            content_type: "application/octet-stream".into(),
            encoding: "raw".into(),
            conv_id: "01HTESTCONV00000000000000".into(),
            payload,
            chunks: Some(lattice_core::ChunkInfo {
                total,
                index,
                size: 0,
                checksum: vec![],
            }),
            ..Default::default()
        }
    }

    #[test]
    fn missing_indexes_reports_gaps() {
        assert_eq!(missing_indexes(4, &[0, 2]), vec![1, 3]);
        assert!(missing_indexes(2, &[0, 1]).is_empty());
    }

    #[test]
    fn whole_checksum_verification() {
        use sha2::{Digest, Sha256};
        let parts = vec![b"abc".to_vec(), b"def".to_vec()];
        let mut h = Sha256::new();
        h.update(b"abcdef");
        let expected = h.finalize().to_vec();
        assert!(verify_whole(&expected, &parts));
        assert!(!verify_whole(&expected, &vec![b"abc".to_vec()]));
                assert!(verify_whole(&[], &parts), "empty checksum is treated as no verification provided");
    }

    #[test]
    fn reassembly_buffers_out_of_order_and_orders_parts() {
        let mut r = Reassembly::new(1024, 8, Duration::from_secs(60));
        let msg = "01JTESTMSG000000000000001";
        assert!(!r.insert(&chunk_env(msg, 3, 2, b"cc".to_vec()), msg, 2, 3).unwrap());
        assert!(!r.insert(&chunk_env(msg, 3, 0, b"aa".to_vec()), msg, 0, 3).unwrap());
        assert!(!r.insert(&chunk_env(msg, 3, 1, b"bb".to_vec()), msg, 1, 3).unwrap());
        let p = r.take(msg).expect("complete buffer");
        assert_eq!(p.parts.len(), 3);
        let mut joined = Vec::new();
        for v in p.parts.into_values() {
            joined.extend_from_slice(&v);
        }
        assert_eq!(joined, b"aabbcc");
                assert!(r.take(msg).is_none(), "take can only succeed once");
    }

    #[test]
    fn reassembly_enforces_memory_and_message_caps() {
        let mut r = Reassembly::new(4, 1, Duration::from_secs(60));
        let a = "01JTESTMSG00000000000000A";
        let b = "01JTESTMSG00000000000000B";
        assert!(!r.insert(&chunk_env(a, 2, 0, b"aa".to_vec()), a, 0, 2).unwrap());
                // Retransmitting the same chunk only overwrites; bytes are not counted twice
        assert!(!r.insert(&chunk_env(a, 2, 0, b"aa".to_vec()), a, 0, 2).unwrap());
        assert_eq!(r.buffered_bytes, 2);
                // A second aggregation exceeds max_messages=1 → RATE
        let err = r
            .insert(&chunk_env(b, 2, 0, b"bb".to_vec()), b, 0, 2)
            .unwrap_err();
        assert_eq!(err.code, lattice_core::ErrorCode::Rate);
                // Total bytes over the limit → RATE (verified with another in-process buffer instance)
        let mut small = Reassembly::new(4, 8, Duration::from_secs(60));
        assert!(!small.insert(&chunk_env(a, 4, 0, b"aa".to_vec()), a, 0, 4).unwrap());
        assert!(!small.insert(&chunk_env(a, 4, 1, b"bb".to_vec()), a, 1, 4).unwrap());
        let err = small
            .insert(&chunk_env(a, 4, 2, b"ccc".to_vec()), a, 2, 4)
            .unwrap_err();
        assert_eq!(err.code, lattice_core::ErrorCode::Rate);
        assert_eq!(err.details.as_ref().and_then(|d| d.get("reason")).and_then(|v| v.as_str()), Some("reassembly_full"));
    }

    #[test]
    fn reassembly_rejects_inconsistent_headers() {
        let mut r = Reassembly::new(1024, 8, Duration::from_secs(60));
        let msg = "01JTESTMSG000000000000002";
        r.insert(&chunk_env(msg, 3, 0, b"aa".to_vec()), msg, 0, 3).unwrap();
                // total mismatch
        let mut e = chunk_env(msg, 4, 1, b"bb".to_vec());
        e.chunks.as_mut().unwrap().total = 4;
                // Called with an explicit total argument (simulating another chunk declaring a different total)
        assert!(r.insert(&e, msg, 1, 4).is_err());
                // conv_id mismatch
        let mut e2 = chunk_env(msg, 3, 1, b"bb".to_vec());
        e2.conv_id = "01HOTHERCONV0000000000000".into();
        assert!(r.insert(&e2, msg, 1, 3).is_err());
                // Whole checksum header mismatch
        let mut e3 = chunk_env(msg, 3, 1, b"bb".to_vec());
        e3.checksum_sha256 = vec![1; 32];
        r.insert(&e3, msg, 1, 3).unwrap();
        let mut e4 = chunk_env(msg, 3, 2, b"cc".to_vec());
        e4.checksum_sha256 = vec![2; 32];
        assert!(r.insert(&e4, msg, 2, 3).is_err());
    }

    #[test]
    fn stale_buffers_are_purged() {
        let mut r = Reassembly::new(1024, 8, Duration::from_millis(1));
        let msg = "01JTESTMSG000000000000003";
        r.insert(&chunk_env(msg, 2, 0, b"aa".to_vec()), msg, 0, 2).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        r.purge_stale(Instant::now());
        assert!(r.take(msg).is_none());
        assert_eq!(r.buffered_bytes, 0);
    }

    #[test]
    fn whole_checksum_matches_incremental_order() {
        use sha2::{Digest, Sha256};
        let mut map = BTreeMap::new();
        map.insert(1u32, b"def".to_vec());
        map.insert(0u32, b"abc".to_vec());
        let mut h = Sha256::new();
        h.update(b"abcdef");
        let expected = h.finalize().to_vec();
        assert!(whole_checksum_matches(&expected, &map));
        assert!(whole_checksum_matches(&[], &map));
        let mut wrong = expected.clone();
        wrong[0] ^= 0xff;
        assert!(!whole_checksum_matches(&wrong, &map));
    }
}
