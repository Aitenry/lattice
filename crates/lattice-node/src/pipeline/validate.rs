//! Validation stage: field legality, quota, and size thresholds (② §2.2 `validate`; thresholds in §17.6).

use lattice_core::protocol::{CHUNK_THRESHOLD_MAX_BYTES, INLINE_MAX_BYTES};

use crate::error::{self, Result};
use crate::state::AppState;

/// Allowed `type` namespaces (§5): built-in + `custom:<ns>` + `stream-sig`.
pub const BUILTIN_TYPES: [&str; 11] = [
    "text", "json", "xml", "proto", "msgpack", "binary", "file", "image", "media", "stream",
    "stream-sig",
];

pub fn validate_envelope(env: &lattice_core::Envelope) -> Result<()> {
    if env.id.is_empty() {
        return Err(error::protocol("envelope.id is required"));
    }
    if env.conv_id.is_empty() {
        return Err(error::protocol("envelope.conv_id is required"));
    }
    if env.conv_id.len() > 200 {
        return Err(error::format("conv_id too long"));
    }
    let ty = env.r#type.as_str();
    let known = BUILTIN_TYPES.contains(&ty)
        || (ty.starts_with("custom:") && ty.len() > "custom:".len());
    if !known {
        return Err(error::LatticeError::format(format!("unknown envelope type: {ty}"))
            .with_reason("type"));
    }
    if let Some(chunks) = &env.chunks {
        if chunks.total > 1 && chunks.index >= chunks.total {
            return Err(error::LatticeError::format("chunk index out of range")
                .with_reason("chunk_index"));
        }
    }
    Ok(())
}

/// Per-frame/per-request payload threshold (§17.6). Anything above `chunk.threshold_max` must use MinIO Multipart.
pub fn validate_size(state: &AppState, env: &lattice_core::Envelope) -> Result<()> {
    let size = env.payload.len();
    let is_file_like = matches!(env.r#type.as_str(), "file" | "image" | "media");
    let threshold = state.cfg.policy.chunk_threshold_max.max(INLINE_MAX_BYTES as u64);

    if is_file_like && size as u64 > threshold {
        return Err(error::LatticeError::too_large("payload must use /v1/uploads")
            .with_detail("hint", serde_json::json!("use_uploads")));
    }
    if size as u64 > threshold {
        return Err(error::LatticeError::too_large(format!(
            "payload {size} exceeds chunk threshold {threshold}"
        ))
        .with_detail("hint", serde_json::json!("use_ws_or_chunk")));
    }
        let _ = CHUNK_THRESHOLD_MAX_BYTES; // documented default; at runtime config wins (tunable)
    Ok(())
}

/// Effective **chunk aggregate limit** (§17.6 threshold matrix): a total size with 1MB < size ≤ `chunk.threshold_max` (32MB)
/// is the only case allowed on the WS chunk path; anything larger must use MinIO Multipart at `/v1/uploads` (the >32MB path).
pub fn chunk_aggregate_limit(state: &AppState) -> u64 {
    state
        .cfg
        .policy
        .chunk_threshold_max
        .max(INLINE_MAX_BYTES as u64)
}

/// **Aggregate** cap check for chunk envelopes (E14 S7 defect fix; §17.6).
///
/// The old implementation checked only per-chunk size, so `total` chunks × ≤512KB each could be stitched indefinitely — a
/// `129×256KB=33.8MB` aggregate was ACKed in full, making the ">32MB must use MinIO Multipart" split rule dead code.
///
/// This checks the aggregate as `total × size` **before uplink dedup** (`size` is each chunk's declared size, which must be
/// ≥ the actual payload, see below); anything over the limit is rejected with `FORMAT` directly:
/// - WS `chunk` frame → `error{code=FORMAT}`, with no `chunks_index` registration and no ACK;
///   REST-side chunks go through `/v1/uploads` (Multipart 8MB per chunk); this function only affects the chunk-envelope path;
///   oversized plain REST bodies are still covered by the existing `413 TOO_LARGE + hint=use_ws_or_chunk` fallback.
///
/// `size < payload.len()` is treated as a client trying to bypass the aggregate cap with a small `size`, and is likewise rejected with `FORMAT`.
pub fn validate_chunk_aggregate(state: &AppState, env: &lattice_core::Envelope) -> Result<()> {
    validate_chunk_aggregate_cap(env, chunk_aggregate_limit(state))
}

/// Pure-function core of [`validate_chunk_aggregate`] (easy to unit test, no AppState dependency).
pub fn validate_chunk_aggregate_cap(env: &lattice_core::Envelope, cap: u64) -> Result<()> {
    let Some(chunks) = env.chunks.as_ref() else {
        return Ok(());
    };
    if !env.is_chunk() {
        return Ok(());
    }
    if (chunks.size as usize) < env.payload.len() {
        return Err(error::LatticeError::format(format!(
            "chunk.size {} smaller than payload {}",
            chunks.size,
            env.payload.len()
        ))
        .with_reason("chunk_size"));
    }
    let declared = (chunks.total as u64).saturating_mul(chunks.size as u64);
    if declared > cap {
        return Err(error::LatticeError::format(format!(
            "chunk aggregate {declared} exceeds {cap}; use /v1/uploads multipart"
        ))
        .with_reason("chunk_aggregate")
        .with_detail("hint", serde_json::json!("use_uploads")));
    }
    Ok(())
}

/// Per-user quota and rate limiting (§17.13: 100 msg/s).
pub fn validate_quota(state: &AppState, user: &str, payload_bytes: u64) -> Result<()> {
    if !state.allow_msg(user) {
        state
            .metrics
            .ratelimit_dropped_total
            .with_label_values(&[&crate::observe::Metrics::user_hash(user)])
            .inc();
        return Err(error::LatticeError::rate("rate limit exceeded").with_reason("msg_per_s"));
    }
    if !state.allow_bytes(user, payload_bytes) {
        state
            .metrics
            .ratelimit_dropped_total
            .with_label_values(&[&crate::observe::Metrics::user_hash(user)])
            .inc();
        return Err(error::LatticeError::rate("rate limit exceeded").with_reason("bytes_per_s"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(ty: &str, payload: Vec<u8>) -> lattice_core::Envelope {
        lattice_core::Envelope {
            id: "01J".into(),
            conv_id: "01H".into(),
            r#type: ty.into(),
            payload,
            ..Default::default()
        }
    }

    #[test]
    fn type_namespace_rules() {
        assert!(validate_envelope(&env("text", vec![])).is_ok());
        assert!(validate_envelope(&env("custom:iot", vec![])).is_ok());
        assert!(validate_envelope(&env("nope", vec![])).is_err());
        assert!(validate_envelope(&env("custom:", vec![])).is_err());
    }

    #[test]
    fn required_fields() {
        let mut e = env("text", vec![]);
        e.id = String::new();
        assert_eq!(validate_envelope(&e).unwrap_err().code, lattice_core::ErrorCode::Protocol);
        let mut e2 = env("text", vec![]);
        e2.conv_id = String::new();
        assert!(validate_envelope(&e2).is_err());
    }

    #[test]
    fn chunk_index_bounds() {
        let mut e = env("binary", vec![]);
        e.chunks = Some(lattice_core::ChunkInfo { total: 3, index: 3, size: 1, checksum: vec![] });
        assert!(validate_envelope(&e).is_err());
    }

    #[test]
    fn chunk_aggregate_over_32mb_is_rejected() {
        const MB: u64 = 1024 * 1024;
        const PART: usize = 256 * 1024;
        let cap = 32 * MB;
                // 129 × 256KB = 33.8MB > 32MB: the S7 defect scenario must be rejected with FORMAT
        let mut over = env("binary", vec![0x43; PART]);
        over.chunks = Some(lattice_core::ChunkInfo {
            total: 129,
            index: 0,
            size: PART as u32,
            checksum: vec![],
        });
        let err = validate_chunk_aggregate_cap(&over, cap).unwrap_err();
        assert_eq!(err.code, lattice_core::ErrorCode::Format);
        assert_eq!(err.details.as_ref().and_then(|d| d.get("reason")).and_then(|v| v.as_str()), Some("chunk_aggregate"));

                // 128 × 256KB = 32MB: within the boundary (≤ cap) and must be allowed
        let mut at = env("binary", vec![0x43; PART]);
        at.chunks = Some(lattice_core::ChunkInfo {
            total: 128,
            index: 127,
            size: PART as u32,
            checksum: vec![],
        });
        assert!(validate_chunk_aggregate_cap(&at, cap).is_ok());

                // Single-chunk path (total=1) is unaffected by aggregate validation
        let mut single = env("text", vec![1, 2, 3]);
        single.chunks = Some(lattice_core::ChunkInfo {
            total: 1,
            index: 0,
            size: 3,
            checksum: vec![],
        });
        assert!(validate_chunk_aggregate_cap(&single, cap).is_ok());
    }

    #[test]
    fn chunk_size_smaller_than_payload_is_rejected() {
        let cap = 32 * 1024 * 1024;
        let mut e = env("binary", vec![0x43; 256 * 1024]);
        e.chunks = Some(lattice_core::ChunkInfo {
            total: 200,
            index: 0,
                        size: 1, // misreported chunk size: could bypass the total×size aggregate cap
            checksum: vec![],
        });
        let err = validate_chunk_aggregate_cap(&e, cap).unwrap_err();
        assert_eq!(err.code, lattice_core::ErrorCode::Format);
        assert_eq!(err.details.as_ref().and_then(|d| d.get("reason")).and_then(|v| v.as_str()), Some("chunk_size"));
    }
}
