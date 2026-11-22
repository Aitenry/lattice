//! ULID and chunk ids (§17.2).
//!
//! Message ids use ULID: **the first 48 bits are a millisecond timestamp**, which lets the server locate the `messages` partition directly (⑥ §2.4).

/// Generate a new ULID (26-character Crockford Base32).
pub fn new_id() -> String {
    ulid::Ulid::new().to_string()
}

/// Build an id from a millisecond timestamp (for tests and reconciliation scripts).
pub fn id_at_ms(ms: u64) -> String {
    ulid::Ulid::from_parts(ms, rand_tail()).to_string()
}

fn rand_tail() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u128)
        .unwrap_or(0);
    // Low 80 bits of randomness + time entropy; used only for id uniqueness, never for security
    let mix = (nanos << 32) ^ (std::process::id() as u128) << 8;
    mix & ((1u128 << 80) - 1)
}

/// Whether the string is a valid ULID (26 characters).
pub fn is_ulid(s: &str) -> bool {
    ulid::Ulid::from_string(s).is_ok()
}

/// Chunk envelope id: `<id>.c<i>` (§17.2).
pub fn chunk_id(msg_id: &str, index: u32) -> String {
    format!("{msg_id}.c{index}")
}

/// Parse a chunk envelope id → `(msg_id, index)`; returns None for a non-chunk id.
pub fn parse_chunk_id(id: &str) -> Option<(&str, u32)> {
    let (msg, tail) = id.rsplit_once(".c")?;
    let idx: u32 = tail.parse().ok()?;
    Some((msg, idx))
}

/// Millisecond timestamp of the ULID's first 48 bits (⑥ §2.4: basis for partition pruning).
pub fn ms_of(id: &str) -> Option<u64> {
    let u = ulid::Ulid::from_string(id).ok()?;
    Some(u.timestamp_ms())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulid_shape() {
        let id = new_id();
        assert_eq!(id.len(), 26);
        assert!(is_ulid(&id));
        assert!(ms_of(&id).is_some());
    }

    #[test]
    fn chunk_id_roundtrip() {
        let id = new_id();
        let c = chunk_id(&id, 7);
        assert!(c.ends_with(".c7"));
        let (msg, idx) = parse_chunk_id(&c).unwrap();
        assert_eq!(msg, id);
        assert_eq!(idx, 7);
        assert!(parse_chunk_id(&id).is_none());
    }

    #[test]
    fn ids_are_monotonic_by_time_prefix() {
        let a = id_at_ms(1_700_000_000_000);
        let b = id_at_ms(1_700_000_001_000);
        assert!(a < b, "ULIDs with the same millisecond prefix must compare in lexicographic order");
    }
}
