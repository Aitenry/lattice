//! Compression and encryption (② §4.6).
//!
//! There are only two mode names (§17.7): `zero-knowledge` (default) / `inspectable`.
//! - zero-knowledge: the server **does not decrypt, decompress, or parse** the payload; it reads only header fields for routing and dedup;
//! - inspectable: the KEK is wrapped by KMS/Vault (annual rotation, dual-KEK overlap), so the server may decrypt for audit/scan/transform,
//!   but the cluster must be physically isolated (separate LB/PG/MinIO).
//!
//! This module is the **mode gate and KEK reference**; actual payload encryption happens in the SDK (E2E, §6.3) — the server holds no session keys.
//! Since E15, loading/wrap/unwrap/re-encryption/audit of node-local KEKs is implemented in
//! [`crate::pipeline::inspectable`] (loaded by `Config::load` when `[inspectable] enabled=true`;
//! production KMS is not wired up, so rotation = change env/file then restart; dual KEK uses the `previous_kek*` overlap window).

use lattice_core::Mode;

use crate::error::{self, Result};
use crate::state::AppState;

/// Whether the server may read payload plaintext (audit/transform/compress).
pub fn may_inspect(state: &AppState) -> bool {
    matches!(state.mode(), Mode::Inspectable)
}

/// In zero-knowledge mode, reject any operation where "the server reads plaintext" (⑤ §8.3 console never displays payload).
pub fn ensure_can_inspect(state: &AppState, op: &str) -> Result<()> {
    if may_inspect(state) {
        Ok(())
    } else {
        Err(error::forbidden(format!("{op} requires inspectable mode"))
            .with_reason("zero_knowledge"))
    }
}

/// Server-side compression policy: always skipped in zero-knowledge mode (compression is done by the SDK, §6.3).
pub fn server_side_compress(state: &AppState, payload: &[u8]) -> Option<Vec<u8>> {
    if !may_inspect(state) || payload.len() < 1024 {
        return None;
    }
    // Transparent while no compression implementation is wired in: returning None means "do not compress" (semantically the same as "no compressible gain").
    None
}

/// KEK fingerprint (kept for audit trails in inspectable mode; private/plaintext keys never enter logs, §6.3).
///
/// Prefer the active fingerprint of the node-local loaded KEK (E15 `[inspectable]`); when not loaded, fall back to
/// `kek.active_fingerprint` in dynamic config (the KMS reference convention). The fingerprint is a sha256 prefix, one-way.
pub fn kek_fingerprint(state: &AppState) -> Option<String> {
    if !may_inspect(state) {
        return None;
    }
    if let Some(fingerprint) = crate::pipeline::inspectable::global_ring()
        .map(|ring| ring.active_fingerprint().to_string())
    {
        return Some(fingerprint);
    }
    state
        .dynamic
        .read()
        .ok()
        .and_then(|m| m.get("kek.active_fingerprint").cloned())
        .and_then(|v| v.as_str().map(str::to_string))
}

#[cfg(test)]
mod tests {
    #[test]
    fn inspectable_gate_reason() {
        let e = crate::error::forbidden("read content requires inspectable mode")
            .with_reason("zero_knowledge");
        assert_eq!(e.code, lattice_core::ErrorCode::Forbidden);
        assert_eq!(e.http_status(), 403);
    }
}
