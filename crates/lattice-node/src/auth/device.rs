//! Devices and fingerprints (§17.11 / ⑥ §2.3 `devices`).
//!
//! Rules:
//! - `hello` must report `device_fp`; a mismatch with the login record → `AUTH_FAIL` and forced re-login (⑤ §9.6);
//! - One user + one fingerprint has exactly one active device row (`devices_active_fp_uk`); repeated logins reuse it (⑥ D10).

use crate::error::{self, Result};
use crate::store::pg;

/// Check whether the reported fingerprint matches the stored device fingerprint.
pub fn verify_fingerprint(expected: Option<&str>, reported: &str, required: bool) -> Result<()> {
    if !required {
        return Ok(());
    }
    match expected {
        Some(e) if !e.is_empty() => {
            if e == reported {
                Ok(())
            } else {
                Err(error::unauthorized("device fingerprint mismatch").with_reason("fp_mismatch"))
            }
        }
// No fingerprint in the DB (legacy device): the caller backfills it on the first frame, so allow here.
        _ => Ok(()),
    }
}

/// Device resolution on login/reconnect: reuse the same fingerprint and refresh `last_seen` when present.
pub async fn resolve_device(
    pool: &pg::Pool,
    user_id: &str,
    device_fp: &str,
    device_name: Option<&str>,
    platform: Option<&str>,
    token_hash: Option<&str>,
) -> Result<pg::Device> {
    pg::upsert_device(pool, user_id, device_fp, device_name, platform, token_hash).await
}

/// Handling when the WS `hello` device fingerprint does not match: **revoke the device refresh chain + audit trail**.
///
/// Contract source (② §6 "authentication" row): a `hello` fingerprint mismatch with the DB means device credentials may be impersonated →
/// "force re-login (token revocation)"; ⑤ §8.6 audit write points include "refresh failure, device revocation".
/// Rejection itself is done by the WS layer with `AUTH_FAIL` and close (⑤ §9.6); this function only revokes and audits.
/// The access JWT is a stateless snapshot (TTL 900s, ⑤ §0.2); the refresh chain becomes unrenewable immediately here.
///
/// Failure policy: revocation failure only WARNs (the connection must still be rejected with AUTH_FAIL; a storage fault must never let it through);
/// audit is non-fatal (same as login) and only WARNs on failure.
pub async fn revoke_on_fingerprint_mismatch(
    st: &std::sync::Arc<crate::state::AppState>,
    user_id: &str,
    device_id: &str,
    expected_fp: Option<&str>,
    reported_fp: &str,
    ip: Option<&str>,
) {
    if let Err(e) = pg::revoke_device(&st.db, device_id).await {
        tracing::warn!(
            error = %e,
            device = %device_id,
            "revoke device on fingerprint mismatch failed"
        );
    }
    if let Err(e) = crate::routing::audit::audit_emit(
        st,
        Some(user_id),
        "device.fp_mismatch",
        Some(device_id),
        &serde_json::json!({
            "reason": "fp_mismatch",
            "expected": expected_fp,
            "reported": reported_fp,
            "device_revoked": true,
        }),
        ip,
    )
    .await
    {
        tracing::warn!(error = %e, device = %device_id, "fingerprint mismatch audit write failed (non-fatal)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_mismatch_is_auth_fail() {
        let e = verify_fingerprint(Some("sha256:aaa"), "sha256:bbb", true).unwrap_err();
        assert_eq!(e.code, lattice_core::ErrorCode::AuthFail);
        assert!(verify_fingerprint(Some("sha256:aaa"), "sha256:aaa", true).is_ok());
        assert!(verify_fingerprint(None, "sha256:bbb", true).is_ok());
        assert!(verify_fingerprint(Some("x"), "y", false).is_ok());
    }
}
