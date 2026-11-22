//! Password hashing and refresh tokens (§17.11: argon2id; refresh is 256 random bits, the server stores only the hash).

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use sha2::{Digest, Sha256};

use crate::error::{self, Result};

/// Password length baseline (② §6: complexity policy belongs to the upstream IdP/operations; the server enforces only the length floor).
pub const MIN_PASSWORD_CHARS: usize = 8;
pub const MAX_PASSWORD_CHARS: usize = 128;

/// Validate that a new password meets the server baseline: non-empty, 8–128 characters.
///
/// Account creation, administrator password reset, and user self-service change share this one validation, avoiding
/// "8–128 at creation but 1 char allowed at change" dual policies in the same domain (⑤ §0.5 error body: 422 FORMAT +
/// `details.field=password` / `details.rule=8-128`).
pub fn validate_password(password: &str) -> Result<()> {
    let len = password.chars().count();
    if len < MIN_PASSWORD_CHARS || len > MAX_PASSWORD_CHARS {
        return Err(error::format("invalid password length")
            .with_detail("field", serde_json::json!("password"))
            .with_detail("rule", serde_json::json!("8-128")));
    }
    Ok(())
}

/// argon2id hash (② §6 authentication).
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| error::internal(format!("password hash failed: {e}")))
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    match PasswordHash::new(stored) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// refresh token: 32 random bytes → `b64:<base64url>`; the server stores only `sha256` (`devices.token_hash`).
pub fn new_refresh_token() -> (String, String) {
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = format!("b64:{}", b64url(&raw));
    let hash = hash_refresh(&token);
    (token, hash)
}

pub fn hash_refresh(token: &str) -> String {
    let d = Sha256::digest(token.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn b64url(raw: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_roundtrip() {
        let h = hash_password("s3cret-pass").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("s3cret-pass", &h));
        assert!(!verify_password("wrong", &h));
        assert!(!verify_password("s3cret-pass", "not-a-hash"));
    }

    #[test]
    fn password_policy_is_shared_baseline() {
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password("a".repeat(128).as_str()).is_ok());
// Empty/too short/too long are all 422 FORMAT, with field/rule so the console can pinpoint them
        for bad in ["", "1234567", "a".repeat(129).as_str()] {
            let e = validate_password(bad).unwrap_err();
            assert_eq!(e.code, lattice_core::ErrorCode::Format);
            assert_eq!(e.http_status(), 422);
            assert_eq!(e.details.as_ref().unwrap()["field"], "password");
        }
    }

    #[test]
    fn refresh_token_is_opaque_and_hashed() {
        let (t1, h1) = new_refresh_token();
        let (t2, _) = new_refresh_token();
        assert_ne!(t1, t2, "refresh must be random every time");
        assert!(t1.starts_with("b64:"));
        assert_eq!(h1, hash_refresh(&t1));
        assert_eq!(h1.len(), 64);
        assert!(!h1.contains(&t1), "only the hash is stored");
    }
}
