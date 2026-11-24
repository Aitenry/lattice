//! Transfer capability tokens (design §6.10 / §17.17).
//!
//! A download endpoint does not return an object-store URL any more. It mints a **capability
//! token** for exactly one object and answers `302 {public_base_url}/t/{token}`:
//!
//! ```text
//! token = base64url(payload_json) "." base64url(HMAC-SHA256(secret, "lattice-transfer.v1." || payload_b64))
//! ```
//!
//! The payload carries bucket/key/filename/content-type/size/sha256/disposition plus `exp`.
//! The transfer service verifies signature and expiry; it needs no database and no user JWT,
//! so any replica can serve any token (the capability is self-contained). Tokens are short
//! lived (default 300s, clamped 30..=3600) and are never logged.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Domain separator: a token from another subsystem must never verify here.
const SIGNING_PREFIX: &[u8] = b"lattice-transfer.v1.";
/// Hard cap on a payload before parsing (the real payload is ~300 bytes).
const MAX_PAYLOAD_B64_BYTES: usize = 4 * 1024;
/// Hard cap on a full token.
const MAX_TOKEN_BYTES: usize = 8 * 1024;
/// Allowed clock skew for `iat` (seconds).
const MAX_CLOCK_SKEW_SECS: i64 = 300;
/// Allowed bucket/key length (plugin and message keys are far below this).
const MAX_RESOURCE_LEN: usize = 1_024;
/// Allowed filename length (kept short so `Content-Disposition` stays one header line).
const MAX_FILENAME_LEN: usize = 200;

/// Capability payload. Short field names keep URLs compact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// Token format version (always 1).
    pub v: u8,
    /// Bucket (`lattice-plugins`, `lattice-large`, `lattice-media`, …).
    pub b: String,
    /// Object key inside the bucket.
    pub k: String,
    /// Suggested download filename (sanitized when the header is built).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub n: String,
    /// Content type override; empty = `application/octet-stream`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub t: String,
    /// Object size in bytes; 0 = unknown.
    #[serde(default)]
    pub s: u64,
    /// Lowercase hex SHA-256 of the content; empty = unknown. Also used as ETag when present.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub h: String,
    /// `attachment` (default) or `inline`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub d: String,
    /// Cache class: `public` (shared/CDN caching allowed; plugin packages, immutable versions)
    /// or empty/`private` (user-scoped content: no shared caching).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub c: String,
    /// Expiry (unix seconds).
    pub e: i64,
    /// Issued-at (unix seconds).
    #[serde(default)]
    pub i: i64,
    /// Requesting user id (audit/log correlation only; never trusted for authorization).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub u: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    Malformed,
    BadSignature,
    Expired,
    UnsupportedVersion,
    InvalidResource(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Malformed => write!(f, "malformed transfer token"),
            TokenError::BadSignature => write!(f, "bad transfer token signature"),
            TokenError::Expired => write!(f, "transfer token expired"),
            TokenError::UnsupportedVersion => write!(f, "unsupported transfer token version"),
            TokenError::InvalidResource(why) => write!(f, "invalid transfer token resource: {why}"),
        }
    }
}

impl std::error::Error for TokenError {}

/// Signs and verifies transfer capabilities. Cheap to clone (the secret is small); the service
/// keeps one per process, the node one per `AppState`.
#[derive(Clone)]
pub struct TokenSigner {
    secret: Vec<u8>,
    ttl_secs: u64,
    public_base_url: String,
}

impl TokenSigner {
    /// Build a signer. `secret` must be at least 32 bytes (config validation enforces the same
    /// rule, this is the second line of defence for direct constructor callers).
    pub fn new(secret: &str, ttl_secs: u64, public_base_url: &str) -> Result<Self, String> {
        if secret.as_bytes().len() < 32 {
            return Err("transfer secret must be at least 32 bytes".into());
        }
        let ttl_secs = if ttl_secs == 0 {
            300
        } else {
            ttl_secs.clamp(30, 3_600)
        };
        Ok(TokenSigner {
            secret: secret.as_bytes().to_vec(),
            ttl_secs,
            public_base_url: public_base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Service-side constructor: verification only, no public base URL required.
    pub fn verifier(secret: &str) -> Result<Self, String> {
        Self::new(secret, 300, "")
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// Mint a token for `claims`; `claims.e`/`claims.i` are overwritten with the signer's clock
    /// and TTL. Returns the raw token (no URL prefix).
    pub fn mint(&self, mut claims: Claims) -> String {
        let now = chrono::Utc::now().timestamp();
        claims.v = 1;
        claims.i = now;
        claims.e = now + self.ttl_secs as i64;
        let payload = serde_json::to_vec(&claims).expect("serialize transfer claims");
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
        let sig = self.sign_bytes(payload_b64.as_bytes());
        format!("{payload_b64}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    /// Mint a token and wrap it in the public transfer URL.
    ///
    /// An empty `public_base_url` yields a **same-origin relative** location (`/t/{token}`).
    /// That is the default for an edge that fronts both the API and the transfer service under
    /// one origin: clients resolve it against the host they already reached, so no deployment
    /// hostname is baked into a capability URL (and a LAN client never receives `127.0.0.1`).
    pub fn url_for(&self, claims: Claims) -> String {
        let token = self.mint(claims);
        let base = self.public_base_url.trim_end_matches('/');
        if base.is_empty() {
            format!("/t/{token}")
        } else {
            format!("{base}/t/{token}")
        }
    }

    /// Verify signature, format, expiry and resource bounds. Never partially trusts the payload:
    /// the JSON is parsed only after the signature matches.
    pub fn verify(&self, token: &str, now: i64) -> Result<Claims, TokenError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::Malformed);
        }
        let (payload_b64, sig_b64) = token.split_once('.').ok_or(TokenError::Malformed)?;
        if payload_b64.is_empty()
            || payload_b64.len() > MAX_PAYLOAD_B64_BYTES
            || sig_b64.is_empty()
            || sig_b64.contains('.')
        {
            return Err(TokenError::Malformed);
        }
        let sig = URL_SAFE_NO_PAD
            .decode(sig_b64.as_bytes())
            .map_err(|_| TokenError::Malformed)?;
        let expected = self.sign_bytes(payload_b64.as_bytes());
        if !constant_time_eq(&sig, &expected) {
            return Err(TokenError::BadSignature);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64.as_bytes())
            .map_err(|_| TokenError::Malformed)?;
        let claims: Claims = serde_json::from_slice(&payload).map_err(|_| TokenError::Malformed)?;
        if claims.v != 1 {
            return Err(TokenError::UnsupportedVersion);
        }
        validate_resource(&claims.b, &claims.k, &claims.n)?;
        if claims.e < now {
            return Err(TokenError::Expired);
        }
        if claims.i > now + MAX_CLOCK_SKEW_SECS {
            return Err(TokenError::InvalidResource("issued in the future".into()));
        }
        Ok(claims)
    }

    fn sign_bytes(&self, payload_b64: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac accepts any key size");
        mac.update(SIGNING_PREFIX);
        mac.update(payload_b64);
        mac.finalize().into_bytes().to_vec()
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Resource bounds: no control characters (header/response splitting), no traversal segments,
/// no leading slash (the bucket is passed separately), sane lengths.
fn validate_resource(bucket: &str, key: &str, filename: &str) -> Result<(), TokenError> {
    if bucket.is_empty() || bucket.len() > MAX_RESOURCE_LEN {
        return Err(TokenError::InvalidResource("bucket length".into()));
    }
    if key.is_empty() || key.len() > MAX_RESOURCE_LEN {
        return Err(TokenError::InvalidResource("key length".into()));
    }
    if filename.len() > MAX_FILENAME_LEN {
        return Err(TokenError::InvalidResource("filename length".into()));
    }
    for (label, value) in [("bucket", bucket), ("key", key), ("filename", filename)] {
        if value.chars().any(|c| c.is_control()) {
            return Err(TokenError::InvalidResource(format!(
                "{label} contains control characters"
            )));
        }
    }
    if bucket.contains('/') || bucket == "." || bucket == ".." {
        return Err(TokenError::InvalidResource("bucket".into()));
    }
    if key.starts_with('/')
        || key.split('/').any(|seg| seg == ".." || seg == ".")
        || key.contains('\\')
    {
        return Err(TokenError::InvalidResource("key".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn signer() -> TokenSigner {
        TokenSigner::new(SECRET, 300, "http://127.0.0.1:8088").unwrap()
    }

    fn claims() -> Claims {
        Claims {
            v: 1,
            b: "lattice-plugins".into(),
            k: "task-planner/0.1.1/task-planner-0.1.1.zip".into(),
            n: "task-planner-0.1.1.zip".into(),
            t: "application/zip".into(),
            s: 20_097,
            h: "a".repeat(64),
            d: "attachment".into(),
            c: "public".into(),
            e: 0,
            i: 0,
            u: "01M5WBF9E39E0FQ9RBYH63D0BN".into(),
        }
    }

    #[test]
    fn roundtrip_and_url() {
        let s = signer();
        let url = s.url_for(claims());
        assert!(url.starts_with("http://127.0.0.1:8088/t/"), "{url}");
        let token = url.strip_prefix("http://127.0.0.1:8088/t/").unwrap();
        let got = s.verify(token, chrono::Utc::now().timestamp()).unwrap();
        assert_eq!(got.b, "lattice-plugins");
        assert_eq!(got.k, "task-planner/0.1.1/task-planner-0.1.1.zip");
        assert_eq!(got.h, "a".repeat(64));
        assert!(got.e > chrono::Utc::now().timestamp());
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let s = signer();
        let token = s.mint(claims());
        let (payload_b64, sig_b64) = token.split_once('.').unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(payload_b64.as_bytes()).unwrap();
        raw.push(b' ');
        let forged = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(raw),
            sig_b64
        );
        assert_eq!(
            s.verify(&forged, chrono::Utc::now().timestamp()),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let token = signer().mint(claims());
        let other = TokenSigner::new(
            "ffffffffffffffffffffffffffffffff",
            300,
            "http://127.0.0.1:8088",
        )
        .unwrap();
        assert_eq!(
            other.verify(&token, chrono::Utc::now().timestamp()),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn expired_is_rejected() {
        let s = signer();
        let token = s.mint(claims());
        let later = chrono::Utc::now().timestamp() + 301;
        assert_eq!(s.verify(&token, later), Err(TokenError::Expired));
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        let s = signer();
        for bad in [
            "",
            "abc",
            "a.b.c",
            ".abc",
            "abc.",
            "!!!!.!!!!",
            "abc.def",
        ] {
            assert!(
                matches!(
                    s.verify(bad, chrono::Utc::now().timestamp()),
                    Err(TokenError::Malformed) | Err(TokenError::BadSignature)
                ),
                "token {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn resource_bounds_are_enforced() {
        let s = signer();
        for (bucket, key) in [
            ("", "a"),
            ("lattice-plugins", ""),
            ("lattice/plugins", "a"),
            ("lattice-plugins", "/abs"),
            ("lattice-plugins", "a/../b"),
            ("lattice-plugins", "a\\b"),
            ("lattice-plugins", "a\r\nHost: evil"),
        ] {
            let mut c = claims();
            c.b = bucket.into();
            c.k = key.into();
            let token = s.mint(c);
            assert!(
                matches!(
                    s.verify(&token, chrono::Utc::now().timestamp()),
                    Err(TokenError::InvalidResource(_))
                ),
                "bucket {bucket:?} key {key:?} must be rejected"
            );
        }
    }

    #[test]
    fn short_secret_is_refused() {
        assert!(TokenSigner::new("short", 300, "http://x").is_err());
        assert!(TokenSigner::verifier("0123456789abcdef0123456789abcdef").is_ok());
    }

    #[test]
    fn ttl_is_clamped() {
        let s = TokenSigner::new(SECRET, 1, "http://x").unwrap();
        assert_eq!(s.ttl_secs(), 30);
        let s = TokenSigner::new(SECRET, 99_999, "http://x").unwrap();
        assert_eq!(s.ttl_secs(), 3_600);
    }
}
