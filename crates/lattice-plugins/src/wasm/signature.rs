//! Plugin package **Ed25519 signature verification** (design ② §4.5 / PL-10).
//!
//! # Signature format (the publisher signs offline; the host only verifies)
//!
//! ```text
//! payload   = sha256( wasm_bytes || manifest_canonical_json )   // 32-byte raw digest
//! signature = Ed25519_sign(plugin_private_key, payload)         // 64 bytes
//! manifest  = { ..., "signature": "<base64(signature)>", "signing_key_id": "<key id>" }
//! ```
//!
//! - The byte-level contract of `manifest_canonical_json` is in [`PluginManifest::canonical_payload`]
//!   (fixed field order + compact JSON, **excluding** the signature fields themselves);
//! - `signature` uses the **base64 standard alphabet** (with or without padding; base64url is also accepted);
//! - `signing_key_id` refers to `[plugins] trusted_keys` (id → base64 raw 32B public key) or
//!   `[plugins] trusted_keys_file` (a JSON object `{ "<id>": "<base64 pubkey>" }`, also accepting a
//!   `{"keys": {...}}` wrapper).
//!
//! # Trust semantics (fail-closed)
//!
//! - [`SignatureCheck::Verified`]: signature usable and passing → plugin `trusted=true`;
//! - [`SignatureCheck::Invalid`]: signature declared but encoding/length/public key unknown/verification failed → **always reject loading**
//!   (even with `require_verified_signature=false`, a bad signature counts as tampering);
//! - [`SignatureCheck::Missing`]: no signature / no key id / host has no trusted public key → loading is allowed only under
//!   `require_verified_signature=false`, but `trusted=false` and **cannot be invoked**.
//!
//! # Boundaries
//!
//! - Private keys never live in this repo or the host process: signing happens offline at the publisher; the host holds public keys only;
//! - No certificate chain/revocation/timestamp: `trusted_keys` is static config, so rotation = edit config + restart the node;
//! - Logs/`Debug` emit only key ids and counts, **never public key bytes, wasm bytes, or signature bytes**.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, ED25519};

use crate::manifest::{PluginManifest, SignatureStatus};

/// Number of bytes in a raw Ed25519 public key.
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
/// Number of bytes in an Ed25519 signature.
pub const ED25519_SIGNATURE_BYTES: usize = 64;

/// base64 decoding (lenient: standard/URL-safe, with/without padding all accepted).
///
/// Used only for short data such as public keys/signatures; error messages contain no raw values (avoids leaking signatures/keys in logs).
pub fn decode_b64_flexible(value: &str) -> Result<Vec<u8>, String> {
    let v = value.trim();
    if v.is_empty() {
        return Err("empty base64 value".into());
    }
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(v) {
            return Ok(bytes);
        }
    }
    Err("value is not valid base64 (standard or url-safe)".into())
}

/// Trusted verification key table (`id` → 32-byte raw Ed25519 public key).
///
/// `Debug` prints only the key id list, never public key bytes (log redaction requirement).
#[derive(Clone, Default)]
pub struct TrustedKeys {
    keys: BTreeMap<String, [u8; ED25519_PUBLIC_KEY_BYTES]>,
}

impl fmt::Debug for TrustedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedKeys")
            .field("count", &self.keys.len())
            .field("ids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl TrustedKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from `[plugins] trusted_keys` (id → base64 pubkey).
    pub fn from_b64_map(
        map: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, String> {
        let mut keys = Self::new();
        for (id, b64) in map {
            keys.insert(&id, &b64)?;
        }
        Ok(keys)
    }

    /// Parse from JSON bytes: supports `{ "<id>": "<base64 pubkey>" }` and `{"keys": {...}}`.
    pub fn merge_from_json(&mut self, raw: &[u8]) -> Result<usize, String> {
        let value: serde_json::Value = serde_json::from_slice(raw)
            .map_err(|e| format!("trusted_keys file is not valid JSON: {e}"))?;
        let obj = match &value {
            serde_json::Value::Object(map) if map.contains_key("keys") => match &map["keys"] {
                serde_json::Value::Object(inner) => inner,
                _ => return Err("trusted_keys file `keys` must be an object".into()),
            },
            serde_json::Value::Object(map) => map,
            _ => return Err("trusted_keys file must be a JSON object".into()),
        };
        let mut added = 0usize;
        for (id, v) in obj {
            let b64 = v
                .as_str()
                .ok_or_else(|| format!("trusted key `{id}` must be a base64 string"))?;
            self.insert(id, b64)?;
            added += 1;
        }
        Ok(added)
    }

    /// Load from a JSON file (missing/unreadable file → Err; the caller decides fail-closed vs. warning).
    pub fn from_json_file(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read(path)
            .map_err(|e| format!("read trusted_keys file {} failed: {e}", path.display()))?;
        let mut keys = Self::new();
        keys.merge_from_json(&raw)?;
        Ok(keys)
    }

    /// Insert a public key; empty id or a non-32-byte public key → Err.
    pub fn insert(&mut self, id: &str, public_key_b64: &str) -> Result<(), String> {
        let id = id.trim();
        if id.is_empty() {
            return Err("trusted key id must not be empty".into());
        }
        if id.len() > 128 || id.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(format!(
                "trusted key id `{}` must be <=128 chars without whitespace/control",
                redact_id(id)
            ));
        }
        let bytes = decode_b64_flexible(public_key_b64)
            .map_err(|e| format!("trusted key `{id}`: public key is not base64: {e}"))?;
        if bytes.len() != ED25519_PUBLIC_KEY_BYTES {
            return Err(format!(
                "trusted key `{id}`: Ed25519 public key must be {ED25519_PUBLIC_KEY_BYTES} bytes, got {}",
                bytes.len()
            ));
        }
        let mut key = [0u8; ED25519_PUBLIC_KEY_BYTES];
        key.copy_from_slice(&bytes);
        self.keys.insert(id.to_string(), key);
        Ok(())
    }

    /// Merge another table (file entries override ids of the same name).
    pub fn merge(&mut self, other: &TrustedKeys) {
        for (id, key) in &other.keys {
            self.keys.insert(id.clone(), *key);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Key id list (read-only; not secret material, safe in admin status).
    pub fn ids(&self) -> Vec<&str> {
        self.keys.keys().map(String::as_str).collect()
    }

    pub fn contains(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    /// Verify with the given key; `Ok(())` = passed.
    ///
    /// The error message is a **low-cardinality reason** (never key/signature bytes), for logs and [`SignatureStatus::detail`].
    pub fn verify(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), &'static str> {
        let Some(public_key) = self.keys.get(key_id) else {
            return Err("unknown_signing_key");
        };
        UnparsedPublicKey::new(&ED25519, public_key.as_slice())
            .verify(message, signature)
            .map_err(|_| "signature_mismatch")
    }
}

/// Redact an id: keep only the first 32 chars (abnormal ids are truncated in error messages to avoid log injection).
fn redact_id(id: &str) -> String {
    id.chars().take(32).collect()
}

/// Compute and return the verification verdict for one package.
///
/// `signature_override` holds signature bytes already decoded from the manifest/`signature` file;
/// a non-empty `signature_encoding_error` means the manifest declared a signature but base64 decoding failed.
pub fn verify_status(
    manifest: &PluginManifest,
    wasm: &[u8],
    signature_override: Option<&[u8]>,
    signature_encoding_error: Option<&str>,
    keys: &TrustedKeys,
) -> SignatureStatus {
    let key_id = manifest
        .signing_key_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    if let Some(err) = signature_encoding_error {
        return SignatureStatus::invalid(key_id, format!("bad_signature_encoding: {err}"));
    }

    let Some(signature) = signature_override else {
        return SignatureStatus::missing(if manifest.has_signature() {
            "unsigned_overridden"
        } else {
            "no_signature"
        });
    };

    let Some(key_id) = key_id else {
        return SignatureStatus::missing("no_signing_key_id");
    };

    if keys.is_empty() {
        return SignatureStatus::missing("no_trusted_keys");
    }
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return SignatureStatus::invalid(
            Some(key_id),
            format!("bad_signature_length: expected 64, got {}", signature.len()),
        );
    }
    if !keys.contains(&key_id) {
        // An unknown key id means reject: "unknown key degrades to unsigned" is not allowed.
        return SignatureStatus::invalid(Some(key_id), "unknown_signing_key");
    }
    let digest = manifest.signing_digest(wasm);
    match keys.verify(&key_id, &digest, signature) {
        Ok(()) => SignatureStatus::verified(key_id),
        Err(reason) => SignatureStatus::invalid(Some(key_id), reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{PluginLimits, SignatureCheck};

    fn manifest(ns: &str) -> PluginManifest {
        PluginManifest {
            ns: ns.into(),
            version: 1,
            entry: "process".into(),
            deps: vec![],
            limits: PluginLimits {
                memory_mb: 64,
                fuel: 100_000_000,
                timeout_ms: 500,
            },
            signature: None,
            signing_key_id: None,
        }
    }

    fn b64(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    /// RFC 8032 §7.1 TEST 1 (empty message) — a self-test of the verification primitive, unrelated to the Lattice digest.
    #[test]
    fn rfc8032_test_vector_1_verifies() {
        let pk = decode_b64_flexible_vector(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        );
        let sig = decode_b64_flexible_vector(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        let mut keys = TrustedKeys::new();
        keys.insert("rfc-test-1", &b64(&pk)).unwrap();
        assert!(keys.verify("rfc-test-1", b"", &sig).is_ok());
        assert_eq!(keys.verify("rfc-test-1", b"x", &sig), Err("signature_mismatch"));
        assert_eq!(keys.verify("unknown", b"", &sig), Err("unknown_signing_key"));
    }

    fn decode_b64_flexible_vector(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn trusted_keys_parse_and_debug_redacts_bytes() {
        let pk = [7u8; 32];
        let mut keys = TrustedKeys::from_b64_map([("release-1".to_string(), b64(&pk))]).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains("release-1"));
        assert_eq!(keys.ids(), vec!["release-1"]);
        let debug = format!("{keys:?}");
        assert!(debug.contains("release-1"));
        assert!(!debug.contains(&b64(&pk)), "Debug must not emit public key bytes: {debug}");

        // File loading: both the plain map and the {"keys":{...}} form are accepted.
        let raw = format!(r#"{{"keys":{{"file-key":"{}"}}}}"#, b64(&pk));
        keys.merge_from_json(raw.as_bytes()).unwrap();
        assert!(keys.contains("file-key"));
        let raw2 = format!(r#"{{"file-key-2":"{}"}}"#, b64(&pk));
        keys.merge_from_json(raw2.as_bytes()).unwrap();
        assert!(keys.contains("file-key-2"));

        // Bad public keys: wrong length / invalid base64 / invalid id
        assert!(TrustedKeys::from_b64_map([("x".to_string(), b64(&[1u8; 31]))]).is_err());
        assert!(TrustedKeys::from_b64_map([("x".to_string(), "!!!".to_string())]).is_err());
        assert!(TrustedKeys::from_b64_map([("x y".to_string(), b64(&pk))]).is_err());
    }

    #[test]
    fn missing_and_invalid_classification() {
        let keys = TrustedKeys::from_b64_map([("k1".to_string(), b64(&[9u8; 32]))]).unwrap();
        let wasm = b"\0asm\x01\0\0\0";
        let mut m = manifest("cls");

        // 1) no signature at all → Missing
        assert_eq!(
            verify_status(&m, wasm, None, None, &keys).check,
            SignatureCheck::Missing
        );

        // 2) signature but no key id → Missing (never guess a key)
        m.signature = Some(b64(&[0u8; 64]));
        assert_eq!(
            verify_status(&m, wasm, Some(&[0u8; 64]), None, &keys).check,
            SignatureCheck::Missing
        );

        // 3) key id + signature, but wrong length → Invalid
        m.signing_key_id = Some("k1".into());
        assert_eq!(
            verify_status(&m, wasm, Some(&[0u8; 63]), None, &keys).check,
            SignatureCheck::Invalid
        );

        // 4) unknown key → Invalid (no downgrade to unsigned)
        m.signing_key_id = Some("nope".into());
        let st = verify_status(&m, wasm, Some(&[0u8; 64]), None, &keys);
        assert_eq!(st.check, SignatureCheck::Invalid);
        assert_eq!(st.detail, "unknown_signing_key");

        // 5) base64 encoding failure → Invalid
        let st = verify_status(&m, wasm, None, Some("bad b64"), &keys);
        assert_eq!(st.check, SignatureCheck::Invalid);

        // 6) host has no trusted public key → Missing (not Verified; trusted never becomes true)
        let empty = TrustedKeys::new();
        let st = verify_status(&m, wasm, Some(&[0u8; 64]), None, &empty);
        assert_eq!(st.check, SignatureCheck::Missing);
        assert_eq!(st.detail, "no_trusted_keys");
    }

    #[test]
    fn canonical_payload_is_stable_and_excludes_signature_fields() {
        let mut m = manifest("echo");
        let expected = r#"{"ns":"echo","version":1,"entry":"process","deps":[],"limits":{"memory_mb":64,"fuel":100000000,"timeout_ms":500}}"#;
        assert_eq!(String::from_utf8(m.canonical_payload()).unwrap(), expected);

        // Changing signature fields does not affect the signed payload (otherwise the signature could not be self-contained)
        m.signature = Some("AAAA".into());
        m.signing_key_id = Some("release-1".into());
        assert_eq!(String::from_utf8(m.canonical_payload()).unwrap(), expected);

        // The digest covers wasm + canonical manifest; either change must change it
        let wasm_a = b"\0asm\x01\0\0\0";
        let wasm_b = b"\0asm\x01\0\0\0\0";
        let da = m.signing_digest(wasm_a);
        let db = m.signing_digest(wasm_b);
        assert_ne!(da, db);
        m.version = 2;
        assert_ne!(m.signing_digest(wasm_a), da);
    }
}
