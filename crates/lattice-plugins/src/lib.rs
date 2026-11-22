//! Plugin host (doc ② §4.5).
//!
//! Responsibility boundaries:
//! - [`registry`]: runtime view of the `plugins` table (ns/version/status/canary_ratio) and canary decisions;
//! - [`manifest`]: plugin package manifest + **canonicalization of the Ed25519-signed payload (canonical JSON)**;
//! - [`sidecar`]: gRPC sidecar client (`PluginSidecar.Process`, ⑤ §10) — the real tonic
//!   implementation (single reused connection, 500ms timeout, 30s circuit break, optional mTLS, no panic on failure, payload never logged),
//!   see `src/sidecar/grpc.rs`;
//! - [`wasm`] (feature `wasm`, enabled by default): **WASM host** — wasmtime execution,
//!   memory/fuel/wall-clock limits, concurrency cap, failure circuit break, manifest+wasm registry; no WASI/file/network capability;
//! - [`wasm::signature`] (feature `wasm`): **Ed25519 signature verification** (ring): the signed body is always
//!   `sha256(wasm_bytes || manifest_canonical_json)`, and verification keys are loaded from `[plugins] trusted_keys`
//!   (id → base64 raw pubkey) or from files; unsigned, wrong signature, or unknown key is fail-closed
//!   when `require_verified_signature=true`.
//!
//! Not yet included (P5, see doc ② §11 milestones):
//! - sidecar **process** lifecycle/auto-restart (this crate has the client only; the plugin runtime/K8s probes own the process),
//!   `PluginSidecar.Health` is not wired up, and real media format adaptation (detect/convert pipeline wiring lives on
//!   the `lattice-node` side; this crate does not depend on the node);
//! - signing private key custody/toolchain is outside this repo (the publisher signs the 32B digest offline with an `ed25519` private key);
//!   key rotation/revocation (trusted_keys is static config; changing it requires a node restart).
//!
//! `lattice-node` depends on this crate with `default-features = false`, so a default node build does not
//! compile wasmtime/ring; for the host on the node side use `cargo build -p lattice-node --features wasm-host`.
//! The sidecar client is **not affected by the feature** (the node's default build can use the tonic client; tonic is already in the node dependency tree).

pub mod limits {
    /// Per-instance memory cap (doc ② §2.3 `plugins.limits`).
    pub const MEMORY_MB: u64 = 64;
    /// Instruction count cap (fuel).
    pub const INSTRUCTIONS: u64 = 100_000_000;
    /// Per-call wall-clock cap.
    pub const CLOCK_NS: u64 = 500_000_000;
    /// sidecar call timeout (⑤ §10).
    pub const SIDECAR_TIMEOUT_MS: u64 = 500;
    /// Failure circuit-break window (⑤ §10).
    pub const CIRCUIT_BREAK_SECS: u64 = 30;
}

#[cfg(feature = "wasm")]
pub mod wasm;

pub mod sidecar;

pub mod manifest {
    use serde::{Deserialize, Serialize};

    use crate::limits;

    /// Plugin resource limits (optional `manifest.json` fields; 0 / absent = use host defaults).
    ///
    /// The host uses them only as an **upper bound**: effective value = `min(manifest, host_config)`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(default)]
    pub struct PluginLimits {
        /// Per-instance linear memory cap (MiB).
        pub memory_mb: u64,
        /// Per-call fuel (instruction count) cap.
        pub fuel: u64,
        /// Per-call wall-clock cap (ms).
        pub timeout_ms: u64,
    }

    impl Default for PluginLimits {
        fn default() -> Self {
            Self {
                memory_mb: limits::MEMORY_MB,
                fuel: limits::INSTRUCTIONS,
                timeout_ms: limits::SIDECAR_TIMEOUT_MS,
            }
        }
    }

    /// Plugin package manifest (`wasm` + `manifest.json` + signature).
    ///
    /// Signature fields (optional):
    /// - `signature`: 64-byte Ed25519 signature in **base64** (standard alphabet, with or without padding);
    /// - `signing_key_id`: verification key id (a key in `[plugins] trusted_keys`).
    ///
    /// Neither **participates in** the signed payload (otherwise the signature could not be self-contained); see
    /// [`PluginManifest::canonical_payload`] / [`PluginManifest::signing_digest`].
    /// The directory registry can also keep the signature in a separate `signature` file next to the package (see `wasm::DirRegistry`).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginManifest {
        pub ns: String,
        pub version: u32,
        #[serde(default)]
        pub entry: String,
        #[serde(default)]
        pub deps: Vec<String>,
        #[serde(default)]
        pub limits: PluginLimits,
        /// 64-byte Ed25519 signature in base64 (`None` = unsigned).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signature: Option<String>,
        /// Verification key id (a key in `[plugins] trusted_keys`; an unknown id counts as an invalid signature).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signing_key_id: Option<String>,
    }

    impl PluginManifest {
        /// Registry / circuit-break key: `ns` with the optional `@version` suffix removed.
        pub fn short_name(&self) -> &str {
            let ns = self.ns.as_str();
            match ns.split_once('@') {
                Some((base, _)) => base,
                None => ns,
            }
        }

        /// Entry export name: defaults to `process` (ABI v1); see the [`crate::wasm`] module docs.
        pub fn entry_name(&self) -> &str {
            if self.entry.is_empty() {
                "process"
            } else {
                self.entry.as_str()
            }
        }

        /// Returns `entry` when explicitly set (non-empty) — the directory registry uses it to recognize the `.wasm` file name.
        pub fn entry_name_override(&self) -> Option<&str> {
            if self.entry.is_empty() {
                None
            } else {
                Some(self.entry.as_str())
            }
        }

        /// **Canonical JSON bytes** of the signed payload (stable across languages).
        ///
        /// Contract (signing tools at the publisher must reproduce it byte for byte; the E2E cross-checks with the Rust `wasm-plugin-fixture`):
        /// - Only 5 fields, in fixed order: `ns`, `version`, `entry`, `deps`, `limits`;
        /// - `limits` fields in fixed order: `memory_mb`, `fuel`, `timeout_ms`;
        /// - Compact JSON (no whitespace), strings escaped per the JSON standard (non-ASCII kept as raw UTF-8);
        /// - Does **not** include `signature` / `signing_key_id` / any other unknown field.
        ///
        /// Example: `{"ns":"echo","version":1,"entry":"process","deps":[],"limits":{"memory_mb":64,"fuel":100000000,"timeout_ms":500}}`
        pub fn canonical_payload(&self) -> Vec<u8> {
            #[derive(Serialize)]
            struct CanonicalLimits {
                memory_mb: u64,
                fuel: u64,
                timeout_ms: u64,
            }
            #[derive(Serialize)]
            struct CanonicalManifest<'a> {
                ns: &'a str,
                version: u32,
                entry: &'a str,
                deps: &'a [String],
                limits: CanonicalLimits,
            }
            let canonical = CanonicalManifest {
                ns: self.ns.as_str(),
                version: self.version,
                entry: self.entry.as_str(),
                deps: self.deps.as_slice(),
                limits: CanonicalLimits {
                    memory_mb: self.limits.memory_mb,
                    fuel: self.limits.fuel,
                    timeout_ms: self.limits.timeout_ms,
                },
            };
            serde_json::to_vec(&canonical).unwrap_or_default()
        }

        /// The signed body is always `sha256(wasm_bytes || manifest_canonical_json)` (32 raw digest bytes,
        /// **not** hex — Ed25519 signs these 32 bytes).
        pub fn signing_digest(&self, wasm: &[u8]) -> [u8; 32] {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(wasm);
            h.update(self.canonical_payload());
            h.finalize().into()
        }

        /// Convenience: hex form of `signing_digest` (for logs/audit/comparison; never contains the wasm body).
        pub fn signing_digest_hex(&self, wasm: &[u8]) -> String {
            self.signing_digest(wasm)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        }

        /// Whether a signature is declared (any signature string counts; the result is in [`SignatureStatus`]).
        pub fn has_signature(&self) -> bool {
            self.signature.as_deref().is_some_and(|s| !s.trim().is_empty())
        }
    }

    /// Signature verification result (**no longer a placeholder**):
    /// - [`SignatureCheck::Verified`]: signature present, key id in the trusted table, Ed25519 verification passed;
    /// - [`SignatureCheck::Invalid`]: signature present but base64/length invalid, key id unknown, or verification failed;
    /// - [`SignatureCheck::Missing`]: no signature, no `signing_key_id`, or the host has no trusted public key configured
    ///   (verification is impossible, so it counts as missing — **must not** be treated as trusted).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum SignatureCheck {
        Verified,
        Invalid,
        Missing,
    }

    impl SignatureCheck {
        pub fn as_str(self) -> &'static str {
            match self {
                SignatureCheck::Verified => "verified",
                SignatureCheck::Invalid => "invalid",
                SignatureCheck::Missing => "missing",
            }
        }

        /// Only `Verified` may set the plugin's `trusted=true`.
        pub fn is_verified(self) -> bool {
            self == SignatureCheck::Verified
        }
    }

    /// Actual signature status of a package (with a low-cardinality reason for admin lists / logs; never keys or signature bytes).
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SignatureStatus {
        pub check: SignatureCheck,
        /// Key id declared by the manifest (unknown keys echo the id too, to help ops; not a secret).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key_id: Option<String>,
        /// Low-cardinality reason: `verified` / `no_signature` / `no_signing_key_id` /
        /// `no_trusted_keys` / `bad_signature_encoding` / `bad_signature_length` /
        /// `unknown_signing_key` / `signature_mismatch`.
        pub detail: String,
    }

    impl SignatureStatus {
        pub fn new(check: SignatureCheck, key_id: Option<String>, detail: impl Into<String>) -> Self {
            Self {
                check,
                key_id,
                detail: detail.into(),
            }
        }

        pub fn missing(detail: impl Into<String>) -> Self {
            Self::new(SignatureCheck::Missing, None, detail)
        }

        pub fn invalid(key_id: Option<String>, detail: impl Into<String>) -> Self {
            Self::new(SignatureCheck::Invalid, key_id, detail)
        }

        pub fn verified(key_id: String) -> Self {
            Self::new(SignatureCheck::Verified, Some(key_id), "verified")
        }
    }

    /// Payload digest check: compare `sha256(wasm + manifest)` first so that "a signature that does not match the content" is never loaded.
    pub fn digest_matches(wasm: &[u8], manifest_bytes: &[u8], expected_hex: &str) -> bool {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(wasm);
        h.update(manifest_bytes);
        let got = h.finalize();
        let mut hex = String::with_capacity(64);
        for b in got {
            hex.push_str(&format!("{b:02x}"));
        }
        hex == expected_hex
    }
}


pub mod registry {
    use serde::{Deserialize, Serialize};

    /// Plugin status (`plugins.status`, ⑥ §2.3 CHECK).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum PluginStatus {
        Staging,
        Canary,
        Active,
        RolledBack,
    }

    impl PluginStatus {
        pub fn as_str(self) -> &'static str {
            match self {
                PluginStatus::Staging => "staging",
                PluginStatus::Canary => "canary",
                PluginStatus::Active => "active",
                PluginStatus::RolledBack => "rolled_back",
            }
        }

        pub fn parse(s: &str) -> Option<Self> {
            match s {
                "staging" => Some(PluginStatus::Staging),
                "canary" => Some(PluginStatus::Canary),
                "active" => Some(PluginStatus::Active),
                "rolled_back" => Some(PluginStatus::RolledBack),
                _ => None,
            }
        }
    }

    /// Runtime entry.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginEntry {
        pub ns: String,
        pub version: u32,
        pub status: PluginStatus,
        pub canary_ratio: u32,
        /// `wasm` or `sidecar` (mutually exclusive, ⑥ §2.3 CHECK)
        pub form: String,
    }

    /// Canary decision `user hash % 100 < ratio` (doc ② §4.5).
    /// Uses a stable hash: the same user must hit the same version at the same ratio (otherwise the canary ratio is meaningless).
    pub fn in_canary(user_id: &str, ratio: u32) -> bool {
        if ratio == 0 {
            return false;
        }
        if ratio >= 100 {
            return true;
        }
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in user_id.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100_0000_01b3);
        }
        (h % 100) < ratio as u64
    }

    /// Pick a version: canary hit and a canary version exists → canary, else active.
    pub fn pick<'a>(entries: &'a [PluginEntry], ns: &str, user_id: &str) -> Option<&'a PluginEntry> {
        let cands: Vec<&PluginEntry> = entries.iter().filter(|e| e.ns == ns).collect();
        if let Some(c) = cands
            .iter()
            .find(|e| e.status == PluginStatus::Canary && in_canary(user_id, e.canary_ratio))
        {
            return Some(c);
        }
        cands
            .iter()
            .find(|e| e.status == PluginStatus::Active)
            .copied()
            .or_else(|| cands.first().copied())
    }
}

#[cfg(test)]
mod tests {
    use super::registry::*;

    fn entry(ns: &str, v: u32, status: PluginStatus, ratio: u32) -> PluginEntry {
        PluginEntry { ns: ns.into(), version: v, status, canary_ratio: ratio, form: "wasm".into() }
    }

    #[test]
    fn canary_is_stable_and_bounded() {
        assert!(!in_canary("u1", 0));
        assert!(in_canary("u1", 100));
        let a = in_canary("user-42", 10);
        let b = in_canary("user-42", 10);
        assert_eq!(a, b, "the same user at the same ratio must hit stably");
    }

    #[test]
    fn pick_prefers_active_and_canary() {
        let entries = vec![
            entry("json", 1, PluginStatus::Active, 0),
            entry("json", 2, PluginStatus::Canary, 100),
        ];
        // ratio=100 → canary hit
        assert_eq!(pick(&entries, "json", "u1").unwrap().version, 2);
        let entries2 = vec![
            entry("json", 1, PluginStatus::Active, 0),
            entry("json", 2, PluginStatus::Canary, 0),
        ];
        assert_eq!(pick(&entries2, "json", "u1").unwrap().version, 1);
        assert!(pick(&entries2, "xml", "u1").is_none());
    }

    #[test]
    fn digest_detects_tamper() {
        use super::manifest::digest_matches;
        use sha2::{Digest, Sha256};
        let wasm = b"\0asm";
        let manifest = b"{\"ns\":\"json\"}";
        let mut h = Sha256::new();
        h.update(wasm);
        h.update(manifest);
        let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        assert!(digest_matches(wasm, manifest, &hex));
        assert!(!digest_matches(b"tampered", manifest, &hex));
    }
}
