//! **Node-local KEK** for `inspectable` mode (E15 / D3 default node-local / ② §4.6, §17.7).
//!
//! Scope (minimal viable, **no production KMS**):
//! - `[inspectable]` config loads a 32B KEK from env/Secret (`LATTICE__INSPECTABLE__KEK*`) or a file,
//!   **wrap / unwrap**s data keys (DEK, 32B), and writes `kek_id` + `wrapped_key` into the envelope's
//!   reserved metadata (`lattice.kek_id` / `lattice.wrapped_key` / `lattice.kek_wrap`),
//!   for audit/re-encryption lookup (E2E encryption of the payload itself still happens in the SDK; the server only wraps the DEK);
//! - Rotation model = **dual-KEK overlap window**: `[inspectable] previous_kek(_id)` points at the old KEK. Old envelopes
//!   (with the old `kek_id` in metadata) remain decryptable; after re-encryption ([`rewrap_envelope`]) the new envelope uses the current
//!   active KEK; "new data uses the new KEK" = subsequent `wrap` calls always use active;
//! - Audit hook: every wrap/unwrap/rekey (including failures) records a **plaintext-free** audit event (action / result /
//!   kek_id / fingerprint / byte count / reason) + per-action counts (`audit().counts()`), and also emits it through `tracing`;
//!   neither events nor logs contain KEK/DEK/plaintext. Audit counts from the first in-process `bootstrap` are
//!   exposed by [`Metrics::new`] as `lattice_inspectable_audit_total{action,result}`;
//! - **Boundaries**: production KMS/Vault wrapping, runtime hot rotation, per-user/per-tenant KEKs, and key-material persistence are not wired up.
//!   The admin API `POST /v1/admin/keys/rotate target=kek` still explicitly reports `implemented:false` (unchanged by this work package).
//!
//! Why not AES-GCM: this crate's dependency table has no AEAD crate, while `hmac`/`sha2` are existing dependencies.
//! Here HMAC-SHA256 builds a **keystream (CTR mode) + HMAC-SHA256 tag** wrap (encrypt-then-MAC,
//! constant-time tag verification), relying only on existing dependencies and adding no crate; cryptographically it is a standard PRF construction, but **not** an
//! audited KMS scheme — it is only a node-local minimal implementation; production must switch to KMS/Vault AEAD/KMS wrap.
//!
//! When disabled (`[inspectable] enabled=false`, the default): no material is read, validated, or loaded, and no background task runs;
//! [`KekRing::from_config`] returns `Ok(None)`, and every unloaded path is fail-closed (returns an error instead of plaintext).

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

use hmac::{Hmac, Mac};
use lattice_core::envelope::{base64_decode, base64_encode};
use lattice_core::{Envelope, Mode};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::config::InspectableCfg;
use crate::error::{self, Result};

type HmacSha256 = Hmac<Sha256>;

/// KEK material length (32B = 256bit; only this length is allowed, to avoid "a short key also runs").
pub const KEK_BYTES: usize = 32;
/// DEK length (input of wrap/unwrap; AES-256-grade data key).
pub const DEK_BYTES: usize = 32;
/// Length of the wrap nonce.
pub const NONCE_BYTES: usize = 16;
/// Length of the wrap tag (HMAC-SHA256 truncated to 32B).
pub const TAG_BYTES: usize = 32;
/// envelope reserved metadata: `kek_id` (metadata is strings only, no material).
pub const META_KEK_ID: &str = "lattice.kek_id";
/// envelope reserved metadata: base64(nonce || ciphertext || tag).
pub const META_WRAPPED_KEY: &str = "lattice.wrapped_key";
/// envelope reserved metadata: wrap algorithm identifier (reserved for future algorithm upgrades).
pub const META_WRAP_ALGO: &str = "lattice.kek_wrap";
/// Current wrap algorithm identifier.
pub const WRAP_ALGO: &str = "hmac-sha256-ctr+v1";

/// Audit event cap (bounded, to prevent memory growth under high traffic; counts are unaffected).
const AUDIT_RECENT_CAP: usize = 32;
/// KEK id length cap (prevents material misconfigured into an id from bloating logs).
const KEK_ID_MAX_LEN: usize = 64;

// ---------------------------------------------------------------------------
// DEK / KEK material
// ---------------------------------------------------------------------------

/// Data key (32B). **Does not implement Serialize/Display; Debug is always redacted**:
/// even if accidentally formatted with `{:?}` into a log it does not leak. Zeroed on Drop (best-effort, no zeroize dependency).
#[derive(Clone, PartialEq, Eq)]
pub struct Dek([u8; DEK_BYTES]);

impl Dek {
        /// Generate randomly (never persisted node-side; only used by the self-check/wrapping API callers).
    pub fn generate() -> Self {
        let mut raw = [0u8; DEK_BYTES];
        rand::thread_rng().fill_bytes(&mut raw);
        Dek(raw)
    }

        /// Construct from fixed bytes (when the caller already holds a DEK).
    pub fn from_bytes(raw: [u8; DEK_BYTES]) -> Self {
        Dek(raw)
    }

        /// Read-only bytes (used inside the crate; no serializable handle is exposed externally).
    pub(crate) fn expose(&self) -> &[u8; DEK_BYTES] {
        &self.0
    }
}

impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dek(<redacted>)")
    }
}

impl Drop for Dek {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn cfg_err(msg: impl Into<String>, reason: &'static str) -> lattice_core::LatticeError {
    error::format(msg).with_reason(reason)
}

fn reason_of(e: &lattice_core::LatticeError) -> String {
    e.details
        .as_ref()
        .and_then(|d| d.get("reason"))
        .and_then(|v| v.as_str())
        .unwrap_or("error")
        .to_string()
}

/// Parse 32B KEK material: standard base64 (44 chars) or hex (64 chars), exactly one of the two.
///
/// Decide by shape first: exactly 64 hex chars → hex; otherwise standard base64. This avoids hex strings being
/// decoded by base64 into 48 bytes first and then reporting the misleading "wrong length" error.
/// Error messages report only length/format and never echo the material itself.
pub fn parse_kek_material(raw: &str) -> Result<[u8; KEK_BYTES]> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(cfg_err(
            "[inspectable] kek material is empty",
            "kek_invalid",
        ));
    }
    let is_hex64 = s.len() == KEK_BYTES * 2 && s.bytes().all(|b| b.is_ascii_hexdigit());
    let decoded = if is_hex64 {
        hex::decode(s).map_err(|_| {
            cfg_err(
                "[inspectable] kek material looks like hex but failed to decode",
                "kek_invalid",
            )
        })?
    } else if let Some(b) = base64_decode(s) {
        b
    } else {
        return Err(cfg_err(
            "[inspectable] kek material is neither standard base64 nor hex",
            "kek_invalid",
        ));
    };
    if decoded.len() != KEK_BYTES {
        return Err(cfg_err(
            format!(
                "[inspectable] kek material must be {KEK_BYTES} bytes, got {}",
                decoded.len()
            ),
            "kek_invalid",
        ));
    }
    let mut out = [0u8; KEK_BYTES];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn read_kek_file(path: &str) -> Result<String> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        error::internal(format!("read [inspectable] kek_file failed: {path}: {e}"))
            .with_reason("kek_file")
    })?;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        return Ok(line.to_string());
    }
    Err(cfg_err(
        format!("[inspectable] kek_file {path} contains no key material"),
        "kek_file",
    ))
}

/// Startup config validation (called by `Config::validate`):
/// - disabled: **zero validation, zero reads** (allows configuring the material first and flipping the switch later);
/// - enabled: `[policy] mode` must be `inspectable`, KEK source/id/length must be valid, and previous must be complete.
pub fn validate_config(cfg: &InspectableCfg, mode: Mode) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    if mode != Mode::Inspectable {
        return Err(cfg_err(
            "[inspectable] enabled=true requires [policy] mode=\"inspectable\" (otherwise the loaded KEK is never usable)",
            "inspectable_mode_mismatch",
        )
        .with_detail("mode", serde_json::json!("zero-knowledge")));
    }
    material_from_config(cfg).map(|_| ())
}

/// Validated KEK material (**exists briefly on the stack only**, never logged or persisted).
struct KekMaterial {
    active_id: String,
    active_key: [u8; KEK_BYTES],
    previous: Option<(String, [u8; KEK_BYTES])>,
}

impl std::fmt::Debug for KekMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KekMaterial")
            .field("active_id", &self.active_id)
            .field("active_key", &"<redacted>")
            .field("previous_id", &self.previous.as_ref().map(|(id, _)| id))
            .finish()
    }
}

impl Drop for KekMaterial {
    fn drop(&mut self) {
        self.active_key.fill(0);
        if let Some((_, key)) = self.previous.as_mut() {
            key.fill(0);
        }
    }
}

fn validate_kek_id(id: &str) -> Result<String> {
    let id = id.trim();
    if id.is_empty() {
        return Err(cfg_err(
            "[inspectable] enabled=true requires a non-empty kek_id",
            "kek_id",
        ));
    }
    if id.len() > KEK_ID_MAX_LEN || id.chars().any(char::is_whitespace) {
        return Err(cfg_err(
            format!("[inspectable] kek_id must be 1..={KEK_ID_MAX_LEN} chars without whitespace"),
            "kek_id",
        ));
    }
    Ok(id.to_string())
}

fn material_from_config(cfg: &InspectableCfg) -> Result<KekMaterial> {
    let active_id = validate_kek_id(&cfg.kek_id)?;

    let inline = cfg.kek.trim();
    let file = cfg.kek_file.trim();
    let raw_material = match (inline.is_empty(), file.is_empty()) {
        (true, true) => {
            return Err(cfg_err(
                "[inspectable] enabled=true requires kek (env/Secret) or kek_file",
                "kek_source",
            ))
        }
        (false, false) => {
            return Err(cfg_err(
                "[inspectable] kek and kek_file are mutually exclusive (ambiguous KEK source)",
                "kek_source",
            ))
        }
        (false, true) => inline.to_string(),
        (true, false) => read_kek_file(file)?,
    };
    let active_key = parse_kek_material(&raw_material)?;

    let prev_id = cfg.previous_kek_id.trim();
    let prev_material = cfg.previous_kek.trim();
    let previous = match (prev_id.is_empty(), prev_material.is_empty()) {
        (true, true) => None,
        (false, false) => {
            let prev_id = validate_kek_id(prev_id)?;
            if prev_id == active_id {
                return Err(cfg_err(
                                                            "[inspectable] previous_kek_id must differ from kek_id (otherwise the rotation window is meaningless)",
                    "kek_source",
                ));
            }
            Some((prev_id, parse_kek_material(prev_material)?))
        }
        _ => {
            return Err(cfg_err(
                "[inspectable] previous_kek and previous_kek_id must be configured together",
                "kek_source",
            ))
        }
    };
    Ok(KekMaterial {
        active_id,
        active_key,
        previous,
    })
}

// ---------------------------------------------------------------------------
// Audit hook (plaintext-free)
// ---------------------------------------------------------------------------

/// One inspectable audit event. **Contains only locator/statistical information**: action, result, kek_id, KEK fingerprint
/// (sha256 prefix, one-way), byte count, and failure reason; it contains no KEK/DEK/payload plaintext whatsoever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// `inspectable.wrap` | `inspectable.unwrap` | `inspectable.rekey`
    pub action: &'static str,
    /// `ok` | `denied` | `error`
    pub result: &'static str,
    pub kek_id: String,
        /// Re-encryption target KEK id (only `inspectable.rekey` has it; empty otherwise).
    pub to_kek_id: Option<String>,
        /// sha256 fingerprint prefix of the related KEK (empty when the KEK is unknown).
    pub kek_fingerprint: String,
    pub bytes: usize,
    pub reason: Option<String>,
}

impl AuditEvent {
        /// JSON form (safe to write to the audit stream/log degradation path). **Contains no plaintext keys/data**.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "action": self.action,
            "result": self.result,
            "kek_id": self.kek_id,
            "to_kek_id": self.to_kek_id,
            "kek_fingerprint": self.kek_fingerprint,
            "bytes": self.bytes,
            "reason": self.reason,
        })
    }
}

/// Audit hook counters + bounded recent events.
///
/// Count key = (action, result), matching metric `lattice_inspectable_audit_total{action,result}`.
#[derive(Default)]
pub struct AuditLog {
    counts: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
    recent: Mutex<VecDeque<AuditEvent>>,
}

impl AuditLog {
    fn record(&self, event: AuditEvent) {
        if let Ok(mut c) = self.counts.lock() {
            *c.entry((event.action, event.result)).or_insert(0) += 1;
        }
        if let Ok(mut r) = self.recent.lock() {
            if r.len() >= AUDIT_RECENT_CAP {
                r.pop_front();
            }
            r.push_back(event.clone());
        }
                        // Audit log hook: only these fields are allowed; KEK/DEK/plaintext never appear.
        tracing::info!(
            action = event.action,
            result = event.result,
            kek_id = %event.kek_id,
            kek_fingerprint = %event.kek_fingerprint,
            bytes = event.bytes,
            reason = ?event.reason,
            "inspectable audit"
        );
    }

        /// Per-action/result counts (audit hook counters; accumulated in-process).
    pub fn counts(&self) -> BTreeMap<(&'static str, &'static str), u64> {
        self.counts.lock().map(|c| c.clone()).unwrap_or_default()
    }

        /// Most recent audit events (bounded; for diagnostics/tests).
    pub fn recent(&self) -> Vec<AuditEvent> {
        self.recent
            .lock()
            .map(|r| r.iter().cloned().collect())
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// KekRing: load / wrap / unwrap / rewrap / startup self-check
// ---------------------------------------------------------------------------

/// KEK fingerprint = first 16 hex chars of `sha256(key)` (one-way; used for audit/metric lookup, leaks no material).
pub fn kek_fingerprint(key: &[u8; KEK_BYTES]) -> String {
    let digest = Sha256::digest(key);
    let hex = hex::encode(digest);
    hex[..16].to_string()
}

struct KekEntry {
    id: String,
    key: [u8; KEK_BYTES],
    fingerprint: String,
}

impl KekEntry {
    fn new(id: String, key: [u8; KEK_BYTES]) -> Self {
        let fingerprint = kek_fingerprint(&key);
        KekEntry {
            id,
            key,
            fingerprint,
        }
    }
}

impl std::fmt::Debug for KekEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KekEntry")
            .field("id", &self.id)
            .field("fingerprint", &self.fingerprint)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Drop for KekEntry {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

/// A data key wrapped by a KEK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
        /// Which KEK wrapped it (envelope reserved metadata `lattice.kek_id`).
    pub kek_id: String,
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
    tag: [u8; TAG_BYTES],
}

impl WrappedKey {
        /// Value encoded into envelope metadata: `base64(nonce || ciphertext || tag)`.
    pub fn to_metadata_value(&self) -> String {
        let mut raw = Vec::with_capacity(NONCE_BYTES + self.ciphertext.len() + TAG_BYTES);
        raw.extend_from_slice(&self.nonce);
        raw.extend_from_slice(&self.ciphertext);
        raw.extend_from_slice(&self.tag);
        base64_encode(&raw)
    }

        /// Decode from envelope metadata; wrong format/length → fail-closed (no content echoed).
    pub fn from_metadata_value(kek_id: &str, value: &str) -> Result<Self> {
        let raw = base64_decode(value.trim()).ok_or_else(|| {
            cfg_err(
                "envelope wrapped key is not standard base64",
                "kek_meta_invalid",
            )
        })?;
        if raw.len() <= NONCE_BYTES + TAG_BYTES {
            return Err(cfg_err(
                "envelope wrapped key is too short",
                "kek_meta_invalid",
            ));
        }
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.copy_from_slice(&raw[..NONCE_BYTES]);
        let mut tag = [0u8; TAG_BYTES];
        tag.copy_from_slice(&raw[raw.len() - TAG_BYTES..]);
        let ciphertext = raw[NONCE_BYTES..raw.len() - TAG_BYTES].to_vec();
        Ok(WrappedKey {
            kek_id: kek_id.to_string(),
            nonce,
            ciphertext,
            tag,
        })
    }
}

/// Re-encryption result (for audit/tests; contains no key material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewrapReport {
    pub from_kek_id: String,
    pub to_kek_id: String,
        /// true = the KEK really changed; false = it was already the active KEK (only the nonce was refreshed).
    pub rewrapped: bool,
}

/// Node-local KEK ring: active (new data) + retired (previous, old data remains readable).
///
/// Immutable (runtime hot rotation is not wired up): rotate = change config/restart (the old KEK goes into `previous_kek`).
pub struct KekRing {
    active: KekEntry,
    retired: Vec<KekEntry>,
    audit: Arc<AuditLog>,
}

impl std::fmt::Debug for KekRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KekRing")
            .field("active", &self.active)
            .field("retired", &self.retired)
            .finish()
    }
}

impl KekRing {
        /// Load from config. `enabled=false` → `Ok(None)` (zero side effects); enabled with invalid material → `Err` (fail-fast).
    pub fn from_config(cfg: &InspectableCfg) -> Result<Option<Arc<KekRing>>> {
        if !cfg.enabled {
            return Ok(None);
        }
        let material = material_from_config(cfg)?;
        let active = KekEntry::new(material.active_id.clone(), material.active_key);
        let retired = material
            .previous
            .as_ref()
            .map(|(id, key)| KekEntry::new(id.clone(), *key))
            .into_iter()
            .collect();
        Ok(Some(Arc::new(KekRing {
            active,
            retired,
            audit: Arc::new(AuditLog::default()),
        })))
    }

    pub fn active_id(&self) -> &str {
        &self.active.id
    }

    pub fn active_fingerprint(&self) -> &str {
        &self.active.fingerprint
    }

        /// `(kek_id, fingerprint, role)`: role ∈ active|previous (for metrics/admin display; no material).
    pub fn keys(&self) -> Vec<(String, String, &'static str)> {
        let mut out = vec![(
            self.active.id.clone(),
            self.active.fingerprint.clone(),
            "active",
        )];
        for k in &self.retired {
            out.push((k.id.clone(), k.fingerprint.clone(), "previous"));
        }
        out
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

        /// Startup self-check (runs once when `Config::load` loads the KEK; failure = refuse to start):
        /// 1. do one wrap→unwrap round trip with the active KEK (proves the KEK works and there are no config/memory errors);
        /// 2. when a previous KEK is configured: wrap a DEK with the old KEK → old data decryptable → re-encrypt to active
        ///    → new data decryptable (proves the rotation path "old data readable, new data uses the new KEK" under the dual-KEK overlap window).
    ///
        /// Only produces audit counts (`inspectable.wrap/unwrap/rekey`); touches no user data and prints no keys.
    pub fn startup_self_check(&self) -> Result<()> {
        let dek = Dek::generate();
        let wrapped = self.wrap(&dek)?;
        let back = self.unwrap(&wrapped)?;
        if back != dek {
            return Err(error::internal(
                "inspectable KEK self-check failed: wrap/unwrap roundtrip mismatch",
            )
            .with_reason("kek_self_check"));
        }
        if let Some(old) = self.retired.first() {
                                    // Simulate "existing data wrapped by the old KEK": old data decryptable → re-encrypt to the new KEK → new data decryptable.
            let old_wrapped = self.wrap_with(old, &dek)?;
            let old_back = self.unwrap(&old_wrapped)?;
            if old_back != dek {
                return Err(error::internal(
                    "inspectable KEK self-check failed: previous KEK cannot unwrap old data",
                )
                .with_reason("kek_self_check"));
            }
            let (migrated, _report) = self.rewrap(&old_wrapped)?;
            if migrated.kek_id != self.active.id {
                return Err(error::internal(
                    "inspectable KEK self-check failed: rekey did not switch to active KEK",
                )
                .with_reason("kek_self_check"));
            }
            if self.unwrap(&migrated)? != dek {
                return Err(error::internal(
                    "inspectable KEK self-check failed: rekeyed data unreadable under active KEK",
                )
                .with_reason("kek_self_check"));
            }
        }
        Ok(())
    }

    fn find(&self, kek_id: &str) -> Option<&KekEntry> {
        if self.active.id == kek_id {
            return Some(&self.active);
        }
        self.retired.iter().find(|k| k.id == kek_id)
    }

        /// Wrap a DEK with the current active KEK (all new data goes through here).
    pub fn wrap(&self, dek: &Dek) -> Result<WrappedKey> {
        self.wrap_with(&self.active, dek)
    }

    fn wrap_with(&self, entry: &KekEntry, dek: &Dek) -> Result<WrappedKey> {
        let mut nonce = [0u8; NONCE_BYTES];
        rand::thread_rng().fill_bytes(&mut nonce);
        let (enc_key, mac_key) = derive_subkeys(&entry.key);
        let ciphertext = keystream_xor(&enc_key, &nonce, dek.expose());
        let tag = wrap_tag(&mac_key, &entry.id, &nonce, &ciphertext);
        self.audit.record(AuditEvent {
            action: "inspectable.wrap",
            result: "ok",
            kek_id: entry.id.clone(),
            to_kek_id: None,
            kek_fingerprint: entry.fingerprint.clone(),
            bytes: DEK_BYTES,
            reason: None,
        });
        Ok(WrappedKey {
            kek_id: entry.id.clone(),
            nonce,
            ciphertext,
            tag,
        })
    }

        /// Unwrap with the KEK named by `wrapped.kek_id` (active or previous both work; unknown/tag failure = fail-closed).
    pub fn unwrap(&self, wrapped: &WrappedKey) -> Result<Dek> {
        let Some(entry) = self.find(&wrapped.kek_id) else {
            self.audit.record(AuditEvent {
                action: "inspectable.unwrap",
                result: "denied",
                kek_id: wrapped.kek_id.clone(),
                to_kek_id: None,
                kek_fingerprint: String::new(),
                bytes: 0,
                reason: Some("kek_unknown".into()),
            });
            return Err(
                error::forbidden("wrapped key references an unknown KEK id (fail-closed)")
                    .with_reason("kek_unknown"),
            );
        };
        let (enc_key, mac_key) = derive_subkeys(&entry.key);
        if wrapped.ciphertext.len() != DEK_BYTES {
            self.audit.record(AuditEvent {
                action: "inspectable.unwrap",
                result: "denied",
                kek_id: entry.id.clone(),
                to_kek_id: None,
                kek_fingerprint: entry.fingerprint.clone(),
                bytes: 0,
                reason: Some("kek_unwrap_failed".into()),
            });
            return Err(
                error::forbidden("wrapped key has invalid length (fail-closed)")
                    .with_reason("kek_unwrap_failed"),
            );
        }
        let mut mac = HmacSha256::new_from_slice(&mac_key).expect("hmac key length");
        mac.update(&wrap_tag_input(
            &entry.id,
            &wrapped.nonce,
            &wrapped.ciphertext,
        ));
        if mac.verify_slice(&wrapped.tag).is_err() {
            self.audit.record(AuditEvent {
                action: "inspectable.unwrap",
                result: "denied",
                kek_id: entry.id.clone(),
                to_kek_id: None,
                kek_fingerprint: entry.fingerprint.clone(),
                bytes: 0,
                reason: Some("kek_unwrap_failed".into()),
            });
            return Err(error::forbidden(
                "wrapped key authentication failed (wrong KEK or tampered data; fail-closed)",
            )
            .with_reason("kek_unwrap_failed"));
        }
        let plaintext = keystream_xor(&enc_key, &wrapped.nonce, &wrapped.ciphertext);
        let mut raw = [0u8; DEK_BYTES];
        raw.copy_from_slice(&plaintext);
        self.audit.record(AuditEvent {
            action: "inspectable.unwrap",
            result: "ok",
            kek_id: entry.id.clone(),
            to_kek_id: None,
            kek_fingerprint: entry.fingerprint.clone(),
            bytes: DEK_BYTES,
            reason: None,
        });
        Ok(Dek(raw))
    }

        /// Re-encrypt a wrapped key to the current active KEK (the rotation action "old data readable, new data uses the new KEK").
    ///
        /// Audit: success records `inspectable.rekey` (from/to kek_id + active fingerprint + byte count), failure records denied;
        /// events contain no KEK/DEK/plaintext.
    pub fn rewrap(&self, wrapped: &WrappedKey) -> Result<(WrappedKey, RewrapReport)> {
        let from_kek_id = wrapped.kek_id.clone();
        let dek = match self.unwrap(wrapped) {
            Ok(dek) => dek,
            Err(e) => {
                self.audit.record(AuditEvent {
                    action: "inspectable.rekey",
                    result: "denied",
                    kek_id: from_kek_id,
                    to_kek_id: None,
                    kek_fingerprint: String::new(),
                    bytes: 0,
                    reason: Some(reason_of(&e)),
                });
                return Err(e);
            }
        };
        let rewrapped = self.wrap(&dek)?;
        let report = RewrapReport {
            from_kek_id,
            to_kek_id: self.active.id.clone(),
            rewrapped: rewrapped.kek_id != wrapped.kek_id,
        };
        self.audit.record(AuditEvent {
            action: "inspectable.rekey",
            result: "ok",
            kek_id: report.from_kek_id.clone(),
            to_kek_id: Some(report.to_kek_id.clone()),
            kek_fingerprint: self.active.fingerprint.clone(),
            bytes: DEK_BYTES,
            reason: None,
        });
        Ok((rewrapped, report))
    }
}

// ---------------------------------------------------------------------------
// envelope integration (reuses lattice_core::Envelope metadata and the base64 codec interfaces)
// ---------------------------------------------------------------------------

/// Write `wrapped` into the envelope's reserved metadata (`kek_id` / `wrapped_key` / algorithm identifier).
fn put_wrapped(env: &mut Envelope, wrapped: &WrappedKey) {
    env.metadata
        .insert(META_KEK_ID.to_string(), wrapped.kek_id.clone());
    env.metadata
        .insert(META_WRAP_ALGO.to_string(), WRAP_ALGO.to_string());
    env.metadata
        .insert(META_WRAPPED_KEY.to_string(), wrapped.to_metadata_value());
}

/// Wrap `dek` with the active KEK and write it into envelope metadata (for later audit/rotation lookup).
pub fn attach_wrapped_dek(ring: &KekRing, env: &mut Envelope, dek: &Dek) -> Result<()> {
    let wrapped = ring.wrap(dek)?;
    put_wrapped(env, &wrapped);
    Ok(())
}

/// Read the wrapped key back from envelope metadata: missing field/wrong format/unknown KEK all fail closed.
pub fn wrapped_dek_of(env: &Envelope) -> Result<WrappedKey> {
    let value = env.metadata.get(META_WRAPPED_KEY).ok_or_else(|| {
        cfg_err(
            "envelope has no wrapped key metadata (inspectable KEK path)",
            "kek_meta_missing",
        )
    })?;
    let kek_id = env
        .metadata
        .get(META_KEK_ID)
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    if kek_id.is_empty() {
        return Err(cfg_err(
            "envelope has wrapped key but no kek_id metadata",
            "kek_meta_missing",
        ));
    }
    WrappedKey::from_metadata_value(kek_id, value)
}

/// Unwrap the envelope's DEK (unknown KEK / tag failure → fail-closed, no plaintext returned).
pub fn envelope_dek(ring: &KekRing, env: &Envelope) -> Result<Dek> {
    ring.unwrap(&wrapped_dek_of(env)?)
}

/// Re-encrypt the envelope's wrapped key to the current active KEK; on success the envelope metadata points at the new KEK.
pub fn rewrap_envelope(ring: &KekRing, env: &mut Envelope) -> Result<RewrapReport> {
    let wrapped = wrapped_dek_of(env)?;
    let (rewrapped, report) = ring.rewrap(&wrapped)?;
    put_wrapped(env, &rewrapped);
    Ok(report)
}

/// Whether the envelope carries an inspectable KEK wrap (should not appear on the zero-knowledge path; used for gating/diagnostics).
pub fn carries_wrapped_dek(env: &Envelope) -> bool {
    env.metadata.contains_key(META_WRAPPED_KEY)
}

// ---------------------------------------------------------------------------
// Process-level loading (called by Config::load; lets Metrics expose load state/self-check audit counts)
// ---------------------------------------------------------------------------

static INSTANCE: OnceLock<Option<Arc<KekRing>>> = OnceLock::new();

/// Load the node-local KEK (takes effect on the **first** in-process `Config::load`; when disabled, records `None`).
///
/// When enabled it must pass [`validate_config`] first; here we load again + run the startup self-check, and a self-check failure = startup failure
/// (do not enter the inspectable service carrying "KEK unavailable"). Zero side effects when disabled.
pub fn bootstrap(cfg: &InspectableCfg) -> Result<()> {
    if INSTANCE.get().is_some() {
                        // Already loaded in-process (tests/repeated load): keep the first result to avoid re-running the self-check and polluting audit counts.
        return Ok(());
    }
    let ring = KekRing::from_config(cfg)?;
    if let Some(ring) = &ring {
        ring.startup_self_check()?;
    }
    let _ = INSTANCE.set(ring);
    Ok(())
}

/// Process-level KEK ring (`None` when not loaded/disabled). Read by `encrypt::kek_fingerprint` and others.
pub fn global_ring() -> Option<Arc<KekRing>> {
    INSTANCE.get().and_then(|slot| slot.clone())
}

/// Metrics load snapshot (read by `Metrics::new`): load state + KEK fingerprint (no material) + audit counts.
#[derive(Debug, Clone, Default)]
pub struct InspectableSnapshot {
    pub enabled: bool,
    pub kek_loaded: bool,
    /// `(kek_id, fingerprint, role)`, role ∈ active|previous.
    pub keys: Vec<(String, String, &'static str)>,
        /// `(action, result, count)`; action looks like `inspectable.rekey`.
    pub audit_counts: Vec<(&'static str, &'static str, u64)>,
}

/// Process-level load snapshot (uninitialized = all zero; disabled = enabled=false/kek_loaded=false).
pub fn metrics_snapshot() -> InspectableSnapshot {
    match INSTANCE.get() {
        None | Some(None) => InspectableSnapshot::default(),
        Some(Some(ring)) => InspectableSnapshot {
            enabled: true,
            kek_loaded: true,
            keys: ring.keys(),
            audit_counts: ring
                .audit
                .counts()
                .into_iter()
                .map(|((action, result), count)| (action, result, count))
                .collect(),
        },
    }
}

// ---------------------------------------------------------------------------
// wrap primitives (HMAC-SHA256 keystream + HMAC-SHA256 tag; encrypt-then-MAC)
// ---------------------------------------------------------------------------

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&out);
    raw
}

/// KEK → (enc, mac) subkeys: purposes are separated so the keystream and the tag never share the same output.
fn derive_subkeys(kek: &[u8; KEK_BYTES]) -> ([u8; 32], [u8; 32]) {
    (
        hmac_sha256(kek, b"lattice/kek/enc/v1"),
        hmac_sha256(kek, b"lattice/kek/mac/v1"),
    )
}

/// HMAC-SHA256 CTR keystream: PRF over nonce+counter, then XOR with the data (wrap = symmetric XOR).
fn keystream_xor(key: &[u8; 32], nonce: &[u8; NONCE_BYTES], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut produced = 0usize;
    let mut counter: u32 = 0;
    while produced < data.len() {
        let mut msg = Vec::with_capacity(64);
        msg.extend_from_slice(b"lattice/kek/wrap-ks/v1");
        msg.extend_from_slice(nonce);
        msg.extend_from_slice(&counter.to_be_bytes());
        let block = hmac_sha256(key, &msg);
        let n = (data.len() - produced).min(block.len());
        for i in 0..n {
            out.push(data[produced + i] ^ block[i]);
        }
        produced += n;
        counter = counter.wrapping_add(1);
    }
    out
}

/// Additional data covered by the tag: algorithm domain + kek_id + nonce + ciphertext length + ciphertext (prevents id reuse/truncation).
fn wrap_tag_input(kek_id: &str, nonce: &[u8; NONCE_BYTES], ciphertext: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + kek_id.len() + ciphertext.len());
    v.extend_from_slice(b"lattice/kek/wrap-tag/v1");
    v.extend_from_slice(&(kek_id.len() as u32).to_be_bytes());
    v.extend_from_slice(kek_id.as_bytes());
    v.extend_from_slice(nonce);
    v.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    v.extend_from_slice(ciphertext);
    v
}

fn wrap_tag(
    mac_key: &[u8; 32],
    kek_id: &str,
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
) -> [u8; TAG_BYTES] {
    hmac_sha256(mac_key, &wrap_tag_input(kek_id, nonce, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(raw: impl AsRef<[u8]>) -> String {
        base64_encode(raw.as_ref())
    }

    fn enabled_cfg(id: &str, key: [u8; 32]) -> InspectableCfg {
        InspectableCfg {
            enabled: true,
            kek_id: id.to_string(),
            kek: b64(key),
            ..Default::default()
        }
    }

    fn ring(id: &str, key: [u8; 32]) -> Arc<KekRing> {
        KekRing::from_config(&enabled_cfg(id, key))
            .expect("ring config")
            .expect("ring enabled")
    }

    fn ring_with_previous(
        id: &str,
        key: [u8; 32],
        prev_id: &str,
        prev_key: [u8; 32],
    ) -> Arc<KekRing> {
        let cfg = InspectableCfg {
            enabled: true,
            kek_id: id.to_string(),
            kek: b64(key),
            previous_kek_id: prev_id.to_string(),
            previous_kek: b64(prev_key),
            ..Default::default()
        };
        KekRing::from_config(&cfg)
            .expect("ring with previous")
            .expect("enabled")
    }

            // ---- load/config validation ----

    #[test]
    fn disabled_is_zero_side_effect() {
        let mut cfg = InspectableCfg::default();
                        // Even if clearly invalid material is left behind, nothing is read/validated while disabled (rolling rollout: configure material first, flip the switch later)
        cfg.kek = "not-a-kek".into();
        cfg.kek_id = "kek-staged".into();
        assert!(KekRing::from_config(&cfg).unwrap().is_none());
        assert!(validate_config(&cfg, Mode::ZeroKnowledge).is_ok());
        assert!(validate_config(&cfg, Mode::Inspectable).is_ok());
    }

    #[test]
    fn enabled_requires_inspectable_mode() {
        let cfg = enabled_cfg("kek-1", [0x11; 32]);
        assert!(validate_config(&cfg, Mode::ZeroKnowledge).is_err());
        validate_config(&cfg, Mode::Inspectable).unwrap();

                        // Missing/ambiguous material, wrong length, or missing id are all fail-fast
        let mut bad = enabled_cfg("kek-1", [0x11; 32]);
        bad.kek.clear();
        assert_eq!(
            reason_of(&validate_config(&bad, Mode::Inspectable).unwrap_err()),
            "kek_source"
        );
        let mut bad = enabled_cfg("kek-1", [0x11; 32]);
        bad.kek_file = "/tmp/kek".into();
        assert_eq!(
            reason_of(&validate_config(&bad, Mode::Inspectable).unwrap_err()),
            "kek_source"
        );
        let mut bad = enabled_cfg("kek-1", [0x11; 32]);
        bad.kek = b64([0u8; 16]);
        assert_eq!(
            reason_of(&validate_config(&bad, Mode::Inspectable).unwrap_err()),
            "kek_invalid"
        );
        let bad = enabled_cfg("", [0x11; 32]);
        assert_eq!(
            reason_of(&validate_config(&bad, Mode::Inspectable).unwrap_err()),
            "kek_id"
        );
                        // previous configured only half-way
        let mut bad = enabled_cfg("kek-1", [0x11; 32]);
        bad.previous_kek = b64([0x22; 32]);
        assert_eq!(
            reason_of(&validate_config(&bad, Mode::Inspectable).unwrap_err()),
            "kek_source"
        );
    }

    #[test]
    fn material_parse_accepts_base64_and_hex_but_rejects_short_or_garbage() {
        let key = [0xABu8; 32];
        assert_eq!(parse_kek_material(&b64(key)).unwrap(), key);
        assert_eq!(parse_kek_material(&hex::encode(key)).unwrap(), key);
        assert_eq!(
            reason_of(&parse_kek_material("").unwrap_err()),
            "kek_invalid"
        );
        assert_eq!(
            reason_of(&parse_kek_material("not base64 !!!").unwrap_err()),
            "kek_invalid"
        );
        assert_eq!(
            reason_of(&parse_kek_material(&b64([0u8; 16])).unwrap_err()),
            "kek_invalid"
        );
                        // The error message must not echo the material itself
        let err = format!("{}", parse_kek_material(&b64([0x5Au8; 16])).unwrap_err());
        assert!(!err.contains(&b64([0x5Au8; 16])));
    }

    #[test]
    fn kek_file_source_loads_and_ignores_comments() {
        let path = std::env::temp_dir().join(format!(
            "lattice-kek-test-{}-{}.key",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let key = [0x33u8; 32];
        std::fs::write(&path, format!("# node local KEK\n\n{}\n", hex::encode(key))).unwrap();
        let cfg = InspectableCfg {
            enabled: true,
            kek_id: "kek-file".into(),
            kek_file: path.display().to_string(),
            ..Default::default()
        };
        let r = KekRing::from_config(&cfg).unwrap().unwrap();
        assert_eq!(r.active_id(), "kek-file");
        std::fs::remove_file(&path).ok();

                        // File missing → fail-fast (reason=kek_file)
        let missing = InspectableCfg {
            enabled: true,
            kek_id: "kek-file".into(),
            kek_file: path.display().to_string(),
            ..Default::default()
        };
        assert_eq!(
            reason_of(&KekRing::from_config(&missing).unwrap_err()),
            "kek_file"
        );
    }

    // ---- wrap / unwrap ----

    #[test]
    fn wrap_unwrap_roundtrip_and_metadata_encoding() {
        let r = ring("kek-2026", [0x11; 32]);
        let dek = Dek::generate();
        let wrapped = r.wrap(&dek).unwrap();
        assert_eq!(wrapped.kek_id, r.active_id());
                        // Random nonce: two wraps of the same DEK produce different ciphertext
        let wrapped2 = r.wrap(&dek).unwrap();
        assert_ne!(wrapped.ciphertext, wrapped2.ciphertext);
        assert_ne!(wrapped.nonce, wrapped2.nonce);
                        // Round trip
        assert_eq!(r.unwrap(&wrapped).unwrap(), dek);
                        // Metadata value codec round trip (base64 container)
        let value = wrapped.to_metadata_value();
        let decoded = WrappedKey::from_metadata_value("kek-2026", &value).unwrap();
        assert_eq!(decoded, wrapped);
        assert_eq!(r.unwrap(&decoded).unwrap(), dek);
                        // The fingerprint is a sha256 prefix and contains no material
        assert_eq!(kek_fingerprint(&[0x11; 32]), r.active_fingerprint());
        assert_eq!(kek_fingerprint(&[0x11; 32]).len(), 16);
        assert!(!kek_fingerprint(&[0x11; 32]).contains(&b64([0x11; 32])));
                        // Debug does not leak DEK/KEX
        let dbg = format!("{wrapped:?} {dek:?} {r:?}");
        assert!(!dbg.contains(&b64(*dek.expose())));
        assert!(!dbg.contains(&b64([0x11; 32])));
    }

    #[test]
    fn wrong_or_unknown_kek_fails_closed_and_audits_denied() {
                        // Same id, different material = misconfiguration/wrong KEK → tag verification fails
        let r1 = ring("kek-1", [0x11; 32]);
        let r2 = ring("kek-1", [0x22; 32]);
        let dek = Dek::generate();
        let wrapped = r1.wrap(&dek).unwrap();
        let err = r2.unwrap(&wrapped).unwrap_err();
        assert_eq!(reason_of(&err), "kek_unwrap_failed");
        assert_eq!(err.code, lattice_core::ErrorCode::Forbidden);
        assert!(!format!("{err}").contains(&b64(*dek.expose())));
        let counts = r2.audit().counts();
        assert_eq!(
            counts.get(&("inspectable.unwrap", "denied")).copied(),
            Some(1)
        );

                        // Unknown kek_id → explicit fail-closed (not "fall back to blindly trying active")
        let r3 = ring("kek-other", [0x33; 32]);
        let err = r3.unwrap(&wrapped).unwrap_err();
        assert_eq!(reason_of(&err), "kek_unknown");
        assert!(r3
            .audit()
            .recent()
            .iter()
            .any(|e| e.result == "denied" && e.reason.as_deref() == Some("kek_unknown")));
    }

    #[test]
    fn tampered_ciphertext_or_tag_is_rejected() {
        let r = ring("kek-1", [0x11; 32]);
        let dek = Dek::generate();
        let mut wrapped = r.wrap(&dek).unwrap();
        wrapped.ciphertext[0] ^= 0x01;
        assert_eq!(
            reason_of(&r.unwrap(&wrapped).unwrap_err()),
            "kek_unwrap_failed"
        );

        let mut wrapped = r.wrap(&dek).unwrap();
        wrapped.tag[31] ^= 0x80;
        assert_eq!(
            reason_of(&r.unwrap(&wrapped).unwrap_err()),
            "kek_unwrap_failed"
        );
    }

            // ---- re-encryption / rotation window ----

    #[test]
    fn rekey_switches_new_data_to_new_kek_and_old_data_stays_readable() {
        let old = ring("kek-2025", [0x11; 32]);
        let new = ring_with_previous("kek-2026", [0x22; 32], "kek-2025", [0x11; 32]);
        let dek = Dek::generate();

                        // Existing data: wrapped by the old KEK
        let mut env = Envelope {
            id: "01J0000000000000000000000A".into(),
            conv_id: "01H0000000000000000000000B".into(),
            ..Default::default()
        };
        attach_wrapped_dek(&old, &mut env, &dek).unwrap();
        assert_eq!(
            env.metadata.get(META_KEK_ID).map(String::as_str),
            Some("kek-2025")
        );
        assert!(carries_wrapped_dek(&env));
        assert_eq!(
            env.metadata.get(META_WRAP_ALGO).map(String::as_str),
            Some(WRAP_ALGO)
        );

                        // Inside the rotation window: old data readable (previous KEK), new data uses the new KEK
        assert_eq!(envelope_dek(&new, &env).unwrap(), dek);
        let fresh = new.wrap(&dek).unwrap();
        assert_eq!(fresh.kek_id, "kek-2026");

                        // After re-encryption: the envelope points at the new KEK, and both the new and old KEK rings decrypt the new data
        let report = rewrap_envelope(&new, &mut env).unwrap();
        assert!(report.rewrapped);
        assert_eq!(report.from_kek_id, "kek-2025");
        assert_eq!(report.to_kek_id, "kek-2026");
        assert_eq!(
            env.metadata.get(META_KEK_ID).map(String::as_str),
            Some("kek-2026")
        );
        assert_eq!(envelope_dek(&new, &env).unwrap(), dek);

                        // Window closed (only the new KEK remains): re-encrypted data is readable; un-re-encrypted old data fails closed
        let only_new = ring("kek-2026", [0x22; 32]);
        assert_eq!(envelope_dek(&only_new, &env).unwrap(), dek);
        let mut stale = Envelope::default();
        attach_wrapped_dek(&old, &mut stale, &dek).unwrap();
        assert_eq!(
            reason_of(&envelope_dek(&only_new, &stale).unwrap_err()),
            "kek_unknown"
        );

                        // Audit: exactly one inspectable.rekey ok, with no plaintext
        let recent = new.audit().recent();
        let rekey = recent
            .iter()
            .find(|e| e.action == "inspectable.rekey" && e.result == "ok")
            .expect("rekey audit event");
        let json = rekey.to_json().to_string();
        assert!(json.contains("inspectable.rekey"));
        assert!(json.contains("kek-2025") && json.contains("kek-2026"));
        let dek_b64 = base64_encode(dek.expose());
        let old_b64 = b64([0x11; 32]);
        let new_b64 = b64([0x22; 32]);
        for secret in [&dek_b64, &old_b64, &new_b64] {
                                    assert!(!json.contains(secret.as_str()), "audit events must not contain key material");
        }
    }

    #[test]
    fn rewrap_same_active_kek_refreshes_without_false_switch() {
        let r = ring("kek-1", [0x11; 32]);
        let dek = Dek::generate();
        let wrapped = r.wrap(&dek).unwrap();
        let (again, report) = r.rewrap(&wrapped).unwrap();
                        assert!(!report.rewrapped, "it is already the active KEK, so this is not a KEK switch");
        assert_eq!(report.to_kek_id, "kek-1");
        assert_eq!(r.unwrap(&again).unwrap(), dek);
    }

    #[test]
    fn startup_self_check_records_audit_hooks() {
                        // No previous: wrap+unwrap each 1 ok
        let r = ring("kek-1", [0x11; 32]);
        r.startup_self_check().unwrap();
        let counts = r.audit().counts();
        assert_eq!(counts.get(&("inspectable.wrap", "ok")).copied(), Some(1));
        assert_eq!(counts.get(&("inspectable.unwrap", "ok")).copied(), Some(1));
        assert_eq!(counts.get(&("inspectable.rekey", "ok")).copied(), None);

                        // With previous: extra wrap(old)+unwrap(old)+rekey+unwrap(re-encrypted) → rekey ok 1
        let r = ring_with_previous("kek-2", [0x22; 32], "kek-1", [0x11; 32]);
        r.startup_self_check().unwrap();
        let counts = r.audit().counts();
        assert_eq!(counts.get(&("inspectable.rekey", "ok")).copied(), Some(1));
        let unwrap_ok = counts
            .get(&("inspectable.unwrap", "ok"))
            .copied()
            .unwrap_or(0);
        assert!(
            unwrap_ok >= 3,
                                    "old-KEK unwrap + active unwrap + unwrap after re-encryption: {unwrap_ok}"
        );
                        // Audit events contain only locator information
        for ev in r.audit().recent() {
            let json = ev.to_json().to_string();
            assert!(!json.contains(&b64([0x11; 32])));
            assert!(!json.contains(&b64([0x22; 32])));
            assert!(json.contains("kek_id"));
        }
    }

            // ---- envelope integration fail-closed ----

    #[test]
    fn envelope_metadata_missing_or_malformed_fails_closed() {
        let r = ring("kek-1", [0x11; 32]);
        let empty = Envelope::default();
        assert_eq!(
            reason_of(&envelope_dek(&r, &empty).unwrap_err()),
            "kek_meta_missing"
        );
        assert!(!carries_wrapped_dek(&empty));

                        // Has wrapped_key but no kek_id
        let mut no_id = Envelope::default();
        no_id.metadata.insert(
            META_WRAPPED_KEY.into(),
            r.wrap(&Dek::generate()).unwrap().to_metadata_value(),
        );
        assert_eq!(
            reason_of(&envelope_dek(&r, &no_id).unwrap_err()),
            "kek_meta_missing"
        );

                        // Invalid base64 / too short
        for bad in ["%%%not-b64%%%".to_string(), base64_encode(&[0u8; 8])] {
            let mut env = Envelope::default();
            env.metadata.insert(META_KEK_ID.into(), "kek-1".into());
            env.metadata.insert(META_WRAPPED_KEY.into(), bad.into());
            assert_eq!(
                reason_of(&envelope_dek(&r, &env).unwrap_err()),
                "kek_meta_invalid"
            );
        }

                        // kek_id does not match the material (same id, different key) → unwrap denied
        let mut env = Envelope::default();
        attach_wrapped_dek(&ring("kek-1", [0x11; 32]), &mut env, &Dek::generate()).unwrap();
        assert_eq!(
            reason_of(&envelope_dek(&ring("kek-1", [0x44; 32]), &env).unwrap_err()),
            "kek_unwrap_failed"
        );
    }

    #[test]
    fn metrics_snapshot_without_bootstrap_is_all_zero() {
                        // Unit tests never call Config::load → INSTANCE uninitialized: the metrics snapshot must be all zero (must not pretend to be loaded)
        if INSTANCE.get().is_none() {
            let snap = metrics_snapshot();
            assert!(!snap.enabled && !snap.kek_loaded);
            assert!(snap.keys.is_empty());
            assert!(snap.audit_counts.is_empty());
        }
    }
}
