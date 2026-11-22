//! JWT signing and verification (§17.11: RS256, TTL 900s, dual-key overlap rotation for 24h).
//!
//! Key sources under `[auth] key_dir`:
//! - `jwt.key.pem`: current signing key (RS256, 2048bit, PKCS#8/PKCS#1 PEM);
//! - `jwt.key.prev.pem`: old key inside the rotation window, **still valid for verification**;
//! - `jwt.keys.json`: rotation metadata (`rotated_at`/`previous_until`/current and old key fingerprints),
//!   used after restart to restore the window without resurrecting an expired previous key.
//!
//! When files are missing, a 2048bit RSA pair is **generated automatically** so dev compose starts with one command; production mounts them from a K8s Secret
//! (② §6 key management). A read-only mount does not affect startup (existing keys load directly),
//! but admin-plane rotation fails explicitly with `reason=key_dir_readonly`; see [`JwtKeys::stage_rotation`].
//!
//! ## Rotation semantics (PL-03 3.8 / ⑤ §8.4)
//!
//! 1. **Stage first, commit later**: the new key is written to `*.tmp` and fsynced (a read-only directory fails here, with memory and disk unchanged);
//!    after the audit write succeeds, [`StagedRotation::commit`] rename-replaces `jwt.key.pem` atomically,
//!    moves the old current to `jwt.key.prev.pem`, and writes `jwt.keys.json`;
//! 2. **Dual-key overlap**: signing uses the new key immediately, while the old key stays valid as previous until `previous_until`
//!    (`verify` tries current/previous); the window defaults to 24h (`[auth] key_overlap_hours`);
//! 3. **Cleanup after the window**: the periodic job (`[auth] key_prune_interval_ms`) deletes the previous file,
//!    clears metadata, and removes it from the verification set; `verify` itself also skips expired old keys by `previous_until` as a fallback;
//! 4. **Persistence across restart**: loading trusts files plus metadata validation; if a crash mid-commit left metadata and files inconsistent,
//!    files win and the old key gets a full window (better to keep an old key a little longer than to invalidate in-flight tokens at once).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::error::{self, Result};

/// Current signing key file name (PEM; content is never returned through the admin plane).
pub const CURRENT_KEY_FILE: &str = "jwt.key.pem";
/// Previous key file name inside the rotation window.
pub const PREVIOUS_KEY_FILE: &str = "jwt.key.prev.pem";
/// Rotation metadata file name (contains no private key material).
pub const KEY_META_FILE: &str = "jwt.keys.json";

/// RS256 key size in bits (§17.11; not configurable, to avoid weak keys through misconfiguration).
pub const KEY_BITS: usize = 2048;

/// Admin-plane roles (⑤ §0.2 RBAC): administrator / operations / user.
///
/// History: before v0.7 the third tier was `viewer` (read-only); per the product decision it was renamed `user` with
/// **unchanged semantics** (user=read-only, ops=read-only+action, admin=everything including changes). Compatibility for old values lives only on
/// the read path [`Role::parse`] (old DB `users.role='viewer'` / old token claims);
/// new writes (account creation/role change) accept only `admin|ops|user` and never produce `viewer` again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Ops,
    User,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Ops => "ops",
            Role::User => "user",
        }
    }

    /// Resolve a role value (**read path**: the `users.role` column / the JWT `role` claim snapshot).
    ///
    /// - `admin`/`ops`/`user`: normal values;
    /// - `viewer`: tolerated during migration as `user` (read-only) — the rename does not loosen permissions;
    /// - anything else/unknown: degrade to `user` at least privilege (equivalent to the old "unknown degrades to viewer").
    pub fn parse(s: &str) -> Role {
        match s {
            "admin" => Role::Admin,
            "ops" => Role::Ops,
            "user" | "viewer" => Role::User,
            _ => Role::User,
        }
    }

    /// Read-class operations (⑤ §0.2).
    pub fn can_read(self) -> bool {
        matches!(self, Role::Admin | Role::Ops | Role::User)
    }

    /// Action class (drain/replay/queue purge/risk-control action).
    pub fn can_act(self) -> bool {
        matches!(self, Role::Admin | Role::Ops)
    }

    /// Change class (plugin publish/rollback/quota/keys.rotate/purge/dynamic config).
    pub fn can_change(self) -> bool {
        matches!(self, Role::Admin)
    }
}

/// Claim structure of the access JWT. `sub` = user_id, `dev` = device_id (the other half of device fingerprint validation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub dev: String,
    pub role: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    /// Unique id, for revocation and audit correlation
    pub jti: String,
}

/// Old key inside the rotation window (verification only, never signs).
struct PreviousKey {
    decoding: DecodingKey,
    fingerprint: String,
    /// Verification window end; once reached it no longer takes part (even if the cleanup job has not run yet).
    until: DateTime<Utc>,
}

/// JWT key snapshot within one process (immutable; rotation = build a new snapshot and swap it into `AppState`).
pub struct JwtKeys {
    encoding: EncodingKey,
    current_decoding: DecodingKey,
    current_pem: String,
    current_fingerprint: String,
    previous: Option<PreviousKey>,
    pub issuer: String,
    pub ttl: i64,
    pub key_dir: PathBuf,
    /// Dual-key overlap window in hours; written to metadata/snapshot on rotation and reported by GET /keys.
    pub overlap_hours: f64,
    rotated_at: Option<DateTime<Utc>>,
}

impl JwtKeys {
    /// Load from the directory (generating if needed); if `prev` exists and is inside the window, add it to the verification set (dual-key overlap).
    pub fn load_or_create(
        dir: &Path,
        issuer: &str,
        ttl: i64,
        overlap_hours: f64,
    ) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .map_err(|e| error::internal(format!("key dir unavailable ({}): {e}", dir.display())))?;
        cleanup_stale_tmp(dir);

        let cur_path = dir.join(CURRENT_KEY_FILE);
        let prev_path = dir.join(PREVIOUS_KEY_FILE);
        let meta = read_meta(dir);

        // ---- current: read the existing key, generate if missing (dev bootstrap) ----
        let (current_pem, generated) = match std::fs::read_to_string(&cur_path) {
            Ok(pem) => (pem, false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let pem = generate_rsa_pem()?;
                write_atomic(&cur_path, pem.as_bytes(), &tmp_for(dir, CURRENT_KEY_FILE))
                    .map_err(|e| error::internal(format!("write jwt key failed: {e}")))?;
                tracing::warn!(
                    path = %cur_path.display(),
                    "generated new RS256 key (dev bootstrap; production must mount a Secret)"
                );
                (pem, true)
            }
            Err(e) => {
                return Err(error::internal(format!("read jwt key failed: {e}")));
            }
        };
        let current_fingerprint = fingerprint(&current_pem);
        let mut rotated_at = if generated { Some(Utc::now()) } else { None };
        // Metadata must be written back (bootstrap / old directory upgrade / startup cleanup / repair after a mid-commit crash)
        let mut dirty = generated || meta.is_none();

        // ---- previous: file + metadata together decide whether it is still inside the verification window ----
        let mut previous: Option<(String, DateTime<Utc>)> = None;
        match std::fs::read_to_string(&prev_path) {
            Ok(prev_pem) => {
                let prev_fp = fingerprint(&prev_pem);
                if prev_fp == current_fingerprint {
                    // The previous rotation crashed after writing prev but before writing current: prev equals current, so drop prev.
                    tracing::warn!(
                        path = %prev_path.display(),
                        "prev jwt key equals current (half-committed rotation); dropping prev"
                    );
                    let _ = std::fs::remove_file(&prev_path);
                    dirty = true;
                } else {
                    let meta_matches = meta.as_ref().is_some_and(|m| {
                        m.current_fingerprint.as_deref() == Some(current_fingerprint.as_str())
                            && m.previous_fingerprint.as_deref() == Some(prev_fp.as_str())
                    });
                    let until = meta
                        .as_ref()
                        .and_then(|m| m.previous_until.as_deref())
                        .and_then(parse_rfc3339);
                    match (meta_matches, until) {
                        (true, Some(until)) if until > Utc::now() => {
                            previous = Some((prev_pem, until));
                            rotated_at = meta
                                .as_ref()
                                .and_then(|m| m.rotated_at.as_deref())
                                .and_then(parse_rfc3339)
                                .or(rotated_at);
                        }
                        (true, Some(_)) => {
                            // The window expired while the node was down: clean up at startup, never resurrect the old key.
                            tracing::info!(
                                path = %prev_path.display(),
                                "expired prev jwt key removed at startup"
                            );
                            let _ = std::fs::remove_file(&prev_path);
                            dirty = true;
                        }
                        _ => {
                            // Old-version directory (no metadata), or the last rotation crashed after writing current but before writing metadata:
                            // files win, so give the old key a full window and avoid invalidating in-flight tokens immediately.
                            let until = Utc::now() + overlap_duration(overlap_hours);
                            tracing::warn!(
                                path = %prev_path.display(),
                                previous_until = %until.to_rfc3339(),
                                "prev jwt key has no consistent metadata; recovering with a full overlap window"
                            );
                            previous = Some((prev_pem, until));
                            rotated_at = Some(Utc::now());
                            dirty = true;
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(error = %e, "prev jwt key unreadable; ignoring"),
        }

        // rotated_at: metadata first (when it actually describes current), otherwise the current file mtime.
        if let Some(m) = &meta {
            if m.current_fingerprint.as_deref() == Some(current_fingerprint.as_str()) {
                if let Some(t) = m.rotated_at.as_deref().and_then(parse_rfc3339) {
                    rotated_at = Some(t);
                }
            }
        }
        if rotated_at.is_none() {
            rotated_at = file_mtime(&cur_path);
        }

        let keys = Self::build(
            dir,
            issuer,
            ttl,
            overlap_hours,
            current_pem,
            previous,
            rotated_at,
        )?;
        if dirty {
            // Read-only Secret mounts are normal in production: a metadata repair failure only warns and does not block startup.
            if let Err(e) = keys.write_meta() {
                tracing::warn!(
                    error = %e,
                    "write jwt keys metadata failed (key dir may be read-only)"
                );
            }
        }
        Ok(keys)
    }

    fn build(
        dir: &Path,
        issuer: &str,
        ttl: i64,
        overlap_hours: f64,
        current_pem: String,
        previous: Option<(String, DateTime<Utc>)>,
        rotated_at: Option<DateTime<Utc>>,
    ) -> Result<Self> {
        let current_fingerprint = fingerprint(&current_pem);
        let encoding = EncodingKey::from_rsa_pem(current_pem.as_bytes())
            .map_err(|e| error::internal(format!("invalid jwt key: {e}")))?;
        let current_decoding = decoding_key_from_private_pem(&current_pem)?;
        let previous = match previous {
            Some((pem, until)) => {
                let fp = fingerprint(&pem);
                if fp == current_fingerprint {
                    None
                } else {
                    match decoding_key_from_private_pem(&pem) {
                        Ok(decoding) => Some(PreviousKey {
                            decoding,
                            fingerprint: fp,
                            until,
                        }),
                        Err(e) => {
                            // A corrupt old key must not stop the node; only old tokens inside the window fail verification.
                            tracing::warn!(
                                error = %e.message,
                                "prev jwt key ignored (unparsable)"
                            );
                            None
                        }
                    }
                }
            }
            None => None,
        };
        Ok(JwtKeys {
            encoding,
            current_decoding,
            current_pem,
            current_fingerprint,
            previous,
            issuer: issuer.to_string(),
            ttl,
            key_dir: dir.to_path_buf(),
            overlap_hours,
            rotated_at,
        })
    }

    pub fn issue(&self, user_id: &str, device_id: &str, role: Role) -> Result<(String, i64)> {
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            sub: user_id.to_string(),
            dev: device_id.to_string(),
            role: role.as_str().to_string(),
            iss: self.issuer.clone(),
            iat: now,
            exp: now + self.ttl,
            jti: lattice_core::ids::new_id(),
        };
        let token = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &self.encoding)
            .map_err(|e| error::internal(format!("jwt encode failed: {e}")))?;
        Ok((token, self.ttl))
    }

    /// Verify an access JWT: current first, previous only inside the window (dual-key overlap).
    ///
    /// Failure reasons are written to `details.reason` (`expired`/`signature`/`claims`) for
    /// `lattice_key_verification_failures_total{reason}` metrics and troubleshooting.
    pub fn verify(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.clone()]);
        validation.validate_exp = true;
        validation.validate_aud = false;

        let mut expired = false;
        let mut signature = false;
        let mut claims = false;
        let mut malformed = false;
        let mut keys: Vec<&DecodingKey> = vec![&self.current_decoding];
        if let Some(prev) = &self.previous {
            // Fallback: even if the cleanup job has not run, a previous key outside the window must not verify.
            if Utc::now() < prev.until {
                keys.push(&prev.decoding);
            }
        }
        for key in keys {
            match jsonwebtoken::decode::<Claims>(token, key, &validation) {
                Ok(data) => return Ok(data.claims),
                Err(e) => match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => expired = true,
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => signature = true,
                    jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(_)
                    | jsonwebtoken::errors::ErrorKind::InvalidIssuer
                    | jsonwebtoken::errors::ErrorKind::InvalidAudience
                    | jsonwebtoken::errors::ErrorKind::InvalidSubject
                    | jsonwebtoken::errors::ErrorKind::ImmatureSignature => claims = true,
                    _ => malformed = true,
                },
            }
        }
        let reason = if expired {
            "expired"
        } else if claims {
            "claims"
        } else if signature && !malformed {
            "signature"
        } else {
            "malformed"
        };
        Err(error::unauthorized(format!(
            "invalid or expired token ({reason})"
        ))
        .with_reason(reason))
    }

    /// Current signing key fingerprint (admin `GET /v1/admin/keys` returns fingerprints only, **never private keys**, ⑤ §8.4).
    pub fn current_fingerprint(&self) -> &str {
        &self.current_fingerprint
    }

    /// Fingerprint of the old key inside the rotation window; `None` when there is none (never fabricated).
    pub fn previous_fingerprint(&self) -> Option<&str> {
        self.previous.as_ref().map(|p| p.fingerprint.as_str())
    }

    /// End of the old key verification window; `None` when there is none.
    pub fn previous_until(&self) -> Option<DateTime<Utc>> {
        self.previous.as_ref().map(|p| p.until)
    }

    pub fn rotated_at(&self) -> Option<DateTime<Utc>> {
        self.rotated_at
    }

    /// Whether previous has passed its window (the cleanup job uses this).
    pub fn previous_expired(&self) -> bool {
        self.previous
            .as_ref()
            .is_some_and(|p| Utc::now() >= p.until)
    }

    /// Stage one: writability probe + generate a new key + write three `*.tmp` files (fsync).
    ///
    /// This method **changes no externally visible state**: a read-only directory (K8s Secret mount) fails here with
    /// `details.reason=key_dir_readonly`; the caller therefore writes no audit and certainly does not swap memory.
    pub fn stage_rotation(&self) -> Result<StagedRotation> {
        let dir = self.key_dir.clone();
        probe_dir_writable(&dir)?;

        let new_pem = generate_rsa_pem()?;
        let new_fingerprint = fingerprint(&new_pem);
        let old_fingerprint = self.current_fingerprint.clone();
        if new_fingerprint == old_fingerprint {
            // The probability is negligible, but if it happens we must never "rotate onto the same key".
            return Err(error::internal("generated key collides with current key; retry"));
        }
        let rotated_at = Utc::now();
        let previous_until = rotated_at + overlap_duration(self.overlap_hours);

        let tmp_cur = tmp_for(&dir, CURRENT_KEY_FILE);
        let tmp_prev = tmp_for(&dir, PREVIOUS_KEY_FILE);
        let tmp_meta = tmp_for(&dir, KEY_META_FILE);
        cleanup_paths(&[&tmp_cur, &tmp_prev, &tmp_meta]);

        let meta = KeyMeta {
            algorithm: "RS256".into(),
            rotated_at: Some(rotated_at.to_rfc3339()),
            previous_until: Some(previous_until.to_rfc3339()),
            current_fingerprint: Some(new_fingerprint.clone()),
            previous_fingerprint: Some(old_fingerprint.clone()),
            overlap_hours: Some(self.overlap_hours),
            updated_at: Some(rotated_at.to_rfc3339()),
        };
        let meta_json = serde_json::to_vec_pretty(&meta)
            .map_err(|e| error::internal(format!("encode jwt keys metadata failed: {e}")))?;

        // fsync all three payloads to tmp first; rename happens only in the commit stage.
        write_file_sync(&tmp_prev, self.current_pem.as_bytes())
            .map_err(|e| key_dir_error(&dir, e))?;
        write_file_sync(&tmp_cur, new_pem.as_bytes()).map_err(|e| key_dir_error(&dir, e))?;
        write_file_sync(&tmp_meta, &meta_json).map_err(|e| key_dir_error(&dir, e))?;

        Ok(StagedRotation {
            dir,
            issuer: self.issuer.clone(),
            ttl: self.ttl,
            overlap_hours: self.overlap_hours,
            old_current_pem: self.current_pem.clone(),
            new_current_pem: new_pem,
            old_fingerprint,
            new_fingerprint,
            rotated_at,
            previous_until,
            tmp_cur,
            tmp_prev,
            tmp_meta,
            prev_committed: false,
            cur_committed: false,
        })
    }

    /// Stage three: cleanup after previous expires (delete the prev file, clear metadata, return a new snapshot without the old key).
    ///
    /// Returns `Ok(None)` when not yet expired / no previous (idempotent; safe to call repeatedly from the periodic job).
    /// A delete failure only warns and the key is still removed from the in-memory verification set: metadata `previous_until` has expired,
    /// so even a leftover file is discarded as an expired old key on reload and never resurrected.
    pub fn prune_previous(&self) -> Result<Option<JwtKeys>> {
        let Some(prev) = &self.previous else {
            return Ok(None);
        };
        if Utc::now() < prev.until {
            return Ok(None);
        }
        let prev_path = self.key_dir.join(PREVIOUS_KEY_FILE);
        match std::fs::remove_file(&prev_path) {
            Ok(()) => tracing::info!(
                path = %prev_path.display(),
                fingerprint = %prev.fingerprint,
                "expired jwt previous key removed from verification set"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                error = %e,
                path = %prev_path.display(),
                "delete expired prev jwt key failed; removing it from verification set only"
            ),
        }
        let new = Self::build(
            &self.key_dir,
            &self.issuer,
            self.ttl,
            self.overlap_hours,
            self.current_pem.clone(),
            None,
            self.rotated_at,
        )?;
        if let Err(e) = new.write_meta() {
            tracing::warn!(error = %e, "rewrite jwt keys metadata after prune failed");
        }
        Ok(Some(new))
    }

    fn write_meta(&self) -> std::io::Result<()> {
        let meta = KeyMeta {
            algorithm: "RS256".into(),
            rotated_at: self.rotated_at.map(|t| t.to_rfc3339()),
            previous_until: self.previous_until().map(|t| t.to_rfc3339()),
            current_fingerprint: Some(self.current_fingerprint.clone()),
            previous_fingerprint: self.previous_fingerprint().map(str::to_string),
            overlap_hours: Some(self.overlap_hours),
            updated_at: Some(Utc::now().to_rfc3339()),
        };
        let json = serde_json::to_vec_pretty(&meta)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        write_atomic(
            &self.key_dir.join(KEY_META_FILE),
            &json,
            &tmp_for(&self.key_dir, KEY_META_FILE),
        )
    }
}

/// A staged but uncommitted rotation. `Drop` cleans up leftover tmp files (abandon/failure paths leave no half-written new key).
pub struct StagedRotation {
    dir: PathBuf,
    issuer: String,
    ttl: i64,
    overlap_hours: f64,
    old_current_pem: String,
    new_current_pem: String,
    old_fingerprint: String,
    new_fingerprint: String,
    rotated_at: DateTime<Utc>,
    previous_until: DateTime<Utc>,
    tmp_cur: PathBuf,
    tmp_prev: PathBuf,
    tmp_meta: PathBuf,
    prev_committed: bool,
    cur_committed: bool,
}

impl StagedRotation {
    pub fn new_fingerprint(&self) -> &str {
        &self.new_fingerprint
    }

    pub fn old_fingerprint(&self) -> &str {
        &self.old_fingerprint
    }

    pub fn rotated_at(&self) -> DateTime<Utc> {
        self.rotated_at
    }

    pub fn previous_until(&self) -> DateTime<Utc> {
        self.previous_until
    }

    /// Parameters for the audit write (**fingerprints and times only, no key material**).
    pub fn audit_detail(&self, reason: &str) -> serde_json::Value {
        serde_json::json!({
            "target": "jwt",
            "reason": reason,
            "algorithm": "RS256",
            "key_bits": KEY_BITS,
            "overlap_hours": self.overlap_hours,
            "rotated_at": self.rotated_at.to_rfc3339(),
            "previous_until": self.previous_until.to_rfc3339(),
            "current_fingerprint": self.new_fingerprint,
            "previous_fingerprint": self.old_fingerprint,
        })
    }

    /// Stage two: commit. Rename order = prev (copy of the old current) → current (new key) → metadata.
    ///
    /// - The current rename is the actual switch point; if it fails earlier, the current file is still the old key
    ///   (worst case prev == current, which self-heals on load), so the new key is never lost and the old key never overwritten;
    /// - A metadata write failure only warns: current/prev are switched, and loading takes the "metadata inconsistent" self-heal path.
    pub fn commit(mut self) -> Result<JwtKeys> {
        let prev_path = self.dir.join(PREVIOUS_KEY_FILE);
        let cur_path = self.dir.join(CURRENT_KEY_FILE);
        let meta_path = self.dir.join(KEY_META_FILE);

        std::fs::rename(&self.tmp_prev, &prev_path).map_err(|e| key_dir_error(&self.dir, e))?;
        self.prev_committed = true;
        std::fs::rename(&self.tmp_cur, &cur_path).map_err(|e| key_dir_error(&self.dir, e))?;
        self.cur_committed = true;
        if let Err(e) = std::fs::rename(&self.tmp_meta, &meta_path) {
            tracing::warn!(
                error = %e,
                "commit jwt keys metadata failed; files switched, metadata will self-heal on load"
            );
        }
        JwtKeys::build(
            &self.dir,
            &self.issuer,
            self.ttl,
            self.overlap_hours,
            self.new_current_pem.clone(),
            Some((self.old_current_pem.clone(), self.previous_until)),
            Some(self.rotated_at),
        )
    }
}

impl Drop for StagedRotation {
    fn drop(&mut self) {
        if !self.prev_committed {
            let _ = std::fs::remove_file(&self.tmp_prev);
        }
        if !self.cur_committed {
            let _ = std::fs::remove_file(&self.tmp_cur);
        }
        let _ = std::fs::remove_file(&self.tmp_meta);
    }
}

/// Rotation metadata (`jwt.keys.json`): fingerprints and times only, **never key material**.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct KeyMeta {
    #[serde(default)]
    algorithm: String,
    #[serde(default)]
    rotated_at: Option<String>,
    #[serde(default)]
    previous_until: Option<String>,
    #[serde(default)]
    current_fingerprint: Option<String>,
    #[serde(default)]
    previous_fingerprint: Option<String>,
    #[serde(default)]
    overlap_hours: Option<f64>,
    #[serde(default)]
    updated_at: Option<String>,
}

fn read_meta(dir: &Path) -> Option<KeyMeta> {
    let raw = std::fs::read_to_string(dir.join(KEY_META_FILE)).ok()?;
    match serde_json::from_str(&raw) {
        Ok(meta) => Some(meta),
        Err(e) => {
            tracing::warn!(error = %e, "jwt keys metadata unparsable; treating as legacy layout");
            None
        }
    }
}

fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

fn file_mtime(path: &Path) -> Option<DateTime<Utc>> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let dur = modified.duration_since(UNIX_EPOCH).ok()?;
    DateTime::from_timestamp(dur.as_secs() as i64, dur.subsec_nanos())
}

fn overlap_duration(hours: f64) -> ChronoDuration {
    // Negative values/NaN are treated as 0 (expire immediately); never widen the window.
    let secs = if hours.is_finite() && hours > 0.0 {
        (hours * 3600.0).round() as i64
    } else {
        0
    };
    ChronoDuration::seconds(secs)
}

fn tmp_for(dir: &Path, file: &str) -> PathBuf {
    dir.join(format!("{file}.tmp"))
}

fn cleanup_stale_tmp(dir: &Path) {
    cleanup_paths(&[
        &tmp_for(dir, CURRENT_KEY_FILE),
        &tmp_for(dir, PREVIOUS_KEY_FILE),
        &tmp_for(dir, KEY_META_FILE),
    ]);
}

fn cleanup_paths(paths: &[&Path]) {
    for p in paths {
        if let Err(e) = std::fs::remove_file(p) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %p.display(), error = %e, "remove stale key tmp failed");
            }
        }
    }
}

/// **Diagnosable error** for a read-only directory: admin rotation must refuse on it (never swap memory only).
fn key_dir_error(dir: &Path, e: std::io::Error) -> error::LatticeError {
    error::internal(format!(
        "key dir is not writable ({}): {e}",
        dir.display()
    ))
    .with_reason("key_dir_readonly")
    .with_detail("key_dir", serde_json::json!(dir.display().to_string()))
    .with_detail("os_error", serde_json::json!(e.kind().to_string()))
}

/// Writability probe: fail explicitly before generating a new 2048bit key (read-only Secret mount case).
fn probe_dir_writable(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| key_dir_error(dir, e))?;
    let probe = dir.join(format!(
        ".lattice-key-write-probe-{}",
        lattice_core::ids::new_id()
    ));
    let result = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)?;
        f.write_all(b"lattice-key-write-probe")?;
        f.sync_all()?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&probe);
    result.map_err(|e| key_dir_error(dir, e))
}

fn write_file_sync(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Atomic write: write `{file}.tmp` + fsync, then `rename` over the target (rename within a directory is atomic).
fn write_atomic(path: &Path, data: &[u8], tmp: &Path) -> std::io::Result<()> {
    write_file_sync(tmp, data)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

fn generate_rsa_pem() -> Result<String> {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::RsaPrivateKey;

    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, KEY_BITS)
        .map_err(|e| error::internal(format!("rsa keygen failed: {e}")))?;
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| error::internal(format!("rsa pem encode failed: {e}")))?;
    Ok(pem.to_string())
}

/// Build a verification key from a private key PEM: **the public key must be exported first**.
///
/// In `jsonwebtoken` 9, `DecodingKey::from_rsa_pem` only accepts public key PEM (SPKI / PKCS#1). Passing a PKCS#8
/// private key directly **does not error**, but the resulting modulus/exponent are wrong, which shows up as every token failing
/// with `InvalidSignature`. Here we always go `RsaPrivateKey → to_public_key() → SPKI PEM`,
/// accepting both PKCS#1 (`BEGIN RSA PRIVATE KEY`) and PKCS#8 (`BEGIN PRIVATE KEY`) mounted by operations.
fn decoding_key_from_private_pem(pem: &str) -> Result<DecodingKey> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::RsaPrivateKey;

    let key = match RsaPrivateKey::from_pkcs8_pem(pem) {
        Ok(k) => k,
        Err(pkcs8_err) => RsaPrivateKey::from_pkcs1_pem(pem).map_err(|_| {
            error::internal(format!("parse jwt private key failed: {pkcs8_err}"))
        })?,
    };
    let pub_pem = key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| error::internal(format!("encode jwt public key failed: {e}")))?;
    DecodingKey::from_rsa_pem(pub_pem.as_bytes())
        .map_err(|e| error::internal(format!("invalid jwt public key: {e}")))
}

pub fn fingerprint(pem: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(pem.trim().as_bytes());
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// Shared by tests: generate two keys once (rotation cases generate more; that is the behavior under test).
    fn fixture_pems() -> &'static (String, String) {
        static PEMS: OnceLock<(String, String)> = OnceLock::new();
        PEMS.get_or_init(|| (generate_rsa_pem().unwrap(), generate_rsa_pem().unwrap()))
    }

    /// Separate temp directory (parallel tests share no key files).
    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lattice-jwt-test-{}",
            lattice_core::ids::new_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Pre-seed current (optional prev / metadata) so cases need not generate RSA each time.
    fn fixture_dir(
        current_pem: &str,
        previous_pem: Option<&str>,
        meta: Option<&KeyMeta>,
    ) -> PathBuf {
        let dir = temp_dir();
        std::fs::write(dir.join(CURRENT_KEY_FILE), current_pem).unwrap();
        if let Some(prev) = previous_pem {
            std::fs::write(dir.join(PREVIOUS_KEY_FILE), prev).unwrap();
        }
        if let Some(meta) = meta {
            std::fs::write(dir.join(KEY_META_FILE), serde_json::to_vec(meta).unwrap()).unwrap();
        }
        dir
    }

    fn meta_for(
        current_pem: &str,
        previous_pem: Option<&str>,
        until: Option<DateTime<Utc>>,
    ) -> KeyMeta {
        KeyMeta {
            algorithm: "RS256".into(),
            rotated_at: Some(Utc::now().to_rfc3339()),
            previous_until: until.map(|t| t.to_rfc3339()),
            current_fingerprint: Some(fingerprint(current_pem)),
            previous_fingerprint: previous_pem.map(fingerprint),
            overlap_hours: Some(24.0),
            updated_at: Some(Utc::now().to_rfc3339()),
        }
    }

    fn load(dir: &Path) -> JwtKeys {
        JwtKeys::load_or_create(dir, "lattice", 900, 24.0).unwrap()
    }

    fn list_files(dir: &Path) -> Vec<String> {
        let mut files: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().to_string()))
            .collect();
        files.sort();
        files
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let (pem, _) = fixture_pems();
        let dir = fixture_dir(pem, None, None);
        let k = load(&dir);
        let (token, ttl) = k.issue("01JUSER", "dev-1", Role::Ops).unwrap();
        assert_eq!(ttl, 900);
        let claims = k.verify(&token).unwrap();
        assert_eq!(claims.sub, "01JUSER");
        assert_eq!(claims.role, "ops");
        assert_eq!(claims.iss, "lattice");
        assert!(claims.exp - claims.iat == 900);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampered_token_rejected() {
        let (pem, _) = fixture_pems();
        let dir = fixture_dir(pem, None, None);
        let k = load(&dir);
        let (token, _) = k.issue("01JUSER", "dev-1", Role::User).unwrap();
        // 1) Append garbage characters → invalid shape/encoding → malformed
        let mut truncated = token.clone();
        truncated.push('x');
        let err = k.verify(&truncated).unwrap_err();
        assert_eq!(err.code, lattice_core::ErrorCode::AuthFail);
        let reason = err
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|v| v.as_str());
        assert_eq!(reason, Some("malformed"));
        // 2) Change the first character of the signature segment (same length) → signature mismatch → signature (the metric label)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let sig = parts[2];
        let repl = if sig.starts_with('A') { "B" } else { "A" };
        let bad_sig = format!("{repl}{}", &sig[1..]);
        let tampered = format!("{}.{}.{}", parts[0], parts[1], bad_sig);
        let err = k.verify(&tampered).unwrap_err();
        assert_eq!(err.code, lattice_core::ErrorCode::AuthFail);
        let reason = err
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|v| v.as_str());
        assert_eq!(reason, Some("signature"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn role_matrix_matches_0_2() {
        assert!(Role::User.can_read() && !Role::User.can_act() && !Role::User.can_change());
        assert!(Role::Ops.can_read() && Role::Ops.can_act() && !Role::Ops.can_change());
        assert!(Role::Admin.can_change());
    }

    /// The enum rename changes names only, never semantics: the old value `viewer` degrades to read-only `user` on read;
    /// new writes accept only the three new values from `as_str()` (old values can never re-enter the DB from the write path).
    #[test]
    fn role_parse_accepts_legacy_viewer_as_user() {
        assert_eq!(Role::parse("admin"), Role::Admin);
        assert_eq!(Role::parse("ops"), Role::Ops);
        assert_eq!(Role::parse("user"), Role::User);
        // Migration compatibility: old DB column values / old token claims
        assert_eq!(Role::parse("viewer"), Role::User);
        // Unknown values still degrade to least privilege (the old implementation degraded to viewer, now to user)
        assert_eq!(Role::parse("root"), Role::User);
        assert_eq!(Role::parse(""), Role::User);
        // `as_str` yields only new values: user, no longer viewer
        assert_eq!(Role::Admin.as_str(), "admin");
        assert_eq!(Role::Ops.as_str(), "ops");
        assert_eq!(Role::User.as_str(), "user");
        for role in [Role::Admin, Role::Ops, Role::User] {
            assert_eq!(Role::parse(role.as_str()), role);
        }
    }

    #[test]
    fn rotation_swaps_keys_atomically_and_survives_reload() {
        let (pem1, _) = fixture_pems();
        let dir = fixture_dir(pem1, None, None);
        let keys = load(&dir);
        let old_fp = keys.current_fingerprint().to_string();
        let (t1, _) = keys.issue("01JUSER", "dev-1", Role::Admin).unwrap();

        // --- Stage one: stage (externally visible state unchanged) ---
        let staged = keys.stage_rotation().unwrap();
        let new_fp = staged.new_fingerprint().to_string();
        assert_eq!(staged.old_fingerprint(), old_fp);
        assert_ne!(new_fp, old_fp);
        assert_eq!(
            std::fs::read_to_string(dir.join(CURRENT_KEY_FILE)).unwrap().trim(),
            pem1.trim(),
            "stage must not modify the current file"
        );
        assert!(!dir.join(PREVIOUS_KEY_FILE).exists(), "stage must not create a prev file");
        let until = staged.previous_until();
        assert!(until > Utc::now(), "the dual-key window must be in the future");

        // --- Stage two: commit ---
        let rotated = staged.commit().unwrap();
        assert_eq!(rotated.current_fingerprint(), new_fp);
        assert_ne!(rotated.current_fingerprint(), old_fp);
        assert_eq!(rotated.previous_fingerprint(), Some(old_fp.as_str()));
        assert!(rotated.previous_until().unwrap() > Utc::now() - ChronoDuration::seconds(1));
        // Dual-key overlap: the old token still verifies inside the window; new tokens sign and verify with the new key
        assert_eq!(
            rotated.verify(&t1).unwrap().sub,
            "01JUSER",
            "old tokens must keep working inside the window"
        );
        let (t2, _) = rotated.issue("01JUSER", "dev-1", Role::Admin).unwrap();
        assert_ne!(t1, t2);
        assert_eq!(rotated.verify(&t2).unwrap().sub, "01JUSER");
        // Disk: current=new key, prev=old key, metadata has fingerprints/window; no tmp leftovers
        assert_eq!(
            fingerprint(&std::fs::read_to_string(dir.join(CURRENT_KEY_FILE)).unwrap()),
            rotated.current_fingerprint()
        );
        assert_eq!(
            fingerprint(&std::fs::read_to_string(dir.join(PREVIOUS_KEY_FILE)).unwrap()),
            old_fp
        );
        let meta: KeyMeta =
            serde_json::from_slice(&std::fs::read(dir.join(KEY_META_FILE)).unwrap()).unwrap();
        assert_eq!(
            meta.current_fingerprint.as_deref(),
            Some(rotated.current_fingerprint())
        );
        assert_eq!(meta.previous_fingerprint.as_deref(), Some(old_fp.as_str()));
        assert!(meta.previous_until.is_some());
        assert!(
            !list_files(&dir).iter().any(|f| f.ends_with(".tmp")),
            "no *.tmp leftovers allowed"
        );

        // --- Restart (reload): new key persisted, window restored from metadata, old tokens still work ---
        let reloaded = load(&dir);
        assert_eq!(reloaded.current_fingerprint(), rotated.current_fingerprint());
        assert_eq!(reloaded.previous_fingerprint(), Some(old_fp.as_str()));
        assert_eq!(
            reloaded.previous_until(),
            rotated.previous_until(),
            "the window must not be extended or reset by a restart"
        );
        assert_eq!(
            reloaded.verify(&t1).unwrap().sub,
            "01JUSER",
            "old tokens still work after restart inside the window"
        );
        assert_eq!(reloaded.verify(&t2).unwrap().sub, "01JUSER");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn second_rotation_replaces_previous_and_oldest_token_is_rejected() {
        let (pem1, _) = fixture_pems();
        let dir = fixture_dir(pem1, None, None);
        let keys = load(&dir);
        let (t1, _) = keys.issue("01JUSER", "dev-1", Role::User).unwrap();
        let r1 = keys.stage_rotation().unwrap().commit().unwrap();
        let fp1 = r1.current_fingerprint().to_string();
        let (t2, _) = r1.issue("01JUSER", "dev-1", Role::User).unwrap();
        // Second rotation: K2 becomes previous and K1 leaves the verification set entirely
        let r2 = r1.stage_rotation().unwrap().commit().unwrap();
        assert_eq!(r2.previous_fingerprint(), Some(fp1.as_str()));
        assert_ne!(r2.current_fingerprint(), fp1);
        let (t3, _) = r2.issue("01JUSER", "dev-1", Role::User).unwrap();
        assert!(r2.verify(&t3).is_ok());
        assert!(r2.verify(&t2).is_ok(), "the immediately preceding key is still inside the window");
        assert!(r2.verify(&t1).is_err(), "an old token two generations back must be rejected");
        // The prev file holds only the last generation; old keys do not accumulate
        assert_eq!(
            fingerprint(&std::fs::read_to_string(dir.join(PREVIOUS_KEY_FILE)).unwrap()),
            fp1
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_removes_expired_previous_and_rejects_old_token() {
        let (pem1, _) = fixture_pems();
        let dir = fixture_dir(pem1, None, None);
        // overlap = 0 → previous_until = rotation time (expires immediately), so unit tests need not wait 24h.
        let keys = JwtKeys::load_or_create(&dir, "lattice", 900, 0.0).unwrap();
        let old_fp = keys.current_fingerprint().to_string();
        let (t1, _) = keys.issue("01JUSER", "dev-1", Role::User).unwrap();
        let rotated = keys.stage_rotation().unwrap().commit().unwrap();
        assert_eq!(rotated.previous_fingerprint(), Some(old_fp.as_str()));
        assert!(rotated.previous_expired(), "previous expires immediately when overlap=0");
        assert!(rotated.verify(&t1).is_err(), "an old token outside the window must be rejected even before cleanup");
        let (t2, _) = rotated.issue("01JUSER", "dev-1", Role::User).unwrap();
        assert!(rotated.verify(&t2).is_ok());

        let pruned = rotated
            .prune_previous()
            .unwrap()
            .expect("an expired previous should be cleaned up");
        assert_eq!(pruned.previous_fingerprint(), None);
        assert!(!dir.join(PREVIOUS_KEY_FILE).exists(), "the prev file must be deleted");
        let meta: KeyMeta =
            serde_json::from_slice(&std::fs::read(dir.join(KEY_META_FILE)).unwrap()).unwrap();
        assert_eq!(meta.previous_fingerprint, None, "metadata must no longer claim a previous key");
        assert_eq!(meta.previous_until, None);
        assert_eq!(
            meta.current_fingerprint.as_deref(),
            Some(pruned.current_fingerprint())
        );
        assert!(pruned.verify(&t2).is_ok());
        assert!(
            pruned.prune_previous().unwrap().is_none(),
            "idempotent no-op when there is no previous"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn startup_prunes_previous_whose_window_expired() {
        let (pem1, pem2) = fixture_pems();
        let past = Utc::now() - ChronoDuration::seconds(1);
        let meta = meta_for(pem1, Some(pem2), Some(past));
        let dir = fixture_dir(pem1, Some(pem2), Some(&meta));
        let keys = load(&dir);
        assert_eq!(keys.previous_fingerprint(), None, "an old key that expired while the node was down must not be resurrected");
        assert!(!dir.join(PREVIOUS_KEY_FILE).exists(), "expired prev files are cleaned at startup");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_prev_without_metadata_gets_full_overlap_window() {
        let (pem1, pem2) = fixture_pems();
        // Old directory with only two PEMs and no jwt.keys.json
        let dir = fixture_dir(pem1, Some(pem2), None);
        let keys = load(&dir);
        assert_eq!(
            keys.previous_fingerprint(),
            Some(fingerprint(pem2).as_str())
        );
        assert!(keys.previous_until().unwrap() > Utc::now());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn readonly_key_dir_rotation_fails_without_changing_keys() {
        let (pem1, _) = fixture_pems();
        let dir = fixture_dir(pem1, None, None);
        let keys = load(&dir);
        let fp_before = keys.current_fingerprint().to_string();
        let file_before = std::fs::read_to_string(dir.join(CURRENT_KEY_FILE)).unwrap();

        // Simulate "read-only mount/unwritable path" cross-platform: temporarily replace key_dir with a regular file,
        // so any create/write necessarily fails (chmod has no effect on directories on Windows).
        let backup = dir.with_extension("readonly-bak");
        std::fs::rename(&dir, &backup).unwrap();
        std::fs::write(&dir, b"not-a-directory").unwrap();
        let err = keys.stage_rotation().err().expect("a read-only directory must make rotation fail");
        let reason = err
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        assert_eq!(reason.as_deref(), Some("key_dir_readonly"));
        assert_eq!(keys.current_fingerprint(), fp_before, "a failed rotation must not change in-memory keys");

        std::fs::remove_file(&dir).unwrap();
        std::fs::rename(&backup, &dir).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join(CURRENT_KEY_FILE)).unwrap(),
            file_before,
            "a failed rotation must not change the on-disk current key"
        );
        assert!(
            !list_files(&dir).iter().any(|f| f.ends_with(".tmp")),
            "a failed rotation must not leave tmp files: {:?}",
            list_files(&dir)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn metadata_only_has_fingerprints_not_key_material() {
        let (pem1, _) = fixture_pems();
        let dir = fixture_dir(pem1, None, None);
        let keys = load(&dir);
        let rotated = keys.stage_rotation().unwrap().commit().unwrap();
        let meta_raw = std::fs::read_to_string(dir.join(KEY_META_FILE)).unwrap();
        assert!(meta_raw.contains(rotated.current_fingerprint()));
        assert!(!meta_raw.contains("PRIVATE KEY"), "metadata must not contain a private key");
        assert!(!meta_raw.contains("BEGIN"), "metadata must not contain PEM content");
        std::fs::remove_dir_all(&dir).ok();
    }
}
