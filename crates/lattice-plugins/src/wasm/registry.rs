//! Plugin package loading: `manifest.json` + wasm bytes + signature (Ed25519; verification in [`super::signature`]).
//!
//! Two minimal registry implementations (the **minimal version** of design ② §4.5's "read signed/published plugin manifest+wasm
//! from object storage/PG"):
//!
//! - [`MemoryRegistry`]: in-memory registry for tests / unit calls;
//! - [`DirRegistry`]: directory registry, laid out as `<root>/<plugin>/manifest.json` + `plugin.wasm`
//!   (or the file name given by `manifest.entry` when it ends with `.wasm`).
//!
//! Where a directory package's signature comes from (one of two, manifest wins):
//! 1. the `signature` field of `manifest.json` (base64, standard alphabet) + `signing_key_id`;
//! 2. a separate `signature` file in the package directory (base64 text, or the raw 64-byte signature; `signing_key_id` still comes
//!    from the manifest) — supporting directory layouts where "signature and manifest are published separately".
//!
//! Verification does **not** happen here (there are no trusted public keys here): [`PluginPackage`] only decodes the signature bytes;
//! the verdict comes from [`super::signature::verify_status`] when the host registers it.
//!
//! Object storage / PG wiring is left to the node side (`lattice-node`'s hub / S3 already implement it); this crate only defines
//! the [`PluginRegistry`] trait and the load-from-bytes entry points.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::RwLock;

use sha2::{Digest, Sha256};

use super::{WasmError, MIB};

/// One plugin package: manifest bytes (covered by the digest check) + wasm bytes + decoded signature bytes.
#[derive(Debug, Clone)]
pub struct PluginPackage {
    /// Raw `manifest.json` bytes (they take part in the digest together with wasm; the canonical verification payload is rebuilt from the parsed fields,
    /// so whitespace/field order in the manifest file do not affect verification — see [`crate::manifest::PluginManifest::canonical_payload`]).
    pub manifest_bytes: Vec<u8>,
    /// Parsed manifest.
    pub manifest: crate::manifest::PluginManifest,
    /// wasm binary (not WAT text; tests convert with `wat::parse_str`).
    pub wasm: Vec<u8>,
    /// Decoded Ed25519 signature bytes (from manifest.signature or the `signature` file in the directory).
    pub signature: Option<Vec<u8>>,
    /// Readable reason when the manifest/signature file declares a signature but base64 decoding fails (treated as Invalid at verification).
    pub signature_encoding_error: Option<String>,
    /// Expected `sha256(wasm || manifest_bytes)` hex digest (optional).
    pub digest: Option<String>,
}

impl PluginPackage {
    /// Build from manifest JSON bytes + wasm bytes (parses the manifest and base64 signature, but does not compile wasm
    /// or verify — verification happens at host registration).
    pub fn new(manifest_bytes: Vec<u8>, wasm: Vec<u8>) -> Result<Self, WasmError> {
        let manifest: crate::manifest::PluginManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| WasmError::Manifest {
                plugin: String::new(),
                reason: format!("manifest.json is not valid JSON: {e}"),
            })?;
        let mut pkg = Self {
            manifest_bytes,
            manifest,
            wasm,
            signature: None,
            signature_encoding_error: None,
            digest: None,
        };
        pkg.load_signature_from_manifest()?;
        Ok(pkg)
    }

    /// Build directly from an already-parsed manifest (tests / node side after reading ns/version from PG).
    pub fn from_manifest(
        manifest: crate::manifest::PluginManifest,
        wasm: Vec<u8>,
    ) -> Self {
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap_or_default();
        let mut pkg = Self {
            manifest_bytes,
            manifest,
            wasm,
            signature: None,
            signature_encoding_error: None,
            digest: None,
        };
        // Also decode the base64 signature carried in the parsed manifest; a decoding failure must not panic, it is classified as Invalid at verification.
        if let Some(b64) = pkg.manifest.signature.as_deref() {
            if !b64.trim().is_empty() {
                match super::signature::decode_b64_flexible(b64) {
                    Ok(bytes) => pkg.signature = Some(bytes),
                    Err(e) => pkg.signature_encoding_error = Some(e),
                }
            }
        }
        pkg
    }

    /// Load signature bytes from the manifest's `signature` field (base64 decode failure → Err, rejecting the bad package).
    fn load_signature_from_manifest(&mut self) -> Result<(), WasmError> {
        let Some(b64) = self.manifest.signature.clone() else {
            return Ok(());
        };
        if b64.trim().is_empty() {
            return Ok(());
        }
        match super::signature::decode_b64_flexible(&b64) {
            Ok(bytes) => self.signature = Some(bytes),
            Err(e) => {
                return Err(WasmError::Manifest {
                    plugin: self.manifest.ns.clone(),
                    reason: format!(
                        "manifest.signature is not valid base64 (Ed25519 signature): {e}"
                    ),
                })
            }
        }
        Ok(())
    }

    /// Attach raw signature bytes (tests / already-decoded cases; **does not verify**, verification happens at host registration).
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self.signature_encoding_error = None;
        self
    }

    /// Record a base64 decoding failure for the signature (used when a directory `signature` file is corrupt; verification classifies it as Invalid).
    pub fn with_signature_encoding_error(mut self, reason: impl Into<String>) -> Self {
        self.signature_encoding_error = Some(reason.into());
        self
    }

    /// Attach the expected digest `sha256(wasm || manifest_bytes)` (hex, lower or upper case).
    pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = Some(digest.into());
        self
    }

    /// Circuit break / registry key: manifest `ns` with the optional `@version` suffix removed.
    pub fn short_name(&self) -> &str {
        self.manifest.short_name()
    }

    /// Compute the verification verdict (needs the host trusted key table; never contains keys/signature bytes).
    pub fn signature_status(
        &self,
        keys: &super::signature::TrustedKeys,
    ) -> crate::manifest::SignatureStatus {
        super::signature::verify_status(
            &self.manifest,
            &self.wasm,
            self.signature.as_deref(),
            self.signature_encoding_error.as_deref(),
            keys,
        )
    }

    /// `sha256(wasm || manifest_bytes)` (same order as [`crate::manifest::digest_matches`]).
    pub fn content_sha256(&self) -> String {
        let mut h = Sha256::new();
        h.update(&self.wasm);
        h.update(&self.manifest_bytes);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Static manifest validation: ns non-empty, version > 0, entry legal (when non-empty it must be a simple identifier).
    pub fn validate_manifest(&self) -> Result<(), WasmError> {
        let ns = &self.manifest.ns;
        if ns.trim().is_empty() {
            return Err(WasmError::Manifest {
                plugin: "<unknown>".into(),
                reason: "manifest.ns is empty".into(),
            });
        }
        if ns.len() > 128 || ns.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(WasmError::Manifest {
                plugin: ns.clone(),
                reason: "manifest.ns must be <=128 chars without whitespace/control".into(),
            });
        }
        if self.manifest.version == 0 {
            return Err(WasmError::Manifest {
                plugin: ns.clone(),
                reason: "manifest.version must be > 0".into(),
            });
        }
        if let Some(entry) = self.manifest.entry_name_override() {
            if !is_simple_ident(entry) {
                return Err(WasmError::Manifest {
                    plugin: ns.clone(),
                    reason: format!("manifest.entry `{entry}` is not a valid export identifier"),
                });
            }
        }
        if let Some(key_id) = self.manifest.signing_key_id.as_deref() {
            if key_id.trim().is_empty() || key_id.len() > 128 {
                return Err(WasmError::Manifest {
                    plugin: ns.clone(),
                    reason: "manifest.signing_key_id must be 1..=128 chars".into(),
                });
            }
        }
        Ok(())
    }
}

fn is_simple_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.chars()
            .all(|c| c.is_ascii_graphic() && c != '"' && c != '\\' && c != '\'')
}

/// Registry interface: the host feeds published versions in at startup / hot reload.
///
/// Minimal implementations: [`MemoryRegistry`] / [`DirRegistry`]; wiring object storage (S3 `lattice-plugins`) and
/// PG `plugins` / `hub_plugin_versions` is node-side work, not this crate.
pub trait PluginRegistry: Send + Sync {
    /// All currently visible plugins (with multiple versions per name, the implementation decides what to return; the host overrides registration by short_name).
    fn list(&self) -> Vec<PluginPackage>;

    /// Get one package by short_name.
    fn get(&self, short_name: &str) -> Option<PluginPackage> {
        self.list()
            .into_iter()
            .find(|p| p.short_name() == short_name)
    }
}

/// In-memory registry.
#[derive(Debug, Default)]
pub struct MemoryRegistry {
    inner: RwLock<BTreeMap<String, PluginPackage>>,
}

impl MemoryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert / overwrite (same name+version: the later insert wins). Returns the replaced package.
    pub fn insert(&self, package: PluginPackage) -> Option<PluginPackage> {
        let key = package.short_name().to_string();
        self.inner.write().expect("registry poisoned").insert(key, package)
    }

    pub fn remove(&self, short_name: &str) -> Option<PluginPackage> {
        self.inner.write().expect("registry poisoned").remove(short_name)
    }

    pub fn len(&self) -> usize {
        self.inner.read().expect("registry poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot in insertion order (BTreeMap key order).
    pub fn entries(&self) -> Vec<PluginPackage> {
        self.list()
    }
}

impl PluginRegistry for MemoryRegistry {
    fn list(&self) -> Vec<PluginPackage> {
        self.inner.read().expect("registry poisoned").values().cloned().collect()
    }
}

/// Directory registry scan result: successful packages + per-package failure reasons (so bad packages surface to ops instead of being silently skipped).
#[derive(Debug, Default)]
pub struct DirScan {
    pub packages: Vec<PluginPackage>,
    pub rejected: Vec<(String, String)>,
}

/// Directory registry: `<root>/<plugin>/manifest.json` + wasm file (+ optional `signature` file).
///
/// wasm file name rule: when `manifest.entry` ends with `.wasm`, use that relative path (rejecting `..`/absolute paths);
/// otherwise use `plugin.wasm` in the same directory.
#[derive(Debug, Clone)]
pub struct DirRegistry {
    root: PathBuf,
}

impl DirRegistry {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn scan(&self) -> DirScan {
        let mut scan = DirScan::default();
        let entries = match std::fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) => {
                scan.rejected
                    .push((self.root.display().to_string(), format!("read_dir failed: {e}")));
                return scan;
            }
        };
        let mut dirs: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        for dir in dirs {
            let name = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            match load_dir_package(&dir) {
                Ok(pkg) => scan.packages.push(pkg),
                Err(reason) => scan.rejected.push((name, reason)),
            }
        }
        scan
    }
}

impl PluginRegistry for DirRegistry {
    fn list(&self) -> Vec<PluginPackage> {
        self.scan().packages
    }
}

fn load_dir_package(dir: &Path) -> Result<PluginPackage, String> {
    let manifest_path = dir.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path)
        .map_err(|e| format!("read {} failed: {e}", manifest_path.display()))?;
    let manifest: crate::manifest::PluginManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| format!("manifest.json invalid: {e}"))?;
    let wasm_name = match manifest.entry_name_override() {
        Some(entry) if entry.ends_with(".wasm") => {
            let rel = Path::new(&entry);
            if rel.is_absolute()
                || rel
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_)))
            {
                return Err(format!("manifest.entry `{entry}` escapes the plugin directory"));
            }
            rel.to_path_buf()
        }
        _ => PathBuf::from("plugin.wasm"),
    };
    let wasm_path = dir.join(&wasm_name);
    let wasm = std::fs::read(&wasm_path)
        .map_err(|e| format!("read wasm {} failed: {e}", wasm_path.display()))?;
    if wasm.is_empty() {
        return Err(format!("wasm file {} is empty", wasm_path.display()));
    }
    if wasm.len() > MAX_WASM_BYTES {
        return Err(format!(
            "wasm file {} is {} bytes, exceeds max {}",
            wasm_path.display(),
            wasm.len(),
            MAX_WASM_BYTES
        ));
    }
    let mut pkg = PluginPackage::new(manifest_bytes, wasm)
        .map_err(|e| format!("manifest.json invalid: {e}"))?;
    pkg.manifest = manifest;
    // Signature file: manifest.signature wins; otherwise read the sibling `signature` (base64 text or 64B raw).
    if pkg.signature.is_none() && pkg.signature_encoding_error.is_none() {
        if let Some(bytes) = read_signature_file(dir)? {
            pkg.signature = Some(bytes);
        }
    }
    Ok(pkg)
}

/// Read the optional `signature` file: base64 text (may contain newlines) or an exact 64-byte raw signature.
fn read_signature_file(dir: &Path) -> Result<Option<Vec<u8>>, String> {
    let path = dir.join("signature");
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read signature {} failed: {e}", path.display())),
    };
    if raw.len() == super::signature::ED25519_SIGNATURE_BYTES {
        return Ok(Some(raw));
    }
    let text = String::from_utf8(raw)
        .map_err(|_| format!("signature file {} is neither 64 raw bytes nor base64 text", path.display()))?;
    super::signature::decode_b64_flexible(&text)
        .map(Some)
        .map_err(|e| format!("signature file {} is not valid base64: {e}", path.display()))
}

/// Size cap for a wasm file in a plugin directory (defensive: real plugin packages are far smaller; ② §4.5 sets no cap,
/// the node-side hub caps packages at 20MiB, so this is relaxed to 64MiB and anything above is rejected).
pub const MAX_WASM_BYTES: usize = 64 * MIB as usize;

/// Summarize `DirScan` failures into a single readable line (for ops logs / reports).
pub fn format_dir_scan(scan: &DirScan) -> String {
    let mut s = format!(
        "{} package(s) loaded, {} rejected",
        scan.packages.len(),
        scan.rejected.len()
    );
    for (name, reason) in &scan.rejected {
        s.push_str(&format!("; {name}: {reason}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(ns: &str, entry: &str) -> PluginPackage {
        let manifest = crate::manifest::PluginManifest {
            ns: ns.into(),
            version: 1,
            entry: entry.into(),
            deps: vec![],
            limits: Default::default(),
            signature: None,
            signing_key_id: None,
        };
        PluginPackage::from_manifest(manifest, b"\0asm\x01\0\0\0".to_vec())
    }

    #[test]
    fn short_name_strips_at_suffix() {
        assert_eq!(pkg("json", "").short_name(), "json");
        assert_eq!(pkg("json@2", "").short_name(), "json");
        assert_eq!(pkg("ns.with_dots", "").short_name(), "ns.with_dots");
    }

    #[test]
    fn unsigned_package_status_needs_trusted_keys_to_be_verified() {
        let unsigned = pkg("a", "");
        let keys = super::super::signature::TrustedKeys::new();
        let status = unsigned.signature_status(&keys);
        assert_eq!(status.check, crate::manifest::SignatureCheck::Missing);
        assert_eq!(status.detail, "no_signature");

        // Signature bytes but no key id: still Missing (do not guess a key, do not treat it as verified).
        let signed = pkg("a", "").with_signature(vec![1, 2, 3]);
        let status = signed.signature_status(&keys);
        assert_eq!(status.check, crate::manifest::SignatureCheck::Missing);
        assert_eq!(status.detail, "no_signing_key_id");
    }

    #[test]
    fn manifest_validation_rejects_bad_fields() {
        let mut p = pkg("ok", "process");
        assert!(p.validate_manifest().is_ok());
        p.manifest.version = 0;
        assert!(p.validate_manifest().is_err());
        p.manifest.version = 1;
        p.manifest.ns = "  ".into();
        assert!(p.validate_manifest().is_err());
        p.manifest.ns = "a b".into();
        assert!(p.validate_manifest().is_err());
        p.manifest.ns = "ok".into();
        p.manifest.entry = "bad entry".into();
        assert!(p.validate_manifest().is_err(), "entry must not contain spaces");
        p.manifest.entry = "process".into();
        p.manifest.signing_key_id = Some("   ".into());
        assert!(p.validate_manifest().is_err(), "a blank key id is invalid");
    }

    #[test]
    fn digest_matches_content_sha256() {
        let p = pkg("dig", "");
        let sha = p.content_sha256();
        assert_eq!(sha.len(), 64);
        let mut h = Sha256::new();
        h.update(&p.wasm);
        h.update(&p.manifest_bytes);
        assert_eq!(sha, h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>());
    }

    #[test]
    fn memory_registry_roundtrip() {
        let reg = MemoryRegistry::new();
        assert!(reg.is_empty());
        reg.insert(pkg("json", ""));
        reg.insert(pkg("xml", ""));
        assert_eq!(reg.len(), 2);
        assert!(reg.get("json").is_some());
        assert!(reg.get("missing").is_none());
        let replaced = reg.insert(pkg("json", ""));
        assert!(replaced.is_some());
        assert_eq!(reg.len(), 2);
        assert!(reg.remove("json").is_some());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn dir_registry_scans_packages_and_reports_bad_ones() {
        let root = std::env::temp_dir().join(format!(
            "lattice-plugins-dirscan-{}-{}",
            std::process::id(),
            crate::wasm::test_support::unique_seq()
        ));
        let ok_dir = root.join("json");
        std::fs::create_dir_all(&ok_dir).unwrap();
        std::fs::write(
            ok_dir.join("manifest.json"),
            br#"{"ns":"json","version":3,"entry":"process","deps":[]}"#,
        )
        .unwrap();
        std::fs::write(ok_dir.join("plugin.wasm"), b"\0asm\x01\0\0\0").unwrap();
        let bad_dir = root.join("bad");
        std::fs::create_dir_all(&bad_dir).unwrap();
        std::fs::write(bad_dir.join("manifest.json"), b"not json").unwrap();
        // Bad signature file: neither 64B raw nor base64 → bad package
        let bad_sig = root.join("bad-sig");
        std::fs::create_dir_all(&bad_sig).unwrap();
        std::fs::write(
            bad_sig.join("manifest.json"),
            br#"{"ns":"badsig","version":1,"signing_key_id":"k1"}"#,
        )
        .unwrap();
        std::fs::write(bad_sig.join("plugin.wasm"), b"\0asm\x01\0\0\0").unwrap();
        std::fs::write(bad_sig.join("signature"), b"!!!not-base64!!!").unwrap();

        let scan = DirRegistry::new(&root).scan();
        assert_eq!(scan.packages.len(), 1, "{scan:?}");
        assert_eq!(scan.packages[0].short_name(), "json");
        let rejected: Vec<&str> = scan.rejected.iter().map(|(n, _)| n.as_str()).collect();
        assert!(rejected.contains(&"bad"), "{scan:?}");
        assert!(rejected.contains(&"bad-sig"), "{scan:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dir_registry_reads_signature_sidecar_file() {
        let root = std::env::temp_dir().join(format!(
            "lattice-plugins-sigfile-{}-{}",
            std::process::id(),
            crate::wasm::test_support::unique_seq()
        ));
        let dir = root.join("sigfile");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("manifest.json"),
            br#"{"ns":"sigfile","version":1,"signing_key_id":"k1"}"#,
        )
        .unwrap();
        std::fs::write(dir.join("plugin.wasm"), b"\0asm\x01\0\0\0").unwrap();
        // Signature file in base64 text form (content is a fake 64B signature)
        let fake = vec![0xABu8; 64];
        std::fs::write(dir.join("signature"), base64_text(&fake)).unwrap();
        let scan = DirRegistry::new(&root).scan();
        assert_eq!(scan.packages.len(), 1, "{scan:?}");
        let pkg = &scan.packages[0];
        assert_eq!(pkg.signature.as_deref(), Some(fake.as_slice()));
        assert!(pkg.signature_encoding_error.is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn base64_text(bytes: &[u8]) -> String {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        STANDARD.encode(bytes)
    }

    #[test]
    fn manifest_signature_field_is_decoded_on_load() {
        let b64 = base64_text(&[0xCD; 64]);
        let manifest_json = format!(
            r#"{{"ns":"inline","version":2,"signature":"{b64}","signing_key_id":"k1"}}"#
        );
        let pkg = PluginPackage::new(manifest_json.into_bytes(), b"\0asm\x01\0\0\0".to_vec()).unwrap();
        assert_eq!(pkg.signature.as_deref(), Some(&[0xCD; 64][..]));
        assert_eq!(pkg.manifest.signing_key_id.as_deref(), Some("k1"));

        // Invalid base64 → rejected at construction (package-level manifest error)
        let bad = r#"{"ns":"inline","version":1,"signature":"!!!"}"#;
        assert!(PluginPackage::new(bad.as_bytes().to_vec(), vec![0]).is_err());
    }
}
