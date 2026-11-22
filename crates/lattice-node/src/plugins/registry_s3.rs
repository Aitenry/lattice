//! S3/object-storage **WASM plugin registry** (E25 / PL-10 / design ② §4.5 "read from object storage").
//!
//! ## Why "index-driven" instead of ListObjectsV2
//!
//! The node's existing object-storage client ([`crate::store::s3::S3`]) only offers **direct read/write by key** and
//! presigning, with no list-objects API; `store/s3.rs` is shared by several parties, so this task leaves it untouched. This registry
//! therefore uses an **explicit index**: publishers write an extra `index.json` next to the package, and the node only reads by key (all through the existing
//! `S3::get_bytes`, sharing the core object read/write SigV4/connection implementation rather than adding a second signing path).
//!
//! ## Object layout (bucket = `[s3] bucket_plugins`, prefix = `LATTICE_PLUGIN_S3_PREFIX`)
//!
//! ```text
//! <prefix>/index.json                       # {"plugins":[{"ns":"json","version":3,"path":"json-v3"}]}
//! <prefix>/<path>/manifest.json             # same format as the directory source (signature/base64 may be embedded)
//! <prefix>/<path>/plugin.wasm               # or the relative path when manifest.entry ends with .wasm
//! <prefix>/<path>/signature                 # optional: base64 text or a raw 64-byte Ed25519 signature
//! ```
//!
//! ## Semantics (consistent with node-side source merging)
//!
//! - **Enablement**: `LATTICE_PLUGIN_S3_PREFIX` non-empty (off by default, zero side effects for existing deployments); the bucket can be
//!   overridden by `LATTICE_PLUGIN_S3_BUCKET`, else `[s3] bucket_plugins` (default `lattice-plugins`).
//! - **fail-closed**: an item whose index/manifest/signature file **cannot be read or parsed** goes to [`S3Scan::rejected`] and
//!   the node host rejects it per `require_verified_signature`; this module **does not verify signatures** (no trusted public key) —
//!   it only assembles manifest/wasm/signature bytes into [`PluginPackage`], and the host produces the verification verdict.
//! - **Index missing** (HTTP 404) = empty registry (not an error); other read errors (network/auth/timeout)
//!   return `Err`: hot reload treats it as a hard failure 500 and keeps the old snapshot; startup load only WARNs and does not block ready.
//! - **Bad package rejection**: path traversal (`..`/absolute path/separators), manifest vs index `ns/version` mismatch,
//!   empty/oversized wasm, a signature object that is neither 64B raw nor base64 → all go to rejected and are not loaded.
//! - Fetched payloads (raw manifest/wasm/signature) **never enter logs/state/metrics**; only sizes and reason summaries are recorded.
//!
//! ## Source priority (assembled in `plugins.rs`)
//!
//! `dir > pg > s3`: a local directory is the operator emergency override; the PG `plugins` table carries the publish/canary state machine; object storage is the
//! package repository (on same-ns conflict the higher-priority source wins; S3 rows are skipped and counted).

use std::sync::OnceLock;
use std::time::Instant;

use lattice_plugins::manifest::PluginManifest;
use lattice_plugins::wasm::registry::PluginPackage;
use lattice_plugins::wasm::signature::{decode_b64_flexible, ED25519_SIGNATURE_BYTES};
use serde::Deserialize;

use crate::store::s3::S3;

/// Enablement switch: non-empty enables it; the value is the object key prefix (e.g. `server-wasm`).
pub const ENV_PREFIX: &str = "LATTICE_PLUGIN_S3_PREFIX";
/// Bucket override (defaults to `[s3] bucket_plugins`).
pub const ENV_BUCKET: &str = "LATTICE_PLUGIN_S3_BUCKET";
/// Default prefix (fallback only when explicitly enabled with an empty value; actual enablement requires the env var non-empty).
pub const DEFAULT_PREFIX: &str = "server-wasm";
/// Index file name.
pub const INDEX_FILE: &str = "index.json";
/// Manifest file name, same as the directory source.
pub const MANIFEST_FILE: &str = "manifest.json";
/// Default wasm file name (when manifest.entry is not a `.wasm` relative path).
pub const WASM_FILE: &str = "plugin.wasm";
/// Optional standalone signature file name.
pub const SIGNATURE_FILE: &str = "signature";

/// Runtime config (bucket + normalized prefix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryS3Config {
    pub bucket: String,
    /// Normalized prefix: leading/trailing `/` stripped, non-empty.
    pub prefix: String,
}

impl RegistryS3Config {
    pub fn new(bucket: impl Into<String>, prefix: impl Into<String>) -> Self {
        let bucket = bucket.into().trim().to_string();
        let prefix = prefix
            .into()
            .trim()
            .trim_matches('/')
            .trim_end_matches('/')
            .to_string();
        Self { bucket, prefix }
    }

    fn key(&self, rest: &str) -> String {
        if rest.is_empty() {
            self.prefix.clone()
        } else {
            format!("{}/{}", self.prefix, rest)
        }
    }

    pub fn index_key(&self) -> String {
        self.key(INDEX_FILE)
    }

    pub fn manifest_key(&self, package_path: &str) -> String {
        self.key(&format!("{package_path}/{MANIFEST_FILE}"))
    }

    pub fn wasm_key(&self, package_path: &str, wasm_name: &str) -> String {
        self.key(&format!("{package_path}/{wasm_name}"))
    }

    pub fn signature_key(&self, package_path: &str) -> String {
        self.key(&format!("{package_path}/{SIGNATURE_FILE}"))
    }
}

/// Resolve the registry switch from env + `[s3]` config; `None` = not enabled (default).
///
/// Reads env only, does not touch `config.rs` (a concurrent task is editing that file; E25 keeps config in env vars/module constants).
pub fn config_from_env(s3: &crate::config::S3Cfg) -> Option<RegistryS3Config> {
    let prefix = std::env::var(ENV_PREFIX).unwrap_or_default();
    let prefix = prefix.trim().trim_matches('/');
    if prefix.is_empty() {
        return None;
    }
    let bucket_env = std::env::var(ENV_BUCKET).unwrap_or_default();
    let bucket = if bucket_env.trim().is_empty() {
        let configured = s3.bucket_plugins.trim();
        if configured.is_empty() {
            "lattice-plugins"
        } else {
            configured
        }
    } else {
        bucket_env.trim()
    };
    Some(RegistryS3Config::new(bucket, prefix))
}

/// Index entry (`<prefix>/index.json`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct IndexEntry {
    pub ns: String,
    #[serde(default)]
    pub version: Option<u32>,
    /// Package directory name (single segment; default = `ns`). `/`, `\`, and `..` are forbidden.
    #[serde(default)]
    pub path: Option<String>,
}

impl IndexEntry {
    /// Effective package path (defaults to `ns`; an `@version` suffix on `ns` is stripped too).
    pub fn package_path(&self) -> String {
        let raw = self.path.as_deref().unwrap_or(&self.ns);
        raw.split('@').next().unwrap_or(raw).to_string()
    }
}

#[derive(Debug, Default, Deserialize)]
struct IndexDoc {
    #[serde(default)]
    plugins: Vec<IndexEntry>,
}

/// Result of one S3 scan (contains no raw payload).
#[derive(Debug, Default)]
pub struct S3Scan {
    pub packages: Vec<PluginPackage>,
    /// (package path/ns, rejection reason summary)
    pub rejected: Vec<(String, String)>,
    /// Whether index.json exists (404 = absent = empty registry, not an error).
    pub index_present: bool,
    pub index_bytes: usize,
    /// Number of objects read successfully (manifest + wasm + signature).
    pub objects: usize,
    pub elapsed_ms: u64,
}

/// Read the S3 plugin registry.
///
/// - `Ok(scan)`: the index exists and parses; individual bad packages go to `rejected` (no whole-scan failure).
/// - `Err(reason)`: **hard failure** (index read failed / invalid JSON) — startup load only WARNs, hot reload returns 500
///   and keeps the old snapshot. An `index` 404 is treated as an empty registry (`Ok`).
pub async fn load(
    s3: &S3,
    cfg: &RegistryS3Config,
    max_wasm_bytes: u64,
) -> Result<S3Scan, String> {
    let started = Instant::now();
    let mut scan = S3Scan::default();
    let index_bytes = match s3.get_bytes(&cfg.bucket, &cfg.index_key()).await {
        Ok(bytes) => bytes,
        Err(e) if is_not_found(&e) => {
            scan.elapsed_ms = started.elapsed().as_millis() as u64;
            return Ok(scan);
        }
        Err(e) => {
            return Err(format!(
                "read s3 plugin index {}/{}: {e}",
                cfg.bucket,
                cfg.index_key()
            ))
        }
    };
    scan.index_present = true;
    scan.index_bytes = index_bytes.len();
    let entries = parse_index(&index_bytes).map_err(|e| format!("invalid s3 plugin index: {e}"))?;

    for entry in entries {
        let label = entry.package_path();
        match load_one(s3, cfg, &entry, max_wasm_bytes, &mut scan.objects).await {
            Ok(package) => scan.packages.push(package),
            Err(reason) => scan.rejected.push((label, reason)),
        }
    }
    // Assembly order is deterministic (reproducible logs/state; different paths may share an ns, left to the host's same-name override rule).
    scan.packages
        .sort_by(|a, b| (a.short_name(), a.manifest.version).cmp(&(b.short_name(), b.manifest.version)));
    scan.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(scan)
}

fn is_not_found(err: &str) -> bool {
    err.contains("HTTP 404")
}

async fn load_one(
    s3: &S3,
    cfg: &RegistryS3Config,
    entry: &IndexEntry,
    max_wasm_bytes: u64,
    objects: &mut usize,
) -> Result<PluginPackage, String> {
    let path = entry.package_path();
    validate_package_path(&path)?;
    let manifest_bytes = s3
        .get_bytes(&cfg.bucket, &cfg.manifest_key(&path))
        .await
        .map_err(|e| format!("read manifest.json: {e}"))?;
    *objects += 1;
    let manifest: PluginManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("manifest.json invalid: {e}"))?;
    // Cross-package guard: the index-declared ns/version (if given) must match the manifest.
    if entry.ns != manifest.ns {
        return Err(format!(
            "index ns `{}` does not match manifest.ns `{}`",
            entry.ns, manifest.ns
        ));
    }
    if let Some(expected) = entry.version {
        if expected != manifest.version {
            return Err(format!(
                "index version {expected} does not match manifest.version {}",
                manifest.version
            ));
        }
    }
    let wasm_name = wasm_file_name(&manifest)?;
    validate_relative_wasm_name(&wasm_name)?;
    let wasm = s3
        .get_bytes(&cfg.bucket, &cfg.wasm_key(&path, &wasm_name))
        .await
        .map_err(|e| format!("read wasm `{wasm_name}`: {e}"))?;
    *objects += 1;
    // Optional standalone signature (404 = absent; a signature embedded in the manifest counts too).
    let signature = match s3.get_bytes(&cfg.bucket, &cfg.signature_key(&path)).await {
        Ok(raw) => {
            *objects += 1;
            Some(decode_signature_object(&raw)?)
        }
        Err(e) if is_not_found(&e) => None,
        Err(e) => return Err(format!("read signature: {e}")),
    };
    assemble_package(
        manifest_bytes,
        manifest,
        wasm,
        signature,
        max_wasm_bytes,
    )
}

/// Index JSON → entry list (strict: must be a non-empty `plugins` array; required fields validated per entry).
pub fn parse_index(bytes: &[u8]) -> Result<Vec<IndexEntry>, String> {
    let doc: IndexDoc =
        serde_json::from_slice(bytes).map_err(|e| format!("index.json is not valid JSON: {e}"))?;
    if doc.plugins.is_empty() {
        return Err("index.json has an empty `plugins` array".to_string());
    }
    let mut out = Vec::with_capacity(doc.plugins.len());
    for (i, entry) in doc.plugins.into_iter().enumerate() {
        if entry.ns.trim().is_empty() {
            return Err(format!("plugins[{i}].ns is empty"));
        }
        if entry.ns.len() > 128 || entry.ns.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(format!("plugins[{i}].ns must be <=128 chars without whitespace/control"));
        }
        if let Some(version) = entry.version {
            if version == 0 {
                return Err(format!("plugins[{i}].version must be > 0"));
            }
        }
        validate_package_path(&entry.package_path()).map_err(|e| format!("plugins[{i}]: {e}"))?;
        out.push(entry);
    }
    Ok(out)
}

/// Package directory name safety: single segment, non-empty, only `[A-Za-z0-9._-]`, and not `.`/`..`.
pub fn validate_package_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("package path is empty".to_string());
    }
    if path == "." || path == ".." || path.contains("..") {
        return Err(format!("package path `{path}` contains `..`"));
    }
    if path
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
    {
        return Err(format!(
            "package path `{path}` must be a single path segment ([A-Za-z0-9._-])"
        ));
    }
    Ok(())
}

/// manifest → wasm relative file name (same rules as the directory source).
pub fn wasm_file_name(manifest: &PluginManifest) -> Result<String, String> {
    match manifest.entry_name_override() {
        Some(entry) if entry.ends_with(".wasm") => Ok(entry.to_string()),
        _ => Ok(WASM_FILE.to_string()),
    }
}

/// wasm relative name safety: reject absolute paths, `..`, and root prefixes (subdirectory-relative paths are allowed, same convention as DirRegistry).
pub fn validate_relative_wasm_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("wasm file name is empty".to_string());
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(format!("wasm file `{name}` must be relative"));
    }
    for seg in name.split(['/', '\\']) {
        if seg == ".." {
            return Err(format!("wasm file `{name}` escapes the package directory"));
        }
    }
    Ok(())
}

/// Decode a standalone `signature` object: exactly 64B raw, or base64 text (standard/URL-safe).
///
/// **ASCII whitespace (including newlines) in base64 text is stripped first**: publish tools often wrap signatures at 76 columns,
/// whitespace has no syntactic meaning in base64; after stripping, decoding must still yield exactly 64B (otherwise fail-closed).
pub fn decode_signature_object(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.len() == ED25519_SIGNATURE_BYTES {
        return Ok(raw.to_vec());
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| "signature object is neither 64 raw bytes nor base64 text".to_string())?;
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let sig = decode_b64_flexible(&compact)
        .map_err(|e| format!("signature object is not valid base64: {e}"))?;
    if sig.len() != ED25519_SIGNATURE_BYTES {
        return Err(format!(
            "signature object decodes to {} bytes, expected {}",
            sig.len(),
            ED25519_SIGNATURE_BYTES
        ));
    }
    Ok(sig)
}

/// Pure assembly (easy to unit test): manifest bytes + wasm + optional standalone signature → [`PluginPackage`].
///
/// No signature verification and no wasm compilation (the host does both on register); **package-level** checks such as size/empty are done.
pub fn assemble_package(
    manifest_bytes: Vec<u8>,
    manifest: PluginManifest,
    wasm: Vec<u8>,
    sidecar_signature: Option<Vec<u8>>,
    max_wasm_bytes: u64,
) -> Result<PluginPackage, String> {
    if wasm.is_empty() {
        return Err("wasm object is empty".to_string());
    }
    let limit = max_wasm_bytes.max(1);
    if wasm.len() as u64 > limit {
        return Err(format!(
            "wasm is {} bytes, exceeds max_wasm_bytes {limit}",
            wasm.len()
        ));
    }
    // `PluginPackage::new` parses the manifest and decodes an embedded signature (bad base64 → package-level reject, fail-closed).
    let mut pkg = PluginPackage::new(manifest_bytes, wasm)
        .map_err(|e| format!("manifest.json invalid: {e}"))?;
    pkg.manifest = manifest;
    if sidecar_signature.is_some() {
        // A standalone `signature` object is authoritative (same semantics as the directory source's signature sidecar).
        pkg.signature = sidecar_signature;
    }
    Ok(pkg)
}

/// Warn at most once per process (avoids repeated identical missing-index logs on hot reload).
pub fn warn_once_absent(key: &str) {
    static WARNED: OnceLock<()> = OnceLock::new();
    if WARNED.set(()).is_ok() {
        tracing::info!(
            key,
            "[plugins] s3 plugin index not found; treating the object-storage plugin registry as empty"
        );
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    fn manifest_json(ns: &str, version: u32) -> Vec<u8> {
        format!(
            r#"{{"ns":"{ns}","version":{version},"entry":"","deps":[],"limits":{{"memory_mb":0,"fuel":0,"timeout_ms":0}}}}"#
        )
        .into_bytes()
    }

    fn parsed(ns: &str, version: u32) -> PluginManifest {
        serde_json::from_slice(&manifest_json(ns, version)).unwrap()
    }

    #[test]
    fn config_from_env_is_off_by_default() {
        // Note: do not remove/set the process env here (other tests may read it concurrently); only verify pure normalization and that default-off
        // semantics hold when env is missing. Env-present cases are covered by E2E (real process).
        if std::env::var(ENV_PREFIX).is_err() {
            let cfg = crate::config::S3Cfg::default();
            assert!(config_from_env(&cfg).is_none());
        }
    }

    #[test]
    fn config_normalizes_prefix_and_bucket() {
        let cfg = RegistryS3Config::new(" lattice-plugins ", "/server-wasm/");
        assert_eq!(cfg.bucket, "lattice-plugins");
        assert_eq!(cfg.prefix, "server-wasm");
        assert_eq!(cfg.index_key(), "server-wasm/index.json");
        assert_eq!(cfg.manifest_key("echo-v1"), "server-wasm/echo-v1/manifest.json");
        assert_eq!(
            cfg.wasm_key("echo-v1", "plugin.wasm"),
            "server-wasm/echo-v1/plugin.wasm"
        );
        assert_eq!(
            cfg.signature_key("echo-v1"),
            "server-wasm/echo-v1/signature"
        );
    }

    #[test]
    fn parse_index_accepts_valid_entries_and_path_defaults() {
        let raw = br#"{"plugins":[
            {"ns":"json","version":3,"path":"json-v3"},
            {"ns":"xml@2","version":2},
            {"ns":"proto"}
        ]}"#;
        let entries = parse_index(raw).expect("valid index");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].package_path(), "json-v3");
        assert_eq!(entries[1].package_path(), "xml", "ns with the @version suffix stripped is used as the path");
        assert_eq!(entries[2].package_path(), "proto");
    }

    #[test]
    fn parse_index_rejects_empty_or_bad_entries() {
        assert!(parse_index(br#"not json"#).is_err());
        assert!(parse_index(br#"{"plugins":[]}"#).is_err(), "an empty index is invalid (a 404 marks an empty registry)");
        assert!(parse_index(br#"{"plugins":[{"ns":"  "}]}"#).is_err());
        assert!(parse_index(br#"{"plugins":[{"ns":"a b"}]}"#).is_err());
        assert!(parse_index(br#"{"plugins":[{"ns":"ok","version":0}]}"#).is_err());
        assert!(
            parse_index(br#"{"plugins":[{"ns":"ok","path":"../etc"}]}"#).is_err(),
            "path traversal must be rejected"
        );
        assert!(parse_index(br#"{"plugins":[{"ns":"ok","path":"a/b"}]}"#).is_err());
    }

    #[test]
    fn package_path_and_wasm_name_are_traversal_safe() {
        assert!(validate_package_path("echo-v1").is_ok());
        assert!(validate_package_path("echo_v1.2").is_ok());
        assert!(validate_package_path("").is_err());
        assert!(validate_package_path("..").is_err());
        assert!(validate_package_path("a/b").is_err());
        assert!(validate_package_path("a\\b").is_err());

        assert!(validate_relative_wasm_name("plugin.wasm").is_ok());
        assert!(validate_relative_wasm_name("sub/plugin.wasm").is_ok());
        assert!(validate_relative_wasm_name("/abs/plugin.wasm").is_err());
        assert!(validate_relative_wasm_name("../escape.wasm").is_err());
    }

    #[test]
    fn wasm_file_name_follows_manifest_entry_override() {
        let m = parsed("json", 1);
        assert_eq!(wasm_file_name(&m).unwrap(), "plugin.wasm");
        let mut m2 = parsed("json", 1);
        m2.entry = "pkg/impl.wasm".into();
        assert_eq!(wasm_file_name(&m2).unwrap(), "pkg/impl.wasm");
    }

    #[test]
    fn decode_signature_object_accepts_raw_and_base64() {
        use base64::Engine as _;
        let raw = vec![0xABu8; 64];
        assert_eq!(decode_signature_object(&raw).unwrap(), raw);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert_eq!(decode_signature_object(b64.as_bytes()).unwrap(), raw);
        // Multi-line base64 (publish tools often wrap lines)
        let wrapped = format!("{}\n{}\n", &b64[..44], &b64[44..]);
        assert_eq!(decode_signature_object(wrapped.as_bytes()).unwrap(), raw);
        // Bad object: neither 64B raw nor valid base64
        assert!(decode_signature_object(b"!!!not-base64!!!").is_err());
        // Signature of the wrong length
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        assert!(decode_signature_object(short.as_bytes()).is_err());
    }

    #[test]
    fn assemble_package_rejects_empty_oversized_and_bad_manifest() {
        let m = parsed("json", 1);
        assert!(assemble_package(manifest_json("json", 1), m.clone(), Vec::new(), None, 1024)
            .unwrap_err()
            .contains("empty"));
        assert!(
            assemble_package(manifest_json("json", 1), m.clone(), vec![0u8; 2048], None, 1024)
                .unwrap_err()
                .contains("max_wasm_bytes")
        );
        assert!(assemble_package(
            b"not json".to_vec(),
            m.clone(),
            b"\0asm\x01\0\0\0".to_vec(),
            None,
            1024
        )
        .is_err());
        let ok = assemble_package(
            manifest_json("json", 1),
            m,
            b"\0asm\x01\0\0\0".to_vec(),
            None,
            1024,
        )
        .expect("valid package");
        assert_eq!(ok.short_name(), "json");
        assert!(ok.signature.is_none());
    }

    #[test]
    fn assemble_package_sidecar_signature_overrides_manifest_signature() {
        let mut m = parsed("sig", 2);
        m.signature = Some(base64::engine::general_purpose::STANDARD.encode([1u8; 64]));
        let pkg = assemble_package(
            manifest_json("sig", 2),
            m,
            b"\0asm\x01\0\0\0".to_vec(),
            Some(vec![7u8; 64]),
            1024,
        )
        .expect("valid package");
        assert_eq!(pkg.signature.as_deref(), Some(&[7u8; 64][..]));
    }
}
