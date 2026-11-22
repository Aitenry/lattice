//! Node-side **WASM plugin host wiring** (PL-10 / design ② §4.5).
//!
//! This module wires the `lattice-plugins` WASM host into the node lifecycle and is a **runtime singleton**:
//!
//! 1. **Startup registration** ([`init`], called by `node::build` before ready):
//!    - build the trusted table from `[plugins] trusted_keys` (id → base64 raw Ed25519 public key) + `trusted_keys_file`;
//!      read/parse failures are fail-closed (warn only, all unverified packages rejected);
//!    - `HostConfig` uses `[plugins] timeout_ms/memory_mb/instructions` as host caps
//!      (a manifest may only request less), `require_verified_signature` defaults to true;
//!    - scan `[plugins] wasm_dir` (`<ns>/manifest.json + plugin.wasm + signature`) and register;
//!      **bad packages only warn + metrics, never block node ready**;
//!    - with `[plugins] from_db=true` (default), read the PG `plugins` table **asynchronously**
//!      (`wasm is not null and status in ('active','canary')`; same ns → highest active version,
//!      canary ignored and recorded); the manifest comes from `config.manifest` (preferred when complete) or is assembled from
//!      `ns/version + config.entry/deps/limits/signing_key_id`; `plugins.signature`
//!      (64B Ed25519 over `sha256(wasm || canonical_manifest_json)`) is verified with the same trusted table;
//!      **the directory wins**: on a same-ns conflict the directory package applies and the PG row is skipped with a WARN; SQL prefilters by
//!      `[plugins] max_wasm_bytes` (default 16MiB) to avoid OOM on huge objects; query/load failures only WARN,
//!      never blocking node ready;
//!    - metrics `lattice_plugin_wasm_loaded/verified/rejected_total/signature_total/source_total`
//!      (`source_total` counts by `source=dir|pg`).
//! 2. **Admin-plane reads** ([`wasm_status`]): the `wasm` field appended by `GET /v1/admin/plugins`,
//!    listing loaded/rejected plugins, verification status, and `from_db`/`sources` counts (**without wasm bytes, keys,**
//!    **or signature bodies**).
//! 3. **Invoke** ([`invoke`]): implementation of `POST /v1/admin/plugins/{ns}/invoke`; only
//!    plugins with `trusted=true` (Ed25519 verified) can be invoked; errors map to low-cardinality reasons
//!    `not_found / not_verified / circuit_open / timeout / trap / memory / fuel / ...`;
//!    rate limiting and concurrency are handled by the host (`max_concurrency` + circuit breaker).
//! 4. **Hot reload** ([`reload`]): `POST /v1/admin/plugins/wasm/reload` (admin auth;
//!    body optional `{source:"all|dir|pg"}`, default `all`):
//!    - **Atomic rebuild**: first assemble the directory scan + PG registry into a **new host/snapshot** (wasmtime
//!      `Module` compiled in memory; bad packages are only rejected per the existing fail-closed policy, never blocking); on full or partial
//!      success, swap `RwLock<Arc<WasmHost>>` once; in-flight invokes finish on the old `Arc` without interruption
//!      and never see a half-assembled registry;
//!    - **Failure keeps the old snapshot**: PG query failure / directory scan failure / host rebuild failure → 500 with
//!      `details.reason` (`pg_query|dir_scan|host_init`); generation unchanged, current registry untouched;
//!    - **Previous-version fallback**: when a new package is rejected (bad signature/unsigned/compile failure/missing dependency), if the previous snapshot
//!      has the same ns it is restored (`retained` count), so one bad upgrade cannot take a live plugin offline;
//!    - concurrency mutex (one reload at a time, duplicate requests 409) + rate limit (1/s, over-limit 429);
//!      the `source` filter **re-reads only** that source, the other keeps the previous snapshot (`dir`/`pg` do not affect each other);
//!    - returns `{loaded, from_dir, from_pg, rejected, conflicts, retained, skipped,
//!      generation, elapsed_ms, source}` (**without** wasm bytes/signature/public key/payload); audit
//!      `plugin.wasm.reload`; generation increases monotonically (initial snapshot = 1, failures do not increment).
//!
//! # Feature boundaries
//!
//! All host capabilities sit behind the compile-time feature `wasm-host` (off by default; the default node build does not compile
//! wasmtime/ring); when disabled this module provides **same-signature stubs**: the node starts normally, admin status returns
//! `enabled=false`, and invoke/reload return 422 `wasm_host_disabled`.
//!
//! # Not done (report boundaries)
//!
//! - **Zero-knowledge runtime probe (added in E25)**: with `mode=zero-knowledge` the node sets
//!   `HostConfig::allow_content_plugins` to `false`; content plugins (ns prefixes `convert:` /
//!   `transcode:` / `format:` / `detect:`, classification in
//!   `lattice_plugins::wasm::content_plugin_class`) fail closed at the **registration entry**
//!   (`ErrorKind::ContentBlocked` → `rejected[].kind="content_blocked"`, invoke falls back to
//!   422 `reason=zero_knowledge`), observable via `wasm_status.mode/content_plugins`; env/E2E
//!   probes in `scripts/plugin-zk-format-e2e.mjs`. **Classification gap**: manifests have no explicit
//!   `class` field, so a plugin with any name that actually reads payloads cannot be proven to violate; a complete allowlist needs a class
//!   column in the manifest/`plugins` table (a cross-document contract change, out of E25 scope).
//! - **Real format conversion (host layer added in E25)**: `lattice-plugins::wasm::convert` provides
//!   `negotiate_convert` (real `convert:<src>-><dst>` plugin execution + zero-copy passthrough semantics, unit tests cover
//!   Cow::Borrowed/not calling the plugin); the node-side real execution path = admin invoke
//!   (`scripts/plugin-zk-format-e2e.mjs` verifies with a real NDJSON→JSON converter). **GAP**:
//!   `pipeline/format.rs::convert` is still the "no converter passthrough" placeholder and the ingestion format stage is not wired;
//!   negotiated zero-copy is only asserted at the host API layer; the REST/WS transport layer has no end-to-end zero-copy evidence.
//! - **Sidecar process lifecycle/crash auto-restart (E25 is script-level only)**: this crate only has a gRPC client
//!   (`plugins::sidecar`); it does not start/supervise the sidecar process; supervisor templates (K8s/systemd/
//!   compose) and measured health-check/restart semantics are in `scripts/wasm-sidecar-supervisor/` +
//!   `scripts/wasm-sidecar-supervisor-e2e.mjs` (script-level, not run on a real cluster);
//!   `PluginSidecar.Health` is still not wired into the node client, so "Health=false → trip that ns" is not wired.
//! - **External KMS/Vault (not done, boundary)**: the `inspectable` mode KEK still comes from env/`kek_file`
//!   as a node-local source (E15); there is no KMS/Vault client and no remote key fetch/rotation API; D3's "production KMS
//!   hosting" stays unimplemented, and E25's zero-knowledge probe/convert paths do not depend on a server-side KEK (inspectable only reads
//!   `[policy] mode`).
//! - **Canary routing (added in E25, off by default)**: `[plugins]` has no corresponding config section (`config.rs` is being changed by a concurrent
//!   task, so this task leaves it alone), so it is enabled by the env switch `LATTICE_PLUGIN_CANARY_ENABLED=true`;
//!   once enabled, PG canary rows (`canary_ratio ∈ 0/50/100`, loaded only when >0) register into a **separate canary host**
//!   (separate Store pool/circuit breaker/metrics); invoke routes by a stable hash bucket of `ns+entry+input`;
//!   `plugin_version` is observable via the existing `version` field of the invoke response, and route counts are observable in
//!   `GET /v1/admin/plugins.wasm.canary` and logs (the admin response shape is fixed by `admin/mod.rs`, which this task may not modify,
//!   so no response field was added). Off by default = old behavior (canary ignored and recorded).
//!   Multi-node consistency (same salt/ratio → same version per request on two nodes + S3 registry consistency across nodes) is measured in
//!   `scripts/plugin-multinode-canary-e2e.mjs`; single-node E2E in `scripts/plugin-canary-e2e.mjs`.
//! - **S3 object-storage registry (added in E25, off by default)**: see [`registry_s3`]; the enable switch is
//!   `LATTICE_PLUGIN_S3_PREFIX` (non-empty), merged with directory/PG as `dir > pg > s3`.
//! - No signing-key custody/key-rotation API (trusted_keys is static);
//! - Hot reload rebuilding the host resets per-plugin circuit breakers/in-host counters (the old host is released with the last in-flight call);
//! - invoke has no separate QPS limit (only host concurrency/pool caps and the circuit breaker protect it);
//! - the canonical canary rule (design PL-10 §6: hash by stable user identifier) cannot get the end-user identity on the admin invoke path,
//!   so a request-content hash is used instead for now (stable and reproducible for the same request; consistent across nodes).

/// S3 object-storage plugin registry (enabled when `LATTICE_PLUGIN_S3_PREFIX` is non-empty; see the module docs).
#[cfg(feature = "wasm-host")]
pub mod registry_s3;


/// Error reason (low cardinality; shared by `details.reason` and metric labels, **no payload/keys**).
#[cfg(feature = "wasm-host")]
pub fn reason_for_kind(kind: lattice_plugins::wasm::ErrorKind) -> &'static str {
    use lattice_plugins::wasm::ErrorKind as K;
    match kind {
        K::Manifest => "manifest",
        K::Signature => "not_verified",
        // Zero-knowledge mode content-plugin allowlist (E25 zero-knowledge runtime probe): the rejection reason uses the same
        // low-cardinality reason `zero_knowledge` as the pipeline's `pipeline::encrypt::ensure_can_inspect`.
        K::ContentBlocked => "zero_knowledge",
        K::NotFound => "not_found",
        K::MissingExport => "missing_export",
        K::BadAbi => "bad_abi",
        K::Memory => "memory",
        K::Fuel => "fuel",
        K::Timeout => "timeout",
        K::Trap => "trap",
        K::ExitCode => "exit_code",
        K::CircuitOpen => "circuit_open",
        K::Busy => "busy",
        K::Internal => "internal",
    }
}

/// HTTP status for each failure class (contract: 422 = caller/plugin-package problem, 500 = execution-time failure/internal).
#[cfg(feature = "wasm-host")]
pub fn http_status_for_kind(kind: lattice_plugins::wasm::ErrorKind) -> u16 {
    use lattice_plugins::wasm::ErrorKind as K;
    match kind {
        K::NotFound | K::Signature | K::BadAbi | K::MissingExport | K::Manifest => 422,
        // Content plugins are unavailable in zero-knowledge mode = the deployment mode disallows them (422, not a 500 execution failure).
        K::ContentBlocked => 422,
        _ => 500,
    }
}

/// Result of one successful call (the raw output is base64-encoded by the admin layer).
#[derive(Debug, Clone)]
pub struct InvokeOutcome {
    pub output: Vec<u8>,
    pub plugin: String,
    pub version: u32,
    pub entry: String,
    pub elapsed_ms: u64,
    pub fuel_used: Option<u64>,
    /// Actual route: `stable` / `canary` (canary routing; always `stable` when disabled).
    pub route: &'static str,
}

/// One failed call (the admin layer builds the ⑤ §0.5 error body from it).
#[derive(Debug, Clone)]
pub struct InvokeFailure {
    /// Low-cardinality reason: `not_found` / `not_verified` / `circuit_open` / `timeout` / …
    pub reason: &'static str,
    /// Readable message (no payload/keys).
    pub message: String,
    /// 422 or 500.
    pub http_status: u16,
}

impl InvokeFailure {
    pub fn new(reason: &'static str, http_status: u16, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
            http_status,
        }
    }
}

/// Hot-reload source (the optional body `source` of `POST /v1/admin/plugins/wasm/reload`, default `all`).
///
/// - `All`: re-read both directory and PG (the directory wins on same-ns conflicts, following the startup load policy);
/// - `Dir`: rescan the directory only; the PG source keeps the previous snapshot (no DB query, PG plugins not lost);
/// - `Pg`: re-read the PG registry only; the directory source keeps the previous snapshot;
/// - `S3`: re-read only the object-storage registry (available only when `LATTICE_PLUGIN_S3_PREFIX` is enabled).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadSource {
    All,
    Dir,
    Pg,
    S3,
}

impl ReloadSource {
    /// Parse the body `source` (case-insensitive; empty/absent = `all`; invalid value returns `None` → 422).
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "all" => Some(Self::All),
            "dir" => Some(Self::Dir),
            "pg" => Some(Self::Pg),
            "s3" => Some(Self::S3),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Dir => "dir",
            Self::Pg => "pg",
            Self::S3 => "s3",
        }
    }

    pub fn includes_dir(self) -> bool {
        matches!(self, Self::All | Self::Dir)
    }

    pub fn includes_pg(self) -> bool {
        matches!(self, Self::All | Self::Pg)
    }

    pub fn includes_s3(self) -> bool {
        matches!(self, Self::All | Self::S3)
    }
}

/// Result of one successful hot reload (the admin layer serializes it directly into the response; **without** wasm bytes/signature/public key/payload).
///
/// Field contract (task card): `loaded` is the total number of plugins actually registered in the **new snapshot** (= `from_dir + from_pg`);
/// `rejected` is the number of candidate packages rejected during this rebuild (including the `conflicts` subset, consistent with
/// the startup-load `wasm.rejected` convention); `retained` is the number of rejected candidates that fell back to the previous snapshot's version.
#[derive(Debug, Clone)]
pub struct ReloadOutcome {
    pub source: &'static str,
    pub loaded: usize,
    pub from_dir: usize,
    pub from_pg: usize,
    /// Number of packages actually in effect from the S3 source (0 when not enabled/not re-read).
    pub from_s3: usize,
    /// Number of packages registered in the canary host (0 when disabled).
    pub canary_loaded: usize,
    pub rejected: usize,
    pub conflicts: usize,
    pub retained: usize,
    pub skipped: usize,
    /// New snapshot generation (initial snapshot = 1, +1 per successful hot reload; monotonically increasing).
    pub generation: u64,
    pub elapsed_ms: u64,
    /// Time of the most recent successful hot reload (RFC3339 UTC; consistent with `GET /v1/admin/plugins.wasm`).
    pub last_reload_at: String,
}

impl ReloadOutcome {
    /// Low-cardinality summary for audit/logs (**without** wasm bytes/keys/payload).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "outcome": "ok",
            "source": self.source,
            "loaded": self.loaded,
            "from_dir": self.from_dir,
            "from_pg": self.from_pg,
            "from_s3": self.from_s3,
            "canary_loaded": self.canary_loaded,
            "rejected": self.rejected,
            "conflicts": self.conflicts,
            "retained": self.retained,
            "skipped": self.skipped,
            "generation": self.generation,
            "elapsed_ms": self.elapsed_ms,
            "last_reload_at": self.last_reload_at,
        })
    }
}

/// One **unfinished** hot reload (the old snapshot stays unchanged).
///
/// `http_status` determines the admin error code: 422 = request problem (invalid source/host not enabled),
/// 409 = a concurrent reload is running, 429 = hit the 1/s rate limit, 500 = source read/host rebuild failure
/// (`reason` ∈ `pg_query|dir_scan|host_init|not_initialized`).
#[derive(Debug, Clone)]
pub struct ReloadFailure {
    pub reason: &'static str,
    pub http_status: u16,
    pub message: String,
}

impl ReloadFailure {
    pub fn new(reason: &'static str, http_status: u16, message: impl Into<String>) -> Self {
        Self {
            reason,
            http_status,
            message: message.into(),
        }
    }

    /// Audit summary (reason/status only, no payload).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "outcome": "error",
            "reason": self.reason,
            "http_status": self.http_status,
        })
    }
}

/// Node-side **gRPC sidecar client wiring** (PL-10 / ⑤ §10).
///
/// Runtime is a process-level `OnceLock` singleton (same approach as the WASM host, without changing `state.rs`):
///
/// 1. **Startup registration** ([`init`], called by [`crate::plugins::init`] from `node::build` before ready):
///    - `[plugins.sidecar].enabled=false` (default) → no client is created and `plugins::sidecar::client()`
///      returns `NoopSidecar` ("no converter" passthrough semantics, ⑤ §10 failure behavior);
///    - `enabled=true` → `GrpcSidecarClient::connect`: only validate config/read certificates + `connect_lazy()`,
///      **no network IO**, so an offline sidecar does not affect node startup/ready;
///    - config errors (empty endpoint/scheme inconsistent with TLS/missing TLS values/certificate read failure) only WARN +
///      fall back to `NoopSidecar` (fail-closed, never silent plaintext); plaintext mode warns at startup (dev only).
/// 2. **Invoke** ([`client`]): singleton `Arc<dyn SidecarClient>`; the 500ms timeout / 30s circuit breaker live inside the client.
/// 3. **Diagnostics** ([`status`]): low-cardinality JSON (enabled/client/endpoint/mtls/timeout/circuit window/
///    config error), **without certificates, keys, or payloads**. Wiring `GET /v1/admin/plugins` is out of this task's scope
///    (the admin files are not in the allowed change set); later admin/probe work can reuse this function directly.
///
/// Call-site boundary (stated in the report): real format conversion (detect/convert pipeline → sidecar) **is not wired**;
/// this module only guarantees "the client is usable when configured, passthrough semantics are unchanged when not, and startup is unaffected".
pub mod sidecar {
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use lattice_plugins::sidecar::{
        GrpcSidecarClient, NoopSidecar, SidecarClient, SidecarConfig, SidecarTls,
    };
    use serde_json::{json, Value};

    use crate::config::SidecarCfg;

    /// Process-level singleton (one sidecar client per node process).
    static CLIENT: OnceLock<Arc<dyn SidecarClient>> = OnceLock::new();
    /// Runtime diagnostics (enabled/config error/plaintext marker; no certificates/keys/payloads).
    static STATUS: OnceLock<SidecarStatus> = OnceLock::new();

    #[derive(Debug, Clone)]
    struct SidecarStatus {
        enabled: bool,
        /// `grpc` (a real client is registered) or `noop` (not configured/config error).
        client: &'static str,
        endpoint: String,
        mtls: bool,
        plaintext: bool,
        timeout_ms: u64,
        circuit_break_secs: u64,
        error: Option<String>,
    }

    /// `[plugins.sidecar]` → `lattice-plugins` client config (pure function, easy to unit test).
    ///
    /// TLS semantics (consistent with the client, fail-closed):
    /// - all three empty → plaintext (`tls: None`; dev only, warns at init);
    /// - all three present → mTLS;
    /// - only some present → `Err` (the node WARNs and falls back to Noop, **never** silently downgrading to plaintext).
    pub fn options(cfg: &SidecarCfg) -> Result<SidecarConfig, String> {
        let endpoint = cfg.endpoint.trim().to_string();
        if endpoint.is_empty() {
            return Err("[plugins.sidecar] endpoint is empty".into());
        }
        let timeout = Duration::from_millis(cfg.effective_timeout_ms());
        let circuit_break = Duration::from_secs(lattice_plugins::limits::CIRCUIT_BREAK_SECS);
        if cfg.tls_unset() {
            return Ok(SidecarConfig {
                endpoint,
                timeout,
                tls: None,
                circuit_break,
            });
        }
        if !cfg.tls_complete() {
            return Err(
                "[plugins.sidecar] tls_ca/tls_cert/tls_key must be all set (mTLS) or all empty \
                 (plaintext dev)"
                    .into(),
            );
        }
        Ok(SidecarConfig {
            endpoint,
            timeout,
            tls: Some(SidecarTls {
                ca_path: cfg.tls_ca.trim().to_string(),
                cert_path: cfg.tls_cert.trim().to_string(),
                key_path: cfg.tls_key.trim().to_string(),
            }),
            circuit_break,
        })
    }

    /// Called at node startup (before ready). Any failure only WARNs/records status and **never blocks the node**.
    pub fn init(st: &crate::state::AppState) {
        let cfg = &st.cfg.plugins.sidecar;
        let timeout_ms = cfg.effective_timeout_ms();
        let circuit_break_secs = lattice_plugins::limits::CIRCUIT_BREAK_SECS;
        if !cfg.enabled {
            let _ = STATUS.set(SidecarStatus {
                enabled: false,
                client: "noop",
                endpoint: cfg.endpoint.trim().to_string(),
                mtls: false,
                plaintext: false,
                timeout_ms,
                circuit_break_secs,
                error: None,
            });
            tracing::debug!(
                "[plugins.sidecar] enabled=false; keeping NoopSidecar (pass-through, ⑤ §10)"
            );
            return;
        }
        let plaintext = cfg.tls_unset();
        let result = options(cfg)
            .and_then(|opts| GrpcSidecarClient::connect(&opts).map_err(|e| e.to_string()));
        match result {
            Ok(client) => {
                if plaintext {
                    // Plaintext is allowed only in dev; production must use mTLS (⑤ §10).
                    tracing::warn!(
                        endpoint = %client.endpoint(),
                        "[plugins.sidecar] plaintext gRPC (tls_ca/tls_cert/tls_key empty); \
                         dev only — production must enable mTLS"
                    );
                }
                tracing::info!(
                    endpoint = %client.endpoint(),
                    mtls = client.mtls(),
                    timeout_ms = client.timeout().as_millis() as u64,
                    circuit_break_secs = client.circuit_break().as_secs(),
                    "[plugins.sidecar] client ready (lazy connect; no network IO before first call)"
                );
                let status = SidecarStatus {
                    enabled: true,
                    client: "grpc",
                    endpoint: client.endpoint().to_string(),
                    mtls: client.mtls(),
                    plaintext,
                    timeout_ms: client.timeout().as_millis() as u64,
                    circuit_break_secs: client.circuit_break().as_secs(),
                    error: None,
                };
                if CLIENT.set(Arc::new(client)).is_err() {
                    tracing::warn!("[plugins.sidecar] already initialized; second init ignored");
                }
                let _ = STATUS.set(status);
            }
            Err(e) => {
                // fail-closed: do not risk a half-configured client; fall back to Noop (callers pass through with "no converter").
                tracing::warn!(
                    endpoint = %cfg.endpoint,
                    error = %e,
                    "[plugins.sidecar] init failed; keeping NoopSidecar (pass-through); \
                     node startup/ready unaffected"
                );
                let _ = STATUS.set(SidecarStatus {
                    enabled: true,
                    client: "noop",
                    endpoint: cfg.endpoint.trim().to_string(),
                    mtls: cfg.tls_complete(),
                    plaintext,
                    timeout_ms,
                    circuit_break_secs,
                    error: Some(e),
                });
            }
        }
    }

    /// Get the sidecar call singleton; unconfigured/init failure → `NoopSidecar` (passthrough semantics).
    ///
    /// Call sites (future pipeline convert) depend only on this function and never hold the client type directly.
    pub fn client() -> Arc<dyn SidecarClient> {
        CLIENT
            .get()
            .cloned()
            .unwrap_or_else(|| Arc::new(NoopSidecar))
    }

    /// Diagnostic status (low-cardinality JSON; no certificates/keys/payloads). Reusable by unit tests/admin/probes.
    pub fn status() -> Value {
        let st = STATUS.get();
        json!({
            "enabled": st.map(|s| s.enabled).unwrap_or(false),
            "client": st.map(|s| s.client).unwrap_or("noop"),
            "endpoint": st.map(|s| s.endpoint.clone()).unwrap_or_default(),
            "mtls": st.map(|s| s.mtls).unwrap_or(false),
            "plaintext": st.map(|s| s.plaintext).unwrap_or(false),
            "timeout_ms": st
                .map(|s| s.timeout_ms)
                .unwrap_or(lattice_plugins::limits::SIDECAR_TIMEOUT_MS),
            "circuit_break_secs": st
                .map(|s| s.circuit_break_secs)
                .unwrap_or(lattice_plugins::limits::CIRCUIT_BREAK_SECS),
            "error": st.and_then(|s| s.error.clone()),
        })
    }
}

#[cfg(feature = "wasm-host")]
mod host_impl {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex, OnceLock, RwLock};
    use std::time::{Duration, Instant};

    use lattice_plugins::manifest::{PluginLimits, PluginManifest};
    use lattice_plugins::wasm::{
        CallRecord, CircuitEvent, DirRegistry, ErrorKind, HostConfig, HostHooks, LoadRejection,
        PluginInfo, PluginPackage, TrustedKeys, WasmError, WasmHost, MIB,
    };
    use serde_json::{json, Value};

    use crate::observe::Metrics;
    use crate::state::AppState;
    use crate::store::pg;

    use super::{
        http_status_for_kind, reason_for_kind, InvokeFailure, InvokeOutcome, ReloadFailure,
        ReloadOutcome, ReloadSource,
    };

    /// In-process singleton (one host per node process; not stored in `AppState`, to avoid changing state.rs).
    static RUNTIME: OnceLock<Arc<WasmRuntime>> = OnceLock::new();
    /// Init failure reason (shown in admin status; failures only warn and the node stays ready).
    static INIT_ERROR: OnceLock<String> = OnceLock::new();
    /// Reason for being disabled (`wasm_dir` empty and `from_db=false`, or the feature is off which the stub handles).
    static DISABLED_REASON: OnceLock<String> = OnceLock::new();

    /// PG source runtime status (admin diagnostics; **low cardinality**, without wasm bytes/signature/key material).
    #[derive(Debug, Clone)]
    struct PgSourceStatus {
        enabled: bool,
        /// `disabled` / `pending` / `loading` / `done` / `error` / `unavailable`.
        state: &'static str,
        query_ms: u64,
        /// Candidate rows returned after SQL filtering (active+canary, prefiltered by size).
        rows: usize,
        loaded: usize,
        rejected: usize,
        /// Canary-ignored + same-ns lower-version ignored.
        skipped: usize,
        canary_ignored: usize,
        /// Packages of canary versions actually registered into the canary host (0 when disabled).
        canary_loaded: usize,
        canary_rejected: usize,
        /// Directory-priority conflict count (included in rejected).
        conflicts: usize,
        oversized: usize,
        error: Option<String>,
        /// Details (at most 32 each; only ns/version/size, no content).
        canary_ignored_items: Vec<Value>,
        canary_loaded_items: Vec<Value>,
        canary_rejected_items: Vec<Value>,
        conflict_items: Vec<Value>,
        oversized_items: Vec<Value>,
    }

    impl Default for PgSourceStatus {
        fn default() -> Self {
            Self {
                enabled: false,
                state: "disabled",
                query_ms: 0,
                rows: 0,
                loaded: 0,
                rejected: 0,
                skipped: 0,
                canary_ignored: 0,
                canary_loaded: 0,
                canary_rejected: 0,
                conflicts: 0,
                oversized: 0,
                error: None,
                canary_ignored_items: Vec::new(),
                canary_loaded_items: Vec::new(),
                canary_rejected_items: Vec::new(),
                conflict_items: Vec::new(),
                oversized_items: Vec::new(),
            }
        }
    }

    impl PgSourceStatus {
        fn to_json(&self) -> Value {
            json!({
                "enabled": self.enabled,
                "state": self.state,
                "query_ms": self.query_ms,
                "rows": self.rows,
                "loaded": self.loaded,
                "rejected": self.rejected,
                "skipped": self.skipped,
                "canary_ignored": self.canary_ignored,
                "canary_loaded": self.canary_loaded,
                "canary_rejected": self.canary_rejected,
                "conflicts": self.conflicts,
                "oversized": self.oversized,
                "error": self.error,
                "canary_ignored_items": self.canary_ignored_items,
                "canary_loaded_items": self.canary_loaded_items,
                "canary_rejected_items": self.canary_rejected_items,
                "conflict_items": self.conflict_items,
                "oversized_items": self.oversized_items,
            })
        }
    }

    /// S3 object-storage source diagnostic status (**low cardinality**, without payload/signature/public key).
    #[derive(Debug, Clone)]
    struct S3SourceStatus {
        enabled: bool,
        /// `disabled` / `pending` / `loading` / `done` / `error` / `unavailable`.
        state: &'static str,
        bucket: String,
        prefix: String,
        index_present: bool,
        index_bytes: usize,
        /// Objects read successfully (manifest+wasm+signature).
        objects: usize,
        loaded: usize,
        rejected: usize,
        /// Packages skipped due to a same-ns conflict with the directory/PG.
        conflicts: usize,
        elapsed_ms: u64,
        error: Option<String>,
        rejected_items: Vec<Value>,
        conflict_items: Vec<Value>,
    }

    impl Default for S3SourceStatus {
        fn default() -> Self {
            Self {
                enabled: false,
                state: "disabled",
                bucket: String::new(),
                prefix: String::new(),
                index_present: false,
                index_bytes: 0,
                objects: 0,
                loaded: 0,
                rejected: 0,
                conflicts: 0,
                elapsed_ms: 0,
                error: None,
                rejected_items: Vec::new(),
                conflict_items: Vec::new(),
            }
        }
    }

    impl S3SourceStatus {
        fn to_json(&self) -> Value {
            json!({
                "enabled": self.enabled,
                "state": self.state,
                "bucket": self.bucket,
                "prefix": self.prefix,
                "index_present": self.index_present,
                "index_bytes": self.index_bytes,
                "objects": self.objects,
                "loaded": self.loaded,
                "rejected": self.rejected,
                "conflicts": self.conflicts,
                "elapsed_ms": self.elapsed_ms,
                "error": self.error,
                "rejected_items": self.rejected_items,
                "conflict_items": self.conflict_items,
            })
        }
    }

    /// Package source (for internal cache/fallback attribution only).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum PackageSource {
        Dir,
        Pg,
        S3,
    }

    impl PackageSource {
        fn as_str(self) -> &'static str {
            match self {
                Self::Dir => "dir",
                Self::Pg => "pg",
                Self::S3 => "s3",
            }
        }
    }

    /// Result of one canary routing decision.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HostRoute {
        Stable,
        Canary,
    }

    impl HostRoute {
        fn as_str(self) -> &'static str {
            match self {
                Self::Stable => "stable",
                Self::Canary => "canary",
            }
        }
    }

    /// Runtime snapshot state (the read side of hot reload's "scratch table → one swap").
    ///
    /// Together with [`WasmRuntime::host`] it forms an **immutable snapshot**: reload builds the new host + new
    /// `RuntimeState` on the stack, then writes each lock once on success (host first, state after; no reader can observe a half state
    /// in between, because invoke reads only the host and the admin plane reads only the state counters).
    #[derive(Debug, Clone)]
    struct RuntimeState {
        /// Snapshot generation: initial startup snapshot = 1, +1 per **successful** hot reload (failures do not increment; monotonic).
        generation: u64,
        /// Time of the most recent successful hot reload (RFC3339 UTC); startup loading is not a hot reload → `None`.
        last_reload_at: Option<String>,
        /// Summary of the most recent successful hot reload (low-cardinality JSON; no payload/keys).
        last_reload: Option<Value>,
        /// Time of the most recent hot-reload **attempt** (rate-limit window; counted on success and failure).
        last_attempt: Option<Instant>,
        /// Directory-source namespaces registered (including rejected ones): the directory wins on a PG same-ns conflict.
        dir_names: BTreeSet<String>,
        /// Packages **actually in effect** from the directory source in the current snapshot (carried over for non-refreshed sources + rejected-candidate fallbacks).
        dir_packages: Vec<PluginPackage>,
        /// Packages **actually in effect** from the PG source in the current snapshot (same as above).
        pg_packages: Vec<PluginPackage>,
        /// Directory-source rejection details in the current snapshot (admin `wasm.rejected`; no payload).
        dir_rejected: Vec<LoadRejection>,
        /// PG-source rejection details in the current snapshot.
        pg_rejected: Vec<LoadRejection>,
        /// PG source diagnostic status.
        pg: PgSourceStatus,
        /// S3-source packages actually in effect / rejection details / diagnostic status in the current snapshot.
        s3_packages: Vec<PluginPackage>,
        s3_rejected: Vec<LoadRejection>,
        s3: S3SourceStatus,
        /// Canary: packages actually in effect in the canary host + rejection details + route counters.
        canary_packages: Vec<PluginPackage>,
        canary_rejected: Vec<LoadRejection>,
        canary_requests: u64,
        canary_routed: u64,
        stable_routed: u64,
        canary_fallbacks: u64,
    }

    impl Default for RuntimeState {
        fn default() -> Self {
            Self {
                generation: 1,
                last_reload_at: None,
                last_reload: None,
                last_attempt: None,
                dir_names: BTreeSet::new(),
                dir_packages: Vec::new(),
                pg_packages: Vec::new(),
                dir_rejected: Vec::new(),
                pg_rejected: Vec::new(),
                pg: PgSourceStatus::default(),
                s3_packages: Vec::new(),
                s3_rejected: Vec::new(),
                s3: S3SourceStatus::default(),
                canary_packages: Vec::new(),
                canary_rejected: Vec::new(),
                canary_requests: 0,
                canary_routed: 0,
                stable_routed: 0,
                canary_fallbacks: 0,
            }
        }
    }

    /// Static canary routing config (read from env at startup; the runtime ratio is read live from `AppState.plugins`).
    #[derive(Debug, Clone, Default)]
    struct CanaryConfig {
        /// Whether canary routing is enabled (`LATTICE_PLUGIN_CANARY_ENABLED`).
        enabled: bool,
        /// Routing salt (`LATTICE_PLUGIN_CANARY_SALT`, empty by default; multiple clusters can use it to offset bucketing of the same request).
        salt: String,
    }

    pub(super) struct WasmRuntime {
        /// Runtime snapshot: hot reload **replaces it atomically** (in-flight invokes finish on the old `Arc`, uninterrupted).
        /// This is the **stable** (active version) host.
        host: RwLock<Arc<WasmHost>>,
        /// Canary host (separate Store pool/circuit breaker/metrics; always an empty host when disabled).
        canary_host: RwLock<Arc<WasmHost>>,
        /// Static canary routing config (enabled/salt).
        canary: CanaryConfig,
        /// Weak reference to node state (invoke reads the **live** `canary_ratio` from `AppState.plugins`;
        /// admin publish/canary actions refresh that snapshot in place, so the three tiers can switch without a restart).
        state_ref: std::sync::Weak<AppState>,
        /// Config used to rebuild the host (same as startup: trusted_keys/limits); hot reload clones it and recompiles Modules.
        host_config: HostConfig,
        metrics: Arc<Metrics>,
        /// `[plugins] wasm_dir`; empty = load only from the PG registry.
        wasm_dir: String,
        require_verified_signature: bool,
        trusted_key_ids: Vec<String>,
        /// Whether the PG `plugins` table source is enabled (`[plugins] from_db`).
        from_db: bool,
        /// S3 object-storage registry config (`None` = not enabled).
        s3: Option<super::registry_s3::RegistryS3Config>,
        /// Per-package wasm cap for the PG source (SQL prefilter; prevents OOM on huge objects).
        max_wasm_bytes: u64,
        /// Snapshot state (generation/last reload/caches/source counts/rejection details).
        state: Mutex<RuntimeState>,
        /// Hot-reload serialization: only one at a time (`try_lock` failure → 409, no queueing).
        reload_gate: tokio::sync::Mutex<()>,
    }

    impl WasmRuntime {
        /// Take the current snapshot (clone the `Arc` under a short read lock; later execution is unaffected by a swap).
        fn host(&self) -> Arc<WasmHost> {
            // Lock poisoning (a lock-holding thread panicked) must not paralyze the node: recover the inner value and continue (the registry is only cloned read-only).
            self.host
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        fn canary_host(&self) -> Arc<WasmHost> {
            self.canary_host
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        fn state(&self) -> std::sync::MutexGuard<'_, RuntimeState> {
            self.state.lock().unwrap_or_else(|e| e.into_inner())
        }

        /// Read the canary_ratio mapping from PG rows: `(ns short name, version) -> ratio`.
        ///
        /// The data source is all `plugins` rows (`pg::plugins_all`, without wasm bytes). At startup
        /// `load_pg_plugins` stores one copy in `AppState.plugins`; admin publish/canary actions also refresh that
        /// in-memory snapshot, so the invoke side only needs a weak reference for the **live** ratio.
        fn live_canary_targets(&self, ns: &str) -> Option<(u32, u8)> {
            let st = self.state_ref.upgrade()?;
            let entries = st.plugins.read().ok()?;
            let mut best: Option<(u32, u8)> = None;
            for entry in entries.iter() {
                if short_ns(&entry.ns) != ns {
                    continue;
                }
                if entry.status != lattice_plugins::registry::PluginStatus::Canary {
                    continue;
                }
                let ratio = entry.canary_ratio.min(100) as u8;
                if ratio == 0 {
                    continue;
                }
                let version = entry.version;
                match best {
                    Some((cur, cur_ratio)) if cur >= version => {
                        let _ = cur_ratio;
                    }
                    _ => best = Some((version, ratio)),
                }
            }
            best
        }

        /// Canary bucketing input: compress "salt + ns + entry + request content digest" into a stable key, then hand it to
        /// `lattice_plugins::registry::in_canary` (canary decisions are **centralized in that one function**, consistent with
        /// design PL-10 §6's "stable hash, single decision implementation"; the same request yields the same result on any node).
        fn canary_key(&self, ns: &str, entry: &str, input: &[u8]) -> String {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(self.canary.salt.as_bytes());
            h.update(b"\0");
            h.update(ns.as_bytes());
            h.update(b"\0");
            h.update(entry.as_bytes());
            h.update(b"\0");
            h.update(input);
            let digest = h.finalize();
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            format!("{ns}:{entry}:{hex}")
        }

        /// Routing decision for this invoke (also writes the counters back to state; callers need no extra accounting).
        ///
        /// Semantics (PL-10 canary tiers):
        /// - canary off / no canary row / ratio=0 → stable;
        /// - ratio=100 → canary; 0<ratio<100 → bucket via `in_canary(key, ratio)`;
        /// - the canary host lacks that ns (package rejected/not loaded) → fall back to stable (counted in `canary_fallbacks`).
        fn decide_route(&self, ns: &str, entry: &str, input: &[u8]) -> HostRoute {
            if !self.canary.enabled {
                return HostRoute::Stable;
            }
            let Some((_version, ratio)) = self.live_canary_targets(ns) else {
                return HostRoute::Stable;
            };
            let key = self.canary_key(ns, entry, input);
            if !lattice_plugins::registry::in_canary(&key, u32::from(ratio)) {
                return HostRoute::Stable;
            }
            // The canary target must actually be loaded and verified, otherwise fall back to stable (never turn the ratio into 5xx).
            let canary = self.canary_host();
            let usable = canary
                .info(ns)
                .map(|info| info.trusted)
                .unwrap_or(false);
            if !usable {
                let mut state = self.state();
                state.canary_fallbacks = state.canary_fallbacks.saturating_add(1);
                tracing::warn!(
                    plugin = %ns,
                    ratio,
                    "[plugins] canary route requested but canary package is unavailable; falling back to stable"
                );
                return HostRoute::Stable;
            }
            HostRoute::Canary
        }
    }

    /// Max items kept in detail lists (prevents unbounded admin status growth).
    const ITEMS_CAP: usize = 32;

    /// Registry key: `ns` with the optional `@version` suffix removed (same semantics as `PluginManifest::short_name`).
    fn short_ns(ns: &str) -> &str {
        ns.split_once('@').map(|(base, _)| base).unwrap_or(ns)
    }

    /// **Version selection** result for one PG candidate row set (pure function for unit tests; touches no DB/host).
    #[derive(Debug, Default)]
    pub(super) struct PgSelection {
        /// Index of the selected highest active version row per ns.
        pub selected: Vec<usize>,
        /// Index of the selected highest canary version row per ns when canary is enabled.
        pub selected_canary: Vec<usize>,
        /// Ignored canary rows (`(ns, version)`; canary off or ratio=0, never loaded silently).
        pub canary_ignored: Vec<(String, i32)>,
        /// Ignored lower/duplicate version rows of the same ns (active).
        pub lower_versions: Vec<(String, i32)>,
        /// Ignored lower-version canary rows of the same ns.
        pub canary_lower_versions: Vec<(String, i32)>,
    }

    /// Pick the highest active version per ns; a canary row is selected as the highest canary version when canary is enabled and
    /// `canary_ratio>0`, otherwise it is ignored and recorded (idempotent, deterministic).
    pub(super) fn select_pg_candidates(
        rows: &[pg::PluginWasmRow],
        canary_ratios: &BTreeMap<(String, i32), u8>,
        canary_enabled: bool,
    ) -> PgSelection {
        // BTreeMap: the selected ns order is deterministic (reproducible logs/state).
        let mut best: BTreeMap<String, usize> = BTreeMap::new();
        let mut best_canary: BTreeMap<String, usize> = BTreeMap::new();
        let mut result = PgSelection::default();
        for (idx, row) in rows.iter().enumerate() {
            let name = short_ns(&row.ns).to_string();
            if row.status == "canary" {
                if !canary_enabled {
                    // Canary off: ignore and record the canary row (same as the old behavior, never loaded silently).
                    result.canary_ignored.push((name, row.version));
                    continue;
                }
                let ratio = canary_ratios
                    .get(&(name.clone(), row.version))
                    .copied()
                    .unwrap_or(0);
                if ratio == 0 {
                    // ratio=0 = canary disabled for this row: do not load it (and do not promote it to stable).
                    result.canary_ignored.push((name, row.version));
                    continue;
                }
                match best_canary.get(&name).copied() {
                    None => {
                        best_canary.insert(name, idx);
                    }
                    Some(cur) if rows[cur].version >= row.version => {
                        result.canary_lower_versions.push((name, row.version));
                    }
                    Some(cur) => {
                        result
                            .canary_lower_versions
                            .push((name.clone(), rows[cur].version));
                        best_canary.insert(name, idx);
                    }
                }
                continue;
            }
            match best.get(&name).copied() {
                None => {
                    best.insert(name, idx);
                }
                Some(cur) if rows[cur].version >= row.version => {
                    result
                        .lower_versions
                        .push((name, row.version));
                }
                Some(cur) => {
                    result
                        .lower_versions
                        .push((name.clone(), rows[cur].version));
                    best.insert(name, idx);
                }
            }
        }
        result.selected.extend(best.into_values());
        result.selected_canary.extend(best_canary.into_values());
        result
    }

    // ------------------------------------------------------------------
    // Environment-variable config (`config.rs` is being changed by a concurrent task; this task does not modify it)
    // ------------------------------------------------------------------

    /// Canary routing switch: `LATTICE_PLUGIN_CANARY_ENABLED` (truthy: 1/true/yes/on).
    const ENV_CANARY_ENABLED: &str = "LATTICE_PLUGIN_CANARY_ENABLED";
    /// Canary routing salt (optional; empty by default; multiple clusters can use it to offset bucketing).
    const ENV_CANARY_SALT: &str = "LATTICE_PLUGIN_CANARY_SALT";
    /// Store pool size override (default = the host default of 8 when `[plugins]` has no such field).
    const ENV_POOL_SIZE: &str = "LATTICE_PLUGIN_POOL_SIZE";
    /// Prewarm slot count override (0 = prewarm the whole pool).
    const ENV_POOL_PREWARM: &str = "LATTICE_PLUGIN_POOL_PREWARM";
    /// Per-Store instance rotation cap override.
    const ENV_MAX_INSTANCES_PER_STORE: &str = "LATTICE_PLUGIN_MAX_INSTANCES_PER_STORE";
    /// Pool-full queue timeout (milliseconds) override.
    const ENV_QUEUE_TIMEOUT_MS: &str = "LATTICE_PLUGIN_QUEUE_TIMEOUT_MS";

    fn env_truthy(name: &str) -> bool {
        matches!(
            std::env::var(name).unwrap_or_default().trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    }

    fn env_usize(name: &str) -> Option<usize> {
        std::env::var(name)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
    }

    fn env_u64(name: &str) -> Option<u64> {
        std::env::var(name)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
    }

    fn canary_config_from_env() -> CanaryConfig {
        CanaryConfig {
            enabled: env_truthy(ENV_CANARY_ENABLED),
            salt: std::env::var(ENV_CANARY_SALT).unwrap_or_default(),
        }
    }


    /// Assemble a pre-verification plugin package from a PG row (pure function for unit tests).
    ///
    /// Manifest construction (`plugins.config` jsonb):
    /// - a complete `config.manifest` JSON is **preferred**; its `ns`/`version` must match the row (cross-package guard),
    ///   and an embedded `signature` field is ignored (the `plugins.signature` bytea is authoritative);
    /// - otherwise assemble from row fields + `config.entry` (empty default = `process` at the DB layer)/`config.deps`/
    ///   `config.limits` (absent 0 = host default caps)/`config.signing_key_id`;
    /// - an empty `plugins.signature` bytea = unsigned (fail-closed: rejected when require=true);
    /// - no declared `signing_key_id` and exactly one trusted key on the host → use that key (unambiguous).
    pub(super) fn package_from_pg_row(
        row: &pg::PluginWasmRow,
        trusted_keys: &TrustedKeys,
    ) -> Result<PluginPackage, String> {        let cfg = match &row.config {
            Value::Object(map) => map,
            _ => return Err("plugins.config must be a JSON object".to_string()),
        };
        let mut manifest = if let Some(full) = cfg.get("manifest") {
            let mut m: PluginManifest = serde_json::from_value(full.clone())
                .map_err(|e| format!("config.manifest is not a valid plugin manifest: {e}"))?;
            if m.short_name() != short_ns(&row.ns) {
                return Err(format!(
                    "config.manifest.ns `{}` does not match plugins.ns `{}`",
                    m.short_name(),
                    row.ns
                ));
            }
            if i64::from(m.version) != i64::from(row.version) {
                return Err(format!(
                    "config.manifest.version {} does not match plugins.version {}",
                    m.version, row.version
                ));
            }
            m.signature = None;
            m
        } else {
            let version = u32::try_from(row.version)
                .ok()
                .filter(|v| *v > 0)
                .ok_or_else(|| format!("plugins.version {} must be > 0", row.version))?;
            let entry = match cfg.get("entry") {
                Some(Value::String(s)) => s.clone(),
                None | Some(Value::Null) => String::new(),
                Some(_) => return Err("plugins.config.entry must be a string".to_string()),
            };
            let deps = match cfg.get("deps") {
                Some(v) => serde_json::from_value::<Vec<String>>(v.clone())
                    .map_err(|e| format!("plugins.config.deps must be a string array: {e}"))?,
                None => Vec::new(),
            };
            let limits = match cfg.get("limits") {
                Some(v) => serde_json::from_value::<PluginLimits>(v.clone())
                    .map_err(|e| format!("plugins.config.limits is invalid: {e}"))?,
                // 0 = use the host default caps (consistent with manifest semantics, see `effective_limits`).
                None => PluginLimits {
                    memory_mb: 0,
                    fuel: 0,
                    timeout_ms: 0,
                },
            };
            PluginManifest {
                ns: row.ns.clone(),
                version,
                entry,
                deps,
                limits,
                signature: None,
                signing_key_id: None,
            }
        };
        if manifest
            .signing_key_id
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            if let Some(explicit) = cfg.get("signing_key_id").and_then(Value::as_str) {
                if !explicit.trim().is_empty() {
                    manifest.signing_key_id = Some(explicit.trim().to_string());
                }
            }
        }
        if manifest.signing_key_id.is_none() && trusted_keys.len() == 1 {
            manifest.signing_key_id = trusted_keys.ids().first().map(|s| (*s).to_string());
        }
        let package = PluginPackage::from_manifest(manifest, row.wasm.clone());
        // The `plugins.signature` bytea is authoritative: empty = unsigned (Missing → fail-closed reject).
        Ok(if row.signature.is_empty() {
            package
        } else {
            package.with_signature(row.signature.clone())
        })
    }

    fn push_capped(items: &mut Vec<Value>, item: Value) {
        if items.len() < ITEMS_CAP {
            items.push(item);
        }
    }

    fn truncate_reason(s: &str, max: usize) -> String {
        if s.chars().count() <= max {
            s.to_string()
        } else {
            let cut: String = s.chars().take(max).collect();
            format!("{cut}…")
        }
    }

    /// Turn host call events into Prometheus metrics (never prints payloads).
    struct MetricsHooks {
        metrics: Arc<Metrics>,
        // Circuit-breaker open/recover events exist inside the host; the metric counts only "open" occurrences.
    }

    impl HostHooks for MetricsHooks {
        fn on_call(&self, record: &CallRecord) {
            let outcome = record
                .outcome
                .map(reason_for_kind)
                .unwrap_or("ok");
            self.metrics
                .plugin_wasm_invocations_total
                .with_label_values(&[record.plugin.as_str(), outcome])
                .inc();
            self.metrics
                .plugin_wasm_invoke_duration
                .with_label_values(&[record.plugin.as_str()])
                .observe(record.elapsed_ms as f64 / 1000.0);
        }

        fn on_circuit(&self, event: &CircuitEvent) {
            if event.open {
                self.metrics
                    .plugin_wasm_circuit_trips_total
                    .with_label_values(&[event.plugin.as_str()])
                    .inc();
            }
        }
    }

    /// Read `[plugins]` config → build the trusted public key table (file failure is fail-closed: warn only, no unverified packages registered).
    fn load_trusted_keys(st: &Arc<AppState>) -> TrustedKeys {
        let cfg = &st.cfg.plugins;
        let mut keys = match TrustedKeys::from_b64_map(cfg.trusted_keys.clone()) {
            Ok(keys) => keys,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "invalid [plugins] trusted_keys; wasm plugins will fail verification (fail-closed)"
                );
                TrustedKeys::new()
            }
        };
        let file = cfg.trusted_keys_file.trim();
        if !file.is_empty() {
            match std::fs::read(file) {
                Ok(raw) => match keys.merge_from_json(&raw) {
                    Ok(added) => tracing::info!(
                        file = %file,
                        added,
                        total = keys.len(),
                        "trusted_keys_file merged"
                    ),
                    Err(e) => tracing::error!(
                        file = %file,
                        error = %e,
                        "trusted_keys_file invalid; keeping only [plugins] trusted_keys (fail-closed)"
                    ),
                },
                Err(e) => tracing::error!(
                    file = %file,
                    error = %e,
                    "trusted_keys_file unreadable; keeping only [plugins] trusted_keys (fail-closed)"
                ),
            }
        }
        if !keys.is_empty() {
            // Print only the id list (public key bytes are not secret, but minimal exposure means listing ids only).
            tracing::info!(key_ids = ?keys.ids(), "wasm plugin trusted keys loaded");
        }
        keys
    }

    fn host_config(st: &Arc<AppState>, trusted_keys: TrustedKeys) -> HostConfig {
        let cfg = &st.cfg.plugins;
        let memory_mb = if cfg.memory_mb == 0 {
            lattice_plugins::limits::MEMORY_MB
        } else {
            cfg.memory_mb
        };
        let fuel = if cfg.instructions == 0 {
            lattice_plugins::limits::INSTRUCTIONS
        } else {
            cfg.instructions
        };
        let timeout_ms = if cfg.timeout_ms == 0 {
            lattice_plugins::limits::SIDECAR_TIMEOUT_MS
        } else {
            cfg.timeout_ms
        };
        // Pooling parameters come from env vars (`config.rs` is outside this task's change scope; E2E/operations need no TOML change).
        // Zero-knowledge runtime probe (E25): with `mode=zero-knowledge`, content plugins (`convert:*` etc.)
        // fail closed at the host registration entry, so no payload-parsing plugin exists on the node that could be invoked;
        // `inspectable` is audit/conversion mode and stays allowed.
        let allow_content_plugins =
            st.mode() == lattice_core::Mode::Inspectable;
        let mut host = HostConfig {
            memory_bytes: memory_mb.saturating_mul(MIB),
            fuel,
            call_timeout: Duration::from_millis(timeout_ms.max(1)),
            trusted_keys,
            require_verified_signature: cfg.require_verified_signature,
            allow_content_plugins,
            ..HostConfig::default()
        };
        if let Some(size) = env_usize(ENV_POOL_SIZE) {
            host.pool_size = size;
        }
        if let Some(prewarm) = env_usize(ENV_POOL_PREWARM) {
            host.pool_prewarm = prewarm;
        }
        if let Some(max_instances) = env_usize(ENV_MAX_INSTANCES_PER_STORE) {
            host.max_instances_per_store = max_instances;
        }
        if let Some(queue_ms) = env_u64(ENV_QUEUE_TIMEOUT_MS) {
            host.queue_timeout = Duration::from_millis(queue_ms);
        }
        host
    }

    /// Called at node startup (`node::build`, before ready). Any failure only warns/records and does not block the node.
    ///
    /// - The directory source (`wasm_dir`) is scanned and registered **synchronously**, with unchanged semantics;
    /// - the PG registry (`from_db=true`) is read and registered **asynchronously** by a background job after ready: query/verify/bad-package
    ///   failures all only WARN and do not block ready (a node process initializes the host only once);
    /// - the S3 registry (enabled by `LATTICE_PLUGIN_S3_PREFIX`) is likewise read by a background job (network IO does not block ready);
    /// - the initial snapshot has `generation = 1` (hot reloads start at 2; failures do not increment).
    pub fn init(st: &Arc<AppState>) {
        // Register the sidecar client first (off by default; config errors only WARN and fall back to Noop, independent of wasm).
        super::sidecar::init(st.as_ref());
        let cfg = &st.cfg.plugins;
        let dir = cfg.wasm_dir.trim().to_string();
        let from_db = cfg.from_db;
        let s3 = super::registry_s3::config_from_env(&st.cfg.s3);
        if dir.is_empty() && !from_db && s3.is_none() {
            let reason = "[plugins] wasm_dir is empty, from_db=false and no S3 plugin registry \
                          (LATTICE_PLUGIN_S3_PREFIX unset); wasm plugin host disabled"
                .to_string();
            tracing::info!(%reason);
            let _ = DISABLED_REASON.set(reason);
            return;
        }
        let canary = canary_config_from_env();
        if !canary.enabled {
            tracing::info!(
                "[plugins] canary routing disabled (set LATTICE_PLUGIN_CANARY_ENABLED=true to \
                 route PG canary rows by hash); canary rows stay ignored as before"
            );
        }
        if let Some(s3cfg) = &s3 {
            tracing::info!(
                bucket = %s3cfg.bucket,
                prefix = %s3cfg.prefix,
                "[plugins] S3 plugin registry enabled (read-only; merged as the lowest-priority source)"
            );
        }
        let trusted_keys = load_trusted_keys(st);
        if trusted_keys.is_empty() && cfg.require_verified_signature {
            tracing::warn!(
                "require_verified_signature=true but no trusted_keys configured: \
                 every wasm plugin will be rejected (fail-closed; configure [plugins] trusted_keys)"
            );
        }
        let host_cfg = host_config(st, trusted_keys.clone());
        let host = match WasmHost::with_hooks(
            host_cfg.clone(),
            Arc::new(MetricsHooks { metrics: st.metrics.clone() }),
        ) {
            Ok(host) => Arc::new(host),
            Err(e) => {
                let msg = format!("wasm host init failed: {e}");
                tracing::error!(error = %e, "wasm host init failed; wasm plugins disabled");
                let _ = INIT_ERROR.set(msg);
                return;
            }
        };
        // Canary host: separate Store pool/circuit breaker/metrics; equivalent to an empty host when no packages are registered.
        let canary_host = match WasmHost::with_hooks(
            host_cfg.clone(),
            Arc::new(MetricsHooks { metrics: st.metrics.clone() }),
        ) {
            Ok(host) => Arc::new(host),
            Err(e) => {
                let msg = format!("canary wasm host init failed: {e}");
                tracing::error!(error = %e, "canary wasm host init failed; canary routing disabled");
                let _ = INIT_ERROR.set(msg);
                return;
            }
        };

        // Initial snapshot state (generation=1; PG/S3 sources pending/disabled consistent with startup semantics).
        let mut state = RuntimeState {
            pg: PgSourceStatus {
                enabled: from_db,
                state: if from_db { "pending" } else { "disabled" },
                ..PgSourceStatus::default()
            },
            s3: S3SourceStatus {
                enabled: s3.is_some(),
                state: if s3.is_some() { "pending" } else { "disabled" },
                bucket: s3.as_ref().map(|c| c.bucket.clone()).unwrap_or_default(),
                prefix: s3.as_ref().map(|c| c.prefix.clone()).unwrap_or_default(),
                ..S3SourceStatus::default()
            },
            ..RuntimeState::default()
        };
        if dir.is_empty() {
            tracing::info!(
                "[plugins] wasm_dir is empty; only the PG plugin registry (from_db=true) is used"
            );
        } else {
            // Scan the directory + register each package (bad packages only warn + metrics, without affecting other packages or node ready).
            let scan = DirRegistry::new(&dir).scan();
            for (plugin, reason) in scan.rejected {
                tracing::warn!(plugin = %plugin, reason = %reason, "wasm plugin package rejected (scan)");
                st.metrics
                    .plugin_wasm_rejected_total
                    .with_label_values(&["manifest"])
                    .inc();
                st.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&["dir", "rejected"])
                    .inc();
                state.dir_rejected.push(LoadRejection {
                    plugin,
                    kind: ErrorKind::Manifest.as_str().to_string(),
                    reason,
                });
            }
            let packages = scan.packages;
            let known: BTreeSet<String> =
                packages.iter().map(|p| p.short_name().to_string()).collect();
            state.dir_names = known.clone();
            for package in packages {
                let name = package.short_name().to_string();
                // Count the verification result first (even if the package is later rejected for missing deps/compile failure, verification status must be visible).
                let status = package.signature_status(&trusted_keys);
                st.metrics
                    .plugin_wasm_signature_total
                    .with_label_values(&[status.check.as_str()])
                    .inc();
                let missing: Vec<String> = package
                    .manifest
                    .deps
                    .iter()
                    .filter(|d| !known.contains(d.as_str()))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    let reason = format!("missing dependency: {}", missing.join(", "));
                    tracing::warn!(plugin = %name, reason = %reason, "wasm plugin rejected");
                    st.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&[ErrorKind::MissingExport.as_str()])
                        .inc();
                    st.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["dir", "rejected"])
                        .inc();
                    state.dir_rejected.push(LoadRejection {
                        plugin: name,
                        kind: ErrorKind::MissingExport.as_str().to_string(),
                        reason,
                    });
                    continue;
                }
                match host.register(package.clone()) {
                    Ok(info) => {
                        tracing::info!(
                            plugin = %info.short_name,
                            version = info.version,
                            entry = %info.entry,
                            source = "dir",
                            signature = info.signature.as_str(),
                            signature_detail = %info.signature_detail,
                            signing_key_id = info.signing_key_id.as_deref().unwrap_or(""),
                            trusted = info.trusted,
                            wasm_bytes = info.wasm_bytes,
                            "wasm plugin registered"
                        );
                        st.metrics
                            .plugin_wasm_source_total
                            .with_label_values(&["dir", "loaded"])
                            .inc();
                        state.dir_packages.push(package);
                    }
                    Err(e) => {
                        tracing::warn!(
                            plugin = e.plugin().unwrap_or(&name),
                            kind = e.kind().as_str(),
                            reason = %e,
                            "wasm plugin rejected"
                        );
                        st.metrics
                            .plugin_wasm_rejected_total
                            .with_label_values(&[e.kind().as_str()])
                            .inc();
                        st.metrics
                            .plugin_wasm_source_total
                            .with_label_values(&["dir", "rejected"])
                            .inc();
                        state.dir_rejected.push(LoadRejection {
                            plugin: e.plugin().unwrap_or(&name).to_string(),
                            kind: e.kind().as_str().to_string(),
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }
        let dir_loaded = state.dir_packages.len();
        let dir_rejected = state.dir_rejected.len();
        let verified = host.plugins().iter().filter(|p| p.trusted).count();
        st.metrics.plugin_wasm_loaded.set(dir_loaded as i64);
        st.metrics.plugin_wasm_verified.set(verified as i64);
        tracing::info!(
            wasm_dir = %dir,
            from_db,
            loaded = dir_loaded,
            verified,
            rejected = dir_rejected,
            trusted_keys = trusted_keys.len(),
            require_verified_signature = cfg.require_verified_signature,
            max_wasm_bytes = cfg.effective_max_wasm_bytes(),
            generation = state.generation,
            "wasm plugin host ready (dir registered synchronously; pg loads asynchronously)"
        );

        let runtime = Arc::new(WasmRuntime {
            host: RwLock::new(host),
            canary_host: RwLock::new(canary_host),
            canary,
            state_ref: Arc::downgrade(st),
            host_config: host_cfg,
            metrics: st.metrics.clone(),
            wasm_dir: dir,
            require_verified_signature: cfg.require_verified_signature,
            trusted_key_ids: trusted_keys.ids().iter().map(|s| s.to_string()).collect(),
            from_db,
            s3,
            max_wasm_bytes: cfg.effective_max_wasm_bytes(),
            state: Mutex::new(state),
            reload_gate: tokio::sync::Mutex::new(()),
        });
        if RUNTIME.set(runtime.clone()).is_err() {
            tracing::warn!("wasm host already initialized; second init ignored");
            return;
        }
        if from_db || runtime.s3.is_some() {
            // Asynchronous: PG/S3 query/verify/register must not block ready; failures only WARN + admin status.
            spawn_startup_load(runtime, st.clone());
        }
    }

    /// Spawn a background job to load startup sources (PG + S3; does not block ready; query/verify/network failures only WARN).
    fn spawn_startup_load(rt: Arc<WasmRuntime>, st: Arc<AppState>) {
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => {
                tracing::warn!(
                    "[plugins] no tokio runtime at wasm init; PG/S3 plugin registries skipped \
                     (directory plugins unaffected, node ready unaffected)"
                );
                let mut state = rt.state();
                if rt.from_db {
                    state.pg.state = "unavailable";
                    state.pg.error = Some("no tokio runtime available at wasm init".to_string());
                }
                if rt.s3.is_some() {
                    state.s3.state = "unavailable";
                    state.s3.error = Some("no tokio runtime available at wasm init".to_string());
                }
                return;
            }
        };
        handle.spawn(async move {
            if rt.from_db {
                load_pg_plugins(rt.clone(), st.clone()).await;
            }
            if rt.s3.is_some() {
                load_s3_plugins(rt, st).await;
            }
        });
    }

    /// Startup read of the PG `plugins` table → version selection → verify/register; **any failure only WARNs**, no panic, no blocking the node.
    ///
    /// At startup packages are registered directly into the initial host (no atomic swap; only hot reload uses [`reload`]'s new snapshot + atomic replace).
    async fn load_pg_plugins(rt: Arc<WasmRuntime>, st: Arc<AppState>) {
        rt.state().pg.state = "loading";
        let max_wasm_bytes = rt.max_wasm_bytes;
        let max_i64 = max_wasm_bytes.min(i64::MAX as u64) as i64;
        let started = Instant::now();
        let rows = match pg::plugin_wasm_candidates(&st.db, max_i64).await {
            Ok(rows) => rows,
            Err(e) => {
                let msg = e.to_string();
                tracing::warn!(
                    error = %msg,
                    "[plugins] PG plugin registry query failed; node ready unaffected \
                     (directory plugins unaffected; admin reload can retry without restart)"
                );
                let mut state = rt.state();
                state.pg.state = "error";
                state.pg.query_ms = started.elapsed().as_millis() as u64;
                state.pg.error = Some(truncate_reason(&msg, 300));
                return;
            }
        };
        // Oversized rows are fetched as metadata only (SQL reads no wasm bytes); a query failure is treated as empty (does not affect normal loading).
        let oversized = match pg::plugin_wasm_oversized(&st.db, max_i64).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "[plugins] PG plugin oversized-row query failed (best effort; candidates unaffected)"
                );
                Vec::new()
            }
        };
        let query_ms = started.elapsed().as_millis() as u64;
        // canary_ratio is not in the candidate-row SQL (`pg.rs` is outside this task's change scope): take the ratio from the full
        // metadata rows of the same `plugins` table, and refresh `AppState.plugins` along the way (admin canary actions also write that memory view,
        // and the invoke side reads it for the **live** ratio → tier switching needs no restart).
        let ratio_rows = match pg::plugins_all(&st.admin_db).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "[plugins] plugins_all query failed; canary routing data unavailable this snapshot"
                );
                Vec::new()
            }
        };
        let mut canary_ratios: BTreeMap<(String, i32), u8> = BTreeMap::new();
        for row in &ratio_rows {
            canary_ratios.insert(
                (short_ns(&row.ns).to_string(), row.version),
                row.canary_ratio.clamp(0, 100) as u8,
            );
        }
        refresh_plugins_view(&st, &ratio_rows);
        let selection = select_pg_candidates(&rows, &canary_ratios, rt.canary.enabled);

        let host = rt.host();
        let canary_host = rt.canary_host();
        let dir_names = rt.state().dir_names.clone();
        let trusted_keys = rt.host_config.trusted_keys.clone();
        let mut loaded_packages: Vec<PluginPackage> = Vec::new();
        let mut canary_packages: Vec<PluginPackage> = Vec::new();
        let mut rejected: Vec<LoadRejection> = Vec::new();
        let mut canary_rejected: Vec<LoadRejection> = Vec::new();
        let mut conflict_items: Vec<Value> = Vec::new();
        let mut canary_ignored_items: Vec<Value> = Vec::new();
        let mut canary_loaded_items: Vec<Value> = Vec::new();
        let mut canary_rejected_items: Vec<Value> = Vec::new();
        let mut oversized_items: Vec<Value> = Vec::new();
        let mut conflicts = 0usize;
        let mut canary_ignored = 0usize;
        let mut canary_loaded = 0usize;
        let mut skipped = 0usize;

        // canary: canary off / ratio=0 → ignore and record (never load silently; rows with >0 when canary is enabled are registered below).
        for (ns, version) in &selection.canary_ignored {
            tracing::info!(
                plugin = %ns,
                version = *version,
                source = "pg",
                canary_enabled = rt.canary.enabled,
                "[plugins] canary plugin ignored (no gray routing; only active max version is loaded)"
            );
            rt.metrics
                .plugin_wasm_source_total
                .with_label_values(&["pg", "skipped"])
                .inc();
            canary_ignored += 1;
            skipped += 1;
            push_capped(
                &mut canary_ignored_items,
                json!({
                    "ns": ns,
                    "version": version,
                    "reason": if rt.canary.enabled { "canary_ratio_zero" } else { "canary_routing_disabled" },
                }),
            );
        }
        // Same-ns lower canary versions: ignored (canary uses the highest canary version).
        for (ns, version) in &selection.canary_lower_versions {
            tracing::debug!(
                plugin = %ns,
                version = *version,
                source = "pg",
                "[plugins] lower canary version ignored (max canary version wins)"
            );
            rt.metrics
                .plugin_wasm_source_total
                .with_label_values(&["pg", "skipped"])
                .inc();
            skipped += 1;
        }
        // Same-ns lower/duplicate versions: ignored (the highest active version wins).
        for (ns, version) in &selection.lower_versions {
            tracing::debug!(
                plugin = %ns,
                version = *version,
                source = "pg",
                "[plugins] lower plugin version ignored (max active version wins)"
            );
            rt.metrics
                .plugin_wasm_source_total
                .with_label_values(&["pg", "skipped"])
                .inc();
            skipped += 1;
        }

        // Dependency existence: directory package ns + PG ns selected in this batch (including canary ns; same contract as the directory source).
        let mut known: BTreeSet<String> = dir_names.clone();
        for idx in &selection.selected {
            known.insert(short_ns(&rows[*idx].ns).to_string());
        }
        for idx in &selection.selected_canary {
            known.insert(short_ns(&rows[*idx].ns).to_string());
        }

        for idx in selection.selected {
            let row = &rows[idx];
            let ns = short_ns(&row.ns).to_string();
            // Directory priority: a directory package (even one ultimately rejected) has the same ns → skip the PG row and WARN.
            if dir_names.contains(&ns) || host.info(&ns).is_some() {
                tracing::warn!(
                    plugin = %ns,
                    version = row.version,
                    source = "pg",
                    "[plugins] directory plugin takes precedence over PG row (dir > pg); PG row skipped"
                );
                rt.metrics
                    .plugin_wasm_rejected_total
                    .with_label_values(&["conflict"])
                    .inc();
                rt.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&["pg", "rejected"])
                    .inc();
                conflicts += 1;
                rejected.push(LoadRejection {
                    plugin: ns.clone(),
                    kind: "conflict".to_string(),
                    reason: "directory plugin with the same ns takes precedence (dir > pg)"
                        .to_string(),
                });
                push_capped(
                    &mut conflict_items,
                    json!({ "ns": ns, "version": row.version, "reason": "dir_precedence" }),
                );
                continue;
            }
            let package = match package_from_pg_row(row, &trusted_keys) {
                Ok(package) => package,
                Err(reason) => {
                    tracing::warn!(
                        plugin = %ns,
                        version = row.version,
                        source = "pg",
                        reason = %reason,
                        "[plugins] PG plugin manifest rejected"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&[ErrorKind::Manifest.as_str()])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "rejected"])
                        .inc();
                    rejected.push(LoadRejection {
                        plugin: ns,
                        kind: ErrorKind::Manifest.as_str().to_string(),
                        reason,
                    });
                    continue;
                }
            };
            // Count the verification result first (same contract as the directory source: visible even if later rejected for missing deps/compile failure).
            let status = package.signature_status(&trusted_keys);
            rt.metrics
                .plugin_wasm_signature_total
                .with_label_values(&[status.check.as_str()])
                .inc();
            let missing: Vec<String> = package
                .manifest
                .deps
                .iter()
                .filter(|d| !known.contains(d.as_str()))
                .cloned()
                .collect();
            if !missing.is_empty() {
                let reason = format!("missing dependency: {}", missing.join(", "));
                tracing::warn!(
                    plugin = %ns,
                    version = row.version,
                    source = "pg",
                    reason = %reason,
                    "[plugins] PG plugin rejected"
                );
                rt.metrics
                    .plugin_wasm_rejected_total
                    .with_label_values(&[ErrorKind::MissingExport.as_str()])
                    .inc();
                rt.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&["pg", "rejected"])
                    .inc();
                rejected.push(LoadRejection {
                    plugin: ns,
                    kind: ErrorKind::MissingExport.as_str().to_string(),
                    reason,
                });
                continue;
            }
            match host.register(package.clone()) {
                Ok(info) => {
                    tracing::info!(
                        plugin = %info.short_name,
                        version = info.version,
                        entry = %info.entry,
                        source = "pg",
                        signature = info.signature.as_str(),
                        signature_detail = %info.signature_detail,
                        signing_key_id = info.signing_key_id.as_deref().unwrap_or(""),
                        trusted = info.trusted,
                        wasm_bytes = info.wasm_bytes,
                        "[plugins] WASM plugin registered from PG"
                    );
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "loaded"])
                        .inc();
                    loaded_packages.push(package);
                }
                Err(e) => {
                    tracing::warn!(
                        plugin = e.plugin().unwrap_or(&ns),
                        version = row.version,
                        source = "pg",
                        kind = e.kind().as_str(),
                        reason = %e,
                        "[plugins] PG plugin rejected"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&[e.kind().as_str()])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "rejected"])
                        .inc();
                    rejected.push(LoadRejection {
                        plugin: e.plugin().unwrap_or(&ns).to_string(),
                        kind: e.kind().as_str().to_string(),
                        reason: e.to_string(),
                    });
                }
            }
        }

        // ---- canary version registration (separate canary host; only rows selected when canary is enabled and ratio>0) ----
        for idx in selection.selected_canary {
            let row = &rows[idx];
            let ns = short_ns(&row.ns).to_string();
            // Directory priority also applies to canary: if a local directory package has the same ns → skip the canary row.
            if dir_names.contains(&ns) {
                tracing::warn!(
                    plugin = %ns,
                    version = row.version,
                    source = "pg",
                    "[plugins] directory plugin takes precedence over PG canary row (dir > pg); canary row skipped"
                );
                rt.metrics
                    .plugin_wasm_rejected_total
                    .with_label_values(&["conflict"])
                    .inc();
                rt.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&["pg", "rejected"])
                    .inc();
                canary_rejected.push(LoadRejection {
                    plugin: ns.clone(),
                    kind: "conflict".to_string(),
                    reason: "directory plugin with the same ns takes precedence (dir > pg)"
                        .to_string(),
                });
                push_capped(
                    &mut canary_rejected_items,
                    json!({ "ns": ns, "version": row.version, "reason": "dir_precedence" }),
                );
                continue;
            }
            let package = match package_from_pg_row(row, &trusted_keys) {
                Ok(package) => package,
                Err(reason) => {
                    tracing::warn!(
                        plugin = %ns,
                        version = row.version,
                        source = "pg",
                        reason = %reason,
                        "[plugins] PG canary plugin manifest rejected"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&[ErrorKind::Manifest.as_str()])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "rejected"])
                        .inc();
                    canary_rejected.push(LoadRejection {
                        plugin: ns.clone(),
                        kind: ErrorKind::Manifest.as_str().to_string(),
                        reason,
                    });
                    continue;
                }
            };
            let status = package.signature_status(&trusted_keys);
            rt.metrics
                .plugin_wasm_signature_total
                .with_label_values(&[status.check.as_str()])
                .inc();
            let missing: Vec<String> = package
                .manifest
                .deps
                .iter()
                .filter(|d| !known.contains(d.as_str()))
                .cloned()
                .collect();
            if !missing.is_empty() {
                let reason = format!("missing dependency: {}", missing.join(", "));
                tracing::warn!(
                    plugin = %ns,
                    version = row.version,
                    source = "pg",
                    canary = true,
                    reason = %reason,
                    "[plugins] PG canary plugin rejected"
                );
                rt.metrics
                    .plugin_wasm_rejected_total
                    .with_label_values(&[ErrorKind::MissingExport.as_str()])
                    .inc();
                rt.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&["pg", "rejected"])
                    .inc();
                canary_rejected.push(LoadRejection {
                    plugin: ns.clone(),
                    kind: ErrorKind::MissingExport.as_str().to_string(),
                    reason,
                });
                continue;
            }
            match canary_host.register(package.clone()) {
                Ok(info) => {
                    tracing::info!(
                        plugin = %info.short_name,
                        version = info.version,
                        entry = %info.entry,
                        source = "pg",
                        route = "canary",
                        signature = info.signature.as_str(),
                        trusted = info.trusted,
                        wasm_bytes = info.wasm_bytes,
                        "[plugins] WASM canary plugin registered (gray routing host)"
                    );
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "canary_loaded"])
                        .inc();
                    canary_loaded += 1;
                    push_capped(
                        &mut canary_loaded_items,
                        json!({ "ns": info.short_name, "version": info.version }),
                    );
                    canary_packages.push(package);
                }
                Err(e) => {
                    tracing::warn!(
                        plugin = e.plugin().unwrap_or(&ns),
                        version = row.version,
                        source = "pg",
                        route = "canary",
                        kind = e.kind().as_str(),
                        reason = %e,
                        "[plugins] PG canary plugin rejected"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&[e.kind().as_str()])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "rejected"])
                        .inc();
                    canary_rejected.push(LoadRejection {
                        plugin: e.plugin().unwrap_or(&ns).to_string(),
                        kind: e.kind().as_str().to_string(),
                        reason: e.to_string(),
                    });
                }
            }
        }

        // Oversized rows: SQL already prefiltered (no wasm bytes read) → reject and count.
        for row in &oversized {
            let ns = short_ns(&row.ns).to_string();
            tracing::warn!(
                plugin = %ns,
                version = row.version,
                source = "pg",
                wasm_bytes = row.wasm_bytes,
                max_wasm_bytes,
                "[plugins] PG plugin rejected: wasm exceeds [plugins] max_wasm_bytes (not loaded)"
            );
            rt.metrics
                .plugin_wasm_rejected_total
                .with_label_values(&[ErrorKind::Manifest.as_str()])
                .inc();
            rt.metrics
                .plugin_wasm_source_total
                .with_label_values(&["pg", "rejected"])
                .inc();
            rejected.push(LoadRejection {
                plugin: ns.clone(),
                kind: ErrorKind::Manifest.as_str().to_string(),
                reason: format!(
                    "wasm is {} bytes, exceeds [plugins] max_wasm_bytes {} (pre-filtered, not loaded)",
                    row.wasm_bytes, max_wasm_bytes
                ),
            });
            push_capped(
                &mut oversized_items,
                json!({ "ns": ns, "version": row.version, "status": row.status, "wasm_bytes": row.wasm_bytes }),
            );
        }

        let loaded_count = loaded_packages.len();
        let rejected_count = rejected.len();
        let canary_rejected_count = canary_rejected.len();
        // Merge into snapshot state + refresh low-cardinality metrics (loaded = "actually registered in the current snapshot").
        let total_loaded = host.plugins().len();
        let verified = host.plugins().iter().filter(|p| p.trusted).count();
        rt.metrics.plugin_wasm_loaded.set(total_loaded as i64);
        rt.metrics.plugin_wasm_verified.set(verified as i64);
        {
            let mut state = rt.state();
            state.pg = PgSourceStatus {
                enabled: true,
                state: "done",
                query_ms,
                rows: rows.len(),
                loaded: loaded_count,
                rejected: rejected_count,
                skipped,
                canary_ignored,
                canary_loaded,
                canary_rejected: canary_rejected_count,
                conflicts,
                oversized: oversized.len(),
                error: None,
                canary_ignored_items,
                canary_loaded_items,
                canary_rejected_items,
                conflict_items,
                oversized_items,
            };
            state.pg_packages = loaded_packages;
            state.pg_rejected = rejected;
            state.canary_packages = canary_packages;
            state.canary_rejected = canary_rejected;
        }
        tracing::info!(
            pg_rows = rows.len(),
            loaded = loaded_count,
            rejected = rejected_count,
            canary_loaded,
            canary_rejected = canary_rejected_count,
            skipped,
            canary_ignored,
            conflicts,
            oversized = oversized.len(),
            query_ms,
            generation = rt.state().generation,
            "[plugins] PG plugin registry loaded (async; node ready unaffected)"
        );
    }

    /// Refresh `AppState.plugins` (the in-memory view of the `plugins` table; data source for the live canary ratio).
    fn refresh_plugins_view(st: &AppState, rows: &[pg::PluginRow]) {
        let entries: Vec<lattice_plugins::registry::PluginEntry> = rows
            .iter()
            .map(|p| lattice_plugins::registry::PluginEntry {
                ns: p.ns.clone(),
                version: p.version as u32,
                status: lattice_plugins::registry::PluginStatus::parse(&p.status)
                    .unwrap_or(lattice_plugins::registry::PluginStatus::Staging),
                canary_ratio: p.canary_ratio.clamp(0, 100) as u32,
                form: if p.sidecar_addr.is_some() {
                    "sidecar".into()
                } else {
                    "wasm".into()
                },
            })
            .collect();
        if let Ok(mut w) = st.plugins.write() {
            *w = entries;
        }
    }

    /// Startup read of the S3 object-storage registry → verify/register (merged as the **lowest-priority** source: dir > pg > s3).
    ///
    /// Network/auth failures only WARN and do not block ready (same contract as the PG source); a single bad package goes to status `rejected`.
    async fn load_s3_plugins(rt: Arc<WasmRuntime>, st: Arc<AppState>) {
        let Some(cfg) = rt.s3.clone() else {
            return;
        };
        {
            let mut state = rt.state();
            state.s3.state = "loading";
        }
        let max_bytes = rt.max_wasm_bytes.max(lattice_plugins::wasm::registry::MAX_WASM_BYTES as u64);
        let scan = match super::registry_s3::load(&st.s3, &cfg, max_bytes).await {
            Ok(scan) => scan,
            Err(e) => {
                let msg = truncate_reason(&e, 300);
                tracing::warn!(
                    bucket = %cfg.bucket,
                    prefix = %cfg.prefix,
                    error = %msg,
                    "[plugins] S3 plugin registry read failed; node ready unaffected \
                     (directory/PG plugins unaffected; admin reload can retry without restart)"
                );
                let mut state = rt.state();
                state.s3.state = "error";
                state.s3.error = Some(msg);
                return;
            }
        };
        if !scan.index_present {
            super::registry_s3::warn_once_absent(&cfg.index_key());
        }
        let host = rt.host();
        let dir_names = rt.state().dir_names.clone();
        // Namespaces already registered from the directory/PG: S3 is lower priority, so skip and count.
        let mut taken: BTreeSet<String> = dir_names;
        taken.extend(rt.state().pg_packages.iter().map(|p| p.short_name().to_string()));
        let mut loaded_packages: Vec<PluginPackage> = Vec::new();
        let mut rejected: Vec<LoadRejection> = Vec::new();
        let mut rejected_items: Vec<Value> = Vec::new();
        let mut conflict_items: Vec<Value> = Vec::new();
        let mut conflicts = 0usize;
        for package in scan.packages {
            let ns = package.short_name().to_string();
            if taken.contains(&ns) || host.info(&ns).is_some() {
                tracing::warn!(
                    plugin = %ns,
                    source = "s3",
                    "[plugins] higher-priority source already registered this ns (dir/pg > s3); S3 package skipped"
                );
                rt.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&["s3", "skipped"])
                    .inc();
                conflicts += 1;
                push_capped(
                    &mut conflict_items,
                    json!({ "ns": ns, "version": package.manifest.version, "reason": "higher_priority_source" }),
                );
                continue;
            }
            let status = package.signature_status(&rt.host_config.trusted_keys);
            rt.metrics
                .plugin_wasm_signature_total
                .with_label_values(&[status.check.as_str()])
                .inc();
            match host.register(package.clone()) {
                Ok(info) => {
                    tracing::info!(
                        plugin = %info.short_name,
                        version = info.version,
                        source = "s3",
                        signature = info.signature.as_str(),
                        trusted = info.trusted,
                        wasm_bytes = info.wasm_bytes,
                        "[plugins] WASM plugin registered from S3"
                    );
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["s3", "loaded"])
                        .inc();
                    taken.insert(ns);
                    loaded_packages.push(package);
                }
                Err(e) => {
                    tracing::warn!(
                        plugin = e.plugin().unwrap_or(&ns),
                        source = "s3",
                        kind = e.kind().as_str(),
                        reason = %e,
                        "[plugins] S3 plugin rejected"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&[e.kind().as_str()])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["s3", "rejected"])
                        .inc();
                    push_capped(
                        &mut rejected_items,
                        json!({
                            "plugin": e.plugin().unwrap_or(&ns),
                            "kind": e.kind().as_str(),
                            "reason": truncate_reason(&e.to_string(), 240),
                        }),
                    );
                    rejected.push(LoadRejection {
                        plugin: e.plugin().unwrap_or(&ns).to_string(),
                        kind: e.kind().as_str().to_string(),
                        reason: e.to_string(),
                    });
                }
            }
        }
        for (plugin, reason) in scan.rejected {
            tracing::warn!(plugin = %plugin, source = "s3", reason = %reason, "[plugins] S3 plugin package rejected");
            rt.metrics
                .plugin_wasm_rejected_total
                .with_label_values(&["manifest"])
                .inc();
            rt.metrics
                .plugin_wasm_source_total
                .with_label_values(&["s3", "rejected"])
                .inc();
            push_capped(
                &mut rejected_items,
                json!({ "plugin": plugin, "kind": "manifest", "reason": truncate_reason(&reason, 240) }),
            );
            rejected.push(LoadRejection {
                plugin,
                kind: "manifest".to_string(),
                reason,
            });
        }
        let loaded = loaded_packages.len();
        let rejected_count = rejected.len();
        let total_loaded = host.plugins().len();
        let verified = host.plugins().iter().filter(|p| p.trusted).count();
        rt.metrics.plugin_wasm_loaded.set(total_loaded as i64);
        rt.metrics.plugin_wasm_verified.set(verified as i64);
        {
            let mut state = rt.state();
            state.s3 = S3SourceStatus {
                enabled: true,
                state: "done",
                bucket: cfg.bucket.clone(),
                prefix: cfg.prefix.clone(),
                index_present: scan.index_present,
                index_bytes: scan.index_bytes,
                objects: scan.objects,
                loaded,
                rejected: rejected_count,
                conflicts,
                elapsed_ms: scan.elapsed_ms,
                error: None,
                rejected_items,
                conflict_items,
            };
            state.s3_packages = loaded_packages;
            state.s3_rejected = rejected;
        }
        tracing::info!(
            bucket = %cfg.bucket,
            prefix = %cfg.prefix,
            index_present = scan.index_present,
            loaded,
            rejected = rejected_count,
            conflicts,
            objects = scan.objects,
            elapsed_ms = scan.elapsed_ms,
            "[plugins] S3 plugin registry loaded (async; node ready unaffected)"
        );
    }

    // ------------------------------------------------------------------
    // Hot reload (`POST /v1/admin/plugins/wasm/reload`; PL-10 hot reload)
    // ------------------------------------------------------------------

    /// Minimum hot-reload interval (1/s): success and failure both consume the window, preventing admin spam; rejection is 429 + `Retry-After`.
    const RELOAD_MIN_INTERVAL_MS: u64 = 1_000;
    /// Max wait for the startup async PG load before reloading (avoids losing startup results/racing the new snapshot).
    const PG_STARTUP_WAIT_MS: u64 = 10_000;

    fn reload_failure(
        reason: &'static str,
        http_status: u16,
        message: impl Into<String>,
    ) -> ReloadFailure {
        ReloadFailure::new(reason, http_status, message)
    }

    fn count_reload_metric(rt: &WasmRuntime, result: &str) {
        rt.metrics
            .plugin_wasm_reload_total
            .with_label_values(&[result])
            .inc();
    }

    /// Wait for startup async source loading to finish (PG/S3 `pending/loading` → `done/error/unavailable`).
    async fn wait_startup_sources(rt: &Arc<WasmRuntime>) {
        let deadline = Instant::now() + Duration::from_millis(PG_STARTUP_WAIT_MS);
        while Instant::now() < deadline {
            let (pg_state, s3_state) = {
                let state = rt.state();
                (state.pg.state, state.s3.state)
            };
            let pg_waiting = rt.from_db && (pg_state == "pending" || pg_state == "loading");
            let s3_waiting =
                rt.s3.is_some() && (s3_state == "pending" || s3_state == "loading");
            if !pg_waiting && !s3_waiting {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        tracing::warn!(
            waited_ms = PG_STARTUP_WAIT_MS,
            "[plugins] wasm reload waited for the startup source load; building from current sources anyway"
        );
    }

    /// **Candidate plan** ("scratch table") for one hot reload: packages read from sources + identified rejections, runtime untouched.
    struct ReloadPlan {
        /// Directory candidates (rescan result; when `source` excludes dir = the previous snapshot's effective directory packages).
        dir: Vec<PluginPackage>,
        /// Directory-source rejection details (rescan = new scan result; carried over = previous snapshot's details).
        dir_rejected: Vec<LoadRejection>,
        /// Directory candidate namespaces (including rejected directory packages; PG same-name conflict rule).
        dir_names: BTreeSet<String>,
        /// PG stable (active) candidates (re-read result; when `source` excludes pg = the previous snapshot's effective PG packages).
        pg: Vec<PluginPackage>,
        /// PG namespaces selected in this batch (dependency existence check; includes manifest-parse-failure candidates, same as startup).
        pg_known: BTreeSet<String>,
        pg_rejected: Vec<LoadRejection>,
        /// Canary candidates (only when canary is enabled and ratio>0; carried over from the previous snapshot when `source` excludes pg).
        canary: Vec<PluginPackage>,
        canary_rejected: Vec<LoadRejection>,
        /// New diagnostic status of the PG re-read this round (None = keep the previous snapshot's status).
        pg_status: Option<PgSourceStatus>,
        /// S3 candidates (re-read result; when `source` excludes s3 = the previous snapshot's effective S3 packages).
        s3: Vec<PluginPackage>,
        s3_rejected: Vec<LoadRejection>,
        s3_status: Option<S3SourceStatus>,
        /// Conflict count / skipped count (canary, lower versions; counted per source re-read this round).
        conflicts: usize,
        skipped: usize,
        /// Effective packages of the previous snapshot (fallback source for rejected candidates' old versions; directory priority).
        prev: Vec<(PackageSource, PluginPackage)>,
    }

    /// Read sources → candidate plan. **Any hard source failure returns Err** (old snapshot unchanged, admin maps to 500).
    async fn plan_reload(
        st: &Arc<AppState>,
        rt: &Arc<WasmRuntime>,
        source: ReloadSource,
    ) -> Result<ReloadPlan, ReloadFailure> {
        let prev_state = rt.state().clone();
        let mut prev: Vec<(PackageSource, PluginPackage)> = Vec::new();
        for package in &prev_state.dir_packages {
            prev.push((PackageSource::Dir, package.clone()));
        }
        for package in &prev_state.pg_packages {
            prev.push((PackageSource::Pg, package.clone()));
        }
        for package in &prev_state.s3_packages {
            prev.push((PackageSource::S3, package.clone()));
        }
        let mut plan = ReloadPlan {
            dir: Vec::new(),
            dir_rejected: Vec::new(),
            dir_names: prev_state.dir_names.clone(),
            pg: Vec::new(),
            pg_known: BTreeSet::new(),
            pg_rejected: Vec::new(),
            canary: Vec::new(),
            canary_rejected: Vec::new(),
            pg_status: None,
            s3: Vec::new(),
            s3_rejected: Vec::new(),
            s3_status: None,
            conflicts: 0,
            skipped: 0,
            prev,
        };

        // ---- Directory source ----
        if source.includes_dir() {
            plan.dir_names = BTreeSet::new();
            if !rt.wasm_dir.is_empty() {
                // Hard failure: directory unreadable → 500 with reason, current registry untouched (never silently drop directory plugins).
                if let Err(e) = std::fs::read_dir(&rt.wasm_dir) {
                    tracing::warn!(
                        wasm_dir = %rt.wasm_dir,
                        error = %e,
                        "[plugins] wasm reload: wasm_dir is not readable; keeping current registry snapshot"
                    );
                    return Err(reload_failure(
                        "dir_scan",
                        500,
                        format!("[plugins] wasm_dir `{}` is not readable: {e}", rt.wasm_dir),
                    ));
                }
                let scan = DirRegistry::new(&rt.wasm_dir).scan();
                for (plugin, reason) in scan.rejected {
                    tracing::warn!(
                        plugin = %plugin,
                        reason = %reason,
                        "wasm plugin reload: package rejected (scan)"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&["manifest"])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["dir", "rejected"])
                        .inc();
                    plan.dir_rejected.push(LoadRejection {
                        plugin,
                        kind: ErrorKind::Manifest.as_str().to_string(),
                        reason,
                    });
                }
                plan.dir = scan.packages;
                plan.dir_names = plan.dir.iter().map(|p| p.short_name().to_string()).collect();
            }
        } else {
            // No rescan: keep the previous snapshot (no duplicate metrics; rejection details are carried over too).
            plan.dir = prev_state.dir_packages.clone();
            plan.dir_rejected = prev_state.dir_rejected.clone();
        }

        // ---- PG source ----
        if source.includes_pg() {
            if !rt.from_db {
                return Err(reload_failure(
                    "pg_source_disabled",
                    422,
                    "source=pg requires [plugins] from_db=true on this node",
                ));
            }
            let max_i64 = rt.max_wasm_bytes.min(i64::MAX as u64) as i64;
            let started = Instant::now();
            let rows = match pg::plugin_wasm_candidates(&st.db, max_i64).await {
                Ok(rows) => rows,
                Err(e) => {
                    let msg = truncate_reason(&e.to_string(), 300);
                    tracing::warn!(
                        error = %msg,
                        "[plugins] wasm reload: PG plugin registry query failed; keeping current registry snapshot"
                    );
                    return Err(reload_failure(
                        "pg_query",
                        500,
                        format!("PG plugin registry query failed: {msg}"),
                    ));
                }
            };
            let oversized = match pg::plugin_wasm_oversized(&st.db, max_i64).await {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "[plugins] wasm reload: PG oversized-row query failed (best effort; candidates unaffected)"
                    );
                    Vec::new()
                }
            };
            let query_ms = started.elapsed().as_millis() as u64;
            // canary_ratio and the live canary view: read all metadata of the same `plugins` table and refresh the memory view.
            let ratio_rows = match pg::plugins_all(&st.admin_db).await {
                Ok(rows) => rows,
                Err(e) => {
                    let msg = truncate_reason(&e.to_string(), 300);
                    tracing::warn!(
                        error = %msg,
                        "[plugins] wasm reload: plugins_all query failed; keeping current snapshot"
                    );
                    return Err(reload_failure(
                        "pg_query",
                        500,
                        format!("plugins canary ratio query failed: {msg}"),
                    ));
                }
            };
            let mut canary_ratios: BTreeMap<(String, i32), u8> = BTreeMap::new();
            for row in &ratio_rows {
                canary_ratios.insert(
                    (short_ns(&row.ns).to_string(), row.version),
                    row.canary_ratio.clamp(0, 100) as u8,
                );
            }
            refresh_plugins_view(st, &ratio_rows);
            let selection = select_pg_candidates(&rows, &canary_ratios, rt.canary.enabled);
            let mut pg_status = PgSourceStatus {
                enabled: true,
                state: "done",
                query_ms,
                rows: rows.len(),
                ..PgSourceStatus::default()
            };
            let mut canary_ignored_items: Vec<Value> = Vec::new();
            let mut canary_loaded_items: Vec<Value> = Vec::new();
            let mut canary_rejected_items: Vec<Value> = Vec::new();
            let mut conflict_items: Vec<Value> = Vec::new();
            let mut oversized_items: Vec<Value> = Vec::new();

            // canary: canary off / ratio=0 → ignore and record (same contract as startup).
            for (ns, version) in &selection.canary_ignored {
                tracing::info!(
                    plugin = %ns,
                    version = *version,
                    source = "pg",
                    canary_enabled = rt.canary.enabled,
                    "[plugins] canary plugin ignored (no gray routing; only active max version is loaded)"
                );
                rt.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&["pg", "skipped"])
                    .inc();
                plan.skipped += 1;
                pg_status.canary_ignored += 1;
                push_capped(
                    &mut canary_ignored_items,
                    json!({
                        "ns": ns,
                        "version": version,
                        "reason": if rt.canary.enabled { "canary_ratio_zero" } else { "canary_routing_disabled" },
                    }),
                );
            }
            // Same-ns lower canary versions: ignored (canary uses the highest canary version).
            for (ns, version) in &selection.canary_lower_versions {
                tracing::debug!(
                    plugin = %ns,
                    version = *version,
                    source = "pg",
                    "[plugins] lower canary version ignored (max canary version wins)"
                );
                rt.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&["pg", "skipped"])
                    .inc();
                plan.skipped += 1;
            }
            // Same-ns lower/duplicate versions: ignored (the highest active version wins).
            for (ns, version) in &selection.lower_versions {
                tracing::debug!(
                    plugin = %ns,
                    version = *version,
                    source = "pg",
                    "[plugins] lower plugin version ignored (max active version wins)"
                );
                rt.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&["pg", "skipped"])
                    .inc();
                plan.skipped += 1;
            }

            // Dependency existence: directory candidate ns + PG ns selected in this batch (same contract as startup loading).
            plan.pg_known = selection
                .selected
                .iter()
                .map(|i| short_ns(&rows[*i].ns).to_string())
                .collect();
            let mut known: BTreeSet<String> = plan.dir_names.clone();
            known.extend(plan.pg_known.iter().cloned());
            let trusted_keys = rt.host_config.trusted_keys.clone();
            for idx in selection.selected {
                let row = &rows[idx];
                let ns = short_ns(&row.ns).to_string();
                // Directory priority: a directory candidate has the same ns (even if ultimately rejected) → skip the PG row and count.
                if plan.dir_names.contains(&ns) {
                    tracing::warn!(
                        plugin = %ns,
                        version = row.version,
                        source = "pg",
                        "[plugins] directory plugin takes precedence over PG row (dir > pg); PG row skipped"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&["conflict"])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "rejected"])
                        .inc();
                    plan.conflicts += 1;
                    plan.pg_rejected.push(LoadRejection {
                        plugin: ns.clone(),
                        kind: "conflict".to_string(),
                        reason: "directory plugin with the same ns takes precedence (dir > pg)"
                            .to_string(),
                    });
                    push_capped(
                        &mut conflict_items,
                        json!({ "ns": ns, "version": row.version, "reason": "dir_precedence" }),
                    );
                    continue;
                }
                let package = match package_from_pg_row(row, &trusted_keys) {
                    Ok(package) => package,
                    Err(reason) => {
                        tracing::warn!(
                            plugin = %ns,
                            version = row.version,
                            source = "pg",
                            reason = %reason,
                            "[plugins] wasm reload: PG plugin manifest rejected"
                        );
                        rt.metrics
                            .plugin_wasm_rejected_total
                            .with_label_values(&[ErrorKind::Manifest.as_str()])
                            .inc();
                        rt.metrics
                            .plugin_wasm_source_total
                            .with_label_values(&["pg", "rejected"])
                            .inc();
                        plan.pg_rejected.push(LoadRejection {
                            plugin: ns,
                            kind: ErrorKind::Manifest.as_str().to_string(),
                            reason,
                        });
                        continue;
                    }
                };
                // Count the verification result first (visible even if rejected later, same contract as startup).
                let status = package.signature_status(&trusted_keys);
                rt.metrics
                    .plugin_wasm_signature_total
                    .with_label_values(&[status.check.as_str()])
                    .inc();
                let missing: Vec<String> = package
                    .manifest
                    .deps
                    .iter()
                    .filter(|d| !known.contains(d.as_str()))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    let reason = format!("missing dependency: {}", missing.join(", "));
                    tracing::warn!(
                        plugin = %ns,
                        version = row.version,
                        source = "pg",
                        reason = %reason,
                        "[plugins] wasm reload: PG plugin rejected"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&[ErrorKind::MissingExport.as_str()])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "rejected"])
                        .inc();
                    plan.pg_rejected.push(LoadRejection {
                        plugin: ns,
                        kind: ErrorKind::MissingExport.as_str().to_string(),
                        reason,
                    });
                    continue;
                }
                plan.pg.push(package);
            }

            // Dependency existence: canary namespaces are also added to the known set (canary may depend on active/directory plugins).
            for idx in &selection.selected_canary {
                known.insert(short_ns(&rows[*idx].ns).to_string());
            }

            // ---- canary candidates (separate canary host; directory priority applies too) ----
            for idx in selection.selected_canary {
                let row = &rows[idx];
                let ns = short_ns(&row.ns).to_string();
                if plan.dir_names.contains(&ns) {
                    tracing::warn!(
                        plugin = %ns,
                        version = row.version,
                        source = "pg",
                        "[plugins] directory plugin takes precedence over PG canary row (dir > pg); canary row skipped"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&["conflict"])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "rejected"])
                        .inc();
                    plan.conflicts += 1;
                    plan.canary_rejected.push(LoadRejection {
                        plugin: ns.clone(),
                        kind: "conflict".to_string(),
                        reason: "directory plugin with the same ns takes precedence (dir > pg)"
                            .to_string(),
                    });
                    push_capped(
                        &mut canary_rejected_items,
                        json!({ "ns": ns, "version": row.version, "reason": "dir_precedence" }),
                    );
                    continue;
                }
                let package = match package_from_pg_row(row, &trusted_keys) {
                    Ok(package) => package,
                    Err(reason) => {
                        tracing::warn!(
                            plugin = %ns,
                            version = row.version,
                            source = "pg",
                            route = "canary",
                            reason = %reason,
                            "[plugins] wasm reload: PG canary manifest rejected"
                        );
                        rt.metrics
                            .plugin_wasm_rejected_total
                            .with_label_values(&[ErrorKind::Manifest.as_str()])
                            .inc();
                        rt.metrics
                            .plugin_wasm_source_total
                            .with_label_values(&["pg", "rejected"])
                            .inc();
                        plan.canary_rejected.push(LoadRejection {
                            plugin: ns.clone(),
                            kind: ErrorKind::Manifest.as_str().to_string(),
                            reason,
                        });
                        continue;
                    }
                };
                let status = package.signature_status(&trusted_keys);
                rt.metrics
                    .plugin_wasm_signature_total
                    .with_label_values(&[status.check.as_str()])
                    .inc();
                let missing: Vec<String> = package
                    .manifest
                    .deps
                    .iter()
                    .filter(|d| !known.contains(d.as_str()))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    let reason = format!("missing dependency: {}", missing.join(", "));
                    tracing::warn!(
                        plugin = %ns,
                        version = row.version,
                        source = "pg",
                        route = "canary",
                        reason = %reason,
                        "[plugins] wasm reload: PG canary plugin rejected"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&[ErrorKind::MissingExport.as_str()])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "rejected"])
                        .inc();
                    plan.canary_rejected.push(LoadRejection {
                        plugin: ns.clone(),
                        kind: ErrorKind::MissingExport.as_str().to_string(),
                        reason,
                    });
                    continue;
                }
                push_capped(
                    &mut canary_loaded_items,
                    json!({ "ns": ns, "version": row.version }),
                );
                plan.canary.push(package);
            }

            // Oversized rows: SQL already prefiltered (no wasm bytes read) → reject and count.
            for row in &oversized {
                let ns = short_ns(&row.ns).to_string();
                tracing::warn!(
                    plugin = %ns,
                    version = row.version,
                    source = "pg",
                    wasm_bytes = row.wasm_bytes,
                    max_wasm_bytes = rt.max_wasm_bytes,
                    "[plugins] wasm reload: PG plugin rejected: wasm exceeds [plugins] max_wasm_bytes (not loaded)"
                );
                rt.metrics
                    .plugin_wasm_rejected_total
                    .with_label_values(&[ErrorKind::Manifest.as_str()])
                    .inc();
                rt.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&["pg", "rejected"])
                    .inc();
                plan.pg_rejected.push(LoadRejection {
                    plugin: ns.clone(),
                    kind: ErrorKind::Manifest.as_str().to_string(),
                    reason: format!(
                        "wasm is {} bytes, exceeds [plugins] max_wasm_bytes {} (pre-filtered, not loaded)",
                        row.wasm_bytes, rt.max_wasm_bytes
                    ),
                });
                push_capped(
                    &mut oversized_items,
                    json!({ "ns": ns, "version": row.version, "status": row.status, "wasm_bytes": row.wasm_bytes }),
                );
            }

            pg_status.skipped = plan.skipped;
            pg_status.conflicts = plan.conflicts;
            pg_status.oversized = oversized.len();
            pg_status.loaded = plan.pg.len();
            pg_status.rejected = plan.pg_rejected.len();
            pg_status.canary_loaded = plan.canary.len();
            pg_status.canary_rejected = plan.canary_rejected.len();
            pg_status.canary_ignored_items = canary_ignored_items;
            pg_status.canary_loaded_items = canary_loaded_items;
            pg_status.canary_rejected_items = canary_rejected_items;
            pg_status.conflict_items = conflict_items;
            pg_status.oversized_items = oversized_items;
            plan.pg_status = Some(pg_status);
        } else {
            // No PG re-read: carry over the previous snapshot's effective packages + rejection details.
            plan.pg = prev_state.pg_packages.clone();
            plan.pg_known = plan.pg.iter().map(|p| p.short_name().to_string()).collect();
            plan.pg_rejected = prev_state.pg_rejected.clone();
            plan.canary = prev_state.canary_packages.clone();
            plan.canary_rejected = prev_state.canary_rejected.clone();
        }

        // ---- S3 source ----
        if source.includes_s3() {
            match &rt.s3 {
                None => {
                    // `source=all` only re-reads **enabled** sources: skip S3 when unconfigured (keep empty/carried over);
                    // only an explicit `source=s3` is a request problem → 422 (existing contract).
                    if source == ReloadSource::S3 {
                        return Err(reload_failure(
                            "s3_source_disabled",
                            422,
                            "source=s3 requires LATTICE_PLUGIN_S3_PREFIX to be set on this node",
                        ));
                    }
                    plan.s3 = prev_state.s3_packages.clone();
                    plan.s3_rejected = prev_state.s3_rejected.clone();
                }
                Some(cfg) => {
                    let max_bytes = rt
                        .max_wasm_bytes
                        .max(lattice_plugins::wasm::registry::MAX_WASM_BYTES as u64);
                    match super::registry_s3::load(&st.s3, cfg, max_bytes).await {
                        Ok(scan) => {
                            let mut rejected_items: Vec<Value> = Vec::new();
                            let mut conflict_items: Vec<Value> = Vec::new();
                            // Namespaces already taken by higher-priority sources (directory/PG): S3 skips and counts.
                            let mut taken: BTreeSet<String> = plan.dir_names.clone();
                            taken.extend(plan.pg_known.iter().cloned());
                            let mut conflicts = 0usize;
                            let mut loaded = 0usize;
                            for package in scan.packages {
                                let ns = package.short_name().to_string();
                                if taken.contains(&ns) {
                                    tracing::warn!(
                                        plugin = %ns,
                                        source = "s3",
                                        "[plugins] higher-priority source already provides this ns (dir/pg > s3); S3 package skipped"
                                    );
                                    rt.metrics
                                        .plugin_wasm_source_total
                                        .with_label_values(&["s3", "skipped"])
                                        .inc();
                                    conflicts += 1;
                                    push_capped(
                                        &mut conflict_items,
                                        json!({ "ns": ns, "version": package.manifest.version, "reason": "higher_priority_source" }),
                                    );
                                    continue;
                                }
                                taken.insert(ns.clone());
                                loaded += 1;
                                plan.s3.push(package);
                            }
                            let rejected_count = scan.rejected.len();
                            for (plugin, reason) in scan.rejected {
                                tracing::warn!(plugin = %plugin, source = "s3", reason = %reason, "[plugins] wasm reload: S3 plugin package rejected");
                                push_capped(
                                    &mut rejected_items,
                                    json!({ "plugin": plugin, "kind": "manifest", "reason": truncate_reason(&reason, 240) }),
                                );
                                plan.s3_rejected.push(LoadRejection {
                                    plugin,
                                    kind: "manifest".to_string(),
                                    reason,
                                });
                            }
                            plan.s3_status = Some(S3SourceStatus {
                                enabled: true,
                                state: "done",
                                bucket: cfg.bucket.clone(),
                                prefix: cfg.prefix.clone(),
                                index_present: scan.index_present,
                                index_bytes: scan.index_bytes,
                                objects: scan.objects,
                                loaded,
                                rejected: rejected_count,
                                conflicts,
                                elapsed_ms: scan.elapsed_ms,
                                error: None,
                                rejected_items,
                                conflict_items,
                            });
                        }
                        Err(e) => {
                            tracing::warn!(
                                bucket = %cfg.bucket,
                                prefix = %cfg.prefix,
                                error = %e,
                                "[plugins] wasm reload: S3 registry read failed; keeping current registry snapshot"
                            );
                            return Err(reload_failure(
                                "s3_read",
                                500,
                                format!("S3 plugin registry read failed: {}", truncate_reason(&e, 240)),
                            ));
                        }
                    }
                }
            }
        } else {
            plan.s3 = prev_state.s3_packages.clone();
            plan.s3_rejected = prev_state.s3_rejected.clone();
        }
        Ok(plan)
    }

    /// Assembly result of the new snapshot (all "scratch table" entries registered into the host, not yet swapped).
    struct SnapshotParts {
        host: Arc<WasmHost>,
        canary_host: Arc<WasmHost>,
        dir_packages: Vec<PluginPackage>,
        pg_packages: Vec<PluginPackage>,
        s3_packages: Vec<PluginPackage>,
        canary_packages: Vec<PluginPackage>,
        dir_names: BTreeSet<String>,
        dir_rejected: Vec<LoadRejection>,
        pg_rejected: Vec<LoadRejection>,
        s3_rejected: Vec<LoadRejection>,
        canary_rejected: Vec<LoadRejection>,
        pg_status: PgSourceStatus,
        s3_status: S3SourceStatus,
        loaded: usize,
        from_dir: usize,
        from_pg: usize,
        from_s3: usize,
        canary_loaded: usize,
        rejected: usize,
        conflicts: usize,
        retained: usize,
        skipped: usize,
    }

    /// Rejected-candidate fallback: backfill from the previous snapshot's package with the same ns (directory priority); success counts as `retained`.
    ///
    /// Semantics: "a bad new version (bad signature/unsigned/compile failure/missing dependency/oversized) must not take the live old version offline".
    #[allow(clippy::too_many_arguments)]
    fn retain_previous(
        rt: &WasmRuntime,
        host: &WasmHost,
        prev: &[(PackageSource, PluginPackage)],
        ns: &str,
        new_dir: &mut Vec<PluginPackage>,
        new_pg: &mut Vec<PluginPackage>,
        new_s3: &mut Vec<PluginPackage>,
    ) -> usize {
        if host.info(ns).is_some() {
            return 0;
        }
        let Some((source, package)) = prev.iter().find(|(_, p)| p.short_name() == ns).cloned() else {
            return 0;
        };
        match host.register(package.clone()) {
            Ok(info) => {
                tracing::warn!(
                    plugin = %info.short_name,
                    version = info.version,
                    source = source.as_str(),
                    "[plugins] wasm reload: rejected candidate rolled back to the previous version (retained)"
                );
                rt.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&[source.as_str(), "loaded"])
                    .inc();
                match source {
                    PackageSource::Dir => new_dir.push(package),
                    PackageSource::Pg => new_pg.push(package),
                    PackageSource::S3 => new_s3.push(package),
                }
                1
            }
            Err(e) => {
                tracing::warn!(
                    plugin = %ns,
                    error = %e,
                    "[plugins] wasm reload: previous version could not be retained either"
                );
                0
            }
        }
    }

    /// Assemble the new host (wasmtime `Module` compiled in memory): bad packages are only rejected/fallen back, never aborting the rebuild.
    ///
    /// This function is **synchronously blocking** (compilation); callers run it on the blocking thread pool via `spawn_blocking`.
    fn assemble_reload(
        rt: &Arc<WasmRuntime>,
        plan: ReloadPlan,
        prev_pg_status: PgSourceStatus,
        prev_s3_status: S3SourceStatus,
    ) -> Result<SnapshotParts, ReloadFailure> {
        let host = match WasmHost::with_hooks(
            rt.host_config.clone(),
            Arc::new(MetricsHooks { metrics: rt.metrics.clone() }),
        ) {
            Ok(host) => Arc::new(host),
            Err(e) => {
                let msg = format!("wasm host rebuild failed: {e}");
                tracing::error!(error = %e, "[plugins] wasm reload: {msg}");
                return Err(reload_failure("host_init", 500, msg));
            }
        };
        let canary_host = match WasmHost::with_hooks(
            rt.host_config.clone(),
            Arc::new(MetricsHooks { metrics: rt.metrics.clone() }),
        ) {
            Ok(host) => Arc::new(host),
            Err(e) => {
                let msg = format!("canary wasm host rebuild failed: {e}");
                tracing::error!(error = %e, "[plugins] wasm reload: {msg}");
                return Err(reload_failure("host_init", 500, msg));
            }
        };
        let ReloadPlan {
            dir,
            dir_rejected,
            dir_names,
            pg,
            pg_known,
            pg_rejected,
            canary,
            canary_rejected,
            pg_status,
            s3,
            s3_rejected,
            s3_status,
            conflicts: plan_conflicts,
            skipped,
            prev,
        } = plan;
        let trusted_keys = rt.host_config.trusted_keys.clone();
        let dir_known: BTreeSet<String> = dir.iter().map(|p| p.short_name().to_string()).collect();
        let mut dir_rejected_items = dir_rejected;
        let mut pg_rejected_items = pg_rejected;
        let mut canary_rejected_items = canary_rejected;
        let mut s3_rejected_items = s3_rejected;
        let mut new_dir: Vec<PluginPackage> = Vec::new();
        let mut new_pg: Vec<PluginPackage> = Vec::new();
        let mut new_s3: Vec<PluginPackage> = Vec::new();
        let mut new_canary: Vec<PluginPackage> = Vec::new();
        let mut conflicts = plan_conflicts;
        let mut retained = 0usize;

        // ---- Directory candidates (directory priority; bad packages fall back to the previous snapshot's same ns) ----
        for package in dir {
            let name = package.short_name().to_string();
            let missing: Vec<String> = package
                .manifest
                .deps
                .iter()
                .filter(|d| !dir_known.contains(d.as_str()))
                .cloned()
                .collect();
            if !missing.is_empty() {
                let reason = format!("missing dependency: {}", missing.join(", "));
                tracing::warn!(
                    plugin = %name,
                    reason = %reason,
                    "[plugins] wasm reload: directory plugin rejected"
                );
                rt.metrics
                    .plugin_wasm_rejected_total
                    .with_label_values(&[ErrorKind::MissingExport.as_str()])
                    .inc();
                rt.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&["dir", "rejected"])
                    .inc();
                dir_rejected_items.push(LoadRejection {
                    plugin: name.clone(),
                    kind: ErrorKind::MissingExport.as_str().to_string(),
                    reason,
                });
                retained += retain_previous(rt, &host, &prev, &name, &mut new_dir, &mut new_pg, &mut new_s3);
                continue;
            }
            // Count the verification result first (visible even if compilation fails later, same contract as startup).
            let status = package.signature_status(&trusted_keys);
            rt.metrics
                .plugin_wasm_signature_total
                .with_label_values(&[status.check.as_str()])
                .inc();
            match host.register(package.clone()) {
                Ok(info) => {
                    tracing::info!(
                        plugin = %info.short_name,
                        version = info.version,
                        entry = %info.entry,
                        source = "dir",
                        signature = info.signature.as_str(),
                        signature_detail = %info.signature_detail,
                        signing_key_id = info.signing_key_id.as_deref().unwrap_or(""),
                        trusted = info.trusted,
                        wasm_bytes = info.wasm_bytes,
                        "wasm plugin registered"
                    );
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["dir", "loaded"])
                        .inc();
                    new_dir.push(package);
                }
                Err(e) => {
                    tracing::warn!(
                        plugin = e.plugin().unwrap_or(&name),
                        kind = e.kind().as_str(),
                        reason = %e,
                        "wasm plugin reload: directory plugin rejected"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&[e.kind().as_str()])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["dir", "rejected"])
                        .inc();
                    dir_rejected_items.push(LoadRejection {
                        plugin: e.plugin().unwrap_or(&name).to_string(),
                        kind: e.kind().as_str().to_string(),
                        reason: e.to_string(),
                    });
                    retained += retain_previous(rt, &host, &prev, &name, &mut new_dir, &mut new_pg, &mut new_s3);
                }
            }
        }

        // ---- PG candidates (directory priority; bad packages fall back to the previous snapshot's same ns) ----
        let mut known: BTreeSet<String> = dir_names.clone();
        known.extend(pg_known.iter().cloned());
        for package in pg {
            let ns = package.short_name().to_string();
            if dir_names.contains(&ns) || host.info(&ns).is_some() {
                tracing::warn!(
                    plugin = %ns,
                    version = package.manifest.version,
                    source = "pg",
                    "[plugins] directory plugin takes precedence over PG row (dir > pg); PG row skipped"
                );
                rt.metrics
                    .plugin_wasm_rejected_total
                    .with_label_values(&["conflict"])
                    .inc();
                rt.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&["pg", "rejected"])
                    .inc();
                conflicts += 1;
                pg_rejected_items.push(LoadRejection {
                    plugin: ns.clone(),
                    kind: "conflict".to_string(),
                    reason: "directory plugin with the same ns takes precedence (dir > pg)"
                        .to_string(),
                });
                continue;
            }
            let missing: Vec<String> = package
                .manifest
                .deps
                .iter()
                .filter(|d| !known.contains(d.as_str()))
                .cloned()
                .collect();
            if !missing.is_empty() {
                let reason = format!("missing dependency: {}", missing.join(", "));
                tracing::warn!(
                    plugin = %ns,
                    version = package.manifest.version,
                    source = "pg",
                    reason = %reason,
                    "[plugins] wasm reload: PG plugin rejected"
                );
                rt.metrics
                    .plugin_wasm_rejected_total
                    .with_label_values(&[ErrorKind::MissingExport.as_str()])
                    .inc();
                rt.metrics
                    .plugin_wasm_source_total
                    .with_label_values(&["pg", "rejected"])
                    .inc();
                pg_rejected_items.push(LoadRejection {
                    plugin: ns.clone(),
                    kind: ErrorKind::MissingExport.as_str().to_string(),
                    reason,
                });
                retained += retain_previous(rt, &host, &prev, &ns, &mut new_dir, &mut new_pg, &mut new_s3);
                continue;
            }
            let status = package.signature_status(&trusted_keys);
            rt.metrics
                .plugin_wasm_signature_total
                .with_label_values(&[status.check.as_str()])
                .inc();
            match host.register(package.clone()) {
                Ok(info) => {
                    tracing::info!(
                        plugin = %info.short_name,
                        version = info.version,
                        entry = %info.entry,
                        source = "pg",
                        signature = info.signature.as_str(),
                        signature_detail = %info.signature_detail,
                        signing_key_id = info.signing_key_id.as_deref().unwrap_or(""),
                        trusted = info.trusted,
                        wasm_bytes = info.wasm_bytes,
                        "[plugins] WASM plugin registered from PG"
                    );
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "loaded"])
                        .inc();
                    new_pg.push(package);
                }
                Err(e) => {
                    tracing::warn!(
                        plugin = e.plugin().unwrap_or(&ns),
                        version = package.manifest.version,
                        source = "pg",
                        kind = e.kind().as_str(),
                        reason = %e,
                        "wasm plugin reload: PG plugin rejected"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&[e.kind().as_str()])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "rejected"])
                        .inc();
                    pg_rejected_items.push(LoadRejection {
                        plugin: e.plugin().unwrap_or(&ns).to_string(),
                        kind: e.kind().as_str().to_string(),
                        reason: e.to_string(),
                    });
                    retained += retain_previous(rt, &host, &prev, &ns, &mut new_dir, &mut new_pg, &mut new_s3);
                }
            }
        }

        // ---- S3 candidates (lowest priority: dir > pg > s3; bad packages rejected/fallen back to the previous snapshot's same ns) ----
        {
            let mut known: BTreeSet<String> = dir_names.clone();
            known.extend(pg_known.iter().cloned());
            for package in &s3 {
                known.insert(package.short_name().to_string());
            }
            for package in s3 {
                let ns = package.short_name().to_string();
                if dir_names.contains(&ns) || host.info(&ns).is_some() {
                    tracing::warn!(
                        plugin = %ns,
                        version = package.manifest.version,
                        source = "s3",
                        "[plugins] higher-priority source already registered this ns (dir/pg > s3); S3 package skipped"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&["conflict"])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["s3", "rejected"])
                        .inc();
                    conflicts += 1;
                    s3_rejected_items.push(LoadRejection {
                        plugin: ns.clone(),
                        kind: "conflict".to_string(),
                        reason: "higher-priority source provides the same ns (dir/pg > s3)"
                            .to_string(),
                    });
                    continue;
                }
                let missing: Vec<String> = package
                    .manifest
                    .deps
                    .iter()
                    .filter(|d| !known.contains(d.as_str()))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    let reason = format!("missing dependency: {}", missing.join(", "));
                    tracing::warn!(
                        plugin = %ns,
                        version = package.manifest.version,
                        source = "s3",
                        reason = %reason,
                        "[plugins] wasm reload: S3 plugin rejected"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&[ErrorKind::MissingExport.as_str()])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["s3", "rejected"])
                        .inc();
                    s3_rejected_items.push(LoadRejection {
                        plugin: ns.clone(),
                        kind: ErrorKind::MissingExport.as_str().to_string(),
                        reason,
                    });
                    retained +=
                        retain_previous(rt, &host, &prev, &ns, &mut new_dir, &mut new_pg, &mut new_s3);
                    continue;
                }
                let status = package.signature_status(&trusted_keys);
                rt.metrics
                    .plugin_wasm_signature_total
                    .with_label_values(&[status.check.as_str()])
                    .inc();
                match host.register(package.clone()) {
                    Ok(info) => {
                        tracing::info!(
                            plugin = %info.short_name,
                            version = info.version,
                            source = "s3",
                            signature = info.signature.as_str(),
                            trusted = info.trusted,
                            wasm_bytes = info.wasm_bytes,
                            "[plugins] WASM plugin registered from S3"
                        );
                        rt.metrics
                            .plugin_wasm_source_total
                            .with_label_values(&["s3", "loaded"])
                            .inc();
                        new_s3.push(package);
                    }
                    Err(e) => {
                        tracing::warn!(
                            plugin = e.plugin().unwrap_or(&ns),
                            version = package.manifest.version,
                            source = "s3",
                            kind = e.kind().as_str(),
                            reason = %e,
                            "[plugins] wasm reload: S3 plugin rejected"
                        );
                        rt.metrics
                            .plugin_wasm_rejected_total
                            .with_label_values(&[e.kind().as_str()])
                            .inc();
                        rt.metrics
                            .plugin_wasm_source_total
                            .with_label_values(&["s3", "rejected"])
                            .inc();
                        s3_rejected_items.push(LoadRejection {
                            plugin: e.plugin().unwrap_or(&ns).to_string(),
                            kind: e.kind().as_str().to_string(),
                            reason: e.to_string(),
                        });
                        retained += retain_previous(
                            rt,
                            &host,
                            &prev,
                            &ns,
                            &mut new_dir,
                            &mut new_pg,
                            &mut new_s3,
                        );
                    }
                }
            }
        }

        // ---- canary candidates (separate canary host; directory priority/dependency existence same as stable) ----
        {
            let mut known: BTreeSet<String> = dir_names.clone();
            known.extend(pg_known.iter().cloned());
            known.extend(new_s3.iter().map(|p| p.short_name().to_string()));
            for package in &canary {
                known.insert(package.short_name().to_string());
            }
            for package in canary {
                let ns = package.short_name().to_string();
                if dir_names.contains(&ns) {
                    tracing::warn!(
                        plugin = %ns,
                        version = package.manifest.version,
                        source = "pg",
                        route = "canary",
                        "[plugins] directory plugin takes precedence over PG canary row (dir > pg); canary row skipped"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&["conflict"])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "rejected"])
                        .inc();
                    conflicts += 1;
                    canary_rejected_items.push(LoadRejection {
                        plugin: ns.clone(),
                        kind: "conflict".to_string(),
                        reason: "directory plugin with the same ns takes precedence (dir > pg)"
                            .to_string(),
                    });
                    continue;
                }
                let missing: Vec<String> = package
                    .manifest
                    .deps
                    .iter()
                    .filter(|d| !known.contains(d.as_str()))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    let reason = format!("missing dependency: {}", missing.join(", "));
                    tracing::warn!(
                        plugin = %ns,
                        version = package.manifest.version,
                        source = "pg",
                        route = "canary",
                        reason = %reason,
                        "[plugins] wasm reload: canary plugin rejected"
                    );
                    rt.metrics
                        .plugin_wasm_rejected_total
                        .with_label_values(&[ErrorKind::MissingExport.as_str()])
                        .inc();
                    rt.metrics
                        .plugin_wasm_source_total
                        .with_label_values(&["pg", "rejected"])
                        .inc();
                    canary_rejected_items.push(LoadRejection {
                        plugin: ns.clone(),
                        kind: ErrorKind::MissingExport.as_str().to_string(),
                        reason,
                    });
                    continue;
                }
                let status = package.signature_status(&trusted_keys);
                rt.metrics
                    .plugin_wasm_signature_total
                    .with_label_values(&[status.check.as_str()])
                    .inc();
                match canary_host.register(package.clone()) {
                    Ok(info) => {
                        tracing::info!(
                            plugin = %info.short_name,
                            version = info.version,
                            route = "canary",
                            signature = info.signature.as_str(),
                            trusted = info.trusted,
                            "WASM canary plugin registered (gray routing host)"
                        );
                        rt.metrics
                            .plugin_wasm_source_total
                            .with_label_values(&["pg", "canary_loaded"])
                            .inc();
                        new_canary.push(package);
                    }
                    Err(e) => {
                        // A bad canary upgrade does not roll back the old canary: the routing side falls back to stable when it finds it unavailable (safe).
                        tracing::warn!(
                            plugin = e.plugin().unwrap_or(&ns),
                            version = package.manifest.version,
                            route = "canary",
                            kind = e.kind().as_str(),
                            reason = %e,
                            "[plugins] wasm reload: canary plugin rejected (routing falls back to stable)"
                        );
                        rt.metrics
                            .plugin_wasm_rejected_total
                            .with_label_values(&[e.kind().as_str()])
                            .inc();
                        rt.metrics
                            .plugin_wasm_source_total
                            .with_label_values(&["pg", "rejected"])
                            .inc();
                        canary_rejected_items.push(LoadRejection {
                            plugin: e.plugin().unwrap_or(&ns).to_string(),
                            kind: e.kind().as_str().to_string(),
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }

        let loaded = host.plugins().len();
        let canary_loaded = canary_host.plugins().len();
        let from_dir = new_dir.len();
        let from_pg = new_pg.len();
        let from_s3 = new_s3.len();
        let rejected = dir_rejected_items.len()
            + pg_rejected_items.len()
            + s3_rejected_items.len()
            + canary_rejected_items.len();
        let mut final_pg_status = match pg_status {
            Some(status) => status,
            None => prev_pg_status,
        };
        final_pg_status.loaded = from_pg;
        final_pg_status.rejected = pg_rejected_items.len();
        final_pg_status.canary_loaded = new_canary.len();
        final_pg_status.canary_rejected = canary_rejected_items.len();
        final_pg_status.conflicts = conflicts;
        final_pg_status.skipped = skipped;
        let mut final_s3_status = match s3_status {
            Some(status) => status,
            None => prev_s3_status,
        };
        final_s3_status.loaded = from_s3;
        final_s3_status.rejected = s3_rejected_items.len();
        final_s3_status.conflicts = conflicts.saturating_sub(final_pg_status.conflicts);
        Ok(SnapshotParts {
            host,
            canary_host,
            dir_packages: new_dir,
            pg_packages: new_pg,
            s3_packages: new_s3,
            canary_packages: new_canary,
            dir_names,
            dir_rejected: dir_rejected_items,
            pg_rejected: pg_rejected_items,
            s3_rejected: s3_rejected_items,
            canary_rejected: canary_rejected_items,
            pg_status: final_pg_status,
            s3_status: final_s3_status,
            loaded,
            from_dir,
            from_pg,
            from_s3,
            canary_loaded,
            rejected,
            conflicts,
            retained,
            skipped,
        })
    }

    /// Commit the new snapshot: generation+1, flush state, **one write swap** (in-flight invokes finish on the old Arc).
    fn commit_reload(
        rt: &Arc<WasmRuntime>,
        parts: SnapshotParts,
        source: ReloadSource,
        started: Instant,
    ) -> ReloadOutcome {
        let SnapshotParts {
            host,
            canary_host,
            dir_packages,
            pg_packages,
            s3_packages,
            canary_packages,
            dir_names,
            dir_rejected,
            pg_rejected,
            s3_rejected,
            canary_rejected,
            pg_status,
            s3_status,
            loaded,
            from_dir,
            from_pg,
            from_s3,
            canary_loaded,
            rejected,
            conflicts,
            retained,
            skipped,
        } = parts;
        let verified = host.plugins().iter().filter(|p| p.trusted).count();
        // Write the snapshot state first (generation/details), then swap the host: both happen inside reload_gate, so readers see at most an
        // extremely short window of "old host + new counters" and never a half-assembled registry (invoke reads only the host).
        let outcome = {
            let mut state = rt.state();
            let generation = state.generation.saturating_add(1);
            let last_reload_at =
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let outcome = ReloadOutcome {
                source: source.as_str(),
                loaded,
                from_dir,
                from_pg,
                from_s3,
                canary_loaded,
                rejected,
                conflicts,
                retained,
                skipped,
                generation,
                elapsed_ms: started.elapsed().as_millis() as u64,
                last_reload_at: last_reload_at.clone(),
            };
            state.generation = generation;
            state.last_reload_at = Some(last_reload_at);
            state.last_reload = Some(outcome.to_json());
            state.dir_packages = dir_packages;
            state.pg_packages = pg_packages;
            state.s3_packages = s3_packages;
            state.canary_packages = canary_packages;
            state.dir_rejected = dir_rejected;
            state.pg_rejected = pg_rejected;
            state.s3_rejected = s3_rejected;
            state.canary_rejected = canary_rejected;
            state.pg = pg_status;
            state.s3 = s3_status;
            state.dir_names = dir_names;
            outcome
        };
        // Atomic swap: later invokes use the new host; running invokes finish on the old `Arc<WasmHost>`,
        // uninterrupted and without seeing a half-assembled state. The stable/canary locks are each written once (invoke reads stable, then
        // canary within an extremely short window that may span snapshots, so at worst one route lands on a "mixed old/new" state — therefore canary is written first
        // and stable after: canary decisions read the stable snapshot while canary is already newest, so a false fallback from a missing canary cannot occur).
        *rt.canary_host.write().unwrap_or_else(|e| e.into_inner()) = canary_host;
        *rt.host.write().unwrap_or_else(|e| e.into_inner()) = host;
        rt.metrics.plugin_wasm_loaded.set(outcome.loaded as i64);
        rt.metrics.plugin_wasm_verified.set(verified as i64);
        rt.metrics
            .plugin_wasm_reload_total
            .with_label_values(&["ok"])
            .inc();
        rt.metrics
            .plugin_wasm_reload_duration
            .observe(started.elapsed().as_secs_f64());
        tracing::info!(
            source = outcome.source,
            generation = outcome.generation,
            loaded = outcome.loaded,
            from_dir = outcome.from_dir,
            from_pg = outcome.from_pg,
            from_s3 = outcome.from_s3,
            canary_loaded = outcome.canary_loaded,
            rejected = outcome.rejected,
            conflicts = outcome.conflicts,
            retained = outcome.retained,
            skipped = outcome.skipped,
            elapsed_ms = outcome.elapsed_ms,
            "[plugins] WASM plugin registry reloaded (atomic swap)"
        );
        outcome
    }

    /// Admin implementation of `POST /v1/admin/plugins/wasm/reload` (PL-10 hot reload).
    ///
    /// Flow: concurrency mutex (409) → rate limit (429) → wait for the startup PG load → read sources (hard failure 500) →
    /// assemble the new host via `spawn_blocking` → one swap. Failure paths **never modify the current registry**.
    pub async fn reload(
        st: &Arc<AppState>,
        source: ReloadSource,
    ) -> Result<ReloadOutcome, ReloadFailure> {
        let Some(rt) = runtime() else {
            if let Some(err) = INIT_ERROR.get() {
                return Err(reload_failure(
                    "not_initialized",
                    500,
                    format!("wasm plugin host init failed: {err}"),
                ));
            }
            return Err(reload_failure(
                "wasm_host_disabled",
                422,
                "wasm plugin host is not enabled on this node (see GET /v1/admin/plugins)",
            ));
        };
        let started = Instant::now();
        // Concurrency mutex: only one reload at a time (duplicate requests get 409 immediately, no queueing).
        let _gate = match rt.reload_gate.try_lock() {
            Ok(gate) => gate,
            Err(_) => {
                count_reload_metric(&rt, "error");
                tracing::warn!(
                    source = source.as_str(),
                    "[plugins] wasm reload rejected: another reload is already in progress"
                );
                return Err(reload_failure(
                    "reload_in_progress",
                    409,
                    "another wasm plugin reload is already in progress",
                ));
            }
        };
        // Rate limit: 1/s (success and failure both consume the window).
        {
            let mut state = rt.state();
            if let Some(last) = state.last_attempt {
                let elapsed = last.elapsed().as_millis() as u64;
                if elapsed < RELOAD_MIN_INTERVAL_MS {
                    drop(state);
                    count_reload_metric(&rt, "error");
                    let retry_in = RELOAD_MIN_INTERVAL_MS - elapsed;
                    tracing::warn!(
                        source = source.as_str(),
                        retry_in_ms = retry_in,
                        "[plugins] wasm reload rejected: rate limited (1/s)"
                    );
                    return Err(reload_failure(
                        "rate_limited",
                        429,
                        format!("wasm plugin reload is limited to 1/s; retry in {retry_in}ms"),
                    ));
                }
            }
            state.last_attempt = Some(started);
        }
        // Wait for the startup async PG/S3 load first (avoids losing startup results/racing the new snapshot).
        if rt.from_db || rt.s3.is_some() {
            wait_startup_sources(&rt).await;
        }
        // Read sources → candidate plan (hard failure: old snapshot unchanged + 500 with reason).
        let plan = match plan_reload(st, &rt, source).await {
            Ok(plan) => plan,
            Err(fail) => {
                count_reload_metric(&rt, "error");
                rt.metrics
                    .plugin_wasm_reload_duration
                    .observe(started.elapsed().as_secs_f64());
                tracing::warn!(
                    source = source.as_str(),
                    reason = fail.reason,
                    error = %fail.message,
                    "[plugins] wasm reload failed; keeping the current registry snapshot"
                );
                return Err(fail);
            }
        };
        // Assemble the new host (compilation on the blocking pool; runtime stays on the old snapshot meanwhile, invoke unaffected).
        let prev_pg_status = rt.state().pg.clone();
        let prev_s3_status = rt.state().s3.clone();
        let rt_bg = rt.clone();
        let spawned = tokio::task::spawn_blocking(move || {
            assemble_reload(&rt_bg, plan, prev_pg_status, prev_s3_status)
        })
        .await;
        let parts = match spawned {
            Ok(Ok(parts)) => parts,
            Ok(Err(fail)) => {
                count_reload_metric(&rt, "error");
                rt.metrics
                    .plugin_wasm_reload_duration
                    .observe(started.elapsed().as_secs_f64());
                tracing::warn!(
                    source = source.as_str(),
                    reason = fail.reason,
                    error = %fail.message,
                    "[plugins] wasm reload failed; keeping the current registry snapshot"
                );
                return Err(fail);
            }
            Err(e) => {
                count_reload_metric(&rt, "error");
                rt.metrics
                    .plugin_wasm_reload_duration
                    .observe(started.elapsed().as_secs_f64());
                tracing::error!(error = %e, "[plugins] wasm reload blocking task failed; keeping the current registry snapshot");
                return Err(reload_failure(
                    "host_init",
                    500,
                    format!("wasm reload blocking task failed: {e}"),
                ));
            }
        };
        Ok(commit_reload(&rt, parts, source, started))
    }

    fn runtime() -> Option<Arc<WasmRuntime>> {
        RUNTIME.get().cloned()
    }

    /// The `wasm` field appended by `GET /v1/admin/plugins` (also what the task card calls "`GET /v1/admin/plugins.wasm`").
    ///
    /// Hot-reload-visible fields: `generation` (snapshot id, monotonically increasing), `last_reload_at` (time of the most recent successful
    /// hot reload; startup loading does not count → `null`), `last_reload` (most recent success summary),
    /// `reload_min_interval_ms` (the 1/s rate-limit window); source counts are in `sources.{dir,pg}`.
    /// **Excludes** wasm bytes, signature bodies, and public keys.
    pub fn wasm_status() -> Value {
        let Some(rt) = runtime() else {
            if let Some(err) = INIT_ERROR.get() {
                return json!({
                    "enabled": false,
                    "compiled": true,
                    "error": err,
                });
            }
            if let Some(reason) = DISABLED_REASON.get() {
                return json!({
                    "enabled": false,
                    "compiled": true,
                    "reason": reason,
                });
            }
            return json!({
                "enabled": false,
                "compiled": true,
                "reason": "wasm plugin host not initialized",
            });
        };
        let host = rt.host();
        let canary_host = rt.canary_host();
        let security = host.security_report();
        // Clone the snapshot data first, then lock items one by one (no host calls inside the `state` lock, avoiding lock-order issues).
        let loaded = host.plugins();
        let metrics = host.metrics();
        let canary_metrics = canary_host.metrics();
        let canary_loaded = canary_host.plugins();
        let (
            generation,
            last_reload_at,
            last_reload,
            dir_loaded,
            dir_rejected,
            pg,
            s3,
            rejected,
            canary_requests,
            canary_routed,
            stable_routed,
            canary_fallbacks,
        ) = {
            let state = rt.state();
            let mut rejected: Vec<LoadRejection> = Vec::with_capacity(
                state.dir_rejected.len()
                    + state.pg_rejected.len()
                    + state.s3_rejected.len()
                    + state.canary_rejected.len(),
            );
            rejected.extend(state.dir_rejected.iter().cloned());
            rejected.extend(state.pg_rejected.iter().cloned());
            rejected.extend(state.s3_rejected.iter().cloned());
            rejected.extend(state.canary_rejected.iter().cloned());
            (
                state.generation,
                state.last_reload_at.clone(),
                state.last_reload.clone(),
                state.dir_packages.len(),
                state.dir_rejected.len(),
                state.pg.clone(),
                state.s3.clone(),
                rejected,
                state.canary_requests,
                state.canary_routed,
                state.stable_routed,
                state.canary_fallbacks,
            )
        };
        // Canary targets (read live from the `AppState.plugins` memory view; admin canary actions refresh it).
        let canary_targets: Vec<Value> = rt
            .state_ref
            .upgrade()
            .and_then(|st| st.plugins.read().ok().map(|entries| {
                entries
                    .iter()
                    .filter(|e| {
                        e.status == lattice_plugins::registry::PluginStatus::Canary
                            && e.canary_ratio > 0
                    })
                    .map(|e| {
                        json!({
                            "ns": short_ns(&e.ns),
                            "version": e.version,
                            "ratio": e.canary_ratio.min(100),
                        })
                    })
                    .take(64)
                    .collect::<Vec<_>>()
            }))
            .unwrap_or_default();
        // Zero-knowledge runtime probe (E25): mode + content-plugin allowlist status (directly assertable by E2E/operations;
        // without any wasm/payload/keys). `mode` reads the node's live config (fixed at startup).
        let mode = rt
            .state_ref
            .upgrade()
            .map(|st| match st.mode() {
                lattice_core::Mode::Inspectable => "inspectable",
                lattice_core::Mode::ZeroKnowledge => "zero-knowledge",
            })
            .unwrap_or("unknown");
        let content_plugins_allowed = rt.host_config.allow_content_plugins;
        json!({
            "enabled": true,
            "compiled": true,
            "wasm_dir": rt.wasm_dir,
            // Zero-knowledge runtime probe (E25): in zero-knowledge mode content plugins are fail-closed at the registration entry.
            "mode": mode,
            "content_plugins": {
                "allowed": content_plugins_allowed,
                "policy": if content_plugins_allowed { "inspectable" } else { "zero_knowledge" },
                "classifier": "ns_prefix",
                "prefixes": lattice_plugins::wasm::CONTENT_PLUGIN_NS_PREFIXES,
                "note": "content plugins (convert:/transcode:/format:/detect:) are fail-closed in zero-knowledge mode",
            },
            "require_verified_signature": rt.require_verified_signature,
            "signature_verification": "ed25519_ring",
            "trusted_keys": rt.trusted_key_ids.len(),
            "trusted_key_ids": rt.trusted_key_ids,
            // Source diagnostics (PL-10 added the PG registry): the `from_db` switch + load/reject counts per source.
            "from_db": rt.from_db,
            "max_wasm_bytes": rt.max_wasm_bytes,
            // Pooling (E25): pool size/prewarm/hit/miss/queue/reject are in metrics.pool_*.
            "pool": {
                "size": rt.host_config.effective_pool_size(),
                "prewarmed": rt.host_config.effective_prewarm(),
                "max_instances_per_store": rt.host_config.effective_instances_per_store(),
                "queue_timeout_ms": rt.host_config.queue_timeout.as_millis() as u64,
            },
            // Canary routing (E25): switch + route counters + currently effective canary targets (without package content).
            "canary": {
                "enabled": rt.canary.enabled,
                "salt_set": !rt.canary.salt.is_empty(),
                "requests": canary_requests,
                "routed_canary": canary_routed,
                "routed_stable": stable_routed,
                "fallbacks": canary_fallbacks,
                "loaded": canary_loaded,
                "targets": canary_targets,
                "metrics": canary_metrics,
            },
            // Hot reload (PL-10 hot reload): snapshot id + time/summary of the most recent successful reload (failures do not increment).
            "generation": generation,
            "last_reload_at": last_reload_at,
            "last_reload": last_reload,
            "reload_min_interval_ms": RELOAD_MIN_INTERVAL_MS,
            "sources": {
                "dir": { "loaded": dir_loaded, "rejected": dir_rejected },
                "pg": pg.to_json(),
                "s3": s3.to_json(),
            },
            "loaded": loaded,
            "rejected": rejected,
            "security": security,
            "metrics": metrics,
        })
    }

    /// Admin invoke: only trusted (signature-verified) plugins can be invoked.
    ///
    /// Hot-reload semantics: on entry `host()` clones the current snapshot `Arc`, and the whole call (including queueing/execution) completes on that
    /// snapshot; the reload swap never interrupts a running call (the old host is released with the last in-flight call).
    pub fn invoke(
        ns: &str,
        input: &[u8],
        entry: Option<&str>,
    ) -> Result<InvokeOutcome, InvokeFailure> {
        let Some(rt) = runtime() else {
            return Err(InvokeFailure::new(
                "not_found",
                422,
                "wasm plugin host is not enabled on this node (see GET /v1/admin/plugins)",
            ));
        };
        // Zero-knowledge content-plugin gate (defense in depth): normally `register` already fails closed,
        // but this re-blocks any abnormal/leftover state and exposes the low-cardinality reason as `zero_knowledge`.
        if !rt.host_config.allow_content_plugins {
            if let Some(class) = lattice_plugins::wasm::content_plugin_class(ns) {
                return Err(InvokeFailure::new(
                    "zero_knowledge",
                    422,
                    format!(
                        "content plugin class `{}` is blocked in zero-knowledge mode \
                         (audit/conversion requires inspectable mode)",
                        class.trim_end_matches(':')
                    ),
                ));
            }
        }
        // Canary decision: first pick stable/canary from the request hash (off by default → stable), then verify trusted
        // in the target host. The two hosts hold separate snapshots: in-flight calls are unaffected by a reload swap.
        let route = rt.decide_route(ns, entry.unwrap_or(""), input);
        {
            let mut state = rt.state();
            state.canary_requests = state.canary_requests.saturating_add(1);
            match route {
                HostRoute::Canary => state.canary_routed = state.canary_routed.saturating_add(1),
                HostRoute::Stable => state.stable_routed = state.stable_routed.saturating_add(1),
            }
        }
        let (host, route_str) = match route {
            HostRoute::Canary => (rt.canary_host(), HostRoute::Canary.as_str()),
            HostRoute::Stable => (rt.host(), HostRoute::Stable.as_str()),
        };
        let Some(info) = host.info(ns) else {
            // The unregistered plugin name comes from the request (admin plane) and cannot be a metric label (unbounded cardinality):
            // all such cases are recorded under the fixed label `_not_registered`, and the exact ns goes only to audit/error bodies.
            rt.metrics
                .plugin_wasm_invocations_total
                .with_label_values(&["_not_registered", "not_found"])
                .inc();
            return Err(InvokeFailure::new(
                "not_found",
                422,
                format!("wasm plugin `{ns}` is not registered"),
            ));
        };
        if !info.trusted {
            rt.metrics
                .plugin_wasm_invocations_total
                .with_label_values(&[ns, "not_verified"])
                .inc();
            return Err(InvokeFailure::new(
                "not_verified",
                422,
                format!(
                    "wasm plugin `{ns}` is not verified ({}); only Ed25519-verified plugins are invokable",
                    info.signature_detail
                ),
            ));
        }
        let entry_used = entry.unwrap_or(&info.entry).to_string();
        match host.call_entry(ns, entry, input) {
            Ok(out) => Ok(InvokeOutcome {
                output: out.output,
                plugin: out.plugin,
                version: out.version,
                entry: entry_used,
                elapsed_ms: out.elapsed_ms,
                fuel_used: out.fuel_used,
                route: route_str,
            }),
            Err(e) => {
                let kind = e.kind();
                // The on_call hook already recorded metrics; here we only add "host rejected" errors (early failures that never enter wasm
                // also go through the same hook via the host's internal record_failure, so they are not double-counted).
                Err(InvokeFailure::new(
                    reason_for_kind(kind),
                    http_status_for_kind(kind),
                    e.to_string(),
                ))
            }
        }
    }

    /// For tests/diagnostics: plugin info of the current snapshot host (empty when disabled).
    #[allow(dead_code)]
    pub fn plugins() -> Vec<PluginInfo> {
        runtime().map(|rt| rt.host().plugins()).unwrap_or_default()
    }

    /// For tests/diagnostics: convert a host error into InvokeFailure.
    #[allow(dead_code)]
    pub fn failure_from(e: &WasmError) -> InvokeFailure {
        InvokeFailure::new(
            reason_for_kind(e.kind()),
            http_status_for_kind(e.kind()),
            e.to_string(),
        )
    }
}

#[cfg(not(feature = "wasm-host"))]
mod stub_impl {
    use std::sync::Arc;

    use serde_json::{json, Value};

    use crate::state::AppState;

    use super::{InvokeFailure, InvokeOutcome, ReloadFailure, ReloadOutcome, ReloadSource};

    /// The `wasm-host` feature is not compiled: notify only, never block the node.
    /// The sidecar client is independent of the wasm feature and is still registered here (off by default → Noop).
    pub fn init(st: &AppState) {
        super::sidecar::init(st);
    }

    pub fn wasm_status() -> Value {
        json!({
            "enabled": false,
            "compiled": false,
            "reason": "binary built without the `wasm-host` feature; rebuild with \
                       `cargo build -p lattice-node --features wasm-host` to load wasm plugins",
        })
    }

    pub fn invoke(
        _ns: &str,
        _input: &[u8],
        _entry: Option<&str>,
    ) -> Result<InvokeOutcome, InvokeFailure> {
        Err(InvokeFailure::new(
            "wasm_host_disabled",
            422,
            "binary built without the `wasm-host` feature",
        ))
    }

    /// `wasm-host` not compiled: nothing to swap, so return 422 directly (consistent with the invoke stub semantics).
    pub async fn reload(
        _st: &Arc<AppState>,
        _source: ReloadSource,
    ) -> Result<ReloadOutcome, ReloadFailure> {
        Err(ReloadFailure::new(
            "wasm_host_disabled",
            422,
            "binary built without the `wasm-host` feature",
        ))
    }
}

#[cfg(feature = "wasm-host")]
pub use host_impl::{init, invoke, reload, wasm_status};
#[cfg(not(feature = "wasm-host"))]
pub use stub_impl::{init, invoke, reload, wasm_status};

#[cfg(all(test, feature = "wasm-host"))]
mod tests {
    use super::*;
    use lattice_plugins::wasm::ErrorKind;

    #[test]
    fn reasons_are_low_cardinality_and_map_to_expected_status() {
        assert_eq!(reason_for_kind(ErrorKind::NotFound), "not_found");
        assert_eq!(reason_for_kind(ErrorKind::Signature), "not_verified");
        assert_eq!(
            reason_for_kind(ErrorKind::ContentBlocked),
            "zero_knowledge",
            "Zero-knowledge mode content-plugin rejection reason (E25 probe contract)"
        );
        assert_eq!(reason_for_kind(ErrorKind::CircuitOpen), "circuit_open");
        assert_eq!(reason_for_kind(ErrorKind::Timeout), "timeout");
        assert_eq!(reason_for_kind(ErrorKind::Trap), "trap");
        assert_eq!(reason_for_kind(ErrorKind::Memory), "memory");
        assert_eq!(reason_for_kind(ErrorKind::Fuel), "fuel");
        assert_eq!(http_status_for_kind(ErrorKind::NotFound), 422);
        assert_eq!(http_status_for_kind(ErrorKind::Signature), 422);
        assert_eq!(
            http_status_for_kind(ErrorKind::ContentBlocked),
            422,
            "Zero-knowledge mode rejection is a deployment policy (422), not an execution failure 500"
        );
        assert_eq!(http_status_for_kind(ErrorKind::CircuitOpen), 500);
        assert_eq!(http_status_for_kind(ErrorKind::Timeout), 500);
        assert_eq!(http_status_for_kind(ErrorKind::Internal), 500);
    }

    #[test]
    fn invoke_failure_carries_reason_and_status() {
        let f = InvokeFailure::new("not_found", 422, "plugin x not registered");
        assert_eq!(f.reason, "not_found");
        assert_eq!(f.http_status, 422);
        assert!(f.message.contains("not registered"));
    }

    #[test]
    fn wasm_status_reports_disabled_without_feature_or_before_init() {
        // Unit tests do not run node::build → uninitialized; with the feature off it must also return enabled=false.
        let v = wasm_status();
        assert_eq!(v["enabled"], serde_json::json!(false));
        assert!(v.get("compiled").is_some());
    }

    // ------------------------------------------------------------------
    // PG `plugins` registry (pure-function unit tests: version selection / manifest construction / signature fields)
    // ------------------------------------------------------------------

    fn pg_row(ns: &str, version: i32, status: &str) -> crate::store::pg::PluginWasmRow {
        crate::store::pg::PluginWasmRow {
            id: format!("{ns}-{version}"),
            ns: ns.to_string(),
            version,
            status: status.to_string(),
            wasm: b"\0asm\x01\0\0\0".to_vec(),
            signature: Vec::new(),
            config: serde_json::json!({}),
        }
    }

    fn trusted_keys_of(ids: &[&str]) -> lattice_plugins::wasm::TrustedKeys {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        lattice_plugins::wasm::TrustedKeys::from_b64_map(
            ids.iter().map(|id| ((*id).to_string(), b64.clone())),
        )
        .expect("32B base64 public key");
    }

    #[test]
    fn pg_selection_picks_max_active_version_and_ignores_canary() {
        let rows = vec![
            pg_row("alpha", 3, "canary"),
            pg_row("alpha", 2, "active"),
            pg_row("alpha", 1, "active"),
            pg_row("beta", 5, "active"),
            pg_row("beta", 5, "active"), // duplicate row for the same version (defense beyond the unique constraint)
            pg_row("gamma", 1, "canary"),
        ];
        let ratios = std::collections::BTreeMap::new();
        let sel = super::host_impl::select_pg_candidates(&rows, &ratios, false);
        let chosen: Vec<(&str, i32)> = sel
            .selected
            .iter()
            .map(|i| (rows[*i].ns.as_str(), rows[*i].version))
            .collect();
        assert_eq!(chosen, vec![("alpha", 2), ("beta", 5)], "same ns → highest active version");
        assert!(
            sel.selected_canary.is_empty(),
            "canary versions must not be loaded when canary is off"
        );
        assert_eq!(
            sel.canary_ignored,
            vec![("alpha".to_string(), 3), ("gamma".to_string(), 1)],
            "canary off: canary rows ignored and recorded (same as the old behavior)"
        );
        // alpha v1 + beta's duplicate v5 go to lower_versions (duplicate same-version rows ignored)
        assert_eq!(sel.lower_versions.len(), 2, "{:?}", sel.lower_versions);
        assert!(sel.lower_versions.contains(&("alpha".to_string(), 1)));
        assert!(sel.lower_versions.contains(&("beta".to_string(), 5)));
    }

    #[test]
    fn pg_selection_loads_canary_only_when_enabled_and_ratio_positive() {
        let rows = vec![
            pg_row("alpha", 3, "canary"),
            pg_row("alpha", 2, "active"),
            pg_row("beta", 7, "canary"),
            pg_row("beta", 6, "canary"),
            pg_row("beta", 5, "active"),
            pg_row("gamma", 1, "canary"),
        ];
        let mut ratios = std::collections::BTreeMap::new();
        ratios.insert(("alpha".to_string(), 3), 50u8);
        ratios.insert(("beta".to_string(), 7), 100u8);
        ratios.insert(("beta".to_string(), 6), 50u8);
        // gamma has no ratio → treated as 0 (not loaded)
        let sel = super::host_impl::select_pg_candidates(&rows, &ratios, true);
        let stable: Vec<(&str, i32)> = sel
            .selected
            .iter()
            .map(|i| (rows[*i].ns.as_str(), rows[*i].version))
            .collect();
        assert_eq!(stable, vec![("alpha", 2), ("beta", 5)]);
        let canary: Vec<(&str, i32)> = sel
            .selected_canary
            .iter()
            .map(|i| (rows[*i].ns.as_str(), rows[*i].version))
            .collect();
        assert_eq!(
            canary,
            vec![("alpha", 3), ("beta", 7)],
            "canary takes the highest version; a higher version of the same ns wins"
        );
        assert!(
            sel.canary_ignored
                .contains(&("gamma".to_string(), 1)),
            "canary rows with ratio=0 are still ignored and recorded: {:?}",
            sel.canary_ignored
        );
        assert!(
            sel.canary_lower_versions.contains(&("beta".to_string(), 6)),
            "lower canary versions are ignored: {:?}",
            sel.canary_lower_versions
        );
    }

    #[test]
    fn pg_manifest_from_config_fields_and_canonical_contract() {
        let mut row = pg_row("pg-echo", 3, "active");
        row.config = serde_json::json!({
            "entry": "",
            "deps": ["base@1"],
            "limits": {"memory_mb": 8, "fuel": 1000, "timeout_ms": 250},
            "signing_key_id": "k1"
        });
        let keys = trusted_keys_of(&["k1"]);
        let pkg = super::host_impl::package_from_pg_row(&row, &keys).expect("valid config");
        assert_eq!(pkg.manifest.ns, "pg-echo");
        assert_eq!(pkg.manifest.version, 3);
        assert_eq!(pkg.manifest.entry, "");
        assert_eq!(pkg.manifest.deps, vec!["base@1".to_string()]);
        assert_eq!(pkg.manifest.limits.memory_mb, 8);
        assert_eq!(pkg.manifest.limits.fuel, 1000);
        assert_eq!(pkg.manifest.limits.timeout_ms, 250);
        assert_eq!(pkg.manifest.signing_key_id.as_deref(), Some("k1"));
        assert!(pkg.signature.is_none(), "empty signature bytea = unsigned");
        // The signing payload must be byte-identical to the directory source (canonical contract).
        assert_eq!(
            String::from_utf8(pkg.manifest.canonical_payload()).unwrap(),
            r#"{"ns":"pg-echo","version":3,"entry":"","deps":["base@1"],"limits":{"memory_mb":8,"fuel":1000,"timeout_ms":250}}"#
        );
        // Verification result (unsigned → Missing; rejected by the host when require=true)
        assert_eq!(
            pkg.signature_status(&keys).check,
            lattice_plugins::manifest::SignatureCheck::Missing
        );
    }

    #[test]
    fn pg_manifest_defaults_limits_zero_means_host_default() {
        let row = pg_row("pg-basic", 1, "active");
        let pkg = super::host_impl::package_from_pg_row(&row, &trusted_keys_of(&["k1"]))
            .expect("empty config is valid");
        assert_eq!(pkg.manifest.entry, "", "empty entry → the host resolves the process export");
        assert!(pkg.manifest.deps.is_empty());
        assert_eq!(pkg.manifest.limits.memory_mb, 0, "0 = host default caps");
        assert_eq!(pkg.manifest.limits.fuel, 0);
        assert_eq!(pkg.manifest.limits.timeout_ms, 0);
        // Only one trusted key configured → use it when signing_key_id is not declared (unambiguous)
        assert_eq!(pkg.manifest.signing_key_id.as_deref(), Some("k1"));
    }

    #[test]
    fn pg_manifest_full_config_json_takes_precedence_and_requires_identity_match() {
        let mut row = pg_row("pg-full", 2, "active");
        row.config = serde_json::json!({
            "manifest": {
                "ns": "pg-full",
                "version": 2,
                "entry": "transform",
                "deps": [],
                "limits": {"memory_mb": 4, "fuel": 0, "timeout_ms": 0}
            }
        });
        let keys = trusted_keys_of(&["k1"]);
        let pkg = super::host_impl::package_from_pg_row(&row, &keys).expect("complete manifest");
        assert_eq!(pkg.manifest.entry, "transform");
        assert_eq!(pkg.manifest.limits.memory_mb, 4);

        // ns / version inconsistent with the row = cross-package risk, must be rejected
        let mut bad = row.clone();
        bad.config = serde_json::json!({"manifest": {"ns": "other", "version": 2}});
        assert!(super::host_impl::package_from_pg_row(&bad, &keys)
            .unwrap_err()
            .contains("does not match"));
        let mut bad2 = row.clone();
        bad2.config = serde_json::json!({"manifest": {"ns": "pg-full", "version": 9}});
        assert!(super::host_impl::package_from_pg_row(&bad2, &keys)
            .unwrap_err()
            .contains("does not match"));
    }

    #[test]
    fn pg_signature_bytea_is_authoritative_and_two_keys_need_explicit_id() {
        use base64::Engine as _;
        let mut row = pg_row("pg-sig", 1, "active");
        row.signature = vec![7u8; 64];
        row.config = serde_json::json!({
            "manifest": {
                "ns": "pg-sig",
                "version": 1,
                "signature": base64::engine::general_purpose::STANDARD.encode([1u8; 64]),
                "signing_key_id": "k1"
            }
        });
        let keys = trusted_keys_of(&["k1"]);
        let pkg = super::host_impl::package_from_pg_row(&row, &keys).unwrap();
        assert_eq!(
            pkg.signature.as_deref(),
            Some(&[7u8; 64][..]),
            "the plugins.signature bytea is authoritative and overrides an embedded manifest signature"
        );
        // 64B but content mismatch → Invalid (not Missing; a bad signature is treated as tampering)
        assert_eq!(
            pkg.signature_status(&keys).check,
            lattice_plugins::manifest::SignatureCheck::Invalid
        );

        // Multiple keys and no declared signing_key_id: do not guess a key (Missing → fail-closed reject)
        let mut row2 = pg_row("pg-two", 1, "active");
        row2.signature = vec![7u8; 64];
        let keys2 = trusted_keys_of(&["k1", "k2"]);
        let pkg2 = super::host_impl::package_from_pg_row(&row2, &keys2).unwrap();
        assert!(pkg2.manifest.signing_key_id.is_none());
        assert_eq!(
            pkg2.signature_status(&keys2).check,
            lattice_plugins::manifest::SignatureCheck::Missing
        );
        // Unsigned (empty bytea) also counts as Missing
        let mut row3 = pg_row("pg-unsigned", 1, "active");
        row3.config = serde_json::json!({"signing_key_id": "k1"});
        let pkg3 = super::host_impl::package_from_pg_row(&row3, &keys).unwrap();
        assert!(pkg3.signature.is_none());
        assert_eq!(pkg3.signature_status(&keys).detail, "no_signature");
    }

    #[test]
    fn pg_manifest_rejects_invalid_config_and_version() {
        let keys = trusted_keys_of(&["k1"]);
        let row = pg_row("pg-bad", 0, "active");
        assert!(super::host_impl::package_from_pg_row(&row, &keys)
            .unwrap_err()
            .contains("must be > 0"));

        let mut row2 = pg_row("pg-bad", 1, "active");
        row2.config = serde_json::json!({"deps": "not-an-array"});
        assert!(super::host_impl::package_from_pg_row(&row2, &keys)
            .unwrap_err()
            .contains("deps"));

        // A non-object config (an array in jsonb) must also be rejected, not panic
        let mut row3 = pg_row("pg-bad", 1, "active");
        row3.config = serde_json::json!([1, 2, 3]);
        assert!(super::host_impl::package_from_pg_row(&row3, &keys)
            .unwrap_err()
            .contains("JSON object"));

        // Invalid manifest JSON structure (wrong version type)
        let mut row4 = pg_row("pg-bad", 1, "active");
        row4.config = serde_json::json!({"manifest": {"ns": "pg-bad", "version": "x"}});
        assert!(super::host_impl::package_from_pg_row(&row4, &keys).is_err());
    }
}

/// Sidecar wiring unit tests (run in the default build; independent of the wasm-host feature and needing no network).
#[cfg(test)]
mod sidecar_tests {
    use std::time::Duration;

    use lattice_plugins::sidecar::{PluginError, ProcessReq};

    use crate::config::SidecarCfg;

    use super::sidecar;

    #[test]
    fn options_default_plaintext_maps_500ms_30s() {
        let mut cfg = SidecarCfg::default();
        cfg.enabled = true;
        cfg.endpoint = "http://127.0.0.1:19090".into();
        let opts = sidecar::options(&cfg).expect("plaintext config is valid (dev only; init WARNs)");
        assert_eq!(opts.endpoint, "http://127.0.0.1:19090");
        assert!(opts.tls.is_none());
        assert_eq!(opts.timeout, Duration::from_millis(500), "⑤ §10 timeout 500ms");
        assert_eq!(
            opts.circuit_break,
            Duration::from_secs(30),
            "⑤ §10 circuit break 30s"
        );
        // 0 → default 500ms
        cfg.timeout_ms = 0;
        assert_eq!(
            sidecar::options(&cfg).unwrap().timeout,
            Duration::from_millis(500)
        );
    }

    #[test]
    fn options_mtls_requires_all_three_files() {
        let mut cfg = SidecarCfg::default();
        cfg.enabled = true;
        cfg.endpoint = "https://sidecar:19090".into();
        cfg.tls_ca = "/etc/lattice/tls/sidecar-ca.crt".into();
        cfg.tls_cert = "/etc/lattice/tls/sidecar-client.crt".into();
        cfg.tls_key = "/etc/lattice/tls/sidecar-client.key".into();
        let opts = sidecar::options(&cfg).expect("all three present = mTLS");
        let tls = opts.tls.expect("mTLS");
        assert_eq!(tls.ca_path, "/etc/lattice/tls/sidecar-ca.crt");
        assert_eq!(tls.cert_path, "/etc/lattice/tls/sidecar-client.crt");
        assert_eq!(tls.key_path, "/etc/lattice/tls/sidecar-client.key");

        // Only part configured: fail-closed (must not silently downgrade to plaintext)
        cfg.tls_key.clear();
        let err = sidecar::options(&cfg).expect_err("partial TLS must be rejected");
        assert!(err.contains("all set"), "the error should be actionable: {err}");
    }

    #[test]
    fn options_reject_empty_endpoint() {
        let mut cfg = SidecarCfg::default();
        cfg.enabled = true;
        let err = sidecar::options(&cfg).expect_err("enabled with an empty endpoint must error");
        assert!(err.contains("endpoint"), "{err}");
    }

    #[test]
    fn status_before_init_reports_disabled_noop() {
        // Unit tests do not run node::build → uninitialized: default off, Noop, and the 500ms/30s contract values are visible.
        let v = sidecar::status();
        assert_eq!(v["enabled"], serde_json::json!(false));
        assert_eq!(v["client"], serde_json::json!("noop"));
        assert_eq!(v["timeout_ms"], serde_json::json!(500));
        assert_eq!(v["circuit_break_secs"], serde_json::json!(30));
        assert_eq!(v["mtls"], serde_json::json!(false));
        // The status contains no certificate/key/payload fields
        let text = v.to_string();
        for forbidden in [
            "tls_ca", "tls_cert", "tls_key", "payload", "input", "output",
        ] {
            assert!(
                !text.contains(forbidden),
                "status must not contain {forbidden}: {text}"
            );
        }
    }

    #[tokio::test]
    async fn client_without_init_is_noop_passthrough() {
        // Sidecar not configured: callers get NoopSidecar → Failed (call sites pass through with "no converter").
        let client = sidecar::client();
        let err = client
            .process(ProcessReq {
                ns: "json".into(),
                op: "convert".into(),
                input: b"payload".to_vec(),
            })
            .await
            .expect_err("unconfigured must fail first (the caller then passes through)");
        assert!(matches!(err, PluginError::Failed { .. }));
        assert_eq!(err.reason(), "failed");
        assert!(err.to_string().contains("sidecar not configured"));
    }
}

/// Hot-reload request contract unit tests (independent of the `wasm-host` feature: parsing/error mapping/response shape are consistent across builds).
#[cfg(test)]
mod reload_tests {
    use super::{ReloadFailure, ReloadOutcome, ReloadSource};

    #[test]
    fn reload_source_parse_is_case_insensitive_and_defaults_to_all() {
        assert_eq!(ReloadSource::parse(""), Some(ReloadSource::All));
        assert_eq!(ReloadSource::parse("  ALL "), Some(ReloadSource::All));
        assert_eq!(ReloadSource::parse("all"), Some(ReloadSource::All));
        assert_eq!(ReloadSource::parse("dir"), Some(ReloadSource::Dir));
        assert_eq!(ReloadSource::parse("Pg"), Some(ReloadSource::Pg));
        assert_eq!(ReloadSource::parse("S3"), Some(ReloadSource::S3));
        assert_eq!(ReloadSource::parse("sidecar"), None);
        assert_eq!(ReloadSource::parse("all dir"), None);
    }

    #[test]
    fn reload_source_slices_are_consistent() {
        assert!(ReloadSource::All.includes_dir()
            && ReloadSource::All.includes_pg()
            && ReloadSource::All.includes_s3());
        assert!(ReloadSource::Dir.includes_dir() && !ReloadSource::Dir.includes_pg());
        assert!(!ReloadSource::Pg.includes_dir() && ReloadSource::Pg.includes_pg());
        assert!(
            ReloadSource::S3.includes_s3()
                && !ReloadSource::S3.includes_dir()
                && !ReloadSource::S3.includes_pg()
        );
        assert_eq!(ReloadSource::All.as_str(), "all");
        assert_eq!(ReloadSource::Dir.as_str(), "dir");
        assert_eq!(ReloadSource::Pg.as_str(), "pg");
        assert_eq!(ReloadSource::S3.as_str(), "s3");
    }

    #[test]
    fn reload_outcome_json_has_contract_fields_and_no_payload() {
        let out = ReloadOutcome {
            source: "all",
            loaded: 3,
            from_dir: 2,
            from_pg: 1,
            from_s3: 0,
            canary_loaded: 1,
            rejected: 1,
            conflicts: 0,
            retained: 1,
            skipped: 2,
            generation: 4,
            elapsed_ms: 7,
            last_reload_at: "2026-11-22T01:00:00.000Z".to_string(),
        };
        let v = out.to_json();
        assert_eq!(v["outcome"], "ok");
        assert_eq!(v["source"], "all");
        assert_eq!(v["loaded"], 3);
        assert_eq!(v["from_dir"], 2);
        assert_eq!(v["from_pg"], 1);
        assert_eq!(v["from_s3"], 0);
        assert_eq!(v["canary_loaded"], 1);
        assert_eq!(v["rejected"], 1);
        assert_eq!(v["conflicts"], 0);
        assert_eq!(v["retained"], 1);
        assert_eq!(v["skipped"], 2);
        assert_eq!(v["generation"], 4);
        assert_eq!(v["elapsed_ms"], 7);
        // Audit/response shape contract: must not return payload/keys/raw wasm
        let text = v.to_string();
        for forbidden in ["payload", "wasm_b64", "signature", "public_key", "input_b64"] {
            assert!(!text.contains(forbidden), "reload detail must not contain {forbidden}: {text}");
        }
    }

    #[test]
    fn reload_failure_json_is_low_cardinality() {
        let fail = ReloadFailure::new("pg_query", 500, "PG plugin registry query failed: boom");
        let v = fail.to_json();
        assert_eq!(v["outcome"], "error");
        assert_eq!(v["reason"], "pg_query");
        assert_eq!(v["http_status"], 500);
        assert!(v.to_string().contains("pg_query"));
    }
}