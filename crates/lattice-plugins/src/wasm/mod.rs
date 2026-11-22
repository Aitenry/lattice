//! WASM plugin host (design §4.5 / ② §4.5).
//!
//! ## What it does
//!
//! - Loads "`manifest.json` + wasm bytes + Ed25519 signature" plugin packages ([`PluginPackage`]);
//!   for the signature format and trust semantics see [`signature`]: signed body = `sha256(wasm || manifest_canonical_json)`;
//! - Compiles modules with wasmtime (once per plugin, [`Module`] reused); scheduling goes through a **bounded Store pool**
//!   ([`HostConfig::pool_size`] concurrent slots, with `pool_prewarm` pre-warmed):
//!   - **a fresh `Instance` per call** — linear memory/globals are not reused across calls, avoiding leftover data
//!     from one call leaking into the next (wasmtime `Store` has no instance reclamation API, so reusing an Instance leaks state);
//!   - **Store slot reuse**: fuel / epoch deadline / `StoreLimits` are reset per call to the plugin's effective limits;
//!     once a single Store has hosted [`HostConfig::max_instances_per_store`] instances it is recycled and rebuilt,
//!     which reuses resources without letting the instance arena grow unbounded;
//!   - when the pool is full, `call` queues within `queue_timeout` and returns `Busy` on timeout; `try_call` is immediately Busy;
//!     the metrics `pool_hits/pool_misses/pool_created/pool_recycled/queued_wait_total/busy_rejected`
//!     are visible in [`MetricsSnapshot`];
//! - Three hard limits (narrowed by the plugin manifest's `limits`; host config is the upper bound):
//!   - **memory**: `StoreLimits` 64MiB per instance (`memory.grow` beyond the limit traps immediately);
//!   - **instruction count**: wasmtime fuel, 100 million by default (`Trap::OutOfFuel`);
//!   - **wall clock**: epoch interruption, 500ms by default (separate ticker thread, 10ms precision,
//!     `Trap::Interrupt` attributed as timeout);
//! - Concurrency cap (default 8): `call` queues (with a wait cap), `try_call` returns `Busy` immediately;
//! - Failure circuit break (default 30s, per plugin `short_name`): after timeout / fuel / memory / trap / non-zero exit code,
//!   [`ErrorKind::CircuitOpen`] is returned directly inside the window; after the window calls pass again (a success resets it);
//! - Metric / log hooks ([`HostHooks`]): call latency, fuel consumption, failure attribution; **only lengths are recorded,
//!   payload is never printed**;
//! - Registry: in-memory ([`MemoryRegistry`]) and directory ([`DirRegistry`]) minimal implementations,
//!   with entry points to load published manifest+wasm; object storage/PG wiring is left to the node side.
//! - **Zero-knowledge content-plugin allowlist** (E25): [`HostConfig::allow_content_plugins`] allows them by default;
//!   the node sets it to `false` when `[policy] mode="zero-knowledge"`, and then the content plugins identified by [`content_plugin_class`]
//!   (`convert:*` / `transcode:*` / `format:*` / `detect:*`) are
//!   rejected fail-closed at the [`WasmHost::register`] entry ([`ErrorKind::ContentBlocked`]);
//!   they are neither compiled nor registered; `inspectable` deployments keep allowing them (audit/conversion is the point of that mode).
//! - **Format conversion + zero-copy passthrough** (E25, see [`convert`]): returns [`std::borrow::Cow::Borrowed`]
//!   when `src==dst`/there is no converter (no copy, no plugin call); only a `convert:<src>-><dst>` converter hit
//!   really executes; failure degrades to passthrough of the original bytes and reports a low-cardinality reason (never fakes success).
//!
//! ## Entry convention (ABI v1, no WASI)
//!
//! A plugin is a **core wasm module** (not a component), and the host links no imports, so plugins have
//! **no filesystem, network, clock, randomness, or environment variable** capability. Two entry points, pick one:
//!
//! 1. `process(input_ptr: i32, input_len: i32) -> i64` (recommended; supports input/output)
//!    - the module must export `memory`;
//!    - if it exports `alloc(len: i32) -> i32`, the host writes the input to the address returned by `alloc`;
//!      **without `alloc` only empty input is allowed** (the host never guesses or overwrites static plugin data);
//!    - the low 32 bits of the return value are the output pointer and the high 32 bits the output length (`u32` bit pattern); the host reads the output back
//!      from linear memory (length capped by [`HostConfig::max_output_bytes`]).
//! 2. `run() -> i32` (minimal entry, no input/output); returning 0 means success, non-zero counts as
//!    [`ErrorKind::ExitCode`].
//!
//! The manifest `entry` defaults to `process`; an `entry` ending in `.wasm` is treated as the wasm file name in the directory registry
//! (see [`DirRegistry`]), otherwise it is treated as the export function name (custom `process` names are supported).
//! Admin invoke can also override the entry name per request (`call_entry`; both the `process`/`run` ABIs are tried).
//!
//! ## Security boundary (**must not claim plugins execute safely**)
//!
//! - Done: no WASI import (no file/network/clock at all), hard instruction/memory/wall-clock limits, concurrency cap,
//!   failure circuit break, manifest required-field/static validation, optional content digest check, **Ed25519 signature verification** (ring):
//!   `trusted=true` can only come from [`SignatureCheck::Verified`] (trusted key + passing signature);
//!   unsigned/bad signature/unknown key is fail-closed under `require_verified_signature=true`;
//!   in zero-knowledge deployments content plugins are fail-closed at the registration entry (classification is by ns prefix convention, see
//!   the known gap in [`CONTENT_PLUGIN_NS_PREFIXES`]: the manifest has no explicit `class` field);
//! - **Not done (explicit gaps, see design §4.5)**: WASM sandbox escape drills, sidecar calls, real media format
//!   adaptation (detect/convert pipeline), **instance-level reuse** (wasmtime offers no instance reset/reclaim; reusing an
//!   Instance leaks linear memory/globals, so this implementation uses Store slot reuse + a fresh Instance per call,
//!   rebuilding a Store after N calls), cross-plugin dependency linking (`deps` is only an existence
//!   check, with no import resolution), signing private key custody/key revocation/timestamps. The current form therefore fits only
//!   dev / internal format plugins from trusted sources; sandbox escape drills and key rotation must be added before production use.
//! - wasmtime enables Cranelift JIT by default: JIT-compiled code runs in the **host process address space**,
//!   so the limits constrain only wasm-side resources and are not equivalent to process isolation; use a separate sidecar process for stronger isolation.
//!
//! [`SignatureCheck::Verified`]: crate::manifest::SignatureCheck::Verified


use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use wasmtime::{
    Config as WasmConfig, Engine, ExternType, Instance, Module, Store, StoreLimits,
    StoreLimitsBuilder, Trap,
};

pub mod registry;
pub mod signature;
mod convert;

pub use convert::{converter_ns, negotiate_convert, ConvertKind, ConvertOutcome};

#[cfg(test)]
mod tests;

pub use registry::{
    DirRegistry, DirScan, MemoryRegistry, PluginPackage, PluginRegistry,
};
pub use signature::TrustedKeys;

use crate::manifest::{SignatureCheck, SignatureStatus};
use crate::limits;

/// 1 MiB, keeps limit constants readable.
pub const MIB: u64 = 1024 * 1024;

/// Default per-instance memory cap: 64MiB (design §4.5).
pub const DEFAULT_MEMORY_BYTES: u64 = limits::MEMORY_MB * MIB;
/// Default per-call fuel cap: 100 million instructions (design §4.5).
pub const DEFAULT_FUEL: u64 = limits::INSTRUCTIONS;
/// Default per-call wall-clock cap: 500ms (design §4.5 / ⑤ §10).
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_millis(limits::SIDECAR_TIMEOUT_MS);
/// Default concurrency cap: 8 (② §4.5 specifies 32; the minimal version starts at 8, configurable).
pub const DEFAULT_MAX_CONCURRENCY: usize = 8;
/// Default max instances per Store: 8 (the Store is recycled and rebuilt when reached, preventing unbounded instance arena growth).
pub const DEFAULT_INSTANCES_PER_STORE: usize = 8;
/// Default failure circuit-break window: 30s (⑤ §10).
pub const DEFAULT_CIRCUIT_BREAK: Duration = Duration::from_secs(limits::CIRCUIT_BREAK_SECS);
/// Default epoch ticker step: 10ms (wall-clock limit precision; smaller is more accurate but costs more epoch checks).
pub const DEFAULT_EPOCH_TICK: Duration = Duration::from_millis(10);
/// Default per-call input / output cap.
pub const DEFAULT_MAX_IO_BYTES: usize = 8 * 1024 * 1024;
/// Default per-module wasm byte cap (defensive; hub packages cap at 20MiB).
pub const DEFAULT_MAX_MODULE_BYTES: usize = 64 * 1024 * 1024;

/// **Content-plugin** ns prefixes (E25 zero-knowledge runtime probe / PL-10 §6 risk mitigation).
///
/// Zero-knowledge deployments promise "the server never decrypts, decompresses, or parses payload", so any plugin category
/// that **needs to read payload content** must be rejected by host policy (`HostConfig::allow_content_plugins=false`). The only
/// classification signal available today is the ns naming convention: `pipeline/format.rs` conversion plugins are fixed as
/// `convert:<from>-><to>`; in addition `transcode:` / `format:` / `detect:` are treated as the same class marker, so a
/// plugin of the same kind cannot bypass this by renaming. Comparison lowercases first (ns matching is case-insensitive).
///
/// **Known classification gap**: `manifest.json` (`crate::manifest::PluginManifest`) has no explicit
/// `class`/`content` field, so the naming convention alone cannot prove that an arbitrarily named plugin "never reads payload";
/// a complete allowlist needs a category column in the manifest/`plugins` table (a cross-doc contract change, out of E25 scope).
pub const CONTENT_PLUGIN_NS_PREFIXES: [&str; 4] = ["convert:", "transcode:", "format:", "detect:"];

/// Whether the ns is a content plugin; returns the matched class prefix (`convert:`, etc.), else `None`.
///
/// **Prefix** matching only (`convert:json->text` / `convert:json->text@2` both count); no payload inspection.
pub fn content_plugin_class(ns: &str) -> Option<&'static str> {
    let lower = ns.trim().to_ascii_lowercase();
    CONTENT_PLUGIN_NS_PREFIXES
        .iter()
        .copied()
        .find(|prefix| lower.starts_with(prefix))
}

/// Default content-plugin policy (allow = backward compatible; the node explicitly sets it to false in zero-knowledge mode).
pub const DEFAULT_ALLOW_CONTENT_PLUGINS: bool = true;


/// Failure attribution (used by metrics / logs / circuit break; **never contains payload**).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// **Package-level** problems: manifest missing/invalid, invalid wasm, digest mismatch, etc.
    Manifest,
    /// Ed25519 verification failed (unsigned/bad signature/unknown key), or an unverified plugin was rejected at the call entry.
    Signature,
    /// Content plugin (`convert:*`, etc.) rejected by host policy: in zero-knowledge mode (`allow_content_plugins=false`)
    /// plugins that parse/convert payload server-side may not register. **Not** an execution failure; does not trip the circuit.
    ContentBlocked,
    /// Plugin not registered.
    NotFound,
    /// Missing entry export / export signature mismatch / missing memory / instantiation failure (including unknown imports).
    MissingExport,
    /// ABI errors: input/output pointer out of bounds, `alloc` returning an invalid address, output over the cap, etc.
    BadAbi,
    /// Hit the memory cap (`memory.grow` rejected by the limiter).
    Memory,
    /// Out of fuel.
    Fuel,
    /// Wall-clock timeout (epoch interrupt).
    Timeout,
    /// Any other wasm trap (`unreachable`, out-of-bounds access, stack overflow, etc.).
    Trap,
    /// `run()` returned non-zero.
    ExitCode,
    /// Circuit open; the call was rejected outright.
    CircuitOpen,
    /// Concurrency-slot queue timeout; the call was rejected.
    Busy,
    /// Host internal error (engine initialization, etc.).
    Internal,
}

impl ErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Manifest => "manifest",
            ErrorKind::Signature => "signature",
            ErrorKind::ContentBlocked => "content_blocked",
            ErrorKind::NotFound => "not_found",
            ErrorKind::MissingExport => "missing_export",
            ErrorKind::BadAbi => "bad_abi",
            ErrorKind::Memory => "memory",
            ErrorKind::Fuel => "fuel",
            ErrorKind::Timeout => "timeout",
            ErrorKind::Trap => "trap",
            ErrorKind::ExitCode => "exit_code",
            ErrorKind::CircuitOpen => "circuit_open",
            ErrorKind::Busy => "busy",
            ErrorKind::Internal => "internal",
        }
    }

    /// Whether this counts as "plugin execution failure" and trips the circuit. Package-level/ABI configuration errors do not.
    pub fn trips_circuit(self) -> bool {
        matches!(
            self,
            ErrorKind::Memory | ErrorKind::Fuel | ErrorKind::Timeout | ErrorKind::Trap | ErrorKind::ExitCode
        )
    }
}

/// Host error. `Display` describes only the reason and limits; it **never contains input/output payload, keys, or signature bytes**.
#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    #[error("invalid plugin manifest ({plugin}): {reason}")]
    Manifest { plugin: String, reason: String },
    #[error("plugin {plugin} rejected: signature not verified ({reason})")]
    Signature { plugin: String, reason: String },
    #[error(
        "plugin {plugin} rejected: content plugin class `{class}` is blocked by host policy \
         (zero-knowledge mode; conversion requires inspectable mode)"
    )]
    ContentBlocked { plugin: String, class: String },
    #[error("plugin {plugin} is not registered")]
    NotFound { plugin: String },
    #[error("plugin {plugin} missing required export `{name}`: {reason}")]
    MissingExport {
        plugin: String,
        name: String,
        reason: String,
    },
    #[error("plugin {plugin} bad ABI: {reason}")]
    BadAbi { plugin: String, reason: String },
    #[error("plugin {plugin} exceeded memory limit ({limit_bytes} bytes)")]
    Memory { plugin: String, limit_bytes: u64 },
    #[error("plugin {plugin} exhausted fuel ({fuel} instructions)")]
    Fuel { plugin: String, fuel: u64 },
    #[error("plugin {plugin} timed out after {timeout_ms}ms")]
    Timeout { plugin: String, timeout_ms: u64 },
    #[error("plugin {plugin} trapped: {msg}")]
    Trap { plugin: String, msg: String },
    #[error("plugin {plugin} returned exit code {code}")]
    ExitCode { plugin: String, code: i32 },
    #[error("plugin {plugin} circuit open ({retry_after_ms}ms remaining)")]
    CircuitOpen { plugin: String, retry_after_ms: u64 },
    #[error("wasm host busy: max_concurrency={limit} slots are in use")]
    Busy { limit: usize },
    #[error("wasm host internal error: {msg}")]
    Internal { msg: String },
}

impl WasmError {
    pub fn kind(&self) -> ErrorKind {
        match self {
            WasmError::Manifest { .. } => ErrorKind::Manifest,
            WasmError::Signature { .. } => ErrorKind::Signature,
            WasmError::ContentBlocked { .. } => ErrorKind::ContentBlocked,
            WasmError::NotFound { .. } => ErrorKind::NotFound,
            WasmError::MissingExport { .. } => ErrorKind::MissingExport,
            WasmError::BadAbi { .. } => ErrorKind::BadAbi,
            WasmError::Memory { .. } => ErrorKind::Memory,
            WasmError::Fuel { .. } => ErrorKind::Fuel,
            WasmError::Timeout { .. } => ErrorKind::Timeout,
            WasmError::Trap { .. } => ErrorKind::Trap,
            WasmError::ExitCode { .. } => ErrorKind::ExitCode,
            WasmError::CircuitOpen { .. } => ErrorKind::CircuitOpen,
            WasmError::Busy { .. } => ErrorKind::Busy,
            WasmError::Internal { .. } => ErrorKind::Internal,
        }
    }

    /// short_name of the plugin this error belongs to (host-level errors such as `Busy`/`Internal` return None).
    pub fn plugin(&self) -> Option<&str> {
        match self {
            WasmError::Manifest { plugin, .. }
            | WasmError::Signature { plugin, .. }
            | WasmError::ContentBlocked { plugin, .. }
            | WasmError::NotFound { plugin }
            | WasmError::MissingExport { plugin, .. }
            | WasmError::BadAbi { plugin, .. }
            | WasmError::Memory { plugin, .. }
            | WasmError::Fuel { plugin, .. }
            | WasmError::Timeout { plugin, .. }
            | WasmError::Trap { plugin, .. }
            | WasmError::ExitCode { plugin, .. }
            | WasmError::CircuitOpen { plugin, .. } => {
                if plugin.is_empty() {
                    None
                } else {
                    Some(plugin.as_str())
                }
            }
            WasmError::Busy { .. } | WasmError::Internal { .. } => None,
        }
    }
}

/// Effective limits (the smaller of the manifest request and the host cap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveLimits {
    pub memory_bytes: u64,
    pub fuel: u64,
    pub timeout_ms: u64,
}

/// Entry mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryMode {
    /// `process(i32, i32) -> i64` + `memory` (+ optional `alloc`).
    Process,
    /// `run() -> i32`.
    Run,
}

impl EntryMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EntryMode::Process => "process",
            EntryMode::Run => "run",
        }
    }
}

/// Public info about a loaded plugin (serializable to ops / E2E reports; **never contains wasm bytes/keys/signature bytes**).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub ns: String,
    pub short_name: String,
    pub version: u32,
    /// Entry export name (defaults to `process`).
    pub entry: String,
    pub mode: EntryMode,
    pub deps: Vec<String>,
    pub limits: EffectiveLimits,
    pub wasm_bytes: usize,
    /// `sha256(wasm || manifest_bytes)`, same order as [`crate::manifest::digest_matches`].
    pub content_sha256: String,
    /// Verification verdict (`verified` / `invalid` / `missing`); no longer a placeholder.
    pub signature: SignatureCheck,
    /// Verification key id declared by the manifest (unknown keys echo the id too; not a secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    /// Low-cardinality verification detail (`verified` / `no_signature` / `unknown_signing_key` / …).
    pub signature_detail: String,
    /// True only for [`SignatureCheck::Verified`]; callers use it to block untrusted plugins.
    pub trusted: bool,
}

/// Structured record of one call ([`HostHooks::on_call`]; also never contains payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord {
    pub plugin: String,
    pub version: u32,
    pub entry: String,
    pub mode: EntryMode,
    pub ok: bool,
    /// Failure attribution; `None` on success.
    pub outcome: Option<ErrorKind>,
    pub elapsed_ms: u64,
    pub fuel_used: Option<u64>,
    pub input_bytes: usize,
    pub output_bytes: usize,
    /// Error summary (no payload; None on success).
    pub error: Option<String>,
}

/// Circuit-break state change event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitEvent {
    pub plugin: String,
    pub open: bool,
    pub reason: String,
    pub break_ms: u64,
}

/// Metric / log hooks. The host's default implementation is [`LogHooks`] (tracing, no payload).
pub trait HostHooks: Send + Sync {
    fn on_call(&self, _record: &CallRecord) {}
    fn on_circuit(&self, _event: &CircuitEvent) {}
    fn on_load(&self, _info: &PluginInfo) {}
}

/// Default hooks: structured logs only (plugin/version/outcome/elapsed/fuel, no payload).
#[derive(Debug, Default)]
pub struct LogHooks;

impl HostHooks for LogHooks {
    fn on_call(&self, record: &CallRecord) {
        if record.ok {
            tracing::debug!(
                plugin = %record.plugin,
                version = record.version,
                entry = %record.entry,
                elapsed_ms = record.elapsed_ms,
                fuel_used = record.fuel_used.unwrap_or(0),
                input_bytes = record.input_bytes,
                output_bytes = record.output_bytes,
                "wasm plugin call ok"
            );
        } else {
            tracing::warn!(
                plugin = %record.plugin,
                version = record.version,
                entry = %record.entry,
                outcome = record.outcome.map(|o| o.as_str()).unwrap_or("unknown"),
                elapsed_ms = record.elapsed_ms,
                fuel_used = record.fuel_used.unwrap_or(0),
                input_bytes = record.input_bytes,
                error = record.error.as_deref().unwrap_or(""),
                "wasm plugin call failed"
            );
        }
    }

    fn on_circuit(&self, event: &CircuitEvent) {
        if event.open {
            tracing::warn!(
                plugin = %event.plugin,
                reason = %event.reason,
                break_ms = event.break_ms,
                "wasm plugin circuit opened"
            );
        } else {
            tracing::info!(plugin = %event.plugin, "wasm plugin circuit reset");
        }
    }

    fn on_load(&self, info: &PluginInfo) {
        tracing::info!(
            plugin = %info.short_name,
            version = info.version,
            entry = %info.entry,
            mode = info.mode.as_str(),
            signature = info.signature.as_str(),
            signature_detail = %info.signature_detail,
            trusted = info.trusted,
            signing_key_id = info.signing_key_id.as_deref().unwrap_or(""),
            "wasm plugin registered"
        );
    }
}

/// Host config. Every limit is an **upper bound**; a plugin manifest can only request smaller values.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// Per-instance memory cap (bytes), default 64MiB.
    pub memory_bytes: u64,
    /// Per-call fuel cap, default 100 million.
    pub fuel: u64,
    /// Per-call wall-clock cap, default 500ms.
    pub call_timeout: Duration,
    /// Concurrency cap, default 8.
    ///
    /// Relation to the other pool settings: with `pool_size=0` this value is the pool cap; with `pool_size>0`
    /// `pool_size` wins (`max_concurrency` is kept as a compatibility field).
    pub max_concurrency: usize,
    /// Store pool cap (number of concurrency slots); 0 = use [`HostConfig::max_concurrency`].
    ///
    /// When the pool is full, `call` queues (bounded, see [`HostConfig::queue_timeout`]); `try_call` is immediately Busy.
    pub pool_size: usize,
    /// Number of Store slots **pre-warmed** at host construction; 0 = fill the whole pool (equivalent to `pool_size`).
    ///
    /// Pre-warmed slots count as pool hits from the first call; without pre-warm the first concurrent calls create slots on demand (pool misses).
    pub pool_prewarm: usize,
    /// Max **instances** a single pooled Store hosts before being rebuilt; default 8, 0 = default.
    ///
    /// Why rebuild: wasmtime `Store` **does not reclaim the arena of created instances**
    /// (official docs: instances in a `Store` live until the Store is dropped). To satisfy both
    /// "a fresh Instance per call (isolated memory/globals, no state bleed)" and "bounded memory",
    /// the pool rotates Stores at this cap: once reached, the old Store is dropped (releasing all its instances) and a new one is created.
    /// Lower caps save more memory but reduce the pool reuse benefit; `1` is equivalent to a new Store per call (the old behavior).
    pub max_instances_per_store: usize,
    /// Upper bound on how long `call` queues for a slot; beyond it [`WasmError::Busy`] is returned; default 2s.
    pub queue_timeout: Duration,
    /// Failure circuit-break window, default 30s.
    pub circuit_break: Duration,
    /// Per-call input cap.
    pub max_input_bytes: usize,
    /// Per-call output cap.
    pub max_output_bytes: usize,
    /// Per-module wasm byte cap.
    pub max_module_bytes: usize,
    /// Trusted verification public keys (`[plugins] trusted_keys` / trusted_keys_file). Empty = nothing to verify with,
    /// so every signature verdict degrades to `Missing` (`trusted=false`).
    pub trusted_keys: TrustedKeys,
    /// Require a verified signature: when on, unsigned / bad signature / unknown key all reject registration (fail-closed).
    ///
    /// The library default `false` exists only for unit tests of the "unsigned minimal version"; **the node config defaults to `true`**
    /// (`[plugins] require_verified_signature`; see `PluginsCfg` in `lattice-node`).
    pub require_verified_signature: bool,
    /// Whether registering **content plugins** is allowed (ns prefixes in [`CONTENT_PLUGIN_NS_PREFIXES`]). Default `true`.
    ///
    /// Zero-knowledge deployments (`[policy] mode="zero-knowledge"`) have the node set this to `false`: content plugins are then
    /// rejected fail-closed at `register` ([`ErrorKind::ContentBlocked`]) and never enter the host registry,
    /// guaranteeing at the root that a zero-knowledge node has no "payload-parsing" plugin that can be invoked; `inspectable` deployments keep
    /// `true` (audit/conversion is their design purpose). **Classification relies on the ns naming convention**; a complete allowlist needs
    /// a category field in the manifest/DB (see the known-gap note on [`CONTENT_PLUGIN_NS_PREFIXES`]).
    pub allow_content_plugins: bool,
    /// epoch ticker step (wall-clock limit precision).
    pub epoch_tick: Duration,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            memory_bytes: DEFAULT_MEMORY_BYTES,
            fuel: DEFAULT_FUEL,
            call_timeout: DEFAULT_CALL_TIMEOUT,
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            pool_size: 0,
            pool_prewarm: 0,
            max_instances_per_store: DEFAULT_INSTANCES_PER_STORE,
            queue_timeout: Duration::from_secs(2),
            circuit_break: DEFAULT_CIRCUIT_BREAK,
            max_input_bytes: DEFAULT_MAX_IO_BYTES,
            max_output_bytes: DEFAULT_MAX_IO_BYTES,
            max_module_bytes: DEFAULT_MAX_MODULE_BYTES,
            trusted_keys: TrustedKeys::new(),
            require_verified_signature: false,
            allow_content_plugins: DEFAULT_ALLOW_CONTENT_PLUGINS,
            epoch_tick: DEFAULT_EPOCH_TICK,
        }
    }
}

impl HostConfig {
    /// Effective Store pool cap (number of concurrency slots).
    pub fn effective_pool_size(&self) -> usize {
        if self.pool_size == 0 {
            self.max_concurrency.max(1)
        } else {
            self.pool_size.max(1)
        }
    }

    /// Effective pre-warm slot count: 0 = fill the whole pool (the `pool_prewarm=0` semantics), clamped to the pool size.
    pub fn effective_prewarm(&self) -> usize {
        let size = self.effective_pool_size();
        if self.pool_prewarm == 0 {
            size
        } else {
            self.pool_prewarm.min(size)
        }
    }

    /// Effective per-Store instance rotation cap.
    pub fn effective_instances_per_store(&self) -> usize {
        if self.max_instances_per_store == 0 {
            DEFAULT_INSTANCES_PER_STORE
        } else {
            self.max_instances_per_store
        }
    }

    /// Short-timeout config for tests / E2E (**do not** use such small values in production).
    pub fn short_windows() -> Self {
        Self {
            call_timeout: Duration::from_millis(120),
            queue_timeout: Duration::from_secs(2),
            circuit_break: Duration::from_millis(150),
            epoch_tick: Duration::from_millis(5),
            ..Self::default()
        }
    }
}

/// Metrics snapshot (read by the `/v1/admin/metrics` adapter layer or E2E reports).
///
/// `pool_*` are the Store pooling (PL-10 E25) metrics: hits/misses/created/recycled/queued/rejected.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub calls_total: u64,
    pub ok_total: u64,
    pub failure_total: u64,
    pub by_outcome: BTreeMap<String, u64>,
    pub circuit_trips: u64,
    pub circuit_open_rejected: u64,
    pub busy_rejected: u64,
    pub queued_wait_total: u64,
    pub active_calls: usize,
    pub plugins: usize,
    /// Pool cap (number of concurrency slots).
    pub pool_size: usize,
    /// Number of Store slots pre-warmed at host construction.
    pub pool_prewarmed: usize,
    /// Number of currently idle slots (instantaneous sample).
    pub pool_idle: usize,
    /// Calls that took a Store from an idle slot (reuse hit).
    pub pool_hits: u64,
    /// Calls that created a Store slot on demand because no idle slot was free (miss).
    pub pool_misses: u64,
    /// Cumulative number of Stores created (including pre-warm).
    pub pool_created: u64,
    /// Number of Stores recycled and rebuilt after reaching `max_instances_per_store`.
    pub pool_recycled: u64,
    /// Per-Store instance rotation cap (effective value).
    pub max_instances_per_store: usize,
}

/// Security boundary report (**honest declaration**, for reports/docs; do not use it to claim plugins are safe).
#[derive(Debug, Clone, Serialize)]
pub struct SecurityReport {
    pub wasi: &'static str,
    pub filesystem: &'static str,
    pub network: &'static str,
    pub clock_random_env: &'static str,
    /// Verification capability/config summary (no public keys/signature bytes):
    /// - trusted public keys present: `ed25519_ring: ...`;
    /// - no trusted public keys: `not_implemented: ...` — for **this host instance** signatures cannot be verified,
    ///   so all packages are `trusted=false` (keeps the old E2E wording and stays truthful: no key means no verification).
    pub signature_verification: String,
    /// Number of trusted public keys (the keys themselves are not listed).
    pub trusted_keys: usize,
    pub require_verified_signature: bool,
    /// Whether content plugins may register (zero-knowledge mode = false; see [`HostConfig::allow_content_plugins`]).
    pub content_plugins_allowed: bool,
    pub trusted_plugins: usize,
    pub untrusted_plugins: usize,
    pub sandbox_escape_drill: &'static str,
    pub process_isolation: &'static str,
    pub note: &'static str,
}

/// Result of one call.
#[derive(Debug, Clone)]
pub struct CallOutput {
    pub output: Vec<u8>,
    pub plugin: String,
    pub version: u32,
    pub elapsed_ms: u64,
    pub fuel_used: Option<u64>,
}

/// Batch load report.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LoadReport {
    pub loaded: Vec<PluginInfo>,
    pub rejected: Vec<LoadRejection>,
}

impl LoadReport {
    pub fn ok(&self) -> bool {
        self.rejected.is_empty()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadRejection {
    pub plugin: String,
    pub kind: String,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// wasmtime store data / limiter
// ---------------------------------------------------------------------------

struct HostData {
    limiter: PluginLimiter,
}

/// Wrapper around `StoreLimits`: delegates limit decisions and records "memory growth denied" so the trap can be attributed to
/// [`ErrorKind::Memory`] (otherwise a failed `memory.grow` followed by out-of-bounds access reports only a generic trap).
struct PluginLimiter {
    inner: StoreLimits,
    memory_denied: bool,
}

impl wasmtime::ResourceLimiter for PluginLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        match self.inner.memory_growing(current, desired, maximum) {
            Ok(allow) => {
                if !allow {
                    self.memory_denied = true;
                }
                Ok(allow)
            }
            Err(e) => {
                self.memory_denied = true;
                Err(e)
            }
        }
    }

    fn memory_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.memory_denied = true;
        self.inner.memory_grow_failed(error)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.inner.table_growing(current, desired, maximum)
    }

    fn table_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.inner.table_grow_failed(error)
    }

    fn instances(&self) -> usize {
        self.inner.instances()
    }

    fn tables(&self) -> usize {
        self.inner.tables()
    }

    fn memories(&self) -> usize {
        self.inner.memories()
    }
}

// ---------------------------------------------------------------------------
// Loaded plugins
// ---------------------------------------------------------------------------

struct LoadedPlugin {
    info: PluginInfo,
    module: Module,
    limits: EffectiveLimits,
    /// Number of ticks needed for the epoch interrupt (wall-clock limit).
    timeout_ticks: u64,
}

// ---------------------------------------------------------------------------
// Store pool (bounded concurrency slots + pre-warmed reuse)
// ---------------------------------------------------------------------------

/// One Store slot in the pool.
///
/// **Instances are not reused**: wasmtime `Store` does not reclaim the Instance arena, so reusing an Instance would let
/// linear memory/globals leak across calls (state bleed). So each call does `Instance::new` inside the slot's Store
/// to create a **fresh instance** (independent memory/globals), while the slot's Store itself is reused;
/// once a Store has hosted `max_instances_per_store` instances it is dropped and rebuilt (releasing the arena).
struct PoolSlot {
    store: Store<HostData>,
    /// Instances created in this Store (recycled and rebuilt once the cap is reached).
    instances_used: usize,
}

struct PoolState {
    idle: Vec<PoolSlot>,
    in_flight: usize,
}

/// Bounded Store pool: reuse idle → create below the cap → queue when full (bounded timeout; Busy on timeout).
///
/// Metric semantics (matching [`MetricsSnapshot::pool_*`]):
/// - `pool_hits`: an idle slot was taken (reuse);
/// - `pool_misses`: no idle slot, but concurrency was below the cap → a new Store slot is created;
/// - `pool_created`: cumulative Stores created (including pre-warm);
/// - `pool_recycled`: Stores recycled and rebuilt after their instance count hit the cap;
/// - `queued_wait_total` / `busy_rejected`: calls that queued / were rejected on queue timeout.
struct InstancePool {
    engine: Engine,
    limit: usize,
    prewarmed: usize,
    max_instances_per_store: usize,
    state: Mutex<PoolState>,
    cv: Condvar,
    active: AtomicUsize,
    queued_total: AtomicU64,
    busy_rejected: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    created: AtomicU64,
    recycled: AtomicU64,
}

/// Pool slot lease; on `Drop` the Store goes back to the idle list (Stores beyond the concurrency window are dropped).
struct PoolGuard<'a> {
    pool: &'a InstancePool,
    slot: Option<PoolSlot>,
}

impl Drop for PoolGuard<'_> {
    fn drop(&mut self) {
        let mut st = self.pool.state.lock().unwrap_or_else(|e| e.into_inner());
        st.in_flight = st.in_flight.saturating_sub(1);
        self.pool.active.fetch_sub(1, Ordering::Relaxed);
        if let Some(slot) = self.slot.take() {
            if st.idle.len() < self.pool.limit {
                st.idle.push(slot);
            }
        }
        drop(st);
        self.pool.cv.notify_one();
    }
}

/// Create an empty Store slot (the limiter is replaced per call; fuel/epoch are reset per call).
fn new_pool_store(engine: &Engine) -> PoolSlot {
    let mut store = Store::new(
        engine,
        HostData {
            limiter: PluginLimiter {
                inner: StoreLimitsBuilder::new().build(),
                memory_denied: false,
            },
        },
    );
    // The limiter closure is installed once; each call only replaces the limits in `data.limiter.inner`.
    store.limiter(|data: &mut HostData| &mut data.limiter as &mut dyn wasmtime::ResourceLimiter);
    PoolSlot {
        store,
        instances_used: 0,
    }
}

impl InstancePool {
    fn new(
        engine: Engine,
        limit: usize,
        prewarmed: usize,
        max_instances_per_store: usize,
    ) -> Self {
        let limit = limit.max(1);
        let prewarmed = prewarmed.min(limit);
        let max_instances_per_store = max_instances_per_store.max(1);
        let mut idle = Vec::with_capacity(prewarmed);
        for _ in 0..prewarmed {
            idle.push(new_pool_store(&engine));
        }
        Self {
            engine,
            limit,
            prewarmed,
            max_instances_per_store,
            state: Mutex::new(PoolState {
                idle,
                in_flight: 0,
            }),
            cv: Condvar::new(),
            active: AtomicUsize::new(0),
            queued_total: AtomicU64::new(0),
            busy_rejected: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            created: AtomicU64::new(prewarmed as u64),
            recycled: AtomicU64::new(0),
        }
    }

    fn limit(&self) -> usize {
        self.limit
    }

    /// Take a Store slot.
    ///
    /// - `wait=true`: queue when the pool is full, at most `queue_timeout` (timeout → None → Busy);
    /// - `wait=false`: return None immediately when full (try_call semantics, no queueing).
    ///
    /// Returning `None` has already counted `busy_rejected`.
    fn acquire(&self, wait: bool, queue_timeout: Duration) -> Option<PoolGuard<'_>> {
        let deadline = Instant::now() + queue_timeout;
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut waited = false;
        loop {
            // 1) Idle slots first (reuse hit).
            if let Some(mut slot) = st.idle.pop() {
                if slot.instances_used >= self.max_instances_per_store {
                    // This Store's instance arena hit the rotation cap: drop and rebuild (freeing memory).
                    slot = new_pool_store(&self.engine);
                    self.created.fetch_add(1, Ordering::Relaxed);
                    self.recycled.fetch_add(1, Ordering::Relaxed);
                }
                st.in_flight += 1;
                self.hits.fetch_add(1, Ordering::Relaxed);
                self.active.fetch_add(1, Ordering::Relaxed);
                return Some(PoolGuard {
                    pool: self,
                    slot: Some(slot),
                });
            }
            // 2) No idle slot but concurrency below the cap: create a new slot (miss).
            if st.in_flight < self.limit {
                st.in_flight += 1;
                self.misses.fetch_add(1, Ordering::Relaxed);
                self.created.fetch_add(1, Ordering::Relaxed);
                self.active.fetch_add(1, Ordering::Relaxed);
                return Some(PoolGuard {
                    pool: self,
                    slot: Some(new_pool_store(&self.engine)),
                });
            }
            // 3) Pool full: reject immediately or wait with a bound.
            if !wait {
                self.busy_rejected.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            let now = Instant::now();
            if now >= deadline {
                self.busy_rejected.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            if !waited {
                // Queue counter: counted as soon as waiting **starts** (both success and timeout count as "queued", matching the old SlotGate
                // backward-compatible subset: a successful queue always counts).
                waited = true;
                self.queued_total.fetch_add(1, Ordering::Relaxed);
            }
            let (next, _) = self
                .cv
                .wait_timeout(st, deadline.saturating_duration_since(now))
                .unwrap_or_else(|e| e.into_inner());
            st = next;
        }
    }

    fn pool_idle(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .idle
            .len()
    }
}


// ---------------------------------------------------------------------------
// WasmHost
// ---------------------------------------------------------------------------

/// Minimal WASM plugin host. `Send + Sync`, can live in node state / an `Arc`.
pub struct WasmHost {
    engine: Engine,
    config: HostConfig,
    plugins: RwLock<BTreeMap<String, Arc<LoadedPlugin>>>,
    circuit: Mutex<HashMap<String, Instant>>,
    /// Bounded Store pool (concurrency slots; pre-warmed reuse + queueing when full).
    pool: InstancePool,
    hooks: Arc<dyn HostHooks>,
    metrics: Metrics,
    ticker_stop: Arc<AtomicBool>,
    ticker: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Default)]
struct Metrics {
    calls: AtomicU64,
    ok: AtomicU64,
    failures: AtomicU64,
    circuit_trips: AtomicU64,
    circuit_open_rejected: AtomicU64,
    by_outcome: Mutex<BTreeMap<String, u64>>,
}

impl Metrics {
    fn record(&self, outcome: ErrorKind) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mut map = self.by_outcome.lock().expect("metrics poisoned");
        *map.entry(outcome.as_str().to_string()).or_insert(0) += 1;
    }

    fn record_ok(&self) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.ok.fetch_add(1, Ordering::Relaxed);
        let mut map = self.by_outcome.lock().expect("metrics poisoned");
        *map.entry("ok".to_string()).or_insert(0) += 1;
    }

    fn snapshot(&self, pool: &InstancePool, plugins: usize) -> MetricsSnapshot {
        let by_outcome = self.by_outcome.lock().expect("metrics poisoned").clone();
        MetricsSnapshot {
            calls_total: self.calls.load(Ordering::Relaxed),
            ok_total: self.ok.load(Ordering::Relaxed),
            failure_total: self.failures.load(Ordering::Relaxed),
            by_outcome,
            circuit_trips: self.circuit_trips.load(Ordering::Relaxed),
            circuit_open_rejected: self.circuit_open_rejected.load(Ordering::Relaxed),
            busy_rejected: pool.busy_rejected.load(Ordering::Relaxed),
            queued_wait_total: pool.queued_total.load(Ordering::Relaxed),
            active_calls: pool.active.load(Ordering::Relaxed),
            plugins,
            pool_size: pool.limit,
            pool_prewarmed: pool.prewarmed,
            pool_idle: pool.pool_idle(),
            pool_hits: pool.hits.load(Ordering::Relaxed),
            pool_misses: pool.misses.load(Ordering::Relaxed),
            pool_created: pool.created.load(Ordering::Relaxed),
            pool_recycled: pool.recycled.load(Ordering::Relaxed),
            max_instances_per_store: pool.max_instances_per_store,
        }
    }
}

impl WasmHost {
    /// Construct the host: enables fuel + epoch interruption, starts an epoch ticker background thread,
    /// and the ticker stops when the host is `Drop`ped.
    pub fn new(config: HostConfig) -> Result<Self, WasmError> {
        Self::with_hooks(config, Arc::new(LogHooks))
    }

    pub fn with_hooks(config: HostConfig, hooks: Arc<dyn HostHooks>) -> Result<Self, WasmError> {
        let mut wcfg = WasmConfig::new();
        wcfg.consume_fuel(true);
        wcfg.epoch_interruption(true);
        // Minimal capability surface: no multi-memory / 64-bit memory / custom page sizes / tail-call /
        // stack-switching. `threads`/`gc`/`component-model` have no corresponding Config method once default
        // features are disabled (the capability no longer exists).
        wcfg.wasm_multi_memory(false);
        wcfg.wasm_memory64(false);
        wcfg.wasm_custom_page_sizes(false);
        wcfg.wasm_tail_call(false);
        wcfg.wasm_stack_switching(false);
        let engine = Engine::new(&wcfg)
            .map_err(|e| WasmError::Internal { msg: format!("wasmtime engine init: {e}") })?;

        let tick = config.epoch_tick.max(Duration::from_millis(1));
        let ticker_stop = Arc::new(AtomicBool::new(false));
        let ticker = {
            let engine = engine.clone();
            let stop = ticker_stop.clone();
            std::thread::Builder::new()
                .name("lattice-wasm-epoch".into())
                .spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        std::thread::sleep(tick);
                        engine.increment_epoch();
                    }
                })
                .map_err(|e| WasmError::Internal { msg: format!("spawn epoch ticker: {e}") })?
        };

        // The pool holds its own `Engine` clone (to create slots on demand); the host keeps one too.
        let engine_for_pool = engine.clone();
        Ok(Self {
            engine,
            pool: InstancePool::new(
                engine_for_pool,
                config.effective_pool_size(),
                config.effective_prewarm(),
                config.effective_instances_per_store(),
            ),
            config,
            plugins: RwLock::new(BTreeMap::new()),
            circuit: Mutex::new(HashMap::new()),
            hooks,
            metrics: Metrics::default(),
            ticker_stop,
            ticker: Mutex::new(Some(ticker)),
        })
    }

    pub fn config(&self) -> &HostConfig {
        &self.config
    }

    /// Register (or update) a plugin package: manifest/digest validation → **Ed25519 verification** → compile module → resolve entry.
    /// Re-registering the same `short_name` is a version update and resets that plugin's circuit break.
    ///
    /// Verification policy (fail-closed):
    /// - `require_verified_signature=true`: only [`SignatureCheck::Verified`] can register;
    ///   unsigned / bad signature / unknown key are all rejected as [`ErrorKind::Signature`];
    /// - `require_verified_signature=false`: Verified registers as trusted; Missing may register but with
    ///   `trusted=false` (callers must not invoke it); **Invalid is always rejected** (a bad signature signals tampering).
    pub fn register(&self, package: PluginPackage) -> Result<PluginInfo, WasmError> {
        package.validate_manifest()?;
        let short_name = package.short_name().to_string();
        // Zero-knowledge deployments (E25 zero-knowledge runtime probe): content plugins are rejected fail-closed at the registration entry,
        // never compiled or registered. Classification relies on the ns prefix convention (see `CONTENT_PLUGIN_NS_PREFIXES`).
        if !self.config.allow_content_plugins {
            if let Some(class) = content_plugin_class(&package.manifest.ns) {
                return Err(WasmError::ContentBlocked {
                    plugin: short_name,
                    class: class.trim_end_matches(':').to_string(),
                });
            }
        }
        let status: SignatureStatus = package.signature_status(&self.config.trusted_keys);
        match status.check {
            SignatureCheck::Verified => {}
            SignatureCheck::Invalid => {
                // Signature declared but verification failed: reject even when verification is not required (bad signature = tampering signal).
                return Err(WasmError::Signature {
                    plugin: short_name,
                    reason: status.detail,
                });
            }
            SignatureCheck::Missing => {
                if self.config.require_verified_signature {
                    return Err(WasmError::Signature {
                        plugin: short_name,
                        reason: status.detail,
                    });
                }
            }
        }
        if package.wasm.len() > self.config.max_module_bytes {
            return Err(WasmError::Manifest {
                plugin: short_name,
                reason: format!(
                    "wasm module is {} bytes, exceeds host max_module_bytes {}",
                    package.wasm.len(),
                    self.config.max_module_bytes
                ),
            });
        }
        if let Some(expected) = &package.digest {
            if !crate::manifest::digest_matches(
                &package.wasm,
                &package.manifest_bytes,
                expected.trim(),
            ) {
                return Err(WasmError::Manifest {
                    plugin: package.short_name().to_string(),
                    reason: "content digest mismatch (sha256(wasm || manifest))".into(),
                });
            }
        }

        let module = Module::new(&self.engine, &package.wasm).map_err(|e| WasmError::Manifest {
            plugin: package.short_name().to_string(),
            reason: format!("wasm compile failed: {e}"),
        })?;

        let (entry, mode) = resolve_entry(&module, &package.manifest).map_err(|(name, reason)| {
            WasmError::MissingExport {
                plugin: package.short_name().to_string(),
                name,
                reason,
            }
        })?;
        if mode == EntryMode::Process && !module_has_memory(&module) {
            return Err(WasmError::MissingExport {
                plugin: package.short_name().to_string(),
                name: "memory".into(),
                reason: "process ABI requires an exported `memory`".into(),
            });
        }

        let limits = effective_limits(&package.manifest, &self.config);
        let tick_ms = self.config.epoch_tick.as_millis().max(1) as u64;
        let timeout_ticks = limits.timeout_ms.div_ceil(tick_ms) + 1;
        let info = PluginInfo {
            ns: package.manifest.ns.clone(),
            short_name: short_name.clone(),
            version: package.manifest.version,
            entry: entry.clone(),
            mode,
            deps: package.manifest.deps.clone(),
            limits,
            wasm_bytes: package.wasm.len(),
            content_sha256: package.content_sha256(),
            signature: status.check,
            signing_key_id: status.key_id.clone(),
            signature_detail: status.detail.clone(),
            trusted: status.check == SignatureCheck::Verified,
        };
        let loaded = Arc::new(LoadedPlugin { info: info.clone(), module, limits, timeout_ticks });
        let mut map = self.plugins.write().expect("plugin map poisoned");
        map.insert(short_name.clone(), loaded);
        drop(map);
        self.circuit_reset(&short_name);
        self.hooks.on_load(&info);
        Ok(info)
    }

    /// Batch load from a registry: first validate `deps` against the short_name set (existence check only, no linking),
    /// then `register` one by one; bad packages/missing dependencies go into [`LoadReport::rejected`], never silently skipped.
    pub fn load_registry(&self, registry: &dyn PluginRegistry) -> LoadReport {
        let packages = registry.list();
        let known: std::collections::BTreeSet<String> =
            packages.iter().map(|p| p.short_name().to_string()).collect();
        let mut report = LoadReport::default();
        for package in packages {
            let name = package.short_name().to_string();
            let missing: Vec<String> = package
                .manifest
                .deps
                .iter()
                .filter(|d| !known.contains(d.as_str()))
                .cloned()
                .collect();
            if !missing.is_empty() {
                report.rejected.push(LoadRejection {
                    plugin: name,
                    kind: ErrorKind::MissingExport.as_str().to_string(),
                    reason: format!("missing dependency: {}", missing.join(", ")),
                });
                continue;
            }
            match self.register(package) {
                Ok(info) => report.loaded.push(info),
                Err(e) => report.rejected.push(LoadRejection {
                    plugin: e.plugin().unwrap_or("<unknown>").to_string(),
                    kind: e.kind().as_str().to_string(),
                    reason: e.to_string(),
                }),
            }
        }
        report
    }

    /// Load from a directory (layout in [`DirRegistry`]): bad packages/bad manifests also go into rejected.
    pub fn load_dir(&self, dir: &Path) -> LoadReport {
        let scan: DirScan = DirRegistry::new(dir).scan();
        let mut report = LoadReport::default();
        for (plugin, reason) in scan.rejected {
            report.rejected.push(LoadRejection {
                plugin,
                kind: ErrorKind::Manifest.as_str().to_string(),
                reason,
            });
        }
        let packages = scan.packages;
        let known: std::collections::BTreeSet<String> =
            packages.iter().map(|p| p.short_name().to_string()).collect();
        for package in packages {
            let name = package.short_name().to_string();
            let missing: Vec<String> = package
                .manifest
                .deps
                .iter()
                .filter(|d| !known.contains(d.as_str()))
                .cloned()
                .collect();
            if !missing.is_empty() {
                report.rejected.push(LoadRejection {
                    plugin: name,
                    kind: ErrorKind::MissingExport.as_str().to_string(),
                    reason: format!("missing dependency: {}", missing.join(", ")),
                });
                continue;
            }
            match self.register(package) {
                Ok(info) => report.loaded.push(info),
                Err(e) => report.rejected.push(LoadRejection {
                    plugin: e.plugin().unwrap_or("<unknown>").to_string(),
                    kind: e.kind().as_str().to_string(),
                    reason: e.to_string(),
                }),
            }
        }
        report
    }

    /// Plugin info (`None` when not registered).
    pub fn info(&self, short_name: &str) -> Option<PluginInfo> {
        self.plugins
            .read()
            .expect("plugin map poisoned")
            .get(short_name)
            .map(|p| p.info.clone())
    }

    /// Currently registered plugins (in short_name order).
    pub fn plugins(&self) -> Vec<PluginInfo> {
        self.plugins
            .read()
            .expect("plugin map poisoned")
            .values()
            .map(|p| p.info.clone())
            .collect()
    }

    /// Call the plugin entry (queues for a slot, at most [`HostConfig::queue_timeout`]).
    pub fn call(&self, short_name: &str, input: &[u8]) -> Result<CallOutput, WasmError> {
        self.invoke(short_name, input, true, None)
    }

    /// Call the plugin entry (no queueing; [`WasmError::Busy`] immediately when no slot is free).
    pub fn try_call(&self, short_name: &str, input: &[u8]) -> Result<CallOutput, WasmError> {
        self.invoke(short_name, input, false, None)
    }

    /// Call the plugin entry, allowing this call to **override the entry export name** (the admin `invoke` optional `entry`).
    ///
    /// `entry=None` is equivalent to [`WasmHost::call`]; an override name is resolved in the module against both the `process`/`run` ABIs
    /// on the fly (missing export → [`WasmError::MissingExport`]). Queueing behaves like `call`.
    pub fn call_entry(
        &self,
        short_name: &str,
        entry: Option<&str>,
        input: &[u8],
    ) -> Result<CallOutput, WasmError> {
        self.invoke(short_name, input, true, entry)
    }

    /// Same as [`WasmHost::call_entry`], but returns [`WasmError::Busy`] immediately when no slot is free.
    pub fn try_call_entry(
        &self,
        short_name: &str,
        entry: Option<&str>,
        input: &[u8],
    ) -> Result<CallOutput, WasmError> {
        self.invoke(short_name, input, false, entry)
    }

    /// Manually reset a plugin's circuit break (ops / new version rollout).
    pub fn circuit_reset(&self, short_name: &str) {
        let mut map = self.circuit.lock().expect("circuit poisoned");
        if map.remove(short_name).is_some() {
            self.hooks.on_circuit(&CircuitEvent {
                plugin: short_name.to_string(),
                open: false,
                reason: "reset".into(),
                break_ms: 0,
            });
        }
    }

    /// Whether the circuit is currently open.
    pub fn is_circuit_open(&self, short_name: &str) -> bool {
        let mut map = self.circuit.lock().expect("circuit poisoned");
        match map.get(short_name).copied() {
            Some(until) if Instant::now() < until => true,
            Some(_) => {
                map.remove(short_name);
                false
            }
            None => false,
        }
    }

    pub fn metrics(&self) -> MetricsSnapshot {
        let plugins = self.plugins.read().expect("plugin map poisoned").len();
        self.metrics.snapshot(&self.pool, plugins)
    }

    /// Security boundary self-description (**honest reporting**; do not use it to claim plugins execute safely).
    pub fn security_report(&self) -> SecurityReport {
        let plugins = self.plugins();
        let verified = plugins.iter().filter(|p| p.trusted).count();
        let trusted_key_count = self.config.trusted_keys.len();
        let signature_verification = if trusted_key_count == 0 {
            // No trusted public keys configured = this instance cannot verify: keeps the old E2E wording, and semantically verification is indeed "not implemented"
            // (no signature can be proven, so every plugin is trusted=false).
            "not_implemented: Ed25519 verify missing (design §4.5)".to_string()
        } else {
            format!(
                "ed25519_ring: trusted_keys={trusted_key_count}; verified_plugins={verified}; \
                 unverified_plugins={}; require_verified_signature={}",
                plugins.len().saturating_sub(verified),
                self.config.require_verified_signature
            )
        };
        SecurityReport {
            wasi: "disabled: no WASI host functions are linked",
            filesystem: "none: no imports exist for file access",
            network: "none: no imports exist for sockets/HTTP",
            clock_random_env: "none: no clock/random/env imports",
            signature_verification,
            trusted_keys: trusted_key_count,
            require_verified_signature: self.config.require_verified_signature,
            content_plugins_allowed: self.config.allow_content_plugins,
            trusted_plugins: verified,
            untrusted_plugins: plugins.iter().filter(|p| !p.trusted).count(),
            sandbox_escape_drill: "not_run",
            process_isolation: "none: wasmtime JIT runs in the host process address space",
            note: "wasm sandbox limits resources; it is not a security boundary substitute for signatures + sidecar isolation",
        }
    }

    fn invoke(
        &self,
        short_name: &str,
        input: &[u8],
        wait_for_slot: bool,
        entry_override: Option<&str>,
    ) -> Result<CallOutput, WasmError> {
        let plugin = {
            let map = self.plugins.read().expect("plugin map poisoned");
            map.get(short_name).cloned()
        };
        let Some(plugin) = plugin else {
            let err = WasmError::NotFound { plugin: short_name.to_string() };
            self.record_failure(short_name, 0, EntryMode::Run, "", input.len(), &err);
            return Err(err);
        };
        // Entry name: defaults to the one resolved at registration; the admin plane may pass an entry override.
        // Note: the `trusted` gate is enforced at the node's invoke entry (this crate's call is also used directly by unit tests/dev;
        // unverified plugins may load when require=false, but production entries must not invoke them).
        let entry_used = entry_override.unwrap_or(&plugin.info.entry).to_string();

        if input.len() > self.config.max_input_bytes {
            let err = WasmError::BadAbi {
                plugin: short_name.to_string(),
                reason: format!(
                    "input {} bytes exceeds max_input_bytes {}",
                    input.len(),
                    self.config.max_input_bytes
                ),
            };
            self.record_failure(short_name, plugin.info.version, plugin.info.mode, &entry_used, input.len(), &err);
            return Err(err);
        }

        // Circuit check before queueing: return immediately inside the window, with no pointless queueing.
        if let Some(retry_ms) = self.circuit_retry_ms(short_name) {
            let err = WasmError::CircuitOpen {
                plugin: short_name.to_string(),
                retry_after_ms: retry_ms,
            };
            self.metrics.circuit_open_rejected.fetch_add(1, Ordering::Relaxed);
            self.record_failure(short_name, plugin.info.version, plugin.info.mode, &entry_used, input.len(), &err);
            return Err(err);
        }

        let Some(mut slot) = self.pool.acquire(wait_for_slot, self.config.queue_timeout) else {
            let err = WasmError::Busy { limit: self.pool.limit() };
            self.record_failure(short_name, plugin.info.version, plugin.info.mode, &entry_used, input.len(), &err);
            return Err(err);
        };

        let started = Instant::now();
        let limits = plugin.limits;
        // Pool slot reuse: reset limits/fuel/epoch first, then create a new Instance in the slot's Store (the isolation point).
        slot.slot
            .as_mut()
            .expect("pool guard always holds a slot")
            .instances_used += 1;
        if let Err(err) = self.prepare_store(&mut slot, &plugin) {
            self.record_failure(short_name, plugin.info.version, plugin.info.mode, &entry_used, input.len(), &err);
            return Err(err);
        }
        let store = &mut slot
            .slot
            .as_mut()
            .expect("pool guard always holds a slot")
            .store;
        let result = self.execute(store, &plugin, input, entry_override);
        let fuel_used = store
            .get_fuel()
            .ok()
            .map(|remaining| limits.fuel.saturating_sub(remaining));
        let elapsed_ms = started.elapsed().as_millis() as u64;

        match result {
            Ok(output) => {
                if self
                    .circuit
                    .lock()
                    .expect("circuit poisoned")
                    .remove(short_name)
                    .is_some()
                {
                    self.hooks.on_circuit(&CircuitEvent {
                        plugin: short_name.to_string(),
                        open: false,
                        reason: "success".into(),
                        break_ms: 0,
                    });
                }
                self.metrics.record_ok();
                self.hooks.on_call(&CallRecord {
                    plugin: short_name.to_string(),
                    version: plugin.info.version,
                    entry: entry_used.clone(),
                    mode: plugin.info.mode,
                    ok: true,
                    outcome: None,
                    elapsed_ms,
                    fuel_used,
                    input_bytes: input.len(),
                    output_bytes: output.len(),
                    error: None,
                });
                Ok(CallOutput {
                    output,
                    plugin: short_name.to_string(),
                    version: plugin.info.version,
                    elapsed_ms,
                    fuel_used,
                })
            }
            Err(err) => {
                if err.kind().trips_circuit() {
                    self.trip_circuit(short_name, &err);
                }
                self.metrics
                    .record(err.kind());
                self.metrics.failures.fetch_add(1, Ordering::Relaxed);
                self.hooks.on_call(&CallRecord {
                    plugin: short_name.to_string(),
                    version: plugin.info.version,
                    entry: entry_used.clone(),
                    mode: plugin.info.mode,
                    ok: false,
                    outcome: Some(err.kind()),
                    elapsed_ms,
                    fuel_used,
                    input_bytes: input.len(),
                    output_bytes: 0,
                    error: Some(err.to_string()),
                });
                Err(err)
            }
        }
    }

    /// Per-call reset before using a pool slot: limits / fuel / epoch are all re-set to **this plugin's** effective limits
    /// (pooled Stores are reused across plugins, so limits cannot be set only when the slot is created).
    ///
    /// Note: the `instances` / `memories` limits are relaxed to the per-Store rotation cap — wasmtime `Store`
    /// does not reclaim the arena of created Instances, so slots count up to `max_instances_per_store` and are rebuilt periodically,
    /// making "a new Instance per call (isolation)" and "bounded memory" hold at the same time.
    fn prepare_store(
        &self,
        slot: &mut PoolGuard<'_>,
        plugin: &LoadedPlugin,
    ) -> Result<(), WasmError> {
        let limits = plugin.limits;
        let max_instances = self.config.effective_instances_per_store();
        let store = &mut slot
            .slot
            .as_mut()
            .expect("pool guard always holds a slot")
            .store;
        {
            let data = store.data_mut();
            data.limiter.inner = StoreLimitsBuilder::new()
                .memory_size(limits.memory_bytes as usize)
                .instances(max_instances)
                .memories(max_instances)
                .tables(4)
                .trap_on_grow_failure(true)
                .build();
            data.limiter.memory_denied = false;
        }
        store
            .set_fuel(limits.fuel)
            .map_err(|e| WasmError::Internal { msg: format!("set_fuel: {e}") })?;
        store.set_epoch_deadline(plugin.timeout_ticks);
        Ok(())
    }

    fn execute(
        &self,
        store: &mut Store<HostData>,
        plugin: &LoadedPlugin,
        input: &[u8],
        entry_override: Option<&str>,
    ) -> Result<Vec<u8>, WasmError> {
        let name = &plugin.info.short_name;
        // Entry ABI: resolved at registration from manifest.entry; an override is resolved against the module's actual exports on the fly.
        let (entry, mode) = match entry_override {
            None => (plugin.info.entry.clone(), plugin.info.mode),
            Some(custom) => match resolve_entry_name(&plugin.module, custom) {
                Ok(mode) => (custom.to_string(), mode),
                Err(reason) => {
                    return Err(WasmError::MissingExport {
                        plugin: name.clone(),
                        name: custom.to_string(),
                        reason,
                    })
                }
            },
        };
        let instance = Instance::new(&mut *store, &plugin.module, &[])
            .map_err(|e| self.trap_error(name, &e, store))?;
        match mode {
            EntryMode::Process => {
                let memory = instance
                    .get_memory(&mut *store, "memory")
                    .ok_or_else(|| WasmError::MissingExport {
                        plugin: name.clone(),
                        name: "memory".into(),
                        reason: "process ABI requires an exported `memory`".into(),
                    })?;
                let input_ptr = if input.is_empty() {
                    0
                } else if let Ok(alloc) =
                    instance.get_typed_func::<i32, i32>(&mut *store, "alloc")
                {
                    let ptr = alloc
                        .call(&mut *store, input.len() as i32)
                        .map_err(|e| self.trap_error(name, &e, store))?;
                    if ptr < 0 {
                        return Err(WasmError::BadAbi {
                            plugin: name.clone(),
                            reason: "alloc returned a negative pointer".into(),
                        });
                    }
                    memory
                        .write(&mut *store, ptr as usize, input)
                        .map_err(|_| WasmError::BadAbi {
                            plugin: name.clone(),
                            reason: format!(
                                "alloc returned out-of-bounds pointer (ptr={}, len={})",
                                ptr,
                                input.len()
                            ),
                        })?;
                    ptr
                } else {
                    return Err(WasmError::BadAbi {
                        plugin: name.clone(),
                        reason: "non-empty input requires an exported `alloc(i32)->i32`".into(),
                    });
                };
                let process = instance
                    .get_typed_func::<(i32, i32), i64>(&mut *store, &entry)
                    .map_err(|e| WasmError::MissingExport {
                        plugin: name.clone(),
                        name: entry.clone(),
                        reason: format!("expected (i32,i32)->i64: {e}"),
                    })?;
                let packed = process
                    .call(&mut *store, (input_ptr, input.len() as i32))
                    .map_err(|e| self.trap_error(name, &e, store))?;
                let out_ptr = (packed & 0xFFFF_FFFF) as u32;
                let out_len = ((packed >> 32) & 0xFFFF_FFFF) as u32;
                if out_len as usize > self.config.max_output_bytes {
                    return Err(WasmError::BadAbi {
                        plugin: name.clone(),
                        reason: format!(
                            "output length {} exceeds max_output_bytes {}",
                            out_len, self.config.max_output_bytes
                        ),
                    });
                }
                let mut output = vec![0u8; out_len as usize];
                if out_len > 0 {
                    memory
                        .read(&*store, out_ptr as usize, &mut output)
                        .map_err(|_| WasmError::BadAbi {
                            plugin: name.clone(),
                            reason: format!(
                                "output pointer out of bounds (ptr={out_ptr}, len={out_len})"
                            ),
                        })?;
                }
                Ok(output)
            }
            EntryMode::Run => {
                let run = instance
                    .get_typed_func::<(), i32>(&mut *store, &entry)
                    .map_err(|e| WasmError::MissingExport {
                        plugin: name.clone(),
                        name: entry.clone(),
                        reason: format!("expected ()->i32: {e}"),
                    })?;
                let code = run
                    .call(&mut *store, ())
                    .map_err(|e| self.trap_error(name, &e, store))?;
                if code != 0 {
                    return Err(WasmError::ExitCode {
                        plugin: name.clone(),
                        code,
                    });
                }
                Ok(Vec::new())
            }
        }
    }

    /// Attribute a wasmtime trap to a host error: prefer the limiter's "memory growth denied" flag,
    /// then distinguish fuel/timeout by trap type, and classify the rest as trap.
    fn trap_error(&self, plugin: &str, e: &wasmtime::Error, store: &Store<HostData>) -> WasmError {
        if store.data().limiter.memory_denied {
            return WasmError::Memory {
                plugin: plugin.to_string(),
                limit_bytes: self.config.memory_bytes,
            };
        }
        if e.downcast_ref::<wasmtime::OutOfMemory>().is_some() {
            return WasmError::Memory {
                plugin: plugin.to_string(),
                limit_bytes: self.config.memory_bytes,
            };
        }
        if let Some(trap) = e.downcast_ref::<Trap>() {
            return match trap {
                Trap::OutOfFuel => WasmError::Fuel {
                    plugin: plugin.to_string(),
                    fuel: self.config.fuel,
                },
                Trap::Interrupt => WasmError::Timeout {
                    plugin: plugin.to_string(),
                    timeout_ms: self.config.call_timeout.as_millis() as u64,
                },
                _ => WasmError::Trap {
                    plugin: plugin.to_string(),
                    msg: truncate(&format!("{trap}: {e}"), 240),
                },
            };
        }
        WasmError::Trap {
            plugin: plugin.to_string(),
            msg: truncate(&e.to_string(), 240),
        }
    }

    fn circuit_retry_ms(&self, short_name: &str) -> Option<u64> {
        let mut map = self.circuit.lock().expect("circuit poisoned");
        match map.get(short_name).copied() {
            Some(until) => {
                let now = Instant::now();
                if now < until {
                    Some(until.duration_since(now).as_millis() as u64)
                } else {
                    map.remove(short_name);
                    None
                }
            }
            None => None,
        }
    }

    fn trip_circuit(&self, short_name: &str, err: &WasmError) {
        let until = Instant::now() + self.config.circuit_break;
        let mut map = self.circuit.lock().expect("circuit poisoned");
        let newly_open = match map.get(short_name).copied() {
            Some(prev) => Instant::now() >= prev,
            None => true,
        };
        map.insert(short_name.to_string(), until);
        drop(map);
        self.metrics.circuit_trips.fetch_add(1, Ordering::Relaxed);
        if newly_open {
            self.hooks.on_circuit(&CircuitEvent {
                plugin: short_name.to_string(),
                open: true,
                reason: err.kind().as_str().to_string(),
                break_ms: self.config.circuit_break.as_millis() as u64,
            });
        }
    }

    fn record_failure(
        &self,
        short_name: &str,
        version: u32,
        mode: EntryMode,
        entry: &str,
        input_bytes: usize,
        err: &WasmError,
    ) {
        self.metrics.record(err.kind());
        self.metrics.failures.fetch_add(1, Ordering::Relaxed);
        self.hooks.on_call(&CallRecord {
            plugin: short_name.to_string(),
            version,
            entry: entry.to_string(),
            mode,
            ok: false,
            outcome: Some(err.kind()),
            elapsed_ms: 0,
            fuel_used: None,
            input_bytes,
            output_bytes: 0,
            error: Some(err.to_string()),
        });
    }
}

impl Drop for WasmHost {
    fn drop(&mut self) {
        self.ticker_stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.ticker.lock().expect("ticker poisoned").take() {
            let _ = handle.join();
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Truncate by chars to avoid splitting UTF-8.
        s.chars().take(max).collect()
    }
}

fn module_has_memory(module: &Module) -> bool {
    module
        .exports()
        .any(|e| e.name() == "memory" && matches!(e.ty(), ExternType::Memory(_)))
}

/// Resolve the ABI by entry name (used by admin invoke overrides; does not apply the manifest's default/fallback rules).
fn resolve_entry_name(module: &Module, name: &str) -> Result<EntryMode, String> {
    match module.get_export(name) {
        Some(ExternType::Func(ft)) if is_process_sig(&ft) => Ok(EntryMode::Process),
        Some(ExternType::Func(ft)) if is_run_sig(&ft) => Ok(EntryMode::Run),
        Some(ExternType::Func(ft)) => Err(format!(
            "export `{name}` has params {:?} / results {:?}, expected (i32,i32)->i64 or ()->i32",
            ft.params().collect::<Vec<_>>(),
            ft.results().collect::<Vec<_>>()
        )),
        Some(_) => Err(format!("export `{name}` is not a function")),
        None => Err(format!("no export named `{name}`")),
    }
}

/// Resolve the entry: prefer the `(i32,i32)->i64` export named `manifest.entry` (default `process`) in the module;
/// otherwise look for `run() -> i32` (including the name given by manifest.entry); if neither matches, return (name, reason).
fn resolve_entry(
    module: &Module,
    manifest: &crate::manifest::PluginManifest,
) -> Result<(String, EntryMode), (String, String)> {
    let entry = manifest.entry_name();
    // 1) manifest.entry (default process) as the process entry
    if let Some(ExternType::Func(ft)) = module.get_export(entry) {
        if is_process_sig(&ft) {
            return Ok((entry.to_string(), EntryMode::Process));
        }
        // 2) manifest.entry may also point directly at a run-style entry (custom name)
        if is_run_sig(&ft) {
            return Ok((entry.to_string(), EntryMode::Run));
        }
    }
    // 3) fall back to the standard run()
    if entry != "run" {
        if let Some(ExternType::Func(ft)) = module.get_export("run") {
            if is_run_sig(&ft) {
                return Ok(("run".to_string(), EntryMode::Run));
            }
        }
    }
    let reason = match module.get_export(entry) {
        Some(ExternType::Func(ft)) => format!(
            "export `{entry}` has params {:?} / results {:?}, expected (i32,i32)->i64 or ()->i32",
            ft.params().collect::<Vec<_>>(),
            ft.results().collect::<Vec<_>>()
        ),
        Some(_) => format!("export `{entry}` is not a function"),
        None => format!("no export named `{entry}` and no `run() -> i32` fallback"),
    };
    Err((entry.to_string(), reason))
}

fn is_process_sig(ft: &wasmtime::FuncType) -> bool {
    let params: Vec<wasmtime::ValType> = ft.params().collect();
    let results: Vec<wasmtime::ValType> = ft.results().collect();
    params.len() == 2
        && matches!(params[0], wasmtime::ValType::I32)
        && matches!(params[1], wasmtime::ValType::I32)
        && results.len() == 1
        && matches!(results[0], wasmtime::ValType::I64)
}

fn is_run_sig(ft: &wasmtime::FuncType) -> bool {
    let results: Vec<wasmtime::ValType> = ft.results().collect();
    ft.params().next().is_none() && results.len() == 1 && matches!(results[0], wasmtime::ValType::I32)
}

/// Smaller of the manifest request and the host cap; 0 means "use the host default".
fn effective_limits(
    manifest: &crate::manifest::PluginManifest,
    config: &HostConfig,
) -> EffectiveLimits {
    let req = manifest.limits;
    let memory_bytes = if req.memory_mb == 0 {
        config.memory_bytes
    } else {
        req.memory_mb.saturating_mul(MIB).min(config.memory_bytes)
    };
    let fuel = if req.fuel == 0 { config.fuel } else { req.fuel.min(config.fuel) };
    let timeout_ms = if req.timeout_ms == 0 {
        config.call_timeout.as_millis() as u64
    } else {
        req.timeout_ms.min(config.call_timeout.as_millis() as u64)
    };
    EffectiveLimits {
        memory_bytes: memory_bytes.max(64 * 1024),
        fuel: fuel.max(1),
        timeout_ms: timeout_ms.max(1),
    }
}

impl std::fmt::Debug for WasmHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmHost")
            .field("config", &self.config)
            .field("plugins", &self.plugins.read().map(|p| p.len()).unwrap_or(0))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// Process-unique sequence number (for naming temp directories).
    pub fn unique_seq() -> u64 {
        SEQ.fetch_add(1, Ordering::Relaxed)
    }
}
