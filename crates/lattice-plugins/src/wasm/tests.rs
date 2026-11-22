//! WASM host unit tests: normal calls / fuel / epoch timeout / memory overrun / trap / missing exports / circuit break /
//! concurrency cap / manifest validation / directory loading.
//!
//! Test modules are generated from WAT text with `wat::parse_str` (the host accepts binaries only).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::manifest::{PluginLimits, PluginManifest, SignatureCheck};

// ---------------------------------------------------------------------------
// Test WAT modules
// ---------------------------------------------------------------------------

/// Passthrough: `process(ptr,len)` returns the input unchanged (`alloc` always returns 1024).
const ECHO_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "process") (param i32 i32) (result i64)
    (i64.or
      (i64.extend_i32_u (local.get 0))
      (i64.shl (i64.extend_i32_u (local.get 1)) (i64.const 32)))))
"#;

/// Infinite loop (run mode): the loop body has arithmetic instructions (so every path consumes fuel),
/// until fuel runs out or the epoch interrupts.
const SPIN_WAT: &str = r#"
(module
  (func (export "run") (result i32)
    (local $i i64)
    (loop $l
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $l))
    (unreachable)))
"#;

/// Memory overrun: `memory.grow` by 2000 pages (128MiB) > 64MiB limit → limiter rejects → trap.
const MEMORY_HOG_WAT: &str = r#"
(module
  (memory 1)
  (func (export "run") (result i32)
    (drop (memory.grow (i32.const 2000)))
    (i32.const 0)))
"#;

/// `unreachable` trap.
const TRAP_WAT: &str = r#"
(module
  (func (export "run") (result i32) (unreachable)))
"#;

/// Only memory, with no entry export at all.
const MEMORY_ONLY_WAT: &str = r#"(module (memory (export "memory") 1))"#;

/// Returns a custom exit code.
const EXIT_CODE_WAT: &str = r#"
(module
  (func (export "run") (result i32) (i32.const 7)))
"#;

/// Normal run entry.
const RUN_OK_WAT: &str = r#"
(module
  (func (export "run") (result i32) (i32.const 0)))
"#;

/// Invalid ABI: output length 0xFFFFFFFF (exceeds max_output_bytes).
const BAD_ABI_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "process") (param i32 i32) (result i64)
    (i64.const 18446744069414584325)))
"#;

/// Module with an import (no WASI linked → instantiation fails).
const IMPORT_WAT: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))
  (func (export "run") (result i32) (i32.const 0)))
"#;

/// Slow call: a fixed 100M iterations (used to occupy concurrency slots; does not depend on timeouts).
const SLOW_WAT: &str = r#"
(module
  (func (export "run") (result i32)
    (local $i i32)
    (block $done
      (loop $l
        (br_if $done (i32.ge_u (local.get $i) (i32.const 100000000)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l)))
    (i32.const 0)))
"#;

/// Even slower occupancy call: 2B iterations (~0.8s; ~18B fuel).
///
/// For cases sensitive to the **wall-clock queueing window** such as "queue timeout when the pool is full": `SLOW_WAT` under CI/parallel load
/// may finish before the queuer is scheduled in, making `call` get a slot and return Ok instead of Busy (flaky).
/// The occupancy time (~0.8s) must be far larger than the queueing window (100ms), so scheduling jitter cannot change the tested semantics.
const VERY_SLOW_WAT: &str = r#"
(module
  (func (export "run") (result i32)
    (local $i i32)
    (block $done
      (loop $l
        (br_if $done (i32.ge_u (local.get $i) (i32.const 2000000000)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l)))
    (i32.const 0)))
"#;

/// Stateful plugin: each call increments a mutable global and returns it as the first output byte.
///
/// Used to verify **call isolation after pooling**: the host creates a new Instance in the pooled Store each time, and a new Instance's
/// globals/linear memory start at their initial values, so every output must be 1 (reusing an Instance would show 2/3/…).
const COUNTER_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (global $c (mut i32) (i32.const 0))
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "process") (param i32 i32) (result i64)
    (global.set $c (i32.add (global.get $c) (i32.const 1)))
    (i32.store8 (i32.const 1024) (global.get $c))
    (i64.or
      (i64.const 1024)
      (i64.shl (i64.const 1) (i64.const 32)))))
"#;

/// Manifest limits for "use host default limits" (0 = defer to host HostConfig).
fn host_default_limits() -> PluginLimits {
    PluginLimits {
        memory_mb: 0,
        fuel: 0,
        timeout_ms: 0,
    }
}

fn wasm(wat_src: &str) -> Vec<u8> {
    wat::parse_str(wat_src).expect("wat parse")
}

fn manifest(ns: &str, version: u32, entry: &str) -> PluginManifest {
    PluginManifest {
        ns: ns.into(),
        version,
        entry: entry.into(),
        deps: vec![],
        limits: PluginLimits::default(),
        signature: None,
        signing_key_id: None,
    }
}

fn package(ns: &str, version: u32, entry: &str, wat_src: &str) -> PluginPackage {
    PluginPackage::from_manifest(manifest(ns, version, entry), wasm(wat_src))
}

fn package_with_limits(
    ns: &str,
    version: u32,
    entry: &str,
    wat_src: &str,
    limits: PluginLimits,
) -> PluginPackage {
    let mut m = manifest(ns, version, entry);
    m.limits = limits;
    PluginPackage::from_manifest(m, wasm(wat_src))
}

/// Test implementation that records hook events.
#[derive(Default)]
struct Recorder {
    calls: Mutex<Vec<CallRecord>>,
    circuits: Mutex<Vec<CircuitEvent>>,
    loads: AtomicUsize,
}

impl HostHooks for Recorder {
    fn on_call(&self, record: &CallRecord) {
        self.calls.lock().unwrap().push(record.clone());
    }

    fn on_circuit(&self, event: &CircuitEvent) {
        self.circuits.lock().unwrap().push(event.clone());
    }

    fn on_load(&self, _info: &PluginInfo) {
        self.loads.fetch_add(1, Ordering::Relaxed);
    }
}

fn make_host(config: HostConfig) -> (WasmHost, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let host = WasmHost::with_hooks(config, recorder.clone()).expect("host");
    (host, recorder)
}

// ---------------------------------------------------------------------------
// Construction / type constraints
// ---------------------------------------------------------------------------

#[test]
fn host_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WasmHost>();
}

#[test]
fn defaults_match_design_values() {
    let c = HostConfig::default();
    assert_eq!(c.memory_bytes, 64 * MIB);
    assert_eq!(c.fuel, 100_000_000);
    assert_eq!(c.call_timeout, Duration::from_millis(500));
    assert_eq!(c.max_concurrency, 8);
    assert_eq!(c.circuit_break, Duration::from_secs(30));
    // Store pool defaults: 0 = pool size follows max_concurrency; 0 prewarm = fill the whole pool; 0 = default rotation cap.
    assert_eq!(c.pool_size, 0);
    assert_eq!(c.effective_pool_size(), 8);
    assert_eq!(c.pool_prewarm, 0);
    assert_eq!(c.effective_prewarm(), 8);
    assert_eq!(c.max_instances_per_store, DEFAULT_INSTANCES_PER_STORE);
    assert_eq!(c.effective_instances_per_store(), 8);
    assert_eq!(c.queue_timeout, Duration::from_secs(2));
}

// ---------------------------------------------------------------------------
// Normal calls: input passthrough + run entry + version replacement
// ---------------------------------------------------------------------------

#[test]
fn echo_roundtrip_passes_input_through() {
    let (host, recorder) = make_host(HostConfig::default());
    let info = host.register(package("echo", 1, "", ECHO_WAT)).unwrap();
    assert_eq!(info.mode, EntryMode::Process);
    assert_eq!(info.entry, "process");
    assert_eq!(info.limits.memory_bytes, 64 * MIB);
    assert!(!info.trusted, "an unverified plugin must be marked trusted=false");

    let input = b"hello lattice wasm plugin";
    let out = host.call("echo", input).unwrap();
    assert_eq!(out.output, input);
    assert_eq!(out.version, 1);
    assert!(out.fuel_used.unwrap_or(0) > 0, "a process call should consume fuel");
    assert!(out.elapsed_ms < 500);

    let calls = recorder.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].ok);
    assert_eq!(calls[0].outcome, None);
    assert_eq!(calls[0].input_bytes, input.len());
    assert_eq!(calls[0].output_bytes, input.len());
    assert_eq!(recorder.loads.load(Ordering::Relaxed), 1);
}

#[test]
fn empty_input_works_without_alloc() {
    // A process module without alloc allows empty input (ptr=0,len=0).
    let wat = r#"
    (module
      (memory (export "memory") 1)
      (func (export "process") (param i32 i32) (result i64) (i64.const 0)))
    "#;
    let (host, _) = make_host(HostConfig::default());
    host.register(package("empty", 1, "", wat)).unwrap();
    let out = host.call("empty", b"").unwrap();
    assert!(out.output.is_empty());
}

#[test]
fn run_entry_success_and_nonzero_exit_code() {
    let (host, _) = make_host(HostConfig::default());
    host.register(package("run-ok", 1, "", RUN_OK_WAT)).unwrap();
    let out = host.call("run-ok", b"").unwrap();
    assert!(out.output.is_empty());
    assert!(host.call("run-ok", b"").unwrap().output.is_empty());

    host.register(package("run-exit", 1, "", EXIT_CODE_WAT)).unwrap();
    let err = host.call("run-exit", b"").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ExitCode);
    assert!(matches!(err, WasmError::ExitCode { code: 7, .. }));
}

#[test]
fn re_registering_same_short_name_replaces_version() {
    let (host, _) = make_host(HostConfig::default());
    host.register(package("dup", 1, "", ECHO_WAT)).unwrap();
    let info = host.register(package("dup", 2, "", RUN_OK_WAT)).unwrap();
    assert_eq!(info.version, 2);
    assert_eq!(host.plugins().len(), 1);
    assert_eq!(host.info("dup").unwrap().mode, EntryMode::Run);
}

#[test]
fn minimal_manifest_json_uses_defaults() {
    // Older manifests have no entry/deps/limits fields and must still load (backward compatible).
    let pkg = PluginPackage::new(
        br#"{"ns":"legacy","version":2}"#.to_vec(),
        wasm(ECHO_WAT),
    )
    .unwrap();
    assert_eq!(pkg.manifest.entry_name(), "process");
    assert_eq!(pkg.manifest.limits, PluginLimits::default());
    assert_eq!(pkg.manifest.deps, Vec::<String>::new());

    let (host, _) = make_host(HostConfig::default());
    let info = host.register(pkg).unwrap();
    assert_eq!(info.entry, "process");
    assert_eq!(
        info.limits,
        EffectiveLimits {
            memory_bytes: 64 * MIB,
            fuel: 100_000_000,
            timeout_ms: 500,
        }
    );
    assert_eq!(host.call("legacy", b"x").unwrap().output, b"x");
}

// ---------------------------------------------------------------------------
// fuel limits
// ---------------------------------------------------------------------------

#[test]
fn dead_loop_exhausts_fuel_and_classifies() {
    let (host, recorder) = make_host(HostConfig::default());
    let mut limits = PluginLimits::default();
    limits.fuel = 2_000_000;
    host.register(package_with_limits("spin-fuel", 1, "", SPIN_WAT, limits))
        .unwrap();

    let started = Instant::now();
    let err = host.call("spin-fuel", b"").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Fuel, "err={err}");
    assert!(matches!(err, WasmError::Fuel { .. }));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the fuel limit should fail fast, actual {:?}",
        started.elapsed()
    );

    let calls = recorder.calls.lock().unwrap();
    assert_eq!(calls.last().unwrap().outcome, Some(ErrorKind::Fuel));
    assert!(!calls.last().unwrap().ok);
}

// ---------------------------------------------------------------------------
// Wall-clock limit (epoch interruption)
// ---------------------------------------------------------------------------

#[test]
fn dead_loop_times_out_via_epoch_and_trips_circuit() {
    let mut cfg = HostConfig::short_windows();
    cfg.call_timeout = Duration::from_millis(120);
    cfg.epoch_tick = Duration::from_millis(5);
    cfg.circuit_break = Duration::from_millis(150);
    // Give fuel generously so runtime is limited only by wall clock.
    cfg.fuel = 1_000_000_000_000;
    let (host, recorder) = make_host(cfg);

    // fuel / timeout / memory all use host config (manifest passes 0), so runtime is limited only by wall clock.
    host.register(package_with_limits(
        "spin-time",
        1,
        "",
        SPIN_WAT,
        host_default_limits(),
    ))
    .unwrap();

    let started = Instant::now();
    let err = host.call("spin-time", b"").unwrap_err();
    let elapsed = started.elapsed();
    assert_eq!(err.kind(), ErrorKind::Timeout, "err={err}");
    assert!(
        elapsed >= Duration::from_millis(90),
        "must not fire before the wall-clock limit; actual {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the epoch interrupt should take effect on the order of 500ms; actual {elapsed:?}"
    );

    // Circuit opens: the next call is circuit_open immediately (wasm is not executed).
    let t2 = Instant::now();
    let err2 = host.call("spin-time", b"").unwrap_err();
    assert_eq!(err2.kind(), ErrorKind::CircuitOpen, "err2={err2}");
    assert!(matches!(err2, WasmError::CircuitOpen { .. }));
    assert!(t2.elapsed() < Duration::from_millis(90), "an open circuit must return immediately");
    assert!(host.is_circuit_open("spin-time"));
    assert!(recorder.circuits.lock().unwrap().iter().any(|e| e.open));

    // After the short window it recovers automatically: still a timeout (not circuit_open), showing half-open release.
    std::thread::sleep(Duration::from_millis(180));
    assert!(!host.is_circuit_open("spin-time"));
    let err3 = host.call("spin-time", b"").unwrap_err();
    assert_eq!(err3.kind(), ErrorKind::Timeout, "after recovery it should execute again, err3={err3}");

    let metrics = host.metrics();
    assert!(metrics.circuit_open_rejected >= 1);
    assert!(metrics.circuit_trips >= 1);
    assert_eq!(metrics.by_outcome.get("timeout").copied().unwrap_or(0), 2);
}

#[test]
fn circuit_reset_allows_immediate_call() {
    let mut cfg = HostConfig::short_windows();
    cfg.call_timeout = Duration::from_millis(60);
    cfg.circuit_break = Duration::from_secs(30);
    cfg.fuel = 1_000_000_000_000;
    let (host, _) = make_host(cfg);
    host.register(package_with_limits(
        "spin-reset",
        1,
        "",
        SPIN_WAT,
        host_default_limits(),
    ))
    .unwrap();
    assert!(host.call("spin-reset", b"").is_err());
    assert!(host.is_circuit_open("spin-reset"));
    host.circuit_reset("spin-reset");
    assert!(!host.is_circuit_open("spin-reset"));
    let err = host.call("spin-reset", b"").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Timeout);
}

// ---------------------------------------------------------------------------
// Memory limits
// ---------------------------------------------------------------------------

#[test]
fn memory_growth_beyond_limit_traps_and_classifies_memory() {
    let (host, _) = make_host(HostConfig::default());
    host.register(package("mem-hog", 1, "", MEMORY_HOG_WAT)).unwrap();
    let err = host.call("mem-hog", b"").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Memory, "err={err}");
    assert!(matches!(err, WasmError::Memory { limit_bytes, .. } if limit_bytes == 64 * MIB));
    assert!(host.is_circuit_open("mem-hog"));

    let metrics = host.metrics();
    assert_eq!(metrics.by_outcome.get("memory").copied().unwrap_or(0), 1);
}

#[test]
fn per_manifest_memory_limit_is_clamped_by_host_cap() {
    let (host, _) = make_host(HostConfig::default());
    // Manifest requests 1MiB: memory.grow of 2000 pages (128MiB) is rejected just the same.
    let mut limits = PluginLimits::default();
    limits.memory_mb = 1;
    let pkg = package_with_limits("mem-1m", 1, "", MEMORY_HOG_WAT, limits);
    let info = host.register(pkg).unwrap();
    assert_eq!(info.limits.memory_bytes, MIB);
    let err = host.call("mem-1m", b"").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Memory);
}

#[test]
fn huge_manifest_limits_are_clamped_by_host() {
    let (host, _) = make_host(HostConfig::default());
    let mut limits = PluginLimits::default();
    limits.memory_mb = 1024; // 1GiB request
    limits.fuel = 999_999_999_999;
    limits.timeout_ms = 99_999;
    let info = host
        .register(package_with_limits("clamp", 1, "", ECHO_WAT, limits))
        .unwrap();
    assert_eq!(info.limits.memory_bytes, 64 * MIB);
    assert_eq!(info.limits.fuel, 100_000_000);
    assert_eq!(info.limits.timeout_ms, 500);
}

// ---------------------------------------------------------------------------
// trap / ABI / missing export / invalid wasm
// ---------------------------------------------------------------------------

#[test]
fn unreachable_traps() {
    let (host, _) = make_host(HostConfig::default());
    host.register(package("trap", 1, "", TRAP_WAT)).unwrap();
    let err = host.call("trap", b"").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Trap, "err={err}");
}

#[test]
fn missing_export_is_rejected_at_registration() {
    let (host, _) = make_host(HostConfig::default());
    let err = host.register(package("no-entry", 1, "", MEMORY_ONLY_WAT)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::MissingExport, "err={err}");

    // Only reported at registration time; never enters the plugin table.
    assert!(host.info("no-entry").is_none());
}

#[test]
fn bad_output_length_is_bad_abi() {
    let (host, _) = make_host(HostConfig::default());
    host.register(package("bad-abi", 1, "", BAD_ABI_WAT)).unwrap();
    let err = host.call("bad-abi", b"x").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BadAbi, "err={err}");
}

#[test]
fn invalid_wasm_is_rejected_as_manifest_error() {
    let (host, _) = make_host(HostConfig::default());
    let pkg = PluginPackage::from_manifest(manifest("broken", 1, ""), b"not wasm".to_vec());
    let err = host.register(pkg).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Manifest, "err={err}");
}

#[test]
fn module_with_unlinked_import_fails_instantiation() {
    let (host, _) = make_host(HostConfig::default());
    let pkg = PackageBuilder::new("imports", IMPORT_WAT).run_entry().build();
    host.register(pkg).unwrap();
    let err = host.call("imports", b"").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Trap, "err={err}");
    assert!(
        err.to_string().contains("import"),
        "instantiation failure should point at the unlinked import, err={err}"
    );
}

#[test]
fn digest_mismatch_is_rejected_but_correct_digest_accepted() {
    let (host, _) = make_host(HostConfig::default());
    let base = package("digest", 1, "", ECHO_WAT);
    let correct = base.content_sha256();
    let bad = base.clone().with_digest("00".repeat(32));
    assert_eq!(host.register(bad).unwrap_err().kind(), ErrorKind::Manifest);
    host.register(base.with_digest(correct)).unwrap();
    assert!(host.call("digest", b"hi").is_ok());
}

#[test]
fn unverified_signature_is_untrusted_and_require_verified_rejects_all() {
    // The default host has no trusted public key: any signature bytes can only be Missing/untrusted, never trusted.
    let (host, _) = make_host(HostConfig::default());
    let signed = package("signed", 1, "", ECHO_WAT).with_signature(vec![0xAB; 64]);
    let info = host.register(signed).unwrap();
    assert_eq!(info.signature, SignatureCheck::Missing);
    assert_eq!(info.signature_detail, "no_signing_key_id");
    assert!(!info.trusted);

    // Turn on "require verified signature" → unsigned/no trusted key is rejected outright (fail-closed).
    let mut cfg = HostConfig::default();
    cfg.require_verified_signature = true;
    let (strict_host, _) = make_host(cfg);
    let err = strict_host
        .register(package("strict", 1, "", ECHO_WAT).with_signature(vec![0; 64]))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Signature);
    assert!(err.to_string().contains("signature not verified"), "err={err}");
    let report = strict_host.security_report();
    // No trusted public key → keeps the old E2E wording (and is semantically correct: no key = cannot verify).
    assert_eq!(
        report.signature_verification,
        "not_implemented: Ed25519 verify missing (design §4.5)"
    );
    assert_eq!(report.trusted_keys, 0);
    assert!(report.require_verified_signature);
    assert_eq!(report.wasi, "disabled: no WASI host functions are linked");
}

#[test]
fn invalid_signature_is_always_rejected_even_without_require_flag() {
    // Signature + key id declared, but the signature content does not match → Invalid → rejected even with require=false.
    let mut cfg = HostConfig::default();
    let mut keys = TrustedKeys::new();
    keys.insert("release-1", &b64(&[3u8; 32])).unwrap();
    cfg.trusted_keys = keys;
    let (host, _) = make_host(cfg);
    let mut pkg = package("bad-sig", 1, "", ECHO_WAT).with_signature(vec![0u8; 64]);
    pkg.manifest.signing_key_id = Some("release-1".into());
    let err = host.register(pkg).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Signature);
    assert!(matches!(
        err,
        WasmError::Signature { ref reason, .. } if reason == "signature_mismatch"
    ));
    assert!(host.info("bad-sig").is_none(), "a bad signature must not enter the plugin table");
}

#[test]
fn unknown_signing_key_is_rejected_fail_closed() {
    let mut cfg = HostConfig::default();
    let mut keys = TrustedKeys::new();
    keys.insert("release-1", &b64(&[3u8; 32])).unwrap();
    cfg.trusted_keys = keys;
    let (host, _) = make_host(cfg);
    let mut pkg = package("unknown-key", 1, "", ECHO_WAT).with_signature(vec![0u8; 64]);
    pkg.manifest.signing_key_id = Some("release-2".into());
    let err = host.register(pkg).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Signature);
    assert!(matches!(
        err,
        WasmError::Signature { ref reason, .. } if reason == "unknown_signing_key"
    ));
}

/// Verify that a real signature passes using the fixed fixture produced by the same flow as the E2E (Node generates an Ed25519 key + signature).
///
/// The fixture is generated by `scripts/wasm-plugin-e2e.mjs --emit-fixture` and committed under
/// `crates/lattice-plugins/tests/fixtures/wasm-signed/`: manifest.json + plugin.wasm +
/// `fixture.json` (public_key_b64 / signing_key_id). Signed body = sha256(wasm || canonical).
#[test]
fn real_ed25519_signed_package_registers_as_trusted_and_invokable() {
    let fx = fixture::load();
    let mut keys = TrustedKeys::new();
    keys.insert(&fx.signing_key_id, &fx.public_key_b64).unwrap();
    let mut cfg = HostConfig::default();
    cfg.trusted_keys = keys;
    cfg.require_verified_signature = true;
    let (host, recorder) = make_host(cfg);

    let pkg = PluginPackage::new(fx.manifest_bytes.clone(), fx.wasm.clone()).unwrap();
    let info = host.register(pkg).unwrap();
    assert_eq!(info.signature, SignatureCheck::Verified, "{info:?}");
    assert_eq!(info.signature_detail, "verified");
    assert_eq!(info.signing_key_id.as_deref(), Some(fx.signing_key_id.as_str()));
    assert!(info.trusted, "passing verification must set trusted=true");
    assert_eq!(info.ns, "signed-echo");

    let input = b"lattice-ed25519-fixture";
    let out = host.call("signed-echo", input).unwrap();
    assert_eq!(out.output, input);
    let report = host.security_report();
    assert!(report.signature_verification.starts_with("ed25519_ring:"), "{report:?}");
    assert_eq!(report.trusted_keys, 1);
    assert_eq!(report.trusted_plugins, 1);
    assert_eq!(report.untrusted_plugins, 0);
    assert_eq!(recorder.loads.load(Ordering::Relaxed), 1);

    // Tamper with the wasm (the signature covers the wasm bytes) → loading is rejected.
    let mut wasm = fx.wasm.clone();
    let last = wasm.len() - 1;
    wasm[last] ^= 0xFF;
    // Rebuild the package with the tampered wasm (manifest unchanged); the signature no longer matches → Invalid.
    let bad = PluginPackage::new(fx.manifest_bytes.clone(), wasm).unwrap();
    let err = host.register(bad).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Signature);
}

#[test]
fn signature_helper_b64_covers_encoding_and_report_redaction() {
    let mut keys = TrustedKeys::new();
    keys.insert("release-1", &b64(&[5u8; 32])).unwrap();
    assert!(keys.contains("release-1"));
    assert_eq!(keys.ids(), vec!["release-1"]);
    assert_eq!(keys.len(), 1);
    let debug = format!("{keys:?}");
    assert!(!debug.contains(&b64(&[5u8; 32])), "Debug must not leak public keys: {debug}");
}

fn b64(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD.encode(bytes)
}

/// Fixed signature fixture (generated by the E2E script; see `tests/fixtures/wasm-signed/README.md`).
mod fixture {
    pub const MANIFEST: &[u8] = include_bytes!("../../tests/fixtures/wasm-signed/manifest.json");
    pub const WASM: &[u8] = include_bytes!("../../tests/fixtures/wasm-signed/plugin.wasm");
    pub const META: &[u8] = include_bytes!("../../tests/fixtures/wasm-signed/fixture.json");

    pub struct Fixture {
        pub manifest_bytes: Vec<u8>,
        pub wasm: Vec<u8>,
        pub public_key_b64: String,
        pub signing_key_id: String,
    }

    pub fn load() -> Fixture {
        let meta: serde_json::Value = serde_json::from_slice(META).expect("fixture.json");
        Fixture {
            manifest_bytes: MANIFEST.to_vec(),
            wasm: WASM.to_vec(),
            public_key_b64: meta["public_key_b64"].as_str().unwrap().to_string(),
            signing_key_id: meta["signing_key_id"].as_str().unwrap().to_string(),
        }
    }
}

#[test]
fn unknown_plugin_returns_not_found() {
    let (host, _) = make_host(HostConfig::default());
    let err = host.call("nope", b"").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotFound);
}

// ---------------------------------------------------------------------------
// Zero-knowledge runtime probe: content plugin allowlist (E25 / PL-10 §6 risk mitigation)
// ---------------------------------------------------------------------------

#[test]
fn content_plugin_class_is_prefix_based_and_case_insensitive() {
    assert_eq!(content_plugin_class("convert:json->text"), Some("convert:"));
    assert_eq!(
        content_plugin_class("convert:application/x-ndjson->application/json@2"),
        Some("convert:")
    );
    assert_eq!(content_plugin_class("Convert:json->text"), Some("convert:"));
    assert_eq!(content_plugin_class("transcode:mp4->ogg"), Some("transcode:"));
    assert_eq!(content_plugin_class("format:json->xml"), Some("format:"));
    assert_eq!(content_plugin_class("detect:magic"), Some("detect:"));
    // Regular utility plugins are unaffected
    assert_eq!(content_plugin_class("echo"), None);
    assert_eq!(content_plugin_class("signed-echo"), None);
    assert_eq!(content_plugin_class("json"), None);
    assert_eq!(content_plugin_class("converter"), None, "only class prefixes with a colon match");
}

#[test]
fn zero_knowledge_policy_rejects_content_plugins_at_registration() {
    // Zero-knowledge deployment: the node sets allow_content_plugins to false.
    let mut cfg = HostConfig::default();
    cfg.allow_content_plugins = false;
    let (host, recorder) = make_host(cfg);

    // Content plugins fail-closed: not compiled, not registered, no on_load fired.
    let err = host
        .register(package("convert:json->text", 1, "", ECHO_WAT))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ContentBlocked, "err={err}");
    assert!(matches!(
        err,
        WasmError::ContentBlocked { ref class, .. } if class == "convert"
    ));
    assert!(err.to_string().contains("zero-knowledge"), "the error must state the mode reason: {err}");
    assert!(host.info("convert:json->text").is_none(), "content plugins must not enter the registry");
    assert_eq!(recorder.loads.load(Ordering::Relaxed), 0);

    // Utility plugins register/run as usual (zero-knowledge mode only forbids content-parsing plugins).
    host.register(package("echo", 1, "", ECHO_WAT)).unwrap();
    let out = host.call("echo", b"hello").unwrap();
    assert_eq!(out.output, b"hello");

    let report = host.security_report();
    assert!(!report.content_plugins_allowed, "the state must be observable: {report:?}");
    assert_eq!(report.trusted_plugins + report.untrusted_plugins, 1);
}

#[test]
fn default_policy_still_allows_content_plugins() {
    // Default (inspectable/library layer) allows content plugins: the policy default must not be flipped to reject.
    let (host, _) = make_host(HostConfig::default());
    let info = host
        .register(package("convert:json->text", 1, "", ECHO_WAT))
        .expect("the default policy allows content plugins");
    assert_eq!(info.short_name, "convert:json->text");
    assert!(host.security_report().content_plugins_allowed);
}


#[test]
fn oversized_input_is_rejected_before_wasm() {
    let mut cfg = HostConfig::default();
    cfg.max_input_bytes = 4;
    let (host, _) = make_host(cfg);
    host.register(package("io-limit", 1, "", ECHO_WAT)).unwrap();
    let err = host.call("io-limit", b"0123456789").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BadAbi);
    assert!(host.call("io-limit", b"0123").is_ok());
}

// ---------------------------------------------------------------------------
// Concurrency cap: queueing vs rejection
// ---------------------------------------------------------------------------

#[test]
fn concurrency_limit_rejects_with_try_call_and_queues_with_call() {
    let mut cfg = HostConfig::default();
    cfg.max_concurrency = 2;
    cfg.call_timeout = Duration::from_secs(10);
    cfg.queue_timeout = Duration::from_secs(5);
    cfg.circuit_break = Duration::from_secs(5);
    cfg.fuel = 5_000_000_000;
    let (host, _) = make_host(cfg);
    host.register(package_with_limits(
        "slow",
        1,
        "",
        SLOW_WAT,
        host_default_limits(),
    ))
    .unwrap();
    let host = Arc::new(host);

    let started = Arc::new(std::sync::Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let h = host.clone();
        let b = started.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            h.call("slow", b"").map(|o| o.output.len())
        }));
    }
    started.wait();

    // Wait until both slots are occupied (up to 5s).
    let deadline = Instant::now() + Duration::from_secs(5);
    while host.metrics().active_calls < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(host.metrics().active_calls, 2, "exactly 2 slots should be occupied");

    // try_call: immediate Busy, no queueing.
    let err = host.try_call("slow", b"").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Busy, "err={err}");

    // call: queues for a slot and eventually succeeds (not Busy).
    let queued = {
        let h = host.clone();
        std::thread::spawn(move || h.call("slow", b"").map(|o| o.output.len()))
    };

    for handle in handles {
        let out = handle.join().unwrap().expect("slow call should succeed");
        assert_eq!(out, 0);
    }
    let queued_out = queued.join().unwrap().expect("queued call should eventually run");
    assert_eq!(queued_out, 0);

    let metrics = host.metrics();
    assert!(metrics.busy_rejected >= 1, "metrics={metrics:?}");
    assert!(metrics.queued_wait_total >= 1, "the queue counter should be recorded, metrics={metrics:?}");
    assert_eq!(metrics.active_calls, 0, "slots must be returned after calls finish");
    assert_eq!(metrics.ok_total, 3);
}

// ---------------------------------------------------------------------------
// Store pooling: pre-warm reuse / on-demand growth / rotation recycle / queue timeout / call isolation
// ---------------------------------------------------------------------------

#[test]
fn pool_prewarms_stores_and_reports_hits() {
    let mut cfg = HostConfig::default();
    cfg.pool_size = 2;
    cfg.pool_prewarm = 0; // 0 = fill the whole pool
    let (host, _) = make_host(cfg);
    host.register(package("pool-echo", 1, "", ECHO_WAT)).unwrap();

    let before = host.metrics();
    assert_eq!(before.pool_size, 2);
    assert_eq!(before.pool_prewarmed, 2, "fills the whole pool");
    assert_eq!(before.pool_created, 2, "2 Stores created at construction");
    assert_eq!(before.pool_idle, 2);
    assert_eq!(before.pool_hits, 0);

    // Sequential calls: both kinds of slots are reused from the idle list → hit, no new creation.
    for _ in 0..4 {
        let out = host.call("pool-echo", b"p").unwrap();
        assert_eq!(out.output, b"p");
    }
    let m = host.metrics();
    assert_eq!(m.pool_hits, 4, "all 4 calls hit pre-warmed slots: {m:?}");
    assert_eq!(m.pool_misses, 0);
    assert_eq!(m.pool_created, 2, "no new Store created");
    assert_eq!(m.pool_idle, 2, "all slots returned after calls finish");
    assert_eq!(m.active_calls, 0);
}

#[test]
fn pool_lazy_creation_counts_misses() {
    let mut cfg = HostConfig::default();
    cfg.pool_size = 3;
    cfg.pool_prewarm = 1; // pre-warm only 1
    cfg.call_timeout = Duration::from_secs(10);
    cfg.fuel = 5_000_000_000;
    let (host, _) = make_host(cfg);
    host.register(package_with_limits(
        "slow",
        1,
        "",
        SLOW_WAT,
        host_default_limits(),
    ))
    .unwrap();
    let host = Arc::new(host);

    let before = host.metrics();
    assert_eq!(before.pool_prewarmed, 1);
    assert_eq!(before.pool_created, 1);

    // Two concurrent calls: the first hits the pre-warmed slot, the second finds no idle slot → creates on demand (miss).
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let h = host.clone();
        let b = barrier.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            h.call("slow", b"").map(|o| o.output.len())
        }));
    }
    for handle in handles {
        assert_eq!(handle.join().unwrap().expect("concurrent calls should succeed"), 0);
    }

    let m = host.metrics();
    assert_eq!(m.pool_hits, 1, "hit the pre-warmed slot: {m:?}");
    assert_eq!(m.pool_misses, 1, "created on demand when no idle slot was free: {m:?}");
    assert_eq!(m.pool_created, 2, "1 pre-warmed + 1 created on demand");
    assert_eq!(m.pool_idle, 2, "both slots returned");
}

#[test]
fn pool_recycles_store_after_max_instances() {
    let mut cfg = HostConfig::default();
    cfg.pool_size = 1;
    cfg.pool_prewarm = 1;
    cfg.max_instances_per_store = 2;
    let (host, _) = make_host(cfg);
    host.register(package("pool-echo", 1, "", ECHO_WAT)).unwrap();

    assert_eq!(host.metrics().max_instances_per_store, 2);
    // The first 2 calls each create 1 Instance; on the 3rd call the same slot has instances_used==2 → recycle and rebuild.
    for i in 0..3 {
        let out = host.call("pool-echo", format!("v{i}").as_bytes()).unwrap();
        assert_eq!(out.output, format!("v{i}").as_bytes());
    }
    let m = host.metrics();
    assert_eq!(m.pool_recycled, 1, "rebuilt once after reaching the cap: {m:?}");
    assert_eq!(m.pool_created, 2, "1 pre-warmed + 1 rebuilt");
    assert_eq!(m.pool_hits, 3, "all 3 calls hit the same slot (1 of them triggered a rebuild)");
}

#[test]
fn pooled_store_keeps_invocations_isolated() {
    let mut cfg = HostConfig::default();
    cfg.pool_size = 1;
    cfg.pool_prewarm = 1;
    cfg.max_instances_per_store = 8;
    let (host, _) = make_host(cfg);
    host.register(package("counter", 1, "", COUNTER_WAT)).unwrap();

    // 5 consecutive calls (hitting the same Store slot): a new Instance each time → always starts at 1.
    for i in 0..5 {
        let out = host.call("counter", b"").unwrap();
        assert_eq!(
            out.output,
            vec![1],
            "call #{i} must see a brand-new Instance (reuse would leak state); got={:?}",
            out.output
        );
    }
    let m = host.metrics();
    assert_eq!(m.pool_hits, 5, "all calls hit the reused slot");
    assert_eq!(m.pool_created, 1, "only one Store was created");
}

#[test]
fn pool_queue_timeout_returns_busy() {
    let mut cfg = HostConfig::default();
    cfg.pool_size = 1;
    cfg.pool_prewarm = 1;
    cfg.call_timeout = Duration::from_secs(30);
    cfg.queue_timeout = Duration::from_millis(100);
    cfg.circuit_break = Duration::from_secs(5);
    // 2B iterations consume ~18B fuel: relax the host cap to 50B so the occupant is not stopped early by fuel.
    cfg.fuel = 50_000_000_000;
    let (host, _) = make_host(cfg);
    host.register(package_with_limits(
        "slow",
        1,
        "",
        VERY_SLOW_WAT,
        host_default_limits(),
    ))
    .unwrap();
    let host = Arc::new(host);

    let started = Arc::new(std::sync::Barrier::new(2));
    let runner = {
        let h = host.clone();
        let b = started.clone();
        std::thread::spawn(move || {
            b.wait();
            h.call("slow", b"")
        })
    };
    started.wait();
    // Wait until the only slot is occupied.
    let deadline = Instant::now() + Duration::from_secs(5);
    while host.metrics().active_calls < 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(host.metrics().active_calls, 1, "the occupancy call should have entered the slot");
    let t = Instant::now();
    let err = host.call("slow", b"").unwrap_err();
    let elapsed = t.elapsed();
    assert_eq!(err.kind(), ErrorKind::Busy, "err={err}");
    assert!(
        elapsed < Duration::from_secs(1),
        "queue timeout should return Busy promptly; actual {elapsed:?}"
    );
    runner.join().unwrap().expect("the occupancy call should succeed");
    let m = host.metrics();
    assert!(m.busy_rejected >= 1, "{m:?}");
    assert!(m.queued_wait_total >= 1, "calls that waited for a slot should be counted: {m:?}");
    assert_eq!(m.active_calls, 0);
}

// ---------------------------------------------------------------------------
// Registry: memory / directory / deps
// ---------------------------------------------------------------------------

#[test]
fn load_registry_checks_deps_and_loads_all() {
    let registry = MemoryRegistry::new();
    let mut with_dep = manifest("with-dep", 1, "");
    with_dep.deps = vec!["base".into()];
    with_dep.limits = PluginLimits::default();
    registry.insert(PluginPackage::from_manifest(with_dep, wasm(ECHO_WAT)));
    registry.insert(package("base", 1, "", ECHO_WAT));

    let (host, _) = make_host(HostConfig::default());
    let report = host.load_registry(&registry);
    assert!(report.ok(), "report={report:?}");
    assert_eq!(report.loaded.len(), 2);
    assert!(host.info("with-dep").is_some());

    // Missing dependency → goes into rejected and is not loaded.
    let registry2 = MemoryRegistry::new();
    let mut orphan = manifest("orphan", 1, "");
    orphan.deps = vec!["missing-dep".into()];
    registry2.insert(PluginPackage::from_manifest(orphan, wasm(ECHO_WAT)));
    let report2 = host.load_registry(&registry2);
    assert_eq!(report2.rejected.len(), 1);
    assert_eq!(report2.rejected[0].plugin, "orphan");
    assert!(report2.rejected[0].reason.contains("missing dependency"));
    assert!(host.info("orphan").is_none());
}

#[test]
fn load_dir_loads_plugin_packages_and_reports_bad_dirs() {
    let root = std::env::temp_dir().join(format!(
        "lattice-plugins-e2e-{}-{}",
        std::process::id(),
        super::test_support::unique_seq()
    ));
    let good = root.join("echo");
    std::fs::create_dir_all(&good).unwrap();
    std::fs::write(
        good.join("manifest.json"),
        br#"{"ns":"echo-dir","version":4,"entry":"process","deps":[],"limits":{"memory_mb":8,"fuel":5000000,"timeout_ms":200}}"#,
    )
    .unwrap();
    std::fs::write(good.join("plugin.wasm"), wasm(ECHO_WAT)).unwrap();
    let bad = root.join("broken");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("manifest.json"), b"{}").unwrap();

    let (host, _) = make_host(HostConfig::default());
    let report = host.load_dir(&root);
    assert_eq!(report.loaded.len(), 1, "report={report:?}");
    assert_eq!(report.rejected.len(), 1, "report={report:?}");
    let info = &report.loaded[0];
    assert_eq!(info.short_name, "echo-dir");
    assert_eq!(info.version, 4);
    assert_eq!(info.limits.memory_bytes, 8 * MIB);
    assert_eq!(info.limits.fuel, 5_000_000);
    assert_eq!(info.limits.timeout_ms, 200);
    assert_eq!(host.call("echo-dir", b"dir-input").unwrap().output, b"dir-input");
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Small helper: a more compact PackageBuilder (for readability only)
// ---------------------------------------------------------------------------

struct PackageBuilder {
    manifest: PluginManifest,
    wasm: Vec<u8>,
}

impl PackageBuilder {
    fn new(ns: &str, wat_src: &str) -> Self {
        Self {
            manifest: manifest(ns, 1, ""),
            wasm: wasm(wat_src),
        }
    }

    fn run_entry(mut self) -> Self {
        self.manifest.entry = "run".into();
        self
    }

    fn build(self) -> PluginPackage {
        PluginPackage::from_manifest(self.manifest, self.wasm)
    }
}
