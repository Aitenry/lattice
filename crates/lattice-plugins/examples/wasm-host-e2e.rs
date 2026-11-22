//! WASM host end-to-end probe (built and run by `scripts/wasm-host-e2e.mjs`).
//!
//! Covers: directory manifest+wasm loading → normal input passthrough / run entry; fuel exhaustion; epoch wall-clock timeout;
//! memory overrun; `unreachable` trap; missing export; invalid manifest; unsigned-signature placeholder; circuit-open immediate rejection +
//! short-window recovery; concurrency cap (try_call rejected + call queued); registry deps validation; security boundary and metrics snapshot.
//!
//! Output: single-line JSON (stdout); exit 0 when everything passes, otherwise exit 1.
//! Test modules are generated from WAT text with `wat::parse_str`; the host side accepts only wasm binaries (same as production).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lattice_plugins::manifest::{PluginLimits, PluginManifest};
use lattice_plugins::manifest::SignatureCheck;
use lattice_plugins::wasm::{
    CallRecord, CircuitEvent, DirRegistry, EntryMode, ErrorKind, HostConfig, HostHooks,
    MemoryRegistry, PluginInfo, PluginPackage, WasmError, WasmHost, MIB,
};
use serde_json::json;

// ---------------------------------------------------------------------------
// Test wasm modules (WAT → wasm binary)
// ---------------------------------------------------------------------------

const ECHO_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "process") (param i32 i32) (result i64)
    (i64.or
      (i64.extend_i32_u (local.get 0))
      (i64.shl (i64.extend_i32_u (local.get 1)) (i64.const 32)))))
"#;

const RUN_OK_WAT: &str = r#"
(module
  (func (export "run") (result i32) (i32.const 0)))
"#;

const SPIN_WAT: &str = r#"
(module
  (func (export "run") (result i32)
    (local $i i64)
    (loop $l
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $l))
    (unreachable)))
"#;

const SLOW_WAT: &str = r#"
(module
  (func (export "run") (result i32)
    (local $i i32)
    (block $done
      (loop $l
        (br_if $done (i32.ge_u (local.get $i) (i32.const 50000000)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l)))
    (i32.const 0)))
"#;

const MEMORY_HOG_WAT: &str = r#"
(module
  (memory 1)
  (func (export "run") (result i32)
    (drop (memory.grow (i32.const 2000)))
    (i32.const 0)))
"#;

const TRAP_WAT: &str = r#"
(module
  (func (export "run") (result i32) (unreachable)))
"#;

const MEMORY_ONLY_WAT: &str = r#"(module (memory (export "memory") 1))"#;

fn wasm(wat_src: &str) -> Vec<u8> {
    wat::parse_str(wat_src).expect("wat parse")
}

fn pkg(ns: &str, version: u32, entry: &str, wat_src: &str, limits: PluginLimits) -> PluginPackage {
    PluginPackage::from_manifest(
        PluginManifest {
            ns: ns.into(),
            version,
            entry: entry.into(),
            deps: vec![],
            limits,
            signature: None,
            signing_key_id: None,
        },
        wasm(wat_src),
    )
}

/// 0 = use host default limits.
fn host_limits() -> PluginLimits {
    PluginLimits {
        memory_mb: 0,
        fuel: 0,
        timeout_ms: 0,
    }
}

// ---------------------------------------------------------------------------
// Hooks / report
// ---------------------------------------------------------------------------

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

fn e2e_host(config: HostConfig) -> (WasmHost, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let host = WasmHost::with_hooks(config, recorder.clone()).expect("host init");
    (host, recorder)
}

struct Scenario {
    name: &'static str,
    pass: bool,
    detail: String,
    elapsed_ms: u128,
}

#[derive(Default)]
struct Report {
    scenarios: Vec<Scenario>,
}

impl Report {
    fn check(&mut self, name: &'static str, pass: bool, detail: impl Into<String>, elapsed: Duration) {
        let detail = detail.into();
        println!(
            "{} {name} ({detail}, {elapsed:?})",
            if pass { "PASS" } else { "FAIL" }
        );
        self.scenarios.push(Scenario {
            name,
            pass,
            detail,
            elapsed_ms: elapsed.as_millis(),
        });
    }
}

fn expect_kind<T: std::fmt::Debug>(result: &Result<T, WasmError>, kind: ErrorKind) -> Result<(), String> {
    match result {
        Ok(v) => Err(format!("expected error kind {kind:?}, got Ok({v:?})")),
        Err(e) if e.kind() == kind => Ok(()),
        Err(e) => Err(format!("expected error kind {kind:?}, got {:?} ({e})", e.kind())),
    }
}

fn err_text<T: std::fmt::Debug>(result: &Result<T, WasmError>) -> String {
    match result {
        Ok(v) => format!("Ok({v:?})"),
        Err(e) => format!("{:?}: {e}", e.kind()),
    }
}

fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "lattice-wasm-host-e2e-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let mut report = Report::default();
    let (host, recorder) = e2e_host(HostConfig::default());
    // 1) Directory registry: <root>/<plugin>/manifest.json + plugin.wasm → load
    let t = Instant::now();
    let dir = unique_temp_dir("echo");
    let plugin_dir = dir.join("echo");
    std::fs::create_dir_all(&plugin_dir).unwrap();
    std::fs::write(
        plugin_dir.join("manifest.json"),
        r#"{"ns":"echo","version":1,"entry":"","deps":[],"limits":{"memory_mb":64,"fuel":100000000,"timeout_ms":500}}"#,
    )
    .unwrap();
    std::fs::write(plugin_dir.join("plugin.wasm"), wasm(ECHO_WAT)).unwrap();
    let scan = DirRegistry::new(&dir).scan();
    let dir_report = host.load_dir(&dir);
    report.check(
        "dir_manifest_wasm_load",
        scan.packages.len() == 1 && scan.rejected.is_empty() && dir_report.ok() && dir_report.loaded.len() == 1,
        format!(
            "scan_packages={} rejected={} load_loaded={} load_rejected={}",
            scan.packages.len(),
            scan.rejected.len(),
            dir_report.loaded.len(),
            dir_report.rejected.len()
        ),
        t.elapsed(),
    );
    let _ = std::fs::remove_dir_all(&dir);

    // 2) process entry: input passthrough + effective limit values
    let t = Instant::now();
    let input = b"lattice wasm host e2e payload";
    let echo = host.call("echo", input);
    let info = host.info("echo").unwrap();
    report.check(
        "echo_process_input_roundtrip",
        echo.as_ref().map(|o| o.output.as_slice() == input).unwrap_or(false)
            && info.mode == EntryMode::Process
            && info.limits.memory_bytes == 64 * MIB,
        format!(
            "in={} result={} limits={:?}",
            input.len(),
            err_text(&echo.map(|o| format!("{}B equal={}", o.output.len(), o.output == input))),
            info.limits
        ),
        t.elapsed(),
    );

    // 3) run() minimal entry
    let t = Instant::now();
    let run_info = host.register(pkg("run-ok", 1, "run", RUN_OK_WAT, host_limits()));
    let run_out = host.call("run-ok", b"");
    report.check(
        "run_entry_zero_exit",
        run_info.as_ref().map(|i| i.mode == EntryMode::Run).unwrap_or(false)
            && run_out.as_ref().map(|o| o.output.is_empty()).unwrap_or(false),
        format!("mode={:?} call={}", run_info.as_ref().map(|i| i.mode), err_text(&run_out)),
        t.elapsed(),
    );

    // 4) fuel limit: manifest 3M fuel → Fuel attribution, and it trips the circuit
    let t = Instant::now();
    host.register(pkg("spin-fuel", 1, "run", SPIN_WAT, PluginLimits {
        memory_mb: 0,
        fuel: 3_000_000,
        timeout_ms: 0,
    }))
    .unwrap();
    let fuel_result = host.call("spin-fuel", b"");
    let fuel_circuit = host.is_circuit_open("spin-fuel");
    report.check(
        "fuel_limit_exhausted",
        expect_kind(&fuel_result, ErrorKind::Fuel).is_ok() && fuel_circuit,
        format!("result={} circuit_open={fuel_circuit} elapsed={:?}", err_text(&fuel_result), t.elapsed()),
        t.elapsed(),
    );

    // 5) Immediate circuit_open during the circuit window (wasm is not entered again)
    let t = Instant::now();
    let opened = host.call("spin-fuel", b"");
    report.check(
        "circuit_open_rejects_fast",
        expect_kind(&opened, ErrorKind::CircuitOpen).is_ok() && t.elapsed() < Duration::from_millis(100),
        format!("result={} elapsed={:?}", err_text(&opened), t.elapsed()),
        t.elapsed(),
    );

    // 6) Wall-clock limit (epoch interruption): 150ms short window
    let t = Instant::now();
    let mut timeout_cfg = HostConfig::short_windows();
    timeout_cfg.call_timeout = Duration::from_millis(150);
    timeout_cfg.epoch_tick = Duration::from_millis(5);
    timeout_cfg.circuit_break = Duration::from_millis(150);
    timeout_cfg.fuel = 1_000_000_000_000; // let only the wall clock take effect
    let (timeout_host, _timeout_recorder) = e2e_host(timeout_cfg);
    timeout_host
        .register(pkg("spin-time", 1, "run", SPIN_WAT, host_limits()))
        .unwrap();
    let started = Instant::now();
    let timed = timeout_host.call("spin-time", b"");
    let timed_elapsed = started.elapsed();
    report.check(
        "epoch_wall_clock_timeout_500ms_class",
        expect_kind(&timed, ErrorKind::Timeout).is_ok()
            && timed_elapsed >= Duration::from_millis(120)
            && timed_elapsed < Duration::from_secs(2),
        format!("result={} elapsed={timed_elapsed:?} (configured 150ms)", err_text(&timed)),
        t.elapsed(),
    );

    // 7) Short-window circuit recovery: after the window it executes again (still Timeout, not circuit_open)
    let t = Instant::now();
    std::thread::sleep(Duration::from_millis(220));
    let recovered = timeout_host.call("spin-time", b"");
    report.check(
        "circuit_recovery_after_window",
        expect_kind(&recovered, ErrorKind::Timeout).is_ok(),
        format!("result={} (window 150ms, waited 220ms)", err_text(&recovered)),
        t.elapsed(),
    );

    // 8) Memory limit: memory.grow 128MiB > 64MiB → Memory attribution
    let t = Instant::now();
    let (mem_host, _) = e2e_host(HostConfig::default());
    mem_host
        .register(pkg("mem-hog", 1, "run", MEMORY_HOG_WAT, host_limits()))
        .unwrap();
    let mem_result = mem_host.call("mem-hog", b"");
    report.check(
        "memory_limit_64mib",
        expect_kind(&mem_result, ErrorKind::Memory).is_ok(),
        format!("result={} host_limit={}MiB", err_text(&mem_result), 64),
        t.elapsed(),
    );

    // 9) trap / missing export / invalid manifest / unsigned-signature placeholder
    let t = Instant::now();
    let (misc_host, _) = e2e_host(HostConfig::default());
    misc_host
        .register(pkg("trap", 1, "run", TRAP_WAT, host_limits()))
        .unwrap();
    let trap_result = misc_host.call("trap", b"");
    report.check(
        "unreachable_trap",
        expect_kind(&trap_result, ErrorKind::Trap).is_ok(),
        format!("result={}", err_text(&trap_result)),
        t.elapsed(),
    );

    let t = Instant::now();
    let missing = misc_host.register(pkg("no-entry", 1, "process", MEMORY_ONLY_WAT, host_limits()));
    report.check(
        "missing_export_rejected",
        expect_kind(&missing, ErrorKind::MissingExport).is_ok(),
        format!("result={}", err_text(&missing)),
        t.elapsed(),
    );

    let t = Instant::now();
    let bad_manifest = misc_host.load_dir(&bad_manifest_dir());
    report.check(
        "bad_manifest_rejected",
        bad_manifest.loaded.is_empty() && bad_manifest.rejected.len() == 3,
        format!(
            "loaded={} rejected={:?}",
            bad_manifest.loaded.len(),
            bad_manifest
                .rejected
                .iter()
                .map(|r| format!("{}:{}", r.plugin, r.kind))
                .collect::<Vec<_>>()
        ),
        t.elapsed(),
    );

    let t = Instant::now();
    let signed_info = misc_host
        .register(
            pkg("signed", 1, "run", RUN_OK_WAT, host_limits()).with_signature(vec![0xAB; 64]),
        )
        .unwrap();
    // Compatible with the old scenario name: the default host has no trusted_keys, so no signature bytes can possibly be verified → only
    // Missing (not Verified), and trusted must be false; real Ed25519 verification is covered by
    // scripts/wasm-plugin-e2e.mjs (this example keeps the "minimal host with no trusted keys" position).
    report.check(
        "signature_placeholder_is_untrusted",
        signed_info.signature == SignatureCheck::Missing
            && !signed_info.trusted
            && signed_info.signature != SignatureCheck::Verified,
        format!(
            "signature={} detail={} trusted={}",
            signed_info.signature.as_str(),
            signed_info.signature_detail,
            signed_info.trusted
        ),
        t.elapsed(),
    );

    // 10) Concurrency cap: 2 slots; try_call is immediately Busy; call succeeds after queueing
    let t = Instant::now();
    let mut conc_cfg = HostConfig::default();
    conc_cfg.max_concurrency = 2;
    conc_cfg.call_timeout = Duration::from_secs(10);
    conc_cfg.queue_timeout = Duration::from_secs(5);
    conc_cfg.fuel = 5_000_000_000;
    let (conc_host, _) = e2e_host(conc_cfg);
    let conc_host = Arc::new(conc_host);
    conc_host
        .register(pkg("slow", 1, "run", SLOW_WAT, host_limits()))
        .unwrap();

    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let h = conc_host.clone();
        let b = barrier.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            h.call("slow", b"").map(|o| o.output.len())
        }));
    }
    barrier.wait();
    let deadline = Instant::now() + Duration::from_secs(5);
    while conc_host.metrics().active_calls < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    let saturated = conc_host.metrics().active_calls == 2;
    let busy = conc_host.try_call("slow", b"");
    let queued = {
        let h = conc_host.clone();
        std::thread::spawn(move || h.call("slow", b"").map(|o| o.output.len()))
    };
    let mut ok_count = 0;
    for handle in handles {
        if handle.join().unwrap().is_ok() {
            ok_count += 1;
        }
    }
    let queued_ok = queued.join().unwrap().is_ok();
    let conc_metrics = conc_host.metrics();
    report.check(
        "concurrency_limit_queue_and_reject",
        saturated
            && expect_kind(&busy, ErrorKind::Busy).is_ok()
            && queued_ok
            && ok_count == 2
            && conc_metrics.busy_rejected >= 1
            && conc_metrics.queued_wait_total >= 1
            && conc_metrics.active_calls == 0,
        format!(
            "saturated={saturated} try_call={} queued_ok={queued_ok} ok={ok_count}/2 busy_rejected={} queued_wait={} active_after={}",
            err_text(&busy),
            conc_metrics.busy_rejected,
            conc_metrics.queued_wait_total,
            conc_metrics.active_calls
        ),
        t.elapsed(),
    );

    // 11) Registry deps validation
    let t = Instant::now();
    let registry = MemoryRegistry::new();
    let mut with_dep = PluginManifest {
        ns: "with-dep".into(),
        version: 1,
        entry: "run".into(),
        deps: vec!["base".into()],
        limits: host_limits(),
        signature: None,
        signing_key_id: None,
    };
    with_dep.entry = "run".into();
    registry.insert(PluginPackage::from_manifest(with_dep, wasm(RUN_OK_WAT)));
    registry.insert(PluginPackage::from_manifest(
        PluginManifest {
            ns: "base".into(),
            version: 1,
            entry: "run".into(),
            deps: vec![],
            limits: host_limits(),
            signature: None,
            signing_key_id: None,
        },
        wasm(RUN_OK_WAT),
    ));
    let (dep_host, _) = e2e_host(HostConfig::default());
    let dep_report = dep_host.load_registry(&registry);
    report.check(
        "registry_deps_present",
        dep_report.ok() && dep_report.loaded.len() == 2,
        format!(
            "loaded={} rejected={:?}",
            dep_report.loaded.len(),
            dep_report.rejected.len()
        ),
        t.elapsed(),
    );

    // 12) Security boundary + metrics snapshot
    let t = Instant::now();
    let security = host.security_report();
    let metrics = host.metrics();
    let hook_calls = recorder.calls.lock().unwrap().len();
    let hook_circuits = recorder.circuits.lock().unwrap().len();
    report.check(
        "security_boundary_reported",
        security.wasi.contains("disabled")
            && security.filesystem.starts_with("none")
            && security.network.starts_with("none")
            && security.signature_verification.starts_with("not_implemented")
            && security.untrusted_plugins >= 1
            && security.trusted_plugins == 0
            && hook_calls >= 3
            && hook_circuits >= 1,
        format!(
            "wasi={:?} fs={:?} net={:?} signature={:?} trusted={} untrusted={} hook_calls={hook_calls} hook_circuits={hook_circuits}",
            security.wasi,
            security.filesystem,
            security.network,
            security.signature_verification,
            security.trusted_plugins,
            security.untrusted_plugins
        ),
        t.elapsed(),
    );

    // ------------------------------------------------------------------
    let loaded = host.plugins();
    let passed = report.scenarios.iter().filter(|s| s.pass).count();
    let total = report.scenarios.len();
    let ok = passed == total;
    let output = json!({
        "ok": ok,
        "passed": passed,
        "total": total,
        "scenarios": report.scenarios.iter().map(|s| json!({
            "name": s.name,
            "pass": s.pass,
            "detail": s.detail,
            "elapsed_ms": s.elapsed_ms,
        })).collect::<Vec<_>>(),
        "host": {
            "default_config": {
                "memory_bytes": HostConfig::default().memory_bytes,
                "fuel": HostConfig::default().fuel,
                "call_timeout_ms": HostConfig::default().call_timeout.as_millis() as u64,
                "max_concurrency": HostConfig::default().max_concurrency,
                "circuit_break_ms": HostConfig::default().circuit_break.as_millis() as u64,
            },
            "plugins": loaded.iter().map(|p| json!({
                "short_name": p.short_name,
                "version": p.version,
                "entry": p.entry,
                "mode": p.mode,
                "limits": p.limits,
                "wasm_bytes": p.wasm_bytes,
                "content_sha256": p.content_sha256,
                "signature": p.signature,
                "trusted": p.trusted,
            })).collect::<Vec<_>>(),
        },
        "metrics": metrics,
        "security": security,
    });
    println!("{output}");
    if !ok {
        eprintln!("wasm host e2e failed: {passed}/{total} scenarios passed");
        std::process::exit(1);
    }
}

/// Four bad manifest directories: missing fields, invalid JSON, missing wasm file, manifest not a JSON object.
fn bad_manifest_dir() -> std::path::PathBuf {
    let root = unique_temp_dir("bad");
    let valid_wasm = wasm(RUN_OK_WAT);
    let cases: [(&str, &str, Option<&[u8]>); 3] = [
        ("missing-ns", "{}", Some(valid_wasm.as_slice())),
        ("bad-json", "not json", Some(valid_wasm.as_slice())),
        ("missing-wasm", r#"{"ns":"x","version":1}"#, None),
    ];
    for (name, manifest, wasm_bytes) in cases {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"), manifest).unwrap();
        if let Some(bytes) = wasm_bytes {
            std::fs::write(dir.join("plugin.wasm"), bytes).unwrap();
        }
    }
    root
}
