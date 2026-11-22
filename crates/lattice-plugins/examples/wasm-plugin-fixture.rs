//! Plugin package fixture tool (called by `scripts/wasm-plugin-e2e.mjs`; local files only, no network).
//!
//! Why it exists: the E2E generates an Ed25519 key with Node `crypto` and signs with it, but **WAT→wasm compilation** and
//! the **canonical manifest bytes** must match the host implementation exactly. This example reuses the host crate's
//! `wat` (dev-dependency) and [`lattice_plugins::manifest::PluginManifest::canonical_payload`]
//! to hand "wasm bytes / canonical JSON / digest to sign" to the E2E, so the Node side never hand-writes wasm or guesses the JSON format.
//!
//! Usage:
//! ```text
//! # Generate a test wasm binary (the host accepts binaries only, not WAT)
//! cargo run -q -p lattice-plugins --example wasm-plugin-fixture -- wasm echo plugin.wasm
//! cargo run -q -p lattice-plugins --example wasm-plugin-fixture -- wasm spin plugin.wasm
//! cargo run -q -p lattice-plugins --example wasm-plugin-fixture -- wasm run-ok plugin.wasm
//! cargo run -q -p lattice-plugins --example wasm-plugin-fixture -- wasm trap plugin.wasm
//!
//! # Print the manifest's canonical bytes (cross-check that the JSON built by Node matches Rust byte for byte)
//! cargo run -q -p lattice-plugins --example wasm-plugin-fixture -- canonical-json manifest.json
//!
//! # Print the digest to sign as hex: sha256(wasm || canonical_manifest_json)
//! cargo run -q -p lattice-plugins --example wasm-plugin-fixture -- payload-hash plugin.wasm manifest.json
//! ```
//!
//! Output is always a single line; on error, write to stderr and exit 2.

use std::io::Write;

use lattice_plugins::manifest::PluginManifest;

const ECHO_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "process") (param i32 i32) (result i64)
    (i64.or
      (i64.extend_i32_u (local.get 0))
      (i64.shl (i64.extend_i32_u (local.get 1)) (i64.const 32)))))
"#;

/// Infinite loop (run mode): burns fuel / triggers the wall-clock epoch interrupt.
const SPIN_WAT: &str = r#"
(module
  (func (export "run") (result i32)
    (local $i i64)
    (loop $l
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $l))
    (unreachable)))
"#;

/// Normal run entry: returns 0.
const RUN_OK_WAT: &str = r#"
(module
  (func (export "run") (result i32) (i32.const 0)))
"#;

/// `unreachable` trap.
const TRAP_WAT: &str = r#"
(module
  (func (export "run") (result i32) (unreachable)))
"#;

/// Custom process name (verifies entry override / custom entry points).
const CUSTOM_ENTRY_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 2048))
  (func (export "transform") (param i32 i32) (result i64)
    (i64.or
      (i64.extend_i32_u (local.get 0))
      (i64.shl (i64.extend_i32_u (local.get 1)) (i64.const 32)))))
"#;

fn wat_for(kind: &str) -> Option<&'static str> {
    match kind {
        "echo" => Some(ECHO_WAT),
        "spin" => Some(SPIN_WAT),
        "run-ok" => Some(RUN_OK_WAT),
        "trap" => Some(TRAP_WAT),
        "custom-entry" => Some(CUSTOM_ENTRY_WAT),
        _ => None,
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: wasm-plugin-fixture wasm <echo|spin|run-ok|trap|custom-entry> <out.wasm> | \
         canonical-json <manifest.json> | payload-hash <plugin.wasm> <manifest.json>"
    );
    std::process::exit(2);
}

fn emit_wasm(kind: &str, out: &str) {
    let Some(src) = wat_for(kind) else {
        eprintln!("unknown fixture kind `{kind}`");
        std::process::exit(2);
    };
    let bytes = wat::parse_str(src).expect("WAT must compile");
    let path = std::path::Path::new(out);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create fixture parent dir");
    }
    std::fs::write(path, &bytes).unwrap_or_else(|e| {
        eprintln!("write {} failed: {e}", path.display());
        std::process::exit(2);
    });
    println!("{}", bytes.len());
}

fn read_manifest(path: &str) -> PluginManifest {
    let raw = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("read manifest {path} failed: {e}");
        std::process::exit(2);
    });
    serde_json::from_slice(&raw).unwrap_or_else(|e| {
        eprintln!("parse manifest {path} failed: {e}");
        std::process::exit(2);
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("wasm") if args.len() == 3 => emit_wasm(&args[1], &args[2]),
        Some("canonical-json") if args.len() == 2 => {
            let manifest = read_manifest(&args[1]);
            let payload = manifest.canonical_payload();
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&payload).expect("write stdout");
            let _ = stdout.write_all(b"\n");
        }
        Some("payload-hash") if args.len() == 3 => {
            let wasm = std::fs::read(&args[1]).unwrap_or_else(|e| {
                eprintln!("read wasm {} failed: {e}", args[1]);
                std::process::exit(2);
            });
            let manifest = read_manifest(&args[2]);
            println!("{}", manifest.signing_digest_hex(&wasm));
        }
        _ => usage(),
    }
}
