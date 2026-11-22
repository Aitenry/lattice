//! Format conversion decisions and **zero-copy passthrough** (E25 / PL-10 §10.2, §10.3).
//!
//! This file does exactly two things, and both are unit-testable at the host layer:
//!
//! 1. **Negotiation**: `convert:<src>-><dst>` is the conversion plugin naming convention of the `lattice-node` pipeline (`pipeline/format.rs`);
//!    [`converter_ns`] is the only implementation, and `src == dst` (case-insensitive) means **no conversion
//!    is needed**, returning `None`;
//! 2. **Execution + zero-copy fast path**: [`negotiate_convert`] returns [`Cow::Borrowed`] when "no conversion needed" (`src == dst`) or
//!    "no converter" — **no copy, no plugin call**; only a real converter hit
//!    that then succeeds returns [`Cow::Owned`] (new bytes). A converter failure degrades, by design, to **passthrough of the original bytes**
//!    (⑤ §10: no converter/failure → passthrough + explicit receipt), returning [`ConvertKind::PassthroughFailed`]
//!    with a low-cardinality `reason`; **never fakes success**.
//!
//! ## Boundaries (must not be claimed)
//!
//! - The zero-copy assertion holds only at the **host API layer** (pointer identity + no plugin invocation); the REST/WS transport layer has no
//!   zero-copy evidence (serialization/network send necessarily copy), and this module does not pass host-layer assertions off as end-to-end conclusions.
//! - This module is **not** wired into the node uplink pipeline: `pipeline/format.rs::convert` is still a "no converter passthrough"
//!   placeholder (`None`). The real conversion path = admin `POST /v1/admin/plugins/{ns}/invoke` →
//!   `WasmHost::call` (the E2E `scripts/wasm-format-convert-e2e.mjs` verifies it with a real conversion plugin).
//! - Content plugins are rejected by the host registration policy in zero-knowledge mode (`HostConfig::allow_content_plugins`),
//!   so lookups here necessarily miss → passthrough, honoring the zero-knowledge promise.

use std::borrow::Cow;

use super::WasmHost;

/// Conversion plugin ns prefix (matches the `pipeline/format.rs` convention in `lattice-node`).
pub const CONVERT_NS_PREFIX: &str = "convert:";

/// Conversion plugin ns: `convert:<src>-><dst>`.
///
/// Returns `None` = no conversion needed (`src`/`dst` empty, or equal after case folding). `src`/`dst` are only
/// `trim`med, with **no MIME parameter normalization** (e.g. `application/json; charset=utf-8` stays as is):
/// the naming convention matches `pipeline/format.rs` exactly, avoiding two separate normalization schemes producing different ns values.
pub fn converter_ns(src_type: &str, dst_type: &str) -> Option<String> {
    let src = src_type.trim();
    let dst = dst_type.trim();
    if src.is_empty() || dst.is_empty() || src.eq_ignore_ascii_case(dst) {
        return None;
    }
    Some(format!("{CONVERT_NS_PREFIX}{src}->{dst}"))
}

/// Conversion result classification (low cardinality, safe for log/metric labels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvertKind {
    /// `src == dst`: no conversion needed, zero-copy passthrough.
    PassthroughSameFormat,
    /// No `convert:<src>-><dst>` converter registered: zero-copy passthrough (not an error).
    PassthroughNoConverter,
    /// Converter hit but execution failed (timeout/trap/fuel/circuit break/…): degrade to zero-copy passthrough (⑤ §10).
    PassthroughFailed,
    /// Conversion succeeded; output is new bytes (`Cow::Owned`).
    Converted,
}

impl ConvertKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ConvertKind::PassthroughSameFormat => "passthrough_same_format",
            ConvertKind::PassthroughNoConverter => "passthrough_no_converter",
            ConvertKind::PassthroughFailed => "passthrough_failed",
            ConvertKind::Converted => "converted",
        }
    }

    /// Whether a real conversion happened (only this returns `true`).
    pub fn converted(self) -> bool {
        self == ConvertKind::Converted
    }
}

/// Negotiation + execution outcome. `output` is [`Cow::Borrowed`] on the passthrough path (zero copy).
#[derive(Debug, Clone)]
pub struct ConvertOutcome<'a> {
    pub output: Cow<'a, [u8]>,
    pub kind: ConvertKind,
    /// Converter hit as `(ns, version)`; `None` on miss/passthrough.
    pub plugin: Option<(String, u32)>,
    /// Failure degradation reason (low cardinality: `trap`/`timeout`/`fuel`/`circuit_open`/…; `None` on success/passthrough).
    pub reason: Option<&'static str>,
}

impl ConvertOutcome<'_> {
    pub fn converted(&self) -> bool {
        self.kind.converted()
    }

    /// Whether the output is the input bytes itself (zero-copy evidence: the same memory is borrowed).
    pub fn is_zero_copy(&self) -> bool {
        matches!(self.output, Cow::Borrowed(_))
    }
}

/// Negotiate and execute a conversion for `src_type → dst_type`.
///
/// Semantics:
/// - `src == dst` (case-insensitive) → [`ConvertKind::PassthroughSameFormat`], **no registry lookup,
///   no plugin call, no copy**;
/// - no `convert:<src>-><dst>` → [`ConvertKind::PassthroughNoConverter`], also zero-copy;
/// - hit → `WasmHost::call`; success returns `Converted` (new bytes), failure degrades to
///   [`ConvertKind::PassthroughFailed`] (zero-copy passthrough + `reason`), and **never** treats failure as success.
///
/// No auth/mode checks: the caller (node) owns the zero-knowledge mode gate (content plugins cannot even be
/// registered into the host in zero-knowledge mode, so this yields `PassthroughNoConverter`).
pub fn negotiate_convert<'a>(
    host: &WasmHost,
    src_type: &str,
    dst_type: &str,
    input: &'a [u8],
) -> ConvertOutcome<'a> {
    let Some(ns) = converter_ns(src_type, dst_type) else {
        return passthrough(input, ConvertKind::PassthroughSameFormat);
    };
    if host.info(&ns).is_none() {
        return passthrough(input, ConvertKind::PassthroughNoConverter);
    }
    match host.call(&ns, input) {
        Ok(out) => ConvertOutcome {
            output: Cow::Owned(out.output),
            kind: ConvertKind::Converted,
            plugin: Some((out.plugin, out.version)),
            reason: None,
        },
        Err(e) => ConvertOutcome {
            output: Cow::Borrowed(input),
            kind: ConvertKind::PassthroughFailed,
            plugin: None,
            reason: Some(e.kind().as_str()),
        },
    }
}

fn passthrough(input: &[u8], kind: ConvertKind) -> ConvertOutcome<'_> {
    ConvertOutcome {
        output: Cow::Borrowed(input),
        kind,
        plugin: None,
        reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{PluginLimits, PluginManifest};
    use crate::wasm::registry::PluginPackage;
    use crate::wasm::{HostConfig, WasmHost};

    /// Real conversion: JSON Lines (NDJSON) → JSON array.
    ///
    /// Copies the input into the output area byte by byte (`0x0A` becomes `,`) and wraps it with `[`/`]`: a real byte-level format
    /// conversion (input `{"a":1}\n{"b":2}` → output `[{"a":1},{"b":2}]`), not an echo/placeholder.
    const NDJSON_TO_JSON_WAT: &str = r#"
    (module
      (memory (export "memory") 1)
      (func (export "alloc") (param i32) (result i32) (i32.const 1024))
      (func (export "process") (param i32 i32) (result i64)
        (local $i i32) (local $c i32)
        (i32.store8 (i32.const 4096) (i32.const 91))
        (block $done
          (loop $l
            (br_if $done (i32.ge_u (local.get $i) (local.get 1)))
            (local.set $c (i32.load8_u (i32.add (local.get 0) (local.get $i))))
            (if (i32.eq (local.get $c) (i32.const 10))
              (then (local.set $c (i32.const 44))))
            (i32.store8 (i32.add (i32.const 4097) (local.get $i)) (local.get $c))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $l)))
        (i32.store8 (i32.add (i32.const 4097) (local.get 1)) (i32.const 93))
        (i64.or
          (i64.const 4096)
          (i64.shl
            (i64.extend_i32_u (i32.add (local.get 1) (i32.const 2)))
            (i64.const 32)))))
    "#;

    /// Converter execution failure (`run` traps): used to assert "failure degrades to passthrough".
    const TRAP_RUN_WAT: &str = r#"
    (module
      (func (export "run") (result i32) (unreachable)))
    "#;

    fn wasm(src: &str) -> Vec<u8> {
        wat::parse_str(src).expect("wat parse")
    }

    fn package(ns: &str, wat_src: &str) -> PluginPackage {
        PluginPackage::from_manifest(
            PluginManifest {
                ns: ns.into(),
                version: 1,
                entry: String::new(),
                deps: vec![],
                limits: PluginLimits::default(),
                signature: None,
                signing_key_id: None,
            },
            wasm(wat_src),
        )
    }

    fn host() -> WasmHost {
        WasmHost::new(HostConfig::default()).expect("host")
    }

    #[test]
    fn converter_ns_matches_node_pipeline_convention() {
        assert_eq!(converter_ns("json", "text").as_deref(), Some("convert:json->text"));
        assert_eq!(
            converter_ns(" application/x-ndjson ", "application/json").as_deref(),
            Some("convert:application/x-ndjson->application/json")
        );
        // src == dst (case-insensitive) / empty = no conversion needed
        assert_eq!(converter_ns("JSON", "json"), None);
        assert_eq!(converter_ns("", "json"), None);
        assert_eq!(converter_ns("json", "  "), None);
    }

    #[test]
    fn same_format_is_zero_copy_and_never_calls_the_plugin() {
        let host = host();
        // Register a same-named converter on purpose: the fast path must return before the lookup and must not call it.
        host.register(package("convert:json->json", NDJSON_TO_JSON_WAT)).unwrap();
        let input: &[u8] = b"{\"a\":1}";
        let out = negotiate_convert(&host, "json", "json", input);
        assert_eq!(out.kind, ConvertKind::PassthroughSameFormat);
        assert!(out.is_zero_copy());
        assert_eq!(out.output.as_ref(), input);
        assert!(
            std::ptr::eq(out.output.as_ptr(), input.as_ptr()),
            "no conversion needed must borrow the same memory (zero copy); it actually copied"
        );
        assert_eq!(out.plugin, None);
        let m = host.metrics();
        assert_eq!(m.calls_total, 0, "the zero-copy fast path must not enter a wasm call: {m:?}");
        assert_eq!(m.ok_total, 0);
    }

    #[test]
    fn missing_converter_is_zero_copy_passthrough() {
        let host = host();
        let input: &[u8] = b"a,b\n1,2";
        let out = negotiate_convert(&host, "text/csv", "application/json", input);
        assert_eq!(out.kind, ConvertKind::PassthroughNoConverter);
        assert!(out.is_zero_copy());
        assert!(std::ptr::eq(out.output.as_ptr(), input.as_ptr()));
        assert!(out.reason.is_none());
        assert_eq!(host.metrics().calls_total, 0);
    }

    #[test]
    fn real_ndjson_to_json_conversion_executes_the_plugin() {
        let host = host();
        host.register(package(
            "convert:application/x-ndjson->application/json",
            NDJSON_TO_JSON_WAT,
        ))
        .unwrap();
        let input: &[u8] = b"{\"a\":1}\n{\"b\":2}";
        let out = negotiate_convert(&host, "application/x-ndjson", "application/json", input);
        assert_eq!(out.kind, ConvertKind::Converted, "outcome={out:?}");
        assert!(out.converted());
        assert!(!out.is_zero_copy(), "the output of a real conversion must be new bytes");
        assert_eq!(out.output.as_ref(), b"[{\"a\":1},{\"b\":2}]");
        assert_eq!(
            out.plugin.as_ref().map(|(ns, v)| (ns.as_str(), *v)),
            Some(("convert:application/x-ndjson->application/json", 1))
        );
        let m = host.metrics();
        assert_eq!(m.calls_total, 1, "a real conversion must execute the plugin once: {m:?}");
        assert_eq!(m.ok_total, 1);
    }

    #[test]
    fn converter_failure_degrades_to_zero_copy_passthrough() {
        let host = host();
        host.register(package("convert:text->json", TRAP_RUN_WAT)).unwrap();
        let input: &[u8] = b"raw text";
        let out = negotiate_convert(&host, "text", "json", input);
        assert_eq!(out.kind, ConvertKind::PassthroughFailed, "outcome={out:?}");
        assert!(out.is_zero_copy());
        assert!(std::ptr::eq(out.output.as_ptr(), input.as_ptr()));
        assert_eq!(out.reason, Some("trap"));
        assert!(!out.converted(), "failure must not masquerade as a successful conversion");
        let m = host.metrics();
        assert_eq!(m.calls_total, 1);
        assert_eq!(m.failure_total, 1);
        assert_eq!(m.ok_total, 0);
    }
}
