//! Plugin sidecar calls (PL-10 / design §4.5 / doc ⑤ §10).
//!
//! Two forms:
//! - [`sidecar::SidecarClient`]: the call interface (`process(ns, op, input)`) — business code depends only on it;
//! - [`sidecar::grpc::GrpcSidecarClient`]: the real gRPC implementation (tonic + prost, optional mTLS):
//!   - the proto source is the repo-root `proto/lattice.proto` (`package lattice.internal.v1`), and
//!     the generated code lives only in this crate's OUT_DIR (`crates/lattice-plugins/build.rs`),
//!     generated separately from the node-side `NodeInternal` without conflicts;
//!   - **single connection reuse**: `tonic::transport::Channel` is built once (lazy), and later calls clone the client
//!     to reuse the same HTTP/2 connection; dropped connections are handled by tonic's reconnect layer;
//!   - **500ms timeout** ([`crate::limits::SIDECAR_TIMEOUT_MS`]): hard cap for the whole RPC (including connect);
//!   - **30s circuit break** ([`crate::limits::CIRCUIT_BREAK_SECS`], [`Circuit`]): tripped by transport failure/timeout,
//!     during which calls **immediately** return `CircuitOpen` (no sidecar hit); after the window the next call is a half-open probe;
//!   - **failure behavior** (⑤ §10): returns [`PluginError`] and the caller passes the message through as "no converter";
//!     connection failure/unreachable service maps to [`PluginError::Failed`] (no panic, no blocking of the caller);
//!   - **mTLS**: all three of `tls_ca/tls_cert/tls_key` set → mTLS; all three empty → plaintext (dev only,`
//!     startup WARN); only some set → build-time error (fail-closed, never silently degrades to plaintext);
//!   - **logs never print input/output**: logs carry only ns/timeout/error code (low cardinality); payload never leaks.
//!
//! # Not implemented (report boundary)
//!
//! - sidecar process lifecycle/auto-restart (K8s probes/exit-code monitoring) is not in this crate;
//! - `Process.Health` is not wired up (the node calls only `Process`; health checks are the deployment probe's job);
//! - the circuit breaker is **process-wide, single instance** (all ns share one window): consistent with the existing WASM host breaker semantics,
//!   the goal is "fail fast when the sidecar is unavailable", not per-plugin isolation;
//! - real format conversion (detect/convert pipeline) is not wired up: this crate delivers only the client and tests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::limits;

pub mod grpc;

pub use grpc::{GrpcSidecarClient, SidecarConfig, SidecarInitError, SidecarTls};

/// sidecar call request / response (corresponds to ⑤ §10 `ProcessReq` / `ProcessResp`).
#[derive(Debug, Clone)]
pub struct ProcessReq {
    pub ns: String,
    pub op: String,
    pub input: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ProcessResp {
    pub output: Vec<u8>,
    pub error: Option<String>,
    pub elapsed_ms: u64,
}

/// Plugin call error: timeout/failure → the plugin is circuit-broken for 30s and the message passes through as "no converter" (⑤ §10).
#[derive(Debug, Clone, thiserror::Error)]
pub enum PluginError {
    #[error("plugin {ns} circuit open")]
    CircuitOpen { ns: String },
    #[error("plugin {ns} timeout")]
    Timeout { ns: String },
    #[error("plugin {ns} failed: {msg}")]
    Failed { ns: String, msg: String },
}

impl PluginError {
    /// Low-cardinality reason (for log/metric labels; **never contains payload**).
    pub fn reason(&self) -> &'static str {
        match self {
            PluginError::CircuitOpen { .. } => "circuit_open",
            PluginError::Timeout { .. } => "timeout",
            PluginError::Failed { .. } => "failed",
        }
    }

    /// Plugin ns of the request (the ns in the error struct; collapse cardinality before using it as a metric label — see the caller).
    pub fn ns(&self) -> &str {
        match self {
            PluginError::CircuitOpen { ns }
            | PluginError::Timeout { ns }
            | PluginError::Failed { ns, .. } => ns,
        }
    }
}

/// sidecar client interface. The production implementation is [`grpc::GrpcSidecarClient`]; when unconfigured, [`NoopSidecar`] is used.
#[async_trait::async_trait]
pub trait SidecarClient: Send + Sync {
    async fn process(&self, req: ProcessReq) -> Result<ProcessResp, PluginError>;
}

/// Circuit breaker: after repeated failures, reject directly for 30s (no sidecar hit).
///
/// Semantics (consistent with ⑤ §10):
/// - `trip()`: opens the window after a transport failure/timeout (default [`limits::CIRCUIT_BREAK_SECS`] = 30s);
/// - inside the window `is_open()==true` → the caller gets `CircuitOpen` immediately, **without hitting the sidecar**;
/// - after the window it half-opens automatically: the next real call succeeding calls `reset()`, failing trips again.
#[derive(Debug, Default)]
pub struct Circuit {
    open_until_ms: AtomicU64,
}

impl Circuit {
    pub fn is_open(&self) -> bool {
        now_ms() < self.open_until_ms.load(Ordering::Relaxed)
    }

    /// Open the default 30s circuit-break window.
    pub fn trip(&self) {
        self.trip_for(std::time::Duration::from_secs(limits::CIRCUIT_BREAK_SECS));
    }

    /// Open a window of the given length (production uses [`Circuit::trip`]; tests use short windows to verify recovery).
    pub fn trip_for(&self, window: std::time::Duration) {
        let ms = u64::try_from(window.as_millis()).unwrap_or(u64::MAX);
        self.open_until_ms
            .store(now_ms().saturating_add(ms), Ordering::Relaxed);
    }

    pub fn reset(&self) {
        self.open_until_ms.store(0, Ordering::Relaxed);
    }

    /// Remaining milliseconds of the circuit-break window (0 = closed; for diagnostics/status display).
    pub fn remaining_ms(&self) -> u64 {
        self.open_until_ms
            .load(Ordering::Relaxed)
            .saturating_sub(now_ms())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Deployment without a sidecar (default): every call is treated as "no converter" and the message passes through (⑤ §10 failure behavior).
pub struct NoopSidecar;

#[async_trait::async_trait]
impl SidecarClient for NoopSidecar {
    async fn process(&self, req: ProcessReq) -> Result<ProcessResp, PluginError> {
        Err(PluginError::Failed {
            ns: req.ns,
            msg: "sidecar not configured".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_opens_and_expires_with_short_window() {
        let c = Circuit::default();
        assert!(!c.is_open());
        c.trip_for(std::time::Duration::from_millis(60));
        assert!(c.is_open(), "must be open inside the window after trip");
        assert!(c.remaining_ms() > 0 && c.remaining_ms() <= 60);
        std::thread::sleep(std::time::Duration::from_millis(80));
        assert!(!c.is_open(), "half-open after the window (the next real call is allowed)");
        c.reset();
        assert!(!c.is_open());
    }

    #[test]
    fn default_trip_window_is_30s() {
        let c = Circuit::default();
        c.trip();
        let remaining = c.remaining_ms();
        assert!(
            remaining > limits::CIRCUIT_BREAK_SECS * 1000 - 1_000,
            "the default circuit-break window must be ≈30s, actual remaining={remaining}ms"
        );
        assert!(remaining <= limits::CIRCUIT_BREAK_SECS * 1000);
    }

    #[tokio::test]
    async fn noop_sidecar_is_transparent_failure() {
        let err = NoopSidecar
            .process(ProcessReq {
                ns: "json".into(),
                op: "convert".into(),
                input: b"payload".to_vec(),
            })
            .await
            .expect_err("with no sidecar configured this must return an error (the caller then passes through)");
        assert_eq!(err.reason(), "failed");
        assert_eq!(err.ns(), "json");
        assert!(err.to_string().contains("sidecar not configured"));
        // the error text must not contain the payload
        assert!(!err.to_string().contains("payload"));
    }
}
