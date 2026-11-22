//! Real `PluginSidecar` gRPC client (tonic + prost, ⑤ §10).
//!
//! Contract (proto source: repo-root `proto/lattice.proto`, `package lattice.internal.v1`):
//!
//! ```proto
//! service PluginSidecar {
//!   rpc Process(ProcessReq) returns (ProcessResp);   // plugin call (mTLS + 500ms timeout)
//!   rpc Health(Empty) returns (HealthResp);
//! }
//! message ProcessReq  { string ns = 1; string op = 2; bytes input = 3; map<string,string> opts = 4; }
//! message ProcessResp { bytes output = 1; string error = 2; uint64 elapsed_ms = 3; }
//! ```
//!
//! Implementation choices:
//! - **lazy connection**: construction only validates endpoint/TLS config and calls `connect_lazy()` (**no network IO**),
//!   so node startup/`ready` does not depend on whether the sidecar is online; the first `process` actually connects.
//!   (A lazy Channel binds to the current Tokio runtime, so it must be built inside a runtime context; node `node::build` satisfies this.)
//! - **single connection reuse**: `Channel` has built-in HTTP/2 multiplexing + reconnection; each call only clones a lightweight client.
//! - **timeout**: `tokio::time::timeout` wraps the whole RPC (including connect), default
//!   `limits::SIDECAR_TIMEOUT_MS` = 500ms; timeout → [`PluginError::Timeout`] and trips the circuit breaker.
//! - **circuit break**: transport error/timeout trips [`super::Circuit`] (default 30s); inside the window it immediately returns
//!   [`PluginError::CircuitOpen`] without hitting the sidecar; a successful call calls `reset` (recovering after half-open).
//! - **business error**: non-empty `ProcessResp.error` → [`PluginError::Failed`] (the sidecar is online,
//!   so it is **not counted** toward the circuit break, avoiding one bad input opening the breaker for the whole plugin).
//! - **mTLS**: enabled only when all three `SidecarTls` fields (ca/cert/key) are present; a partial config never silently degrades to plaintext;
//!   plaintext mode is WARNed by the caller at startup (dev only).
//! - **log redaction**: only `ns` / error code / timeout value are recorded; **input/output are never recorded** (and payload is never
//!   spliced into error logs).
//!
//! Tests (`tests/sidecar_grpc.rs`) start a real local tonic mock server and cover normal round trips, the 500ms timeout,
//! unreachable service, circuit open/short-window recovery, real mTLS connectivity, TLS config failure semantics, and payload non-leakage.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use crate::limits;

use super::{Circuit, PluginError, ProcessReq, ProcessResp, SidecarClient};

/// This crate's private proto output (included only into this crate's OUT_DIR; the node-side NodeInternal is unaffected).
pub mod pb {
    #![allow(clippy::all)]
    tonic::include_proto!("lattice.internal.v1");
}

/// sidecar client config (mapped from node `[plugins.sidecar]`; see `lattice-node/src/plugins.rs`).
#[derive(Debug, Clone)]
pub struct SidecarConfig {
    /// gRPC endpoint, **must include a scheme**: `http://host:port` (plaintext dev) or `https://host:port` (mTLS).
    pub endpoint: String,
    /// Hard timeout per call (default [`limits::SIDECAR_TIMEOUT_MS`] = 500ms).
    pub timeout: Duration,
    /// The three mTLS certificate files; `None` = plaintext (dev only).
    pub tls: Option<SidecarTls>,
    /// Circuit-break window (default [`limits::CIRCUIT_BREAK_SECS`] = 30s; tests may inject a short window).
    pub circuit_break: Duration,
}

impl Default for SidecarConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            timeout: Duration::from_millis(limits::SIDECAR_TIMEOUT_MS),
            tls: None,
            circuit_break: Duration::from_secs(limits::CIRCUIT_BREAK_SECS),
        }
    }
}

/// The three PEM files for mTLS (path form, matching `[plugins.sidecar] tls_ca/tls_cert/tls_key`).
///
/// - `ca_path`: the CA used to verify the sidecar server certificate (PEM, may contain several);
/// - `cert_path`/`key_path`: the certificate/private key the node presents as gRPC client (PEM).
#[derive(Debug, Clone)]
pub struct SidecarTls {
    pub ca_path: String,
    pub cert_path: String,
    pub key_path: String,
}

impl SidecarTls {
    /// Whether all three are set (empty string counts as unconfigured; a partial config is an error, see [`SidecarInitError::IncompleteTls`]).
    pub fn is_complete(&self) -> bool {
        !self.ca_path.trim().is_empty()
            && !self.cert_path.trim().is_empty()
            && !self.key_path.trim().is_empty()
    }
}

/// Client construction error (config/certificate problems; network unreachability is **not** a construction error — connecting is lazy).
#[derive(Debug, thiserror::Error)]
pub enum SidecarInitError {
    #[error(
        "sidecar endpoint is empty (set [plugins.sidecar] endpoint, e.g. http://127.0.0.1:19090)"
    )]
    EmptyEndpoint,
    #[error("invalid sidecar endpoint `{endpoint}`: {reason}")]
    BadEndpoint { endpoint: String, reason: String },
    #[error("sidecar timeout must be > 0")]
    ZeroTimeout,
    #[error("sidecar TLS config incomplete: tls_ca/tls_cert/tls_key must be all set (mTLS) or all empty (plaintext dev)")]
    IncompleteTls,
    #[error("read sidecar TLS file `{path}`: {source}")]
    TlsFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid sidecar TLS config: {0}")]
    Tls(String),
}

/// Real gRPC sidecar client.
///
/// `Clone` is provided deliberately: the inner `Channel` and client are cheaply cloneable (same connection),
/// so callers can hand out copies without opening extra connections.
#[derive(Debug, Clone)]
pub struct GrpcSidecarClient {
    endpoint: String,
    timeout: Duration,
    circuit_break: Duration,
    mtls: bool,
    inner: pb::plugin_sidecar_client::PluginSidecarClient<Channel>,
    circuit: Arc<Circuit>,
}

impl GrpcSidecarClient {
    /// Build the client: validate config (endpoint/TLS files) → `connect_lazy()`.
    ///
    /// **No network IO, never blocks startup**; an unreachable service only surfaces on the first `process` as
    /// [`PluginError::Failed`] (never a panic).
    ///
    /// Must be called inside a **Tokio runtime context** (the lazy construction of `tonic::transport::Channel` binds
    /// to the current runtime; node `node::build` and the integration tests both satisfy this).
    pub fn connect(cfg: &SidecarConfig) -> Result<Self, SidecarInitError> {
        let endpoint_str = cfg.endpoint.trim().to_string();
        if endpoint_str.is_empty() {
            return Err(SidecarInitError::EmptyEndpoint);
        }
        if cfg.timeout.is_zero() {
            return Err(SidecarInitError::ZeroTimeout);
        }
        let is_https = endpoint_str.starts_with("https://");
        let is_http = endpoint_str.starts_with("http://");
        if !is_http && !is_https {
            return Err(SidecarInitError::BadEndpoint {
                endpoint: endpoint_str,
                reason: "endpoint must start with http:// or https://".to_string(),
            });
        }
        // TLS and scheme must agree: no silent degradation such as "certs configured but plaintext" or "https without certs".
        let mtls = match &cfg.tls {
            Some(tls) => {
                if !tls.is_complete() {
                    return Err(SidecarInitError::IncompleteTls);
                }
                if !is_https {
                    return Err(SidecarInitError::BadEndpoint {
                        endpoint: endpoint_str,
                        reason: "tls_ca/tls_cert/tls_key configured; endpoint must be https://"
                            .to_string(),
                    });
                }
                true
            }
            None => {
                if is_https {
                    return Err(SidecarInitError::BadEndpoint {
                        endpoint: endpoint_str,
                        reason: "https endpoint requires tls_ca/tls_cert/tls_key (mTLS)"
                            .to_string(),
                    });
                }
                false
            }
        };

        // Read the certificates first (local files; config-time errors → construction failure, and the node side only WARNs and falls back to Noop).
        let mut endpoint = Endpoint::from_shared(endpoint_str.clone()).map_err(|e| {
            SidecarInitError::BadEndpoint {
                endpoint: endpoint_str.clone(),
                reason: format!("invalid gRPC URI: {e}"),
            }
        })?;
        endpoint = endpoint.connect_timeout(cfg.timeout);

        if let Some(tls) = &cfg.tls {
            let ca = read_pem(&tls.ca_path)?;
            let cert = read_pem(&tls.cert_path)?;
            let key = read_pem(&tls.key_path)?;
            let tls_cfg = ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(ca))
                .identity(Identity::from_pem(cert, key));
            endpoint = endpoint
                .tls_config(tls_cfg)
                .map_err(|e| SidecarInitError::Tls(e.to_string()))?;
        }

        let channel = endpoint.connect_lazy();
        Ok(Self {
            endpoint: endpoint_str,
            timeout: cfg.timeout,
            circuit_break: cfg.circuit_break,
            mtls,
            inner: pb::plugin_sidecar_client::PluginSidecarClient::new(channel),
            circuit: Arc::new(Circuit::default()),
        })
    }

    /// Configured endpoint (for logs/status; never contains certificate contents).
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Whether mTLS is on (all three `[plugins.sidecar] tls_*` set).
    pub fn mtls(&self) -> bool {
        self.mtls
    }

    /// Hard timeout per call.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Circuit-break window.
    pub fn circuit_break(&self) -> Duration {
        self.circuit_break
    }

    /// Whether the circuit is currently open (inside the window).
    pub fn circuit_open(&self) -> bool {
        self.circuit.is_open()
    }

    /// Circuit-break remaining milliseconds (0 = closed; for diagnostics/status display).
    pub fn circuit_remaining_ms(&self) -> u64 {
        self.circuit.remaining_ms()
    }
}

/// Read a PEM file (empty path counts as unconfigured; a read failure is a construction error).
fn read_pem(path: &str) -> Result<Vec<u8>, SidecarInitError> {
    let path = path.trim();
    if path.is_empty() {
        return Err(SidecarInitError::IncompleteTls);
    }
    std::fs::read(path).map_err(|source| SidecarInitError::TlsFile {
        path: path.to_string(),
        source,
    })
}

/// A non-empty `ProcessResp.error` means failure (⑤ §10 proto comment semantics).
#[async_trait::async_trait]
impl SidecarClient for GrpcSidecarClient {
    async fn process(&self, req: ProcessReq) -> Result<ProcessResp, PluginError> {
        let ns = req.ns.clone();
        // Inside the circuit-break window: fail immediately without hitting the sidecar (no network timeout cost).
        if self.circuit.is_open() {
            return Err(PluginError::CircuitOpen { ns });
        }
        let started = Instant::now();
        let mut client = self.inner.clone();
        let wire = pb::ProcessReq {
            ns: req.ns,
            op: req.op,
            input: req.input,
            opts: Default::default(),
        };
        let call = client.process(tonic::Request::new(wire));
        let wire_resp = match tokio::time::timeout(self.timeout, call).await {
            // Timeout: the message passes through as "no converter" and this plugin is circuit-broken (⑤ §10).
            Err(_) => {
                self.circuit.trip_for(self.circuit_break);
                // Low-cardinality log: ns + timeout value; **input is never printed**.
                tracing::warn!(
                    ns = %ns,
                    timeout_ms = self.timeout.as_millis() as u64,
                    "sidecar process timeout (circuit opened)"
                );
                return Err(PluginError::Timeout { ns });
            }
            // Transport/status error: unavailable → circuit break (payload never printed; the error code is low-cardinality).
            Ok(Err(status)) => {
                self.circuit.trip_for(self.circuit_break);
                let code = status.code();
                tracing::warn!(
                    ns = %ns,
                    code = ?code,
                    "sidecar process failed (circuit opened)"
                );
                return Err(PluginError::Failed {
                    ns,
                    msg: format!("grpc {code:?}: {}", status.message()),
                });
            }
            Ok(Ok(resp)) => resp.into_inner(),
        };
        // Transport layer succeeded: half-open probe succeeded / normal call → close the circuit.
        self.circuit.reset();
        let elapsed_ms = if wire_resp.elapsed_ms > 0 {
            wire_resp.elapsed_ms
        } else {
            started.elapsed().as_millis() as u64
        };
        if wire_resp.error.is_empty() {
            Ok(ProcessResp {
                output: wire_resp.output,
                error: None,
                elapsed_ms,
            })
        } else {
            // sidecar online, business failure: not counted toward the circuit break (bad input should not open the breaker for the whole plugin).
            // The error content may echo caller input; return it to the caller only, never log it.
            tracing::warn!(ns = %ns, "sidecar returned process error");
            Err(PluginError::Failed {
                ns,
                msg: wire_resp.error,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits;

    #[test]
    fn defaults_match_contract() {
        let cfg = SidecarConfig::default();
        assert!(cfg.endpoint.is_empty());
        assert_eq!(
            cfg.timeout,
            Duration::from_millis(limits::SIDECAR_TIMEOUT_MS)
        );
        assert_eq!(cfg.timeout.as_millis(), 500, "⑤ §10 timeout 500ms");
        assert_eq!(
            cfg.circuit_break,
            Duration::from_secs(limits::CIRCUIT_BREAK_SECS)
        );
        assert_eq!(cfg.circuit_break.as_secs(), 30, "⑤ §10 circuit break 30s");
        assert!(cfg.tls.is_none(), "plaintext by default (dev only; the node side WARNs at startup)");
    }

    #[test]
    fn empty_endpoint_rejected_without_panic() {
        let err = GrpcSidecarClient::connect(&SidecarConfig::default()).unwrap_err();
        assert!(matches!(err, SidecarInitError::EmptyEndpoint));
    }

    #[test]
    fn zero_timeout_rejected() {
        let cfg = SidecarConfig {
            endpoint: "http://127.0.0.1:1".into(),
            timeout: Duration::ZERO,
            ..SidecarConfig::default()
        };
        assert!(matches!(
            GrpcSidecarClient::connect(&cfg).unwrap_err(),
            SidecarInitError::ZeroTimeout
        ));
    }

    #[test]
    fn endpoint_requires_scheme() {
        let cfg = SidecarConfig {
            endpoint: "127.0.0.1:19090".into(),
            ..SidecarConfig::default()
        };
        assert!(matches!(
            GrpcSidecarClient::connect(&cfg).unwrap_err(),
            SidecarInitError::BadEndpoint { .. }
        ));
    }

    #[test]
    fn https_without_tls_is_rejected_not_downgraded() {
        let cfg = SidecarConfig {
            endpoint: "https://127.0.0.1:19090".into(),
            ..SidecarConfig::default()
        };
        assert!(matches!(
            GrpcSidecarClient::connect(&cfg).unwrap_err(),
            SidecarInitError::BadEndpoint { .. }
        ));
    }

    #[test]
    fn http_with_tls_is_rejected() {
        let cfg = SidecarConfig {
            endpoint: "http://127.0.0.1:19090".into(),
            tls: Some(SidecarTls {
                ca_path: "/nonexistent/ca.pem".into(),
                cert_path: "/nonexistent/cert.pem".into(),
                key_path: "/nonexistent/key.pem".into(),
            }),
            ..SidecarConfig::default()
        };
        assert!(matches!(
            GrpcSidecarClient::connect(&cfg).unwrap_err(),
            SidecarInitError::BadEndpoint { .. }
        ));
    }

    #[test]
    fn incomplete_tls_is_rejected_fail_closed() {
        for tls in [
            SidecarTls {
                ca_path: "/tmp/ca.pem".into(),
                cert_path: String::new(),
                key_path: String::new(),
            },
            SidecarTls {
                ca_path: String::new(),
                cert_path: "/tmp/cert.pem".into(),
                key_path: String::new(),
            },
            SidecarTls {
                ca_path: String::new(),
                cert_path: String::new(),
                key_path: "/tmp/key.pem".into(),
            },
        ] {
            let cfg = SidecarConfig {
                endpoint: "https://127.0.0.1:19090".into(),
                tls: Some(tls),
                ..SidecarConfig::default()
            };
            assert!(matches!(
                GrpcSidecarClient::connect(&cfg).unwrap_err(),
                SidecarInitError::IncompleteTls
            ));
        }
    }

    #[test]
    fn missing_tls_files_are_init_errors() {
        let cfg = SidecarConfig {
            endpoint: "https://127.0.0.1:19090".into(),
            tls: Some(SidecarTls {
                ca_path: "/nonexistent/lattice-sidecar-ca.pem".into(),
                cert_path: "/nonexistent/lattice-sidecar-client.pem".into(),
                key_path: "/nonexistent/lattice-sidecar-client.key".into(),
            }),
            ..SidecarConfig::default()
        };
        assert!(matches!(
            GrpcSidecarClient::connect(&cfg).unwrap_err(),
            SidecarInitError::TlsFile { .. }
        ));
    }

    #[tokio::test]
    async fn plaintext_lazy_connect_never_touches_network() {
        // An unreachable address still constructs successfully (lazy): node startup does not depend on the sidecar being online.
        // Note: tonic Channel's lazy construction binds to the current Tokio runtime (it must be called inside a runtime context;
        // the node-side `node::build` runs inside the runtime; here #[tokio::test] provides the same context).
        let cfg = SidecarConfig {
            endpoint: "http://127.0.0.1:1".into(),
            ..SidecarConfig::default()
        };
        let c = GrpcSidecarClient::connect(&cfg).expect("lazy connect performs no network IO");
        assert!(!c.mtls());
        assert_eq!(c.endpoint(), "http://127.0.0.1:1");
        assert!(!c.circuit_open());
    }
}
