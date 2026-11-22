//! `PluginSidecar` gRPC client integration tests (⑤ §10; PL-10 sidecar).
//!
//! Everything uses a **real local tonic server** (`127.0.0.1:0`); the transport layer is not mocked:
//! - normal round trip (ns/op/input passthrough, output, elapsed_ms) + single-connection reuse;
//! - 500ms timeout (mock delays 900ms) → `Timeout` + circuit opens;
//! - unreachable service (port already released) → `Failed` (no panic) + circuit opens;
//! - inside the circuit window, immediate `CircuitOpen` (no sidecar hit) + half-open recovery after a short window;
//! - business error (non-empty `ProcessResp.error`) → `Failed` and **does not** open the circuit;
//! - mTLS: rcgen issues CA/server/client certificates on the spot, a real TLS round trip; wrong CA → handshake failure mapped to `Failed`;
//! - TLS config semantics: partial config / missing file / invalid PEM / scheme mismatch → construction error (fail-closed).
//!
//! The "logs never print input/output" redaction assertions live in a **separate test binary**
//! `tests/sidecar_log_redaction.rs`: tracing's callsite interest is a process-wide global cache,
//! and other tests running in parallel in the same process would first mark the callsite "never", making capture-based assertions unstable.
//!
//! Run: `cargo test -p lattice-plugins --test sidecar_grpc` (no network, no external services).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lattice_plugins::sidecar::grpc::pb;
use lattice_plugins::sidecar::{
    GrpcSidecarClient, PluginError, ProcessReq, SidecarClient, SidecarConfig, SidecarInitError,
    SidecarTls,
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt as _;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

// ---------------------------------------------------------------------------
// mock sidecar (real tonic server)
// ---------------------------------------------------------------------------

/// Controllable mock `PluginSidecar`:
/// - `delay_ms`: sleep inside `Process` (tests timeouts);
/// - `fail`: return `Status::unavailable` (tests transport failure/circuit break);
/// - `error_text`: non-empty `ProcessResp.error` (tests that business errors do not trip the circuit);
/// - `last`: records the last received request (verifies ns/op/input passthrough);
/// - `calls`: call counter (verifies the circuit window really avoids hitting the sidecar).
#[derive(Clone)]
struct MockSidecar {
    calls: Arc<AtomicUsize>,
    last: Arc<Mutex<Option<pb::ProcessReq>>>,
    delay_ms: Arc<AtomicU64>,
    fail: Arc<AtomicBool>,
    error_text: Arc<Mutex<String>>,
}

impl Default for MockSidecar {
    fn default() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            last: Arc::new(Mutex::new(None)),
            delay_ms: Arc::new(AtomicU64::new(0)),
            fail: Arc::new(AtomicBool::new(false)),
            error_text: Arc::new(Mutex::new(String::new())),
        }
    }
}

#[tonic::async_trait]
impl pb::plugin_sidecar_server::PluginSidecar for MockSidecar {
    async fn process(
        &self,
        request: Request<pb::ProcessReq>,
    ) -> Result<Response<pb::ProcessResp>, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let req = request.into_inner();
        *self.last.lock().unwrap() = Some(req.clone());
        let delay = self.delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(Status::unavailable("mock sidecar down"));
        }
        let error = self.error_text.lock().unwrap().clone();
        // Output = reversed input (so the assertion shows output really came from the sidecar, not a local fake).
        let output = req.input.iter().rev().copied().collect();
        Ok(Response::new(pb::ProcessResp {
            output,
            error,
            elapsed_ms: 7,
        }))
    }

    async fn health(
        &self,
        _request: Request<pb::Empty>,
    ) -> Result<Response<pb::HealthResp>, Status> {
        Ok(Response::new(pb::HealthResp {
            healthy: true,
            version: "mock-1".into(),
            inflight: 0,
        }))
    }
}

/// Start a tonic server on `127.0.0.1:0` (TLS optional); sends a stop signal on `Drop`.
struct MockServer {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    stop: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl MockServer {
    async fn spawn(mock: MockSidecar, tls: Option<ServerTlsConfig>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock sidecar");
        let addr = listener.local_addr().expect("local_addr");
        // Count TCP connections accepted by the server (verifies client single-connection reuse).
        let connections = Arc::new(AtomicUsize::new(0));
        let conns = connections.clone();
        let incoming = TcpListenerStream::new(listener).map(move |item| {
            if item.is_ok() {
                conns.fetch_add(1, Ordering::SeqCst);
            }
            item
        });
        let svc = pb::plugin_sidecar_server::PluginSidecarServer::new(mock);
        let (stop, stopped) = oneshot::channel::<()>();
        let mut builder = Server::builder();
        if let Some(tls) = tls {
            builder = builder.tls_config(tls).expect("mock server tls config");
        }
        let router = builder.add_service(svc);
        let join = tokio::spawn(async move {
            let _ = router
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = stopped.await;
                })
                .await;
        });
        Self {
            addr,
            connections,
            stop: Some(stop),
            join,
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), self.join).await;
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn plain_client(endpoint: &str) -> GrpcSidecarClient {
    GrpcSidecarClient::connect(&SidecarConfig {
        endpoint: endpoint.to_string(),
        ..SidecarConfig::default()
    })
    .expect("lazy connect does no network IO; a valid config must succeed")
}

fn req(ns: &str, op: &str, input: &[u8]) -> ProcessReq {
    ProcessReq {
        ns: ns.into(),
        op: op.into(),
        input: input.to_vec(),
    }
}

/// Grab a local port that is guaranteed unlistened: bind then drop immediately (connections will be refused).
async fn closed_port_addr() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "lattice-sidecar-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_pem(dir: &Path, name: &str, pem: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, pem).unwrap();
    path.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// rcgen on-the-spot PKI (for the real mTLS tests; does not depend on the repo .dev certificates)
// ---------------------------------------------------------------------------

struct TestPki {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

impl TestPki {
    fn generate() -> Self {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        // CA
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Lattice Sidecar Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Server certificate: SAN covers localhost / 127.0.0.1 (tests use 127.0.0.1 as the endpoint host)
        let server_key = KeyPair::generate().unwrap();
        let mut server_params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "lattice-sidecar");
        server_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        // Client certificate (node identity)
        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "lattice-node");
        client_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .unwrap();

        Self {
            ca_pem: ca_cert.pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    fn server_tls(&self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(Identity::from_pem(
                self.server_cert_pem.as_bytes(),
                self.server_key_pem.as_bytes(),
            ))
            .client_ca_root(Certificate::from_pem(self.ca_pem.as_bytes()))
    }

    fn client_tls(&self, dir: &Path) -> SidecarTls {
        SidecarTls {
            ca_path: write_pem(dir, "ca.pem", &self.ca_pem),
            cert_path: write_pem(dir, "client.pem", &self.client_cert_pem),
            key_path: write_pem(dir, "client.key", &self.client_key_pem),
        }
    }
}

// ---------------------------------------------------------------------------
// 1) Normal round trip + single-connection reuse + ns/op/input passthrough
// ---------------------------------------------------------------------------

#[tokio::test]
async fn process_roundtrip_reuses_single_connection() {
    let mock = MockSidecar::default();
    let server = MockServer::spawn(mock.clone(), None).await;
    let client = plain_client(&server.endpoint());

    let first = tokio::time::timeout(
        Duration::from_secs(5),
        client.process(req("json", "convert", b"abc")),
    )
    .await
    .expect("process must not hang")
    .expect("a normal call must succeed");
    assert_eq!(
        first.output, b"cba",
        "output must be the bytes returned by the sidecar (reversed input)"
    );
    assert_eq!(first.error, None);
    assert_eq!(first.elapsed_ms, 7, "elapsed_ms uses the value reported by the sidecar");

    let second = tokio::time::timeout(
        Duration::from_secs(5),
        client.process(req("xml", "validate", b"xyz")),
    )
    .await
    .expect("process must not hang")
    .expect("the second call must succeed");
    assert_eq!(second.output, b"zyx");

    // ns/op/input pass through to the sidecar unchanged (last request).
    let last = mock.last.lock().unwrap().clone().expect("the sidecar received a request");
    assert_eq!(last.ns, "xml");
    assert_eq!(last.op, "validate");
    assert_eq!(last.input, b"xyz");
    assert!(last.opts.is_empty(), "opts are not used yet (reserved in the contract)");
    assert_eq!(mock.calls.load(Ordering::SeqCst), 2);

    // Single-connection reuse: two sequential calls should establish only 1 TCP connection.
    assert_eq!(
        server.connections.load(Ordering::SeqCst),
        1,
        "multiple calls on the same client must reuse one connection"
    );
    assert!(!client.circuit_open(), "the circuit must be closed after a successful call");
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 2) 500ms timeout + circuit opens (no sidecar hit inside the window)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn process_times_out_at_500ms_and_trips_circuit() {
    let mock = MockSidecar::default();
    mock.delay_ms.store(900, Ordering::SeqCst);
    let server = MockServer::spawn(mock.clone(), None).await;
    let client = plain_client(&server.endpoint());

    let started = Instant::now();
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        client.process(req("slow", "convert", b"payload")),
    )
    .await
    .expect("the timeout is bounded by the client's 500ms cap; it must not hang until the test timeout")
    .expect_err("the mock delays 900ms > the 500ms cap, so it must time out");
    let elapsed = started.elapsed();
    assert!(
        matches!(err, PluginError::Timeout { .. }),
        "the error must be Timeout, actual {err:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(450),
        "it must take about 500ms before timing out, actual {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(900),
        "it must time out before the mock returns, actual {elapsed:?}"
    );
    assert!(client.circuit_open(), "a timeout must trip the circuit");

    // Inside the circuit window: immediate CircuitOpen, and **no sidecar hit**.
    let calls_before = mock.calls.load(Ordering::SeqCst);
    let started = Instant::now();
    let err = client
        .process(req("slow", "convert", b"payload"))
        .await
        .expect_err("must be rejected inside the circuit window");
    assert!(
        matches!(err, PluginError::CircuitOpen { .. }),
        "actual {err:?}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "must fail immediately inside the circuit window (no network), actual {:?}",
        started.elapsed()
    );
    assert_eq!(
        mock.calls.load(Ordering::SeqCst),
        calls_before,
        "must not call the sidecar inside the circuit window"
    );
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 3) Unreachable service → Failed (no panic), then circuit break
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unreachable_sidecar_fails_without_panic() {
    const SECRET: &[u8] = b"SECRET-UNREACHABLE-INPUT";
    let addr = closed_port_addr().await;
    // On this host (Windows), the first connect to a released loopback port takes ~2s before RST,
    // so the timeout is widened to 3s here: the disconnect error returns before the timeout, verifying "unreachable → Failed".
    // (With the default 500ms timeout, such an environment's slow rejection would trip Timeout first — also "no panic + circuit break",
    //  covered by process_times_out_at_500ms_and_trips_circuit.)
    let client = GrpcSidecarClient::connect(&SidecarConfig {
        endpoint: format!("http://{addr}"),
        timeout: Duration::from_secs(3),
        ..SidecarConfig::default()
    })
    .expect("client");

    let err = tokio::time::timeout(
        Duration::from_secs(6),
        client.process(req("json", "convert", SECRET)),
    )
    .await
    .expect("a connection error must return; it cannot hang past the client timeout")
    .expect_err("an unreachable service must return an error");
    assert!(
        matches!(err, PluginError::Failed { .. }),
        "unreachable → Failed (no panic), actual {err:?}"
    );
    assert!(
        !err.to_string().contains("SECRET-UNREACHABLE-INPUT"),
        "the error text must not echo the payload"
    );
    assert!(client.circuit_open(), "a transport failure must trip the circuit");

    // Inside the circuit window: immediate CircuitOpen (no further connection attempts).
    let started = Instant::now();
    let err = client
        .process(req("json", "convert", SECRET))
        .await
        .expect_err("must be rejected inside the circuit window");
    assert!(
        matches!(err, PluginError::CircuitOpen { .. }),
        "actual {err:?}"
    );
    assert!(started.elapsed() < Duration::from_millis(100));
}

// ---------------------------------------------------------------------------
// 4) Circuit recovery after a short window (half-open probe); the default 30s window is asserted in unit tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn circuit_recovers_after_short_window() {
    let mock = MockSidecar::default();
    mock.fail.store(true, Ordering::SeqCst);
    let server = MockServer::spawn(mock.clone(), None).await;
    let client = GrpcSidecarClient::connect(&SidecarConfig {
        endpoint: server.endpoint(),
        circuit_break: Duration::from_millis(120),
        ..SidecarConfig::default()
    })
    .expect("client");

    let err = client
        .process(req("json", "convert", b"abc"))
        .await
        .expect_err("the mock returns unavailable");
    assert!(matches!(err, PluginError::Failed { .. }), "actual {err:?}");
    assert!(client.circuit_open());
    let calls_after_first = mock.calls.load(Ordering::SeqCst);

    // Inside the circuit window: reject immediately, no sidecar hit.
    let err = client
        .process(req("json", "convert", b"abc"))
        .await
        .expect_err("rejected inside the circuit window");
    assert!(matches!(err, PluginError::CircuitOpen { .. }));
    assert_eq!(mock.calls.load(Ordering::SeqCst), calls_after_first);

    // The sidecar recovers; after the short window it half-opens, the call succeeds and closes the circuit.
    mock.fail.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!client.circuit_open(), "a half-open probe must be allowed after the window");
    let ok = client
        .process(req("json", "convert", b"abc"))
        .await
        .expect("must succeed after recovery");
    assert_eq!(ok.output, b"cba");
    assert!(!client.circuit_open());
    assert_eq!(mock.calls.load(Ordering::SeqCst), calls_after_first + 1);
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 5) Business error: Failed but does **not** open the circuit (bad input should not break the whole plugin)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn application_error_does_not_trip_circuit() {
    let mock = MockSidecar::default();
    *mock.error_text.lock().unwrap() = "unsupported_format".into();
    let server = MockServer::spawn(mock.clone(), None).await;
    let client = plain_client(&server.endpoint());

    let err = client
        .process(req("json", "convert", b"abc"))
        .await
        .expect_err("a non-empty ProcessResp.error means failure");
    assert!(matches!(err, PluginError::Failed { .. }), "actual {err:?}");
    assert!(err.to_string().contains("unsupported_format"));
    assert!(!client.circuit_open(), "business errors do not count toward the circuit (the sidecar is online)");

    // The next call hits the sidecar as usual (not blocked by the circuit).
    let calls = mock.calls.load(Ordering::SeqCst);
    let _ = client.process(req("json", "convert", b"abc")).await;
    assert_eq!(mock.calls.load(Ordering::SeqCst), calls + 1);
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// 6) mTLS: a real CA issues certificates → real TLS round trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_roundtrip_with_generated_pki() {
    let pki = TestPki::generate();
    let mock = MockSidecar::default();
    let server = MockServer::spawn(mock.clone(), Some(pki.server_tls())).await;
    let dir = temp_dir("mtls-ok");
    let tls = pki.client_tls(&dir);

    let client = GrpcSidecarClient::connect(&SidecarConfig {
        endpoint: format!("https://127.0.0.1:{}", server.addr.port()),
        tls: Some(tls),
        ..SidecarConfig::default()
    })
    .expect("mTLS client construction (certificate files are valid)");
    assert!(client.mtls());

    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        client.process(req("json", "convert", b"mtls")),
    )
    .await
    .expect("an mTLS call must not hang")
    .expect("the mTLS round trip must succeed");
    assert_eq!(resp.output, b"sltm", "reversed mtls should be sltm");
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    server.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// 7) mTLS handshake failure (client does not trust the server CA) → Failed, no panic, no half-open connection left
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_with_untrusted_ca_fails_cleanly() {
    let server_pki = TestPki::generate();
    let client_pki = TestPki::generate(); // a different CA: the client does not trust the server certificate
    let server = MockServer::spawn(MockSidecar::default(), Some(server_pki.server_tls())).await;
    let dir = temp_dir("mtls-bad-ca");
    let tls = client_pki.client_tls(&dir);

    let client = GrpcSidecarClient::connect(&SidecarConfig {
        endpoint: format!("https://127.0.0.1:{}", server.addr.port()),
        tls: Some(tls),
        ..SidecarConfig::default()
    })
    .expect("config is valid (what is wrong is the trust relationship, not the syntax)");

    let err = tokio::time::timeout(
        Duration::from_secs(5),
        client.process(req("json", "convert", b"x")),
    )
    .await
    .expect("a TLS handshake failure must return quickly")
    .expect_err("an untrusted CA must fail");
    assert!(
        matches!(err, PluginError::Failed { .. }),
        "TLS failure → Failed (no panic), actual {err:?}"
    );
    assert!(client.circuit_open(), "a TLS handshake failure counts as a transport failure → circuit break");
    server.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// 8) TLS config semantics: fail-closed (never silently degrade to plaintext), construction-time errors
// ---------------------------------------------------------------------------

#[test]
fn tls_config_errors_are_fail_closed() {
    let dir = temp_dir("tls-errors");

    // 8.1 Only some of the three configured → IncompleteTls
    for tls in [
        SidecarTls {
            ca_path: write_pem(&dir, "ca2.pem", "x"),
            cert_path: String::new(),
            key_path: String::new(),
        },
        SidecarTls {
            ca_path: write_pem(&dir, "ca3.pem", "x"),
            cert_path: write_pem(&dir, "c3.pem", "x"),
            key_path: String::new(),
        },
    ] {
        let cfg = SidecarConfig {
            endpoint: "https://127.0.0.1:1".into(),
            tls: Some(tls),
            ..SidecarConfig::default()
        };
        assert!(
            matches!(
                GrpcSidecarClient::connect(&cfg).unwrap_err(),
                SidecarInitError::IncompleteTls
            ),
            "a partial TLS config must be rejected (no silent plaintext)"
        );
    }

    // 8.2 Certificate file missing → TlsFile
    let cfg = SidecarConfig {
        endpoint: "https://127.0.0.1:1".into(),
        tls: Some(SidecarTls {
            ca_path: dir.join("missing-ca.pem").to_string_lossy().into_owned(),
            cert_path: dir.join("missing-cert.pem").to_string_lossy().into_owned(),
            key_path: dir.join("missing-key.pem").to_string_lossy().into_owned(),
        }),
        ..SidecarConfig::default()
    };
    assert!(matches!(
        GrpcSidecarClient::connect(&cfg).unwrap_err(),
        SidecarInitError::TlsFile { .. }
    ));

    // 8.3 Invalid PEM (not a certificate/private key) → construction-time Tls error (fail-closed, no panic)
    let bad_tls = SidecarTls {
        ca_path: write_pem(&dir, "bad-ca.pem", "not a pem\n"),
        cert_path: write_pem(&dir, "bad-cert.pem", "not a pem\n"),
        key_path: write_pem(&dir, "bad-key.pem", "not a pem\n"),
    };
    let cfg = SidecarConfig {
        endpoint: "https://127.0.0.1:1".into(),
        tls: Some(bad_tls),
        ..SidecarConfig::default()
    };
    assert!(
        matches!(
            GrpcSidecarClient::connect(&cfg).unwrap_err(),
            SidecarInitError::Tls(_)
        ),
        "an invalid PEM must fail at construction time (no silent plaintext)"
    );

    // 8.4 scheme and TLS consistency
    // - TLS configured but http:// used → reject (otherwise the certificate is silently ignored and plaintext is used)
    let cfg = SidecarConfig {
        endpoint: "http://127.0.0.1:1".into(),
        tls: Some(SidecarTls {
            ca_path: write_pem(&dir, "ca4.pem", "x"),
            cert_path: write_pem(&dir, "c4.pem", "x"),
            key_path: write_pem(&dir, "k4.pem", "x"),
        }),
        ..SidecarConfig::default()
    };
    assert!(matches!(
        GrpcSidecarClient::connect(&cfg).unwrap_err(),
        SidecarInitError::BadEndpoint { .. }
    ));
    // - https:// but no TLS configured → reject (never fall back to plaintext)
    let cfg = SidecarConfig {
        endpoint: "https://127.0.0.1:1".into(),
        ..SidecarConfig::default()
    };
    assert!(matches!(
        GrpcSidecarClient::connect(&cfg).unwrap_err(),
        SidecarInitError::BadEndpoint { .. }
    ));

    let _ = std::fs::remove_dir_all(dir);
}
