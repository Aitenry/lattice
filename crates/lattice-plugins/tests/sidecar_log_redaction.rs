//! sidecar client **log redaction** test (separate test binary).
//!
//! Why a separate file: tracing's callsite interest is a **process-wide global cache** — if another test in the same binary
//! hits the same callsite first on a thread with no subscriber (the sidecar client's WARN),
//! the interest is cached as "never", and this test's thread-local subscriber then receives no events (always happens under parallel runs).
//! A separate test binary guarantees that the first hit on these callsites in this process is the subscriber with the capture writer.
//!
//! Assertions:
//! 1. The capture path works (the client WARN must be seen; otherwise "no payload in logs" would pass vacuously);
//! 2. input / output / sidecar error text all **never appear in logs** (only low-cardinality data such as ns/error codes is allowed).
//!
//! Run: `cargo test -p lattice-plugins --test sidecar_log_redaction` (no network).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lattice_plugins::sidecar::grpc::pb;
use lattice_plugins::sidecar::{GrpcSidecarClient, ProcessReq, SidecarClient, SidecarConfig};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

/// Write tracing output into an in-memory buffer (`Arc<Mutex<Vec<u8>>>`).
#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// One writer per tracing event, holding the buffer lock for the whole event.
///
/// The default formatter emits an event through several `write` calls (level, target,
/// message, fields). With a shared buffer locked per call, two threads can interleave
/// their fragments and splice a token such as `ns=json` into `ns=` + `json`, which made
/// the low-cardinality assertion below fail intermittently on slower CI runners while it
/// still passed locally. Locking in `make_writer` keeps every event contiguous.
struct EventWriter<'a>(std::sync::MutexGuard<'a, Vec<u8>>);

impl std::io::Write for EventWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
    type Writer = EventWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        EventWriter(self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
    }
}

/// Drop ANSI escape sequences (`ESC [ ... m`) so assertions see the plain text form.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Clone, Default)]
struct MockSidecar {
    calls: Arc<AtomicUsize>,
    fail: Arc<AtomicBool>,
    error_text: Arc<Mutex<String>>,
}

#[tonic::async_trait]
impl pb::plugin_sidecar_server::PluginSidecar for MockSidecar {
    async fn process(
        &self,
        request: Request<pb::ProcessReq>,
    ) -> Result<Response<pb::ProcessResp>, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let req = request.into_inner();
        if self.fail.load(Ordering::SeqCst) {
            return Err(Status::unavailable("mock sidecar down"));
        }
        let error = self.error_text.lock().unwrap().clone();
        // output = reversed input (used to assert output never reaches the logs either).
        let output = req.input.iter().rev().copied().collect();
        Ok(Response::new(pb::ProcessResp {
            output,
            error,
            elapsed_ms: 1,
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

struct MockServer {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl MockServer {
    async fn spawn(mock: MockSidecar) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let incoming = TcpListenerStream::new(listener);
        let svc = pb::plugin_sidecar_server::PluginSidecarServer::new(mock);
        let (stop, stopped) = oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(svc)
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = stopped.await;
                })
                .await;
        });
        Self {
            addr,
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

fn plain_client(endpoint: &str) -> GrpcSidecarClient {
    GrpcSidecarClient::connect(&SidecarConfig {
        endpoint: endpoint.to_string(),
        ..SidecarConfig::default()
    })
    .expect("client")
}

fn req(ns: &str, op: &str, input: &[u8]) -> ProcessReq {
    ProcessReq {
        ns: ns.into(),
        op: op.into(),
        input: input.to_vec(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn payload_never_appears_in_logs() {
    const INPUT_SECRET: &str = "SECRET-INPUT-0123456789";
    const OUTPUT_SECRET: &str = "9876543210-TUPNI-TERCES"; // reversed input
    const APP_ERROR_SECRET: &str = "SECRET-APP-ERROR";

    let buf = SharedBuf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        // Colour codes are environment-dependent (a CI runner may report colour support
        // where a local shell does not). They would split `ns=json` into `ns` + ESC + `=json`
        // and defeat the substring assertions below, so the capture is always plain text.
        .with_ansi(false)
        .with_writer(writer)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // 1) The transport-failure path (Status::unavailable) logs a WARN → assert after a successful capture that it contains no payload.
    let mock = MockSidecar::default();
    mock.fail.store(true, Ordering::SeqCst);
    let server = MockServer::spawn(mock.clone()).await;
    let client = plain_client(&server.endpoint());
    let _ = client
        .process(req("json", "convert", INPUT_SECRET.as_bytes()))
        .await;
    server.shutdown().await;

    // 2) The business-error path (the error text returned by the sidecar must not reach the logs either).
    let mock = MockSidecar::default();
    *mock.error_text.lock().unwrap() = APP_ERROR_SECRET.into();
    let server = MockServer::spawn(mock.clone()).await;
    let client = plain_client(&server.endpoint());
    let err = client
        .process(req("json", "convert", INPUT_SECRET.as_bytes()))
        .await
        .expect_err("business error");
    assert!(
        err.to_string().contains(APP_ERROR_SECRET),
        "the error is returned to the caller (not counted as a log)"
    );
    server.shutdown().await;

    // 3) The success path (output is the payload reversed).
    let mock = MockSidecar::default();
    let server = MockServer::spawn(mock.clone()).await;
    let client = plain_client(&server.endpoint());
    let ok = client
        .process(req("json", "convert", INPUT_SECRET.as_bytes()))
        .await
        .expect("successful call");
    assert_eq!(ok.output, OUTPUT_SECRET.as_bytes());
    server.shutdown().await;

    let logs = strip_ansi(&buf.text());
    // First confirm the capture path works (otherwise "no payload in logs" would pass vacuously).
    assert!(
        logs.contains("sidecar process failed") && logs.contains("sidecar returned process error"),
        "the client's WARN log must be captured; actually captured {logs:?}"
    );
    assert!(
        !logs.contains(INPUT_SECRET),
        "logs must not contain the input payload; actual logs: {logs:?}"
    );
    assert!(
        !logs.contains(OUTPUT_SECRET),
        "logs must not contain the output payload; actual logs: {logs:?}"
    );
    assert!(
        !logs.contains(APP_ERROR_SECRET),
        "logs must not contain the sidecar error text; actual logs: {logs:?}"
    );
    // Only low-cardinality data is allowed (ns + error code).
    assert!(
        logs.contains("ns=json") || logs.contains("ns=\"json\""),
        "logs should carry the low-cardinality ns label; actual logs: {logs:?}"
    );
}
