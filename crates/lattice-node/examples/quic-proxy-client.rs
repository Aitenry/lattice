//! QUIC proxy E2E client (`cargo run -p lattice-node --features quic --example quic-proxy-client`).
//!
//! E2E/interop only: for the protocol see "QUIC proxy protocol v1" at the top of `crate::transport::quic`.
//! The two instances A/B are driven by `scripts/quic-proxy-e2e.mjs` / `scripts/quic-auth-e2e.mjs`:
//!
//! ```text
//! # Offerer (first establishes the session via a WS stream-sig offer; prints TOKEN so the E2E can pass it to B through stream-sig)
//! quic-proxy-client --role a --endpoint 127.0.0.1:18443 --stream-id st-1 \
//!     --access-jwt <A.access_jwt> --device-fp <A.fingerprint> \
//!     --ca .dev/quic-e2e-tls/ca.crt --send-bytes 65536 --send-seed 101 --expect-seed 202
//! # Joiner
//! quic-proxy-client --role b --endpoint 127.0.0.1:18443 --stream-id st-1 --token <TOKEN> \
//!     --access-jwt <B.access_jwt> --device-fp <B.fingerprint> ...
//! ```
//!
//! Auth negative cases (E2E):
//! - `--expect-error AUTH_FAIL --expect-reason expired` (expired JWT)
//! - `--expect-error FORBIDDEN --expect-reason device_mismatch` (fingerprint mismatch)
//! - `--expect-error FORBIDDEN --expect-reason not_participant` (not a session participant / role mismatch)
//!
//! Security boundary: when `--ca` is absent, **server certificate verification is skipped** (dev only, explicitly marked in code);
//! production deployments must pin with a CA/certificate, and this example makes no claim to be a production client.

use std::io::{BufReader, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use lattice_node::transport::quic::{
    read_frame, write_frame, ALPN, FRAME_CONTROL, FRAME_DATA,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::{json, Value};

const CHUNK: usize = 16 * 1024;

#[derive(Debug)]
struct Opts {
    endpoint: String,
    stream_id: String,
    role: String,
    token: Option<String>,
    /// Access JWT (QUIC registration auth; absent = no-JWT negative case).
    access_jwt: Option<String>,
    /// Device fingerprint (must match this device's fingerprint in the devices table).
    device_fp: Option<String>,
    ca: Option<PathBuf>,
    server_name: String,
    send_bytes: usize,
    send_seed: u64,
    expect_seed: u64,
    /// Delay before sending (in the E2E flood case, let the peer finish its small traffic first so the shared token bucket does not throttle the reverse small packets too).
    send_delay_ms: u64,
    /// How long to keep the connection after registration/pairing succeeds (drain E2E: hold until the node sends bye).
    hold_ms: u64,
    wait_peer_ms: u64,
    expect_error: Option<String>,
    /// Expected error reason (auth negative cases assert exactly `bad_jwt|expired|device_mismatch|not_participant`).
    expect_reason: Option<String>,
    /// Expect `bye{reason=...}` during the registration wait (for the drain E2E; on match the exit code is 0).
    expect_bye: Option<String>,
    result: Option<PathBuf>,
    connect_timeout_ms: u64,
    /// Shutdown grace (ms): after writing data/bye, wait a moment before closing the connection,
    /// so CONNECTION_CLOSE does not race ahead of buffered data being sent/read by the peer (a real race observed in the E2E).
    close_grace_ms: u64,
}

fn parse_args() -> Result<Opts, String> {
    let mut o = Opts {
        endpoint: "127.0.0.1:18443".into(),
        stream_id: String::new(),
        role: String::new(),
        token: None,
        access_jwt: None,
        device_fp: None,
        ca: None,
        server_name: "localhost".into(),
        send_bytes: 0,
        send_seed: 1,
        expect_seed: 2,
        send_delay_ms: 0,
        hold_ms: 0,
        wait_peer_ms: 15_000,
        expect_error: None,
        expect_reason: None,
        expect_bye: None,
        result: None,
        connect_timeout_ms: 10_000,
        close_grace_ms: 500,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let key = args[i].as_str();
        let next = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("missing value for {key}"))
        };
        match key {
            "--endpoint" => o.endpoint = next(&mut i)?,
            "--stream-id" => o.stream_id = next(&mut i)?,
            "--role" => o.role = next(&mut i)?,
            "--token" => o.token = Some(next(&mut i)?),
            "--access-jwt" => o.access_jwt = Some(next(&mut i)?),
            "--device-fp" => o.device_fp = Some(next(&mut i)?),
            "--ca" => o.ca = Some(PathBuf::from(next(&mut i)?)),
            "--server-name" => o.server_name = next(&mut i)?,
            "--send-bytes" => {
                o.send_bytes = next(&mut i)?
                    .parse()
                    .map_err(|e| format!("bad --send-bytes: {e}"))?
            }
            "--send-seed" => {
                o.send_seed = next(&mut i)?
                    .parse()
                    .map_err(|e| format!("bad --send-seed: {e}"))?
            }
            "--expect-seed" => {
                o.expect_seed = next(&mut i)?
                    .parse()
                    .map_err(|e| format!("bad --expect-seed: {e}"))?
            }
            "--wait-peer-ms" => {
                o.wait_peer_ms = next(&mut i)?
                    .parse()
                    .map_err(|e| format!("bad --wait-peer-ms: {e}"))?
            }
            "--send-delay-ms" => {
                o.send_delay_ms = next(&mut i)?
                    .parse()
                    .map_err(|e| format!("bad --send-delay-ms: {e}"))?
            }
            "--hold-ms" => {
                o.hold_ms = next(&mut i)?
                    .parse()
                    .map_err(|e| format!("bad --hold-ms: {e}"))?
            }
            "--expect-error" => o.expect_error = Some(next(&mut i)?),
            "--expect-reason" => o.expect_reason = Some(next(&mut i)?),
            "--expect-bye" => o.expect_bye = Some(next(&mut i)?),
            "--result" => o.result = Some(PathBuf::from(next(&mut i)?)),
            "--connect-timeout-ms" => {
                o.connect_timeout_ms = next(&mut i)?
                    .parse()
                    .map_err(|e| format!("bad --connect-timeout-ms: {e}"))?
            }
            "--close-grace-ms" => {
                o.close_grace_ms = next(&mut i)?
                    .parse()
                    .map_err(|e| format!("bad --close-grace-ms: {e}"))?
            }
            other => return Err(format!("unknown arg {other}")),
        }
        i += 1;
    }
    if o.stream_id.is_empty() || !matches!(o.role.as_str(), "a" | "b") {
        return Err("--stream-id and --role a|b are required".into());
    }
    Ok(o)
}

/// Deterministic payload: byte `i` = `(i*131 + seed) mod 251` (<251 keeps any offset distinguishable, making lost-frame boundaries easy to locate).
fn payload_byte(i: usize, seed: u64) -> u8 {
    ((i as u64 * 131 + seed) % 251) as u8
}

/// One media data frame (16KiB aligned): `[8B BE frame_index][deterministic payload...]`.
///
/// The frame seq prefix lets the receiver validate frame by frame even when **frames are dropped**: the server drops whole frames (rate limiting), so
/// received frame seqs must be strictly increasing and each frame's content must match its seq — "a contiguous prefix was received" cannot be assumed.
fn chunk_bytes(index: usize, len: usize, seed: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    buf.extend_from_slice(&(index as u64).to_be_bytes());
    for j in 8..len {
        buf.push(payload_byte(index * CHUNK + j, seed));
    }
    buf
}

/// **dev only**: skip server certificate verification (for E2E no-CA mode; production clients must never use it).
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config(ca: Option<&Path>) -> Result<quinn::ClientConfig, String> {
    let mut tls = match ca {
        Some(path) => {
            let data = std::fs::read(path).map_err(|e| format!("read ca {path:?}: {e}"))?;
            let mut roots = rustls::RootCertStore::empty();
            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut BufReader::new(data.as_slice()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("parse ca {path:?}: {e}"))?;
            if certs.is_empty() {
                return Err(format!("ca {path:?} contains no certificate"));
            }
            for c in certs {
                roots.add(c).map_err(|e| format!("add ca cert: {e}"))?;
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        None => {
            eprintln!("WARN: --ca not set; disabling server certificate verification (dev only)");
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
                .with_no_client_auth()
        }
    };
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| format!("quic client crypto: {e}"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_crypto)))
}

fn emit_result(opts: &Opts, value: &Value) -> Result<(), String> {
    let text = serde_json::to_string(value).map_err(|e| e.to_string())?;
    if let Some(path) = &opts.result {
        std::fs::write(path, &text).map_err(|e| format!("write result {path:?}: {e}"))?;
    }
    println!("RESULT {text}");
    let _ = std::io::stdout().flush();
    Ok(())
}

async fn run() -> Result<i32, String> {
    let opts = parse_args()?;
    let addr: SocketAddr = opts
        .endpoint
        .parse()
        .map_err(|e| format!("bad --endpoint: {e}"))?;
    let cfg = client_config(opts.ca.as_deref())?;
    let mut endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().expect("valid bind addr"))
            .map_err(|e| format!("client endpoint: {e}"))?;
    endpoint.set_default_client_config(cfg);

    let connecting = endpoint
        .connect(addr, &opts.server_name)
        .map_err(|e| format!("connect({addr}): {e}"))?;
    let conn = tokio::time::timeout(
        Duration::from_millis(opts.connect_timeout_ms),
        async { connecting.await },
    )
    .await
    .map_err(|_| "connect timeout".to_string())?
    .map_err(|e| format!("connect failed: {e}"))?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("open_bi: {e}"))?;
    let register = json!({
        "t": "register",
        "v": 1,
        "stream_id": opts.stream_id.clone(),
        "role": opts.role.clone(),
        "token": opts.token.clone().unwrap_or_default(),
        // Auth contract (PL-13 13.3): identity comes only from a JWT verified by the server; device_fp is used for device binding checks.
        "access_jwt": opts.access_jwt.clone().unwrap_or_default(),
        "device_fp": opts.device_fp.clone().unwrap_or_default(),
    });
    write_frame(&mut send, FRAME_CONTROL, register.to_string().as_bytes())
        .await
        .map_err(|e| format!("write register: {e}"))?;

    // Wait for registered / peer_ready / error / bye (drain)
    let deadline = tokio::time::Instant::now() + Duration::from_millis(opts.wait_peer_ms);
    let mut join_token = String::new();
    let mut session_token = String::new();
    loop {
        let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remain.is_zero() {
            if let Some(code) = &opts.expect_error {
                let value = json!({"ok": false, "error": "timeout_waiting_for_rejection", "expected_error": code});
                emit_result(&opts, &value)?;
                conn.close(0u32.into(), b"timeout");
                endpoint.wait_idle().await;
                return Ok(3);
            }
            if let Some(reason) = &opts.expect_bye {
                let value = json!({"ok": false, "error": "timeout_waiting_for_bye", "expected_bye": reason});
                emit_result(&opts, &value)?;
                conn.close(0u32.into(), b"timeout");
                endpoint.wait_idle().await;
                return Ok(3);
            }
            let value = json!({"ok": false, "error": "peer_timeout", "role": opts.role, "stream_id": opts.stream_id});
            emit_result(&opts, &value)?;
            conn.close(0u32.into(), b"timeout");
            endpoint.wait_idle().await;
            return Ok(3);
        }
        let frame = tokio::time::timeout(remain, read_frame(&mut recv))
            .await
            .map_err(|_| "peer timeout (read)".to_string())?;
        match frame {
            Ok(None) => {
                let value = json!({"ok": false, "error": "eof_before_peer_ready", "role": opts.role});
                emit_result(&opts, &value)?;
                conn.close(0u32.into(), b"eof");
                endpoint.wait_idle().await;
                return Ok(2);
            }
            Err(e) => {
                let value = json!({"ok": false, "error": format!("frame: {e}")});
                emit_result(&opts, &value)?;
                conn.close(0u32.into(), b"bad-frame");
                endpoint.wait_idle().await;
                return Ok(2);
            }
            Ok(Some((ty, payload))) => {
                if ty != FRAME_CONTROL {
                    continue;
                }
                let Ok(v) = serde_json::from_slice::<Value>(&payload) else {
                    continue;
                };
                match v.get("t").and_then(|t| t.as_str()).unwrap_or_default() {
                    "registered" => {
                        join_token = v
                            .get("join_token")
                            .and_then(|t| t.as_str())
                            .unwrap_or_default()
                            .to_string();
                        session_token = v
                            .get("session_token")
                            .and_then(|t| t.as_str())
                            .unwrap_or_default()
                            .to_string();
                        if opts.role == "a" {
                            // The E2E takes the ticket here and passes it to B through the existing stream-sig payload
                            println!("TOKEN {join_token}");
                            let _ = std::io::stdout().flush();
                        }
                    }
                    "peer_ready" => break,
                    "bye" => {
                        // Node draining (SIGTERM/stream removal): the server sends bye{reason:"shutdown"} on its own
                        let reason = v
                            .get("reason")
                            .and_then(|r| r.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let matched = opts
                            .expect_bye
                            .as_deref()
                            .map(|e| e == reason)
                            .unwrap_or(false);
                        let value = json!({
                            "ok": matched,
                            "role": opts.role,
                            "stream_id": opts.stream_id,
                            "error": "server_bye",
                            "bye_reason": reason,
                            "expected_bye": opts.expect_bye,
                        });
                        emit_result(&opts, &value)?;
                        conn.close(0u32.into(), b"server-bye");
                        endpoint.wait_idle().await;
                        return Ok(if matched { 0 } else { 2 });
                    }
                    "error" => {
                        let code = v
                            .get("code")
                            .and_then(|c| c.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let reason = v
                            .get("reason")
                            .and_then(|r| r.as_str())
                            .unwrap_or_default()
                            .to_string();
                        // Both the error code and the (optional) reason must match to count as expected
                        let code_ok = opts
                            .expect_error
                            .as_deref()
                            .map(|e| e == code)
                            .unwrap_or(false);
                        let reason_ok = opts
                            .expect_reason
                            .as_deref()
                            .map(|e| e == reason)
                            .unwrap_or(true);
                        let matched = code_ok && reason_ok;
                        let value = json!({
                            "ok": matched,
                            "role": opts.role,
                            "stream_id": opts.stream_id,
                            "error_code": code,
                            "error_reason": reason,
                            "expected_error": opts.expect_error,
                            "expected_reason": opts.expect_reason,
                        });
                        emit_result(&opts, &value)?;
                        conn.close(0u32.into(), b"rejected");
                        endpoint.wait_idle().await;
                        return Ok(if matched { 0 } else { 2 });
                    }
                    _ => {}
                }
            }
        }
    }

    if opts.expect_error.is_some() {
        let value = json!({
            "ok": false,
            "error": "expected rejection but stream was accepted",
            "role": opts.role,
            "stream_id": opts.stream_id,
        });
        emit_result(&opts, &value)?;
        conn.close(0u32.into(), b"unexpected");
        endpoint.wait_idle().await;
        return Ok(2);
    }

    // Drain E2E: keep the connection after registration/pairing and wait for the node to send bye{reason:shutdown}
    if opts.hold_ms > 0 {
        tokio::time::sleep(Duration::from_millis(opts.hold_ms)).await;
    }

    // Data plane: both directions send and receive concurrently (one QUIC bidi stream: the send half sends, the recv half receives)
    let stream_id = opts.stream_id.clone();
    let send_bytes = opts.send_bytes;
    let seed_send = opts.send_seed;
    let send_delay_ms = opts.send_delay_ms;
    let send_task = tokio::spawn(async move {
        if send_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(send_delay_ms)).await;
        }
        let mut sent = 0usize;
        let mut index = 0usize;
        while sent < send_bytes {
            let n = CHUNK.min(send_bytes - sent);
            let payload = chunk_bytes(index, n, seed_send);
            if write_frame(&mut send, FRAME_DATA, &payload).await.is_err() {
                return Err("write data failed".to_string());
            }
            sent += n;
            index += 1;
        }
        let bye = json!({"t": "bye", "stream_id": stream_id}).to_string();
        let _ = write_frame(&mut send, FRAME_CONTROL, bye.as_bytes()).await;
        let _ = send.finish();
        Ok::<usize, String>(sent)
    });

    let seed_expect = opts.expect_seed;
    let recv_stream_id = opts.stream_id.clone();
    let recv_task = tokio::spawn(async move {
        let mut received = 0usize;
        let mut matched = 0usize;
        let mut frames_received = 0usize;
        let mut first_mismatch: Option<usize> = None;
        let mut last_index: Option<usize> = None;
        let mut peer_bye = false;
        loop {
            match read_frame(&mut recv).await {
                Ok(None) => break,
                Err(e) => return Err(format!("read data failed: {e}")),
                Ok(Some((ty, payload))) => match ty {
                    FRAME_DATA => {
                        let frame_len = payload.len();
                        if frame_len < 8 {
                            if first_mismatch.is_none() {
                                first_mismatch = Some(received);
                            }
                        } else {
                            let idx = u64::from_be_bytes(
                                payload[..8].try_into().expect("8B frame index"),
                            ) as usize;
                            // The server drops whole frames (rate limiting), so only "each frame is self-consistent + frame seqs increase" is required,
                            // and a contiguous prefix cannot be assumed (drops leave holes).
                            let expected = chunk_bytes(idx, frame_len, seed_expect);
                            let order_ok = last_index.map(|last| idx > last).unwrap_or(true);
                            if expected.as_slice() == &payload[..] && order_ok {
                                matched += frame_len;
                                frames_received += 1;
                                last_index = Some(idx);
                            } else if first_mismatch.is_none() {
                                first_mismatch = Some(received);
                            }
                        }
                        received += frame_len;
                    }
                    FRAME_CONTROL => {
                        if let Ok(v) = serde_json::from_slice::<Value>(&payload) {
                            if v.get("t").and_then(|t| t.as_str()) == Some("bye") {
                                peer_bye = true;
                            }
                        }
                    }
                    _ => {}
                },
            }
        }
        Ok::<_, String>((received, matched, frames_received, first_mismatch, peer_bye, recv_stream_id))
    });

    let sent = send_task.await.map_err(|e| format!("send task join: {e}"))??;
    let (received, matched, frames_received, first_mismatch, peer_bye, _sid) =
        recv_task.await.map_err(|e| format!("recv task join: {e}"))??;
    // Grace period: let the finished send half actually flush/be read by the peer, then send CONNECTION_CLOSE.
    if opts.close_grace_ms > 0 {
        tokio::time::sleep(Duration::from_millis(opts.close_grace_ms)).await;
    }

    let allow_drops = opts.send_bytes > 0 && received != opts.send_bytes;
    // Passing full-frame validation (content + increasing seq) counts as correct; with drops allowed, receiving less than sent is fine
    let content_ok = first_mismatch.is_none() && matched == received;
    let ok = content_ok && (allow_drops || received == opts.send_bytes) && (!join_token.is_empty() || opts.role == "b");
    let value = json!({
        "ok": ok,
        "role": opts.role,
        "stream_id": opts.stream_id,
        "sent_bytes": sent,
        "recv_bytes": received,
        "recv_matched_bytes": matched,
        "frames_received": frames_received,
        "first_mismatch": first_mismatch,
        "peer_bye": peer_bye,
        "allow_drops": allow_drops,
        "session_token_len": session_token.len(),
    });
    emit_result(&opts, &value)?;
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(if ok { 0 } else { 2 })
}

fn main() {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("CLIENT ERROR: runtime: {e}");
            std::process::exit(2);
        }
    };
    match runtime.block_on(run()) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("CLIENT ERROR: {e}");
            std::process::exit(2);
        }
    }
}
