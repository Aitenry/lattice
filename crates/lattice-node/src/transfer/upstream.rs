//! Streaming object reads for the transfer plane (design §6.10).
//!
//! The node itself never proxies object bytes; the `lattice-transfer` service does, and this
//! module is its upstream: a minimal HTTP/1.1 client over the internal (plaintext) S3 endpoint
//! with three properties the download path needs:
//!
//! - **streaming**: headers are parsed, then the body is turned into a `Stream<Bytes>` and
//!   forwarded as it arrives (no full-object buffering — plugin packages reach 50MiB and
//!   recordings are unbounded);
//! - **range**: `Range` / `If-Range` are forwarded to S3 and `206`/`416`/`Content-Range` pass
//!   through, so browsers and RytenBench can resume without re-downloading a whole package;
//! - **failover**: `[s3] endpoints` is tried in order on connect errors / 5xx; the first
//!   healthy endpoint serves the object. Each endpoint signs its own presigned URL because the
//!   signature covers `Host`.
//!
//! Only `Transfer-Encoding: chunked` and `Content-Length` bodies are understood (plus
//! connection-close); anything else is a hard error rather than a silent truncation.

use std::io;
use std::time::Duration;

use bytes::Bytes;
use futures::stream::{self, Stream};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::S3Cfg;
use crate::store::s3::{parse_http_url, S3};

/// Read buffer per streamed chunk (64KiB: large enough for throughput, small enough to keep
/// per-connection memory bounded under the in-flight cap).
const CHUNK_BYTES: usize = 64 * 1024;
/// Response head cap (S3 headers are tiny; a bigger head means a broken/malicious upstream).
const MAX_HEAD_BYTES: usize = 32 * 1024;
/// Chunked-size line cap.
const MAX_CHUNK_LINE_BYTES: usize = 128;
/// Largest accepted single chunked chunk (guards an upstream that declares an absurd chunk).
const MAX_CHUNK_BYTES: u64 = 16 * 1024 * 1024;

/// One streamed object response from object storage.
pub struct Upstream {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub content_length: Option<u64>,
    /// `None` for `HEAD`, `204`, `304` and error responses without a body.
    pub body: Option<BodySource<Box<dyn AsyncRead + Unpin + Send>>>,
    /// Endpoint that served the response (metrics/logs only).
    pub endpoint: String,
}

impl Upstream {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug)]
pub enum UpstreamError {
    /// The request itself is invalid (bad range syntax) — maps to 400.
    BadRequest(String),
    /// Every candidate endpoint failed — maps to 503. Carries `(endpoint, reason)` pairs for
    /// logging/metrics; the client response stays generic.
    Unavailable(Vec<(String, String)>),
    /// The upstream answered, but the request failed for a non-retryable reason.
    Upstream(String),
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamError::BadRequest(why) => write!(f, "bad request: {why}"),
            UpstreamError::Unavailable(attempts) => {
                let detail = attempts
                    .iter()
                    .map(|(endpoint, why)| format!("{endpoint}: {why}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                write!(f, "object storage unavailable: {detail}")
            }
            UpstreamError::Upstream(why) => write!(f, "object storage error: {why}"),
        }
    }
}

impl std::error::Error for UpstreamError {}

/// Object-storage client for the transfer service.
pub struct ObjectStore {
    s3: S3,
    endpoints: Vec<String>,
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl ObjectStore {
    pub fn new(cfg: S3Cfg, connect_timeout: Duration, read_timeout: Duration) -> Self {
        let s3 = S3::new(cfg);
        let endpoints = s3.transfer_endpoints();
        ObjectStore {
            s3,
            endpoints,
            connect_timeout,
            read_timeout,
        }
    }

    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// Open one object. `method` is `GET` or `HEAD`. On connect errors or `5xx` the next
    /// endpoint is tried; a `4xx` answer is returned as-is (same credentials everywhere, so a
    /// 404/416 is authoritative).
    pub async fn open(
        &self,
        method: &str,
        bucket: &str,
        key: &str,
        range: Option<&str>,
        if_range: Option<&str>,
    ) -> Result<Upstream, UpstreamError> {
        if !matches!(method, "GET" | "HEAD") {
            return Err(UpstreamError::BadRequest("unsupported method".into()));
        }
        let range = range.map(validate_range).transpose()?;
        if self.endpoints.is_empty() {
            return Err(UpstreamError::Unavailable(vec![(
                "-".into(),
                "no [s3] endpoint configured".into(),
            )]));
        }
        let mut attempts: Vec<(String, String)> = Vec::new();
        for base in &self.endpoints {
            let url = self.s3.internal_url_at(method, base, bucket, key, 300);
            match self
                .request(base, &url, method, range.as_deref(), if_range)
                .await
            {
                Ok(up) if (500..600).contains(&up.status) => {
                    attempts.push((base.clone(), format!("HTTP {}", up.status)));
                }
                Ok(up) => return Ok(up),
                Err(e) => attempts.push((base.clone(), e)),
            }
        }
        Err(UpstreamError::Unavailable(attempts))
    }

    /// TCP health probe for `/readyz` (one short connect per endpoint, bounded).
    pub async fn probe(&self) -> Vec<(String, Result<(), String>)> {
        let mut out = Vec::with_capacity(self.endpoints.len());
        for base in &self.endpoints {
            let target = match parse_http_url(&format!("{base}/")) {
                Ok((host, port, _)) => (host, port),
                Err(e) => {
                    out.push((base.clone(), Err(e)));
                    continue;
                }
            };
            let connect = TcpStream::connect((target.0.as_str(), target.1));
            let result = match timeout(Duration::from_secs(2), connect).await {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(format!("connect {}:{}: {e}", target.0, target.1)),
                Err(_) => Err(format!("connect {}:{} timed out", target.0, target.1)),
            };
            out.push((base.clone(), result));
        }
        out
    }

    async fn request(
        &self,
        base: &str,
        url: &str,
        method: &str,
        range: Option<&str>,
        if_range: Option<&str>,
    ) -> Result<Upstream, String> {
        let (host, port, path) = parse_http_url(url)?;
        // Signing covers `Host: host:port`, so the header must match exactly what was signed
        // (S3::strip_host keeps the port).
        let signed_host = base
            .trim()
            .trim_start_matches("http://")
            .trim_end_matches('/');
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {signed_host}\r\nAccept-Encoding: identity\r\nConnection: close\r\n"
        );
        if let Some(r) = range {
            req.push_str("Range: ");
            req.push_str(r);
            req.push_str("\r\n");
        }
        if let Some(v) = if_range {
            // ETag / HTTP-date only; anything else is dropped rather than forwarded blindly.
            if v.len() <= 128 && !v.chars().any(|c| c.is_control()) {
                req.push_str("If-Range: ");
                req.push_str(v);
                req.push_str("\r\n");
            }
        }
        req.push_str("\r\n");

        let connect = TcpStream::connect((host.as_str(), port));
        let mut stream = timeout(self.connect_timeout, connect)
            .await
            .map_err(|_| format!("connect {host}:{port} timed out"))?
            .map_err(|e| format!("connect {host}:{port}: {e}"))?;
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;

        let boxed: Box<dyn AsyncRead + Unpin + Send> = Box::new(stream);
        let mut reader = BufReader::new(boxed);
        let (status, headers) = self.read_head(&mut reader).await?;

        let body_allowed = method != "HEAD" && status != 204 && status != 304;
        let chunked = header_of(&headers, "transfer-encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false);
        let content_length = header_of(&headers, "content-length").and_then(|v| v.trim().parse().ok());
        let body = if !body_allowed {
            None
        } else if chunked {
            Some(BodySource::new(reader, BodyMode::Chunked, self.read_timeout))
        } else if let Some(n) = content_length {
            Some(BodySource::new(
                reader,
                BodyMode::Length(n),
                self.read_timeout,
            ))
        } else {
            Some(BodySource::new(reader, BodyMode::UntilEof, self.read_timeout))
        };

        Ok(Upstream {
            status,
            headers,
            content_length,
            body,
            endpoint: base.to_string(),
        })
    }

    async fn read_head<R: AsyncRead + Unpin>(
        &self,
        reader: &mut BufReader<R>,
    ) -> Result<(u16, Vec<(String, String)>), String> {
        let mut total = 0usize;
        let mut status: Option<u16> = None;
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = timeout(self.read_timeout, reader.read_until(b'\n', &mut line))
                .await
                .map_err(|_| "read response head timed out".to_string())?
                .map_err(|e| format!("read response head: {e}"))?;
            if read == 0 {
                return Err("connection closed before response head".into());
            }
            total += read;
            if total > MAX_HEAD_BYTES {
                return Err("response head too large".into());
            }
            while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                break;
            }
            let text = String::from_utf8_lossy(&line);
            if status.is_none() {
                let code = text
                    .split_whitespace()
                    .nth(1)
                    .and_then(|c| c.parse::<u16>().ok())
                    .ok_or_else(|| format!("bad status line: {text}"))?;
                status = Some(code);
                continue;
            }
            if headers.len() >= 128 {
                return Err("too many response headers".into());
            }
            if let Some((k, v)) = text.split_once(':') {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        Ok((
            status.ok_or_else(|| "response head without status line".to_string())?,
            headers,
        ))
    }
}

fn header_of<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Only single-range `bytes=` is forwarded; anything else is rejected by the service before it
/// can reach the upstream. (Multi-range would require multipart/byteranges, which this service
/// deliberately does not implement.)
fn validate_range(raw: &str) -> Result<String, UpstreamError> {
    let v = raw.trim();
    if v.len() > 128 {
        return Err(UpstreamError::BadRequest("range too long".into()));
    }
    let rest = v
        .strip_prefix("bytes=")
        .ok_or_else(|| UpstreamError::BadRequest("only bytes ranges are supported".into()))?;
    if rest.is_empty()
        || rest.contains(',')
        || !rest
            .chars()
            .all(|c| c.is_ascii_digit() || c == '-' || c == ' ')
    {
        return Err(UpstreamError::BadRequest("unsupported range syntax".into()));
    }
    Ok(v.to_string())
}

/// How the upstream body is delimited.
#[derive(Debug, Clone, Copy)]
pub enum BodyMode {
    Length(u64),
    Chunked,
    UntilEof,
}

/// A streaming object body that decodes `chunked` framing and enforces a per-read idle timeout.
pub struct BodySource<R> {
    reader: BufReader<R>,
    mode: BodyMode,
    read_timeout: Duration,
}

impl<R> BodySource<R>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    pub fn new(reader: BufReader<R>, mode: BodyMode, read_timeout: Duration) -> Self {
        BodySource {
            reader,
            mode,
            read_timeout,
        }
    }

    /// Convert the body into a chunk stream suitable for `axum::body::Body::from_stream`.
    pub fn into_stream(self) -> impl Stream<Item = io::Result<Bytes>> {
        stream::unfold(Some(self), |state| async move {
            let mut source = state?;
            match source.next_chunk().await {
                Ok(Some(bytes)) => Some((Ok(bytes), Some(source))),
                Ok(None) => None,
                Err(e) => Some((Err(e), None)),
            }
        })
    }

    async fn next_chunk(&mut self) -> io::Result<Option<Bytes>> {
        match self.mode {
            BodyMode::Length(remaining) => {
                if remaining == 0 {
                    return Ok(None);
                }
                let want = remaining.min(CHUNK_BYTES as u64) as usize;
                let mut buf = vec![0u8; want];
                let mut filled = 0usize;
                while filled < want {
                    let n = timeout(self.read_timeout, self.reader.read(&mut buf[filled..]))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timed out"))?
                        .map_err(|e| io::Error::new(e.kind(), format!("read body: {e}")))?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "object body truncated",
                        ));
                    }
                    filled += n;
                }
                self.mode = BodyMode::Length(remaining - want as u64);
                Ok(Some(Bytes::from(buf)))
            }
            BodyMode::UntilEof => {
                let mut buf = vec![0u8; CHUNK_BYTES];
                let n = timeout(self.read_timeout, self.reader.read(&mut buf))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timed out"))?
                    .map_err(|e| io::Error::new(e.kind(), format!("read body: {e}")))?;
                if n == 0 {
                    Ok(None)
                } else {
                    buf.truncate(n);
                    Ok(Some(Bytes::from(buf)))
                }
            }
            BodyMode::Chunked => self.next_chunked().await,
        }
    }

    async fn next_chunked(&mut self) -> io::Result<Option<Bytes>> {
        let size = self.read_chunk_size().await?;
        if size == 0 {
            // Consume trailers up to the terminating empty line.
            loop {
                let line = self.read_line().await?;
                if line.is_empty() {
                    return Ok(None);
                }
            }
        }
        if size > MAX_CHUNK_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked chunk too large",
            ));
        }
        let mut buf = vec![0u8; size as usize];
        timeout(self.read_timeout, self.reader.read_exact(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read chunk timed out"))?
            .map_err(|e| io::Error::new(e.kind(), format!("read chunk: {e}")))?;
        let mut crlf = [0u8; 2];
        timeout(self.read_timeout, self.reader.read_exact(&mut crlf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read chunk crlf timed out"))?
            .map_err(|e| io::Error::new(e.kind(), format!("read chunk crlf: {e}")))?;
        if &crlf != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked framing: missing CRLF after chunk",
            ));
        }
        Ok(Some(Bytes::from(buf)))
    }

    async fn read_chunk_size(&mut self) -> io::Result<u64> {
        let line = self.read_line().await?;
        let size_hex = line.split(';').next().unwrap_or("").trim();
        u64::from_str_radix(size_hex, 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad chunk size line: {size_hex:?}"),
            )
        })
    }

    async fn read_line(&mut self) -> io::Result<String> {
        let mut line = Vec::new();
        let read = timeout(self.read_timeout, self.reader.read_until(b'\n', &mut line))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read chunk line timed out"))?
            .map_err(|e| io::Error::new(e.kind(), format!("read chunk line: {e}")))?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "chunked body ended early",
            ));
        }
        if line.len() > MAX_CHUNK_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk size line too long",
            ));
        }
        while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(String::from_utf8_lossy(&line).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    async fn collect_body(
        source: BodySource<Box<dyn AsyncRead + Unpin + Send>>,
    ) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut stream = Box::pin(source.into_stream());
        while let Some(item) = stream.next().await {
            out.extend_from_slice(&item?);
        }
        Ok(out)
    }

    async fn body_source(
        payload: &'static [u8],
        mode: BodyMode,
    ) -> BodySource<Box<dyn AsyncRead + Unpin + Send>> {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = server.write_all(payload).await;
            let _ = server.shutdown().await;
        });
        BodySource::new(
            BufReader::new(Box::new(client) as Box<dyn AsyncRead + Unpin + Send>),
            mode,
            Duration::from_secs(2),
        )
    }

    #[tokio::test]
    async fn chunked_body_is_decoded() {
        let src = body_source(
            b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
            BodyMode::Chunked,
        )
        .await;
        assert_eq!(collect_body(src).await.unwrap(), b"Wikipedia");
    }

    #[tokio::test]
    async fn chunked_trailers_are_skipped() {
        let src = body_source(
            b"3\r\nabc\r\n0\r\nX-Trace: 1\r\n\r\n",
            BodyMode::Chunked,
        )
        .await;
        assert_eq!(collect_body(src).await.unwrap(), b"abc");
    }

    #[tokio::test]
    async fn length_body_is_bounded() {
        let src = body_source(b"hello world", BodyMode::Length(5)).await;
        assert_eq!(collect_body(src).await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn truncated_length_body_errors() {
        let src = body_source(b"abc", BodyMode::Length(10)).await;
        assert!(collect_body(src).await.is_err());
    }

    #[tokio::test]
    async fn bad_chunk_size_errors() {
        let src = body_source(b"zz\r\nabc\r\n", BodyMode::Chunked).await;
        assert!(collect_body(src).await.is_err());
    }

    #[test]
    fn range_validation() {
        assert_eq!(validate_range("bytes=0-99").unwrap(), "bytes=0-99");
        assert_eq!(validate_range("bytes=100-").unwrap(), "bytes=100-");
        assert!(validate_range("bytes=0-1,3-4").is_err());
        assert!(validate_range("items=0-1").is_err());
        assert!(validate_range("bytes=0-1\r\nHost: x").is_err());
    }
}
