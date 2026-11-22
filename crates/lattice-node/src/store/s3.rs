//! MinIO presigning (AWS SigV4 query-string signing).
//!
//! Used by ⑤ §5.1 `part_urls` (upload) and §4.3 302 download redirects. TTL 900s, single use (§17.13).
//! Only signing happens here; actual object I/O is direct client-to-MinIO (zero copy, ② §3.2 large-object path).

use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::S3Cfg;

type HmacSha256 = Hmac<Sha256>;

/// SHA-256 of an empty body (`x-amz-content-sha256` required by S3 for bodyless requests).
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Clone)]
pub struct S3 {
    cfg: S3Cfg,
}

impl S3 {
    pub fn new(cfg: S3Cfg) -> Self {
        S3 { cfg }
    }

    pub fn cfg(&self) -> &S3Cfg {
        &self.cfg
    }

    /// Lightweight availability probe (② §4.8 "MinIO unavailable → server pauses chunk tasks").
    ///
    /// Only a TCP connect to the S3 endpoint (2s cap), no signing, no request: background maintenance tasks
    /// (multipart residue cleanup, recording segment GC, plugin object GC) use this probe to
    /// **short-circuit the round** when object storage is unavailable, avoiding one failed connection/retry wait per bucket each round;
    /// the next round continues automatically once object storage recovers (the tasks themselves are idempotent). Does not affect node ready / message plane.
    pub async fn probe(&self) -> std::result::Result<(), String> {
        let (host, port) = self.endpoint_host_port()?;
        let connect = tokio::net::TcpStream::connect((host.as_str(), port));
        match tokio::time::timeout(Duration::from_secs(2), connect).await {
            Ok(Ok(_stream)) => Ok(()),
            Ok(Err(e)) => Err(format!("connect {host}:{port}: {e}")),
            Err(_) => Err(format!("connect {host}:{port} timed out after 2s")),
        }
    }

    fn host(&self) -> String {
        strip_host(&self.cfg.endpoint)
    }

    /// Host that appears in presigned URLs: prefer `public_endpoint` (reachable from browsers/desktop clients), otherwise the intranet endpoint.
    fn public_host(&self) -> String {
        let public = self.cfg.public_endpoint.trim();
        if public.is_empty() {
            self.host()
        } else {
            strip_host(public)
        }
    }

    /// scheme + host + port base for presigned URLs (paired with `public_host`; never mix intranet and public halves).
    fn public_base(&self) -> String {
        let public = self.cfg.public_endpoint.trim();
        if public.is_empty() {
            self.cfg.endpoint.trim_end_matches('/').to_string()
        } else {
            public.trim_end_matches('/').to_string()
        }
    }

    /// `{yyyy}/{mm}/{dd}/{msg_id}/c{index}.bin` (⑥ §4.1 object layout).
    pub fn object_key(&self, msg_id: &str, index: u32) -> String {
        let now = chrono::Utc::now();
        format!(
            "{}/{}/{}/{}/c{}.bin",
            now.format("%Y"),
            now.format("%m"),
            now.format("%d"),
            msg_id,
            index
        )
    }

    pub fn upload_part_key(&self, upload_id: &str, part: u32) -> String {
        let now = chrono::Utc::now();
        format!(
            "uploads/{}/{}/{}/{}/part-{}",
            now.format("%Y"),
            now.format("%m"),
            now.format("%d"),
            upload_id,
            part
        )
    }

    /// Presigned PUT (upload chunk).
    pub fn presign_put(&self, key: &str, ttl_secs: u64) -> String {
        self.presign("PUT", &self.cfg.bucket_large, key, ttl_secs)
    }

    /// Presigned PUT (specific bucket): the plugin center writes package bodies into `lattice-plugins` (⑤ §12.4 / ⑥ §4.1).
    pub fn presign_put_in(&self, bucket: &str, key: &str, ttl_secs: u64) -> String {
        self.presign("PUT", bucket, key, ttl_secs)
    }

    /// Server-side direct object write (plugin package upload; kept fully in memory within the 20MiB cap, ② §4.9).
    ///
    /// Uses a **presigned URL** instead of recomputing SigV4: signing logic exists only in [`S3::presign`];
    /// if the direct-write path implemented its own header signing, the two would drift and produce "bucket created, object write 403".
    pub async fn put_bytes(&self, bucket: &str, key: &str, bytes: &[u8]) -> Result<(), String> {
        let url = self.internal_url("PUT", bucket, key, 300);
        let (host, port, path) = parse_http_url(&url)?;
        let resp = self.http_exchange(&host, port, &path, "PUT", bytes).await?;
        match resp.status {
            200 | 201 | 204 => Ok(()),
            code => Err(format!("PUT {bucket}/{key} -> HTTP {code}")),
        }
    }

    /// Server-side direct object read (existence/integrity checks before download, cleanup tasks).
    pub async fn get_bytes(&self, bucket: &str, key: &str) -> Result<Vec<u8>, String> {
        let url = self.internal_url("GET", bucket, key, 300);
        let (host, port, path) = parse_http_url(&url)?;
        let resp = self.http_exchange(&host, port, &path, "GET", &[]).await?;
        match resp.status {
            200 => Ok(resp.body),
            404 => Err(format!("GET {bucket}/{key} -> HTTP 404 (object not found)")),
            code => Err(format!("GET {bucket}/{key} -> HTTP {code}")),
        }
    }

    /// Delete an object (plugin center `removed` version reclamation, ⑥ §2.6). 404 is treated as already deleted (idempotent).
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), String> {
        let url = self.internal_url("DELETE", bucket, key, 300);
        let (host, port, path) = parse_http_url(&url)?;
        let resp = self.http_exchange(&host, port, &path, "DELETE", &[]).await?;
        match resp.status {
            200 | 202 | 204 | 404 => Ok(()),
            code => Err(format!("DELETE {bucket}/{key} -> HTTP {code}")),
        }
    }

    /// Minimal HTTP/1.1 client (plaintext, intranet MinIO only; TLS is terminated by the fronting proxy, same constraint as bucket creation).
    async fn http_exchange(
        &self,
        host: &str,
        port: u16,
        path: &str,
        method: &str,
        body: &[u8],
    ) -> Result<HttpResp, String> {
        self.http_exchange_headers(host, port, path, method, body, &[]).await
    }

    /// [`S3::http_exchange`] with extra request headers (E18: `Range` chunked sha256 verification of objects).
    ///
    /// The presigned URL has `SignedHeaders=host`; extra headers (e.g. `Range`) are not signed but S3 allows sending them;
    /// used only on the "server internally reads back a completed object" path.
    async fn http_exchange_headers(
        &self,
        host: &str,
        port: u16,
        path: &str,
        method: &str,
        body: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> Result<HttpResp, String> {
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (k, v) in extra_headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        let mut req = req.into_bytes();
        req.extend_from_slice(body);

        let fut = async {
            let mut stream = TcpStream::connect((host, port))
                .await
                .map_err(|e| format!("connect {host}:{port}: {e}"))?;
            stream
                .write_all(&req)
                .await
                .map_err(|e| format!("write: {e}"))?;
            let mut raw = Vec::new();
            stream
                .read_to_end(&mut raw)
                .await
                .map_err(|e| format!("read: {e}"))?;
            parse_http_response(&raw)
        };

        tokio::time::timeout(Duration::from_secs(30), fut)
            .await
            .map_err(|_| "s3 object request timeout after 30s".to_string())?
    }

    /// Presigned GET (download, the 302 target of ⑤ §4.3).
    pub fn presign_get(&self, bucket: &str, key: &str, ttl_secs: u64) -> String {
        self.presign("GET", bucket, key, ttl_secs)
    }

    // ------------------------------------------------------------------
    // Residual multipart cleanup (E04 / `lock:gc-multipart`, ⑥ §2.6 / ⑥ §4)
    // ------------------------------------------------------------------

    /// List **incomplete** multipart uploads in a bucket (`GET /{bucket}?uploads`, S3 ListMultipartUploads).
    ///
    /// - `prefix` optional (e.g. `uploads/` for the large-object bucket);
    /// - automatically pages by `key-marker`/`upload-id-marker`, at most `max_pages` pages (server cap
    ///   1000 per page; residual uploads are usually far below one page, paging only ensures "no silent missed deletions");
    /// - returns **incomplete uploads**; completed objects are not included — GC only aborts items in this list,
    ///   so it never deletes a completed object (the core E04 invariant).
    pub async fn list_multipart_uploads(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        max_pages: usize,
    ) -> Result<Vec<MultipartUpload>, String> {
        let mut out = Vec::new();
        let mut key_marker: Option<String> = None;
        let mut upload_marker: Option<String> = None;
        for _ in 0..max_pages.max(1) {
            let mut extra: Vec<(&str, &str)> = vec![("uploads", "")];
            if let Some(p) = prefix.map(str::trim).filter(|p| !p.is_empty()) {
                extra.push(("prefix", p));
            }
            if let Some(k) = key_marker.as_deref() {
                extra.push(("key-marker", k));
            }
            if let Some(u) = upload_marker.as_deref() {
                extra.push(("upload-id-marker", u));
            }
            let url = self.internal_url_with_query("GET", bucket, "", 300, &extra);
            let (host, port, path) = parse_http_url(&url)?;
            let resp = self.http_exchange(&host, port, &path, "GET", &[]).await?;
            if resp.status != 200 {
                return Err(format!("GET /{bucket}?uploads -> HTTP {}", resp.status));
            }
            let body = String::from_utf8_lossy(&resp.body);
            let page = parse_list_multipart_uploads(&body)?;
            out.extend(page.uploads);
            if !page.is_truncated {
                return Ok(out);
            }
            match (page.next_key_marker, page.next_upload_id_marker) {
                (Some(k), Some(u)) => {
                    key_marker = Some(k);
                    upload_marker = Some(u);
                }
                // Server declared truncation but omitted the marker: return what was collected to avoid an infinite loop.
                _ => return Ok(out),
            }
        }
        Ok(out)
    }

    /// Abort an incomplete multipart upload (`DELETE /{bucket}/{key}?uploadId=...`).
    ///
    /// Idempotent: 404 means another node/a previous round already cleaned it up; returns `Ok`. **Affects only incomplete uploads** —
    /// a completed object under the same key (produced by the last CompleteMultipartUpload) is unaffected.
    pub async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), String> {
        let url =
            self.internal_url_with_query("DELETE", bucket, key, 300, &[("uploadId", upload_id)]);
        let (host, port, path) = parse_http_url(&url)?;
        let resp = self.http_exchange(&host, port, &path, "DELETE", &[]).await?;
        match resp.status {
            200 | 202 | 204 | 404 => Ok(()),
            code => Err(format!(
                "DELETE /{bucket}/{key}?uploadId={upload_id} -> HTTP {code}"
            )),
        }
    }

    // ------------------------------------------------------------------
    // E18: real multipart (CreateMultipartUpload / presigned UploadPart / ListParts / Complete)
    // ------------------------------------------------------------------

    /// Start an S3 multipart upload (`POST /{bucket}/{key}?uploads`) → `uploadId`.
    ///
    /// The presigned `part_urls` from ⑤ §5.1 must belong to the **same multipart upload**, otherwise `complete`
    /// cannot use `CompleteMultipartUpload` to have object storage assemble the object server-side (a 4GB object cannot fit in node memory).
    pub async fn create_multipart_upload(&self, bucket: &str, key: &str) -> Result<String, String> {
        let url = self.internal_url_with_query("POST", bucket, key, 300, &[("uploads", "")]);
        let (host, port, path) = parse_http_url(&url)?;
        let resp = self.http_exchange(&host, port, &path, "POST", &[]).await?;
        if resp.status != 200 {
            return Err(format!(
                "POST /{bucket}/{key}?uploads -> HTTP {}: {}",
                resp.status,
                body_preview(&resp.body)
            ));
        }
        parse_create_multipart_upload(&String::from_utf8_lossy(&resp.body))
    }

    /// Presigned PUT URL for a single part (`partNumber`/`uploadId` participate in signing, TTL 900s, ⑤ §5.1).
    pub fn presign_upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part: u32,
        ttl_secs: u64,
    ) -> String {
        self.presign_owned(
            "PUT",
            bucket,
            key,
            ttl_secs,
            vec![
                ("partNumber".to_string(), part.to_string()),
                ("uploadId".to_string(), upload_id.to_string()),
            ],
            &self.public_host(),
            &self.public_base(),
        )
    }

    /// List completed parts of a multipart upload (`GET /{bucket}/{key}?uploadId=…`, S3 ListParts).
    ///
    /// This implements ⑤ §5.3 "authoritative facts live in MinIO": the completion progress of `GET /v1/uploads/{id}` and
    /// `reissue`'s "renew only incomplete parts" both rely on this method; the Redis session is only a cache.
    pub async fn list_parts(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<Vec<MultipartPart>, String> {
        let mut out = Vec::new();
        let mut marker: Option<u32> = None;
        for _ in 0..10 {
            let marker_str = marker.map(|m| m.to_string());
            let mut extra: Vec<(&str, &str)> = vec![("uploadId", upload_id)];
            if let Some(m) = marker_str.as_deref() {
                extra.push(("part-number-marker", m));
            }
            let url = self.internal_url_with_query("GET", bucket, key, 300, &extra);
            let (host, port, path) = parse_http_url(&url)?;
            let resp = self.http_exchange(&host, port, &path, "GET", &[]).await?;
            if resp.status != 200 {
                return Err(format!(
                    "GET /{bucket}/{key}?uploadId={upload_id} (list parts) -> HTTP {}: {}",
                    resp.status,
                    body_preview(&resp.body)
                ));
            }
            let (mut page, truncated, next) =
                parse_list_parts(&String::from_utf8_lossy(&resp.body))?;
            out.append(&mut page);
            match (truncated, next) {
                (true, Some(n)) => marker = Some(n),
                _ => return Ok(out),
            }
        }
        Ok(out)
    }

    /// Complete a multipart upload (`POST /{bucket}/{key}?uploadId=…` + `CompleteMultipartUpload` XML).
    ///
    /// Object storage **server-side** assembles the object from the part list (zero copy, no node memory); returns the server ETag.
    pub async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[(u32, String)],
    ) -> Result<String, String> {
        let body = complete_multipart_xml(parts);
        let url = self.internal_url_with_query("POST", bucket, key, 300, &[("uploadId", upload_id)]);
        let (host, port, path) = parse_http_url(&url)?;
        let resp = self
            .http_exchange(&host, port, &path, "POST", body.as_bytes())
            .await?;
        if resp.status != 200 {
            return Err(format!(
                "POST /{bucket}/{key}?uploadId={upload_id} (complete) -> HTTP {}: {}",
                resp.status,
                body_preview(&resp.body)
            ));
        }
        Ok(xml_tag(&String::from_utf8_lossy(&resp.body), "ETag").unwrap_or_default())
    }

    /// Overall sha256 of a completed object (read back in `Range` chunks, memory cap ≈ 8MiB per segment).
    ///
    /// Used by `/v1/uploads/{id}/complete` to verify the overall sha256 declared by the client (⑤ §5.2).
    /// A 4GB object cannot be read into memory at once, so read 8MiB `Range` segments; if the server does not support Range
    /// (returns 200 with the full body), accept only when the object is ≤64MiB, otherwise fail explicitly instead of OOM.
    /// Returns `(sha256, actual byte count)`; the caller compares the actual byte count against the declared size.
    pub async fn object_sha256(
        &self,
        bucket: &str,
        key: &str,
        expected_size: u64,
    ) -> Result<([u8; 32], u64), String> {
        const RANGE: u64 = 8 * 1024 * 1024;
        /// Maximum object size allowed when Range is ignored (200 full body); beyond this, report an error rather than OOM.
        const MAX_NON_RANGE: u64 = 64 * 1024 * 1024;
        let url = self.internal_url("GET", bucket, key, 300);
        let (host, port, path) = parse_http_url(&url)?;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut off = 0u64;
        loop {
            if expected_size > 0 && off >= expected_size {
                break;
            }
            let end = if expected_size == 0 {
                0
            } else {
                (off + RANGE - 1).min(expected_size - 1)
            };
            let range = format!("bytes={off}-{end}");
            let resp = self
                .http_exchange_headers(&host, port, &path, "GET", &[], &[("range", &range)])
                .await?;
            match resp.status {
                206 => {
                    if resp.body.is_empty() {
                        return Err(format!(
                            "GET {bucket}/{key} range {range} returned empty body (truncated object)"
                        ));
                    }
                    hasher.update(&resp.body);
                    total += resp.body.len() as u64;
                    off += resp.body.len() as u64;
                }
                200 => {
                    // Server ignored Range: only small objects can be read whole; large objects fail explicitly (no OOM).
                    if expected_size > MAX_NON_RANGE || resp.body.len() as u64 > MAX_NON_RANGE {
                        return Err(format!(
                            "GET {bucket}/{key} ignored Range for {} bytes; \
                             cannot verify whole-object sha256 under a 64MiB memory bound",
                            resp.body.len()
                        ));
                    }
                    hasher.update(&resp.body);
                    total += resp.body.len() as u64;
                    break;
                }
                404 => return Err(format!("GET {bucket}/{key} -> HTTP 404 (object not found)")),
                code => {
                    return Err(format!(
                        "GET {bucket}/{key} range {range} -> HTTP {code}: {}",
                        body_preview(&resp.body)
                    ))
                }
            }
        }
        let digest: [u8; 32] = hasher.finalize().into();
        Ok((digest, total))
    }

    /// Ensure the three buckets exist at startup (idempotent).
    ///
    /// Replaces the `minio-init` one-shot container in `deploy/compose/dev.yaml`: bucket creation
    /// returns to the party that actually uses the buckets (the node itself), removing one container and one startup dependency from deployment.
    /// Existing buckets are not recreated; conflicts are treated as success (`BucketAlreadyOwnedByYou`).
    pub async fn ensure_buckets(&self) -> Result<(), String> {
        for bucket in [
            &self.cfg.bucket_large,
            &self.cfg.bucket_media,
            &self.cfg.bucket_cold,
            &self.cfg.bucket_plugins,
        ] {
            if bucket.trim().is_empty() {
                continue;
            }
            match self.ensure_bucket(bucket).await {
                Ok(true) => tracing::info!(bucket, "s3 bucket created"),
                Ok(false) => tracing::debug!(bucket, "s3 bucket present"),
                Err(e) => return Err(format!("bucket {bucket}: {e}")),
            }
        }
        Ok(())
    }

    async fn ensure_bucket(&self, bucket: &str) -> Result<bool, String> {
        if self.bucket_request("HEAD", bucket).await? == 200 {
            return Ok(false);
        }
        match self.bucket_request("PUT", bucket).await? {
            200 | 201 | 204 | 409 => Ok(true),
            code => Err(format!("PUT /{bucket} -> HTTP {code}")),
        }
    }

    /// Send a minimal request to `/{bucket}` with retries; returns the HTTP status code.
    async fn bucket_request(&self, method: &str, bucket: &str) -> Result<u16, String> {
        let (host, port) = self.endpoint_host_port()?;
        let mut last = String::from("no attempt");
        for attempt in 0..3u32 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
            match self.raw_request(method, bucket, &host, port).await {
                Ok(code) => return Ok(code),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn endpoint_host_port(&self) -> Result<(String, u16), String> {
        let ep = self.cfg.endpoint.trim();
        if ep.starts_with("https://") {
            // Bucket creation uses plaintext HTTP; TLS is terminated by the fronting proxy (dev and production intranet alike).
            return Err("https endpoint not supported for bucket bootstrap".into());
        }
        let rest = ep.trim_start_matches("http://").trim_end_matches('/');
        match rest.rsplit_once(':') {
            Some((h, p)) => Ok((h.to_string(), p.parse().map_err(|_| "bad endpoint port")?)),
            None => Ok((rest.to_string(), 80)),
        }
    }

    async fn raw_request(
        &self,
        method: &str,
        bucket: &str,
        host: &str,
        port: u16,
    ) -> Result<u16, String> {
        let amz_date = chrono::Utc::now()
            .format("%Y%m%dT%H%M%SZ")
            .to_string();
        let canonical_uri = format!("/{bucket}");
        let auth = self.authorization(
            method,
            &canonical_uri,
            host,
            &amz_date,
            EMPTY_SHA256,
        );
        let mut req = format!(
            "{method} {canonical_uri} HTTP/1.1\r\n\
             Host: {host}\r\n\
             x-amz-date: {amz_date}\r\n\
             x-amz-content-sha256: {EMPTY_SHA256}\r\n\
             Authorization: {auth}\r\n"
        );
        if method == "PUT" {
            req.push_str("Content-Length: 0\r\n");
        }
        req.push_str("Connection: close\r\n\r\n");

        let fut = async {
            let mut stream = TcpStream::connect((host, port))
                .await
                .map_err(|e| format!("connect {host}:{port}: {e}"))?;
            stream
                .write_all(req.as_bytes())
                .await
                .map_err(|e| format!("write: {e}"))?;
            let mut buf = [0u8; 128];
            let n = stream
                .read(&mut buf)
                .await
                .map_err(|e| format!("read: {e}"))?;
            let head = String::from_utf8_lossy(&buf[..n]);
            let status = head
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse::<u16>().ok())
                .ok_or_else(|| format!("bad status line: {}", head.lines().next().unwrap_or("")))?;
            Ok::<u16, String>(status)
        };

        tokio::time::timeout(Duration::from_secs(3), fut)
            .await
            .map_err(|_| "timeout after 3s".to_string())?
    }

    /// SigV4 header signing (for bucket creation; object I/O uses `presign` query-string signing).
    fn authorization(
        &self,
        method: &str,
        canonical_uri: &str,
        host: &str,
        amz_date: &str,
        payload_hash: &str,
    ) -> String {
        let date = &amz_date[..8];
        let scope = format!("{date}/{}/s3/aws4_request", self.cfg.region);
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let canonical_headers = format!(
            "host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
        );
        let canonical_request = format!(
            "{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex(&Sha256::digest(canonical_request.as_bytes()))
        );

        let k_date = hmac(
            format!("AWS4{}", self.cfg.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let k_region = hmac(&k_date, self.cfg.region.as_bytes());
        let k_service = hmac(&k_region, b"s3");
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex(&hmac(&k_signing, string_to_sign.as_bytes()));

        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders={signed_headers},Signature={signature}",
            self.cfg.access_key
        )
    }

    fn presign(&self, method: &str, bucket: &str, key: &str, ttl_secs: u64) -> String {
        let host = self.public_host();
        let base = self.public_base();
        self.presign_at(method, bucket, key, ttl_secs, &host, &base)
    }

    /// Presigned URL for server-internal direct access: host and base are the intranet `endpoint`.
    ///
    /// Why not reuse [`S3::presign`]: `public_endpoint` is resolved by browsers/desktop clients
    /// (in deployment it may be `127.0.0.1:9000` or a public object-storage domain), and the node itself may not resolve it;
    /// the two must use their own hosts, but there is **only one signing algorithm** (`presign_at`).
    fn internal_url(&self, method: &str, bucket: &str, key: &str, ttl_secs: u64) -> String {
        self.internal_url_with_query(method, bucket, key, ttl_secs, &[])
    }

    /// [`S3::internal_url`] with extra query parameters (ListMultipartUploads / AbortMultipartUpload).
    fn internal_url_with_query(
        &self,
        method: &str,
        bucket: &str,
        key: &str,
        ttl_secs: u64,
        extra: &[(&str, &str)],
    ) -> String {
        let host = self.host();
        let base = self.cfg.endpoint.trim_end_matches('/').to_string();
        self.presign_with_query(method, bucket, key, ttl_secs, extra, &host, &base)
    }

    fn presign_at(
        &self,
        method: &str,
        bucket: &str,
        key: &str,
        ttl_secs: u64,
        host: &str,
        base: &str,
    ) -> String {
        self.presign_with_query(method, bucket, key, ttl_secs, &[], host, base)
    }

    /// Same as [`S3::presign_at`], but extra query parameters are passed as owned values (E18: partNumber/uploadId).
    fn presign_owned(
        &self,
        method: &str,
        bucket: &str,
        key: &str,
        ttl_secs: u64,
        extra: Vec<(String, String)>,
        host: &str,
        base: &str,
    ) -> String {
        let refs: Vec<(&str, &str)> = extra
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.presign_with_query(method, bucket, key, ttl_secs, &refs, host, base)
    }

    /// SigV4 query-string signing (single implementation; `extra` holds extra business query parameters, signed in key lexicographic order).
    ///
    /// An empty `key` means a bucket-level resource (`/{bucket}?uploads`); non-empty means an object-level resource.
    /// Empty-value parameters such as `uploads=` keep `=` in the canonical query (required by the S3 protocol), naturally
    /// produced by `encode("") == ""`.
    fn presign_with_query(
        &self,
        method: &str,
        bucket: &str,
        key: &str,
        ttl_secs: u64,
        extra: &[(&str, &str)],
        host: &str,
        base: &str,
    ) -> String {
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let scope = format!("{date}/{}/s3/aws4_request", self.cfg.region);
        let canonical_uri = if key.is_empty() {
            format!("/{bucket}")
        } else {
            format!("/{}/{}", bucket, encode_path(key))
        };

        let mut query: Vec<(String, String)> = vec![
            ("X-Amz-Algorithm".to_string(), "AWS4-HMAC-SHA256".to_string()),
            (
                "X-Amz-Credential".to_string(),
                format!("{}/{scope}", self.cfg.access_key),
            ),
            ("X-Amz-Date".to_string(), amz_date.clone()),
            ("X-Amz-Expires".to_string(), ttl_secs.to_string()),
            ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
        ];
        for (k, v) in extra {
            query.push((k.to_string(), v.to_string()));
        }
        // SigV4: canonical query must be sorted lexicographically by parameter name (before encoding).
        query.sort_by(|a, b| a.0.cmp(&b.0));
        let canonical_query = query
            .iter()
            .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let canonical_request = format!(
            "{method}\n{canonical_uri}\n{canonical_query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD"
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex(&Sha256::digest(canonical_request.as_bytes()))
        );

        let k_date = hmac(
            format!("AWS4{}", self.cfg.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let k_region = hmac(&k_date, self.cfg.region.as_bytes());
        let k_service = hmac(&k_region, b"s3");
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex(&hmac(&k_signing, string_to_sign.as_bytes()));

        format!(
            "{}/{canonical_uri}?{canonical_query}&X-Amz-Signature={signature}",
            base.trim_end_matches('/'),
            canonical_uri = canonical_uri.trim_start_matches('/')
        )
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// `http(s)://host[:port]/...` → `host[:port]` (the Host header in the signature).
fn strip_host(endpoint: &str) -> String {
    endpoint
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string()
}

// ---------------------------------------------------------------------------
// Residual multipart uploads (E04): minimal XML parsing for ListMultipartUploads
// ---------------------------------------------------------------------------

/// One incomplete multipart upload (an `<Upload>` item from `GET /{bucket}?uploads`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartUpload {
    /// Target object key (AbortMultipartUpload and later writes locate by it; no object exists during upload).
    pub key: String,
    /// `uploadId` (the query parameter for AbortMultipartUpload).
    pub upload_id: String,
    /// Initiation time returned by S3 (ISO8601, e.g. `2026-11-22T03:40:25.000Z`).
    pub initiated: String,
}

/// Parsed page of ListMultipartUploads (field names mirror S3 XML to ease paging).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MultipartUploadsPage {
    pub uploads: Vec<MultipartUpload>,
    pub is_truncated: bool,
    pub next_key_marker: Option<String>,
    pub next_upload_id_marker: Option<String>,
}

/// Parse S3 `ListMultipartUploads` XML (MinIO compatible).
///
/// No XML dependency: extract only the `Key`/`UploadId`/`Initiated` tags per `<Upload>` block,
/// with minimal XML entity unescaping (object keys may contain `&amp;` etc.). Returns an error on malformed input;
/// GC logs a WARN and retries next round — **never treat "cannot parse" as "no residue"**.
fn parse_list_multipart_uploads(xml: &str) -> Result<MultipartUploadsPage, String> {
    if !xml.contains("<ListMultipartUploadsResult") {
        return Err("not a ListMultipartUploads response".to_string());
    }
    let mut page = MultipartUploadsPage::default();
    let mut rest = xml;
    while let Some(start) = rest.find("<Upload>") {
        let after = &rest[start + "<Upload>".len()..];
        let end = after
            .find("</Upload>")
            .ok_or_else(|| "unterminated <Upload> element".to_string())?;
        let block = &after[..end];
        let key = xml_tag(block, "Key")
            .ok_or_else(|| "multipart <Upload> missing <Key>".to_string())?;
        let upload_id = xml_tag(block, "UploadId")
            .ok_or_else(|| "multipart <Upload> missing <UploadId>".to_string())?;
        let initiated = xml_tag(block, "Initiated").unwrap_or_default();
        page.uploads.push(MultipartUpload {
            key,
            upload_id,
            initiated,
        });
        rest = &after[end + "</Upload>".len()..];
    }
    page.is_truncated = xml_tag(xml, "IsTruncated")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    page.next_key_marker = xml_tag(xml, "NextKeyMarker").filter(|v| !v.is_empty());
    page.next_upload_id_marker = xml_tag(xml, "NextUploadIdMarker").filter(|v| !v.is_empty());
    Ok(page)
}

/// Return the text of the first `<tag>...</tag>` (None if absent).
fn xml_tag(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = block.find(&open)? + open.len();
    let end = block[start..].find(&close)? + start;
    Some(xml_unescape(&block[start..end]))
}

/// One uploaded multipart part (a `<Part>` item from S3 ListParts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartPart {
    /// 1-based part number (matches `partNumber`).
    pub part_number: u32,
    /// Server ETag (may be quoted; echoed back verbatim on Complete).
    pub etag: String,
    /// Object-storage byte size of this part.
    pub size: u64,
}

/// Parse `CreateMultipartUpload` XML → `uploadId`.
fn parse_create_multipart_upload(xml: &str) -> Result<String, String> {
    if !xml.contains("<InitiateMultipartUploadResult") {
        return Err(format!(
            "not a CreateMultipartUpload response: {}",
            body_preview(xml.as_bytes())
        ));
    }
    xml_tag(xml, "UploadId")
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "CreateMultipartUpload response missing <UploadId>".to_string())
}

/// Parse one page of `ListParts` XML (MinIO/S3 compatible) → `(parts, is_truncated, next_part_number_marker)`.
fn parse_list_parts(xml: &str) -> Result<(Vec<MultipartPart>, bool, Option<u32>), String> {
    if !xml.contains("<ListPartsResult") {
        return Err(format!(
            "not a ListParts response: {}",
            body_preview(xml.as_bytes())
        ));
    }
    let mut parts = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Part>") {
        let after = &rest[start + "<Part>".len()..];
        let end = after
            .find("</Part>")
            .ok_or_else(|| "unterminated <Part> element".to_string())?;
        let block = &after[..end];
        let part_number: u32 = xml_tag(block, "PartNumber")
            .ok_or_else(|| "ListParts <Part> missing <PartNumber>".to_string())?
            .parse()
            .map_err(|_| "ListParts <PartNumber> not an integer".to_string())?;
        let etag = xml_tag(block, "ETag").unwrap_or_default();
        let size = xml_tag(block, "Size")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        parts.push(MultipartPart { part_number, etag, size });
        rest = &after[end + "</Part>".len()..];
    }
    let truncated = xml_tag(xml, "IsTruncated")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let next = xml_tag(xml, "NextPartNumberMarker").and_then(|v| v.trim().parse::<u32>().ok());
    Ok((parts, truncated, next))
}

/// Build the `CompleteMultipartUpload` request body (parts must be strictly ascending; ETags echoed verbatim).
fn complete_multipart_xml(parts: &[(u32, String)]) -> String {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (n, etag) in parts {
        xml.push_str(&format!(
            "<Part><PartNumber>{n}</PartNumber><ETag>{}</ETag></Part>",
            xml_escape(etag.trim())
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    xml
}

/// XML text escaping (ETags usually contain only hex and quotes; still escape the minimal safety set).
fn xml_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// Error response body preview (at most 200 chars, so logs/errors cannot grow without bound).
fn body_preview(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let truncated: String = text.chars().take(200).collect();
    if text.chars().count() > 200 {
        format!("{truncated}…")
    } else {
        truncated
    }
}

/// Minimal XML text unescaping (`Key` may contain entities; numeric entities handled too).
fn xml_unescape(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let Some(semi) = tail.find(';') else {
            out.push_str(tail);
            return out;
        };
        let entity = &tail[1..semi];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => {
                if let Some(hex) = entity.strip_prefix("#x").or_else(|| entity.strip_prefix("#X")) {
                    u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                } else if let Some(dec) = entity.strip_prefix('#') {
                    dec.parse::<u32>().ok().and_then(char::from_u32)
                } else {
                    None
                }
            }
        };
        match decoded {
            Some(c) => out.push(c),
            // Unknown entity: keep as-is (never silently swallow key content)
            None => out.push_str(&tail[..=semi]),
        }
        rest = &tail[semi + 1..];
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// Minimal HTTP client (internal object I/O only; plaintext + `Connection: close`)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct HttpResp {
    status: u16,
    body: Vec<u8>,
}

/// `http://host[:port]/path?query` → `(host, port, "/path?query")`.
///
/// Explicitly supports only `http://`: same constraint as [`S3::endpoint_host_port`] (TLS is terminated by the fronting proxy);
/// on `https://` it must error rather than silently downgrade to plaintext.
fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// endpoints are supported for object IO: {url}"))?;
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| "bad endpoint port".to_string())?,
        ),
        None => (host_port.to_string(), 80),
    };
    if host.is_empty() {
        return Err("empty endpoint host".into());
    }
    Ok((host, port, path.to_string()))
}

fn parse_http_response(raw: &[u8]) -> Result<HttpResp, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "bad http response: no header terminator".to_string())?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("bad status line: {}", head.lines().next().unwrap_or("")))?;

    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
                "content-length" => content_length = v.trim().parse::<usize>().ok(),
                _ => {}
            }
        }
    }

    let rest = &raw[split + 4..];
    let body = if chunked {
        decode_chunked(rest)?
    } else if let Some(n) = content_length {
        rest[..rest.len().min(n)].to_vec()
    } else {
        rest.to_vec()
    };
    Ok(HttpResp { status, body })
}

/// `Transfer-Encoding: chunked` decoding (large MinIO downloads may use chunked).
fn decode_chunked(mut raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let eol = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "bad chunked body: missing size line".to_string())?;
        let size_line = String::from_utf8_lossy(&raw[..eol]);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("bad chunk size: {size_hex}"))?;
        raw = &raw[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if raw.len() < size + 2 {
            return Err("bad chunked body: truncated".into());
        }
        out.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..]; // skip the CRLF after the data
    }
}

fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// RFC 3986 encoding (path segments keep only `/` and unreserved).
fn encode_path(path: &str) -> String {
    path.split('/')
        .map(encode)
        .collect::<Vec<_>>()
        .join("/")
}

fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s3() -> S3 {
        S3::new(S3Cfg {
            endpoint: "http://minio:9000".into(),
            region: "us-east-1".into(),
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            ..Default::default()
        })
    }

    #[test]
    fn presign_contains_required_params() {
        let url = s3().presign_put("2025/07/01/01JABC/c0.bin", 900);
        assert!(url.starts_with("http://minio:9000/lattice-large/2025/07/01/01JABC/c0.bin?"));
        for p in [
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            "X-Amz-Expires=900",
            "X-Amz-SignedHeaders=host",
            "X-Amz-Signature=",
        ] {
            assert!(url.contains(p), "missing {p} in {url}");
        }
    }

    #[test]
    fn object_key_layout_matches_doc() {
        let k = s3().object_key("01JABC", 2);
        assert!(k.ends_with("/01JABC/c2.bin"));
        assert_eq!(k.matches('/').count(), 4);
    }

    #[test]
    fn signature_differs_by_method_and_key() {
        let s = s3();
        let a = s.presign_get("lattice-large", "a/b.bin", 900);
        let b = s.presign_put("a/b.bin", 900);
        assert_ne!(a, b);
    }

    #[test]
    fn authorization_header_is_well_formed() {
        let s = s3();
        let auth = s.authorization(
            "PUT",
            "/lattice-large",
            "minio:9000",
            "20250701T000000Z",
            EMPTY_SHA256,
        );
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20250701/"));
        assert!(auth.contains("/us-east-1/s3/aws4_request"));
        assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        // signature is 64 lowercase hex chars
        let sig = auth.rsplit("Signature=").next().unwrap();
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        // identical input must produce an identical signature (deterministic, otherwise MinIO verification fails)
        let again = s.authorization(
            "PUT",
            "/lattice-large",
            "minio:9000",
            "20250701T000000Z",
            EMPTY_SHA256,
        );
        assert_eq!(auth, again);
    }

    #[test]
    fn endpoint_host_port_parsing() {
        let s = s3();
        assert_eq!(
            s.endpoint_host_port().unwrap(),
            ("minio".to_string(), 9000)
        );

        let no_port = S3::new(S3Cfg {
            endpoint: "http://127.0.0.1".into(),
            ..Default::default()
        });
        assert_eq!(
            no_port.endpoint_host_port().unwrap(),
            ("127.0.0.1".to_string(), 80)
        );

        // https is explicitly unsupported for bucket creation (TLS is terminated by the fronting proxy); must error, not fail silently
        let tls = S3::new(S3Cfg {
            endpoint: "https://s3.example.com".into(),
            ..Default::default()
        });
        assert!(tls.endpoint_host_port().is_err());
    }

    #[test]
    fn public_endpoint_only_changes_presign_host() {
        let s = S3::new(S3Cfg {
            endpoint: "http://minio:9000".into(),
            public_endpoint: "http://127.0.0.1:9000".into(),
            ..Default::default()
        });
        let public = s.presign_get("lattice-plugins", "a/1.0.0/a.zip", 900);
        assert!(public.starts_with("http://127.0.0.1:9000/lattice-plugins/a/1.0.0/a.zip?"));
        let internal = s.internal_url("GET", "lattice-plugins", "a/1.0.0/a.zip", 900);
        assert!(internal.starts_with("http://minio:9000/lattice-plugins/a/1.0.0/a.zip?"));
        // Only the host differs; signature parameters stay the same (the signature covers Host, so the two must differ)
        let psig = public.rsplit("X-Amz-Signature=").next().unwrap();
        let isig = internal.rsplit("X-Amz-Signature=").next().unwrap();
        assert_ne!(psig, isig);
        // empty public_endpoint falls back to the intranet endpoint
        let fallback = S3::new(S3Cfg {
            endpoint: "http://minio:9000".into(),
            ..Default::default()
        });
        assert!(fallback
            .presign_get("lattice-plugins", "a.zip", 900)
            .starts_with("http://minio:9000/"));
    }

    #[test]
    fn presign_url_parsing() {
        let (host, port, path) = parse_http_url(
            "http://minio:9000/lattice-plugins/task-planner/1.4.2/a.zip?X-Amz-Signature=ab",
        )
        .unwrap();
        assert_eq!(host, "minio");
        assert_eq!(port, 9000);
        assert!(path.starts_with("/lattice-plugins/task-planner/1.4.2/a.zip?"));
        assert!(parse_http_url("https://minio:9000/x").is_err());
        assert_eq!(parse_http_url("http://127.0.0.1/b").unwrap(), ("127.0.0.1".into(), 80, "/b".into()));
    }

    #[test]
    fn response_parsing_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        let r = parse_http_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello");
    }

    #[test]
    fn response_parsing_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let r = parse_http_response(raw).unwrap();
        assert_eq!(r.body, b"hello");
    }

    #[test]
    fn response_marks_404() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse_http_response(raw).unwrap().status, 404);
    }

    // ---- E04: residual multipart cleanup (ListMultipartUploads / AbortMultipartUpload)----

    #[test]
    fn presign_includes_multipart_query_params() {
        // ListMultipartUploads: bucket-level resource + empty `uploads=` parameter + prefix must be signed.
        let url = s3().internal_url_with_query(
            "GET",
            "lattice-large",
            "",
            300,
            &[("uploads", ""), ("prefix", "uploads/")],
        );
        assert!(url.starts_with("http://minio:9000/lattice-large?"));
        assert!(url.contains("uploads="), "{url}");
        assert!(url.contains("prefix=uploads%2F"), "{url}");
        // An empty key must not produce an invalid path like `/{bucket}//`
        assert!(!url.contains("lattice-large//"), "{url}");

        // AbortMultipartUpload: object-level resource + uploadId query parameter.
        let abort = s3().internal_url_with_query(
            "DELETE",
            "lattice-large",
            "uploads/2026/11/22/u1/part-0",
            300,
            &[("uploadId", "up-123/_x")],
        );
        assert!(abort.contains("/lattice-large/uploads/2026/11/22/u1/part-0?"));
        assert!(abort.contains("uploadId=up-123%2F_x"), "{abort}");

        // canonical query must be lexicographic (uppercase X-Amz-* before lowercase business parameters)
        let q = url.split('?').nth(1).unwrap();
        let x = q.find("X-Amz-Algorithm=").unwrap();
        let prefix = q.find("prefix=").unwrap();
        assert!(x < prefix, "canonical query not sorted: {q}");
    }

    #[test]
    fn list_multipart_uploads_xml_parses_uploads_and_paging() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>lattice-large</Bucket>
  <IsTruncated>true</IsTruncated>
  <NextKeyMarker>uploads/a&amp;b/part-0</NextKeyMarker>
  <NextUploadIdMarker>up-2</NextUploadIdMarker>
  <Upload>
    <Key>uploads/a&amp;b/part-0</Key>
    <UploadId>up-1</UploadId>
    <Initiated>2026-11-22T03:40:25.000Z</Initiated>
  </Upload>
  <Upload>
    <Key>uploads/c</Key>
    <UploadId>up-2</UploadId>
    <Initiated>2026-11-22T04:00:00.000Z</Initiated>
  </Upload>
</ListMultipartUploadsResult>"#;
        let page = parse_list_multipart_uploads(xml).unwrap();
        assert_eq!(page.uploads.len(), 2);
        assert_eq!(page.uploads[0].key, "uploads/a&b/part-0");
        assert_eq!(page.uploads[0].upload_id, "up-1");
        assert_eq!(page.uploads[0].initiated, "2026-11-22T03:40:25.000Z");
        assert_eq!(page.uploads[1].key, "uploads/c");
        assert!(page.is_truncated);
        assert_eq!(page.next_key_marker.as_deref(), Some("uploads/a&b/part-0"));
        assert_eq!(page.next_upload_id_marker.as_deref(), Some("up-2"));
    }

    #[test]
    fn list_multipart_uploads_xml_empty_and_invalid() {
        let empty = r#"<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>"#;
        let page = parse_list_multipart_uploads(empty).unwrap();
        assert!(page.uploads.is_empty());
        assert!(!page.is_truncated);
        assert!(page.next_key_marker.is_none());
        // Non-ListMultipartUploads responses (e.g. XML error bodies) must error rather than report "zero residue"
        assert!(parse_list_multipart_uploads("<Error><Code>AccessDenied</Code></Error>").is_err());
        // A truncated <Upload> also errors (cannot drop silently; retry next round)
        assert!(parse_list_multipart_uploads("<ListMultipartUploadsResult><Upload><Key>k</Key>").is_err());
    }

    #[test]
    fn xml_unescape_handles_entities() {
        assert_eq!(xml_unescape("a&amp;b&lt;c&gt;d&quot;e&apos;f"), "a&b<c>d\"e'f");
        assert_eq!(xml_unescape("x&#65;y&#x42;z"), "xAyBz");
        assert_eq!(xml_unescape("no-entities"), "no-entities");
        assert_eq!(xml_unescape("bad&unknown;entity"), "bad&unknown;entity");
    }

    // ---- E18: real multipart (Create / presigned UploadPart / ListParts / Complete)----

    #[test]
    fn presign_upload_part_carries_multipart_query_params() {
        let s = s3();
        let url = s.presign_upload_part("lattice-large", "2026/11/22/01JABC/c0.bin", "up-123", 2, 900);
        assert!(url.starts_with("http://minio:9000/lattice-large/2026/11/22/01JABC/c0.bin?"), "{url}");
        assert!(url.contains("partNumber=2"), "{url}");
        assert!(url.contains("uploadId=up-123"), "{url}");
        assert!(url.contains("X-Amz-Expires=900"), "{url}");
        assert!(url.contains("X-Amz-Signature="), "{url}");
        // canonical query lexicographic: uppercase X-Amz-* before lowercase business parameters
        let q = url.split('?').nth(1).unwrap();
        assert!(
            q.find("X-Amz-Algorithm=").unwrap() < q.find("partNumber=").unwrap(),
            "canonical query not sorted: {q}"
        );
        // Signatures for different parts must differ (partNumber participates in signing)
        let other = s.presign_upload_part("lattice-large", "2026/11/22/01JABC/c0.bin", "up-123", 1, 900);
        assert_ne!(
            url.rsplit("X-Amz-Signature=").next().unwrap(),
            other.rsplit("X-Amz-Signature=").next().unwrap()
        );
    }

    #[test]
    fn presign_upload_part_uses_public_endpoint() {
        let s = S3::new(S3Cfg {
            endpoint: "http://minio:9000".into(),
            public_endpoint: "http://127.0.0.1:9000".into(),
            ..Default::default()
        });
        let url = s.presign_upload_part("lattice-large", "a/c0.bin", "up-1", 1, 900);
        assert!(url.starts_with("http://127.0.0.1:9000/lattice-large/a/c0.bin?"), "{url}");
    }

    #[test]
    fn create_multipart_upload_xml_parses_upload_id() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>lattice-large</Bucket><Key>a/c0.bin</Key><UploadId>up-abc-123</UploadId>
</InitiateMultipartUploadResult>"#;
        assert_eq!(parse_create_multipart_upload(xml).unwrap(), "up-abc-123");
        assert!(parse_create_multipart_upload("<Error><Code>AccessDenied</Code></Error>").is_err());
        assert!(parse_create_multipart_upload("<InitiateMultipartUploadResult></InitiateMultipartUploadResult>").is_err());
    }

    #[test]
    fn list_parts_xml_parses_parts_and_paging() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>lattice-large</Bucket><Key>a/c0.bin</Key><UploadId>up-1</UploadId>
  <IsTruncated>true</IsTruncated><NextPartNumberMarker>2</NextPartNumberMarker>
  <Part><PartNumber>1</PartNumber><ETag>&quot;e1&quot;</ETag><Size>8388608</Size></Part>
  <Part><PartNumber>2</PartNumber><ETag>"e2"</ETag><Size>1024</Size></Part>
</ListPartsResult>"#;
        let (parts, truncated, next) = parse_list_parts(xml).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].part_number, 1);
        assert_eq!(parts[0].etag, "\"e1\"");
        assert_eq!(parts[0].size, 8_388_608);
        assert_eq!(parts[1].etag, "\"e2\"");
        assert!(truncated);
        assert_eq!(next, Some(2));
        // Empty list / malformed response
        let empty = parse_list_parts("<ListPartsResult><IsTruncated>false</IsTruncated></ListPartsResult>").unwrap();
        assert!(empty.0.is_empty() && !empty.1 && empty.2.is_none());
        assert!(parse_list_parts("<Error><Code>NoSuchUpload</Code></Error>").is_err());
    }

    #[test]
    fn complete_multipart_xml_parts_and_escaping() {
        let xml = complete_multipart_xml(&[
            (1, "\"etag-1\"".to_string()),
            (2, "a&b<c>".to_string()),
        ]);
        assert!(xml.starts_with("<CompleteMultipartUpload><Part>"), "{xml}");
        assert!(xml.contains("<PartNumber>1</PartNumber><ETag>\"etag-1\"</ETag>"), "{xml}");
        assert!(xml.contains("<PartNumber>2</PartNumber><ETag>a&amp;b&lt;c&gt;</ETag>"), "{xml}");
        assert!(xml.ends_with("</CompleteMultipartUpload>"));
        // Ascending order preserved (guaranteed by the caller; this only verifies serialization keeps order)
        let p1 = xml.find("<PartNumber>1</PartNumber>").unwrap();
        let p2 = xml.find("<PartNumber>2</PartNumber>").unwrap();
        assert!(p1 < p2);
    }

    #[test]
    fn list_parts_internal_url_signs_upload_id() {
        let url = s3().internal_url_with_query(
            "GET",
            "lattice-large",
            "2026/11/22/01JABC/c0.bin",
            300,
            &[("uploadId", "up-1"), ("part-number-marker", "2")],
        );
        assert!(url.starts_with("http://minio:9000/lattice-large/2026/11/22/01JABC/c0.bin?"), "{url}");
        assert!(url.contains("uploadId=up-1"), "{url}");
        assert!(url.contains("part-number-marker=2"), "{url}");
    }
}
