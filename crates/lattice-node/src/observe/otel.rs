//! OpenTelemetry OTLP/gRPC trace export (REMAINING E22 / PL-14 task 14.4).
//!
//! Design stance (matches the task card):
//! - **Feature `otel` off by default**: when off, this whole file is a no-op placeholder (no opentelemetry
//!   dependencies compiled, `observe/mod.rs` registers no layer, the `main.rs` HTTP middleware is a pure passthrough,
//!   `state.rs`/`pipeline` span helpers are zero-cost), so node behavior matches the pre-OTel build.
//! - **When enabled**: a global `TracerProvider` + OTLP/gRPC exporter (tonic, the version already in the repo)
//!   wired to the `tracing-subscriber` `tracing-opentelemetry` layer — tracing spans
//!   become OTel spans automatically (HTTP request / pipeline ingest / WS-topic delivery, three stages).
//! - **Sampling**: to honor "100% of errors sampled", the SDK records with `AlwaysOn` and the **export side** applies
//!   deterministic ratio filtering by `trace_id`; error spans (status=ERROR / `lattice.error*` /
//!   ERROR-level events) force the whole trace to be kept. Tradeoff: a little recording cost for deterministic error capture;
//!   production can switch to collector-side tail sampling (see "Boundaries not implemented").
//! - **Never blocks**: exporter build failures and unreachable collectors only WARN; startup and the message path are unaffected.
//! - **Sensitive content**: only **metadata** attributes are written (envelope_id/conv_id/seq/route/status/low-cardinality hash);
//!   payloads, plaintext tokens, Authorization/body and the like never reach spans; a key-redaction fallback also runs before export.
//!
//! ## Environment variables (the only config entry; `config.rs` untouched to avoid conflicts with parallel tasks)
//!
//! | Variable | Default | Description |
//! | --- | --- | --- |
//! | `LATTICE_OTEL_ENABLED` | `false` | only `1/true/on` registers the global tracer and layer (off = no behavior) |
//! | `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` / `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://127.0.0.1:4317` | OTLP/gRPC endpoint |
//! | `LATTICE_OTEL_SAMPLER` | `ratio` | `ratio` / `always_on` / `always_off` |
//! | `LATTICE_OTEL_SAMPLER_RATIO` | `0.1` | design §12 default 10%; `0..=1`, out of range is clamped |
//! | `LATTICE_OTEL_TIMEOUT_MS` | `3000` | timeout per export |
//! | `OTEL_SERVICE_NAME` / `LATTICE_OTEL_SERVICE_NAME` | `lattice-node` | resource `service.name` |
//! | `OTEL_BSP_*` | SDK default | batch queue/delay (`OTEL_BSP_SCHEDULE_DELAY` etc. are read by the SDK) |
//!
//! ## Boundaries not implemented (stated as-is)
//! - Outbound W3C `traceparent` injection: the node has no outbound HTTP client call chain today, so it is omitted;
//!   inbound `traceparent` is supported (middleware extracts then `set_parent`), enabling cross-service correlation.
//! - Alerting "real notification" channels (Alertmanager webhook) are out of scope: `scripts/observe-e2e.mjs` uses the rule-file
//!   structure + eval on given samples + a local state machine to exercise "trigger→notify→recover".

#[cfg(not(feature = "otel"))]
use lattice_core::{Envelope, Frame};

/// Generic span handle (ends and exports on drop). Zero-sized placeholder without the `otel` feature.
pub struct OtelSpan {
    /// RAII only: holds the span; Drop ends and exports it (for stages like route.resolve with no result fields).
    #[cfg(feature = "otel")]
    #[allow(dead_code)]
    span: Option<tracing::Span>,
}

/// Span handle for the pipeline ingest stage.
pub struct IngestSpan {
    #[cfg(feature = "otel")]
    span: Option<tracing::Span>,
}

/// Span handle for the delivery stage.
pub struct DeliverSpan {
    #[cfg(feature = "otel")]
    span: Option<tracing::Span>,
}

/// Correlation fields extracted from a WS downstream frame (span attributes only, never business logic).
#[derive(Debug, Clone, Default)]
pub struct FrameAttrs {
    pub cmd: String,
    pub envelope_id: Option<String>,
    pub conv_id: Option<String>,
    pub seq: Option<u64>,
}

impl FrameAttrs {
    pub fn new(cmd: &str) -> Self {
        Self {
            cmd: cmd.to_string(),
            ..Default::default()
        }
    }
}

// ===========================================================================
// Non-otel feature: everything is a no-op (call sites carry no cfg, default build has zero behavior)
// ===========================================================================

/// Whether OTel is enabled (compile-time feature + runtime `LATTICE_OTEL_ENABLED` both satisfied).
#[cfg(not(feature = "otel"))]
#[inline]
pub fn enabled() -> bool {
    false
}

#[cfg(not(feature = "otel"))]
pub fn init(_node_id: &str) -> bool {
    false
}

#[cfg(not(feature = "otel"))]
pub fn layer_info() -> Option<(&'static str, &'static str, &'static str)> {
    None
}

#[cfg(not(feature = "otel"))]
pub fn shutdown() {}

#[cfg(not(feature = "otel"))]
pub async fn http_trace_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    next.run(req).await
}

#[cfg(not(feature = "otel"))]
pub fn ingest_span(_env: &Envelope) -> IngestSpan {
    IngestSpan {}
}

#[cfg(not(feature = "otel"))]
pub fn finish_ingest(_span: IngestSpan, _seq: u64, _state: &str, _duplicate: bool) {}

#[cfg(not(feature = "otel"))]
pub fn deliver_span(_stage: &'static str, _frame: &Frame, _target: Option<&str>) -> DeliverSpan {
    DeliverSpan {}
}

#[cfg(not(feature = "otel"))]
pub fn finish_deliver(_span: DeliverSpan, _delivered: usize) {}

#[cfg(not(feature = "otel"))]
pub fn route_resolve_span(_target_user: &str) -> OtelSpan {
    OtelSpan {}
}

#[cfg(not(feature = "otel"))]
pub fn record_error(_operation: &'static str, _code: &str) {}

#[cfg(not(feature = "otel"))]
pub fn frame_attrs(frame: &Frame) -> FrameAttrs {
    FrameAttrs::new(frame.cmd.as_str())
}

// ===========================================================================
// feature = "otel": the real implementation
// ===========================================================================

#[cfg(feature = "otel")]
mod imp {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;

    use futures::future::BoxFuture;
    use opentelemetry::global;
    use opentelemetry::propagation::{Extractor, TextMapPropagator as _};
    use opentelemetry::trace::{
        SamplingDecision, SpanKind, Status, TraceContextExt, TraceId, TracerProvider as _,
    };
    use opentelemetry::{Context, KeyValue};
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::export::trace::{ExportResult, SpanData, SpanExporter};
    use opentelemetry_sdk::trace::{
        BatchSpanProcessor, ShouldSample as _, TracerProvider,
    };
    use opentelemetry_sdk::{runtime, Resource};
    use tracing::Instrument;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    use lattice_core::{Envelope, Frame};

    use super::{DeliverSpan, FrameAttrs, IngestSpan, OtelSpan};

    const TRACER_NAME: &str = "lattice-node";
    const ERROR_SPAN_PREFIX: &str = "lattice.error";
    const MAX_DECISIONS: usize = 8192;
    const MAX_ATTR_STR_CHARS: usize = 256;
    const DENY_ATTR_SUBSTRINGS: [&str; 10] = [
        "payload",
        "token",
        "authorization",
        "password",
        "secret",
        "cookie",
        "refresh",
        "access_jwt",
        "request_body",
        "body_bytes",
    ];

    static ENABLED: AtomicBool = AtomicBool::new(false);
    static PROVIDER: OnceLock<TracerProvider> = OnceLock::new();
    static INFO: OnceLock<OtelInfo> = OnceLock::new();

    /// Whether OTel is enabled (compile-time feature + runtime `LATTICE_OTEL_ENABLED` both satisfied).
    pub fn enabled() -> bool {
        ENABLED.load(Ordering::Acquire)
    }

    struct OtelInfo {
        service: &'static str,
        endpoint: &'static str,
        sampler: &'static str,
    }

    /// Sampling config (export-side filtering; see the file header).
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub(super) struct SamplerCfg {
        pub ratio: f64,
        pub mode: SamplerMode,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum SamplerMode {
        Ratio,
        AlwaysOn,
        AlwaysOff,
    }

    impl SamplerCfg {
        pub fn from_env() -> Self {
            let mode = match std::env::var("LATTICE_OTEL_SAMPLER")
                .unwrap_or_else(|_| "ratio".into())
                .trim()
                .to_ascii_lowercase()
                .as_str()
            {
                "always_on" | "alwayson" | "on" => SamplerMode::AlwaysOn,
                "always_off" | "alwaysoff" | "off" => SamplerMode::AlwaysOff,
                _ => SamplerMode::Ratio,
            };
            let ratio = std::env::var("LATTICE_OTEL_SAMPLER_RATIO")
                .ok()
                .and_then(|s| s.trim().parse::<f64>().ok())
                .unwrap_or(0.1)
                .clamp(0.0, 1.0);
            Self { ratio, mode }
        }

        pub fn description(&self) -> &'static str {
            match self.mode {
                SamplerMode::AlwaysOn => "always_on",
                SamplerMode::AlwaysOff => "always_off",
                SamplerMode::Ratio => "ratio",
            }
        }

        /// Whether **non-error** spans of this trace are kept (deterministic: same trace_id, same verdict).
        pub fn keep_trace(&self, trace_id: TraceId) -> bool {
            match self.mode {
                SamplerMode::AlwaysOn => true,
                SamplerMode::AlwaysOff => false,
                SamplerMode::Ratio => {
                    let sampler = opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(self.ratio);
                    matches!(
                        sampler
                            .should_sample(
                                None,
                                trace_id,
                                "lattice",
                                &SpanKind::Internal,
                                &[],
                                &[],
                            )
                            .decision,
                        SamplingDecision::RecordAndSample
                    )
                }
            }
        }
    }

    #[inline]
    fn is_error_span(span: &SpanData) -> bool {
        if span.name.starts_with(ERROR_SPAN_PREFIX) {
            return true;
        }
        if matches!(span.status, Status::Error { .. }) {
            return true;
        }
        span.events.iter().any(|e| {
            e.name.starts_with(ERROR_SPAN_PREFIX)
                || e.attributes.iter().any(|kv| {
                    kv.key.as_str() == "level"
                        && matches!(&kv.value, opentelemetry::Value::String(s) if s.as_str() == "ERROR")
                })
        })
    }

    /// Attribute key redaction: sensitive keys such as payload/token/request body are never exported (defense in depth; call sites never write them anyway).
    fn sanitize_attributes(span: &mut SpanData) {
        span.attributes.retain(|kv| {
            let key = kv.key.as_str().to_ascii_lowercase();
            key != "lattice.trace_id"
                && !DENY_ATTR_SUBSTRINGS
                    .iter()
                    .any(|deny| key.contains(deny))
        });
        for kv in &mut span.attributes {
            if let opentelemetry::Value::String(s) = &mut kv.value {
                let v = s.as_str();
                if v.chars().count() > MAX_ATTR_STR_CHARS {
                    *s = v.chars().take(MAX_ATTR_STR_CHARS).collect::<String>().into();
                }
            }
        }
        // Correlation fields: carry trace_id explicitly as a hex string so E2E/collection can assert three-stream correlation.
        span.attributes.push(KeyValue::new(
            "lattice.trace_id",
            format!("{:032x}", span.span_context.trace_id()),
        ));
    }

    /// Bounded trace decision cache (same verdict for spans of one trace across batches).
    #[derive(Debug)]
    struct Decisions {
        map: std::collections::HashMap<[u8; 16], bool>,
    }

    impl Decisions {
        fn new() -> Self {
            Self {
                map: std::collections::HashMap::new(),
            }
        }
        fn get(&self, key: &[u8; 16]) -> Option<bool> {
            self.map.get(key).copied()
        }
        fn insert(&mut self, key: [u8; 16], keep: bool) {
            if self.map.len() >= MAX_DECISIONS {
                self.map.clear();
            }
            self.map.insert(key, keep);
        }
    }

    /// Export-side sampling exporter: wraps the OTLP exporter and handles
    /// ① attribute redaction; ② sample all error traces; ③ ratio-sample the rest by `trace_id`.
    #[derive(Debug)]
    pub(super) struct SamplingExporter<E: SpanExporter> {
        inner: E,
        sampler: SamplerCfg,
        decisions: Arc<Mutex<Decisions>>,
    }

    impl<E: SpanExporter> SamplingExporter<E> {
        pub fn new(inner: E, sampler: SamplerCfg) -> Self {
            Self {
                inner,
                sampler,
                decisions: Arc::new(Mutex::new(Decisions::new())),
            }
        }

        /// Sampling/redaction core (covered directly by unit tests): returns the batch to export.
        pub fn filter_batch(&self, batch: Vec<SpanData>) -> Vec<SpanData> {
            let mut batch = batch;
            for span in &mut batch {
                sanitize_attributes(span);
            }
            // Scan error traces first: a child span in the same batch must be kept with its error trace even if it ended earlier.
            let mut error_traces: HashSet<[u8; 16]> = HashSet::new();
            for span in &batch {
                if is_error_span(span) {
                    error_traces.insert(span.span_context.trace_id().to_bytes());
                }
            }
            let mut decisions = match self.decisions.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            let mut keep = Vec::with_capacity(batch.len());
            for span in batch {
                let is_error = is_error_span(&span);
                let key = span.span_context.trace_id().to_bytes();
                let mut sample = decisions
                    .get(&key)
                    .unwrap_or_else(|| self.sampler.keep_trace(span.span_context.trace_id()));
                sample = sample || is_error || error_traces.contains(&key);
                if sample {
                    decisions.insert(key, true);
                    keep.push(span);
                } else {
                    decisions.insert(key, false);
                }
            }
            keep
        }
    }

    impl<E: SpanExporter + 'static> SpanExporter for SamplingExporter<E> {
        fn export(&mut self, batch: Vec<SpanData>) -> BoxFuture<'static, ExportResult> {
            let keep = self.filter_batch(batch);
            if keep.is_empty() {
                return Box::pin(async { Ok(()) });
            }
            self.inner.export(keep)
        }

        fn shutdown(&mut self) {
            self.inner.shutdown();
        }

        fn force_flush(&mut self) -> BoxFuture<'static, ExportResult> {
            self.inner.force_flush()
        }

        fn set_resource(&mut self, resource: &Resource) {
            self.inner.set_resource(resource);
        }
    }

    // ------------------------------------------------------------------
    // init / layer / shutdown
    // ------------------------------------------------------------------

    fn env_flag(name: &str) -> bool {
        matches!(
            std::env::var(name)
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "1" | "true" | "on" | "yes"
        )
    }

    pub fn init(node_id: &str) -> bool {
        if ENABLED.load(Ordering::Acquire) {
            return true;
        }
        if !env_flag("LATTICE_OTEL_ENABLED") {
            return false;
        }
        let sampler = SamplerCfg::from_env();
        let endpoint = non_empty_env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
            .or_else(|| non_empty_env("OTEL_EXPORTER_OTLP_ENDPOINT"))
            .unwrap_or_else(|| "http://127.0.0.1:4317".to_string());
        let timeout_ms = std::env::var("LATTICE_OTEL_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(3_000);
        let service = non_empty_env("OTEL_SERVICE_NAME")
            .or_else(|| non_empty_env("LATTICE_OTEL_SERVICE_NAME"))
            .unwrap_or_else(|| "lattice-node".to_string());

        let otlp = match opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&endpoint)
            .with_timeout(Duration::from_millis(timeout_ms))
            .build()
        {
            Ok(e) => e,
            Err(e) => {
                // Never blocks: on an invalid endpoint or init failure, keep local tracing only and do not export.
                tracing::warn!(
                    error = %e,
                    endpoint = %endpoint,
                    "OTel OTLP exporter init failed; trace export disabled (node continues)"
                );
                return false;
            }
        };
        let exporter = SamplingExporter::new(otlp, sampler);
        let batch = BatchSpanProcessor::builder(exporter, runtime::Tokio).build();
        let resource = Resource::new([
            KeyValue::new("service.name", service.clone()),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("node.id", node_id.to_string()),
        ]);
        let provider = TracerProvider::builder()
            // AlwaysOn: "sample all errors" needs unsampled traces to be recoverable on the export side, so recording never rolls dice.
            .with_sampler(opentelemetry_sdk::trace::Sampler::AlwaysOn)
            .with_resource(resource)
            .with_span_processor(batch)
            .build();
        global::set_tracer_provider(provider.clone());
        let _ = PROVIDER.set(provider);
        let info = OtelInfo {
            service: Box::leak(service.into_boxed_str()),
            endpoint: Box::leak(endpoint.into_boxed_str()),
            sampler: sampler.description(),
        };
        let _ = INFO.set(info);
        ENABLED.store(true, Ordering::Release);
        true
    }

    fn non_empty_env(name: &str) -> Option<String> {
        std::env::var(name)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn layer_info() -> Option<(&'static str, &'static str, &'static str)> {
        INFO.get()
            .map(|i| (i.service, i.endpoint, i.sampler))
    }

    pub fn layer<S>() -> Option<
        tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>,
    >
    where
        S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
    {
        if !ENABLED.load(Ordering::Acquire) {
            return None;
        }
        let provider = PROVIDER.get()?;
        let tracer = provider.tracer(TRACER_NAME);
        Some(tracing_opentelemetry::layer::<S>().with_tracer(tracer))
    }

    pub fn shutdown() {
        if let Some(provider) = PROVIDER.get() {
            for result in provider.force_flush() {
                if let Err(e) = result {
                    tracing::warn!(error = %e, "OTel force_flush failed");
                }
            }
            if let Err(e) = provider.shutdown() {
                tracing::warn!(error = %e, "OTel shutdown failed");
            }
        }
    }

    // ------------------------------------------------------------------
    // HTTP request span (middleware; mounted in main.rs)
    // ------------------------------------------------------------------

    struct HeaderCarrier<'a>(&'a axum::http::HeaderMap);

    impl Extractor for HeaderCarrier<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).and_then(|v| v.to_str().ok())
        }
        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(|k| k.as_str()).collect()
        }
    }

    fn extract_parent(headers: &axum::http::HeaderMap) -> Option<Context> {
        let propagator = opentelemetry_sdk::propagation::TraceContextPropagator::new();
        let cx = propagator.extract(&HeaderCarrier(headers));
        if cx.has_active_span() && cx.span().span_context().is_valid() {
            Some(cx)
        } else {
            None
        }
    }

    fn trace_id_hex(span: &tracing::Span) -> Option<String> {
        let cx = span.context();
        let sc = cx.span().span_context().clone();
        if !sc.is_valid() {
            return None;
        }
        Some(format!("{:032x}", sc.trace_id()))
    }

    /// Keep only low-cardinality route templates (MatchedPath first; fall back to the path without the query string).
    fn route_of(req: &axum::extract::Request) -> String {
        use axum::extract::MatchedPath;
        if let Some(m) = req.extensions().get::<MatchedPath>() {
            return m.as_str().to_string();
        }
        req.uri().path().to_string()
    }

    pub async fn http_trace_middleware(
        req: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        if !ENABLED.load(Ordering::Acquire) {
            return next.run(req).await;
        }
        let method = req.method().as_str().to_string();
        let route = route_of(&req);
        let path = req.uri().path().to_string();
        let parent = extract_parent(req.headers());
        let span = tracing::info_span!(
            "http.request",
            "otel.kind" = "server",
            "http.method" = %method,
            "http.route" = %route,
            "http.target" = %path,
            "http.status_code" = tracing::field::Empty,
            "otel.status_code" = tracing::field::Empty,
            "lattice.trace_id" = tracing::field::Empty,
            envelope_id = tracing::field::Empty,
        );
        if let Some(cx) = parent {
            span.set_parent(cx);
        }
        let span_for_response = span.clone();
        let mut resp = next.run(req).instrument(span).await;
        let status = resp.status().as_u16();
        span_for_response.record("http.status_code", status as i64);
        if status >= 500 {
            span_for_response.record("otel.status_code", "ERROR");
        }
        if let Some(tid) = trace_id_hex(&span_for_response) {
            span_for_response.record("lattice.trace_id", tid.as_str());
            if let Ok(v) = axum::http::HeaderValue::from_str(&tid) {
                resp.headers_mut().insert(
                    axum::http::header::HeaderName::from_static("x-lattice-trace-id"),
                    v,
                );
            }
        }
        drop(span_for_response);
        resp
    }

    // ------------------------------------------------------------------
    // Business span helpers (called from state.rs / pipeline)
    // ------------------------------------------------------------------

    pub fn ingest_span(env: &Envelope) -> IngestSpan {
        if !ENABLED.load(Ordering::Acquire) {
            return IngestSpan { span: None };
        }
        let sender_hash = crate::observe::Metrics::user_hash(if env.sender.is_empty() {
            "anon"
        } else {
            &env.sender
        });
        let span = tracing::info_span!(
            "pipeline.ingest",
            "otel.kind" = "consumer",
            envelope_id = %env.id,
            conv_id = %env.conv_id,
            msg_type = %env.r#type,
            sender_hash = %sender_hash,
            seq = tracing::field::Empty,
            "delivery.state" = tracing::field::Empty,
            duplicate = tracing::field::Empty,
        );
        // REST path: link envelope_id to the current HTTP request span (three streams in one).
        let current = tracing::Span::current();
        if !env.id.is_empty() {
            current.record("envelope_id", &tracing::field::display(env.id.as_str()));
        }
        IngestSpan { span: Some(span) }
    }

    pub fn finish_ingest(span: IngestSpan, seq: u64, state: &str, duplicate: bool) {
        if let Some(s) = span.span {
            s.record("seq", seq);
            s.record("delivery.state", state);
            s.record("duplicate", duplicate);
            drop(s);
        }
    }

    pub fn deliver_span(
        stage: &'static str,
        frame: &Frame,
        target: Option<&str>,
    ) -> DeliverSpan {
        if !ENABLED.load(Ordering::Acquire) {
            return DeliverSpan { span: None };
        }
        let attrs = frame_attrs(frame);
        let target_hash = target
            .map(crate::observe::Metrics::user_hash)
            .unwrap_or_default();
        let span = tracing::info_span!(
            "lattice.deliver",
            "otel.kind" = "producer",
            stage = %stage,
            frame_cmd = %attrs.cmd,
            envelope_id = attrs.envelope_id.as_deref().unwrap_or(""),
            conv_id = attrs.conv_id.as_deref().unwrap_or(""),
            seq = attrs.seq.unwrap_or(0) as i64,
            target_hash = %target_hash,
            delivered = tracing::field::Empty,
        );
        DeliverSpan { span: Some(span) }
    }

    pub fn finish_deliver(span: DeliverSpan, delivered: usize) {
        if let Some(s) = span.span {
            s.record("delivered", delivered as i64);
            drop(s);
        }
    }

    pub fn route_resolve_span(target_user: &str) -> OtelSpan {
        if !ENABLED.load(Ordering::Acquire) {
            return OtelSpan { span: None };
        }
        let target_hash = crate::observe::Metrics::user_hash(target_user);
        let span = tracing::info_span!(
            "lattice.route.resolve",
            target_hash = %target_hash,
        );
        OtelSpan { span: Some(span) }
    }

    pub fn record_error(operation: &'static str, code: &str) {
        if !ENABLED.load(Ordering::Acquire) {
            return;
        }
        // ERROR level + explicit otel.status_code: the export-side "sample all error traces" rule keeps the whole chain from this.
        // `code` may be borrowed (call sites pass &str from error details); it is formatted at span creation and not held long.
        let span = tracing::error_span!(
            "lattice.error",
            "otel.kind" = "internal",
            operation = %operation,
            error_code = %code,
            "otel.status_code" = "ERROR",
        );
        drop(span);
    }

    pub fn frame_attrs(frame: &Frame) -> FrameAttrs {
        let mut attrs = FrameAttrs::new(frame.cmd.as_str());
        if !ENABLED.load(Ordering::Acquire) {
            return attrs;
        }
        if !matches!(
            frame.cmd,
            lattice_core::WsCommand::Envelope | lattice_core::WsCommand::Chunk
        ) {
            return attrs;
        }
        if let Ok(env) = Envelope::decode_body(&frame.body) {
            attrs.envelope_id = Some(env.id);
            attrs.conv_id = Some(env.conv_id);
            attrs.seq = Some(env.seq);
        }
        attrs
    }
}

#[cfg(feature = "otel")]
pub use imp::{
    deliver_span, enabled, finish_deliver, finish_ingest, frame_attrs, http_trace_middleware,
    ingest_span, init, layer_info, record_error, route_resolve_span, shutdown,
};

#[cfg(feature = "otel")]
pub use imp::layer;

// ===========================================================================
// Unit tests (compiled only with feature = "otel"; no global subscriber needed)
// ===========================================================================
#[cfg(all(test, feature = "otel"))]
mod tests {
    use super::imp::{SamplerCfg, SamplerMode, SamplingExporter};
    use futures::executor::block_on;
    use opentelemetry::trace::{
        SpanContext, SpanId, SpanKind, Status, TraceFlags, TraceId, TraceState,
    };
    use opentelemetry::KeyValue;
    use opentelemetry_sdk::export::trace::{ExportResult, SpanData, SpanExporter};
    use opentelemetry_sdk::trace::SpanEvents;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone, Default)]
    struct CaptureExporter {
        spans: Arc<Mutex<Vec<SpanData>>>,
    }

    impl SpanExporter for CaptureExporter {
        fn export(
            &mut self,
            batch: Vec<SpanData>,
        ) -> futures::future::BoxFuture<'static, ExportResult> {
            let spans = self.spans.clone();
            Box::pin(async move {
                spans.lock().unwrap().extend(batch);
                Ok(())
            })
        }
    }

    fn tid(byte: u8) -> TraceId {
        TraceId::from_bytes([byte; 16])
    }

    fn make_span(name: &str, trace: TraceId, status: Status) -> SpanData {
        SpanData {
            span_context: SpanContext::new(
                trace,
                SpanId::from_bytes([1; 8]),
                TraceFlags::SAMPLED,
                false,
                TraceState::default(),
            ),
            parent_span_id: SpanId::INVALID,
            span_kind: SpanKind::Internal,
            name: name.to_string().into(),
            start_time: std::time::SystemTime::now(),
            end_time: std::time::SystemTime::now(),
            attributes: vec![KeyValue::new("payload", "SECRET-PAYLOAD-MARKER")],
            dropped_attributes_count: 0,
            events: SpanEvents::default(),
            links: Default::default(),
            status,
            instrumentation_scope: Default::default(),
        }
    }

    #[test]
    fn sampler_modes_are_configurable_and_deterministic() {
        let trace = tid(0x11);
        assert!(SamplerCfg {
            ratio: 0.0,
            mode: SamplerMode::AlwaysOn
        }
        .keep_trace(trace));
        assert!(!SamplerCfg {
            ratio: 1.0,
            mode: SamplerMode::AlwaysOff
        }
        .keep_trace(trace));
        let r0 = SamplerCfg {
            ratio: 0.0,
            mode: SamplerMode::Ratio,
        };
        let r1 = SamplerCfg {
            ratio: 1.0,
            mode: SamplerMode::Ratio,
        };
        assert!(!r0.keep_trace(trace));
        assert!(r1.keep_trace(trace));
        assert_eq!(r0.keep_trace(trace), r0.keep_trace(trace), "the verdict for one trace must be stable");
    }

    #[test]
    fn errors_are_always_exported_even_with_zero_ratio() {
        let capture = CaptureExporter::default();
        let exporter = SamplingExporter::new(
            capture.clone(),
            SamplerCfg {
                ratio: 0.0,
                mode: SamplerMode::Ratio,
            },
        );
        let ok = make_span("http.request", tid(0x22), Status::Unset);
        let err = make_span("lattice.error", tid(0x33), Status::error("boom"));
        let kept = exporter.filter_batch(vec![ok, err]);
        assert_eq!(kept.len(), 1, "error spans must be kept; normal spans are dropped at ratio 0");
        assert!(kept[0].name.starts_with("lattice.error"));
    }

    #[test]
    fn sensitive_attributes_never_leak_into_export() {
        let capture = CaptureExporter::default();
        let exporter = SamplingExporter::new(
            capture.clone(),
            SamplerCfg {
                ratio: 1.0,
                mode: SamplerMode::AlwaysOn,
            },
        );
        let mut span = make_span("http.request", tid(0x44), Status::Unset);
        span.attributes
            .push(KeyValue::new("authorization", "Bearer plain-token"));
        span.attributes
            .push(KeyValue::new("envelope_id", "01JTESTENVELOPE"));
        let kept = exporter.filter_batch(vec![span]);
        assert_eq!(kept.len(), 1);
        let flat = format!("{:?}", kept[0].attributes);
        assert!(!flat.contains("SECRET-PAYLOAD-MARKER"), "payload must not appear in exported attributes");
        assert!(!flat.contains("plain-token"), "plaintext tokens must not appear in exported attributes");
        assert!(flat.contains("01JTESTENVELOPE"), "envelope_id must be kept for correlation");
        assert!(flat.contains("lattice.trace_id"), "the trace_id correlation attribute must exist");
    }

    #[test]
    fn error_trace_keeps_all_spans_of_that_trace() {
        let capture = CaptureExporter::default();
        let exporter = SamplingExporter::new(
            capture.clone(),
            SamplerCfg {
                ratio: 0.0,
                mode: SamplerMode::Ratio,
            },
        );
        let trace = tid(0x55);
        let child = make_span("pipeline.ingest", trace, Status::Unset);
        let root = make_span("lattice.error", trace, Status::error("boom"));
        let kept = exporter.filter_batch(vec![child, root]);
        assert_eq!(kept.len(), 2, "all spans of an error trace must be exported together");
    }

    #[test]
    fn export_call_filters_then_forwards() {
        let capture = CaptureExporter::default();
        let mut exporter = SamplingExporter::new(
            capture.clone(),
            SamplerCfg {
                ratio: 0.0,
                mode: SamplerMode::Ratio,
            },
        );
        block_on(exporter.export(vec![make_span("http.request", tid(0x66), Status::Unset)]))
            .unwrap();
        assert!(capture.spans.lock().unwrap().is_empty());
        block_on(exporter.export(vec![make_span(
            "lattice.error",
            tid(0x77),
            Status::error("x"),
        )]))
        .unwrap();
        assert_eq!(capture.spans.lock().unwrap().len(), 1);
        // The export side still keeps the trace_id correlation attribute, and the sensitive payload key has been stripped.
        let exported = capture.spans.lock().unwrap();
        let attrs = &exported[0].attributes;
        assert!(attrs.iter().any(|kv| kv.key.as_str() == "lattice.trace_id"));
        assert!(
            attrs.iter().all(|kv| kv.key.as_str() != "payload"),
            "sensitive key payload must not be exported"
        );
    }
}
