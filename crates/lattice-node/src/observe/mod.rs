//! Observability: metrics, structured logs, tracing (doc ② §8).
//!
//! OTel tracing (REMAINING E22 / PL-14 14.4) lives in [`otel`]: feature `otel` is off by default;
//! when off, everything in `otel` is a no-op; when on, register it with the tracing subscriber as
//! a `tracing-opentelemetry` layer (global tracer + OTLP/gRPC export + sampling / sample-all errors).

pub mod metrics;
pub mod metrics_server;
pub mod otel;

pub use metrics::Metrics;

/// Initialize tracing: JSON structured logs (doc ② §8.2),
/// field conventions `{ts, level, msg, node_id, conn_id?, envelope_id?, user?}`; **payloads never reach logs**.
///
/// Also initializes OTel tracing per feature/env (`observe::otel::init` + layer);
/// with OTel off or init failed, behavior stays byte-for-byte identical (just one extra atomic read).
pub fn init_tracing(node_id: &str, json: bool) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

// 1) OTel: build the global provider first (failure only WARNs, never blocks); log enablement after the subscriber is up.
    let _ = otel::init(node_id);

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("lattice_node=info,lattice_core=info,warn"));

// 2) Compiled out: use `Identity` (zero-cost no-op layer); compiled in but off at runtime:
//    `otel::layer()` returns None — neither case installs an exporter.
    #[cfg(feature = "otel")]
    let otel_layer = otel::layer();
    #[cfg(not(feature = "otel"))]
    let otel_layer = Option::<tracing_subscriber::layer::Identity>::None;

// 3) Two fixed subscribers, JSON and text; the OTel layer is registered before fmt (span creation → export).
    if json {
        let fmt_layer = fmt::layer()
            .json()
            .with_current_span(true)
            .with_span_list(true);
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(otel_layer)
            .with(fmt_layer);
        let _ = subscriber.try_init();
    } else {
        let fmt_layer = fmt::layer();
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(otel_layer)
            .with(fmt_layer);
        let _ = subscriber.try_init();
    }
    tracing::info!(node_id = %node_id, "tracing initialised");
    if let Some((service, endpoint, sampler)) = otel::layer_info() {
        tracing::info!(
            node_id = %node_id,
            service = %service,
            endpoint = %endpoint,
            sampler = %sampler,
            "OTel OTLP/gRPC trace export enabled (E22)"
        );
    }
}
