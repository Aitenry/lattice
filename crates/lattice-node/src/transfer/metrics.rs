//! Prometheus metrics for the transfer service (design §6.10).
//!
//! A separate registry: the transfer service is a separate process and must not share the
//! node's metric namespace (`lattice_*` node metrics are scraped from the node). Labels are
//! deliberately low-cardinality — never object keys or tokens.

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};

#[derive(Clone)]
pub struct TransferMetrics {
    pub registry: Registry,
    /// `lattice_transfer_requests_total{status}` — status is the HTTP status class written.
    pub requests: IntCounterVec,
    /// `lattice_transfer_bytes_total` — bytes actually streamed to clients.
    pub bytes: IntCounter,
    /// `lattice_transfer_open_seconds{status}` — time until the upstream response head.
    pub open_seconds: HistogramVec,
    /// `lattice_transfer_inflight` — downloads currently streaming.
    pub inflight: IntGauge,
    /// `lattice_transfer_upstream_failures_total{endpoint}` — failed endpoint attempts.
    pub upstream_failures: IntCounterVec,
    /// `lattice_transfer_ready` — 1 when at least one S3 endpoint answered the last probe.
    pub ready: IntGauge,
}

impl TransferMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();
        let requests = IntCounterVec::new(
            Opts::new(
                "lattice_transfer_requests_total",
                "Transfer requests by response status",
            ),
            &["status"],
        )
        .expect("metric");
        let bytes = IntCounter::new(
            "lattice_transfer_bytes_total",
            "Object bytes streamed to clients",
        )
        .expect("metric");
        let open_seconds = HistogramVec::new(
            HistogramOpts::new(
                "lattice_transfer_open_seconds",
                "Time from request start to upstream response head",
            )
            .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["status"],
        )
        .expect("metric");
        let inflight = IntGauge::new(
            "lattice_transfer_inflight",
            "Downloads currently streaming",
        )
        .expect("metric");
        let upstream_failures = IntCounterVec::new(
            Opts::new(
                "lattice_transfer_upstream_failures_total",
                "Failed object-storage endpoint attempts",
            ),
            &["endpoint"],
        )
        .expect("metric");
        let ready = IntGauge::new(
            "lattice_transfer_ready",
            "1 when at least one object-storage endpoint passed the last probe",
        )
        .expect("metric");

        for m in [
            Box::new(requests.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(bytes.clone()),
            Box::new(open_seconds.clone()),
            Box::new(inflight.clone()),
            Box::new(upstream_failures.clone()),
            Box::new(ready.clone()),
        ] {
            registry.register(m).expect("register transfer metric");
        }

        TransferMetrics {
            registry,
            requests,
            bytes,
            open_seconds,
            inflight,
            upstream_failures,
            ready,
        }
    }

    /// Render the registry in Prometheus text exposition format.
    pub fn render(&self) -> Result<Vec<u8>, prometheus::Error> {
        let mut out = Vec::new();
        let encoder = TextEncoder::new();
        encoder.encode(&self.registry.gather(), &mut out)?;
        Ok(out)
    }
}

impl Default for TransferMetrics {
    fn default() -> Self {
        Self::new()
    }
}
