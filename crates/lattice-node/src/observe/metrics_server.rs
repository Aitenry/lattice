//! Prometheus scrape endpoint (design §17.13 `[node] metrics`; doc ② §8.1).
//!
//! Why a separate listener instead of only `GET /v1/admin/metrics`:
//! - Prometheus scrapes carry no JWT by default and admin APIs require RBAC (⑤ §8.1); giving Prometheus
//!   an admin token would put a platform-wide read credential into the monitoring system;
//! - `/v1/admin/metrics` uses the admin connection pool and middleware; frequent scrapes would starve the admin plane (same-origin issue, ② §2.1).
//!
//! So, per doc ② §8.1, expose **unauthenticated, read-only, localhost/cluster-subnet only** `/metrics`
//! (bind from `[node] metrics`, default `127.0.0.1:9100`; inside containers override with
//! `LATTICE__NODE__METRICS=0.0.0.0:9100`). In production, NetworkPolicy/firewall restrict sources.

use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::state::AppState;

/// Start the metrics listener (failure only warns: missing metrics must not block the message plane).
pub fn spawn(state: Arc<AppState>) {
    let addr = state.cfg.node.metrics.trim().to_string();
    if addr.is_empty() || addr == "0" || addr.eq_ignore_ascii_case("off") {
        tracing::info!("metrics listener disabled ([node] metrics is empty/off)");
        return;
    }

    tokio::spawn(async move {
        let app: Router = Router::new()
            .route("/metrics", get(render))
            .route("/healthz", get(|| async { "ok" }))
            .with_state(state.clone());

        let parsed = match addr.parse::<std::net::SocketAddr>() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(addr = %addr, error = %e, "invalid [node] metrics address; metrics disabled");
                return;
            }
        };
        let listener = match tokio::net::TcpListener::bind(parsed).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(addr = %addr, error = %e, "metrics listener bind failed (metrics unavailable)");
                return;
            }
        };
        tracing::info!(addr = %parsed, "prometheus metrics listening at /metrics");
        if let Err(e) = axum::serve(listener, app).await {
            tracing::warn!(error = %e, "metrics server stopped");
        }
    });
}

async fn render(State(st): State<Arc<AppState>>) -> Response {
    let mut resp = st.metrics.render().into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    resp
}
