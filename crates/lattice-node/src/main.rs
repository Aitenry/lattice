//! `lattice-node` entry point (② §7.2 startup sequence).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use lattice_node::config;
use lattice_node::node;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let cfg_path = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var("LATTICE_CONFIG").ok().map(std::path::PathBuf::from));

    let cfg = config::Config::load(cfg_path.as_deref())?;
    let json_logs = cfg.node.log == "json";

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        // Fetch node_id before initializing tracing (logs must carry node_id).
        let pre_id = if cfg.node.id.is_empty() {
            "pending".to_string()
        } else {
            cfg.node.id.clone()
        };
        lattice_node::observe::init_tracing(&pre_id, json_logs);

        let state = node::build(cfg).await?;
        serve(state).await
    })
}

async fn serve(state: Arc<lattice_node::AppState>) -> Result<(), Box<dyn std::error::Error>> {
    // MQTT gateway (P3, ⑤ §11): listen failures only warn and never block node startup (② §7.2).
    lattice_node::transport::mqtt::spawn(state.clone());

    let app: Router = lattice_node::transport::http::router()
        .route("/v1/ws", get(lattice_node::transport::ws::handler))
        // Generic `Idempotency-Key` middleware (REMAINING E12 / ⑤ §0.3): applies only to authenticated write requests that
        // carry a key; missing key, GET/HEAD, WS upgrade, streaming/302 download, and non-2xx are all no-ops.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            lattice_node::transport::http::idempotency::middleware,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(tower_http::cors::CorsLayer::permissive())
        // OTel HTTP request span (REMAINING E22 / `observe/otel.rs`): records trace_id/route/status
        // and writes the `x-lattice-trace-id` response header; when feature `otel` is off or `LATTICE_OTEL_ENABLED`
        // is unset it is pure passthrough (adds no observable behavior).
        .layer(axum::middleware::from_fn(
            lattice_node::observe::otel::http_trace_middleware,
        ))
        .with_state(state.clone());

    let http_addr: SocketAddr = state.cfg.node.listen_http.parse()?;
    let listener = tokio::net::TcpListener::bind(http_addr).await?;
    tracing::info!(addr = %http_addr, "http+ws listening");

    let shutdown = shutdown_signal(state.clone());
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    Ok(())
}

async fn shutdown_signal(state: Arc<lattice_node::AppState>) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    // Drain connections (② §7.2): set draining first (new connections/QUIC registrations are rejected immediately),
    // then drain the QUIC media plane and WS; QUIC drain is bounded (stop accept → bye → close endpoint).
    tracing::info!("shutdown signal received, draining connections");
    state
        .draining
        .store(true, std::sync::atomic::Ordering::Relaxed);
    #[cfg(feature = "quic")]
    lattice_node::transport::quic::drain(&state).await;
    // Drain WS connections (30s window, send byef reason=shutdown, ② §7.2)
    lattice_node::transport::ws::drain_all(&state).await;
    // Flush the OTel trace queue (no-op when disabled): export the last span batch before exit.
    lattice_node::observe::otel::shutdown();
}
