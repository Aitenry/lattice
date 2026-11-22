//! Node lifecycle (② §7.2):
//! load config → build connection pool → migrate (under lock) → register heartbeat → subscribe channels → open listeners → ready.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::config::Config;
use crate::state::{AppState, Hub};
use crate::{jobs, observe, store};

/// Assemble node state (shared by main and tests).
pub async fn build(cfg: Config) -> crate::Result<Arc<AppState>> {
    // 1) Storage connections (dedicated admin pool, ② §2.1)
    let db = store::pg::connect(&cfg.pg.url, cfg.pg.pool_size, cfg.pg.statement_timeout_ms).await?;
    let admin_db = store::pg::connect(
        &cfg.pg.url,
        cfg.admin.pool_size,
        cfg.pg.admin_statement_timeout_ms,
    )
    .await?;
    let redis = store::Redis::connect_with(
        &cfg.redis.url,
        cfg.redis.effective_scan_count(),
    )
    .await?;

    // 2) Migration (runs once per deployment; idempotent and re-entrant, ⑥ §8)
    store::pg::migrate(&db).await?;

    let node_id = if cfg.node.id.is_empty() {
        lattice_core::ids::new_id()
    } else {
        cfg.node.id.clone()
    };

    // 3) JWT keys (generate if missing, dev bootstrap; dual-key overlap window: ⑤ §8.4)
    let jwt = crate::auth::JwtKeys::load_or_create(
        std::path::Path::new(&cfg.auth.key_dir),
        &cfg.auth.jwt_issuer,
        cfg.auth.jwt_ttl,
        cfg.auth.key_overlap_hours,
    )?;

    // 4) Dynamic config: **read PG first, then subscribe to the broadcast** (⑥ §9 D12)
    let mut dynamic = std::collections::HashMap::new();
    match store::pg::config_all(&db).await {
        Ok(rows) => {
            for (k, v) in rows {
                dynamic.insert(k, v);
            }
        }
        Err(e) => tracing::warn!(error = %e, "dynamic config load failed, using TOML defaults"),
    }

    // 5) Bootstrap admin (⑤ §8.2 "first administrator")
    //
    //    Empty database + `[admin] bootstrap_password` configured → create account (role=admin);
    //    user already exists → only converge `users.role` to admin (role authority is the user row,
    //    ⑥ §2.3 D14; idempotent UPDATE, restarts do not create duplicates).
    //    If neither holds, **warn only and create nothing**: creating an account when the password is missing is a backdoor.
    if !cfg.admin.bootstrap_username.is_empty() {
        let username = cfg.admin.bootstrap_username.trim();
        match store::pg::user_by_username(&db, username).await {
            Ok(Some(u)) => {
                if u.role != "admin" {
                    match store::pg::set_user_role(&db, &u.id, "admin").await {
                        Ok(true) => tracing::info!(user = %u.username, "bootstrap user promoted to admin"),
                        Ok(false) => tracing::warn!(user = %u.username, "bootstrap promote had no effect"),
                        Err(e) => tracing::warn!(error = %e, "bootstrap promote failed"),
                    }
                }
            }
            Ok(None) => match store::pg::count_users(&db).await {
                Ok(0) => match cfg.admin.bootstrap_password.as_deref() {
                    Some(pw) if !pw.is_empty() => {
                        match crate::auth::password::hash_password(pw) {
                            Ok(hash) => match store::pg::create_user(
                                &db,
                                username,
                                &hash,
                                Some(if username == "admin" { "Eddie" } else { "bootstrap admin" }),
                                "admin",
                            )
                            .await
                            {
                                Ok(u) => {
                                    // The default admin also gets a generated gradient avatar (failures only WARN).
                                    let avatar = crate::admin::generated_gradient_avatar(&u.id);
                                    if let Err(e) = store::pg::set_user_profile(
                                        &db,
                                        &u.id,
                                        None,
                                        Some(Some(avatar.as_str())),
                                    )
                                    .await
                                    {
                                        tracing::warn!(error = %e, "bootstrap admin avatar failed");
                                    }
                                    tracing::info!(
                                        user = %u.username,
                                        "bootstrap admin created (empty user table); rotate this password"
                                    )
                                }
                                Err(e) => tracing::warn!(error = %e, "bootstrap admin create failed"),
                            },
                            Err(e) => tracing::warn!(error = %e, "bootstrap password hash failed"),
                        }
                    }
                    _ => tracing::warn!(
                        user = %username,
                        "user table is empty and [admin] bootstrap_password is unset; \
                         no account can log in — set LATTICE__ADMIN__BOOTSTRAP_PASSWORD for the first start"
                    ),
                },
                Ok(n) => tracing::warn!(
                    user = %username,
                    users = n,
                    "bootstrap user not found; create it via POST /v1/admin/users"
                ),
                Err(e) => tracing::warn!(error = %e, "user count failed"),
            },
            Err(e) => tracing::warn!(error = %e, "bootstrap user lookup failed"),
        }
    }

    let s3 = store::S3::new(cfg.s3.clone());

    // 3.5) Ensure the object bucket exists. Bucket creation is the bucket user's responsibility, so it lives here rather than in a one-shot container;
    // failures only warn: the message plane does not depend on S3, only large file uploads are affected (② §3.2).
    if let Err(e) = s3.ensure_buckets().await {
        tracing::warn!(
            error = %e,
            "s3 buckets unavailable; large-file upload disabled until MinIO reachable"
        );
    }

    // 3.7) Bus: connect to NATS JetStream when `kind = nats` (P3); on connection/stream creation failure fall back
    //       to Redis PubSub per the degradation matrix — warn only, never block startup (② §4.8 / ⑥ §5).
    let bus: Arc<dyn store::Bus> = match store::bus::build(&cfg.bus, redis.clone()).await {
        Ok(bus) => {
            tracing::info!(bus = bus.kind().as_str(), "bus ready");
            bus
        }
        Err(e) => {
            tracing::warn!(
                kind = %cfg.bus.kind,
                error = %e,
                "bus init failed, falling back to redis-pubsub (② §4.8)"
            );
            Arc::new(store::RedisBus::new(redis.clone()))
        }
    };
    let wal_dir = cfg.wal.effective_dir(&cfg.degrade);
    let wal = store::Wal::with_options(&wal_dir, cfg.wal.effective_max_bytes());
    tracing::info!(
        dir = %wal_dir,
        max_bytes = wal.max_bytes(),
        enabled = cfg.wal.enabled,
        replay_interval_ms = cfg.wal.effective_replay_interval_ms(),
        "local wal ready (pg-unwritable degrade, ② §4.8)"
    );

    // Build metrics first so they can be injected into the connection registry (backpressure drop counters need them, ⑤ §9.5)
    let metrics = observe::Metrics::new();
    // Injected into the Redis access layer: `SCAN` roundtrip counter for prefix scans (`lattice_redis_scan_calls_total`).
    redis.set_metrics(metrics.clone());
    // Session membership short-TTL positive cache (PL-17 bottleneck fix; 0 = disabled, fall back to PG).
    let member_cache =
        crate::state::MemberCache::new(cfg.policy.effective_member_cache_ttl(), crate::state::MEMBER_CACHE_CAP);
    tracing::info!(
        redis_scan_count = redis.scan_count(),
        member_cache_ttl_ms = cfg.policy.effective_member_cache_ttl().as_millis() as u64,
        "perf tuning: redis scan batching + member cache"
    );
    let hub = Arc::new(Hub::default());
    hub.set_metrics(metrics.clone());

    // 5.7) Risk control rule engine (E03 / PL-12 12.6–12.7): **disabled by default** (`[risk] enabled=false`).
    //      When disabled: no extra Redis connections, no background tasks, and all three hot-path hooks return on the first line = zero side effects.
    //      When enabled: message frequency/device switch/auth failure rules match → bounded Redis ZSET `lattice:risk`
    //      + `audit_log(risk.detected/risk.action)` + configurable action (rate limit/revoke refresh/audit only).
    //      Hot paths only do in-memory window + bounded try_send; Redis/audit/revocation all run in background tasks (see risk.rs).
    let risk = crate::routing::risk::RiskEngine::new(cfg.risk.clone(), metrics.clone());

    // 5.8) QUIC server proxy (PL-13 13.3; design §17.9 path ②).
    //      Two switches: compile-time feature `quic` (off by default) + `[quic] enabled` (default false).
    //      When off: no UDP socket, no spawned tasks, no certificates loaded — zero side effects on existing media paths.
    //      When on but bind/certificate fails, **startup fails** (silent degradation of an explicitly enabled proxy is harder to diagnose than an error).
    #[cfg(feature = "quic")]
    let quic_proxy = crate::transport::quic::build(&cfg.quic, metrics.clone())?;

    // 5.8b) WebTransport (HTTP/3) browser access gateway (PL-13 13.3; design §17.9 path ②).
    //      Bridge semantics: WT bidirectional streams → local QUIC listener (the gateway is an internal QUIC client),
    //      with JWT/device/participant auth + TLV relay + 8Mbps per-stream token bucket + per-node stream cap all reusing QUIC.
    //      Unlike [quic]: **config/certificate/port errors only WARN and stay off**, never affecting node ready
    //      or existing QUIC/WS media paths (the browser entry is an optional overlay).
    #[cfg(feature = "webtransport")]
    let webtransport_proxy = crate::transport::webtransport::build(&cfg, metrics.clone()).await;

    // 5.9) Media recording side path (PL-13 13.6): with the default `record_enabled=false`,
    //      no channel is created, no task started, and `AppState.recorder = None` — zero side effects.
    //      When enabled, `on_data` only does a bounded queue try_send; actual persistence happens in the 6.1 background task,
    //      and the bus type (nats/redis) decides in 6.0/6.1 whether to use producer+durable consumer or direct writes.
    let (recorder, record_rx) = crate::routing::media::build_recorder(&cfg.media, metrics.clone());

    let state = Arc::new(AppState {
        db,
        admin_db,
        redis,
        s3,
        bus,
        wal,
        pg_degrade: crate::state::PgDegradeCache::default(),
        member_cache,
        wal_replay_lock: tokio::sync::Mutex::new(()),
        hub,
        metrics,
        risk,
        live: Arc::new(crate::live::Live::default()),
        jwt: RwLock::new(Arc::new(jwt)),
        key_rotate_lock: tokio::sync::Mutex::new(()),
        dynamic: RwLock::new(dynamic),
        plugins: RwLock::new(Vec::new()),
        rate_buckets: Mutex::new(std::collections::HashMap::new()),
        byte_buckets: Mutex::new(std::collections::HashMap::new()),
        stream_buckets: Mutex::new(std::collections::HashMap::new()),
        recorder,
        #[cfg(feature = "quic")]
        quic: quic_proxy.clone(),
        #[cfg(feature = "webtransport")]
        webtransport: webtransport_proxy.clone(),
        route_cache: RwLock::new(std::collections::HashMap::new()),
        ready: AtomicBool::new(false),
        started_at: Instant::now(),
        draining: AtomicBool::new(false),
        node_id,
        cfg,
    });

    // 6.0) Media recording bus consumer (PL-13 13.6; started when `record_enabled && bus.kind=nats`):
    //      durable pull consumer `media-record-{node_id}` (filter `media.record.>`, explicit ack)
    //      processes only this node's ingress frames, aggregates by stream into `[4B len][body]` segments, and writes them to MinIO;
    //      ack only after a successful write, so after restart the durable consumer resumes unacked messages. Other bus types skip it (producer
    //      writes object storage directly). Started asynchronously, never blocks ready.
    crate::routing::media_record::spawn_consumer(state.clone());

    // 6.1) Media recording producer (only record_enabled=true): with `bus.kind=nats` publish `media.record.*`
    //      (publish failure degrades to direct write); with `bus.kind=redis-pubsub` keep the original "aggregate by stream → write MinIO directly".
    //      Asynchronous, never blocks forwarding; failures only warn + metric.
    if let Some(rx) = record_rx {
        crate::routing::media::spawn_recorder(state.clone(), rx);
    }

    // 6) Subscriptions: cross-node routing / topic broadcast fan-in (NATS only) / online events / dynamic config
    crate::routing::crossnode::spawn_subscriber(state.clone()).await;
    crate::routing::crossnode::spawn_topic_listener(state.clone()).await;
    crate::routing::crossnode::spawn_online_listener(state.clone()).await;
    crate::routing::crossnode::spawn_cfg_listener(state.clone()).await;

    // 6.2) Audit stream consumer (② §4.8 / ⑥ §5.2): when `bus.kind=nats`, create durable consumer
    //      `audit-{node_id}` to idempotently persist `audit.log` into `audit_log`; with the Redis bus or when disabled, only log and
    //      have the write entry `audit_emit` write PG directly. Started asynchronously, never blocks ready.
    crate::routing::audit::spawn_consumer(state.clone());

    // 6.3) Risk engine background action task (E03): no-op when disabled (one log line, no spawn);
    //      when enabled, consume match events → bounded Redis queue / audit / action.
    crate::routing::risk::spawn(state.clone());

    // 7) Background tasks
    jobs::spawn_all(state.clone());

    // 7.1) On startup, run WAL catch-up once (records left by a previous crash or long PG outage), then become ready.
    //      Failures only warn: PG is usually available at this point (connected during build); if not, periodic tasks keep retrying.
    if let Err(e) = jobs::replay_wal_once(&state).await {
        tracing::warn!(error = %e, "startup wal replay failed (will retry periodically)");
    }

    // 7.5) Console live snapshots (⑤ §8.5: one task computes, SSE connections only read)
    crate::live::spawn(state.clone());

    // 7.6) Prometheus scrape endpoint (② §8.1; unauthenticated, read-only, bound to [node] metrics)
    crate::observe::metrics_server::spawn(state.clone());

    // 7.7) Internal gRPC (⑤ §10; listen when [grpc] enabled, mTLS in production, plaintext allowed in dev)
    crate::transport::grpc::spawn(state.clone());

    // 7.8) QUIC server proxy (PL-13 13.3; design §17.9 path ②):
    //      UDP listener + stream registration/relay registry (registration auth: JWT + device binding + stream-sig participant).
    //      Lifecycle: endpoint ownership in state.quic; once `AppState.draining` (shared by SIGTERM/admin traffic drain)
    //      is set, stop accepting new connections, send bye{reason:shutdown} to registered streams, then close the endpoint after a bounded wait.
    #[cfg(feature = "quic")]
    if let Some(proxy) = quic_proxy {
        crate::transport::quic::spawn(proxy, state.clone());
    }
    // Reverse case: TOML/env enables [quic] enabled but the binary was built without the quic feature — do not pretend it is enabled.
    #[cfg(not(feature = "quic"))]
    if state.cfg.quic.enabled {
        tracing::warn!(
            bind = %state.cfg.quic.bind,
            "config has [quic] enabled=true but this binary was built without the `quic` feature; \
             QUIC proxy stays disabled (rebuild with --features quic)"
        );
    }

    // 7.8b) WebTransport (HTTP/3) browser access gateway (PL-13 13.3):
    //      HTTP/3 CONNECT `/media` listener + WT↔QUIC bidirectional frame bridge; lifecycle same as QUIC:
    //      once `AppState.draining` (shared by SIGTERM/admin traffic drain) is set, stop accepting new sessions,
    //      let registered streams finish via QUIC drain bye, then close the endpoint after a bounded wait (releasing the UDP port).
    #[cfg(feature = "webtransport")]
    if let Some(proxy) = webtransport_proxy {
        crate::transport::webtransport::spawn(proxy, state.clone());
    }
    // Reverse case: TOML/env enables [webtransport] enabled but the binary was built without the feature — do not pretend it is enabled.
    #[cfg(not(feature = "webtransport"))]
    if state.cfg.webtransport.enabled {
        tracing::warn!(
            bind = %state.cfg.webtransport.bind,
            "config has [webtransport] enabled=true but this binary was built without the \
             `webtransport` feature; WebTransport gateway stays disabled \
             (rebuild with --features webtransport)"
        );
    }

    // 7.9) WASM plugin host wiring (PL-10 / design ② §4.5):
    //      scan [plugins] wasm_dir, verify Ed25519 signatures (trusted_keys), then register; bad packages only warn + metric,
    //      never block node ready. No-op when the `wasm-host` feature is not compiled (default build unchanged).
    crate::plugins::init(&state);

    // 8) Node heartbeat + readiness
    state.heartbeat().await;
    state.ready.store(true, std::sync::atomic::Ordering::Relaxed);

    tracing::info!(
        node_id = %state.node_id,
        version = crate::state::VERSION,
        http = %state.cfg.node.listen_http,
        "lattice-node ready"
    );

    // 8.1) Audit write-path self-check probe (only `[audit] startup_probe=true`, for E2E/chaos; off by default in production).
    //      Sent asynchronously: probe failures only WARN and never slow down or block node startup.
    {
        let st = state.clone();
        tokio::spawn(async move { crate::routing::audit::emit_startup_probe(&st).await });
    }
    Ok(state)
}
