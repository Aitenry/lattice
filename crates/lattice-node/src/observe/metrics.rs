//! Metrics (doc ② §8.1). Metric names, units, and labels match the docs verbatim:
//! histograms always `_seconds`, counters always `_total`, and labels use the dimensions listed in the docs.

use std::sync::Arc;

use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};

#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    pub connections: IntGaugeVec,
    pub msgs_total: IntCounterVec,
    pub e2e_latency: Histogram,
    pub pending_depth: IntGaugeVec,
    pub chunk_retrans_total: IntCounterVec,
    pub plugin_call_duration: Histogram,
    /// Directory plugin registration result (PL-10): loaded / signature verified / rejected (low cardinality by reason).
    pub plugin_wasm_loaded: IntGauge,
    pub plugin_wasm_verified: IntGauge,
    pub plugin_wasm_rejected_total: IntCounterVec,
    /// Plugin load results counted by source (PL-10 added the PG registry): `source` ∈ dir|pg;
    /// `result` ∈ loaded|rejected|skipped (skipped = ignored by canary/older version; conflicts count as rejected).
    pub plugin_wasm_source_total: IntCounterVec,
    /// Signature verification result count: `result` ∈ verified|invalid|missing (counted once at load time).
    pub plugin_wasm_signature_total: IntCounterVec,
    /// admin invoke call count: `plugin`=short_name, `outcome`=ok|not_found|not_verified|
    /// circuit_open|timeout|trap|memory|fuel|busy|bad_abi|… (success contract in the ⑤ §8.4 extension).
    pub plugin_wasm_invocations_total: IntCounterVec,
    /// admin invoke call duration (seconds; per plugin).
    pub plugin_wasm_invoke_duration: HistogramVec,
    /// Plugin circuit-breaker trip count (per plugin).
    pub plugin_wasm_circuit_trips_total: IntCounterVec,
    /// WASM plugin hot-reload result (PL-10 hot reload): `result` ∈ `ok|error`.
    ///
    /// `ok` = a new snapshot was built and atomically swapped; `error` = build failed (PG/directory read failure, host rebuild failure)
    /// or the reload was rejected (409 concurrent/429 rate limit/422 invalid source). **The old snapshot is kept**.
    pub plugin_wasm_reload_total: IntCounterVec,
    /// WASM plugin hot-reload duration (seconds; build new snapshot → atomic swap; no labels, to limit cardinality).
    pub plugin_wasm_reload_duration: Histogram,
    pub ratelimit_dropped_total: IntCounterVec,
    pub backpressure_dropped_total: IntCounterVec,
    /// Number of times **protected-set frames** (`receipt`/`ack`/`stream-sig`/`byef`, ⑤ §9.5) were dropped under backpressure when both the reserved and
    /// normal channels were full. Labels follow the existing convention (`priority` holds the command name).
    ///
    /// Under normal backpressure this stays 0 — a separate metric exists precisely to alert on "protected-set failure"
    /// apart from ordinary backpressure drops (`lattice_backpressure_dropped_total`); each increment also logs at ERROR.
    pub backpressure_protected_dropped_total: IntCounterVec,
    /// HTTP `Idempotency-Key` middleware result (⑤ §0.3 / E12): `result` ∈
    /// `hit` (hit the first response and replayed it) | `miss` (no hit, executed for real) |
    /// `conflict` (same key, different request) | `in_progress` (concurrent same-key lock contention) |
    /// `error` (idempotency store/lock failure, including fail-open degradation). Touched to 0 at startup (5 low-cardinality values).
    pub http_idempotency_total: IntCounterVec,
    pub store_latency: Histogram,
    pub wal_size_bytes: IntGauge,
    /// Local WAL (② §4.8): append result; `result` ∈ ok|full|fail.
    pub wal_append_total: IntCounterVec,
    /// Local WAL periodic replay result; `result` ∈ ok|duplicate|error|poison.
    pub wal_replay_total: IntCounterVec,
    /// Messages **not** written to the WAL due to a limit/huge message/huge object (must never be dropped silently).
    pub wal_dropped_total: IntCounter,
    pub dedup_hit_total: IntCounterVec,
    pub protocol_version: IntGaugeVec,
    /// Extra: SSE connection count (console cap 100, ⑤ §8.5)
    pub sse_connections: IntGauge,
    /// Extra: HTTP request count (by route/status)
    pub http_requests_total: IntCounterVec,
    /// gRPC fallback routing: `method`=Route; `result`=ok/rejected/error. Basis for bus-failure alerts (PL-13).
    pub grpc_fallback_total: IntCounterVec,
    /// Times the Redis routing index read failed and the local stale route cache was used (② §4.1 degradation alert).
    pub route_cache_stale_total: IntCounter,
    /// Media recording tee: dropped frames because the bounded queue was full/closed (PL-13 13.6; drops must not affect forwarding).
    pub media_record_dropped_total: IntCounter,
    /// Media recording tee: segments successfully written to object storage.
    pub media_record_segments_total: IntCounter,
    /// Media recording tee: raw frame bytes successfully written to object storage (including each segment's `[4B len]` boundary prefix).
    pub media_record_bytes_total: IntCounter,
    /// Media recording tee: object-storage write failures (failures only warn + count; forwarding is unaffected).
    pub media_record_errors_total: IntCounter,
    /// Media recording bus producer (PL-13 13.6 / `LATTICE_MEDIA`): `result` =
    /// `ok` (JetStream publish+ack succeeded) | `fallback` (publish failed/unavailable → degrade to direct object-storage write) |
    /// `direct` (Redis bus: per design no publish, write directly) | `error` (publish failed and the degraded direct write also failed).
    pub media_record_publish_total: IntCounterVec,
    /// Media recording consumer result: `result` = `ok` (frames persisted with the segment and acked) |
    /// `duplicate` (redelivery/seq within the watermark: dropped and acked) | `other_node` (ingress frame from another node: dropped and acked) |
    /// `retry` (persist failed, buffer kept for retry) | `dlq` (retries exhausted → terminate) | `poison` (malformed message → terminate).
    pub media_record_consume_total: IntCounterVec,
    /// Media recording consumer approximate lag (server-side pending count, refreshed as it consumes; 0 = no backlog).
    pub media_record_consumer_lag: IntGauge,
    /// Media recording segment index write result (PL-13 13.6 retrieval plane, `media_recordings` table):
    /// `result` = `ok` (new index row) | `dup` (`object_key` already exists: replay overwrite, no duplicate row) |
    /// `error` (PG write failed; only WARN, recording forwarding/persist unaffected).
    pub media_record_index_total: IntCounterVec,
    /// Media recording **manifest** write result (PL-13 13.6):
    /// `result` = `ok` (manifest object written) | `error` (read-back/serialization/persist failed; only WARN,
    /// recording forwarding and indexing unaffected; the manifest API returns 404 for that segment).
    pub media_record_manifest_total: IntCounterVec,
    /// Media recording **lifecycle GC** result (PL-13 13.6/⑥ §4):
    /// `result` = `deleted` (segment row + object + manifest deleted) | `error` (any delete failed;
    /// the index row is kept for the next round). Low cardinality (2 values).
    pub media_record_gc_total: IntCounterVec,
    /// Index rows deleted by the most recent media recording GC round (0 = no expired data/reclamation disabled; for dashboards).
    pub media_record_gc_rows: IntGauge,
    /// Media recording retrieval/download API result: `endpoint` = `list`|`detail`|`download`|`manifest`;
    /// `result` = `ok`|`not_found`|`forbidden`|`error` (low cardinality; auth failures count as 401/403).
    pub media_recording_api_total: IntCounterVec,
    /// QUIC server relay skeleton (PL-13 13.3 / design §17.9 path ②): active QUIC connections.
    ///
    /// Always 0 when `[quic] enabled` is off or the `quic` feature is absent at compile time (the metric name is always exposed so dashboards/alerts can wire up first).
    pub quic_connections: IntGauge,
    /// Active QUIC relay streams (registered and not yet closed `stream_id`s); cap from `[media] max_streams` (default 5000).
    pub quic_streams_active: IntGauge,
    /// QUIC relay bytes; `direction` ∈ in (node received from client)/ out (node forwarded to peer).
    pub quic_bytes_total: IntCounterVec,
    /// QUIC relay drop/reject count; `reason` ∈ bitrate (token bucket exceeded)/ quota (stream cap)/
    /// token (registration ticket mismatch/expired/used)/ bad_request (invalid registration frame)/ auth (JWT/device/participant auth failure)/
    /// closed (bye/disconnect cleanup).
    pub quic_dropped_total: IntCounterVec,
    /// QUIC registration result count; `result` ∈ ok / quota / token / bad_request / auth (auth rejected).
    pub quic_register_total: IntCounterVec,
    /// QUIC proxy registration auth result (PL-13 13.3 JWT/device binding):
    /// `result` ∈ ok (JWT+device+participant checks passed) | expired (JWT expired) |
    /// bad_jwt (missing/bad signature/bad issuer/invalid claims) | device_mismatch (device not owned by the user/fingerprint mismatch/revoked) |
    /// not_participant (user+device is not a participant of the stream-sig session, or the role does not match).
    pub quic_auth_total: IntCounterVec,
    /// WebTransport(HTTP/3) browser gateway (PL-13 13.3) active sessions: WT CONNECT accepted and
    /// the bridge task running (cap from the `[media] max_streams` QUIC registry; not duplicated at this layer).
    pub webtransport_sessions_active: IntGauge,
    /// WebTransport session result count: `result` ∈ ok (bridge finished normally) | path (CONNECT path is not /media) |
    /// handshake (HTTP/3/TLS handshake failed) | auth (JWT/device/participant auth failed) | token (join token rejected) |
    /// quota (stream cap) | bad_request (invalid registration frame/stream) | closed (client disconnect/bridge failure) |
    /// error (upstream QUIC connection failure and other internal errors).
    pub webtransport_sessions_total: IntCounterVec,
    /// WebTransport registration auth result (**same convention as QUIC**; the bridge only observes/counts, auth happens in the QUIC layer):
    /// `result` ∈ ok|expired|bad_jwt|device_mismatch|not_participant.
    pub webtransport_auth_total: IntCounterVec,
    /// WebTransport bridge bytes (CONTROL/DATA payload scope, the same media bytes as the QUIC relay counter):
    /// `direction` ∈ in (node received from browser) / out (node forwarded to browser).
    pub webtransport_bytes_total: IntCounterVec,
    /// Admin-plane key rotation (⑤ §8.4 / PL-03): `target`=jwt|kek|internal_ca;
    /// `result`=ok|key_dir_readonly|audit_error|error|not_implemented.
    pub key_rotate_total: IntCounterVec,
    /// JWT verification failures (low cardinality by reason: expired|signature|claims|malformed); anomaly alert basis.
    pub key_verification_failures_total: IntCounterVec,
    /// MQTT outbound QoS1 retransmission (PL-11): `result` ∈ retransmit|exhausted.
    ///
    /// `retransmit` = resend once with DUP=1 after a timeout; `exhausted` = retransmission cap reached and the gateway disconnects the connection.
    pub mqtt_publish_retransmit_total: IntCounterVec,
    /// Messages from the MQTT offline pending queue successfully enqueued downstream for redelivery (PL-11 11.11).
    pub mqtt_pending_replay_total: IntCounter,
    /// MQTT inbound persist failures (low-cardinality reason: rate|forbidden|persist|protocol|other).
    /// On failure a QoS1 inbound message does not get a success PUBACK (MQTT5 returns a failure reason code), avoiding "ACKed but never stored".
    pub mqtt_ingest_failed_total: IntCounterVec,
    /// MQTT QoS2 state machine count (PL-11 addition): `phase` ∈ pubrec (inbound replied PUBREC) |
    /// pubrel (outbound sent PUBREL) | pubcomp (inbound replied PUBCOMP after persist) | error (protocol/unknown packet id).
    pub mqtt_qos2_total: IntCounterVec,
    /// MQTT session persistence result: `result` ∈ restored (clean=false reconnect restored) | cleaned (clean=true cleared the session).
    pub mqtt_session_total: IntCounterVec,
    /// MQTT WILL publish count (abnormal disconnect / Disconnect with Will that actually published successfully; no labels).
    pub mqtt_will_total: IntCounter,
    /// MQTT retained count: `result` ∈ stored (saved/overwritten) | deleted (empty payload cleared) |
    /// delivered (one retained message delivered on subscribe).
    pub mqtt_retained_total: IntCounterVec,
    /// MQTT wildcard subscription match count (PL-11 wildcard addition): `result` ∈
    /// match (wildcard filter matched a message and delivered it) | mismatch (Redis-mode candidate message did not match the filter) |
    /// invalid (invalid wildcard filter rejected by SUBACK).
    ///
    /// Low cardinality (3 values); filter/topic never become labels.
    pub mqtt_wildcard_total: IntCounterVec,
    /// MQTT shared subscription delivery count (`$share/{group}/{filter}`): `result` ∈
    /// delivered (round-robin picked an active member of the group and delivered) | skipped (no available member/all stuck, message dropped).
    pub mqtt_shared_total: IntCounterVec,
    /// MQTT 5 Topic Alias count: `result` ∈ set (a PUBLISH established/updated the alias→topic mapping) |
    /// used (a PUBLISH with an empty topic resolved the topic from the alias) | error (alias=0, over the cap, unknown alias,
    /// conflicting mapping — all protocol errors; MQTT 5 returns DISCONNECT 0x94).
    pub mqtt_alias_total: IntCounterVec,
    /// MQTT 5 Receive Maximum (more PL-11 additions): `result` ∈
    /// allowed (in-flight count for outbound QoS1/2 PUBLISH is within the client cap, sending allowed) |
    /// throttled (in-flight count reached the client Receive Maximum; packets enter bounded queueing until PUBACK/PUBREC/PUBCOMP
    /// releases quota; overflow of the queue cap disconnects the connection) |
    /// violation (protocol violation: CONNECT Receive Maximum=0 rejected with CONNACK 0x82; or the client's
    /// QoS1/2 inbound in-flight count exceeds the Receive Maximum announced in the server CONNACK → DISCONNECT 0x93).
    pub mqtt_receive_max_total: IntCounterVec,
    /// MQTT 5 Subscription Identifier count (subscriptions that carried a valid 0x0B property and were granted,
    /// no labels; whether an outbound PUBLISH carries the identifier is decided by the subscription table and is not counted here).
    pub mqtt_sub_id_total: IntCounter,
    /// MQTT 5 **outbound** Topic Alias count: `result` ∈ set (the first PUBLISH established the topic→alias mapping,
    /// with a non-empty topic + alias) | used (subsequent PUBLISH compresses with an empty topic + alias) |
    /// disabled (feature off in config or the client's Topic Alias Maximum=0, so compression is not enabled).
    pub mqtt_out_alias_total: IntCounterVec,
    /// MQTT TLS listener result (PL-11 mTLS): `result` ∈ ok (TLS handshake succeeded, including client certificate chain validation) |
    /// fail (handshake failed/timed out/certificate rejected). Always 0 when TLS is not enabled (the metric name is always exposed).
    pub mqtt_tls_connections_total: IntCounterVec,
    /// MQTT TLS client certificate auth result (PL-11 mTLS): `result` ∈
    /// `ok` (certificate identity mapped + CONNECT username/device match) |
    /// `no_cert` (require_client_cert=true but the client presented no certificate) |
    /// `bad_cert` (certificate chain/validity/signature check failed; rejected during the TLS handshake) |
    /// `unknown_identity` (no parsable lattice identity in the certificate, or user/device does not exist) |
    /// `device_mismatch` (device does not belong to that user / revoked / CONNECT username/device does not match the certificate).
    pub mqtt_tls_auth_total: IntCounterVec,
    /// Audit write entry (② §4.8 / PL-14): `result` = ok (NATS Stream acked) |
    /// fallback (bus publish failed/unavailable → direct PG write succeeded) | direct (Redis bus mode: per design,
    /// write PG directly without attempting publish) | error (both publish and direct write failed; audit may be lost → alert).
    pub audit_publish_total: IntCounterVec,
    /// Audit consume result: `result` = ok (persisted) | duplicate (idempotent hit) | retry (PG briefly unavailable,
    /// NAK redelivery) | poison (malformed message → DLQ) | dlq (retries exhausted → DLQ).
    pub audit_consume_total: IntCounterVec,
    /// Audit consumer approximate lag (server-side pending count, refreshed as it consumes; 0 = no backlog).
    pub audit_consumer_lag: IntGauge,
    /// Number of audit events entering the DLQ (minimal implementation here = ERROR log + this counter; there is no separate DLQ table).
    pub audit_dlq_total: IntCounter,
    /// Session membership positive cache (PL-17 bottleneck fix): `result` ∈ hit|miss|invalidate.
    ///
    /// Low-cardinality labels (3 values): hit=cache hit, pass through/return directly; miss=cache miss, query PG;
    /// invalidate=times the membership-change API actively invalidated (join/remove/leave/subscription change). Not recorded when the cache is off.
    pub member_cache_total: IntCounterVec,
    /// Number of commands issued by Redis prefix scans (`SCAN`) (PL-17: quantifies the effect of SCAN batching).
    ///
    /// The unit is **SCAN roundtrips** (one round = one `SCAN cursor MATCH ... COUNT ...`),
    /// not the returned key count; a larger keyspace and smaller COUNT mean a higher count. No labels (no high-cardinality dimension).
    pub redis_scan_calls_total: IntCounter,
    /// Risk-control engine hit count (E03 / PL-12 12.6): `rule` ∈ message_flood|device_switch|
    /// auth_failure_surge (low-cardinality rule names); `action` ∈ audit|throttle|reauth (actual disposition;
    /// an auth-failure surge has no trustworthy user identity → forced audit). Always 0 when risk control is off.
    pub risk_events_total: IntCounterVec,

    // ---- E02: compliance purge cascade residual cleanup ----
    /// Compliance purge cascade cleanup result (E02 / ⑤ §8.2): `result` ∈
    /// `objects_ok` (object batch deletion done) | `objects_error` (some objects could not be deleted; PG rows kept for the next round) |
    /// `redis_ok` (user/device-dimension Redis keys cleaned) | `redis_error` (Redis scan/delete failed) |
    /// `user_deleted` (hard-delete window expired, user row deleted) | `user_error` (hard delete failed, retried next round).
    ///
    /// Low cardinality (6 fixed values), touched to 0 at startup.
    pub purge_cleanup_total: IntCounterVec,
    /// purge object deletion detail (E02 failure/retry semantics): `result` ∈ `deleted` (success, including idempotent 404) |
    /// `failed` (failure; the matching message rows are kept and retried next round, producing no "rows gone, object still there" leak).
    pub purge_objects_total: IntCounterVec,
    /// Deleted users **hard-deleted** by the most recent hard-delete job round (0 when the window is closed/no due users).
    pub purge_cleanup_users: IntGauge,

    // ---- E04: residual multipart GC ----
    /// `lock:gc-multipart` reclamation result (E04 / ⑥ §2.6): `result` ∈
    /// `aborted` (this round aborted ≥1 aged unfinished upload) | `skipped` (enabled but nothing aged this round,
    /// or not enabled/nothing listed) | `error` (list/abort failed, retried next round).
    ///
    /// Only **unfinished** uploads returned by ListMultipartUploads are aborted; completed objects are not in that list,
    /// so growth of this metric does not mean any completed object was deleted.
    pub multipart_gc_total: IntCounterVec,
    /// Unfinished uploads found (scanned) by the most recent residual multipart GC round (including not-aged ones, which are not aborted).
    pub multipart_gc_uploads: IntGauge,

    // ---- E01: storage lifecycle (cold archive + orphan object GC) ----
    /// Whether the cold archive switch is active (1/0; off by default = 0, and then no job is spawned and no IO is done).
    pub archive_enabled: IntGauge,
    /// Cold archive round result (E01 / ⑥ §2.5 `lock:archive`): `result` ∈
    /// `ok` (this round produced at least one archive object/completed one DETACH, or confirmed no expired data) |
    /// `error` (upload/DDL failed; data kept for the next round) | `paused` (MinIO unavailable, round short-circuited).
    pub archive_rounds_total: IntCounterVec,
    /// Archived row counts: `result` ∈ `archived` (messages rows exported and removed from the online table/partition) |
    /// `dedup_exported` (message_dedup rows exported together with the messages) | `failed` (rows of the failed batch this round).
    pub archive_rows_total: IntCounterVec,
    /// Archived partition result: `result` ∈ `detached` (DETACHed after a successful export/upload) |
    /// `failed` (export/upload/DDL failed; partition kept) | `skipped` (retention not reached).
    pub archive_partitions_total: IntCounterVec,
    /// Archive object upload detail: `result` ∈ `uploaded` (success, including overwrite retries) | `failed`.
    pub archive_objects_total: IntCounterVec,
    /// Unix timestamp of the most recent successfully completed archive round (seconds; 0 = never completed successfully).
    pub archive_last_success_unixtime: IntGauge,
    /// Cold-bucket orphan object GC result (E01 / ⑥ §4.1 `lock:gc-objects`): `result` ∈
    /// `deleted` (no live reference, deleted) | `referenced` (still referenced by payload_ref/storage_key,
    /// skipped) | `protected` (archive/backup namespace or grace period not elapsed, skipped) | `error` (delete failed).
    pub archive_object_gc_total: IntCounterVec,
    /// Cold-bucket objects scanned by the most recent orphan GC round.
    pub archive_object_gc_scanned: IntGauge,

    // ---- E31: pipeline stage bypass ----
    /// Stage bypass count (`stage` ∈ `crate::config::PIPELINE_STAGES`). Always 0 in normal production;
    /// with `[pipeline] bypass` enabled for debugging/emergency, each skipped stage entry adds 1 (E2E asserts "only that stage was bypassed").
    pub pipeline_bypass_total: IntCounterVec,

    // ---- E15: inspectable node-local KEK ----
    /// Whether `[inspectable] enabled` is active (1/0; process startup load result; disabled = always 0).
    pub inspectable_enabled: IntGauge,
    /// Whether the node-local KEK is loaded and passed the startup self-check (1/0; production KMS not wired, not loaded = always 0).
    pub inspectable_kek_loaded: IntGauge,
    /// Locator info of the loaded KEK: `kek_id` + `fingerprint` (sha256 prefix, no material) + `role`
    /// (active|previous). Exposes 1 only for a loaded KEK; previous is also visible inside the rotation window.
    pub inspectable_kek_info: IntGaugeVec,
    /// KEK audit hook counts: `action` ∈ inspectable.wrap|inspectable.unwrap|inspectable.rekey,
    /// `result` ∈ ok|denied|error. The startup self-check itself produces counts (wrap/unwrap, plus rekey when previous is configured);
    /// the events carry no KEK/DEK/plaintext.
    pub inspectable_audit_total: IntCounterVec,
}

impl Metrics {
    /// Build the metric registry; inspectable KEK load info comes from the process-level snapshot (E15).
    pub fn new() -> Arc<Self> {
        Self::build(crate::pipeline::inspectable::metrics_snapshot())
    }

    /// Constructor that injects an inspectable snapshot (unit tests: no dependency on process-level `Config::load` state).
    fn build(inspectable_snapshot: crate::pipeline::inspectable::InspectableSnapshot) -> Arc<Self> {
        let registry = Registry::new();
        let connections = IntGaugeVec::new(
            Opts::new("lattice_connections", "Active connections"),
            &["protocol", "state"],
        )
        .unwrap();
        let msgs_total = IntCounterVec::new(
            Opts::new("lattice_msgs_total", "Message count"),
            &["direction", "env_type", "state"],
        )
        .unwrap();
        let e2e_latency = Histogram::with_opts(
            HistogramOpts::new("lattice_e2e_latency_seconds", "End-to-end latency (seconds)")
                .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
        )
        .unwrap();
        let pending_depth = IntGaugeVec::new(
            Opts::new("lattice_pending_depth", "Offline queue depth"),
            &["scope", "user_hash"],
        )
        .unwrap();
        let chunk_retrans_total = IntCounterVec::new(
            Opts::new("lattice_chunk_retrans_total", "Chunk retransmission count"),
            &["reason"],
        )
        .unwrap();
        let plugin_call_duration = Histogram::with_opts(
            HistogramOpts::new("lattice_plugin_call_duration_seconds", "Plugin call duration (seconds)")
                .buckets(vec![0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]),
        )
        .unwrap();
        // Plugin WASM host (PL-10 / design ② §4.5): load/verify/invoke/circuit metrics.
        // Signature-verification labels are touched first so they are exposed as 0 the moment the process starts (E2E/alerts assert by name).
        let plugin_wasm_loaded = IntGauge::new(
            "lattice_plugin_wasm_loaded",
            "Number of loaded WASM plugins (directory + PG registry sources)",
        )
        .unwrap();
        let plugin_wasm_verified = IntGauge::new(
            "lattice_plugin_wasm_verified",
            "Number of loaded WASM plugins that passed Ed25519 signature verification",
        )
        .unwrap();
        let plugin_wasm_rejected_total = IntCounterVec::new(
            Opts::new(
                "lattice_plugin_wasm_rejected_total",
                "WASM plugin registration rejection count (reason=manifest|signature|missing_export|conflict|…)",
            ),
            &["reason"],
        )
        .unwrap();
        // Source counts (dir|pg): doc ② §4.5 requires "load results observable by source".
        // Label values are fixed (low cardinality); an initial touch exposes them as 0 from process start.
        let plugin_wasm_source_total = IntCounterVec::new(
            Opts::new(
                "lattice_plugin_wasm_source_total",
                "WASM plugin load results by source (source=dir|pg; result=loaded|rejected|skipped)",
            ),
            &["source", "result"],
        )
        .unwrap();
        for source in ["dir", "pg"] {
            for result in ["loaded", "rejected", "skipped"] {
                plugin_wasm_source_total.with_label_values(&[source, result]);
            }
        }
        let plugin_wasm_signature_total = IntCounterVec::new(
            Opts::new(
                "lattice_plugin_wasm_signature_total",
                "WASM plugin signature verification count (result=verified|invalid|missing)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["verified", "invalid", "missing"] {
            plugin_wasm_signature_total.with_label_values(&[result]);
        }
        let plugin_wasm_invocations_total = IntCounterVec::new(
            Opts::new(
                "lattice_plugin_wasm_invocations_total",
                "admin invoke call count (outcome=ok|not_found|not_verified|circuit_open|timeout|trap|memory|fuel|…)",
            ),
            &["plugin", "outcome"],
        )
        .unwrap();
        let plugin_wasm_invoke_duration = HistogramVec::new(
            HistogramOpts::new(
                "lattice_plugin_wasm_invoke_duration_seconds",
                "admin invoke plugin call duration (seconds)",
            )
            .buckets(vec![0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0]),
            &["plugin"],
        )
        .unwrap();
        let plugin_wasm_circuit_trips_total = IntCounterVec::new(
            Opts::new(
                "lattice_plugin_wasm_circuit_trips_total",
                "WASM plugin circuit-breaker trip count (per plugin)",
            ),
            &["plugin"],
        )
        .unwrap();
        // Hot reload (PL-10 hot reload): result count + duration; label values fixed (low cardinality), touched at startup so 0 is visible.
        let plugin_wasm_reload_total = IntCounterVec::new(
            Opts::new(
                "lattice_plugin_wasm_reload_total",
                "WASM plugin hot-reload result count (result=ok|error; error includes 409/429/build failure)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["ok", "error"] {
            plugin_wasm_reload_total.with_label_values(&[result]);
        }
        let plugin_wasm_reload_duration = Histogram::with_opts(
            HistogramOpts::new(
                "lattice_plugin_wasm_reload_duration_seconds",
                "WASM plugin hot-reload duration (seconds; build new snapshot to atomic swap)",
            )
            .buckets(vec![0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
        )
        .unwrap();
        let ratelimit_dropped_total = IntCounterVec::new(
            Opts::new("lattice_ratelimit_dropped_total", "Rate-limit drop count"),
            &["user_hash"],
        )
        .unwrap();
        let backpressure_dropped_total = IntCounterVec::new(
            Opts::new("lattice_backpressure_dropped_total", "Backpressure drop count"),
            &["priority"],
        )
        .unwrap();
        // Dropped protected-set frames (receipt/ack/stream-sig/byef) are counted separately: 0 under normal backpressure,
        // and alerted separately from ordinary frame drops (⑤ §9.5; labels keep priority=command name).
        let backpressure_protected_dropped_total = IntCounterVec::new(
            Opts::new(
                "lattice_backpressure_protected_dropped_total",
                "Backpressure drop count for protected-set frames (receipt/ack/stream-sig/byef)",
            ),
            &["priority"],
        )
        .unwrap();
        // HTTP idempotency middleware result (⑤ §0.3 / E12): the 5 low-cardinality values are touched to 0 at startup,
        // ensuring the metric is exposed as 0 right after start/before traffic (E2E/dashboards assert by name).
        let http_idempotency_total = IntCounterVec::new(
            Opts::new(
                "lattice_http_idempotency_total",
                "HTTP Idempotency-Key middleware result (result=hit|miss|conflict|in_progress|error)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["hit", "miss", "conflict", "in_progress", "error"] {
            http_idempotency_total.with_label_values(&[result]);
        }
        let store_latency = Histogram::with_opts(
            HistogramOpts::new("lattice_store_latency_seconds", "Storage access latency (seconds)")
                .buckets(vec![0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]),
        )
        .unwrap();
        let wal_size_bytes =
            IntGauge::new("lattice_wal_size_bytes", "Local WAL size (bytes)").unwrap();
        let wal_append_total = IntCounterVec::new(
            Opts::new("lattice_wal_append_total", "Local WAL append count"),
            &["result"],
        )
        .unwrap();
        let wal_replay_total = IntCounterVec::new(
            Opts::new("lattice_wal_replay_total", "Local WAL replay count"),
            &["result"],
        )
        .unwrap();
        let wal_dropped_total =
            IntCounter::new("lattice_wal_dropped_total", "Messages not written to the local WAL").unwrap();
        let dedup_hit_total = IntCounterVec::new(
            Opts::new("lattice_dedup_hit_total", "Dedup hit count"),
            &["layer"],
        )
        .unwrap();
        let protocol_version = IntGaugeVec::new(
            Opts::new("lattice_protocol_version", "Client protocol version distribution"),
            &["version"],
        )
        .unwrap();
        let sse_connections =
            IntGauge::new("lattice_sse_connections", "Console SSE connection count").unwrap();
        let http_requests_total = IntCounterVec::new(
            Opts::new("lattice_http_requests_total", "HTTP request count"),
            &["path", "status"],
        )
        .unwrap();
        let grpc_fallback_total = IntCounterVec::new(
            Opts::new("lattice_grpc_route_fallback_total", "gRPC fallback routing count"),
            &["method", "result"],
        )
        .unwrap();
        let route_cache_stale_total =
            IntCounter::new("lattice_route_cache_stale_total", "Times the stale route cache was used").unwrap();
        // Media recording tee (PL-13 13.6): dropped frames/segments/bytes/failures
        let media_record_dropped_total = IntCounter::new(
            "lattice_media_record_dropped_total",
            "Dropped frames because the media recording tee queue was full/closed",
        )
        .unwrap();
        let media_record_segments_total = IntCounter::new(
            "lattice_media_record_segments_total",
            "Segments successfully written to object storage by media recording",
        )
        .unwrap();
        let media_record_bytes_total = IntCounter::new(
            "lattice_media_record_bytes_total",
            "Bytes successfully written to object storage by media recording",
        )
        .unwrap();
        let media_record_errors_total =
            IntCounter::new("lattice_media_record_errors_total", "Media recording object-storage write failure count")
                .unwrap();
        // Media recording bus (PL-13 13.6): publish result / consume result / consumer lag.
        // Labels are touched first so metrics are exposed as 0 right after process start (E2E/alerts assert by name).
        let media_record_publish_total = IntCounterVec::new(
            Opts::new(
                "lattice_media_record_publish_total",
                "Media recording bus publish result (result=ok|fallback|direct|error)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["ok", "fallback", "direct", "error"] {
            media_record_publish_total.with_label_values(&[result]);
        }
        let media_record_consume_total = IntCounterVec::new(
            Opts::new(
                "lattice_media_record_consume_total",
                "Media recording bus consume result (result=ok|duplicate|other_node|retry|dlq|poison)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["ok", "duplicate", "other_node", "retry", "dlq", "poison"] {
            media_record_consume_total.with_label_values(&[result]);
        }
        let media_record_consumer_lag = IntGauge::new(
            "lattice_media_record_consumer_lag",
            "Media recording consumer approximate lag (pending count)",
        )
        .unwrap();
        media_record_consumer_lag.set(0);
        // Media recording index + retrieval/download API (PL-13 13.6): labels are touched too, exposed at startup.
        let media_record_index_total = IntCounterVec::new(
            Opts::new(
                "lattice_media_record_index_total",
                "Media recording segment index write result (result=ok|dup|error)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["ok", "dup", "error"] {
            media_record_index_total.with_label_values(&[result]);
        }
        // Manifest + lifecycle GC: labels are touched too, exposed at startup.
        let media_record_manifest_total = IntCounterVec::new(
            Opts::new(
                "lattice_media_record_manifest_total",
                "Media recording manifest write result (result=ok|error)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["ok", "error"] {
            media_record_manifest_total.with_label_values(&[result]);
        }
        let media_record_gc_total = IntCounterVec::new(
            Opts::new(
                "lattice_media_record_gc_total",
                "Media recording lifecycle GC result (result=deleted|error)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["deleted", "error"] {
            media_record_gc_total.with_label_values(&[result]);
        }
        let media_record_gc_rows = IntGauge::new(
            "lattice_media_record_gc_rows",
            "Index rows deleted by the most recent media recording lifecycle GC round",
        )
        .unwrap();
        media_record_gc_rows.set(0);
        let media_recording_api_total = IntCounterVec::new(
            Opts::new(
                "lattice_media_recording_api_total",
                "Media recording retrieval/download API result (endpoint=list|detail|download|manifest; result=ok|not_found|forbidden|error)",
            ),
            &["endpoint", "result"],
        )
        .unwrap();
        for endpoint in ["list", "detail", "download", "manifest"] {
            for result in ["ok", "not_found", "forbidden", "error"] {
                media_recording_api_total
                    .with_label_values(&[endpoint, result]);
            }
        }
        // QUIC server relay skeleton (PL-13 13.3): connections/active streams/bytes/drops/registration results.
        // Labels are touched first so metrics are exposed as 0 right after process start (E2E/alerts assert by name).
        let quic_connections =
            IntGauge::new("lattice_quic_connections", "Active QUIC connection count").unwrap();
        let quic_streams_active = IntGauge::new(
            "lattice_quic_streams_active",
            "Active QUIC relay stream count (cap from [media] max_streams)",
        )
        .unwrap();
        let quic_bytes_total = IntCounterVec::new(
            Opts::new(
                "lattice_quic_bytes_total",
                "QUIC relay bytes (direction=in received / out forwarded)",
            ),
            &["direction"],
        )
        .unwrap();
        for direction in ["in", "out"] {
            quic_bytes_total.with_label_values(&[direction]);
        }
        let quic_dropped_total = IntCounterVec::new(
            Opts::new(
                "lattice_quic_dropped_total",
                "QUIC relay drop/reject count (reason=bitrate|quota|token|bad_request|closed)",
            ),
            &["reason"],
        )
        .unwrap();
        for reason in ["bitrate", "quota", "token", "bad_request", "auth", "closed"] {
            quic_dropped_total.with_label_values(&[reason]);
        }
        let quic_register_total = IntCounterVec::new(
            Opts::new(
                "lattice_quic_register_total",
                "QUIC registration result (result=ok|quota|token|bad_request)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["ok", "quota", "token", "bad_request", "auth"] {
            quic_register_total.with_label_values(&[result]);
        }
        // Touch the auth-result labels first: exposed as 0 from process start (E2E/alerts assert by result name).
        let quic_auth_total = IntCounterVec::new(
            Opts::new(
                "lattice_quic_auth_total",
                "QUIC registration auth result (result=ok|expired|bad_jwt|device_mismatch|not_participant)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["ok", "expired", "bad_jwt", "device_mismatch", "not_participant"] {
            quic_auth_total.with_label_values(&[result]);
        }
        // WebTransport(HTTP/3) browser gateway (PL-13 13.3): sessions/auth/bridge bytes.
        // Metric names match the task card; labels are touched first so they are exposed as 0 at process start (E2E/dashboards assert by name).
        let webtransport_sessions_active = IntGauge::new(
            "lattice_webtransport_sessions_active",
            "Active WebTransport bridge sessions",
        )
        .unwrap();
        let webtransport_sessions_total = IntCounterVec::new(
            Opts::new(
                "lattice_webtransport_sessions_total",
                "WebTransport session result count (result=ok|path|handshake|auth|token|quota|bad_request|closed|error)",
            ),
            &["result"],
        )
        .unwrap();
        for result in [
            "ok",
            "path",
            "handshake",
            "auth",
            "token",
            "quota",
            "bad_request",
            "closed",
            "error",
        ] {
            webtransport_sessions_total.with_label_values(&[result]);
        }
        let webtransport_auth_total = IntCounterVec::new(
            Opts::new(
                "lattice_webtransport_auth_total",
                "WebTransport registration auth result (result=ok|expired|bad_jwt|device_mismatch|not_participant)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["ok", "expired", "bad_jwt", "device_mismatch", "not_participant"] {
            webtransport_auth_total.with_label_values(&[result]);
        }
        let webtransport_bytes_total = IntCounterVec::new(
            Opts::new(
                "lattice_webtransport_bytes_total",
                "WebTransport bridge bytes (direction=in received / out forwarded)",
            ),
            &["direction"],
        )
        .unwrap();
        for direction in ["in", "out"] {
            webtransport_bytes_total.with_label_values(&[direction]);
        }
        // Key rotation and verification failures (PL-03 / ⑤ §8.4)
        let key_rotate_total = IntCounterVec::new(
            Opts::new("lattice_key_rotate_total", "Key rotation count (by target and result)"),
            &["target", "result"],
        )
        .unwrap();
        let key_verification_failures_total = IntCounterVec::new(
            Opts::new(
                "lattice_key_verification_failures_total",
                "JWT verification failure count (by reason)",
            ),
            &["reason"],
        )
        .unwrap();
        // MQTT reliability (PL-11): outbound retransmit / offline redelivery / inbound persist failures
        let mqtt_publish_retransmit_total = IntCounterVec::new(
            Opts::new(
                "lattice_mqtt_publish_retransmit_total",
                "MQTT outbound QoS1 retransmission count (result=retransmit|exhausted)",
            ),
            &["result"],
        )
        .unwrap();
        let mqtt_pending_replay_total = IntCounter::new(
            "lattice_mqtt_pending_replay_total",
            "Messages redelivered downstream from the MQTT offline pending queue",
        )
        .unwrap();
        let mqtt_ingest_failed_total = IntCounterVec::new(
            Opts::new(
                "lattice_mqtt_ingest_failed_total",
                "MQTT inbound persist failure count (by reason)",
            ),
            &["reason"],
        )
        .unwrap();
        // QoS2 / persistent session / WILL / retained (PL-11 additions); label values are touched so zeros are exposed.
        let mqtt_qos2_total = IntCounterVec::new(
            Opts::new(
                "lattice_mqtt_qos2_total",
                "MQTT QoS2 state machine count (phase=pubrec|pubrel|pubcomp|error)",
            ),
            &["phase"],
        )
        .unwrap();
        for phase in ["pubrec", "pubrel", "pubcomp", "error"] {
            mqtt_qos2_total.with_label_values(&[phase]);
        }
        let mqtt_session_total = IntCounterVec::new(
            Opts::new(
                "lattice_mqtt_session_total",
                "MQTT persistent session result (result=restored|cleaned)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["restored", "cleaned"] {
            mqtt_session_total.with_label_values(&[result]);
        }
        let mqtt_will_total = IntCounter::new(
            "lattice_mqtt_will_total",
            "Count of actual MQTT WILL publishes (abnormal disconnect / Disconnect with Will)",
        )
        .unwrap();
        let mqtt_retained_total = IntCounterVec::new(
            Opts::new(
                "lattice_mqtt_retained_total",
                "MQTT retained count (result=stored|deleted|delivered)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["stored", "deleted", "delivered"] {
            mqtt_retained_total.with_label_values(&[result]);
        }
        // Wildcards / shared subscriptions / Topic Alias (more PL-11 additions): label values are touched too.
        let mqtt_wildcard_total = IntCounterVec::new(
            Opts::new(
                "lattice_mqtt_wildcard_total",
                "MQTT wildcard subscription match count (result=match|mismatch|invalid)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["match", "mismatch", "invalid"] {
            mqtt_wildcard_total.with_label_values(&[result]);
        }
        let mqtt_shared_total = IntCounterVec::new(
            Opts::new(
                "lattice_mqtt_shared_total",
                "MQTT shared subscription delivery count (result=delivered|skipped)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["delivered", "skipped"] {
            mqtt_shared_total.with_label_values(&[result]);
        }
        let mqtt_alias_total = IntCounterVec::new(
            Opts::new(
                "lattice_mqtt_alias_total",
                "MQTT 5 Topic Alias count (result=set|used|error)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["set", "used", "error"] {
            mqtt_alias_total.with_label_values(&[result]);
        }
        // MQTT 5 Receive Maximum / Subscription Identifier / outbound Topic Alias (more PL-11 additions).
        // Label values are touched first, ensuring metrics are exposed as 0 right after process start (E2E asserts by name).
        let mqtt_receive_max_total = IntCounterVec::new(
            Opts::new(
                "lattice_mqtt_receive_max_total",
                "MQTT 5 Receive Maximum flow-control count (result=allowed|throttled|violation)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["allowed", "throttled", "violation"] {
            mqtt_receive_max_total.with_label_values(&[result]);
        }
        let mqtt_sub_id_total = IntCounter::new(
            "lattice_mqtt_sub_id_total",
            "MQTT 5 Subscription Identifier grant count (subscriptions carrying a valid identifier)",
        )
        .unwrap();
        let mqtt_out_alias_total = IntCounterVec::new(
            Opts::new(
                "lattice_mqtt_out_alias_total",
                "MQTT 5 outbound Topic Alias count (result=set|used|disabled)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["set", "used", "disabled"] {
            mqtt_out_alias_total.with_label_values(&[result]);
        }
        // TLS/mTLS (PL-11): connection (handshake) result + client certificate auth result; labels touched so zeros are exposed.
        let mqtt_tls_connections_total = IntCounterVec::new(
            Opts::new(
                "lattice_mqtt_tls_connections_total",
                "MQTT TLS listener handshake result (result=ok|fail)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["ok", "fail"] {
            mqtt_tls_connections_total.with_label_values(&[result]);
        }
        let mqtt_tls_auth_total = IntCounterVec::new(
            Opts::new(
                "lattice_mqtt_tls_auth_total",
                "MQTT TLS client certificate auth result (result=ok|no_cert|bad_cert|unknown_identity|device_mismatch)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["ok", "no_cert", "bad_cert", "unknown_identity", "device_mismatch"] {
            mqtt_tls_auth_total.with_label_values(&[result]);
        }
        // Audit stream (② §4.8 / PL-14 / PL-11): write-entry publish result / consume result / lag / DLQ.
        // The result labels are touched first, ensuring metrics are exposed as 0 right after process start (E2E/alerts assert by name).
        let audit_publish_total = IntCounterVec::new(
            Opts::new(
                "lattice_audit_publish_total",
                "Audit write-entry result (result=ok|fallback|direct|error)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["ok", "fallback", "direct", "error"] {
            audit_publish_total.with_label_values(&[result]);
        }
        let audit_consume_total = IntCounterVec::new(
            Opts::new(
                "lattice_audit_consume_total",
                "Audit consume result (result=ok|duplicate|retry|poison|dlq)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["ok", "duplicate", "retry", "poison", "dlq"] {
            audit_consume_total.with_label_values(&[result]);
        }
        let audit_consumer_lag =
            IntGauge::new("lattice_audit_consumer_lag", "Audit consumer approximate lag (pending count)")
                .unwrap();
        audit_consumer_lag.set(0);
        let audit_dlq_total = IntCounter::new(
            "lattice_audit_dlq_total",
            "Number of audit events that entered the DLQ (ERROR log + this counter)",
        )
        .unwrap();
        // Session membership positive cache (PL-17 bottleneck fix): three low-cardinality values hit|miss|invalidate,
        // touched at startup so metrics are exposed as 0 right after process start (E2E/dashboards assert by name).
        let member_cache_total = IntCounterVec::new(
            Opts::new(
                "lattice_member_cache_total",
                "Session membership positive cache count (result=hit|miss|invalidate)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["hit", "miss", "invalidate"] {
            member_cache_total.with_label_values(&[result]);
        }
        // Redis SCAN command count (PL-17: quantifies the effect of SCAN COUNT batching; no labels).
        let redis_scan_calls_total = IntCounter::new(
            "lattice_redis_scan_calls_total",
            "Redis SCAN command (roundtrip) count (prefix scan; COUNT configurable)",
        )
        .unwrap();
        // Risk-control hits (E03): all combinations are touched at startup so metrics are exposed as 0 (dashboards/alerts can wire up first).
        let risk_events_total = IntCounterVec::new(
            Opts::new(
                "lattice_risk_events_total",
                "Risk-control rule hit count (rule=rule name, action=actual disposition)",
            ),
            &["rule", "action"],
        )
        .unwrap();
        for rule in ["message_flood", "device_switch", "auth_failure_surge"] {
            risk_events_total.with_label_values(&[rule, "audit"]);
        }
        // E02 compliance purge cascade cleanup: labels touched first, exposed as 0 at startup (E2E/alerts assert by name).
        let purge_cleanup_total = IntCounterVec::new(
            Opts::new(
                "lattice_purge_cleanup_total",
                "Compliance purge cascade cleanup result (result=objects_ok|objects_error|redis_ok|redis_error|user_deleted|user_error)",
            ),
            &["result"],
        )
        .unwrap();
        for result in [
            "objects_ok",
            "objects_error",
            "redis_ok",
            "redis_error",
            "user_deleted",
            "user_error",
        ] {
            purge_cleanup_total.with_label_values(&[result]);
        }
        let purge_objects_total = IntCounterVec::new(
            Opts::new(
                "lattice_purge_objects_total",
                "purge object delete detail (result=deleted|failed; failed keeps PG rows for the next round)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["deleted", "failed"] {
            purge_objects_total.with_label_values(&[result]);
        }
        let purge_cleanup_users = IntGauge::new(
            "lattice_purge_cleanup_users",
            "Deleted users hard-deleted by the most recent hard-delete window round",
        )
        .unwrap();
        purge_cleanup_users.set(0);
        // E04 residual multipart GC: labels touched first (result=aborted|skipped|error).
        let multipart_gc_total = IntCounterVec::new(
            Opts::new(
                "lattice_multipart_gc_total",
                "Residual multipart GC result (result=aborted|skipped|error; only unfinished uploads are aborted)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["aborted", "skipped", "error"] {
            multipart_gc_total.with_label_values(&[result]);
        }
        let multipart_gc_uploads = IntGauge::new(
            "lattice_multipart_gc_uploads",
            "Unfinished uploads scanned by the most recent residual multipart GC round",
        )
        .unwrap();
        multipart_gc_uploads.set(0);

        // E01 storage lifecycle (cold archive + orphan object GC): labels touched first, exposed as 0 at startup.
        let archive_enabled = IntGauge::new(
            "lattice_archive_enabled",
            "Whether the cold archive job is enabled (1/0; off by default = zero side effects)",
        )
        .unwrap();
        archive_enabled.set(0);
        let archive_rounds_total = IntCounterVec::new(
            Opts::new(
                "lattice_archive_rounds_total",
                "Cold archive round result (result=ok|error|paused; on error data is kept for the next round)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["ok", "error", "paused"] {
            archive_rounds_total.with_label_values(&[result]);
        }
        let archive_rows_total = IntCounterVec::new(
            Opts::new(
                "lattice_archive_rows_total",
                "Cold archive row counts (result=archived|dedup_exported|failed)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["archived", "dedup_exported", "failed"] {
            archive_rows_total.with_label_values(&[result]);
        }
        let archive_partitions_total = IntCounterVec::new(
            Opts::new(
                "lattice_archive_partitions_total",
                "Cold archive partition results (result=detached|failed|skipped)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["detached", "failed", "skipped"] {
            archive_partitions_total.with_label_values(&[result]);
        }
        let archive_objects_total = IntCounterVec::new(
            Opts::new(
                "lattice_archive_objects_total",
                "Cold archive object upload detail (result=uploaded|failed)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["uploaded", "failed"] {
            archive_objects_total.with_label_values(&[result]);
        }
        let archive_last_success_unixtime = IntGauge::new(
            "lattice_archive_last_success_unixtime",
            "Unix timestamp of the most recent successful cold archive round (seconds; 0 = never succeeded)",
        )
        .unwrap();
        archive_last_success_unixtime.set(0);
        let archive_object_gc_total = IntCounterVec::new(
            Opts::new(
                "lattice_archive_object_gc_total",
                "Cold-bucket orphan object GC result (result=deleted|referenced|protected|error)",
            ),
            &["result"],
        )
        .unwrap();
        for result in ["deleted", "referenced", "protected", "error"] {
            archive_object_gc_total.with_label_values(&[result]);
        }
        let archive_object_gc_scanned = IntGauge::new(
            "lattice_archive_object_gc_scanned",
            "Cold-bucket objects scanned by the most recent orphan object GC round",
        )
        .unwrap();
        archive_object_gc_scanned.set(0);

        // E31 pipeline stage bypass: valid stages touched to 0 first (exposed as 0 when not bypassed; E2E asserts by stage label).
        let pipeline_bypass_total = IntCounterVec::new(
            Opts::new(
                "lattice_pipeline_bypass_total",
                "Pipeline stage bypass count (stage=stage name; always 0 in normal production, [pipeline] bypass for debugging/emergency)",
            ),
            &["stage"],
        )
        .unwrap();
        for stage in crate::config::PIPELINE_STAGES {
            pipeline_bypass_total.with_label_values(&[stage]);
        }

        // E15 inspectable node-local KEK: load state/fingerprint + audit hook counts.
        // Load info comes from the process-level `inspectable::bootstrap` (written during `Config::load`; disabled/not loaded = all 0).
        let inspectable_enabled = IntGauge::new(
            "lattice_inspectable_enabled",
            "Whether inspectable mode is enabled ([inspectable] enabled; disabled = always 0)",
        )
        .unwrap();
        let inspectable_kek_loaded = IntGauge::new(
            "lattice_inspectable_kek_loaded",
            "Whether the node-local KEK is loaded and passed the startup self-check (1/0; production KMS not wired)",
        )
        .unwrap();
        let inspectable_kek_info = IntGaugeVec::new(
            Opts::new(
                "lattice_inspectable_kek_info",
                "Loaded KEK locator info (kek_id/fingerprint=sha256 prefix/role=active|previous; no key material)",
            ),
            &["kek_id", "fingerprint", "role"],
        )
        .unwrap();
        let inspectable_audit_total = IntCounterVec::new(
            Opts::new(
                "lattice_inspectable_audit_total",
                "inspectable KEK audit hook counts (action=inspectable.wrap|unwrap|rekey, result=ok|denied|error; events carry no plaintext)",
            ),
            &["action", "result"],
        )
        .unwrap();
        for action in [
            "inspectable.wrap",
            "inspectable.unwrap",
            "inspectable.rekey",
        ] {
            for result in ["ok", "denied", "error"] {
                inspectable_audit_total.with_label_values(&[action, result]);
            }
        }
        inspectable_enabled.set(if inspectable_snapshot.enabled { 1 } else { 0 });
        inspectable_kek_loaded.set(if inspectable_snapshot.kek_loaded { 1 } else { 0 });
        for (kek_id, fingerprint, role) in &inspectable_snapshot.keys {
            inspectable_kek_info
                .with_label_values(&[kek_id.as_str(), fingerprint.as_str(), role])
                .set(1);
        }
        for (action, result, count) in &inspectable_snapshot.audit_counts {
            if *count > 0 {
                inspectable_audit_total
                    .with_label_values(&[action, result])
                    .inc_by(*count);
            }
        }

        for m in [
            registry.register(Box::new(connections.clone())),
            registry.register(Box::new(msgs_total.clone())),
            registry.register(Box::new(e2e_latency.clone())),
            registry.register(Box::new(pending_depth.clone())),
            registry.register(Box::new(chunk_retrans_total.clone())),
            registry.register(Box::new(plugin_call_duration.clone())),
            registry.register(Box::new(plugin_wasm_loaded.clone())),
            registry.register(Box::new(plugin_wasm_verified.clone())),
            registry.register(Box::new(plugin_wasm_rejected_total.clone())),
            registry.register(Box::new(plugin_wasm_source_total.clone())),
            registry.register(Box::new(plugin_wasm_signature_total.clone())),
            registry.register(Box::new(plugin_wasm_invocations_total.clone())),
            registry.register(Box::new(plugin_wasm_invoke_duration.clone())),
            registry.register(Box::new(plugin_wasm_circuit_trips_total.clone())),
            registry.register(Box::new(plugin_wasm_reload_total.clone())),
            registry.register(Box::new(plugin_wasm_reload_duration.clone())),
            registry.register(Box::new(ratelimit_dropped_total.clone())),
            registry.register(Box::new(backpressure_dropped_total.clone())),
            registry.register(Box::new(backpressure_protected_dropped_total.clone())),
            registry.register(Box::new(http_idempotency_total.clone())),
            registry.register(Box::new(store_latency.clone())),
            registry.register(Box::new(wal_size_bytes.clone())),
            registry.register(Box::new(wal_append_total.clone())),
            registry.register(Box::new(wal_replay_total.clone())),
            registry.register(Box::new(wal_dropped_total.clone())),
            registry.register(Box::new(dedup_hit_total.clone())),
            registry.register(Box::new(protocol_version.clone())),
            registry.register(Box::new(sse_connections.clone())),
            registry.register(Box::new(http_requests_total.clone())),
            registry.register(Box::new(grpc_fallback_total.clone())),
            registry.register(Box::new(route_cache_stale_total.clone())),
            registry.register(Box::new(media_record_dropped_total.clone())),
            registry.register(Box::new(media_record_segments_total.clone())),
            registry.register(Box::new(media_record_bytes_total.clone())),
            registry.register(Box::new(media_record_errors_total.clone())),
            registry.register(Box::new(media_record_publish_total.clone())),
            registry.register(Box::new(media_record_consume_total.clone())),
            registry.register(Box::new(media_record_consumer_lag.clone())),
            registry.register(Box::new(media_record_index_total.clone())),
            registry.register(Box::new(media_record_manifest_total.clone())),
            registry.register(Box::new(media_record_gc_total.clone())),
            registry.register(Box::new(media_record_gc_rows.clone())),
            registry.register(Box::new(media_recording_api_total.clone())),
            registry.register(Box::new(quic_connections.clone())),
            registry.register(Box::new(quic_streams_active.clone())),
            registry.register(Box::new(quic_bytes_total.clone())),
            registry.register(Box::new(quic_dropped_total.clone())),
            registry.register(Box::new(quic_register_total.clone())),
            registry.register(Box::new(quic_auth_total.clone())),
            registry.register(Box::new(webtransport_sessions_active.clone())),
            registry.register(Box::new(webtransport_sessions_total.clone())),
            registry.register(Box::new(webtransport_auth_total.clone())),
            registry.register(Box::new(webtransport_bytes_total.clone())),
            registry.register(Box::new(key_rotate_total.clone())),
            registry.register(Box::new(key_verification_failures_total.clone())),
            registry.register(Box::new(mqtt_publish_retransmit_total.clone())),
            registry.register(Box::new(mqtt_pending_replay_total.clone())),
            registry.register(Box::new(mqtt_ingest_failed_total.clone())),
            registry.register(Box::new(mqtt_qos2_total.clone())),
            registry.register(Box::new(mqtt_session_total.clone())),
            registry.register(Box::new(mqtt_will_total.clone())),
            registry.register(Box::new(mqtt_retained_total.clone())),
            registry.register(Box::new(mqtt_wildcard_total.clone())),
            registry.register(Box::new(mqtt_shared_total.clone())),
            registry.register(Box::new(mqtt_alias_total.clone())),
            registry.register(Box::new(mqtt_receive_max_total.clone())),
            registry.register(Box::new(mqtt_sub_id_total.clone())),
            registry.register(Box::new(mqtt_out_alias_total.clone())),
            registry.register(Box::new(mqtt_tls_connections_total.clone())),
            registry.register(Box::new(mqtt_tls_auth_total.clone())),
            registry.register(Box::new(audit_publish_total.clone())),
            registry.register(Box::new(audit_consume_total.clone())),
            registry.register(Box::new(audit_consumer_lag.clone())),
            registry.register(Box::new(audit_dlq_total.clone())),
            registry.register(Box::new(member_cache_total.clone())),
            registry.register(Box::new(redis_scan_calls_total.clone())),
            registry.register(Box::new(risk_events_total.clone())),
            // E02 compliance purge / E04 residual multipart GC
            registry.register(Box::new(purge_cleanup_total.clone())),
            registry.register(Box::new(purge_objects_total.clone())),
            registry.register(Box::new(purge_cleanup_users.clone())),
            registry.register(Box::new(multipart_gc_total.clone())),
            registry.register(Box::new(multipart_gc_uploads.clone())),
            // E01 storage lifecycle (cold archive + orphan object GC)
            registry.register(Box::new(archive_enabled.clone())),
            registry.register(Box::new(archive_rounds_total.clone())),
            registry.register(Box::new(archive_rows_total.clone())),
            registry.register(Box::new(archive_partitions_total.clone())),
            registry.register(Box::new(archive_objects_total.clone())),
            registry.register(Box::new(archive_last_success_unixtime.clone())),
            registry.register(Box::new(archive_object_gc_total.clone())),
            registry.register(Box::new(archive_object_gc_scanned.clone())),
            // E31 pipeline stage bypass / E15 inspectable KEK
            registry.register(Box::new(pipeline_bypass_total.clone())),
            registry.register(Box::new(inspectable_enabled.clone())),
            registry.register(Box::new(inspectable_kek_loaded.clone())),
            registry.register(Box::new(inspectable_kek_info.clone())),
            registry.register(Box::new(inspectable_audit_total.clone())),
        ] {
            if let Err(e) = m {
                tracing::error!(error = %e, "register metric failed");
            }
        }

        Arc::new(Metrics {
            registry,
            connections,
            msgs_total,
            e2e_latency,
            pending_depth,
            chunk_retrans_total,
            plugin_call_duration,
            plugin_wasm_loaded,
            plugin_wasm_verified,
            plugin_wasm_rejected_total,
            plugin_wasm_source_total,
            plugin_wasm_signature_total,
            plugin_wasm_invocations_total,
            plugin_wasm_invoke_duration,
            plugin_wasm_circuit_trips_total,
            plugin_wasm_reload_total,
            plugin_wasm_reload_duration,
            ratelimit_dropped_total,
            backpressure_dropped_total,
            backpressure_protected_dropped_total,
            http_idempotency_total,
            store_latency,
            wal_size_bytes,
            wal_append_total,
            wal_replay_total,
            wal_dropped_total,
            dedup_hit_total,
            protocol_version,
            sse_connections,
            http_requests_total,
            grpc_fallback_total,
            route_cache_stale_total,
            media_record_dropped_total,
            media_record_segments_total,
            media_record_bytes_total,
            media_record_errors_total,
            media_record_publish_total,
            media_record_consume_total,
            media_record_consumer_lag,
            media_record_index_total,
            media_record_manifest_total,
            media_record_gc_total,
            media_record_gc_rows,
            media_recording_api_total,
            quic_connections,
            quic_streams_active,
            quic_bytes_total,
            quic_dropped_total,
            quic_register_total,
            quic_auth_total,
            webtransport_sessions_active,
            webtransport_sessions_total,
            webtransport_auth_total,
            webtransport_bytes_total,
            key_rotate_total,
            key_verification_failures_total,
            mqtt_publish_retransmit_total,
            mqtt_pending_replay_total,
            mqtt_ingest_failed_total,
            mqtt_qos2_total,
            mqtt_session_total,
            mqtt_will_total,
            mqtt_retained_total,
            mqtt_wildcard_total,
            mqtt_shared_total,
            mqtt_alias_total,
            mqtt_receive_max_total,
            mqtt_sub_id_total,
            mqtt_out_alias_total,
            mqtt_tls_connections_total,
            mqtt_tls_auth_total,
            audit_publish_total,
            audit_consume_total,
            audit_consumer_lag,
            audit_dlq_total,
            member_cache_total,
            redis_scan_calls_total,
            risk_events_total,
            purge_cleanup_total,
            purge_objects_total,
            purge_cleanup_users,
            multipart_gc_total,
            multipart_gc_uploads,
            // E01 storage lifecycle (cold archive + orphan object GC)
            archive_enabled,
            archive_rounds_total,
            archive_rows_total,
            archive_partitions_total,
            archive_objects_total,
            archive_last_success_unixtime,
            archive_object_gc_total,
            archive_object_gc_scanned,
            // E31 pipeline stage bypass / E15 inspectable KEK
            pipeline_bypass_total,
            inspectable_enabled,
            inspectable_kek_loaded,
            inspectable_kek_info,
            inspectable_audit_total,
        })
    }

    /// Unit test only: inject an explicit inspectable load snapshot (avoids depending on process-level `Config::load`).
    #[cfg(test)]
    pub(crate) fn new_with_inspectable_snapshot(
        snapshot: crate::pipeline::inspectable::InspectableSnapshot,
    ) -> Arc<Self> {
        Self::build(snapshot)
    }

    /// Prometheus text exposure (`/v1/admin/metrics`, ⑤ §8.1).
    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        if let Err(e) = encoder.encode(&self.registry.gather(), &mut buf) {
            tracing::error!(error = %e, "encode metrics failed");
            return String::new();
        }
        String::from_utf8(buf).unwrap_or_default()
    }

    /// Low-cardinality: use only the first 8 characters of the user id as a label (doc ② §8.2).
    pub fn user_hash(user_id: &str) -> String {
        user_id.chars().take(8).collect()
    }

    pub fn record_store(&self, started: std::time::Instant) {
        self.store_latency.observe(started.elapsed().as_secs_f64());
    }
}

impl Default for Metrics {
    fn default() -> Self {
        // Metrics::new returns an Arc; this only satisfies clippy: callers always use `Metrics::new()`
        Arc::try_unwrap(Metrics::new()).ok().expect("fresh arc")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_documented_metric_names() {
        let m = Metrics::new();
        m.connections.with_label_values(&["ws", "open"]).inc();
        m.msgs_total.with_label_values(&["in", "text", "persisted"]).inc();
        m.dedup_hit_total.with_label_values(&["redis"]).inc();
        m.pending_depth.with_label_values(&["user", "01JABCDE"]).set(3);
        m.chunk_retrans_total.with_label_values(&["request"]).inc();
        m.ratelimit_dropped_total.with_label_values(&["01JABCDE"]).inc();
        m.backpressure_dropped_total.with_label_values(&["envelope"]).inc();
        // Protected-set frame drops (⑤ §9.5): separate metric, must stay 0 under normal backpressure
        m.backpressure_protected_dropped_total
            .with_label_values(&["receipt"])
            .inc();
        // HTTP idempotency middleware result (⑤ §0.3 / E12): the low-cardinality result label spellings are the E2E assertion basis
        for result in ["hit", "miss", "conflict", "in_progress", "error"] {
            m.http_idempotency_total.with_label_values(&[result]).inc();
        }
        m.protocol_version.with_label_values(&["1"]).inc();
        m.e2e_latency.observe(0.01);
        m.plugin_call_duration.observe(0.001);
        // Plugin WASM host (PL-10): load/verify/invoke/circuit
        m.plugin_wasm_loaded.set(2);
        m.plugin_wasm_verified.set(2);
        m.plugin_wasm_rejected_total.with_label_values(&["signature"]).inc();
        // Source counts (dir|pg): label spellings are the E2E/alert assertion basis
        m.plugin_wasm_source_total.with_label_values(&["dir", "loaded"]).inc();
        m.plugin_wasm_source_total.with_label_values(&["pg", "loaded"]).inc();
        m.plugin_wasm_source_total.with_label_values(&["pg", "rejected"]).inc();
        m.plugin_wasm_source_total.with_label_values(&["pg", "skipped"]).inc();
        m.plugin_wasm_signature_total.with_label_values(&["verified"]).inc();
        m.plugin_wasm_signature_total.with_label_values(&["invalid"]).inc();
        m.plugin_wasm_signature_total.with_label_values(&["missing"]).inc();
        m.plugin_wasm_invocations_total.with_label_values(&["echo", "ok"]).inc();
        m.plugin_wasm_invocations_total.with_label_values(&["spin", "timeout"]).inc();
        m.plugin_wasm_invoke_duration.with_label_values(&["echo"]).observe(0.002);
        m.plugin_wasm_circuit_trips_total.with_label_values(&["spin"]).inc();
        // Hot reload (PL-10 hot reload): result/duration; label spellings are the E2E assertion basis
        for result in ["ok", "error"] {
            m.plugin_wasm_reload_total
                .with_label_values(&[result])
                .inc();
        }
        m.plugin_wasm_reload_duration.observe(0.004);
        m.record_store(std::time::Instant::now());
        m.wal_size_bytes.set(0);
        m.wal_append_total.with_label_values(&["ok"]).inc();
        m.wal_append_total.with_label_values(&["full"]).inc();
        m.wal_append_total.with_label_values(&["fail"]).inc();
        m.wal_replay_total.with_label_values(&["ok"]).inc();
        m.wal_replay_total.with_label_values(&["duplicate"]).inc();
        m.wal_replay_total.with_label_values(&["error"]).inc();
        m.wal_replay_total.with_label_values(&["poison"]).inc();
        m.wal_dropped_total.inc();
        m.media_record_dropped_total.inc();
        m.media_record_segments_total.inc();
        m.media_record_bytes_total.inc_by(8);
        m.media_record_errors_total.inc();
        // Media recording bus (PL-13 13.6): publish/consume/lag (label spellings are the E2E assertion basis)
        for result in ["ok", "fallback", "direct", "error"] {
            m.media_record_publish_total.with_label_values(&[result]).inc();
        }
        for result in ["ok", "duplicate", "other_node", "retry", "dlq", "poison"] {
            m.media_record_consume_total.with_label_values(&[result]).inc();
        }
        m.media_record_consumer_lag.set(2);
        // Media recording index + retrieval/download API (PL-13 13.6 retrieval plane; label spellings are the E2E/alert assertion basis)
        for result in ["ok", "dup", "error"] {
            m.media_record_index_total.with_label_values(&[result]).inc();
        }
        // Manifest + lifecycle GC (label spellings are the E2E assertion basis)
        for result in ["ok", "error"] {
            m.media_record_manifest_total
                .with_label_values(&[result])
                .inc();
        }
        for result in ["deleted", "error"] {
            m.media_record_gc_total.with_label_values(&[result]).inc();
        }
        m.media_record_gc_rows.set(3);
        for endpoint in ["list", "detail", "download", "manifest"] {
            for result in ["ok", "not_found", "forbidden", "error"] {
                m.media_recording_api_total
                    .with_label_values(&[endpoint, result])
                    .inc();
            }
        }
        // QUIC server relay skeleton (PL-13 13.3): connections/active streams/bytes/drops/registration results
        m.quic_connections.inc();
        m.quic_streams_active.set(1);
        m.quic_bytes_total.with_label_values(&["in"]).inc_by(1024);
        m.quic_bytes_total.with_label_values(&["out"]).inc_by(1024);
        m.quic_dropped_total.with_label_values(&["bitrate"]).inc();
        m.quic_register_total.with_label_values(&["ok"]).inc();
        // QUIC auth (PL-13 13.3 JWT/device binding): the 5 result label spellings are the E2E assertion basis
        for result in ["ok", "expired", "bad_jwt", "device_mismatch", "not_participant"] {
            m.quic_auth_total.with_label_values(&[result]).inc();
        }
        // WebTransport(HTTP/3) gateway (PL-13 13.3): sessions/auth/bridge bytes (label spellings are the E2E assertion basis)
        m.webtransport_sessions_active.set(1);
        for result in [
            "ok",
            "path",
            "handshake",
            "auth",
            "token",
            "quota",
            "bad_request",
            "closed",
            "error",
        ] {
            m.webtransport_sessions_total.with_label_values(&[result]).inc();
        }
        for result in ["ok", "expired", "bad_jwt", "device_mismatch", "not_participant"] {
            m.webtransport_auth_total.with_label_values(&[result]).inc();
        }
        m.webtransport_bytes_total.with_label_values(&["in"]).inc_by(1024);
        m.webtransport_bytes_total.with_label_values(&["out"]).inc_by(1024);
        // Key rotation / verification failures (PL-03; neither result nor reason label spellings may drift; E2E asserts on them)
        m.key_rotate_total.with_label_values(&["jwt", "ok"]).inc();
        m.key_rotate_total
            .with_label_values(&["jwt", "key_dir_readonly"])
            .inc();
        m.key_rotate_total
            .with_label_values(&["kek", "not_implemented"])
            .inc();
        m.key_verification_failures_total
            .with_label_values(&["signature"])
            .inc();
        // MQTT reliability (PL-11): retransmit / redelivery / inbound failures
        m.mqtt_publish_retransmit_total
            .with_label_values(&["retransmit"])
            .inc();
        m.mqtt_publish_retransmit_total
            .with_label_values(&["exhausted"])
            .inc();
        m.mqtt_pending_replay_total.inc();
        m.mqtt_ingest_failed_total
            .with_label_values(&["rate"])
            .inc();
        // QoS2 state machine / persistent session / WILL / retained (PL-11 additions; label spellings are the E2E assertion basis)
        for phase in ["pubrec", "pubrel", "pubcomp", "error"] {
            m.mqtt_qos2_total.with_label_values(&[phase]).inc();
        }
        for result in ["restored", "cleaned"] {
            m.mqtt_session_total.with_label_values(&[result]).inc();
        }
        m.mqtt_will_total.inc();
        for result in ["stored", "deleted", "delivered"] {
            m.mqtt_retained_total.with_label_values(&[result]).inc();
        }
        // Wildcards / shared subscriptions / Topic Alias (more PL-11 additions; label spellings are the E2E assertion basis)
        for result in ["match", "mismatch", "invalid"] {
            m.mqtt_wildcard_total.with_label_values(&[result]).inc();
        }
        for result in ["delivered", "skipped"] {
            m.mqtt_shared_total.with_label_values(&[result]).inc();
        }
        for result in ["set", "used", "error"] {
            m.mqtt_alias_total.with_label_values(&[result]).inc();
        }
        // TLS/mTLS (PL-11): label spellings are the E2E/dashboard assertion basis
        for result in ["ok", "fail"] {
            m.mqtt_tls_connections_total
                .with_label_values(&[result])
                .inc();
        }
        for result in ["ok", "no_cert", "bad_cert", "unknown_identity", "device_mismatch"] {
            m.mqtt_tls_auth_total.with_label_values(&[result]).inc();
        }
        // Audit stream (PL-11 / PL-14): write-entry result / consume result / lag / DLQ
        for result in ["ok", "fallback", "direct", "error"] {
            m.audit_publish_total.with_label_values(&[result]).inc();
        }
        for result in ["ok", "duplicate", "retry", "poison", "dlq"] {
            m.audit_consume_total.with_label_values(&[result]).inc();
        }
        m.audit_consumer_lag.set(3);
        m.audit_dlq_total.inc();
        // Session membership positive cache / Redis SCAN counter (PL-17 bottleneck fix; label spellings are the assertion basis)
        for result in ["hit", "miss", "invalidate"] {
            m.member_cache_total.with_label_values(&[result]).inc();
        }
        m.redis_scan_calls_total.inc();
        // E02 compliance purge cascade cleanup / E04 residual multipart GC (label spellings are the E2E assertion basis)
        for result in [
            "objects_ok",
            "objects_error",
            "redis_ok",
            "redis_error",
            "user_deleted",
            "user_error",
        ] {
            m.purge_cleanup_total.with_label_values(&[result]).inc();
        }
        for result in ["deleted", "failed"] {
            m.purge_objects_total.with_label_values(&[result]).inc();
        }
        m.purge_cleanup_users.set(1);
        for result in ["aborted", "skipped", "error"] {
            m.multipart_gc_total.with_label_values(&[result]).inc();
        }
        m.multipart_gc_uploads.set(2);
        // E01 storage lifecycle (cold archive + orphan object GC; label spellings are the E2E assertion basis)
        m.archive_enabled.set(1);
        for result in ["ok", "error", "paused"] {
            m.archive_rounds_total.with_label_values(&[result]).inc();
        }
        for result in ["archived", "dedup_exported", "failed"] {
            m.archive_rows_total.with_label_values(&[result]).inc();
        }
        for result in ["detached", "failed", "skipped"] {
            m.archive_partitions_total.with_label_values(&[result]).inc();
        }
        for result in ["uploaded", "failed"] {
            m.archive_objects_total.with_label_values(&[result]).inc();
        }
        m.archive_last_success_unixtime.set(1_800_000_000);
        for result in ["deleted", "referenced", "protected", "error"] {
            m.archive_object_gc_total.with_label_values(&[result]).inc();
        }
        m.archive_object_gc_scanned.set(3);
        // E31 pipeline stage bypass: exposed as 0 by default; bypassed stages are counted by ingest
        for stage in crate::config::PIPELINE_STAGES {
            m.pipeline_bypass_total.with_label_values(&[stage]);
        }
        m.pipeline_bypass_total
            .with_label_values(&["validate"])
            .inc();
        // E15 inspectable KEK: load state/fingerprint (no material) + audit hook counts
        m.inspectable_enabled.set(0);
        m.inspectable_kek_loaded.set(0);
        m.inspectable_kek_info
            .with_label_values(&["kek-test", "0011223344556677", "active"])
            .set(1);
        for action in [
            "inspectable.wrap",
            "inspectable.unwrap",
            "inspectable.rekey",
        ] {
            for result in ["ok", "denied", "error"] {
                m.inspectable_audit_total
                    .with_label_values(&[action, result])
                    .inc();
            }
        }

        let text = m.render();
        for name in [
            "lattice_connections",
            "lattice_msgs_total",
            "lattice_e2e_latency_seconds",
            "lattice_pending_depth",
            "lattice_chunk_retrans_total",
            "lattice_plugin_call_duration_seconds",
            // Plugin WASM host (PL-10): load / verify / invoke / circuit
            "lattice_plugin_wasm_loaded",
            "lattice_plugin_wasm_verified",
            "lattice_plugin_wasm_rejected_total",
            "lattice_plugin_wasm_source_total",
            "lattice_plugin_wasm_signature_total",
            "lattice_plugin_wasm_invocations_total",
            "lattice_plugin_wasm_invoke_duration_seconds",
            "lattice_plugin_wasm_circuit_trips_total",
            // Hot reload (PL-10 hot reload): result counter + duration histogram
            "lattice_plugin_wasm_reload_total",
            "lattice_plugin_wasm_reload_duration_seconds",
            "lattice_ratelimit_dropped_total",
            "lattice_backpressure_dropped_total",
            "lattice_backpressure_protected_dropped_total",
            "lattice_http_idempotency_total",
            "lattice_store_latency_seconds",
            "lattice_wal_size_bytes",
            "lattice_wal_append_total",
            "lattice_wal_replay_total",
            "lattice_wal_dropped_total",
            "lattice_dedup_hit_total",
            "lattice_protocol_version",
            // Media recording tee (PL-13 13.6; names match the task card/design)
            "lattice_media_record_dropped_total",
            "lattice_media_record_segments_total",
            "lattice_media_record_bytes_total",
            "lattice_media_record_errors_total",
            // Media recording bus (PL-13 13.6 upgrade): publish/consume/lag
            "lattice_media_record_publish_total",
            "lattice_media_record_consume_total",
            "lattice_media_record_consumer_lag",
            // Media recording index + manifest + lifecycle GC + retrieval/download API (PL-13 13.6 retrieval plane)
            "lattice_media_record_index_total",
            "lattice_media_record_manifest_total",
            "lattice_media_record_gc_total",
            "lattice_media_record_gc_rows",
            "lattice_media_recording_api_total",
            // QUIC server relay skeleton (PL-13 13.3 / design §17.9 path ②)
            "lattice_quic_connections",
            "lattice_quic_streams_active",
            "lattice_quic_bytes_total",
            "lattice_quic_dropped_total",
            "lattice_quic_register_total",
            "lattice_quic_auth_total",
            // WebTransport(HTTP/3) browser gateway (PL-13 13.3)
            "lattice_webtransport_sessions_active",
            "lattice_webtransport_sessions_total",
            "lattice_webtransport_auth_total",
            "lattice_webtransport_bytes_total",
            // Key rotation / verification failures (PL-03 / ⑤ §8.4)
            "lattice_key_rotate_total",
            "lattice_key_verification_failures_total",
            // MQTT reliability (PL-11): QoS1 retransmit / offline redelivery / inbound persist failures
            "lattice_mqtt_publish_retransmit_total",
            "lattice_mqtt_pending_replay_total",
            "lattice_mqtt_ingest_failed_total",
            // MQTT QoS2 / persistent session / WILL / retained (PL-11 additions)
            "lattice_mqtt_qos2_total",
            "lattice_mqtt_session_total",
            "lattice_mqtt_will_total",
            "lattice_mqtt_retained_total",
            // MQTT wildcards / shared subscriptions / Topic Alias (more PL-11 additions)
            "lattice_mqtt_wildcard_total",
            "lattice_mqtt_shared_total",
            "lattice_mqtt_alias_total",
            // MQTT TLS / mTLS device certificates (PL-11)
            "lattice_mqtt_tls_connections_total",
            "lattice_mqtt_tls_auth_total",
            // Audit stream (PL-11/PL-14): write entry / consume / lag / DLQ
            "lattice_audit_publish_total",
            "lattice_audit_consume_total",
            "lattice_audit_consumer_lag",
            "lattice_audit_dlq_total",
            // Performance bottleneck fix (PL-17): membership cache / Redis SCAN counter
            "lattice_member_cache_total",
            "lattice_redis_scan_calls_total",
            // E02 compliance purge cascade cleanup / E04 residual multipart GC
            "lattice_purge_cleanup_total",
            "lattice_purge_objects_total",
            "lattice_purge_cleanup_users",
            "lattice_multipart_gc_total",
            "lattice_multipart_gc_uploads",
            // E01 storage lifecycle (cold archive + orphan object GC)
            "lattice_archive_enabled",
            "lattice_archive_rounds_total",
            "lattice_archive_rows_total",
            "lattice_archive_partitions_total",
            "lattice_archive_objects_total",
            "lattice_archive_last_success_unixtime",
            "lattice_archive_object_gc_total",
            "lattice_archive_object_gc_scanned",
            // E31 pipeline stage bypass / E15 inspectable KEK
            "lattice_pipeline_bypass_total",
            "lattice_inspectable_enabled",
            "lattice_inspectable_kek_loaded",
            "lattice_inspectable_kek_info",
            "lattice_inspectable_audit_total",
        ] {
            assert!(text.contains(name), "missing metric {name}");
        }
        // Units in names, counters end with _total (v0.2 fix)
        assert!(text.contains("lattice_store_latency_seconds"));
        assert!(!text.contains("lattice_client_latency_{"));
    }

    #[test]
    fn inspectable_snapshot_seeds_gauges_and_audit_counters() {
        // Disabled (not loaded): enabled/loaded always 0, audit 0, no kek_info row
        let off = Metrics::new_with_inspectable_snapshot(
            crate::pipeline::inspectable::InspectableSnapshot::default(),
        );
        let text = off.render();
        assert!(text.contains("lattice_inspectable_enabled 0"));
        assert!(text.contains("lattice_inspectable_kek_loaded 0"));
        assert!(!text.contains("lattice_inspectable_kek_info{"));
        assert!(text.contains("lattice_inspectable_audit_total{action=\"inspectable.rekey\",result=\"ok\"} 0"));

        // Loaded + previous window + startup self-check audit count (E2E asserts the same names from outside)
        let snapshot = crate::pipeline::inspectable::InspectableSnapshot {
            enabled: true,
            kek_loaded: true,
            keys: vec![
                (
                    "kek-2026".to_string(),
                    "0011223344556677".to_string(),
                    "active",
                ),
                (
                    "kek-2025".to_string(),
                    "8899aabbccddeeff".to_string(),
                    "previous",
                ),
            ],
            audit_counts: vec![
                ("inspectable.wrap", "ok", 1),
                ("inspectable.unwrap", "ok", 3),
                ("inspectable.rekey", "ok", 1),
            ],
        };
        let on = Metrics::new_with_inspectable_snapshot(snapshot);
        let text = on.render();
        assert!(text.contains("lattice_inspectable_enabled 1"));
        assert!(text.contains("lattice_inspectable_kek_loaded 1"));
        assert!(text.contains(
            "lattice_inspectable_kek_info{fingerprint=\"0011223344556677\",kek_id=\"kek-2026\",role=\"active\"} 1"
        ));
        assert!(text.contains(
            "lattice_inspectable_kek_info{fingerprint=\"8899aabbccddeeff\",kek_id=\"kek-2025\",role=\"previous\"} 1"
        ));
        assert!(text.contains(
            "lattice_inspectable_audit_total{action=\"inspectable.unwrap\",result=\"ok\"} 3"
        ));
        assert!(text.contains(
            "lattice_inspectable_audit_total{action=\"inspectable.rekey\",result=\"ok\"} 1"
        ));
        // Audit/metrics must not contain key material fields
        assert!(!text.contains("kek_material"));
    }

    #[test]
    fn pipeline_bypass_metric_is_zero_by_default_and_labeled_by_stage() {
        let m = Metrics::new();
        let text = m.render();
        for stage in crate::config::PIPELINE_STAGES {
            assert!(
                text.contains(&format!(
                    "lattice_pipeline_bypass_total{{stage=\"{stage}\"}} 0"
                )),
                "stage {stage} should be exposed as 0 (E2E asserts other stages are unaffected)"
            );
        }
        m.pipeline_bypass_total
            .with_label_values(&["validate"])
            .inc();
        let text = m.render();
        assert!(text.contains("lattice_pipeline_bypass_total{stage=\"validate\"} 1"));
        assert!(text.contains("lattice_pipeline_bypass_total{stage=\"dedup\"} 0"));
    }
}
