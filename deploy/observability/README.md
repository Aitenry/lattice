# Lattice observability

Prometheus scrape configuration, alert rules, and a Grafana dashboard for the
`lattice-node` metrics endpoint. These are deployment-side assets; the
application metrics themselves are defined in
[crates/lattice-node/src/observe/metrics.rs](../../crates/lattice-node/src/observe/metrics.rs).

## Assets

| File | Purpose |
| --- | --- |
| [prometheus/prometheus.yml](prometheus/prometheus.yml) | scrape configuration. Enabled jobs are `lattice-node` on 9100 and `lattice-transfer` on 9101; the `/v1/admin/metrics` fallback and a blackbox `/v1/ready` probe are present but commented |
| [prometheus/lattice-alerts.yml](prometheus/lattice-alerts.yml) | 22 alert rules in 7 groups, every rule with summary, description, and runbook annotations |
| [grafana/lattice-overview.json](grafana/lattice-overview.json) | Grafana dashboard, schema version 39, 19 panels, `DS_PROMETHEUS` datasource input |
| `README.md` | this guide: scrape paths, metric status, alert handling, validation, and gaps |

## Metric names and instrumentation status

The alert expressions and dashboard queries use the following metric families, plus Prometheus's synthetic `up{job="lattice-node"}`. The code is the source of truth; several families are registered but have no call site yet, so the related panels and rules show no data or cannot fire.

| Metric | Labels | Status |
| --- | --- | --- |
| `lattice_connections` | `protocol`, `state` | Instrumented; WebSocket open/close increments and decrements the `ws`/`open` series |
| `lattice_msgs_total` | `direction`, `env_type`, `state` | Instrumented in the message pipeline for ingress, persistence, and routing outcomes |
| `lattice_e2e_latency_seconds` | none | Registered but no production `observe()` call; E2E rules and panels are inert until wired |
| `lattice_pending_depth` | `scope`, `user_hash` | Refreshed on ACK and redelivery-drain paths, not every enqueue; only `scope="user"` is emitted, so depth can lag |
| `lattice_chunk_retrans_total` | `reason` | Instrumented for `chunk_in`, `request`, and `seq_regression` |
| `lattice_plugin_call_duration_seconds` | none | Registered but no production `observe()` call; plugin latency rules are inert |
| `lattice_ratelimit_dropped_total` | `user_hash` | Instrumented in quota validation |
| `lattice_backpressure_dropped_total` | `priority` | Instrumented when the bounded downstream queue drops a frame; `priority` is the command name, such as `envelope`, `route`, or `stream-data` |
| `lattice_store_latency_seconds` | none | Registered, but `record_store()` has no production caller; storage latency rules are inert |
| `lattice_wal_size_bytes` | none | Instrumented by the periodic WAL job |
| `lattice_dedup_hit_total` | `layer` | Instrumented; actual label values are `redis_miss`, `redis`, and `pg` |
| `lattice_protocol_version` | `version` | Instrumented on WebSocket `hello` |
| `lattice_sse_connections` | none | Instrumented; counts `/v1/admin/stream` connections against the default cap of 100 (`admin.sse_max_connections`) |
| `lattice_http_requests_total` | `path`, `status` | Registered but no production `inc()` call; HTTP error-rate rules and panels are inert |

`metrics.rs` also defines plugin WASM, MQTT, QUIC, WebTransport, audit, archive, and purge metrics that these rules and the dashboard do not use. Add rules only after confirming the corresponding call site exists.

## Scrape paths and authentication

| Address | Authentication | Notes |
| --- | --- | --- |
| `http://127.0.0.1:9100/metrics` | none | Main path. Read-only and unauthenticated; `[node] metrics` defaults to `127.0.0.1:9100`, and containers override it to `0.0.0.0:9100`. Restrict sources with NetworkPolicy or a firewall |
| `http://127.0.0.1:9100/healthz` | none | Metrics-listener liveness probe, returns `ok`. A bind failure only logs a warning and does not block the message plane |
| `http://127.0.0.1:8080/v1/admin/metrics` | `Authorization: Bearer <Ops JWT>` | Fallback for binaries without the metrics listener. JWT TTL is 900 seconds, so the token must be refreshed |
| `http://127.0.0.1:8080/v1/ready` | none | Readiness. Returns 200 when PostgreSQL is reachable even if Redis is degraded; returns 503 when PostgreSQL is unreachable or the node is draining |
| `http://127.0.0.1:9090` / `http://127.0.0.1:3000` | Prometheus / Grafana UI | `/targets`, `/rules`, `/alerts`; dashboard import |

Do not enable the 9100 job and the admin-metrics job at the same time. Both
scrape the same registry, so every series would be duplicated.

## Start Prometheus

The node must be running with a reachable metrics listener. A quick check:

```bash
curl -fsS http://127.0.0.1:9100/metrics | head -n 20
```

Run Prometheus with the two in-repo files mounted read-only. The config scrapes every 15 seconds with a 10-second timeout and loads `/etc/prometheus/lattice-alerts.yml`:

```bash
docker run -d --name lattice-prometheus -p 9090:9090 \
  -v "${PWD}/deploy/observability/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
  -v "${PWD}/deploy/observability/prometheus/lattice-alerts.yml:/etc/prometheus/lattice-alerts.yml:ro" \
  prom/prometheus:v2.55.0 --config.file=/etc/prometheus/prometheus.yml
```

`prometheus.yml` targets `host.docker.internal:9100` for Docker Desktop. On Linux, add `--add-host=host.docker.internal:host-gateway`. When Prometheus runs directly on the host, change the target to `127.0.0.1:9100` and `rule_files` to `./lattice-alerts.yml`; when it shares the dev compose network with the node, use `node:9100`. The commented fallback job targets `8080` and needs the token file described below.

Open <http://127.0.0.1:9090> and check:

- `/targets`: the `lattice-node` target should be UP (and `lattice-transfer` when the transfer plane is deployed). Connection refused means the port is not listening or not mapped; a timeout points at network policy or `scrape_timeout`.
- `/rules`: 7 groups and 22 rules should be loaded. `/alerts` is empty unless a rule is firing; Alertmanager is not configured here.

## Start Grafana and import the dashboard

```bash
docker run -d --name lattice-grafana -p 3000:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD='<local-password>' \
  grafana/grafana:11.2.0
```

1. Open <http://127.0.0.1:3000> and sign in as `admin` with the password above.
2. Add a Prometheus data source at `http://host.docker.internal:9090` and save it.
3. Import [grafana/lattice-overview.json](grafana/lattice-overview.json) through Dashboards, Import, Upload JSON, and select the Prometheus data source for the `DS_PROMETHEUS` input.
4. The dashboard refreshes every 30 seconds and defaults to the last 6 hours.

The JSON is an export/import file. For file provisioning, replace `${DS_PROMETHEUS}` in every panel with the real data source UID first; Grafana does not resolve `__inputs` in provisioned dashboards.

## Fallback: short-lived Ops JWT

The fallback job needs a Bearer token. Obtain it from the login API, keep it out of Git, and mount it read-only at the `credentials_file` path used by `prometheus.yml`:

```bash
mkdir -p tmp
curl -fsS -X POST http://127.0.0.1:8080/v1/auth/login \
  -H 'content-type: application/json' \
  --data @tmp/login.json | jq -r .access_jwt > tmp/lattice-admin.jwt
chmod 600 tmp/lattice-admin.jwt
```

`tmp/login.json` holds the operator's local credentials. Prometheus re-reads the token file on every scrape. Refresh it before the 900-second TTL with a cron job run from the checkout root:

```bash
# crontab -e; adjust $HOME/lattice to the checkout location.
*/5 * * * * cd "$HOME/lattice" && curl -fsS -X POST http://127.0.0.1:8080/v1/auth/login \
  -H 'content-type: application/json' --data @tmp/login.json | jq -r .access_jwt > "${PWD}/tmp/lattice-admin.jwt"
```

For systemd, run the same command as a timer's `ExecStart` with `WorkingDirectory=%h/lattice`. Never commit the token or the login file.

## Alert rules

`lattice-alerts.yml` contains 7 groups and 22 rules. Severities are P1 (act
immediately), P2 (act during the shift), and P3 (watch).

| Alert | Severity | Trigger and meaning | First action |
| --- | --- | --- | --- |
| `LatticeNodeScrapeDown` | P1 | `up{job="lattice-node"} == 0` for 1m; process exit, metrics listener failure, or unreachable scrape | Check the process, port 9100, `curl :9100/metrics`, and the Prometheus target error |
| `LatticeNodeOnlineConnectionsCollapsed` | P2 | open connections drop more than 90% versus 10m ago with a baseline of at least 10, for 5m | Check node logs, the Redis online index, and whether `up` also dropped |
| `LatticeDependencyUnavailable` | P1 | `probe_success{job="lattice-ready"} == 0` for 2m; requires blackbox_exporter and the commented job | Read `deps` from `/v1/ready`, recover dependencies, then reconcile pending state |
| `LatticeWalSizeHigh` | P2 | `lattice_wal_size_bytes > 1GiB` for 5m; local WAL backlog | Check disk, WAL write errors, and the snapshot/cleanup job; drain if needed |
| `LatticePendingDepthCritical` | P1 | `sum(lattice_pending_depth) > 100000` for 5m | Inspect the oldest queued messages through `/v1/admin/queue`; check redelivery and ACKs |
| `LatticePendingDepthWarning` | P2 | `sum(lattice_pending_depth) > 10000` for 10m | Watch the growth trend; check Redis pending growth and redelivery throughput |
| `LatticeBackpressureDropWarning` | P2 | drop rate above 1 frame/s for a `priority` for 5m | Find the slow client or link and rate-limit the sender |
| `LatticeBackpressureDropCritical` | P1 | all-node drop rate above 50 frames/s for 5m | Locate the affected users; rate-limit, scale out, and evaluate DLQ replay |
| `LatticeSseConnectionsNearLimit` | P2 | `lattice_sse_connections >= 80` for 5m | Close extra console tabs and confirm the counter falls after disconnects |
| `LatticeSseConnectionsExhausted` | P1 | `lattice_sse_connections >= 100` for 1m; new streams get 429 `sse_limit` | Find and disconnect abnormal consumers; raise `admin.sse_max_connections` if required |
| `LatticePluginCallLatencyHigh` | P2 | plugin-call P99 above 500ms for 5m; metric not wired yet | Check plugin resources and the canary ratio once the metric is instrumented |
| `LatticePluginCallFailureRateHigh` | P2 | `/v1/hub/*` 5xx share above 5% for 5m; proxy metric not wired yet | Check `/v1/admin/audit`, MinIO/PG health, and recent plugin versions |
| `LatticeE2eLatencySloBreach` | P2 | E2E P99 above 100ms for 5m; metric not wired yet | Check store latency, PostgreSQL/Redis, and node load once real E2E data exists |
| `LatticeE2eLatencyCritical` | P1 | E2E P99 above 500ms for 5m; metric not wired yet | Treat as severe latency; inspect dependencies and load immediately |
| `LatticeStoreLatencyHigh` | P2 | storage P99 above 500ms for 5m; metric not wired yet | Locate the slow backend: PostgreSQL lock or slow query, Redis, or S3 |
| `LatticeMessageErrorRateHigh` | P2 | dropped, expired, and DLQ messages exceed 5% of all messages for 10m | Break down by `state`; check delivery state and the DLQ |
| `LatticeChunkRetransRateHigh` | P2 | retransmissions exceed 1% of messages for 5m | Break down by `reason`; check weak clients, chunk timeouts, and watermark reconciliation |
| `LatticeRateLimitDropSpike` | P3 | rate-limit drops above 10/s for 5m | Look up the `user_hash`; distinguish flooding from organic growth and review quotas |
| `LatticeTransferScrapeDown` | P1 | `up{job="lattice-transfer"} == 0` for 1m; transfer replicas down or unreachable | Check the transfer Deployment/Compose service, `/healthz`, and the ingress `/t` route |
| `LatticeTransferNotReady` | P1 | `lattice_transfer_ready == 0` for 1m; no `[s3]` endpoint reachable from the transfer service | Check MinIO/LB reachability, `[s3] endpoint(s)`, and credentials |
| `LatticeTransferErrorRate` | P2 | transfer 5xx share above 5% for 5m (`upstream_unavailable`/`upstream_error`/`busy`/`upstream_denied`) | Inspect the status breakdown and upstream failure by endpoint; scale replicas if `busy` |
| `LatticeTransferUpstreamFailover` | P2 | any `lattice_transfer_upstream_failures_total` increase for 3m | Downloads may still succeed through a replica; repair the failing endpoint (network/MinIO/LB health) |

## Handling notes

- **Node or scrape down**: a metrics-listener bind failure only logs a warning, so a node can serve traffic while `up=0`. Check the process and port 9100 before declaring the node lost.
- **Dependency unavailable**: `/v1/ready` returns 503 when PostgreSQL is down or the node is draining, but a Redis-only failure returns 200 with `deps.redis=degraded`. Recover PostgreSQL first, then reconcile pending state before restoring traffic.
- **Backlog and backpressure**: `envelope` is a normal downstream drop, `stream-data` can be a fixed drop when the WebSocket tunnel is off, and `route` is a full target queue during cross-node forwarding. The usual cause is a slow or non-consuming client.
- **SSE cap**: the default limit is 100 connections to `/v1/admin/stream`. A counter that only grows suggests a missing `SseGuard` decrement; close abnormal connections before raising `admin.sse_max_connections`.
- **Plugin, E2E, and storage alerts**: these inputs are not instrumented yet, so the rules cannot fire on real data. Leave them enabled and wire the metrics rather than deleting the rules.
- **WAL and rate limiting**: continued WAL growth can cause write failures, so drain a node before its disk fills. `user_hash` is a short hash resolvable through the user search API.
- **Transfer plane**: `lattice-transfer` has its own registry on port 9101; a node `up=1` does not imply downloads work. `LatticeTransferNotReady` means object storage is unreachable from the transfer pods (downloads return 503 while the message API stays healthy). `busy` means the per-replica `max_inflight` cap was hit: scale replicas before raising the cap, because each download holds a connection for its whole transfer.

## Thresholds and tuning

The shipped thresholds are starting points for a dev single-node deployment: pending depth 10k/100k, backpressure 1/50 frames per second, WAL 1GiB, SSE 80/100, plugin P99 500ms and 5% failures, E2E P99 100ms/500ms, store P99 500ms, message error rate 5%, chunk retransmission 1%, and rate-limit drops 10/s. Recalibrate them from production capacity and traffic, not from these defaults. Disk usage, memory pressure, NATS reconnects, and MinIO rebuilds need external exporters such as node-exporter and blackbox_exporter; this directory does not ship those.

## Validation

Run these from the repository root:

```bash
promtool check rules deploy/observability/prometheus/lattice-alerts.yml
python -c 'import yaml; yaml.safe_load(open("deploy/observability/prometheus/prometheus.yml"))'
python -c 'import json; json.load(open("deploy/observability/grafana/lattice-overview.json"))'
```

These commands check rule syntax, YAML parseability, and dashboard JSON parseability. They do not prove PromQL semantics, threshold correctness, dashboard rendering, or alert delivery. This repository does not include a runtime check that starts Prometheus, Grafana, or Alertmanager, so firing alerts are only visible on the Prometheus `/alerts` page.

## Known gaps and limitations

- `lattice_http_requests_total` has no `inc()` call site, so HTTP error rate, plugin hub 5xx rate, and admin-plane isolation cannot be measured yet.
- `lattice_store_latency_seconds` has no production `record_store()` caller, and `lattice_plugin_call_duration_seconds` has no production `observe()` caller, so the storage and plugin rules are inert. There is no plugin failure counter.
- `lattice_e2e_latency_seconds` has no production `observe()` caller, so E2E latency panels and rules have no data.
- `lattice_pending_depth` is refreshed on ACK and redelivery paths rather than every enqueue, and only `scope="user"` is emitted; device and topic depth are not observable.
- There is no dependency or heartbeat metric. The dependency alert needs blackbox_exporter, and a Redis-only degradation still returns 200 from `/v1/ready`.
- Disk, memory, NATS reconnect, and MinIO rebuild alerts need external exporters that are not included. The 9100 endpoint is unauthenticated; restrict it with NetworkPolicy or a firewall and never expose it to the internet.
- The fallback path depends on a 900-second JWT and an external refresh job; a stale token produces 401 responses and a false `LatticeNodeScrapeDown`.
- Dashboard panels marked as awaiting instrumentation have no meaningful data. That is a real gap, not a dashboard defect.
