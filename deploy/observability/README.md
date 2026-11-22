# Lattice observability deliverable (Prometheus alerts + Grafana dashboard)

> Scope: PL-14 observability (alert rules / dashboard / operations guide). Only `deploy/observability/**`,
> `perf/**` and `scripts/obs-*.ps1` are added; **no src/docs/existing scripts were modified**.
>
> **The only source of metric names is the code: `crates/lattice-node/src/observe/metrics.rs`.**
> `the platform implementation document (outside this repository)` §8.1 is the metric specification; when the two disagree, **the code wins**
> (differences in §2.2). Every `lattice_*` metric name in the alert expressions and dashboard queries under this directory
> is verified against that file (`scripts/obs-validate.ps1` whitelist check).

---

## 1. Deliverables

| File | Purpose |
| --- | --- |
| `deploy/observability/prometheus/prometheus.yml` | scrape config: the **main path** is the 9100 standalone metrics endpoint from doc §8.1 (`observe/metrics_server.rs`, unauthenticated) + fallback `/v1/admin/metrics` (Bearer JWT, kept commented) + optional blackbox readiness probe |
| `deploy/observability/prometheus/lattice-alerts.yml` | 18 alert rules (6 groups) covering node down, dependency unavailable, pending backlog, backpressure drops, SSE limit, plugin latency/failure, error-rate and latency SLOs, WAL and rate limiting |
| `deploy/observability/grafana/lattice-overview.json` | Grafana dashboard (schemaVersion 39, 19 panels, `DS_PROMETHEUS` datasource variable); every query uses real `lattice_*` metric names |
| `deploy/observability/README.md` | this file: startup, scrape addresses, metric sources, alert meaning and handling, mapping to the docs, validation and gaps |
| `scripts/obs-refresh-admin-jwt.ps1` | refreshes the admin JWT file used for Prometheus scraping (`/v1/admin/metrics` needs auth, JWT TTL=900s) |
| `scripts/obs-backpressure-live.ps1` | shared-dev-node-safe backpressure probe (starts no process, kills none, precisely cleans up test data afterwards) |
| `scripts/obs-validate.ps1` | one-shot validation of YAML/JSON/PromQL/metric-name whitelist/alert coverage |
| `perf/README.md` | how to run PL-17 load tests and reconciliation (scenarios not executed are marked as such) |
| `perf/reports/backpressure-20261121.md` | backpressure measurement report (commands/times/raw key output/conclusion/cleanup check) |
| `perf/reports/backpressure-20261121-probe.json`, `perf/reports/raw/*.log` | raw backpressure probe evidence (JSON results + raw console logs) |

---

## 2. The single source of metric names (read this first)

### 2.1 Actual code metrics (14, taken from `observe/metrics.rs`)

| Metric (original code name) | Type | Actual labels in code | Semantics | Instrumentation status (call sites checked against v0.5.0) |
| --- | --- | --- | --- | --- |
| `lattice_connections` | gauge | `protocol`, `state` | active connections | ✅ instrumented: `["ws","open"]` inc/dec on WS register/unregister |
| `lattice_msgs_total` | counter | `direction`, `env_type`, `state` | message count | ✅ instrumented: pipeline ingest (in/persisted, duplicate, out/routed…) |
| `lattice_e2e_latency_seconds` | histogram (seconds) | **no labels** (docs say direction/stage) | end-to-end latency | ⚠️ placeholder: only `observe(0.0)` in the keepalive seq-watermark branch, not real E2E |
| `lattice_pending_depth` | gauge | `scope`, `user_hash` | offline queue depth | ⚠️ partial: only `set()` on the `ack_remove` path, enqueue paths do not refresh; in practice only `scope="user"` appears |
| `lattice_chunk_retrans_total` | counter | `reason` | chunk retransmissions | ✅ instrumented: `chunk_in` / `request` / `seq_regression` |
| `lattice_plugin_call_duration_seconds` | histogram (seconds) | **no labels** (docs say plugin_ns/form) | plugin call duration | ❌ not wired: no `observe()` call site |
| `lattice_ratelimit_dropped_total` | counter | `user_hash` | rate-limit drops | ✅ instrumented: `validate_quota` |
| `lattice_backpressure_dropped_total` | counter | `priority` | backpressure drops | ✅ instrumented: `Hub::try_send` (priority=command name, e.g. `envelope`), `stream-data`, cross-node `route` |
| `lattice_store_latency_seconds` | histogram (seconds) | **no labels** (docs say backend/op) | storage access duration | ❌ not wired: no `record_store()` call site |
| `lattice_wal_size_bytes` | gauge | **no labels** (docs say node_id) | local WAL size | ✅ instrumented: periodic `set()` from jobs |
| `lattice_dedup_hit_total` | counter | `layer` | dedup hits | ✅ instrumented: `redis_miss` / `redis` / `pg` (docs say local/redis/pg) |
| `lattice_protocol_version` | gauge | `version` | client protocol version distribution | ✅ instrumented: inc on WS hello |
| `lattice_sse_connections` | gauge | **no labels** | console SSE connections | ✅ instrumented: SseGuard inc/dec for `/v1/admin/stream` (cap 100) |
| `lattice_http_requests_total` | counter | `path`, `status` | HTTP request count | ❌ not wired: no `inc()` call site |

In addition, Prometheus's built-in synthetic metric `up{job="lattice-node"}` (scrape success=1) is used by the alerts and dashboard in this directory;
it does not come from metrics.rs but is the scraper's own status signal.

### 2.2 Differences between the code and doc §8.1 (the code wins)

| Doc §8.1 | Actual code (single truth) | Impact |
| --- | --- | --- |
| `lattice_e2e_latency_seconds{direction,stage}` | the histogram has **no labels** | do not filter alerts/dashboards by direction/stage |
| `lattice_pending_depth{scope=user/device/topic,...}` | in practice only `scope="user"` is emitted | no device-level/topic-level depth data yet |
| `lattice_plugin_call_duration_seconds{plugin_ns,form}` | the histogram has **no labels** and is not wired | dashboards/alerts take effect only after instrumentation |
| `lattice_store_latency_seconds{backend,op}` | the histogram has **no labels** and is not wired | same as above |
| `lattice_wal_size_bytes{node_id}` | no labels | distinguish nodes via Prometheus `instance` |
| `lattice_dedup_hit_total{layer=local/redis/pg}` | actual values are `redis_miss`/`redis`/`pg` | alerts/dashboards use the actual values |
| not listed | `lattice_sse_connections` and `lattice_http_requests_total` are extra code metrics | already on the dashboard (the latter awaits instrumentation) |
| `node.metrics = "127.0.0.1:9100"` standalone scrape endpoint | ✅ implemented: `observe/metrics_server.rs` binds `[node] metrics` (default `127.0.0.1:9100`; `LATTICE__NODE__METRICS=0.0.0.0:9100` in containers), unauthenticated and read-only; Prometheus scrapes via option A | landed and measured by a parallel task on 2026-11-21 13:18 with `http://127.0.0.1:9100/metrics` returning 200; fall back to `/v1/admin/metrics` (Bearer JWT) for old binaries or when the listener is disabled |

> `scripts/obs-validate.ps1` re-extracts the whitelist (14) from metrics.rs on every run
> and validates every `lattice_*` identifier in alerts and the dashboard (histogram `_bucket/_count/_sum` normalized to the family name).
> Any addition/rename makes validation fail, preventing invented metric names.

---

## 3. Startup (dev / single node)

### 3.1 Prerequisites

- a Lattice node runs on `127.0.0.1:8080` (dev credentials `admin/lattice_dev_admin_pw`) and the 9100 metrics endpoint is scrapeable:
  `GET http://127.0.0.1:9100/metrics` returns Prometheus text (`observe/metrics_server.rs`, unauthenticated read-only);
  and `GET /v1/ready` returns `{"ready":true,"deps":{"pg":"ok","redis":"ok","bus":"ok"}}`;
- for old binaries or when the metrics listener is disabled (`[node] metrics` empty/off/bind failure), use `/v1/admin/metrics` as the
  fallback (admin JWT required, see §3.2) and enable `prometheus.yml` option B accordingly;
- Docker is available on the host (Prometheus/Grafana run in containers; PG/Redis/MinIO can also be started with `deploy/compose/dev.yaml`);
- the validation scripts need Python (PyYAML, optional promql-parser) and Node.js (dashboard JSON.parse).

### 3.2 (fallback only) generate/refresh the admin JWT for scraping

> The main path uses the unauthenticated 9100 endpoint and does **not** need a JWT. This section applies only when the `/v1/admin/metrics` fallback is enabled.

```powershell
# one-shot generation (writes the token file, the token only, no newline)
powershell -NoProfile -File scripts\obs-refresh-admin-jwt.ps1 -OutFile tmp\lattice-admin.jwt
# refresh every 5 minutes (JWT TTL=900s; Prometheus re-reads credentials_file on every scrape)
schtasks /Create /SC MINUTE /MO 5 /TN "LatticePromToken" ^
  /TR "powershell -NoProfile -File E:\Development-Warehouse\github\lattice\scripts\obs-refresh-admin-jwt.ps1 -OutFile E:\Development-Warehouse\github\lattice\tmp\lattice-admin.jwt" /F
```

> Security: the token file is a sensitive credential; keep it in a local temp directory/read-only mounted volume and never commit it.
> The script refreshes with a fixed `device_fp` (`sha256:obs-prometheus-scraper`) so the devices table does not grow.

### 3.3 Start Prometheus

```powershell
docker run -d --name lattice-prometheus -p 9090:9090 `
  -v "${PWD}\deploy\observability\prometheus\prometheus.yml:/etc/prometheus/prometheus.yml:ro" `
  -v "${PWD}\deploy\observability\prometheus\lattice-alerts.yml:/etc/prometheus/lattice-alerts.yml:ro" `
  prom/prometheus:v2.55.0 --config.file=/etc/prometheus/prometheus.yml
# only the fallback (/v1/admin/metrics) needs the extra token mount:
#   -v "${PWD}\tmp\lattice-admin.jwt:/etc/prometheus/lattice-admin.jwt:ro"
# add this on Linux where host.docker.internal does not exist: --add-host=host.docker.internal:host-gateway
```

Open <http://127.0.0.1:9090>:
- `/targets`: `lattice-node` should be UP (otherwise check the error: connection refused = 9100 not listening/port mapping missing; context deadline = timeout);
- `/rules`: 6 groups / 18 rules should be visible (`LatticeNodeScrapeDown` etc.);
- `/alerts`: empty when nothing fires.

> If Prometheus runs on the host itself (not in a container), change the target in `prometheus.yml` to `127.0.0.1:9100`
> and `rule_files` to `./lattice-alerts.yml`. If node and Prometheus share a compose network
> (`docker compose -f deploy/compose/dev.yaml up -d`), use target `node:9100`.
> The fallback `/v1/admin/metrics` corresponds to targets `host.docker.internal:8080` / `127.0.0.1:8080` / `node:8080`.

### 3.4 Start Grafana and import the dashboard

```powershell
docker run -d --name lattice-grafana -p 3000:3000 `
  -e GF_SECURITY_ADMIN_PASSWORD=lattice_grafana_pw `
  grafana/grafana:11.2.0
```

1. Open <http://127.0.0.1:3000> (admin/lattice_grafana_pw);
2. `Connections → Data sources → Prometheus`, set the URL to `http://host.docker.internal:9090` (port 9090 by default), Save & test;
3. `Dashboards → New → Import → Upload JSON file`, choose `deploy/observability/grafana/lattice-overview.json`,
   select the Prometheus just created in the datasource dropdown (the `DS_PROMETHEUS` variable) → Import;
4. the dashboard refreshes every 30s and shows the last 6 hours by default.

> The dashboard JSON uses Grafana's export/import format (`__inputs` + the `DS_PROMETHEUS` datasource variable),
> so **importing through the Import flow is recommended**. To put it in `provisioning/dashboards` for automatic file loading, first replace
> `${DS_PROMETHEUS}` in the panels with the real datasource UID (Grafana does not resolve `__inputs` in provisioned JSON).

### 3.5 Scrape addresses and authentication

| Address | Status | Authentication | Notes |
| --- | --- | --- | --- |
| `http://127.0.0.1:9100/metrics` | **main path (currently available)** | none (read-only; restrict sources with NetworkPolicy/firewall in production) | standalone metrics endpoint from doc §8.1, provided by `observe/metrics_server.rs`; `prometheus.yml` option A scrapes here by default; measured 2026-11-21 13:28 HTTP 200 |
| `http://127.0.0.1:9100/healthz` | available | none | metrics listener liveness probe, returns `ok` (a bind failure only warns and does not block the message plane) |
| `http://127.0.0.1:8080/v1/admin/metrics` | fallback available | `Authorization: Bearer <admin JWT>` (`require_role(Viewer)`; admin satisfies it; TTL=900s) | for old binaries or when the metrics listener is disabled; `prometheus.yml` option B (commented by default); disable option A when enabling it |
| `http://127.0.0.1:8080/v1/ready` | available (unauthenticated) | none | returns deps status; 503 only when PG and Redis are **both** unavailable. Requires blackbox_exporter to become the `probe_success` metric (optional option C) |
| Prometheus UI | `http://127.0.0.1:9090` | none | `/targets`, `/rules`, `/alerts` |
| Grafana UI | `http://127.0.0.1:3000` | admin/lattice_grafana_pw | dashboard import |

Quick scrape check (PowerShell):

```powershell
# main path: the 9100 standalone endpoint (unauthenticated)
Invoke-WebRequest 'http://127.0.0.1:9100/metrics' |
  Select-Object -ExpandProperty Content | Select-String 'lattice_(connections|msgs_total|backpressure_dropped_total)'
# fallback: /v1/admin/metrics + admin JWT
$jwt = Get-Content tmp\lattice-admin.jwt -Raw
Invoke-WebRequest 'http://127.0.0.1:8080/v1/admin/metrics' -Headers @{ Authorization = "Bearer $jwt" } |
  Select-Object -ExpandProperty Content | Select-String 'lattice_(connections|msgs_total|backpressure_dropped_total)'
```

---

## 4. Alert meanings and handling

Rule file: `deploy/observability/prometheus/lattice-alerts.yml` (6 groups / 18 rules, all with summary/description/runbook).
Severity follows doc §8.3 wording: **P1 act immediately / P2 act during the shift / P3 watch**.

### 4.1 Rule summary

| # | Alert | Severity | Trigger (summary) | Meaning | First action |
| --- | --- | --- | --- | --- | --- |
| 1 | LatticeNodeScrapeDown | P1 | `up{job="lattice-node"} == 0` 1m | node down/process exit/9100 metrics listener not started/scrape unreachable (under the fallback, possibly an expired JWT too) | check the process and port 9100 → curl `:9100/metrics` and `/v1/ready` → read the Prometheus target error |
| 2 | LatticeNodeOnlineConnectionsCollapsed | P2 | online connections drop >90% vs 10m ago with baseline ≥10, 5m | mass disconnect/node restart/registration-deregistration anomaly (heartbeat-metric fallback) | check node logs and the Redis online index; see whether it fires together with up |
| 3 | LatticeDependencyUnavailable | P1 | `probe_success{job="lattice-ready"} == 0` 2m | dependency unavailable (PG+Redis down together or node unreachable; requires blackbox) | locate via details.dep in `/v1/ready`; after recovery reconcile first, then restore traffic |
| 4 | LatticeWalSizeHigh | P2 | `lattice_wal_size_bytes > 1GiB` 5m | WAL backlog, disk about to fill / degraded path anomaly | check disk, WAL write errors and the jobs cleanup task |
| 5 | LatticePendingDepthCritical | P1 | `sum(lattice_pending_depth) > 100000` 5m | severe offline-queue backlog (doc §8.3 P1 threshold) | spot-check the oldest messages via `/v1/admin/queue`, check redelivery and acks |
| 6 | LatticePendingDepthWarning | P2 | `> 10000` 10m | offline backlog trending up | watch growth, check Redis pending and redelivery throughput, scale out/rate-limit early |
| 7 | LatticeBackpressureDropWarning | P2 | `sum by (priority)(rate(lattice_backpressure_dropped_total[5m])) > 1` 5m | the 256-frame downstream queue keeps dropping (weak network/slow client) | locate the link and slow clients by priority; rate-limit the sender/SDK consumption |
| 8 | LatticeBackpressureDropCritical | P1 | same as above, all nodes `> 50` frames/s 5m | mass message loss/egress congestion | locate by user dimension; rate-limit, scale out, evaluate DLQ replay |
| 9 | LatticeSseConnectionsNearLimit | P2 | `lattice_sse_connections >= 80` 5m | console SSE approaching the cap of 100 | close extra console tabs; confirm the counter falls back (inc/dec paired) |
| 10 | LatticeSseConnectionsExhausted | P1 | `lattice_sse_connections >= 100` 1m | SSE exhausted, new connections get 429(sse_limit) | locate the consumers, disconnect abnormal connections; raise `admin.sse_max_connections` if needed |
| 11 | LatticePluginCallLatencyHigh | P2 | plugin P99 > 0.5s 5m (awaiting instrumentation) | plugin calls exceed the 500ms timeout line | check plugin process/sidecar resources and the canary ratio; roll back if needed |
| 12 | LatticePluginCallFailureRateHigh | P2 | plugin hub `/v1/hub/*` 5xx ratio >5% 5m (awaiting instrumentation) | plugin publish/download/install API failures | locate by API and audit log; check MinIO/PG and the hub cleanup tasks |
| 13 | LatticeE2eLatencySloBreach | P2 | E2E P99 > 100ms 5m (awaiting real instrumentation) | doc §8.3 P2 latency SLO breach | check store latency, PG/Redis and node load |
| 14 | LatticeE2eLatencyCritical | P1 | E2E P99 > 500ms 5m (awaiting real instrumentation) | severe latency SLO breach | check dependencies/load immediately; drain/scale out/roll back |
| 15 | LatticeStoreLatencyHigh | P2 | storage P99 > 500ms 5m (awaiting instrumentation) | one storage backend got slower | locate the slow backend (PG slow query/lock, Redis, S3) |
| 16 | LatticeMessageErrorRateHigh | P2 | `msgs_total{state=dropped/expired/dlq}` share >5% 10m | abnormal share of failed/expired/dead-lettered deliveries | break it down by state, check DLQ and delivery state, replay after fixing |
| 17 | LatticeChunkRetransRateHigh | P2 | retransmission rate / message rate >1% 5m | frequent chunk redelivery or seq-regression correction | locate by reason: weak network/chunk timeout/seq-watermark reconciliation |
| 18 | LatticeRateLimitDropSpike | P3 | rate-limit drops >10 per second 5m | sender over quota / traffic flooding / load test | locate user_hash and source IP; route anomalies to risk control, otherwise review quotas |

### 4.2 Handling runbook by symptom

**A. Node down (rules 1/2)**
1. `Get-Process lattice-node` / `Get-NetTCPConnection -LocalPort 9100 -State Listen` to confirm the process and metrics port;
   containerized: `docker ps` for `lattice-dev-node` health; `docker port lattice-dev-node` should show `9100/tcp -> 0.0.0.0:9100`;
2. `Invoke-RestMethod http://127.0.0.1:8080/v1/ready`: with `ready:false` inspect `deps`;
   if `ready:true` but Prometheus Up=0: check 9100 first (`curl http://127.0.0.1:9100/metrics` and `/healthz`);
   a 9100 bind failure only logs a warning (node log `metrics listener bind failed`) and the message plane still works → fix port/config;
   if the `/v1/admin/metrics` fallback is enabled, also check the token file (`Get-Content tmp\lattice-admin.jwt`) and 401s;
3. when the target is unhealthy, read the error column on Prometheus `/targets` (connection refused → 9100 listen/mapping; context deadline → scrape_timeout);
4. process already exited: find the panic cause in node logs (`.dev/node-hub.err.log` or `docker logs lattice-dev-node`) and restart per the release process
   (**note this repo's rule: probes/scripts must not stop the existing shared dev node**).

**B. Dependency unavailable (rule 3)**
1. `details.dep` in `/v1/ready` names the dependency that failed first (the implementation returns 503 only when both pg and redis fail; `dep` is usually `pg`);
2. `docker ps` for `lattice-dev-pg` / `lattice-dev-redis` / `lattice-dev-minio` health and logs;
3. recovery order follows doc §7.4: **PG before Redis/NATS**, then reconcile with `lock:reconcile` (doc ⑥ §6.4) before restoring traffic, so pending messages are not silently lost;
4. single-dependency degradation (Redis unavailable etc.) currently has **no metrics** to observe directly and `/v1/ready` still returns 200—a known gap (§7).

**C. pending backlog / backpressure drops (rules 5-8)**
1. `GET /v1/admin/queue?user=<id>` or the console Queue page for depth/oldest message; `lattice_pending_depth{user_hash}` for hot users;
2. backpressure drops by `priority`: `envelope` (normal downstream dropped) is most common, `stream-data` is a fixed datapoint when the WS tunnel is off (not a full queue), `route` is a full target queue during cross-node forwarding;
3. the root cause is usually a slow/non-consuming client (weak network, background sleep, client bug) → rate-limit the sender, fix the client, scale out nodes;
4. to observe a real drop curve, reproduce with `scripts/obs-backpressure-live.ps1` (see `perf/reports/backpressure-20261121.md`; 1600×16KiB dropped ~900 frames in the measurement).

**D. SSE connection cap (rules 9/10)**
1. `lattice_sse_connections` counts only `/v1/admin/stream`; the cap is `lattice_core::protocol::SSE_MAX_CONNECTIONS=100`, after which new connections get `429 sse_limit`;
2. `SseGuard::Drop` decrements when a connection ends; a counter that only grows indicates a connection-leak regression—check node logs and gateway long-connection reclamation;
3. temporary mitigation: disconnect abnormal sources, raise `admin.sse_max_connections`, degrade the console to polling (the doc §12 P5 design).

**E. Plugin call latency/failure (rules 11/12)**
1. plugin call metrics in metrics.rs are not wired yet, so the rules use plugin-hub HTTP 5xx as a proxy; check node logs and `/v1/admin/audit` first;
2. check MinIO (the `lattice-plugins` bucket), PG `hub_*` tables and the `hub-object-gc`/`hub-draft-clean` tasks;
3. if a specific plugin version causes it, roll back/withdraw that version; once instrumentation lands, watch the 500ms timeout line.

**F. Error rate/latency SLO (rules 13-17)**
1. first confirm whether E2E/store metrics are really instrumented (E2E currently reports a 0 placeholder and store is not wired → these two rule families will not fire spuriously, and are temporarily ineffective);
2. `LatticeMessageErrorRateHigh` uses the instrumented `msgs_total{state}` and breaks it down by state: `dropped`→backpressure/routing; `expired`→TTL/consumption stall; `dlq`→retries exhausted;
3. `LatticeChunkRetransRateHigh` by reason: `request`→client redelivery (weak network/timeout); `seq_regression`→seq-watermark reconciliation/cross-node clock issues;
4. after fixing, confirm no silent loss through the DLQ replay and reconciliation process (perf/README.md).

**G. WAL / rate limiting (rules 4/18)**
- WAL: check disk space, `store/wal` write errors and the snapshot/cleanup job; continued growth leads to write failures → drain the node.
- rate limiting: `user_hash` in `lattice_ratelimit_dropped_total{user_hash}` is the first 8 characters of user_id (low-cardinality);
  reverse-look it up with `GET /v1/admin/users?q=`; route abnormal flooding to `lattice:risk` risk control, and review quotas/scaling for organic growth.

### 4.3 Threshold sources (aligned with doc §8.3)

| Doc §8.3 threshold | Rule here |
| --- | --- |
| P1: readiness probe failure | `LatticeDependencyUnavailable` (blackbox `/v1/ready`) |
| P1: pending_depth > 100k for 5min | `LatticePendingDepthCritical` |
| P1: PG primary unavailable / dedup unavailable on all layers | ⚠️ no dependency or dedup-availability metrics today → approximated with `LatticeDependencyUnavailable`; total dedup unavailability cannot be alerted on directly (gap, see §7) |
| P2: e2e P99 > 100ms 5min | `LatticeE2eLatencySloBreach` |
| P2: chunk_retrans rate > 1% | `LatticeChunkRetransRateHigh` |
| P2: plugin error rate > 5% | `LatticePluginCallFailureRateHigh` (HTTP 5xx proxy, awaiting instrumentation) |
| P2: WAL > 1GB | `LatticeWalSizeHigh` |
| P3: disk >80%, memory >75%, NATS reconnect, MinIO rebuild | needs external exporters such as node-exporter/blackbox; not included in this deliverable (gap, see §7) |

---

## 5. Mapping to doc ② (`the platform implementation document (outside this repository)`) §8 / §12

| Doc | Content | Where this delivery lands |
| --- | --- | --- |
| §8.1 | metric table (name/type/labels) and dual export via `/v1/admin/metrics` + OTLP | `prometheus.yml` scrapes that endpoint; metric names follow `observe/metrics.rs` (differences in §2.2 here); OTLP is out of scope |
| §8.2 | tracing JSON / OTel trace / Jaeger sampling | not covered (this delivery is metrics alerts/dashboards only) |
| §8.3 | alert severities and thresholds (P1/P2/P3) | the 18 rules in `lattice-alerts.yml` follow those thresholds (see §4.3) |
| §10 | load tests and SLOs (connection storm/throughput/E2E P99/large files/redelivery/chaos/broadcast, `perf/reconcile`, `perf/reports/{date}-{scenario}.md`) | `perf/README.md` documents how to run PL-17 load tests and reconciliation; `perf/reports/backpressure-20261121.md` is the backpressure scenario that was executed; the other scenarios were **not executed** (reasons in that README) |
| §12 P5 | console SSE cap 100, degrade to polling when exceeded | `LatticeSseConnectionsNearLimit/Exhausted` alerts + dashboard SSE panel |
| §12 P6 | admin-plane/data-plane isolation within a node (separate admin connection pool) | no admin-specific metrics yet; `lattice_http_requests_total` is not instrumented → the admin plane cannot be observed separately (gap, see §7) |
| §12 P8 | per-user pending backlog fairness | `lattice_pending_depth{user_hash}` panel (TopN) + `LatticePendingDepth*` alerts; the 1M-per-user backlog load test was not executed |
| §12 P10 | `pending:*` is the only queue that cannot self-prove, needing `lock:reconcile` as a fallback | the alert descriptions require reconciliation after recovery; the `perf/reconcile` script does not exist yet → not executed (see perf/README.md) |
| ⑤ §8.5 | SSE cap 100 | the SSE alert and dashboard thresholds use `SSE_MAX_CONNECTIONS=100` |
| §3.1 (v0.10) | backpressure drops must be metered (`Hub::try_send` drop branch incs `lattice_backpressure_dropped_total{priority}`) | backpressure alerts and dashboard panels + measurement report (`perf/reports/backpressure-20261121.md`, priority=`envelope`) |

> Note: the implementation doc has only §1-§12 (§12 = open questions on the platform side). The observability-related P5/P6/P8/P10 of "doc ② §12" are mapped item by item in the table above.

---

## 6. Validation method and results (2026-11-21)

### 6.1 Environment notes (recorded as-is)

- the original Python environment **had no PyYAML** (`python -c "import yaml"` → `ModuleNotFoundError`).
  To satisfy the "parse with Python yaml" validation requirement, `python -m pip install pyyaml` was run on this host (installed into the user environment,
  version **6.0.3**) without modifying repo dependency files;
- `promql-parser` was also installed (optional, for parsing PromQL statements one by one);
- if the target environment is offline and PyYAML cannot be installed: `scripts/obs-validate.ps1` automatically enters a **degraded branch**,
  prints `[DEGRADED]` and switches to minimal structure checks (file non-empty, groups/rules, required keys, alert count);
  in that case the "YAML semantic parsing/PromQL syntax" items are unavailable — this is a built-in degradation, not a faked pass.

### 6.2 One-shot validation

```powershell
python -m pip install pyyaml promql-parser   #python -m pip install pyyaml promql-parser   # optional; the script degrades when missing
powershell -NoProfile -File scripts\obs-validate.ps1
```

Measured output of 2026-11-21 (excerpt; full output in `perf/reports/validation-20261121.txt`):

```
[OK]   PyYAML available: 6.0.3
[OK]   PyYAML parsed alerts successfully
[OK]   alerts top-level structure: groups array (6 groups)
[OK]   alert names unique (18)
[OK]   total alert rules = 18
[OK]   alert coverage: node down
[OK]   alert coverage: dependency unavailable
[OK]   alert coverage: pending backlog
[OK]   alert coverage: backpressure drops
[OK]   alert coverage: SSE cap
[OK]   alert coverage: plugin call latency/failure
[OK]   alert coverage: error rate and latency SLO
[OK]   all PromQL expressions parse (18)
[OK]   PyYAML parsed prometheus.yml successfully
[OK]   prometheus.yml rule_files: ['/etc/prometheus/lattice-alerts.yml']
[OK]   prometheus.yml scrape_configs: ['lattice-node']
[OK]   active targets: ['host.docker.internal:9100']
[OK]   only 1 active scrape job (no duplicate scraping)
[OK]   prometheus.yml comments document the node:9100 target
[OK]   prometheus.yml comments document host-local 127.0.0.1:9100
[OK]   lattice-node job metrics_path=/metrics (9100 standalone endpoint, unauthenticated)
[OK]   lattice-node job does not depend on JWT (the 9100 endpoint needs no auth)
[OK]   fallback /v1/admin/metrics job not enabled (kept commented to avoid duplicate scraping)
[OK]   prometheus.yml comments keep the /v1/admin/metrics fallback documented
[OK]   blackbox /probe job not enabled (optional option kept commented)
[OK]   node JSON.parse passed: deploy/observability/grafana/lattice-overview.json
[OK]   schemaVersion=39
[OK]   panels=19 (>=10)
[OK]   datasource variable DS_PROMETHEUS present
[OK]   all dashboard metric names are in the metrics.rs whitelist (15)
[OK]   all dashboard PromQL parses (23)
RESULT: PASS
```

Validation coverage: YAML parsing (PyYAML), structure (groups→rules, name/expr/for/labels/annotations, severity∈P1/P2/P3),
PromQL syntax (18 rules + 23 dashboard queries), metric-name whitelist (14, all from metrics.rs),
the 7 alert categories required by doc §8.3, and dashboard completeness (19 panels/required categories/datasource variable/targets).

> Note: `scripts/obs-validate.ps1` validates rule **syntax and structure** only; the correctness of `for`/thresholds/business semantics comes from manual review +
> measurement (the backpressure metrics were verified with real machine data in `perf/reports/backpressure-20261121.md`).

### 6.3 Scrape-end measurements (2026-11-21)

| Check | Command/method | Result |
| --- | --- | --- |
| 9100 standalone metrics endpoint (main path) | `Invoke-WebRequest http://127.0.0.1:9100/metrics` (no auth headers) | **HTTP 200**, Prometheus text; `/healthz` returns `ok`; `# TYPE` includes `lattice_e2e_latency_seconds` etc. |
| fallback `/v1/admin/metrics` | `scripts/obs-refresh-admin-jwt.ps1` generates a token → scrape with `Bearer` | **HTTP 200** (readable only with an admin JWT; the script's token was verified and deleted right away) |
| node readiness | `GET /v1/ready` | `{"ready":true,"deps":{"pg":"ok","redis":"ok","bus":"ok"}}` |
| Prometheus / Grafana containers | — | **not actually started** (this delivery only provides config/dashboards, validated with static checks + endpoint measurements; see the unexecuted items in `perf/README.md`) |

> Environment note: between 13:18 and 13:28 on 2026-11-21, another parallel task added `observe/metrics_server.rs` to the source
> and exposed 9100 in `deploy/compose/dev.yaml` (`LATTICE__NODE__METRICS=0.0.0.0:9100`), so the container node
> `lattice-dev-node` became scrapeable on 9100 after startup; the metric definitions in `metrics.rs` are unchanged since 2026-10-26, and this document has been updated to the latest code facts.
> In the task's initial snapshot before that, 9100 was not listening and only the `/v1/admin/metrics` fallback worked (the backpressure measurement in this directory happened during that window,
> see the environment notes in `perf/reports/backpressure-20261121.md`).

---

## 7. Known gaps and follow-up work (registered without modifying src)

| # | Gap | Impact | Suggestion |
| --- | --- | --- | --- |
| G1 | ~~`node.metrics="127.0.0.1:9100"` standalone scrape endpoint not implemented~~ | ✅ **resolved** (a parallel task landed `observe/metrics_server.rs` on 2026-11-21): /metrics is unauthenticated read-only, binds `[node] metrics`; measured 9100 returning 200 | remaining: production must restrict sources with NetworkPolicy/firewall; the in-container `LATTICE__NODE__METRICS=0.0.0.0:9100` is a dev-compose exposure and production should narrow it to the cluster network |
| G2 | `lattice_http_requests_total` has no inc call site | error rate/5xx/plugin failure rate/admin-plane isolation (§12 P6) all lack data | count by `{path,status}` in an axum middleware (normalize path to avoid high cardinality) |
| G3 | `lattice_store_latency_seconds` has no `record_store()` call site | storage-latency SLO alerts are ineffective | call `record_store(started)` in the PG/Redis/S3 access wrappers (the doc originally planned backend/op labels; implement them together) |
| G4 | `lattice_plugin_call_duration_seconds` has no observe call site; no plugin failure counter | plugin latency/failure alerts are inert (currently proxied by hub HTTP 5xx) | instrument plugin calls + add a counter such as `lattice_plugin_call_failures_total{plugin_ns,reason}` |
| G5 | `lattice_e2e_latency_seconds` only has an `observe(0.0)` placeholder | E2E latency SLO alerts/dashboard are ineffective | record real durations across the Envelope path (inbound→deliver) |
| G6 | `lattice_pending_depth` is only refreshed on ack_remove and only has `scope="user"` | depth lags, device/topic levels are invisible, P1 thresholds may fire late | update on both enqueue and dequeue paths; add device/topic scopes (doc §8.1) |
| G7 | no dependency availability metrics (no `dep_up`), no heartbeat metric | dependency unavailability can only use the `/v1/ready` blackbox (and only 503s when both dependencies are down); heartbeats only fall back to up | add metrics such as `lattice_dep_up{backend=pg|redis|bus}` and `lattice_node_heartbeat_age_seconds`; or make /v1/ready return 503 when a single dependency fails/expose deps metrics |
| G8 | dedup unavailability on all layers, disk/memory/NATS reconnect, MinIO rebuild and other doc §8.3 P1/P3 items have no corresponding metrics | cannot be alerted on directly | needs external exporters such as node-exporter/blackbox or new metrics; future iteration |
| G9 | no Alertmanager config/routing | firing rules only reach Prometheus `/alerts`, with no notifications | connect Alertmanager per deployment environment (a commented slot exists in `prometheus.yml`), configure P1/P2 routing and silence policies |
| G10 | scrape tokens depend on a 900s TTL and external refresh | a missing refresh job causes 401 → spurious `LatticeNodeScrapeDown` | use `scripts/obs-refresh-admin-jwt.ps1` + a scheduled task; remove this dependency once 9100 lands |

---

## 8. Limitations and notes

- this delivery is a **dev single-node** example: thresholds (100k pending, 500ms/100ms latency, SSE 80/100) come from the docs and code constants,
  so production must recalibrate them by capacity; Prometheus scrape targets/alert receivers must be changed for the actual cluster.
- only **option A** (the 9100 standalone metrics endpoint, `observe/metrics_server.rs`) is enabled by default; do **not** enable option B
  (`/v1/admin/metrics` + JWT) at the same time, or the same metrics are scraped twice; the fallback is only for old binaries/nodes with the metrics listener disabled.
- 9100 is an **unauthenticated** read-only endpoint: in dev, compose maps it to the host as `0.0.0.0:9100`; in production, NetworkPolicy/firewall
  must restrict sources (the design premise of doc §8.1)—do not expose it to the internet.
- do not commit the JWT token file (needed only for the fallback); `admin/lattice_dev_admin_pw` is a dev-only credential.
- panels marked "awaiting instrumentation" in the dashboard (storage/plugins/E2E/HTTP) currently show No data; that is the known gap from §7, not a fault.
- testing/validation does not modify src/docs/existing scripts; the `scripts/obs-*.ps1` files are all new here, and after running they do not `stop`/`restart`
  any existing service (the backpressure probe script already builds in "do not kill processes + precise cleanup").
