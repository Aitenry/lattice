# Lattice production HA deployment skeleton (PG / Redis / NATS / MinIO)

> **Status: a copyable template, not a running cluster.** This repository only has a single-host dev Docker
> environment, with no more than 3 hosts, so every configuration in this directory has **only been validated
> offline** (`python scripts/ha-manifest-check.py` + `docker compose config`); **no production/multi-node
> cluster has been brought up**, and no real leader election, switchover, or cross-site replication has been
> performed.
> When "production RPO/RTO achieved" may be declared from this directory: after completing the quarterly
> drill checklist in §7 and recording data on a real cluster.
>
> Design basis (authoritative parameters have exactly one source): the design document (outside this repository) §2 (RPO ≤5min /
> RTO ≤30min), §11 (topology), §17.13 (infrastructure parameters: PG 16+Patroni+etcd×3, Redis Sentinel×3,
> NATS JetStream×3, MinIO 4×4 drives EC 12+4). This directory does not redefine values; it only projects
> them into deployment.

## 1. Topology

```
                       Clients: Tauri desktop / Web console / MQTT devices
                                    │
                    ┌───────────────▼─────────────────┐
                    │ Keepalived VIP ×2 (active-active)│  VIP drifts in seconds on failure
                    └───────────────┬─────────────────┘
                    ┌───────────────▼─────────────────┐
                    │ Nginx/Envoy ×2                  │  TLS termination / WS upgrade / SSE / canary weights
                    └──┬────────────┬────────────┬────┘
        ┌──────────────┘            │            └──────────────┐
┌───────▼────────┐        ┌─────────▼────────┐        ┌─────────▼────────┐
│ lattice-node 1 │        │ lattice-node 2   │        │ lattice-node 3   │   ≥3 stateless, HPA-capable
│ :8080 :9090    │        │                  │        │                  │
│ :9100 :1883    │        │                  │        │                  │
└──┬───┬───┬───┬─┘        └──────────────────┘        └──────────────────┘
   │   │   │   │
   │   │   │   └──► S3 stable endpoint (LB, TLS termination) ──► MinIO ×4 (4×4=16 drives, EC 12+4)
   │   │   │                                        └─ lattice-large/media/cold/plugins
   │   │   │                                           (lattice-cold is also the PG WAL archive target)
   │   │   └──────► NATS stable endpoint (L4 VIP/DNS) ──► JetStream ×3 (Raft)
   │   │                                          └─ LATTICE_ROUTE/BROADCAST/AUDIT/MEDIA
   │   └──────────► Redis stable endpoint (HAProxy/VIP) ──► 1 primary + 2 replicas + Sentinel ×3 (quorum 2)
   └──────────────► PG stable endpoint (HAProxy/VIP) ─────► Patroni + PG16 1 primary + 2 replicas + etcd ×3
                                                     └─ WAL archive ──► MinIO lattice-cold (PITR)

    Observability: Prometheus scrapes node:9100 / nats exporter / minio / node_exporter / postgres_exporter
        + alert rules in deploy/observability; grafana dashboards
```

> Every "stable endpoint" in the diagram is mandatory, not an optional optimization: the node code has only
> **single-endpoint** clients for PG/Redis/NATS/S3 (see the "Node-side limitation" column in §5). Without a
> stable endpoint, any instance switchover points the node at the old address.

## 2. Deployment order (dependencies)

Follow this order strictly; each step includes its acceptance point. **PG is always recovered first, and
web/LB traffic ramp-up is last** (② §7.5).

| # | Step | What to do | Acceptance |
|---|---|---|---|
| 0 | Prerequisites | Domains/DNS, VIP+Keepalived, LB, certificates (JWT private key / mTLS / LB TLS), secret management, **NTP clock sync** (replication/Sentinel/Raft all depend on the clock), monitoring | `chronyc tracking` skew <100ms; Secrets can inject environment variables |
| 1 | etcd ×3 | The etcd topology in `deploy/production/patroni/` (production = 3 hosts) | `etcdctl endpoint health` all green on 3 hosts; `etcdctl member list` shows 3 members |
| 2 | PG Patroni ×3 | `deploy/production/patroni/README.md` §1: render `patroni.yml` → start the 3 hosts → create database/migration | `patronictl list` shows 1 Leader + 2 Replica, lag≈0; `pg_stat_archiver.failed_count=0` |
| 3 | MinIO ×4 | `deploy/production/minio/`: start 4 nodes (16 drives) → `bucket-setup.sh` creates buckets/versioning/IAM | `mc admin info` shows 4 nodes online with 4 drives each; the 4 buckets exist and are versioned |
| 4 | Redis HA | `deploy/production/redis/`: master→replica×2→sentinel×3 | Sentinel `master lattice` shows quorum 2 / 2 replicas / link up |
| 5 | NATS ×3 | `deploy/production/nats/`: start 3 nodes → **`streams.sh` pre-creates the streams with replicas=3** | `nats stream report` shows Replicas=3 for all 4 streams; `/healthz` ok on all 3 |
| 6 | lattice-node ×N | Helm chart or bare metal; inject Secrets such as `LATTICE__PG__URL`; **start 1 instance to run migrations first, then scale to ≥3** | `/v1/health` 200, `/v1/ready` 200; logs show `migration` complete, the 4 Streams reused, S3 bucket HEAD hits |
| 7 | web ×2 + Nginx/LB | The web from `deploy/helm` + the `deploy/nginx.conf` shape; LB drain/canary | `curl https://<vip>/` 200; WS upgrade works; `/v1` reverse proxy 200 |
| 8 | Observability/alerting | Prometheus rules/dashboards in `deploy/observability/` | Alert rules load successfully (`promtool check rules`); key panels have data |
| 9 | Acceptance | `scripts/ha-manifest-check.py`; the production equivalent of `scripts/smoke-container.ps1`; `python scripts/reconcile.py`; one controlled failover drill | All green + a filed drill record (RTO/RPO numbers) |

> The only manual database-creation step: create the `lattice` database after Patroni first elects a primary
> (`patroni/init-lattice-db.sh`, already hooked into `bootstrap.post_bootstrap`) — the node only creates
> tables via sqlx migrations; it never creates databases.
> Production migrations should be **run by a single instance** (start 1 first) and the replicas scaled out
> afterwards.
>
> Order for landing TLS/certificates and backups:
> - **Before step 6**: the certificate system is ready (`deploy/production/tls/README.md`: cert-manager or
>   sealed-secrets, Secret key contract, node gRPC/MQTT/QUIC and Ingress certificates); otherwise enabling
>   node `tls.*` fails because the Secret is missing;
> - **After step 6**: enable Helm's `backup.enabled` / `backup.pitr.enabled`, and make sure `archive_command`
>   on the PG side already points at object storage (`deploy/production/backup/README.md`).

## 2.1 TLS / backup productionization entry points (new, still templates)

| Topic | Document | Coverage | Unvalidated |
|---|---|---|---|
| TLS/mTLS certificate system | [`tls/README.md`](tls/README.md), [`tls/cert-manager.yaml`](tls/cert-manager.yaml), [`tls/sealed-secret.example.yaml`](tls/sealed-secret.example.yaml) | HTTP/WS (Ingress/web 8443), MQTT 8883 (device certificate mTLS), gRPC 9090 (inter-node mTLS), QUIC UDP (server TLS); Secret key contract/least privilege/rotation/revocation | Real issuance, handshakes, rotation, sealed-secrets decryption, LB termination |
| Backup / PITR | [`backup/README.md`](backup/README.md), [`backup/archive-verify.sql`](backup/archive-verify.sql), [`backup/base-backup.sh`](backup/base-backup.sh), [`backup/pitr-verify.sh`](backup/pitr-verify.sh) | Three backup layers (pg_dump/physical base/WAL archive), scheduling/retention, SSE-KMS+object lock+off-site copy, archive health check (same SQL as the Helm CronJob) | Object-storage archive path, CronJob execution, retention/encrypted restore, cross-site replication |
| Canary release | [`canary-runbook.md`](canary-runbook.md), [`../helm/lattice/README.md`](../helm/lattice/README.md) §10 | Dual Deployment (stable/canary node) + ingress-nginx `canary-weight`/`canary-by-header` splitting, phased ramp-up/decision metrics/rollback commands; chart-side offline assertions in `scripts/helm-canary-validate.py` | Real ingress-nginx proportional splitting and header matching, external LB weights, MQTT/QUIC device canary, proportional gRPC splitting |

## 3. Per-component RPO / RTO expectations

Design target (design §2): **RPO ≤ 5min, RTO ≤ 30min**. The "Measured" column below cites only **dev
single-host** drill numbers from this repository and **must not** be extrapolated into production conclusions
(see §7).

| Component | Target RPO | Target RTO | Mechanism | Status / measured reference |
|---|---|---|---|---|
| **PG (automatic failover)** | **0** (committed transactions are not lost) | about 30–60s (estimate: leader key ttl=30s expiry + election/promotion; design target switchover <30s, not measured) | `synchronous_mode=true` (commit needs ≥1 synchronous replica ack) + Patroni election (ttl 30s) + stable endpoint drift | Template; cluster unvalidated. Failover time not measured (estimated from `ttl/loop_wait/retry_timeout`) |
| **PG (disaster recovery / PITR)** | ≤ 5min (mechanical upper bound = `archive_timeout=60s` + archive upload time + one WAL segment; measured archive lag 4.1s) | ≤ 30min (including manual confirmation/drain/restore/verification/ramp-up) | `archive_mode=on` + `archive_command` → MinIO; daily `pg_basebackup` base + WAL archiving | Local-directory archive PITR **34/34 PASS** (measured RPO 4.1s, PG automated segment RTO 3.92s, `perf/reports/pitr-20261121.txt`); **object-storage archiving / cross-host / manual ramp-up unvalidated** |
| **Redis (Sentinel switchover)** | Business durable data **0** (authority is in PG: `delivery_log`/`conv_seq_watermark`; switchover losses are backfilled by reconcile); Redis's own asynchronous replication window ≈ ≤1s + AOF everysec | 5–15s (`down-after=5s` + election/promotion; design target: routing uses stale cache during the switchover window) | 1 primary + 2 replicas + Sentinel ×3 (quorum 2); nodes reconnect via the stable endpoint | Template; cluster unvalidated; single-host RDB recovery **29/29 PASS** (0.81s, `perf/reports/recovery-redis-20261121.txt`) does not represent HA |
| **NATS (JetStream 3 replicas)** | Acked messages **0** (Raft 2/3 quorum, 1 node failure loses nothing); if `streams.sh` is forgotten (streams with replicas=1), a single node failure loses that node's stream data | Single node failure: 0 downtime (clients reconnect via the LB, Raft elects in seconds); 2 node failure → degrade to Redis/direct PG writes | 3-node Raft + Stream `replicas=3` + node degradation matrix (② §4.8) | Template; cluster unvalidated; single-host store recovery **31/31 PASS** (1.20–1.53s, `perf/reports/recovery-nats-20261121.txt`) |
| **MinIO (EC 12+4)** | Written objects **0** (tolerates any 4 drive failures ≈ 1 entire node); site-level replication (optional) is asynchronous → cross-site RPO = replication lag | Single drive/node failure does not stop service (background heal); whole-site disaster recovery relies on off-site copies/backups (unvalidated) | 4×4=16 drives in a single set EC 12+4; bucket-setup versioning + optional cross-site replication | Template; distributed cluster unvalidated; single-host single-drive directory recovery **28/28 PASS** (3.12s, `perf/reports/recovery-minio-20261121.txt`) |
| **Access/service layer (node ×≥3)** | 0 (messages land in PG first; when PG is not writable the local WAL absorbs small messages, ≤64MiB) | seconds (LB health check removal + automatic client reconnect; rolling upgrade with `maxUnavailable=0`) | PDB N-1, HPA min 3, preStop drain, node drain semantics | Validated in dev on the Helm/node side; production LB/VIP unvalidated |

**Overall**: RPO ≤5min / RTO ≤30min is a **design target**; this skeleton only provides the mechanism and
expectations; it is **not accepted end to end** (the recovery drill covers only the component automation
segment, excluding manual failure triage/drain/phased ramp-up and cross-host networking).

## 4. Stable endpoints and the `[pg]/[redis]/[bus]/[s3]` configuration mapping

Node-side configuration (`crates/lattice-node/src/config.rs`) and the corresponding production components.
**The "Node-side limitation" column is the core constraint of this skeleton**: the code has no Sentinel,
multi-host, or server-list client, so HA must provide a stable endpoint at the infrastructure layer.

| Config | Production value (example) | Component providing the stable endpoint | Node-side limitation |
|---|---|---|---|
| `[pg] url` | `postgres://lattice_app@pg-lattice.lattice.internal:5432/lattice?sslmode=verify-full` | HAProxy/VIP: health check Patroni `GET :8008/primary` (200=primary) | sqlx single URL, no multi-host failover; password via the `LATTICE__PG__URL` Secret |
| `[pg] pool_size` | 32/instance | — | 3 nodes ×32=96 connections; Patroni `max_connections=500` leaves headroom; adding PgBouncer requires recalculating |
| `[redis] url` | `redis://:${REDIS_PASSWORD}@redis-lattice.lattice.internal:6379/0` | HAProxy/VIP: `tcp-check` reads `INFO replication` and asserts `role:master` | `redis::Client::open` single URL, **no Sentinel protocol support**; after a switchover it relies on endpoint drift + ConnectionManager reconnect |
| `[bus] kind` / `nats_url` | `kind="nats"` / `nats://lattice-nats.lattice.internal:4222` | L4 VIP/DNS round-robin over the three 4222 ports; async-nats reconnects on its own | `async_nats::connect(&str)` parses only a **single** server address (`cargo-vendor2/async-nats/src/lib.rs:1805-1811`); comma-separated lists are not allowed |
| `[bus] jetstream` | `true` | NATS 3-node Raft; **run `nats/streams.sh` first to create streams with replicas=3** | The node's `get_or_create_stream` uses the default replicas=1 and does no config comparison when the stream exists → no redundancy without pre-creation |
| `[s3] endpoint` | `http://minio-lattice.lattice.internal:9000` | L4 LB forwarding to the four nodes on 9000 | The bucket-create/direct-write path in `store/s3.rs` **supports `http://` only** (https errors out; TLS is terminated at the LB) |
| `[s3] public_endpoint` | `https://s3.example.com` | The same LB's external TLS domain (the Host header must be preserved) | scheme+Host of presigned URLs; must be reachable by clients |
| `[s3] access_key/secret_key` | Dedicated IAM user (created by `bucket-setup.sh`) | — | Do not use root in production; passwords via a Secret |
| `[s3] bucket_*` | `lattice-large/media/cold/plugins` | MinIO 4 nodes EC 12+4 | The node's `ensure_buckets()` only creates plain buckets (no versioning/lock) → in production run `bucket-setup.sh` **first** |
| `[wal] dir/max_bytes` | `/var/lib/lattice/wal` / 64MiB | Local disk (the node itself) | Backstop for small messages when PG is not writable; over the limit messages are rejected and counted in `lattice_wal_dropped_total` |
| `[auth] key_dir` | `/etc/lattice/keys` | Secret volume (`jwt.key.pem` + `jwt.key.prev.pem`) | Rotation via `POST /v1/admin/keys/rotate`; a read-only mount returns an explicit error |
| `[grpc] enabled/tls_*` | Internal mTLS | In-cluster Service/LB | Cross-node fallback routing; the plaintext dev shape must not be used in production |

**HAProxy fragments (PG primary / Redis primary)** — these two entry points are the key to a "stable address":

```haproxy
# PG: only the node where Patroni /primary returns 200 is primary; client writes go only there
backend pg_primary
  mode tcp
  option httpchk GET /primary
  http-check expect status 200
  server pg0 10.20.0.11:5432 check port 8008
  server pg1 10.20.0.12:5432 check port 8008
  server pg2 10.20.0.13:5432 check port 8008

# Redis: read INFO replication; only the node with role:master is healthy
# (expand ${REDIS_PASSWORD} with HAProxy 2.x environment variables, or put it in a separate 0600 config file)
backend redis_master
  mode tcp
  option tcp-check
  tcp-check connect
  tcp-check send "AUTH ${REDIS_PASSWORD}\r\n"
  tcp-check expect string +OK
  tcp-check send "INFO replication\r\n"
  tcp-check expect string role:master
  server redis0 10.30.0.11:6379 check
  server redis1 10.30.0.12:6379 check
  server redis2 10.30.0.13:6379 check
```

> HAProxy/VIP itself also needs active-active (Keepalived); this repository **does not provide** their
> production configuration, only a UDP access topology reference in `deploy/quic-lb-udp.yaml`.

## 5. Switchover / failback runbook (general flow)

Every component switchover follows the same rhythm; **do not improvise a different order during an incident**:

1. **Detect**: alert (component `up=0` / replication lag / `pg_stat_archiver.failed_count>0` / Sentinel `+odown` /
   NATS `server down` / MinIO `drive offline`) → record `T0` (the RTO start).
2. **Confirm**: do not just check process liveness; confirm "is a switchover really needed": for PG check
   `patronictl list` and `pg_isready`; for Redis check the flags of Sentinel `master lattice`; for NATS check
   `nats server list`; for MinIO check `mc admin info`.
3. **Drain/freeze writes** (when the data plane is involved): remove the LB weight → wait for connections to
   drain (node preStop 10s + WS `byef`) → freeze writes to the target component. **Read-only troubleshooting
   may proceed without downtime**, but switchover/restore requires freezing.
4. **Perform switchover/restore**: per the commands in each component README (PG §4, Redis §4, NATS §4, MinIO §4).
5. **Verify**: component self-checks + `python scripts/reconcile.py` + production smoke test (login/health/message round-trip/object download).
6. **Reconcile**: `lock:reconcile` (node startup or periodic task) rebuilds pending from `delivery_log`;
   confirm idempotence.
7. **Phased ramp-up**: LB weight 5% → 25% → 100%, observing error rate/latency/backlog for ≥10min at each step.
8. **Record**: RTO (T0→ramp-up complete), RPO (the data point of the last successful archive/replication),
   cause, and improvements; write them into the drill/incident report (report fields in `scripts/restore-runbook.md`).

### 5.1 Failback principles

- **Do not fail back just to "look restored"**: let the steady-state topology be decided by Patroni/Sentinel/Raft.
- Planned PG switchover back to the original primary: wait until the original primary has rejoined as a
  replica with lag≈0, then run `patronictl switchover` once (`patroni/README.md` §4.2).
- Redis failback: trigger `sentinel failover lattice` once more; **do not run `slaveof` manually** (`redis/README.md` §4).
- NATS/MinIO: a recovered node rejoins the cluster/catches up with Raft automatically; failback only needs a
  configuration/image tag rollback.
- Failback also counts as a switchover → it equally requires draining, reconciliation, and RTO/RPO recording.

### 5.2 Component-level command index

| Component | Document |
|---|---|
| PG (failover / switchover / PITR / etcd quorum) | [`patroni/README.md`](patroni/README.md) §4 |
| Redis (Sentinel failover / failback / reconciliation) | [`redis/README.md`](redis/README.md) §4 |
| NATS (single-node failure / 2-node failure degradation / rolling upgrade) | [`nats/README.md`](nats/README.md) §4 |
| MinIO (drive/node failure, heal, replication) | [`minio/README.md`](minio/README.md) §4 |

## 6. Validation

Offline validation (no Docker, no cluster, no containers started):

```powershell
python scripts/ha-manifest-check.py            # YAML/TOML parsing + replica counts/ports/probes/secret placeholders + EC/RPO parameters
python scripts/ha-manifest-check.py --docker   # additionally runs `docker compose config` (requires the local docker CLI)
python scripts/ha-prod-validate.py             # production hardening: Helm multi-profile lint/template + TLS/Patroni/PITR asset checks
python scripts/helm-canary-validate.py         # canary templates + PITR schedule retention assertions; regresses the previous 47 items / 182 items
```

- The `ha-manifest-check.py` baseline = **all 182 items PASS** (unchanged after this hardening; new assets are covered by `ha-prod-validate.py`);
- `ha-prod-validate.py` covers: `helm lint` + `helm template` for multiple chart values profiles + Python
  structural checks (resource fields/references/TOML/security context/NetworkPolicy/PDB/CronJob/TLS path
  alignment), this directory's TLS (cert-manager manifests/Secret key contract/no plaintext private keys),
  Patroni (etcd templates/runbook/sync-async overlay/REST API TLS), and backup (SQL shares the same source as
  the chart, script retention/encryption sections), and verifies that the two copies of `archive-verify.sql`
  are verbatim identical; without kubeconform locally it falls back to Python structural checks
  (`--kubeconform <path>` can specify the binary explicitly);
- Validation details are in each script's header comments; it prints per-item `PASS/FAIL` + `RESULT: checks=N pass=N fail=N`;
- The compose files in this directory **publish no host ports** (they only express topology), so there is zero
  port conflict with the dev stack (5432/6379/4222/9000/8080/8088/1883/9090/9100/8222);
- This directory does not modify `deploy/compose/dev.yaml` and does not touch the `lattice-dev-*` containers.

## 7. Limitations explicitly not validated on this machine (must not be skipped)

1. **No multi-node cluster**: this machine only has single-host Docker; Patroni/etcd/Sentinel/NATS Raft/MinIO
   distributed EC **cluster behavior is entirely unmeasured** (the configuration has only been statically validated).
2. **Failover has never happened**: the PG 30–60s figure is estimated from `ttl=30/loop_wait=10/retry_timeout=10`
   (leader key expiry dominates), Redis 5–15s from `down-after=5s`, and NATS Raft election is untested; split-brain
   protection (`watchdog`) is disabled by default. The automatic/manual switchover, pg_rewind, and split-brain
   handling in `patroni/failover-runbook.md` are equally **not drilled**.
3. **TLS/mTLS is a template, not an integration result**: `tls/` now has certificate manifests, the Secret key
   contract, and rotation procedures, but this machine has no cert-manager/real certificates, and **no real
   TLS/mTLS handshake has ever been performed**; `pg_hba` still defaults to plaintext `host` rules (change to
   `hostssl` in production); the QUIC/WebTransport UDP LB and source IP preservation are unvalidated.
4. **WAL archiving to object storage is unvalidated**: `wal-gateway.sh` has only done an equivalent-mechanism
   drill with local-directory archiving (PITR 34/34, `perf/README.md` §8); the MinIO archive path, archive
   failure alerting, and `pg_wal` backlog thresholds are unvalidated. The retention/encryption (SSE-KMS, object
   lock, age), cross-site replication, and real execution of the Helm CronJobs in `backup/` are equally **unvalidated**.
5. **Redis Sentinel has not been integration-tested with nodes**: nodes do not support the Sentinel protocol
   (a code fact), and the stable-endpoint (HAProxy/VIP/DNS) approach has not been validated with nodes; node
   behavior during the switchover window (connection error → reconnect) is unmeasured.
6. **The NATS replica-count gap is avoided by deployment**: the code creates streams with the default
   `replicas=1`; this skeleton requires running `streams.sh` first. That script has never run on a real 3-node
   cluster (no cluster available); online scale-out with `nats stream update --replicas 3` is unvalidated.
7. **MinIO distributed shape/cross-site replication unvalidated**: EC 12+4 fault tolerance and self-healing,
   heal duration, cross-site replication, and the interaction between object lock and the node delete path have
   never been exercised; the only drill was single-host single-drive data-directory recovery.
8. **Backup scheduling and off-site copies are not in place**: the Helm daily `pg_dump` CronJob is only a full
   baseline, not PITR; the `backup.pitr` physical base/archive-verify CronJobs are new templates (never run on a
   cluster); archiving to `lattice-cold`, off-site copies, and backup monitoring all still need ops to fill in
   (the "quarterly drill" requirement in design §11).
9. **The manual phase is not drilled**: the human decision time for failure triage/drain/phased ramp-up/failback
   is not included in any measured RTO.
10. **Capacity/large databases unvalidated**: base backup windows, archive backlog, EC write amplification, and
    Stream storage limits have not been load-tested at production data volumes.
11. **No production LB/VIP/Keepalived configuration is provided**: this directory only has illustrative HAProxy
    fragments (§4), with no high availability or integration testing.
12. **Canary release unvalidated on a real cluster**: the chart's canary only has offline render assertions
    (weights/headers/rollback/resource contract, `scripts/helm-canary-validate.py`); real ingress-nginx
    proportional splitting and header matching, the precedence of `/v1` versus the existing `/` prefix, and
    hot-updating of Ingress annotations by `helm upgrade --reuse-values` are all **unmeasured**; in the production
    topology, traffic weights for Nginx/Envoy directly hitting nodes must be configured on the external LB
    (`canary-runbook.md` §1/§10).
13. **This directory is not wired into `scripts/check-all.ps1` yet**: lead integrates it centrally; run the §6
    commands manually before that.

## 8. Rollback (removing this skeleton / rolling back a deployed cluster)

| Layer | Rollback action |
|---|---|
| **Repository files** (not deployed) | Simply delete `deploy/production/`, `deploy/compose/ha-dev.yaml`, `scripts/ha-manifest-check.py`, and `scripts/ha-prod-validate.py`; there is no runtime state and no container/port residue |
| **New production assets** (TLS/Patroni/PITR) | Not deployed: delete `deploy/production/tls/`, `deploy/production/backup/`, and the added `etcd-*`/`failover-runbook.md`/`*.overlay.yml` under `deploy/production/patroni/`; on the Helm side, turn `tls.enabled`/`backup.pitr.enabled`/`networkPolicy.*`/`security.*` back to their defaults and `helm upgrade` (workloads only, no data change) |
| **Production already deployed per the skeleton** | For per-component rollback see each README's "Rollback" table; overall rollback order = reverse of the deployment order: LB drain → node tag rollback → web → NATS/Redis/MinIO configuration rollback → PG rollback (PG last, and major-version upgrades cannot be reverted in place) |
| **Drill residue** | None of this skeleton's compose files publishes host ports; if it was ever started on a single host (`ha-dev.yaml`), clean up with `docker compose -f deploy/compose/ha-dev.yaml down -v` and verify the `lattice-dev-*` container IDs are unchanged |
| **Switchover failback** | See §5.1; every failback counts as a new switchover and requires reconciliation + recording |
| **Canary rollback** | First `--set canary.weight=0` (0% traffic, canary replicas kept for troubleshooting), then `--set canary.enabled=false` (removes the canary resources), or `helm rollback <release> <revision>` to roll back the whole release; database migrations only move forward, so confirm compatibility before rolling back the image (chart README §8, `canary-runbook.md` §7) |

## 9. File list

| Path | Content |
|---|---|
| `README.md` | This file: topology/deployment order/RPO-RTO/configuration mapping/runbook/boundaries/rollback |
| `config/production.toml.example` | Production `config.toml` template (including `[pg]/[redis]/[bus]/[s3]` + `[mqtt]/[grpc]/[quic]` TLS sections and the Secret injection list) |
| `patroni/patroni.yml` | Authoritative Patroni parameters (one copy per node, rendered from placeholders; synchronous replication/pg_rewind/WAL archiving/PITR prerequisites) |
| `patroni/docker-compose.yml` | Single-host topology reference for 3 Patroni + 3 etcd |
| `patroni/wal-gateway.sh` | Reference implementation of `archive_command`/`restore_command` (MinIO archiving → PITR) |
| `patroni/init-lattice-db.sh` | Idempotent database creation at first bootstrap |
| `patroni/README.md` | Patroni deployment/probes/switchover/failback/archiving/boundaries |
| `patroni/etcd-dcs.md` | etcd/DCS production notes: 3 nodes, quorum, DCS key layout, failure handling, snapshot backup/restore |
| `patroni/etcd.conf.template` / `etcd.service.template` | etcd configuration + systemd unit templates (TLS/mTLS, quota/compaction, non-root hardening) |
| `patroni/failover-runbook.md` | Failover runbook: decision matrix, automatic/manual failover, pg_rewind, split-brain handling, post-switchover verification |
| `patroni/patroni-restapi-tls.overlay.yml` | REST API TLS + etcd mTLS configuration fragment (optional) |
| `patroni/patroni-dcs-async.overlay.yml` | Synchronous→asynchronous replication downgrade fragment (cost of RPO>0 and failback) |
| `tls/README.md` | Production TLS/mTLS certificate system: termination-point matrix, trust root, cert-manager/sealed-secrets, Secret contract, rotation/revocation, verification |
| `tls/cert-manager.yaml` | ClusterIssuers (internal CA/ACME) + 5 Certificate examples (placeholder domains) |
| `tls/sealed-secret.example.yaml` | SealedSecret manifest shape (empty shell; requires kubeseal output to apply) |
| `backup/README.md` | Backup/PITR productionization: three backup layers, scheduling/retention (object storage + K8s Job layers), encryption/object lock/off-site copy, alerting, restore procedure |
| `canary-runbook.md` | Canary release/rollback runbook: prerequisites, traffic path, phased ramp-up and decision metrics, rollback decision matrix, unvalidated boundaries (chart-side implementation in `../helm/lattice/README.md` §10) |
| `backup/archive-verify.sql` | Archive health SQL (verbatim identical to the chart's `files/archive-verify.sql`) |
| `backup/base-backup.sh` / `pitr-verify.sh` | Bare-metal equivalent scripts (pg_basebackup upload + archive verification; offline-checkable with `sh -n`) |
| `redis/redis-master.conf` / `redis-replica.conf` | Primary/replica templates (AOF, noeviction, TLS/ACL placeholders) |
| `redis/sentinel.conf` | Sentinel template ×3 (master `lattice`, quorum 2, auth/TLS placeholders) |
| `redis/docker-compose.yml` | Single-host topology reference for 1 primary, 2 replicas, Sentinel×3 |
| `redis/README.md` | Redis deployment, node-side limitations, failover, failback, boundaries |
| `nats/nats-0.conf`/`nats-1.conf`/`nats-2.conf` | 3-node JetStream cluster configuration (three-way routes) |
| `nats/streams.sh` | **Pre-creates the 4 Streams with replicas=3** (retention identical to the code) + verification |
| `nats/docker-compose.yml` | Single-host 3-node topology reference |
| `nats/README.md` | Stream retention policy, why pre-creation is required, failure behavior, boundaries |
| `minio/docker-compose.yml` | 4 nodes ×4 drives EC 12+4 startup template (`MINIO_ERASURE_SET_DRIVE_COUNT=16`) |
| `minio/bucket-setup.sh` | 4 buckets + versioning + object lock (cold) + IAM user + replication notes |
| `minio/README.md` | EC capacity/fault tolerance, mapping to `[s3]`, failure/heal, replication, boundaries |
| `../compose/ha-dev.yaml` | **Optional** single-host multi-container drill stack (non-conflicting ports; takes no traffic) |
| `../../scripts/ha-manifest-check.py` | Offline validation script (PASS/FAIL; baseline 182 items) |
| `../../scripts/ha-prod-validate.py` | Production hardening validation (Helm multi-profile + TLS/Patroni/PITR assets; new) |

## 10. Isolation from the dev environment

- None of the compose files in this directory **publish host ports** (production entry points live on the
  LB/VIP); there is **zero conflict** with the dev stack's 5432/6379/4222/9000/9001/8080/8088/1883/9090/9100/8222.
- `deploy/compose/ha-dev.yaml` uses non-conflicting ports 15432–15434 / 16379–16381 / 26379–26381 /
  14222–14224 / 18222–18224 / 19000–19003, is profile-gated, and does not start by default.
- This skeleton (including the added `tls/`, `backup/`, `patroni/etcd-*`/runbooks, and Helm TLS/PITR templates)
  is **read-only file work**: `ha-manifest-check.py --docker` only runs `docker compose config` (starting no
  containers), and `ha-prod-validate.py` only runs local Helm binary (`.tooling/helm/`) rendering + Python
  structural checks, never exec/stop/restart any `lattice-dev-*` container.
