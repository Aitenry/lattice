# Lattice production HA deployment templates (PostgreSQL / Redis / NATS / MinIO)

> **Status: copyable templates, not a running cluster.** This repository contains a single-host development stack, not a production multi-node environment. The assets in this directory describe the intended topology and have been reviewed statically; no multi-host cluster has been brought up with them, and no leader election, switchover, or cross-site replication has been performed.
>
> Targets used throughout: **RPO ≤ 5 min and RTO ≤ 30 min**. These are deployment targets, not accepted results. Declare them achieved only after a drill on the target infrastructure using the checklist below.

## Topology

```
                     Clients: desktop / web console / MQTT devices
                                  │
                    ┌─────────────▼──────────────┐
                    │ Keepalived VIP ×2 (active-active) │  VIP drifts in seconds
                    └─────────────┬──────────────┘
                    ┌─────────────▼──────────────┐
                    │ Nginx/Envoy ×2             │  TLS, WS upgrade, SSE, canary weights
                    └──┬──────────┬──────────┬───┘
        ┌──────────────┘          │          └──────────────┐
┌───────▼────────┐      ┌─────────▼────────┐      ┌─────────▼────────┐
│ lattice-node 1 │      │ lattice-node 2   │      │ lattice-node 3   │  ≥3 stateless
│ 8080 9090 9100 │      │                  │      │                  │
│ 1883           │      │                  │      │                  │
└──┬───┬───┬───┬─┘      └──────────────────┘      └──────────────────┘
   │   │   │   └──► S3 stable endpoint (LB, TLS) ──► MinIO ×4, 4×4=16 drives, EC 12+4
   │   │   │                                        └─ lattice-large/media/cold/plugins
   │   │   └──────► NATS stable endpoint (L4 VIP/DNS) ──► JetStream ×3 (Raft)
   │   │                                          └─ LATTICE_ROUTE/BROADCAST/AUDIT/MEDIA
   │   └──────────► Redis stable endpoint (HAProxy/VIP) ──► 1 primary + 2 replicas + Sentinel ×3 (quorum 2)
   └──────────────► PG stable endpoint (HAProxy/VIP) ─────► Patroni + PG 16: 1 primary + 2 replicas + etcd ×3
                                                └─ WAL archive ──► MinIO lattice-cold (PITR)
    Observability: Prometheus scrapes node :9100, NATS exporter, MinIO, node_exporter, postgres_exporter; rules and dashboard in deploy/observability
```

Every stable endpoint is mandatory. The node takes a **single** endpoint for PG, Redis, NATS, and S3; without a VIP, load balancer, or DNS name that follows the current primary, an instance switchover leaves the node pointed at the old address.

## Deployment order

Follow this order; each step lists its acceptance check. **Recover PostgreSQL first and ramp traffic last.**

| Step | Action | Acceptance |
|---|---|---|
| 0 | Prerequisites: DNS, VIP + Keepalived, load balancer, certificates, secret manager, **NTP clock sync**, monitoring | `chronyc tracking` skew < 100 ms; secrets can be injected as environment variables |
| 1 | etcd ×3 from [`patroni/etcd.conf.template`](patroni/etcd.conf.template) and [`patroni/etcd.service.template`](patroni/etcd.service.template) | `etcdctl endpoint health` green on all 3; `etcdctl member list` shows 3 members |
| 2 | PostgreSQL Patroni ×3: render [`patroni/patroni.yml`](patroni/patroni.yml), start the hosts, create the database | `patronictl list` shows 1 Leader + 2 Replicas with lag ≈ 0; `pg_stat_archiver.failed_count = 0` |
| 3 | MinIO ×4: 4 nodes × 4 drives ([`minio/docker-compose.yml`](minio/docker-compose.yml)), then [`minio/bucket-setup.sh`](minio/bucket-setup.sh) | `mc admin info` shows 4 nodes × 4 drives; the four buckets exist with versioning, plus object lock on `lattice-cold` |
| 4 | Redis HA: one primary, two replicas, three Sentinels ([`redis/README.md`](redis/README.md)) | `redis-cli -p 26379 sentinel master lattice` shows quorum 2, two replicas, link up |
| 5 | NATS ×3 ([`nats/README.md`](nats/README.md)), then **run [`nats/streams.sh`](nats/streams.sh) to create the four streams with `replicas=3`** | `nats stream report` shows Replicas=3 for all four; `/healthz` returns ok on all three nodes |
| 6 | lattice-node ×N: [Helm chart](../helm/lattice/README.md) or bare metal, secrets injected; **start one instance to run migrations, then scale to ≥3** | `/v1/health` and `/v1/ready` return 200; logs show migrations complete and the four streams reused |
| 7 | `lattice-transfer` ×N (same image, entrypoint `/usr/local/bin/lattice-transfer`; chart `transfer.enabled=true`), behind the same LB/Ingress on `/t/` | `/healthz` 200, `/readyz` 200 on every replica; a plugin download from the public entry returns 206 for a `Range` request and the package sha256 matches |
| 8 | Web ×2 and Nginx/LB, following the shape of [`nginx.conf`](../nginx.conf); drain and canary on the LB | `curl -fsS https://<vip>/` returns 200; WebSocket upgrade works; `/v1` reverse proxy works; `/t/` reaches the transfer Service |
| 9 | Acceptance: static checks below, `promtool check rules deploy/observability/prometheus/lattice-alerts.yml`, a production smoke test, and one controlled failover drill | All checks pass and a drill record with RTO/RPO numbers is filed |

> The only manual database step is creating the `lattice` database after Patroni first elects a primary. [`patroni/init-lattice-db.sh`](patroni/init-lattice-db.sh) is wired into `bootstrap.post_bootstrap`; the node creates tables through migrations and never creates databases. Run migrations from a single instance before scaling out.

- **Before step 6**, have the certificate system ready ([`tls/README.md`](tls/README.md)); otherwise enabling node `tls.*` fails because the Secret is missing.
- **After step 6**, enable the chart's `backup.enabled` and `backup.pitr.enabled`, and confirm PG's `archive_command` already targets object storage ([`backup/README.md`](backup/README.md)).

## RPO / RTO expectations

**Target: RPO ≤ 5 min, RTO ≤ 30 min.** The table records the mechanism behind each target; no time in it has been measured on a production cluster.

| Component | RPO target | RTO target | Mechanism | Status |
|---|---|---|---|---|
| PostgreSQL automatic failover | 0 (committed transactions are not lost) | ~30–60 s, estimated from `ttl=30s` plus election/promotion | `synchronous_mode=true` (commit needs ≥ 1 synchronous replica ack) + Patroni election + stable endpoint | Template only; failover time not measured |
| PostgreSQL disaster recovery / PITR | ≤ 5 min (mechanical bound: `archive_timeout=60s` + upload + one WAL segment) | ≤ 30 min including manual confirmation, restore, verification, and ramp-up | `archive_mode=on` + `archive_command` to MinIO + daily `pg_basebackup` base | Object-storage archive path unvalidated |
| Redis Sentinel switchover | Business-durable data 0 (PostgreSQL is authoritative; `delivery_log`/`conv_seq_watermark` losses are backfilled by reconcile); asynchronous replication window ≈ ≤ 1 s | 5–15 s (`down-after=5s` plus election/promotion) | 1 primary + 2 replicas + 3 Sentinels (quorum 2); clients follow the stable endpoint | Template only; node reconnect behavior unmeasured |
| NATS JetStream | Acked messages 0 with `replicas=3`; streams left at the code default of 1 lose data on a node failure | Single node failure: no downtime; two nodes down: degrade to Redis Pub/Sub, then paused broadcast | 3-node Raft with pre-created streams | Template only |
| MinIO EC 12+4 | Written objects 0 (tolerates any 4 drive failures, about one node); site replication is asynchronous | Single drive/node failure does not stop service; whole-site loss relies on off-site copies | 16 drives in one erasure set | Distributed shape unvalidated |
| Access layer (node ×≥3) | 0 (PostgreSQL first; while PG is unwritable the local WAL absorbs inline messages ≤ 1 MiB) | Seconds (load balancer removes an unhealthy node; clients reconnect) | PDB N−1, HPA min 3, `preStop` drain | Chart-level only |

## Stable endpoints and node configuration

The production configuration template is [`config/production.toml.example`](config/production.toml.example), deployed as `/etc/lattice/config.toml`. The "Node-side limitation" column is the core constraint: the code has no Sentinel, multi-host, or server-list client, so HA must come from infrastructure.

| Config | Production value (example) | Stable endpoint | Node-side limitation |
|---|---|---|---|
| `[pg] url` | `postgres://lattice_app@pg-lattice.lattice.internal:5432/lattice?sslmode=verify-full` | HAProxy/VIP checking Patroni `GET :8008/primary` (200 = primary) | sqlx takes a single URL; password comes from the `LATTICE__PG__URL` secret |
| `[pg] pool_size` | 32 per instance | — | 3 nodes × 32 = 96 connections; Patroni `max_connections=500` leaves headroom; adding PgBouncer requires recalculating |
| `[redis] url` | `redis://:${REDIS_PASSWORD}@redis-lattice.lattice.internal:6379/0` | HAProxy/VIP with `tcp-check` asserting `role:master` from `INFO replication` | `redis::Client::open` takes a single URL and has no Sentinel protocol support; reconnect relies on endpoint drift |
| `[bus] kind` / `nats_url` | `nats` / `nats://lattice-nats.lattice.internal:4222` | L4 VIP or DNS across the three 4222 ports | `async_nats::connect` parses a single server address; comma-separated lists are rejected |
| `[bus] jetstream` | `true` | NATS 3-node Raft | The node's `get_or_create_stream` uses `replicas=1` and does not compare configuration; run `streams.sh` first for redundancy |
| `[s3] endpoint` | `http://minio-lattice.lattice.internal:9000` | L4 load balancer to the four nodes on 9000 | The bucket and direct-write paths support `http://` only; TLS terminates at the load balancer |
| `[s3] public_endpoint` | `https://s3.example.com` | The same load balancer's external TLS domain, preserving the Host header | Scheme and Host of presigned URLs; must be reachable by clients |
| `[s3] access_key` / `secret_key` / `bucket_*` | Dedicated IAM user from `bucket-setup.sh`; buckets `lattice-large`, `lattice-media`, `lattice-cold`, `lattice-plugins` | MinIO EC 12+4 | Never use the root account. `ensure_buckets()` only creates plain buckets, so run `bucket-setup.sh` first for versioning and object lock |
| `[wal] dir` / `max_bytes` | `/var/lib/lattice/wal` / 64 MiB | Local disk on the node | Backstop for small inline messages while PostgreSQL is unwritable; over the limit messages are rejected and counted in `lattice_wal_dropped_total` |
| `[auth] key_dir` | `/etc/lattice/keys` | Secret volume with `jwt.key.pem` and `jwt.key.prev.pem` | Rotate through `POST /v1/admin/keys/rotate`; a read-only mount returns an explicit error |
| `[grpc] enabled` / `tls_*` | Internal mTLS | In-cluster Service or internal load balancer | Cross-node fallback routing; the plaintext development shape must not be used in production |

HAProxy fragments for the two entry points that need a "stable address":

```haproxy
# PostgreSQL: only the node where Patroni /primary returns 200 is primary
backend pg_primary
  mode tcp
  option httpchk GET /primary
  http-check expect status 200
  server pg0 10.20.0.11:5432 check port 8008
  server pg1 10.20.0.12:5432 check port 8008
  server pg2 10.20.0.13:5432 check port 8008

# Redis: read INFO replication; only the node with role:master is healthy
# (expand ${REDIS_PASSWORD} with HAProxy 2.x environment variables, or use a separate 0600 config file)
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

## Switchover / failback runbook

Every component follows the same rhythm; do not improvise a different order during an incident.

1. **Detect** the alert (component `up=0`, replication lag, `pg_stat_archiver.failed_count > 0`, Sentinel `+odown`, NATS `server down`, MinIO `drive offline`) and record `T0` as the RTO start.
2. **Confirm** that a switchover is really needed: `patronictl list` and `pg_isready` for PostgreSQL, Sentinel `master lattice` flags for Redis, `nats server list` for NATS, `mc admin info` for MinIO.
3. **Drain and freeze writes**: remove the load-balancer weight, wait for connections to drain (node `preStop` 10 s plus the WS `bye` frame), then freeze writes to the target component. Read-only troubleshooting does not need downtime.
4. **Switch over or restore** with the commands in [`patroni/README.md`](patroni/README.md), [`redis/README.md`](redis/README.md), [`nats/README.md`](nats/README.md), or [`minio/README.md`](minio/README.md).
5. **Verify** component self-checks and a production smoke test (login, health, message round-trip, object download).
6. **Reconcile**: `lock:reconcile` rebuilds pending state from `delivery_log` at node startup or on its periodic task; confirm idempotence.
7. **Ramp up and record**: load-balancer weight 5% → 25% → 100%, observing error rate, latency, and backlog for at least 10 minutes at each step; then record RTO (`T0` → ramp-up complete), RPO (last successful archive/replication), cause, and improvements in the drill report.

### Failback principles

- Do not fail back merely to restore the previous layout; let Patroni, Sentinel, or Raft decide the steady state.
- PostgreSQL: wait until the old primary rejoins as a replica with lag ≈ 0, then run one `patronictl switchover` ([`patroni/README.md`](patroni/README.md)).
- Redis: trigger `sentinel failover lattice` again; never run `slaveof` manually ([`redis/README.md`](redis/README.md)).
- NATS and MinIO: a recovered node rejoins and catches up automatically; roll back only configuration or image tags.
- A failback is itself a switchover and requires draining, reconciliation, and RTO/RPO recording.

## Static validation

```bash
# these checks need no cluster and start no containers
docker compose -f deploy/compose/ha-dev.yaml config --quiet
for f in deploy/production/*/docker-compose.yml; do docker compose -f "$f" config --quiet; done
helm lint deploy/helm/lattice
helm template lattice deploy/helm/lattice --namespace lattice > /dev/null
for f in deploy/production/*/*.sh; do sh -n "$f"; done
```

The assets were reviewed statically: compose topology, replica counts, ports, health checks, probe definitions, secret placeholders, Patroni parameters, and the erasure-coding shape. These checks do not prove HA behavior and do not replace a drill.

## Limitations

1. **No multi-node cluster**: Patroni/etcd, Sentinel, NATS Raft, and MinIO distributed EC behavior are unmeasured; the configuration has only been reviewed statically. A single-host drill stack is available in [`../compose/ha-dev.yaml`](../compose/ha-dev.yaml), but it is a demonstration, not a production cluster.
2. **Failover is not exercised**: the PostgreSQL 30–60 s figure is derived from `ttl=30`/`loop_wait=10`/`retry_timeout=10`; Redis 5–15 s from `down-after=5s`; NATS Raft election is untested. `watchdog`, `pg_rewind`, and split-brain handling are equally not drilled.
3. **TLS/mTLS is a template**: no certificate authority, cert-manager, or real handshake has been exercised. `pg_hba` still defaults to plaintext `host` rules; switch to `hostssl` in production. QUIC/WebTransport UDP load balancing and source-IP preservation are unvalidated.
4. **WAL archiving to object storage is unvalidated**: [`patroni/wal-gateway.sh`](patroni/wal-gateway.sh) only performs single-object put/get with size verification using `mc`; the MinIO archive path, archive-failure alerting, and `pg_wal` backlog thresholds are untested. The templates also provide no encryption, compression, or retention policy; use WAL-G or pgBackRest in production.
5. **Redis Sentinel is not integration-tested with nodes**: the node does not implement the Sentinel protocol, and the stable-endpoint approach has not been validated with a running node; behavior during the switchover window is unmeasured.
6. **The NATS replica gap is avoided by deployment**: the code creates streams with `replicas=1`, so `streams.sh` must run first. That script has not run on a real three-node cluster, and online scale-out with `nats stream update --replicas 3` is unvalidated.
7. **MinIO distributed shape and cross-site replication are unvalidated**: EC 12+4 fault tolerance, self-healing duration, cross-site replication, and the interaction between object lock and the node's delete path have not been exercised.
8. **Backup scheduling and off-site copies are not in place**: the Helm daily `pg_dump` CronJob is a full baseline, not PITR; the PITR CronJobs are templates and have never run on a cluster; archive retention, off-site copies, and backup-failure monitoring still need operations work.
9. **The manual phase and capacity are not measured**: human triage, drain, phased ramp-up, and failback time are not included in any RTO; base-backup windows, archive backlog, EC write amplification, and stream storage limits have not been load-tested at production volume.
10. **No production load balancer or VIP configuration is provided**: this directory has illustrative HAProxy fragments only, and the canary release has never run on a real cluster, so ingress-nginx weight/header splitting, `/v1` prefix precedence, and annotation hot-updates are unmeasured ([`canary-runbook.md`](canary-runbook.md)).

## Rollback

| Layer | Rollback action |
|---|---|
| Repository files (not deployed) | Delete `deploy/production/` and `deploy/compose/ha-dev.yaml`; there is no runtime state, container, or port residue |
| New TLS/Patroni/PITR templates (not deployed) | Delete `deploy/production/tls/`, `deploy/production/backup/`, and the added `etcd-*`/`failover-runbook.md`/`*.overlay.yml` files under `deploy/production/patroni/`; on the Helm side reset `tls.enabled`, `backup.pitr.enabled`, `networkPolicy.*`, and `security.*` to their defaults and run `helm upgrade` |
| Production deployed from this skeleton | Per-component rollback is in each component README; overall order is the reverse of deployment: LB drain → node image rollback → web → NATS/Redis/MinIO configuration rollback → PostgreSQL last (major-version upgrades cannot be reverted in place) |
| Drill residue | These compose files publish no host ports; if the single-host drill stack was started, clean up with `docker compose -f deploy/compose/ha-dev.yaml down -v` and confirm the `lattice-dev-*` containers are untouched |
| Switchover failback | Follow the failback principles above; every failback counts as a new switchover and requires reconciliation and recording |
| Canary rollback | Set `canary.weight=0` first (0% traffic, canary replicas kept for troubleshooting), then `canary.enabled=false`, or use `helm rollback <release> <revision>`; migrations only move forward, so confirm compatibility before rolling back the image ([`canary-runbook.md`](canary-runbook.md), [`../helm/lattice/README.md`](../helm/lattice/README.md)) |
