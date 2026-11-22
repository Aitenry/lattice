# PG production HA (Patroni + etcd ×3)

> This is a **template**, not a running cluster. There is no multi-node environment on this machine; all
> contents have only been validated offline (`python scripts/ha-manifest-check.py`), and **no real
> leader election/switchover/archive drill has ever been performed**.
> Design basis: the design document (outside this repository) §11/§17.13 (PG 16 + Patroni + etcd×3, 1 primary + 2 replicas, switchover <30s).

## Files

| File | Purpose |
|---|---|
| `patroni.yml` | **Authoritative parameters**. Render one copy per node (`${PATRONI_NAME}`/`${NODE_IP}` and other placeholders) |
| `docker-compose.yml` | **Topology reference** for 6 containers on one host (3 Patroni + 3 etcd); production is 3 hosts, not this compose |
| `wal-gateway.sh` | Reference implementation of `archive_command` / `restore_command` (MinIO archiving → PITR) |
| `init-lattice-db.sh` | Idempotent one-time creation of the `lattice` database at first bootstrap (owner `lattice_app`); nodes only run migrations, they never create databases |
| `README.md` | This file: deployment, probes, switchover/failback, WAL archiving, boundaries |
| `etcd-dcs.md` | **etcd/DCS production notes**: 3 nodes, quorum, DCS key layout, handling quorum loss, snapshot backup/restore |
| `etcd.conf.template` | etcd configuration template (TLS/mTLS, quota, compaction; render one per host) |
| `etcd.service.template` | etcd systemd unit template (non-root, filesystem protection, fd limit) |
| `failover-runbook.md` | **Failover runbook**: decision matrix, automatic/manual failover, pg_rewind, split-brain handling, post-switchover verification |
| `patroni-restapi-tls.overlay.yml` | REST API TLS + etcd mTLS configuration fragment (optional, merge into `patroni.yml`) |
| `patroni-dcs-async.overlay.yml` | Synchronous→asynchronous replication downgrade fragment + failback notes (explicit cost: RPO>0) |

## 1. Deployment (3 hosts)

1. **etcd ×3 first** (dedicated disks, dedicated processes; never on the same disk as PG data). On each host:
   `--name=etcdN --initial-cluster=etcd0=http://10.20.0.11:2380,etcd1=...:2380,etcd2=...:2380`,
   with the client port listening on the internal network only (2379); enable mTLS in production (the
   `etcd3` comment block in `patroni.yml`).
2. **Render the Patroni configuration** (one copy per host, passwords from Secret environment variables):
   ```sh
   export PATRONI_NAME=pg0 NODE_IP=10.20.0.11 RESTAPI_IP=10.20.0.11
   export ETCD0=10.20.0.11 ETCD1=10.20.0.12 ETCD2=10.20.0.13
   # + PATRONI_RESTAPI_PASSWORD / PG_SUPERUSER_PASSWORD / PG_REPLICATION_PASSWORD
   #   / PG_REWIND_PASSWORD / PG_APP_PASSWORD  (systemd EnvironmentFile, 0600, from a Secret)
   envsubst < patroni.yml > /etc/patroni/patroni.yml
   chmod 0600 /etc/patroni/patroni.yml
   ```
3. Install PG 16 + Patroni first (PyPI `patroni[etcd3]`); the data directory follows `postgresql.data_dir`.
4. **Start Patroni on all three hosts at the same time** (a new cluster's first start must have all three
   online, otherwise only one node initdb's as primary and the other two can only join later as replicas;
   two nodes are also enough to form a cluster, but never start a single node and put it in service).
5. Once the first primary is elected, create the database **exactly once** (`bootstrap.post_bootstrap`
   already hooks the script, see `init-lattice-db.sh`):
   ```sh
   sudo -u postgres psql -h /var/run/postgresql -c "\l" | grep lattice
   # If absent, run init-lattice-db.sh; the node then runs sqlx migrations at startup to create tables
   ```
6. Wait until `patronictl -c /etc/patroni/patroni.yml list` shows `Leader + 2 Replica` on all three hosts
   with `lag in MB` near 0.
7. **Client entry point**: the node-side `[pg] url` must point at a stable address for the current primary
   (VIP / DNS / HAProxy, see `deploy/production/README.md` §5.1). Patroni does not route clients, so
   connecting directly to one node fails writes after a switchover.

## 2. Probe definitions (do not mistake "alive" for "primary")

| Purpose | Check | Notes |
|---|---|---|
| Process alive | `pg_isready -h 127.0.0.1 -p 5432` | Replicas are equally ready → **proves only that the process runs, not that it is writable** |
| Primary check | Patroni REST `GET :8008/primary` returns 200 | Only the primary returns 200; replicas return 503. HAProxy uses this for health checks |
| Replica check | `GET :8008/replica` returns 200 | Usable for read-only traffic/reporting |
| DCS health | `etcdctl endpoint health --endpoints=...:2379` | When etcd loses quorum, Patroni enters failsafe |
| Replication lag | `Lag in MB` from `patronictl list` / `pg_stat_replication` | Candidates for election must lag ≤ `maximum_lag_on_failover` |

Failover time budget: `ttl=30s` is the upper bound for primary heartbeat expiry, `loop_wait=10s`/`retry_timeout=10s`
determine detection polling → leader election typically completes in 30–60s (dominated by the leader key ttl;
the design target is <30s, **not measured**). Replica recovery (pg_rewind + catch-up) takes minutes
depending on data volume and network.

## 3. WAL archiving / PITR prerequisites

### 3.1 Parameters (all in `patroni.yml`, already enabled)

```yaml
archive_mode: "on"          # without it there is no PITR and RPO is unbounded
archive_timeout: 60         # worst-case archive lag bound (60s; far below the ≤5min RPO)
archive_command: /usr/local/bin/wal-gateway.sh archive %p %f
restore_command: /usr/local/bin/wal-gateway.sh restore %f %p
recovery_target_timeline: latest
wal_level: replica
```
- A **non-zero exit from `archive_command` makes PG retain the WAL and retry**; progress happens only on a 0 return.
- A growing `pg_wal` directory = archiving failure/unreachable object storage and must alert
  (`failed_count>0` in `pg_stat_archiver`, or `last_archived_time` stalled > 5min).
- `perf/reports/pitr-20261121.txt` in this repository validated the "local-directory archive + restore"
  mechanism with a temporary PG16 instance (34/34, archive lag 4.1s, RTO 3.92s); **the object-storage
  (MinIO) archive path is unvalidated**, see `perf/README.md` §8.5.

### 3.2 Quarterly PITR drill (summary, full steps in `scripts/restore-runbook.md` §13)

1. Choose a point in time `T` (for example 1 minute before an accidental delete); 2. Start a new data
   directory from the most recent `pg_basebackup` base;
3. Write `postgresql.auto.conf`/`recovery.signal` + `restore_command` + `recovery_target_time='T'`
   + `recovery_target_action='promote'` (missing `recovery.signal` yields a "false success" that only does
   crash recovery);
4. Start a temporary instance → verify `pg_is_in_recovery()=f`, timeline, and data before/after the target;
5. Switch the VIP/new primary (see §4.3), then restore traffic.

### 3.3 Deploying the archive script

`wal-gateway.sh` must be deployed to `/usr/local/bin/` on every PG host (`chmod 0755`), with:
- the MinIO client `mc` (or the `aws` cli); `mc alias set lattice-s3 http://minio.lattice.internal:9000 ...`;
- environment variables `WAL_S3_ALIAS` / `WAL_BUCKET=lattice-cold` / `WAL_PREFIX=wal/pg/lattice-pg`
  (systemd `EnvironmentFile`, 0600).
- **Production recommendation**: switch to WAL-G (bundled in the spilo image) or pgBackRest directly; this
  script is only the minimal example of "archiving must be on".

## 4. Failover / failback runbook

### 4.1 Automatic failover (primary down)

1. Alert: `patronictl list` shows the old primary as `down`/no Leader; metrics `pg_up=0`, sqlx write failures.
2. Patroni elects a new primary from the synchronous replicas within ~30–60s (`synchronous_mode=true` →
   committed transactions are not lost, RPO=0).
3. Client impact: if the node's `[pg] url` goes through the VIP/HAProxy it points at the new primary
   automatically; anything connecting directly to the old primary's IP must change configuration
   → **this is why production must use a stable endpoint**.
4. After the old primary recovers: Patroni runs `pg_rewind` automatically and it rejoins as a replica;
   confirm `Replica` with `patronictl list`.
5. If fewer than 2 etcd nodes are available at the same time: Patroni enters failsafe (no automatic
   switchover); handle it per §4.4.

### 4.2 Planned primary/replica switchover (rolling upgrade/hardware replacement)

```sh
patronictl -c /etc/patroni/patroni.yml switchover --master pg0 --candidate pg1 --force
# Watch: in patronictl list, Leader becomes pg1, pg0 becomes Replica and lag→0
```
Before switching confirm: replica lag≈0, the application's `[pg] url` goes through the stable endpoint,
and archiving shows `failed_count=0`.

### 4.3 Disaster recovery switchover (data-center level/primary unrecoverable)

1. **Freeze writes**: remove the VIP / stop application traffic (this is the manual confirmation phase of
   the RTO, not drilled in dev);
2. Restore from backup (logical full or PITR, see §3.2) → start the new primary → rebuild the remaining
   replicas with `pg_basebackup`;
3. After recovery **reconcile before restoring traffic** (② §7.5): `scripts/reconcile.py` / `lock:reconcile`
   fix pending state, and `delivery_log` is checked against `messages`/MinIO objects;
4. Ramp up: read-only/small traffic first, then full traffic once the error rate and replication lag look normal.

### 4.4 etcd quorum loss (≥2 nodes unavailable)

- Symptoms: Patroni logs `failed to update leader key` / `DCS is not accessible`; the primary enters
  failsafe and keeps serving (it does not self-terminate), but **automatic switchover stops**.
- Handling: restore etcd quorum (bring the failed etcd nodes back; 2/3 online is enough). If etcd data is
  entirely lost, **do not** wipe etcd and let the cluster re-elect — that loses cluster state; restore DCS
  data from backup following the `patronictl`/official etcd recovery procedure.
- Defenses: separate etcd data disks from PG, spread the 3 etcd nodes across hosts, and take periodic etcd snapshots.

### 4.5 Rollback (undo this switchover/upgrade)

| Scenario | Rollback action |
|---|---|
| Abnormal after a code/node upgrade | Roll back the node image tag (Helm `--set image.tag=<old>` / change the tag in compose); the DB does not need rollback |
| PG minor-version upgrade failed | If the old `pg_ctl` can read the new data directory, revert the binary directly; major-version upgrades must go through a new cluster + logical replication, and **cannot be reverted in place** |
| Problems found after PITR restore | Keep the new instance (do not delete it), pick an earlier target and run PITR again; **do not** write the old data directory back (it conflicts with the archived timeline) |
| Want to switch back after a planned switchover | Run the §4.2 switchover again toward the original primary (not recommended unless the new primary is faulty and has caught up) |
| Remove the new production directory | Just delete files under `deploy/production/` that production does not reference (this skeleton is not part of runtime and holds no state); a cluster already deployed per §1 must be rolled back per the rows above |

## 4.6 More detailed runbooks / templates (production hardening)

| Topic | Document/file |
|---|---|
| etcd ×3 quorum, DCS key layout, handling quorum loss, snapshot backup/restore | [`etcd-dcs.md`](etcd-dcs.md), [`etcd.conf.template`](etcd.conf.template), [`etcd.service.template`](etcd.service.template) |
| Step-by-step failover/failback, manual pg_rewind rollback, split-brain handling, post-switchover checklist | [`failover-runbook.md`](failover-runbook.md) |
| REST API TLS (HAProxy/patronictl also need https) + etcd mTLS | [`patroni-restapi-tls.overlay.yml`](patroni-restapi-tls.overlay.yml) |
| Synchronous → asynchronous replication downgrade (explicit cost: RPO>0) and failback | [`patroni-dcs-async.overlay.yml`](patroni-dcs-async.overlay.yml) |
| Certificate system (cert-manager / sealed-secrets, Secret key contract, rotation) | [`../tls/README.md`](../tls/README.md) |
| Backup layering/retention/encryption/PITR verification | [`../backup/README.md`](../backup/README.md) |

> These documents are **equally just templates**: there is no multi-host environment on this machine, so no
> real leader election/switchover/archiving/TLS handshake drill has been done, and production RPO/RTO
> compliance must not be declared on their basis (see §5).

## 5. Unvalidated boundaries (must not be used to declare compliance)

- **No real 3-node cluster has ever been brought up**: this machine only has single-host Docker, no second host; `docker-compose.yml` is a topology reference only;
- **Failover time not measured** (30–60s is an estimate from `ttl/loop_wait/retry_timeout`), etcd quorum loss untested,
  `pg_rewind` rollback untested, split-brain protection untested (`watchdog` is disabled by default);
- **MinIO archive path unvalidated**: `wal-gateway.sh` has never run against a real MinIO bucket (explicitly logged in perf §8.5);
- **Write latency under synchronous replication unvalidated** (`synchronous_mode=true` adds a local network RTT);
- **TLS/mTLS unvalidated** (all certificate blocks are commented-out placeholders); `pg_hba` defaults to plaintext
  `host` rules and production must change them to `hostssl`;
- **Capacity/large-database backup windows unvalidated** (base backup duration, archive backlog, `pg_wal` alert thresholds).
