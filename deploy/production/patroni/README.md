# PostgreSQL high availability (Patroni with a three-node etcd DCS)

> **Status: template, not a running cluster.** No multi-node environment has been used here and no leader
> election, switchover, or archive drill has been performed; every timing below is estimated from parameters.

## Files

| File | Purpose |
|---|---|
| [`patroni.yml`](patroni.yml), [`docker-compose.yml`](docker-compose.yml) | Authoritative parameters rendered per node from `${PATRONI_NAME}` / `${NODE_IP}` placeholders; six-container single-host topology reference (production uses three hosts) |
| [`wal-gateway.sh`](wal-gateway.sh), [`init-lattice-db.sh`](init-lattice-db.sh) | `archive_command` / `restore_command` reference; idempotent one-time creation of the `lattice` database (owner `lattice_app`) |
| [`etcd-dcs.md`](etcd-dcs.md), [`etcd.conf.template`](etcd.conf.template), [`etcd.service.template`](etcd.service.template) | etcd production notes (quorum, DCS keys, snapshot restore) plus configuration and systemd unit templates |
| [`failover-runbook.md`](failover-runbook.md) | Detailed failover: decision matrix, manual failover, pg_rewind, split-brain, post-switchover checklist |
| [`patroni-restapi-tls.overlay.yml`](patroni-restapi-tls.overlay.yml), [`patroni-dcs-async.overlay.yml`](patroni-dcs-async.overlay.yml) | REST API TLS plus etcd mTLS fragment; synchronous-to-asynchronous downgrade fragment (RPO>0) |

## Deployment on three hosts

1. Deploy **etcd on three dedicated nodes first**, on disks separate from PostgreSQL. Start each with
   `--name=etcdN --initial-cluster=etcd0=http://10.20.0.11:2380,etcd1=...:2380,etcd2=...:2380`, expose client
   port 2379 internally only, and enable mTLS in production.
2. Render once per host, with passwords from a Secret or a mode-0600 systemd `EnvironmentFile`:
   ```sh
   export PATRONI_NAME=pg0 NODE_IP=10.20.0.11 RESTAPI_IP=10.20.0.11
   export ETCD0=10.20.0.11 ETCD1=10.20.0.12 ETCD2=10.20.0.13
   export PATRONI_RESTAPI_PASSWORD=... PG_SUPERUSER_PASSWORD=... PG_REPLICATION_PASSWORD=... PG_REWIND_PASSWORD=... PG_APP_PASSWORD=...
   envsubst < patroni.yml > /etc/patroni/patroni.yml
   chmod 0600 /etc/patroni/patroni.yml
   ```
3. Install PostgreSQL 16 and `patroni[etcd3]`. The template sets `max_connections: 500`, `synchronous_mode: true`,
   `synchronous_mode_strict: false`, and `failsafe_mode: true`; node `[pg] pool_size=32` per instance, and replica
   creation uses `basebackup` with `max-rate: 200M`.
4. Start Patroni on all three hosts at the same time. A new cluster's first start needs all three online,
   otherwise only one node performs `initdb` and the others can only join later as replicas.
5. After the first primary is elected, create the database exactly once. `bootstrap.post_bootstrap` calls
   [`init-lattice-db.sh`](init-lattice-db.sh); verify with
   `sudo -u postgres psql -h /var/run/postgresql -c "\l" | grep lattice`. The node then applies sqlx migrations.
6. Wait until `patronictl -c /etc/patroni/patroni.yml list` shows `Leader` plus two `Replica` entries with lag
   near zero.
7. Point the node's `[pg] url` at a stable address for the current primary (VIP, DNS, or HAProxy). Patroni does
   not route clients, so a direct node address fails writes after a switchover; see
   [`config.rs`](../../../crates/lattice-node/src/config.rs).

## Probes and failover budget

| Purpose | Check | Notes |
|---|---|---|
| Process alive | `pg_isready -h 127.0.0.1 -p 5432` | Replicas also answer; proves only that the process runs |
| Primary | Patroni REST `GET :8008/primary` returns 200 | Replicas return 503; HAProxy uses this for health checks |
| Replica | `GET :8008/replica` returns 200 | Suitable for read-only traffic and reporting |
| DCS health | `etcdctl endpoint health --endpoints=...:2379` | Without quorum, Patroni enters failsafe |
| Replication lag | `patronictl list` or `pg_stat_replication` | Failover candidates must lag no more than `maximum_lag_on_failover` (1 MiB) |

`ttl=30s` bounds how long the primary may be unreachable, and `loop_wait=10s` plus `retry_timeout=10s` set the
detection cadence, so an election typically completes in 30-60 seconds. A sub-30-second switchover is a target,
not a measurement. Replica recovery through `pg_rewind` plus catch-up takes minutes and scales with data volume.

## WAL archiving and PITR prerequisites

These parameters are already set in [`patroni.yml`](patroni.yml):

```yaml
archive_mode: "on"          # without it there is no PITR and RPO is unbounded
archive_timeout: 60         # worst-case bound on archive lag
archive_command: /usr/local/bin/wal-gateway.sh archive %p %f
restore_command: /usr/local/bin/wal-gateway.sh restore %f %p
recovery_target_timeline: latest
```

- A non-zero exit from `archive_command` makes PostgreSQL retain the WAL segment and retry; progress requires a
  zero exit.
- A growing `pg_wal` directory means archiving is failing or object storage is unreachable. Alert on
  `failed_count > 0` in `pg_stat_archiver` and on `last_archived_time` stalling for more than five minutes.

Deploy `wal-gateway.sh` to `/usr/local/bin/` on every host with mode `0755`, install `mc` or the `aws` cli,
pre-configure the alias, and export `WAL_S3_ALIAS`, `WAL_BUCKET=lattice-cold`, and `WAL_PREFIX=wal/pg/lattice-pg`
from a mode-0600 file. The MinIO archive path is not validated; in production switch to WAL-G or pgBackRest.

## PITR drill

1. Choose target time `T` (for example one minute before an accidental delete) and start a new data directory from the newest base earlier than `T`.
2. Add `recovery.signal`, `restore_command`, `recovery_target_time='T'`, and `recovery_target_action='promote'`; without `recovery.signal`, PostgreSQL only performs crash recovery and reports a false success.
3. Start a spare instance (for example `-p 5433`) and verify `pg_is_in_recovery()=f`, the timeline, and data on both sides of `T`.
4. Move the stable endpoint to the restored primary, then restore traffic in phases.

## Failover and failback

### Automatic failover

1. Alert when `patronictl list` shows the old primary as `down` with no leader, `pg_up=0`, and writes failing.
2. Patroni elects a synchronous replica within roughly 30-60 seconds; with `synchronous_mode=true`, committed transactions are not lost (RPO zero).
3. Clients on the stable endpoint move automatically; clients on a fixed node address do not, which is why the stable endpoint is mandatory.
4. `pg_rewind` brings the old primary back as a replica; confirm the role in `patronictl list`. With fewer than two etcd nodes, Patroni enters failsafe and stops automatic switchover.

### Planned switchover

```sh
patronictl -c /etc/patroni/patroni.yml switchover --master pg0 --candidate pg1 --force
# Watch: Leader becomes pg1, pg0 becomes Replica, lag returns to zero
```

Before switching, confirm replica lag is near zero, the node uses the stable endpoint, and archiving reports
`failed_count=0`.

### Disaster recovery

1. Freeze writes by removing the VIP or stopping application traffic; this manual phase counts toward the RTO.
2. Restore from a logical full or a PITR restore, start the new primary, and rebuild the remaining replicas with
   `pg_basebackup`.
3. Reconcile before restoring traffic: the node's `lock:reconcile` task rebuilds pending state and `delivery_log`
   is checked against messages and MinIO objects, then ramp up read-only traffic before full traffic.

### etcd quorum loss

Symptoms are `failed to update leader key` or `DCS is not accessible`; the primary keeps serving in failsafe but
automatic switchover stops. Bring the failed etcd nodes back to restore quorum; two of three is enough. If etcd
data is entirely lost, do not wipe the DCS and let the cluster re-elect, because that discards cluster state;
restore it from a snapshot instead. Keep etcd disks separate from PostgreSQL and take periodic snapshots.

### Rollback

| Scenario | Action |
|---|---|
| Abnormal node upgrade | Roll back the node image tag; the database needs no rollback |
| Failed PostgreSQL minor upgrade | Revert the binary if the old `pg_ctl` can read the new data directory; major upgrades need a new cluster and cannot be reverted in place |
| Problems after a PITR restore | Keep the new instance, choose an earlier target, and run PITR again; never write the old data directory back |
| Switch back after a planned switchover | Run another `patronictl switchover` toward the original primary, but only after it has caught up |

Also see [`etcd-dcs.md`](etcd-dcs.md) and the etcd templates for quorum, DCS keys, and snapshot restore;
[`failover-runbook.md`](failover-runbook.md) for manual failover, pg_rewind, and split-brain handling;
[`patroni-restapi-tls.overlay.yml`](patroni-restapi-tls.overlay.yml) and [`../tls/README.md`](../tls/README.md) for
TLS; and [`../backup/README.md`](../backup/README.md) for backup and restore. This directory is not part of the
runtime; delete `deploy/production/patroni/` to remove the template.

## Unvalidated boundaries

- No three-node cluster has run; the compose file is only a topology reference, and no second host was used.
- Failover time is estimated from `ttl`, `loop_wait`, and `retry_timeout`, not measured; etcd quorum loss,
  `pg_rewind` rollback, and split-brain protection are untested, and `watchdog` is disabled by default.
- The MinIO archive path and write latency under synchronous replication are unvalidated, and `pg_hba` still uses plain `host` rules instead of `hostssl`.
- TLS/mTLS placeholders remain, and capacity, backup windows, archive backlog, and `pg_wal` alert thresholds are unmeasured.
