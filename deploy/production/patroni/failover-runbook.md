# PG failover runbook (Patroni + etcd ×3, synchronous replication)

> Status: **a template written from official behavior and repository configuration, not drilled on a real
> cluster**. There is no multi-host environment on this machine, so failover time, pg_rewind rollback,
> etcd quorum loss, and split-brain protection have not been measured.
> Authoritative parameters: `patroni.yml`; etcd details: `etcd-dcs.md`; TLS fragment: `patroni-restapi-tls.overlay.yml`.
> After a drill, record measured RTO/RPO under `perf/reports/ha-*` (report format in `deploy/production/README.md` §3).

## 0. Prerequisites (if any is missing, do not perform switchover-class operations)

| Prerequisite | Check command/criterion |
|---|---|
| Clients use the **stable endpoint** | Node `[pg] url` points at the VIP/HAProxy/DNS, never directly at one PG host's IP; HAProxy health check = Patroni `GET :8008/primary` returns 200 |
| etcd has quorum | `etcdctl endpoint health` all green; `member list` shows 3 started |
| Monitoring is in place | `patronictl list`, `pg_stat_replication`, `pg_stat_archiver`, centralized PG log collection |
| Archiving healthy | `pg_stat_archiver.failed_count` not growing; `last_archived_time` fresh (PITR prerequisite) |
| Clocks synchronized | `chronyc tracking` skew <100ms (leases/Sentinel/Raft all depend on it) |
| Secrets available | The 5 Patroni passwords + TLS certificates are in secret management; no password appears in `ps` |
| A rollback plan exists | You know the current primary, current timeline, and most recent PITR base; you know how to roll back the image/configuration |

## 1. Failure decision matrix

| Symptom | Diagnosis | First action |
|---|---|---|
| Primary process/host down | Patroni elects automatically (30–60s, dominated by `ttl=30`) | Watch `patronictl list`; do **not** promote manually |
| Primary alive but DCS unreachable | Cannot confirm who is primary | Restore etcd quorum first; do not restart the PG primary at the same time |
| 1 replica down | Synchronous replication may degrade (primary+1 replica still satisfies `synchronous_node_count=1`; losing one more goes asynchronous) | Fix the replica; watch Lag / Sync Standby |
| Replication broken (Lag keeps growing) | Network/disk/`max_wal_senders`/slot problems | Check `pg_stat_replication` and the `pg_wal` disk first; do not rush a switchover |
| `patronictl list` shows two Leaders | **Split-brain risk** (usually with etcd split/DCS restore error) | Freeze writes immediately (remove the VIP/read-only), handle per §6; never serve writes from both |
| pg_rewind failed (old primary cannot rejoin) | Old primary's data directory conflicts with the DCS timeline | Manual pg_rewind per §5; if that fails, rebuild the replica with `pg_basebackup` |
| Archiving stalled (`last_archived_time` not advancing) | Object storage/`wal-gateway.sh`/certificate problem | Fix archiving; `pg_wal` grows meanwhile, so free disk space or a full primary becomes a real outage |

## 2. Automatic failover (primary down, the most common case)

Timeline (**estimated, not measured**):

```
T0          primary goes down / is network-isolated
T0+~30s     leader key TTL expires (ttl=30s)
T0+30~60s   surviving Patroni nodes reach quorum, elect a new primary from the synchronous replicas and promote it (loop_wait=10s polling)
T0+60s~     HAProxy's /primary health check moves write traffic to the new primary (determined by health-check interval + failure threshold)
T0+minutes  after the old primary restarts, Patroni runs pg_rewind automatically and it rejoins as a replica
```

Handling steps:

1. Confirm the alert and blast radius: `patronictl -c /etc/patroni/patroni.yml list` (who is Leader, Lag, TL).
2. Check whether HAProxy already points write traffic at the new primary: `curl -s http://127.0.0.1:<haproxy-stat>/; csv` or
   `curl -s -o /dev/null -w '%{http_code}' http://<vip>:8008/primary` (should be 200).
3. Do **not** run `pg_ctl promote` manually: Patroni is already managing this, and a manual promotion creates split-brain.
4. Wait for the old primary to return: in `patronictl list` it should be `Replica` with `Lag in MB` converging to 0;
   the log shows `rewind` / `starting as a secondary`. If it has not returned after 30 minutes → §5.
5. Application verification (see §7): `/v1/ready`, message round-trip, `scripts/reconcile.py` reconciliation.
6. Record: T0, new primary, RTO, whether transactions were lost (synchronous mode should give RPO=0; asynchronous/degraded may lose some), and the old primary's return time.

## 3. Planned switchover (rolling upgrade/hardware replacement)

```sh
# 1) Pick a candidate replica with lag≈0 and confirm archiving/replication are healthy
patronictl -c /etc/patroni/patroni.yml list
# 2) Switch over (--force for unattended windows; drop it in an interactive environment)
patronictl -c /etc/patroni/patroni.yml switchover --master pg0 --candidate pg1 --force
# 3) Watch: Leader becomes pg1, pg0 becomes Replica, Lag → 0
patronictl -c /etc/patroni/patroni.yml list
```

- Before: drain part of the write traffic or pick off-peak hours; confirm the application reconnect logic
  (does the sqlx pool reconnect to the new primary after old connections fail).
- During: HAProxy's `/primary` health check briefly goes all red (write window = seconds to ttl scale); read traffic can stay on the replicas.
- After: run the §7 verification; then upgrade/replace hardware on pg0; for failback principles see §8.
- Frequent switchovers consume timelines, which is normal; record the TL so PITR alignment is easier.

## 4. Manual failover when automatic failover is unavailable

Perform only when **all** of the following hold: etcd quorum is healthy, the original primary is confirmed
unrecoverable, and there is no split-brain risk.

```sh
# 1) Freeze writes: remove the VIP or put the HAProxy backend in maintenance (manual phase, counted in RTO)
# 2) Mark the original primary unavailable (written to DCS; afterwards the original primary must not be started casually)
patronictl -c /etc/patroni/patroni.yml failover --candidate pg1 --force
# 3) Confirm the new primary
patronictl -c /etc/patroni/patroni.yml list
# 4) Restore the entry point/traffic (read-only/small traffic first, see §7)
```

> After the original primary recovers it **must first be rewound or rebuilt** before rejoining the cluster
> (§5), otherwise it conflicts with the timeline in DCS.

## 5. pg_rewind / old primary rejoining

`bootstrap.dcs.postgresql.use_pg_rewind: true` + `wal_log_hints: "on"` are the prerequisites for automatic
rewind. When automatic rewind fails (common causes: incomplete `pg_wal`, a manually modified data directory,
bad disk blocks):

```sh
# On the old primary (now the "to be rewound" node), stop the PG process managed by Patroni:
patronictl -c /etc/patroni/patroni.yml pause          # pause automatic operations
pg_ctl -D /var/lib/postgresql/data stop -m fast

# Point pg_rewind at the current primary (needs replication/rewind privileges and --target-pgdata)
pg_rewind --target-pgdata=/var/lib/postgresql/data \
  --source-server="host=<new-primary> port=5432 user=rewind_user password=<secret> dbname=postgres" \
  --progress

# Produce a standby configuration (PG12+: standby.signal + primary_conninfo; or let Patroni write it on takeover)
touch /var/lib/postgresql/data/standby.signal
# After startup Patroni takes over (resume), confirm:
patronictl -c /etc/patroni/patroni.yml resume
patronictl -c /etc/patroni/patroni.yml list        # old primary = Replica, Lag → 0
```

Fallback when rewind fails: rebuild that node from the primary with `pg_basebackup -R` (minutes for a large
database, an RTO impact item; the node serves no read traffic during the rebuild).

## 6. Split-brain / DCS split (the most dangerous)

**Symptoms**: `patronictl list` shows Leader on two nodes; clients can write to both; or HAProxy succeeds
alternately on two `/primary` endpoints.

Handling principles:

1. **Freeze all writes first** (remove the VIP/LB, make both nodes read-only with `ALTER SYSTEM SET default_transaction_read_only=on;` followed by
   `pg_reload_conf()`, or stop application write traffic) — an outage is preferable to diverging writes.
2. Determine which side's data is "recognized by DCS": check the leader key holder in `patronictl list`, the PG log timeline,
   and `Latest checkpoint location` in `pg_control`; trust the member holding the leader key in etcd.
3. The non-recognized side: stop PG → snapshot the data directory → rewind or rebuild per §5.
4. DCS data corrupt/entirely lost: restore DCS from a snapshot per `etcd-dcs.md` §6; **do not** wipe etcd and rebuild.
5. Afterwards: reconciliation (`scripts/reconcile.py`), inspect diverging transactions (by business table primary key/`delivery_log`),
   fill in audit records; postmortem why watchdog was not enabled/why etcd crossed data centers.

## 7. Post-switchover verification checklist (restore traffic only after all pass)

```sql
-- 1) Topology: 1 primary, 2 replicas, synchronous replica present (synchronous mode)
SELECT pg_is_in_recovery();                                   -- primary = f
SELECT client_addr, state, sync_state, replay_lag
  FROM pg_stat_replication;                                   -- 2 rows, at least 1 sync
-- 2) Timeline and recovery
SELECT pg_current_wal_lsn(), pg_current_wal_timeline();
-- 3) Archive progress (PITR prerequisite)
SELECT archived_count, failed_count, last_archived_time, last_failed_time FROM pg_stat_archiver;
-- 4) No replication slot backlog
SELECT slot_name, active, pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS retained
  FROM pg_replication_slots;
```

Application side (following the general flow in `deploy/production/README.md` §5):

1. `curl -fsS http://<node>:8080/v1/ready` → 200;
2. Run login/message round-trip/WS upgrade/large-file download once each (`scripts/smoke.ps1` equivalent production smoke test);
3. `python scripts/reconcile.py`: `delivery_log` and `messages` watermarks agree, pending rebuild is idempotent;
4. Observe for ≥10 minutes: error rate, `pg_stat_replication` Lag, archive failure count, node reconnect logs.

## 8. Failback principles (do not fail back just to "look restored")

- Let Patroni determine the steady-state topology; **failback = run the §3 switchover again**, not a reverse manual promote.
- Before failback: the original primary has rejoined as a replica with lag≈0, archiving is healthy, it is off-peak, and a change window exists.
- Failback also counts as a failover: it equally requires draining traffic, verification, reconciliation, and RTO/RPO recording.
- Major PG version upgrades/cluster replacements **cannot** be reverted in place by failback: use a new cluster + logical replication cutover (expand/contract).

## 9. Degrading to asynchronous replication (and failing back to synchronous)

Scenario: cross-data-center synchronous replication makes write latency unacceptable, or only the primary
remains. For the method and cost see the header of `patroni-dcs-async.overlay.yml` (summary):

```sh
# Degrade (explicitly accept RPO>0)
patronictl -c /etc/patroni/patroni.yml edit-config --set synchronous_mode=false --set synchronous_mode_strict=false
# Fail back (requires at least 1 replica to catch up)
patronictl -c /etc/patroni/patroni.yml edit-config --set synchronous_mode=true
patronictl -c /etc/patroni/patroni.yml list     # wait for Sync Standby to appear + Lag ≈0
```

A failure inside the degraded window: the new primary may be missing the last few transactions → after
recovery run `scripts/reconcile.py` first, then decide per business tolerance whether to recover the lost
writes with PITR (PITR rewinds the timeline and needs a separate review).

## 10. Rollback (related to this runbook)

| Scenario | Rollback |
|---|---|
| Problems with the new primary after a switchover | Switch back per §3 once the new primary has caught up/is healthy; promoting the old primary directly is not allowed |
| Node abnormal after rewind | Pause Patroni management (`pause`), rebuild that node from the primary with pg_basebackup; the current primary is unaffected |
| Want RPO=0 back after asynchronous degradation | Fail back to synchronous_mode=true per §9 and declare compliance only after Sync Standby is confirmed |
| Business reports "lost writes" after a switchover | Freeze writes immediately → inspect timeline/archiving → restore to the target point in time per PITR §3.2 (README); **do not** write the old data directory back |
| Files in this directory (not deployed) | Just delete the added runbook/overlay/etcd templates; there is no runtime state |

## 11. Unvalidated boundaries

1. Automatic/manual failover has not been drilled on a real 3-node cluster; 30–60s is an **estimate**;
2. pg_rewind automatic/manual rollback is unvalidated (no real replica to rewind);
3. etcd quorum loss, failsafe, and DCS snapshot restore are unvalidated (same in `etcd-dcs.md`);
4. The effect of synchronous replication on write latency and the write-blocking window during synchronous replica switchover are unvalidated;
5. The HAProxy/VIP `/primary` health check and endpoint drift have not been integration-tested;
6. Split-brain protection (`watchdog` is disabled by default) and the manual split-brain handling procedure are unvalidated;
7. PITR restore against the object-storage archive path is unvalidated (see `deploy/production/backup/README.md`).
