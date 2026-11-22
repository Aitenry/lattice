# etcd / DCS production notes (the election dependency of Patroni)

> Authoritative parameters: the `etcd3` and `bootstrap.dcs` sections of `deploy/production/patroni/patroni.yml`.
> This document only explains **why it is configured this way and how to handle failures**; it does not
> redefine parameter values.
> Status: **template + offline validation** (`python scripts/ha-prod-validate.py`, `scripts/ha-manifest-check.py`);
> there is no multi-host environment on this machine, so **no etcd cluster has been brought up and no
> quorum-loss/recovery drill has been performed**.

## 1. Why etcd ×3 rather than "Patroni electing itself"

Patroni does not implement consensus: it writes cluster state (who is leader, each member's last
heartbeat) into the DCS and relies on the DCS's CAS/leases to prevent split-brain. Production must meet:

| Requirement | Value/approach | Why |
|---|---|---|
| Node count | **3** (or 5) | 3 nodes tolerate 1 failure; 2 nodes have **no** quorum fault tolerance (losing 1 of 2 loses quorum), so never run 2 nodes in production |
| Placement | Dedicated hosts/disks, **never the same disk as PG data** | A PG failure (disk full/IO hang) must not take DCS with it; etcd write latency directly determines election latency |
| Clock | NTP/chrony synchronized, skew <100ms | Lease expiry decisions depend on clock advance |
| Network | Dedicated internal network, RTT <10ms; **cross-region deployment forbidden** | etcd writes are strongly consistent; cross-AZ latency slows leader key renewal |
| Disk | SSD, reserve 8Gi+; enable quota and automatic compaction | Without a quota, the NOSPACE alarm rejects writes → Patroni loses DCS entirely |
| Data safety | `etcdctl snapshot save` every 15–30 minutes + a daily off-site copy | When DCS is lost you must **not** wipe etcd and re-elect (that loses cluster state and risks split-brain) |

## 2. What is stored in DCS

```
/lattice/lattice-pg/                    # Patroni namespace (patroni.yml `namespace: /lattice/`, scope=lattice-pg)
├── leader                              # the key the current leader holds (with TTL, ttl=30s)
├── members/<patroni_name>              # one entry per member: heartbeat/last LSN/role
├── config                              # cluster-level configuration (written by bootstrap.dcs, DCS wins afterwards)
├── history                             # switchover history (timeline related)
├── failover                            # manual failover/switchover requests
└── sync                                # synchronous member state for synchronous_mode
```

- `ttl=30 / loop_wait=10 / retry_timeout=10`: if the leader key is not renewed for 30s the primary is
  considered lost; a surviving Patroni starts the election within the next `loop_wait` round (actual
  failover ≈ 30–60s, **not measured**).
- `bootstrap.dcs` **only takes effect at cluster initialization**; afterwards cluster parameters must be
  changed with `patronictl edit-config` (or by editing `patroni.yml` and re-bootstrapping), otherwise you
  think you changed them while DCS still holds the old values.
- **Never** delete `/lattice/lattice-pg/leader` by hand: that is equivalent to creating a "no leader"
  window, and Patroni's split-brain protection depends on the TTL semantics of that key.

## 3. etcd deployment (3 hosts, templates provided)

Files:

| File | Purpose |
|---|---|
| `etcd.conf.template` | etcd configuration template (placeholders `${ETCD_NAME}`/`${NODE_IP}`/`${ETCD_INITIAL_CLUSTER}`); **do not** parse it as YAML directly |
| `etcd.service.template` | systemd unit (non-root user, kernel/filesystem protection, only the data directory writable) |
| `patroni-restapi-tls.overlay.yml` | Patroni-side configuration fragment for etcd mTLS + REST API TLS (merge into `patroni.yml`) |

Steps (on each machine):

```sh
# 1) Render (password/certificate paths come from a Secret/configuration management, never landed in git)
export ETCD_NAME=etcd0 NODE_IP=10.20.0.11
export ETCD_INITIAL_CLUSTER="etcd0=https://10.20.0.11:2380,etcd1=https://10.20.0.12:2380,etcd2=https://10.20.0.13:2380"
envsubst < etcd.conf.template > /etc/etcd/etcd.conf.yml
chmod 0600 /etc/etcd/etcd.conf.yml          # contains paths but no private key; still managed with least privilege

# 2) TLS (internal CA; etcd certificates separate from node gRPC, SANs include this host's IP/DNS)
#    Files: /etc/etcd/tls/{ca.crt,server.crt,server.key}, owner etcd:etcd, 0640

# 3) systemd
install -m 0644 etcd.service.template /etc/systemd/system/etcd.service
systemctl daemon-reload && systemctl enable --now etcd
```

Acceptance (run on all 3 hosts; do not start Patroni until every check is green):

```sh
etcdctl --endpoints=https://10.20.0.11:2379,https://10.20.0.12:2379,https://10.20.0.13:2379 \
  --cacert=/etc/etcd/tls/ca.crt --cert=/etc/etcd/tls/client.crt --key=/etc/etcd/tls/client.key \
  endpoint health
etcdctl ... member list                 # 3 members, all started
etcdctl ... endpoint status --write-out=table   # exactly 1 is_leader; db size normal
etcdctl ... alarm list                  # empty (a NOSPACE alarm must be handled)
```

`initial-cluster-state: new` on first start is only for a **brand-new cluster**; adding nodes/replacing
disks requires `existing` and the official member add procedure, otherwise you end up with two clusters
that do not recognize each other.

## 4. etcd TLS / mTLS

- **Client TLS + client certificate authentication** (`client-cert-auth: true`): Patroni connects to 2379
  with a client certificate issued by the internal CA, SANs configured per IP/DNS; private key 0600, owner etcd.
- **Peer TLS**: 2380 is exposed only on the internal network, with mTLS as well
  (`peer-client-cert-auth`); otherwise a man-in-the-middle could inject members.
- The Patroni-side configuration is the `etcd3` section of `patroni-restapi-tls.overlay.yml`:
  `protocol: https` + `cacert/cert/key`, plus optional `restapi.certfile/keyfile/cafile` (REST API TLS).
- **Rotation**: rotating etcd certificates requires a rolling restart (run `systemctl restart etcd` on one
  host at a time, waiting between hosts for `endpoint health` to recover and the leader to stabilize);
  Patroni does not hot-reload etcd client certificates, so Patroni must also be roll-restarted after etcd
  restarts. Never restart multiple hosts at the same time within the window.

## 5. Behavior on quorum loss (must know)

| Failure | etcd | Patroni / PG | Correct handling |
|---|---|---|---|
| 1 etcd node down | 2/3 still has quorum, normal | Normal renewal/can switch over | Fix that node; neither switchover nor service is affected meanwhile |
| 2 etcd nodes down | **Quorum lost**, all reads and writes fail | Patroni sees DCS unavailable → under `failsafe_mode` the primary **does not self-terminate** (per Patroni semantics: the primary keeps running but **no longer switches over automatically**) | Restore etcd quorum first (bring the failed nodes back); **do not** restart the PG primary at the same time, avoiding the double risk of "primary restarting + no DCS" |
| etcd data entirely lost | Cluster state lost | Each Patroni may consider itself primary → **split-brain risk** | Restore DCS from a snapshot per §6; before restoring, make all PG instances read-only/freeze writes |
| etcd NOSPACE | Writes fail → equivalent to a quorum failure | Automatic switchover stops | Clean up/expand the quota/compact; run `etcdctl defrag` one host at a time (it briefly blocks) |

> **All etcd down ≠ all PG down**: `failsafe_mode: true` (already on) ensures the primary does not
> self-terminate because it "cannot renew" without DCS — availability first. The cost is that **no
> automatic switchover** happens during that time, so human judgment is required.

## 6. etcd snapshot backup / restore

```sh
# Backup (every 15–30 minutes, cron/timer; snapshot files go off-site/into object storage)
etcdctl --endpoints=... --cacert/--cert/--key snapshot save /var/backups/etcd/etcd-$(date -u +%Y%m%dT%H%M%SZ).db
etcdctl snapshot status /var/backups/etcd/etcd-*.db -w table   # verify revision/hash

# Restore (**must** stop the service on all members first, restore from the same snapshot, then re-bootstrap
# via initial-cluster)
systemctl stop etcd
etcdutl snapshot restore /var/backups/etcd/etcd-XXXX.db \
  --name etcd0 --initial-cluster "etcd0=https://10.20.0.11:2380,..." \
  --initial-cluster-token lattice-etcd \
  --initial-advertise-peer-urls https://10.20.0.11:2380 \
  --data-dir /var/lib/etcd/etcd0
# After all 3 hosts are restored, set initial-cluster-state back to new for a fresh bootstrap (or follow the official disaster recovery docs)
systemctl start etcd
```

Suggested retention: every 15 minutes for the last 48 hours, hourly for the last 30 days, daily for the
last year; encrypt snapshots (KMS/age) + keep an off-site copy. This repository has **not validated** the
object-storage backup path (the same class of unvalidated boundary as PG WAL archiving).

## 7. Capacity and day-2 operations

- The default `quota-backend-bytes` of 2GiB is too small: set 8GiB per the §3 template and configure
  `auto-compaction-retention: "1h"`;
- Monitoring: `etcd_server_has_leader`, `etcd_server_leader_changes_seen_total`, `etcd_disk_wal_fsync_duration_seconds`,
  `etcd_mvcc_db_total_size_in_bytes`, `etcd_server_slow_apply_total`, `etcd_network_peer_round_trip_time_seconds`;
- Alert thresholds: fsync p99 > 25ms, db size > 6GiB, leader changes >0 (within 10 minutes), any endpoint health red;
- Roll out every etcd version upgrade one host at a time; take a snapshot before upgrading, and afterwards
  confirm all 3 members are on the same version in `member list`.

## 8. Unvalidated boundaries

1. No 3-node etcd cluster has ever been brought up (single-host Docker here; `patroni/docker-compose.yml` is a topology reference only);
2. Quorum loss, failsafe, etcd recovery, and split-brain protection have not been measured;
3. etcd mTLS has not been integration-tested (the certificate block in `patroni.yml` is a commented-out placeholder);
4. The snapshot backup/restore path and retention policy are unvalidated;
5. No etcd capacity/latency load testing has been done (fsync, compaction, defrag duration).
