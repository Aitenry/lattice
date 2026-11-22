# Redis production HA (1 primary + 2 replicas + Sentinel ×3)

> **Template**, a Sentinel cluster has never been brought up on this machine. Design basis: the design document (outside this repository) §11/§17.13
> (small-scale Sentinel ×3; relies only on primary/replica semantics, not cross-slot transactions). Offline check: `python scripts/ha-manifest-check.py`.

## Files

| File | Purpose |
|---|---|
| `redis-master.conf` | Primary template: AOF everysec, `noeviction`, placeholders for memory/replication/TLS |
| `redis-replica.conf` | Replica template: `replicaof` + `masterauth` + read-only, persistence identical to the primary |
| `sentinel.conf` | Sentinel template (same file on all 3 hosts): master name `lattice`, **quorum 2**, down-after 5s |
| `docker-compose.yml` | Single-host 6-container (master+2 replica+3 sentinel) topology reference; placeholders are rendered with sed at startup |
| `README.md` | This file: failover notes, switchover/failback, boundaries |

## 1. Deployment notes

1. Each of the 3 hosts runs **1 Sentinel** (the Sentinel count ≠ the data node count); data nodes
   master/replica may be co-located, but the three Sentinels must not all share a host with the master
   (otherwise a host failure loses the quorum outright).
2. Render the configuration (Redis does not expand environment variables):
   ```sh
   export REDIS_PASSWORD=...                      # injected from a Secret; avoid # & | / in the value (sed renders the template)
   export REDIS_MASTER_HOST=redis-0.lattice.internal   # the primary's real address (NOT the VIP!)
   envsubst < redis-master.conf  > /etc/redis/redis.conf     # primary
   envsubst < redis-replica.conf > /etc/redis/redis.conf     # both replicas (set the same REDIS_MASTER_HOST)
   envsubst < sentinel.conf      > /etc/redis/sentinel.conf  # same file on all 3 Sentinels
   ```
3. On replicas, `replica-announce-ip` **must** be set to the host's internal IP in cross-host/NAT setups
   (it is a commented-out line in the template).
4. Start order: master → replica×2 (wait for `master_link_status:up` in `INFO replication`) → sentinel×3.
5. Self-check: `redis-cli -p 26379 sentinel master lattice` should show `num-other-sentinels 2`,
   `quorum 2`, and `num-slaves 2`.

## 2. How the node connects (important limitations)

`crates/lattice-node/src/store/redis.rs` uses `redis::Client::open(cfg.url)` + `ConnectionManager`:
it **does not implement the Sentinel protocol and accepts a single URL only** (`redis://[:password@]host:port[/db]`). Options:

| Approach | How | Cost |
|---|---|---|
| **HAProxy/VIP (recommended)** | Put HAProxy in front: `tcp-check` reads `role:master` from `INFO replication`, so only the primary's backend is healthy | One extra hop; HAProxy itself needs active-active/keepalived |
| DNS switchover | Sentinel notification hook (`client-reconfig-script`) calls the DNS API to point `redis.lattice.internal` at the new primary | Depends on DNS TTL (needs to be second-level) |
| Client change | Integrate a Sentinel client in the node (for example `redis::sentinel`) | **Not done** (a code change, outside this skeleton) |

## 3. Failover notes (what happens / how to observe it)

| Phase | Observable | Order of magnitude |
|---|---|---|
| Primary down | Sentinel `PING` times out → subjective down `sdown` | ~5s (`down-after-milliseconds 5000`) |
| Objective down reached | ≥ quorum(2) Sentinels agree on `odown` | seconds |
| Election + promotion | Pick the replica with the largest replication offset and highest priority, `SLAVEOF NO ONE`, repoint the other replicas at the new primary | typically 1–5s (bounded by `failover-timeout 60000`) |
| Client recovery | The node's `ConnectionManager` reconnects to the stable endpoint; Redis commands error during the switchover window | depends on how fast the endpoint moves |
| Data window | Asynchronous replication + AOF everysec: the last ≤1s of writes not yet synced to a replica may be lost → **backfilled by PG + reconcile** (the pending/seq authority is PG) |

Observation commands:
```sh
redis-cli -p 26379 sentinel master lattice        # flags should contain master; ip/port already point at the new primary
redis-cli -p 26379 sentinel replicas lattice
redis-cli -p 26379 sentinel failover-state lattice   # state during a switchover
tail -f /var/log/redis/sentinel.log                  # +switch-master / +promoted-slave
```
Node-side metrics to watch: rising `lattice_store_latency_seconds{backend="redis"}` and the dependency status in `/v1/ready`.
After a switchover you **must** run `scripts/reconcile.py` (or wait for the periodic `lock:reconcile`) to reconcile pending state before restoring traffic.

## 4. Manual switchover / failback / drill

```sh
# Planned switchover (primary still online):
redis-cli -p 26379 sentinel failover lattice        # triggers one controlled failover (no manual leader election)
# Watch for: +switch-master; confirm the new primary has role:master and the old one became a slave (Sentinel reconfigures automatically)
redis-cli -p 26379 sentinel master lattice

# Failback (switch back to the original primary): do not run slaveof manually; either trigger another
# failover the same way, or accept Sentinel's current topology (failback adds another data window — skip it unless necessary)
```
Drill (no cluster on this machine, so single-host simulation only): start 1 master+2 replica+3 sentinel
(see the compose startup command) → `docker stop <master>` → observe Sentinel promoting a new primary within
~10s → confirm a node script can write through the stable endpoint → `docker start <original-master>` →
confirm it rejoins as a `slave`. **Not executed on this machine** (see §6).

## 5. Rollback

| Scenario | Action |
|---|---|
| Abnormal configuration/version upgrade | Restart the affected instance with the previous configuration file (replicas first, primary last); data lives in AOF/RDB, no data rollback needed |
| Wrong Sentinel parameters | Stop the Sentinel → restore the configuration → restart; it re-learns the topology from the other Sentinels |
| Failover triggered by mistake | After replication catches up, trigger another failover per §4 to return to the original primary; never change topology with a manual `slaveof` |
| Remove this skeleton | Delete `deploy/production/redis/` (not part of runtime); roll back an already-deployed cluster per the two rows above |

## 6. Unvalidated boundaries (this document must not be used to declare Redis HA achieved)

- **No Sentinel cluster has ever been brought up**: failover time, quorum behavior, `client-reconfig-script`, and the full TLS path are all unmeasured;
- **Nodes do not support Sentinel**: the stable-endpoint (HAProxy/VIP/DNS) approach has not been integration-tested with nodes in this repository (see §2);
- **The data window after AOF/RDB failover is unvalidated**: `perf/reports/recovery-redis-20261121.txt` validated
  single-host RDB recovery only (29 assertions, 0.81s recovery), not an HA switchover;
- **Redis Cluster (large-memory form) is not provided**: Cluster×6 in design §17.13 is an alternative, and the code
  relies only on primary/replica semantics, but the cross-slot limitations of `MULTI/EVAL` under Cluster have not been
  assessed → review Lua scripts separately before switching to Cluster;
- TLS (the `tls-port` block is a placeholder), ACLs, and the availability impact of `min-replicas-to-write` are unvalidated.
