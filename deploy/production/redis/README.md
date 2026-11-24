# Redis high availability (primary, two replicas, three Sentinels)

> **Status: template only.** No Sentinel cluster has been brought up. Failover time, quorum behavior, the
> reconfiguration hook, and the TLS path are unmeasured; `docker-compose.yml` is a single-host topology reference.

## Files

| File | Purpose |
|---|---|
| [`redis-master.conf`](redis-master.conf) | Primary template: AOF `everysec`, `maxmemory 4gb`, `noeviction`, replication backlog 64 MB, TLS/ACL placeholders |
| [`redis-replica.conf`](redis-replica.conf) | Replica template: `replicaof`, `masterauth`, read-only, persistence identical to the primary |
| [`sentinel.conf`](sentinel.conf) | One file for all three Sentinels: master name `lattice`, quorum 2, `down-after-milliseconds 5000`, `failover-timeout 60000`, `parallel-syncs 1` |

## Deployment

1. Run one Sentinel on each of three hosts; data nodes may be co-located with Sentinels, but never put all three Sentinels on the primary's host.
2. Render the configuration; Redis does not expand environment variables, so render before starting:
   ```sh
   export REDIS_PASSWORD=...                          # from a Secret; avoid # & | / (sed renders the template)
   export REDIS_MASTER_HOST=redis-0.lattice.internal  # the primary's real address, not the VIP
   envsubst < redis-master.conf  > /etc/redis/redis.conf
   envsubst < redis-replica.conf > /etc/redis/redis.conf     # both replicas, same REDIS_MASTER_HOST
   envsubst < sentinel.conf      > /etc/redis/sentinel.conf  # same file on all three Sentinels
   ```
3. On replicas, set `replica-announce-ip` to the host's internal IP in cross-host or NAT setups.
4. Start the primary, then both replicas (wait for `master_link_status:up`), then the three Sentinels.
5. Self-check: `redis-cli -p 26379 sentinel master lattice` should report `num-other-sentinels 2`, `quorum 2`, and two replicas.

## Node connection constraints

[`store/redis.rs`](../../../crates/lattice-node/src/store/redis.rs) opens a single URL with `redis::Client::open` and a `ConnectionManager`; it does not implement the Sentinel protocol, so the endpoint must move at the infrastructure layer:

| Approach | How | Cost |
|---|---|---|
| HAProxy or VIP (recommended) | HAProxy `tcp-check` reads `role:master` from `INFO replication`, so only the primary's backend is healthy | One extra hop; HAProxy itself needs active-active or keepalived |
| DNS switchover | A Sentinel `client-reconfig-script` hook updates the DNS record to the new primary | Depends on a second-level DNS TTL |
| Client change | Integrate a Sentinel-aware client into the node | Not implemented; a code change beyond this template |

## Failover notes

| Phase | Observable | Order of magnitude |
|---|---|---|
| Primary down | Sentinel `PING` times out, subjective down (`sdown`) | About 5s (`down-after-milliseconds 5000`) |
| Objective down | At least quorum (2) Sentinels agree on `odown` | Seconds |
| Election and promotion | The replica with the largest offset and highest priority is promoted, the others are repointed | Typically 1-5s, bounded by `failover-timeout 60000` |
| Client recovery | The node's `ConnectionManager` reconnects to the stable endpoint; commands error during the window | Depends on how fast the endpoint moves |
| Data window | Asynchronous replication plus AOF `everysec`: up to about one second of unsynced writes can be lost, then backfilled from PostgreSQL by reconciliation | The pending/sequence authority is PostgreSQL |

```sh
redis-cli -p 26379 sentinel master lattice        # flags should contain master; ip/port point at the new primary
redis-cli -p 26379 sentinel replicas lattice
redis-cli -p 26379 sentinel ckquorum lattice
tail -f /var/log/redis/sentinel.log               # +switch-master / +promoted-slave
```

Watch the dependency status in `/v1/ready`. After a switchover, let the node reconcile pending state (the
`lock:reconcile` task) before restoring traffic.

## Manual switchover, failback, and drill

```sh
# Planned switchover while the primary is still online
redis-cli -p 26379 sentinel failover lattice
# Watch for +switch-master; confirm the new primary has role:master and the old one became a replica
redis-cli -p 26379 sentinel master lattice
```

For failback, do not run `slaveof` manually; either trigger another `sentinel failover` after replication catches
up, or accept the current topology (each failback adds another data window). A single-host drill is possible with
the compose file: start one primary, two replicas, and three Sentinels, stop the primary container, watch a new
primary get promoted within roughly ten seconds, confirm writes through the stable endpoint, then restart the old
primary and confirm it rejoins as a replica. That drill has not been executed here.

## Rollback

| Scenario | Action |
|---|---|
| Abnormal configuration or version upgrade | Restart the affected instance with the previous configuration (replicas first, primary last); data lives in AOF/RDB, so no data rollback is needed |
| Wrong Sentinel parameters | Stop the Sentinel, restore the configuration, and restart; it re-learns topology from the other Sentinels |
| Failover triggered by mistake | After replication catches up, trigger another failover to return to the original primary; never change topology with a manual `slaveof` |

This directory is not part of the runtime; delete `deploy/production/redis/` to remove the template.

## Unvalidated boundaries

- No Sentinel cluster has run: failover time, quorum behavior, `client-reconfig-script`, and TLS are unmeasured.
- Nodes do not speak Sentinel, and the stable-endpoint approach has not been integration-tested with a node.
- The post-failover data window is not validated; only single-host persistence recovery has been exercised.
- Redis Cluster is not provided: `MULTI`/`EVAL` behavior across slots has not been assessed, so review Lua scripts
  before considering Cluster; TLS placeholders, ACLs, and `min-replicas-to-write` are untested.
