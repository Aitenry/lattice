# NATS JetStream high availability (three-node cluster)

> **Status: template only.** No three-node cluster has been brought up; Raft election, replica rebalancing, rolling upgrades, and two-node failure degradation are unmeasured.

`nats-0.conf`, `nats-1.conf`, and `nats-2.conf` hold one configuration per node: different `server_name`,
identical three-way `cluster.routes`, client listen 4222, monitoring 8222, cluster routes 6222, and JetStream in
`/data/jetstream` with `max_mem_store: 2G` and `max_file_store: 200G`. [`streams.sh`](streams.sh) pre-creates the
four Streams with `replicas=3` and verifies them; it is idempotent and `--check` verifies without creating. [`docker-compose.yml`](docker-compose.yml) is a single-host topology reference.

## Deployment order

Start the three nodes, then run `./streams.sh`, then start lattice-node. The order is critical: the node calls
`get_or_create_stream`, the client default is `replicas=1`, and an existing Stream is reused as-is; if the node
starts first, the Streams have no redundancy and losing the node that hosts a Stream loses its data. Remedy:
`nats stream update <name> --replicas 3`, or delete and recreate the Stream (losing retained messages).

```sh
nats --server nats://127.0.0.1:4222 server list        # three servers, exactly one meta leader
nats --server nats://127.0.0.1:4222 stream report      # every Stream must show Replicas: 3
nats --server nats://127.0.0.1:4222 stream info LATTICE_AUDIT -j | grep -E 'num_replicas|messages'
```

## Stream retention policy

The parameters match `stream_specs()` in [`store/nats.rs`](../../../crates/lattice-node/src/store/nats.rs); change code and `streams.sh` together.

| Stream | Subjects | Retention | Storage | max_age | Semantics and loss boundary |
|---|---|---|---|---|---|
| `LATTICE_ROUTE` | `route.>` | WorkQueue | File | 24h | Cross-node point-to-point delivery; durable pending state is PostgreSQL plus Redis, the Stream is a short-lived buffer |
| `LATTICE_BROADCAST` | `topic.>` | Limits | File | 24h | Topic fan-out; a node starting fresh replays broadcasts from the last 24h |
| `LATTICE_AUDIT` | `audit.log` | Limits | File | 7d | Audit event sourcing; durable consumer `audit-{node_id}` writes to `audit_log`; DLQ failures only reach logs and metrics |
| `LATTICE_MEDIA` | `media.record.>` | Limits | File | 1h | Media recording side path: the producer publishes after the tee, and durable consumer `media-record-{node_id}` writes segments to MinIO; publish failure degrades to a direct object-storage write. The 1h retention bounds the replay window |

## Client connection constraints

[`store/nats.rs`](../../../crates/lattice-node/src/store/nats.rs) connects with `async_nats::connect(url)`, and
`[bus] nats_url` is a single URL: comma-separated server lists are not supported. Therefore:

- Provide a stable endpoint (L4 VIP, DNS round-robin, or HAProxy TCP forwarding to the three 4222 ports); the
  client reconnects to the same URL, so a failed node must be removed by the load balancer.
- Never point `[bus] nats_url` at a fixed node IP: when that node dies the client reconnects forever and the bus
  stays degraded.

With `[bus] kind=nats`, routes and topics use JetStream (publish waits for an ack) while online events still use
Redis PubSub. When NATS is unavailable the node falls back to Redis (a warning, not a startup failure) and audit
writes go directly to PostgreSQL, so audit events are not lost.

## Failure behavior and operations

| Event | Expected behavior | Verified |
|---|---|---|
| One node down | Quorum remains 2/3; Streams stay readable and writable, a leader is elected in seconds, clients reconnect through the LB | No |
| Two nodes down | Quorum lost; JetStream publish and consume fail and the node degrades to Redis or direct PostgreSQL writes | No |
| Node restart or rolling upgrade | Recovers from the on-disk store and catches up with Raft, preserving durable consumers; do one node at a time and wait for 3/3 | No |
| Disk full | `max_file_store` triggers publish errors and the degradation path; alert on JetStream storage usage | No |

```sh
nats server report jetstream     # Stream/Consumer counts and storage usage per node
nats consumer ls LATTICE_AUDIT   # durable audit-{node_id} on each node
```

## Rollback and failback

JetStream has no primary role: it elects a meta leader and spreads Stream replicas across Raft groups, so a
recovered node rejoins and catches up automatically. There is no component-level failback action; this directory
is not part of the runtime. Check the release notes before rolling back an image tag.

| Scenario | Action |
|---|---|
| Bus abnormal after a node upgrade | Roll back the image tag; as a stopgap set `[bus] kind=redis-pubsub` to degrade |
| Stream accidentally created with `replicas=1` | `nats stream update <name> --replicas 3`; a Stream created while the cluster had one node can gain replicas only after scale-out |
| Node recovery | Start the original node; it rejoins as a Raft follower and replicas are restored. Confirm 3/3 with `nats server report jetstream` and `Replicas: 3` with `stream report` |
| Configuration error | Restore the previous configuration on each node and restart; `streams.sh` only adds and never modifies, so re-running it is safe |

## Unvalidated boundaries

- No cluster has run: Raft election, replica rebalancing, rolling upgrades, and two-node failure are unmeasured.
- The missing `replicas=3` default is not fixed in code; forgetting the pre-creation step silently leaves one replica.
- Authentication and TLS are placeholders, and the account/JWT permission model with nodes is untested.
- No load testing has been done, so where a three-node cluster stops being the right bus is unknown.
