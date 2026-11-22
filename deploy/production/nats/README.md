# NATS JetStream production HA (3-node cluster)

> **Template**, a 3-node cluster has never been brought up on this machine. Design basis: the design document (outside this repository) §11/§17.13 (JetStream ×3).
> Offline check: `python scripts/ha-manifest-check.py`.

## Files

| File | Purpose |
|---|---|
| `nats-0.conf` / `nats-1.conf` / `nats-2.conf` | 3-node configuration (different server_name; identical three-way cluster.routes; JetStream storage/limits) |
| `streams.sh` | Pre-creates the 4 Streams with `replicas=3` **before the nodes start**, and verifies the replica count (idempotent) |
| `docker-compose.yml` | Single-host 3-container topology reference; production runs 3 hosts |
| `README.md` | This file: retention policy, why pre-creation is required, failure behavior, boundaries |

## 1. Deployment order (critical)

```
start nats-0/1/2 cluster  →  ./streams.sh (create the 4 Streams with replicas=3)  →  start lattice-node
```
**If the order is reversed**: the node's `ensure_streams()` creates streams with `replicas=1`
(the code default), and afterwards `get_or_create_stream` finds the stream already present and reuses it
as-is, never changing the replica count → the Stream has no redundancy in a 3-node cluster.
Remedy: `nats stream update <name> --replicas 3` (or delete and recreate the stream, which loses messages
still within retention).

Cluster self-check:
```sh
nats --server nats://127.0.0.1:4222 server list        # 3 servers, exactly 1 meta leader
nats --server nats://127.0.0.1:4222 stream report      # every Stream has Replicas: 3
nats --server nats://127.0.0.1:4222 stream info LATTICE_AUDIT -j | grep -E 'num_replicas|messages'
```

## 2. Stream retention policy (identical to `store/nats.rs::stream_specs()`)

| Stream | Subjects | Retention | Storage | max_age | Semantics / loss boundary |
|---|---|---|---|---|---|
| `LATTICE_ROUTE` | `route.>` | **WorkQueue** (delete on consume) | File | 24h | Cross-node point-to-point delivery; the durable pending authority is PG+Redis, the Stream is only a short-lived buffer |
| `LATTICE_BROADCAST` | `topic.>` | Limits | File | 24h | Topic broadcast fan-out; a new node on first start replays broadcasts from the last 24h (known boundary) |
| `LATTICE_AUDIT` | `audit.log` | Limits | File | **7d** | Audit event sourcing; the durable consumer `audit-{node_id}` writes to `audit_log`; the DLQ only reaches logs+metrics |
| `LATTICE_MEDIA` | `media.record.>` | Limits | File | 1h | Stream only; the recording consumer is not wired (recording uses in-process mpsc + MinIO) |

> Stream parameters have **a single definition in code** (`stream_specs()`); `streams.sh` is its deployment
> projection. Changing subjects/retention/max_age in code requires changing `streams.sh` too, otherwise the
> pre-created streams no longer match what the node expects.

## 3. How the node connects (important limitations)

`crates/lattice-node/src/store/nats.rs::connect_client()` uses `async_nats::connect(url)`, and
`[bus] nats_url` is a **single URL** (`&str` parses to exactly one `ServerAddr`; comma-separated server
lists are not supported: `cargo-vendor2/async-nats/src/lib.rs:1805-1811`). Therefore:

- Production must provide a **stable endpoint**: an L4 VIP / DNS round-robin / HAProxy TCP forwarding to the three 4222 ports;
- The async-nats client reconnects on its own (reconnecting to the same URL, i.e. the LB), so a single-node failure is handled by the LB removing it/reconnecting to another node;
- Never configure a fixed IP of one nats node (once that node goes down the client reconnects forever and fails → the bus degrades to Redis, and audit switches to direct PG writes).

With `[bus] kind=nats`: route/topic go through JetStream (publish waits for ack), while online events still
use Redis PubSub; when NATS is unavailable, `node.rs` falls back to Redis per the ② §4.8 degradation matrix
(warn only, startup is not blocked), and audit writes go directly to PG (nothing is lost).

## 4. Failure behavior and operations

| Event | Expected behavior | Verification status |
|---|---|---|
| 1 node down | Raft quorum 2/3 still present: Streams stay readable/writable, leader election takes seconds; clients reconnect through the LB | Unvalidated |
| 2 nodes down | Quorum lost: JetStream publish/consume fails → the node degrades to Redis/direct PG writes | Unvalidated |
| Single node restart | Recovers from the on-disk store and catches up with Raft; durable consumers are preserved | `perf/reports/recovery-nats-20261121.txt` validated single-instance store recovery (31 assertions), not a cluster |
| Disk full | The `max_file_store` limit triggers publish errors → degradation path; alert on `nats_jetstream_storage_bytes` | Unvalidated |
| Rolling upgrade | Restart one node at a time (wait until the cluster is 3/3 healthy before the next); create new Stream replicas before touching anything | Unvalidated |

Common commands:
```sh
nats server report jetstream          # Stream/Consumer counts and storage usage per node
nats stream info LATTICE_AUDIT        # first_seq/last_seq/messages, replicas, cluster distribution
nats consumer ls LATTICE_AUDIT        # durable audit-{node_id} on each node
nats stream view LATTICE_AUDIT        # audit message replay/troubleshooting (retained 7d)
```

## 5. Rollback / failback

A NATS cluster has no "primary node" role (JetStream elects a meta leader via Raft and distributes Stream
replicas across Raft groups), so there is **no component-level failback action**: a recovered node rejoins
the cluster automatically and catches up, which is the equivalent of "failback".

| Scenario | Action |
|---|---|
| Bus abnormal after a node upgrade | Roll back the image tag; Stream data is backward compatible (streams created by newer versions are readable by older ones); if necessary set `[bus] kind=redis-pubsub` to degrade and stop the bleeding |
| Stream accidentally created with replicas=1 | `nats stream update <name> --replicas 3` (no data loss); a stream created while the cluster had only 1 node can only gain replicas after the cluster is scaled out |
| Recovery after node failure | Simply bring the original node back up (it rejoins automatically as a Raft follower and Stream replicas are restored automatically; no manual "failback" action). Afterwards confirm 3/3 online with `nats server report jetstream` and Replicas=3 with `stream report` |
| Configuration error | Roll back the conf on each node and restart (the cluster re-forms); `streams.sh` only adds, never modifies, so re-running it is safe |
| Remove this skeleton | Delete `deploy/production/nats/` (not part of runtime); roll back an already-deployed cluster per the two rows above |

## 6. Unvalidated boundaries

- **No 3-node cluster has ever been built**: Raft leader election, replica rebalancing, rolling upgrades, and 2-node failure degradation are all unmeasured;
- **The node-side gap of not creating replicas=3 Streams is not fixed in code**: this skeleton works around it by "pre-creating"; `deploy/compose/dev.yaml` (single-node -js) is unaffected, but in production forgetting to run `streams.sh` leaves 1 replica;
- **NATS auth/TLS unvalidated** (the configuration block is a commented-out placeholder); the account/JWT permission model with nodes is also unvalidated (nodes in this repository only publish a URL);
- **No load testing**: the decision point of switching to Kafka when broadcast fan-out exceeds 100k subscriptions (design §17.13) is unvalidated.
