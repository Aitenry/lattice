# lattice-node (backend implementation)

The platform's single-binary node: WS/REST/gRPC/MQTT ingress + message pipeline + online routing + offline redelivery.
**The code is only the implementation of ②** — values live in the design doc §17/§18, interfaces in ⑤, data model in ⑥;
this file only covers "where the code is, how to run it, and what is still not aligned with the docs".

## Build and run

```bash
# First time: install the Rust toolchain inside the repo (.tooling/, without touching the system environment)
scripts\bootstrap-rust.cmd

scripts\cargo.cmd check --workspace
scripts\cargo.cmd test  --workspace          # 72 unit tests

# Run directly (needs PG + Redis; MinIO is required only for the upload/large-message paths)
scripts\cargo.cmd run -p lattice-node -- --config deploy/config/dev.toml

# Start the dependency stack (smoke needs only pg + redis; minio is required only for the upload/large-message paths)
docker compose -f deploy/compose/dev.yaml up -d pg redis

# End-to-end smoke: self-contained script; starts the node → asserts → always kills the node → writes the result to .tooling\smoke-result.json
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\smoke.ps1

# WS smoke (hello/envelope/ack/receipt + offline redelivery) → .tooling\ws-result.json
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\ws-smoke.ps1
```

**When running the node on the host machine (not in a container) you must override the container hostnames**, otherwise startup reports
`Internal + details.dep=pg` (`storage unavailable`):

```bat
set LATTICE__PG__URL=postgres://lattice_app:lattice_dev_pw@127.0.0.1:5432/lattice?sslmode=disable
set LATTICE__REDIS__URL=redis://127.0.0.1:6379
set LATTICE__AUTH__KEY_DIR=<absolute repo path>\.tooling\keys
set LATTICE__S3__ENDPOINT=http://127.0.0.1:9000
```

`pg:` / `redis:` / `minio:` in `dev.toml` are service names on the compose network;
`/etc/lattice/keys` is not writable on Windows, so `key_dir` must be changed. `scripts\smoke.ps1` already bakes in these four overrides.

Config: `deploy/config/dev.toml` (the committed copy of `config.rs::SAMPLE_TOML`) + environment variable overrides
`LATTICE__{SECTION}__{FIELD}`. On first startup the key directory auto-generates an RS256 key pair (`jwt.key.pem` /
`jwt.key.prev.pem`); in production mount it from a K8s Secret (② §6).

Migrations: `sqlx::migrate!("./migrations")` is embedded at compile time and run under a lock at startup (② §7.2).

## Code-to-doc mapping

| Module | Doc |
| --- | --- |
| `lattice-core/{protocol,envelope,frame,ids,keys,error}` | design §17 (command set/state enums/thresholds/error codes/key names), ⑤ §9 |
| `lattice-plugins` | ② §4.5 (registry, stable-hash canary, signature digest, sidecar circuit break) |
| `auth/{jwt,password,device,rbac}` | design §17.11, ⑤ §0.2 / §1, ② §6 |
| `store/{pg,redis,s3,wal,bus}` | ⑥ §2 (DDL) / §3 (keys) / §4 (buckets) / ② §4.8 (degradation) |
| `pipeline/*` | ② §2.2 (stage list, error classification, bypass) |
| `routing/{online,pending,topic,seq,crossnode}` | ② §4.1–§4.4, §4.8 (seq anti-rollback) |
| `transport/{http,ws,grpc,mqtt,quic}` | ⑤ §1–§9, ② §3 |
| `admin` | ⑤ §8 (RBAC in §0.2) |
| `observe/metrics` | ② §8 (metric naming `_seconds`/`_total`) |
| `jobs` / `degrade` | ⑥ §2.6 (cleanup tasks and lock names), ② §4.8 |
| `migrations/000{1..4}_*.sql` | ⑥ §2.3 (per-table DDL), §2.5 (partitioning), seed |

## Current status

- `cargo check --workspace`: passes, zero warnings;
- `cargo test --workspace`: **72/72 pass** (core 19 / node 50 / plugins 3);
- Route coverage: the ⑤ §12 checklist is implemented item by item (auth 3 / users+devices 5 / conversations 8 / messages 4 /
  uploads 5 / probes 2 / topics 4 / admin **35** / WS 13 cmd); the 35 `admin` entries map one-to-one to ⑤ §8.1–§8.6
  (including `users/{id}/role`, §8.6 `audit`, and the `POST /v1/admin/users` added in v0.7);
- **HTTP end-to-end really passes** (`scripts\smoke.ps1`, `ok:true`, 6/6 steps):
  `/v1/ready` → `login` (`role=admin` in the JWT) → `POST /v1/admin/users` creates an account (viewer) →
  `POST /v1/conversations` (`kind=dm`) → `POST /v1/messages` (returns `seq=1`, `state=persisted`,
  `duplicate=false`) → `POST /v1/conversations/{id}/read` (read watermark persisted);
- **WS end-to-end really passes** (`scripts\ws-smoke.ps1`, `ok:true`, 14/14 steps):
  two connections `hello`→`hello-ack` (`session=1/2`, `mode=zero-knowledge`, `proto=1-1`) → A sends a message
  (`state=routed`) → **B receives `envelope` (protobuf-decoded, `seq`/`conv_id` matching the HTTP response)**
  → B sends `ack` → **A receives `receipt{state=acked}`** → with B disconnected another message is sent → after B reconnects
  **redelivery from the pending queue succeeds** (`seq=2`);
- **Upload path really passes** (`scripts\upload-smoke.ps1`, `ok:true`, 11/11 steps, all three MinIO buckets ready):
  `POST /v1/uploads` (9MB → `part_size=8MB`, `part_count=2`) → both parts **presigned-PUT to S3 for real**
  (`etag` non-empty) → `POST /{id}/parts` re-presign (idempotent) → `POST /{id}/complete` (`state=persisted`,
  returns `payload_ref=<yyyy/mm/dd/msgid/c0.bin>`) → progress query after completion returns `404` (session cleared, expected) →
  **`/v1/messages` over 1MB returns `413 {"code":"TOO_LARGE","details":{"hint":"use_ws_or_chunk"}}`** (see R6);
- **Backpressure really passes** (`scripts\backpressure-smoke.ps1`, `ok:true`, 11/11 steps): after one connection completes `hello`
  it **deliberately stops consuming**, while the other side sends **420 × 16KiB** back to back; `lattice_backpressure_dropped_total{priority="envelope"}`
  rises from 0 to **152** (≈ 420 − 256-frame queue − a little socket buffering), and after resuming reads the connection **still drains normally**
  (8 frames read); see R7 for details;
- **Not yet verified**: `grpc/mqtt/quic` (skeletons, P2/P3/P4, see ② §12);
  `proto/lattice.proto` defines only the contract, with no codegen wired in (needs protoc/buf); the `deploy/Dockerfile`
  multi-stage build is not usable on this machine (crates.io cannot be reached inside the container), and the node image and `lattice-dev-node` container have not been run for real.

## Doc problems found during implementation (backfilled in doc set v0.6–v0.13)

> Status: the 8 gaps below have been backfilled into ⑤⑥② and design §17/Appendix A per design §17.14,
> **and the code has been changed to match the backfilled contract**; each item's landing point is in the mapping table at the end of this section.
> The record is kept because "why the old form was unreasonable" is itself the reason not to repeat it.

1. **`users` has no role column**: ⑤ §0.2 requires a `role` JWT claim, but the `users` table in ⑥ has no such column and ⑤ has no
   role management endpoint → v0.6 added `users.role` + `POST /v1/admin/users/{id}/role` (⑥ D14); the code now treats
   `users.role` as the single source of truth and removed the earlier `dynamic_config['rbac.roles']` fallback.
2. **`GET /v1/admin/audit`** appears in ② §3.2 and the console Audit page, but ⑤ §8 lacks the entry → implemented; ⑤ still needs it added.
3. **Upload session has no storage form**: ⑤ §5 has `GET /v1/uploads/{id}` progress query, but ⑥ has no table/key →
   temporarily Redis `lattice:upload:{id}` (TTL matching the presign), needs registering in ⑥ §3.1.
4. **`metric_snapshot` partition granularity conflict**: ⑥ §2.2 says "daily", the §2.5 sample DDL is "monthly" →
   v0.6 unified it to **daily** (with a 30-day retention shorter than the partition span, old partitions cannot be dropped, ⑥ D15); the sample DDL was removed;
   the code pre-creates daily partitions (1 day back to 7 days ahead) and drops partitions older than 30 days.
5. **queue purge's `before_ts` cannot be implemented directly**: ⑤ §8.3 gives `before_ts`, but ⑥ §3.1's pending
   is a ZSET with score = seq (not time) → the implementation looks up `created_at` in PG via `message_times()` to filter;
   it is suggested that ⑥ state explicitly that "pending carries no timestamp" as the tradeoff.
6. **The message bodies in `proto/lattice.proto` are provisional**: ② §3.3 gives only 4 RPC signatures, no message
   fields → until ② is completed, field numbers in this file "may only be added, never changed".

## Backfill landing points and code sync

| # | Doc landing point (v0.6) | Code change |
| --- | --- | --- |
| 1 | ⑥ §2.3 `users.role` + §9.1 D14; design §17.11; ⑤ §0.2 "role source", §8.2 endpoint | `migrations/0001_core.sql` (with `add column if not exists`), `store/pg.rs::{User.role,set_user_role,count_users_by_role}`, `node.rs` (bootstrap account converged to admin), `admin::role_change` (rejects demoting the last admin), `auth/rbac.rs` (removed the `dynamic_config['rbac.roles']` fallback) |
| 2 | ⑤ §8.6 audit query + §12 count 34 | `admin::audit` (implemented earlier, now consistent with the contract) |
| 3 | ⑥ §3.1 `lattice:upload:{id}`, §2.6 retention, §1 responsibility table; ⑤ §5.3 | `store/redis.rs` (upload session keys + `scan_prefix` restricted to the admin plane) |
| 4 | ⑥ §2.2/§2.5/§2.6 unified to daily; design §17.13 | `migrations/0003_audit_metrics.sql` (pre-create daily, 1 day back to 7 ahead), `store/pg.rs::maintain_partitions` (create daily + drop partitions older than 30 days) |
| 5 | ⑤ §8.1 `before_ts` lookup cost; ⑥ §3.1 note score=seq | `admin::queue_purge` (`pg::message_times` lookup + batched `ZREM`, `scope` covering user/device/topic) |
| 6 | ② §3.3 reference changed to ⑤ §10; ⑤ §13 I7 | `proto/lattice.proto` fully rewritten per ⑤ §10; undefined messages marked `[provisional]` |
| 7 | ⑤ §8.2 `POST /v1/admin/users`, §2 "no self-service signup + first admin bootstrap", §12 count 35; ⑥ §9.1 **D17**; design Appendix A v0.7 | `store/pg.rs::{create_user (with explicit role), count_users}`, `admin::users_create`, `config.rs::AdminCfg::bootstrap_password`, `node.rs` startup bootstrap (create the account only with an empty DB + a configured password; without a password only warn) |
| 8 | ⑤ §1.1 login response adds `device:{id, fingerprint}` + "must read" note; ⑥ §9.1 **D18**; design Appendix A v0.8 | `transport/http.rs::login` returns `device.id`/`device.fingerprint` (when the server generates the fingerprint the client has no other way to learn it, and WS `hello` would always `AUTH_FAIL`) |

## Problems only real runs expose (end-to-end smoke fixes)

The 7 bugs below **exist even when all unit tests are green**; only really starting PG/Redis/MinIO and running migrations and requests exposes them:

| # | Symptom | Root cause | Location |
| --- | --- | --- | --- |
| R1 | Startup fails with `Internal + details.dep=pg`; the connection pool cannot establish a single connection | `after_connect` packs two `SET` statements into one `query()`, and PG rejects multiple commands in a prepared statement (`cannot insert multiple commands into a prepared statement`) | `store/pg.rs` (changed to per-statement `execute`) |
| R2 | Startup migration reports `syntax error at or near "$"` | the second `DO` block was written as `do $ ... end $;` (single dollar sign, should be `$`) | `migrations/0003_audit_metrics.sql` |
| R3 | `POST /v1/messages` returns 500 | `message_dedup`'s `expires_at` is bound to `$3` (actually `sender`, text) → text cannot go into `timestamptz`; should be `$11` | `store/pg.rs::insert_message` |
| R4 | WS `hello` always returns `AUTH_FAIL: device fingerprint mismatch`, while HTTP is fine | ⑤ §1.1's `device_fp` is an optional request field: when omitted the server generates `sha256:<ulid>` and persists it, but the response never returns it — the client can never learn the fingerprint, while `hello.device_fp` must match the stored one (`auth.fingerprint_required=true`). The login response now includes `device:{id, fingerprint}` (⑥ D18 / ⑤ §1.1 v0.8) | `transport/http.rs::login` |
| R5 | The `minio` container stays `health: starting` forever and `minio-init` never starts → **the three buckets are never created and the upload path is completely unusable** | the `minio/minio:RELEASE.*` image has **no `mc`** (only `curl`), while the healthcheck uses `["CMD","mc","ready","local"]`, so every exec fails with `executable file not found` | `deploy/compose/dev.yaml` (healthcheck changed to `curl -f http://127.0.0.1:9000/minio/health/live`); later changed further to node-created buckets and removed `minio-init` (see R8) |
| R6 | `/v1/messages` over the limit returns axum's plain-text `Failed to buffer the request body: length limit exceeded`, with no `code`/`hint` | `DefaultBodyLimit` rejects at the **extractor stage**, so `pipeline::validate`'s threshold check never runs; but ⑤ §4 requires `413 TOO_LARGE` + `details.hint=use_ws_or_chunk`, and without the hint the client cannot programmatically decide to switch to WS/chunking | `transport/http.rs` (new `messages_body_guard`: read `Content-Length` before buffering and respond per the contract; `DefaultBodyLimit` kept as a fallback for chunked bodies with no length) |
| R7 | After a slow consumer fills the 256-frame queue, **the metric `lattice_backpressure_dropped_total` stays at 0**, so no drops are visible in monitoring | ⑤ §9.5 requires drop counting, but the metric was incremented only on the `crossnode` (`route`) and `stream-data` branches; **the main downstream path `Hub::try_send` only logged `debug!`**. The unit test `exposes_documented_metric_names` called `inc()` once manually, which "proved" the metric existed and conveniently hid that the production path never called it — only a real 420×16KiB run dropping 152 frames exposed it | `state.rs` (`Hub` gains `set_metrics` to inject `Arc<Metrics>`, incrementing under a `<cmd>` label on drop; `node.rs` adjusted construction order); **remaining deviation**: when the queue is full an `error{code=RATE}` frame cannot be enqueued either, so no error frame is returned; noted in ⑤ §9.5 and ⑥ D20 |

| R8 | Bucket creation depended on a one-shot container: once `minio-init` fails to start (as in R5), **the three buckets never exist**, yet the node reports `ready` as usual | Bucket creation lived outside "the system that uses the buckets" (the `minio/mc` container's `mc mb`). If the node does not know whether the buckets it needs are ready, it cannot prove its own availability — the failure only surfaces as a 403 on the first upload. Changed to idempotent bucket creation at node startup: `PUT` when `HEAD` is missing, treat `409 BucketAlreadyOwnedByYou` as success, 3 retries at 3s each, and on failure only warn without blocking startup (the message path does not depend on S3). Uses only `tokio::net::TcpStream` + SigV4 header signing, adding no new dependency; therefore `https://` endpoints explicitly cannot create buckets (TLS is terminated by a front proxy) | `store/s3.rs::ensure_buckets`; `node.rs` startup sequence; `deploy/compose/dev.yaml` drops the `minio-init` service (② §7.2 now notes the implementation caveat) |
| R9 | Startup log `partition "messages_y2027m02" would overlap partition "messages_y2027m01"`, new month partitions cannot be created → **after a month rollover messages cannot be inserted** | `maintain_partitions` computes the lower bound with `to_date(substring('{part}' from 'y(\d{4})m(\d{2})'), 'YYYYMM')`, but PostgreSQL's `substring(x from pattern)` **returns only the first capture group**: the measured result is `2027` (month lost), `to_date('2027','YYYYMM')` yields `2027-01-01`, so every new range becomes `[January, February)`. Migration `0002` pre-created `m09…m01` with the correct form, while `create table if not exists` skips an existing partition without validating its bound, so **only a cross-month addition exposes it** | `store/pg.rs::maintain_partitions` (bounds now given directly by SQL as `m::text` / `(m + interval '1 month')::date::text`, matching the migration form); ⑥ §9.1 D21 |

| R10 | **Every paginated list page** in the console (users/conversations/messages/dead letters/audit) fails to load and shows only `[INTERNAL] Failed to deserialize query string: invalid type: string "1", expected i64` | Admin-plane search endpoints reuse pagination via `#[serde(flatten)] PageQuery`, and `flatten` forces serde to collect into a map first — on that path `serde_urlencoded` hands every query value to the field as `&str`, so `i64` reports `invalid type: string "1", expected i64`; axum's `Query` rejects with a **plain-text 400**, losing the whole contract error body (`code`/`details`/`trace_id`). **Without** `page/page_size` the fields use defaults and the request succeeds with 200, so unit tests and smoke scripts (which only tested forms without pagination) all passed | `transport/http.rs`: `PageQuery`'s integer columns now use `deserialize_with = "de_i64_lenient"` (accepting integers and numeric strings); a new `Q<T>` extractor replaces `Query<T>` on the admin plane (invalid parameters return `422 FORMAT` + `details.reason=query`); added regression unit tests `transport::http::query_params::*` (4 of them). ⑤ §0.4 / ② §3.1 / ⑥ §9.1 D22 |

| R11 | The console's "server nodes" table always shows "health=unknown / last heartbeat=—"; overview numbers lag by up to 15 seconds (15s polling); after 100 console opens on the same node SSE returns `429` forever | ① The node heartbeat `lattice:node:{id}` JSON has no `health`/`heartbeat_at` at all, and Redis TTL can only derive "how many seconds remain", not an absolute time; ② `admin::stream` computed data inside each **connection's** `unfold` (`SCAN` Redis for nodes, `select 1` to probe PG), so the cadence could not be increased and the page had to run separate polling; ③ `lattice_sse_connections` only had `inc()` and no `dec()`, so the count only grew, and after 100 connections `sse_max_connections` permanently considered the limit reached. All three only surface when **the console is really opened**: endpoint unit tests only check "the field exists", not "whether the value changes with connections" | New `crates/lattice-node/src/live.rs`: **one** background task refreshes three `RwLock<Value>` snapshots `online`/`nodes`/`deps` at 1s/2s/5s, and SSE connections only read snapshots (`admin::stream` slimmed down to serialization); `SseGuard` rides on the stream's carried state and calls `dec()` on `Drop`; `state::heartbeat` gains `health`/`heartbeat_at`, and `live::nodes_from_rows` falls back for old heartbeats missing fields; `online` and `GET /v1/admin/online/stats` share `live::online_payload` (previously each computed its own). Frontend `useSse` adds backoff reconnect (1s→30s), and the overview page drops the 15s timer and the "refresh data" button. Measured: `scripts/stream-verify.ps1` (8 online / 4 node / 2 deps, count 0→1→0), `scripts/realtime-verify.ps1` (with WS connected the push shows `online_devices=1`, back to 0 after disconnect). ⑤ §8.5 / ⑥ §9.1 D23 |

There are also three **deployment/environment** pitfalls: `minio/minio:latest` has no such tag in some environments, so `compose up` hangs on the pull
(pinned to `RELEASE.2023-03-20T20-16-18Z`); the `-1` suffix that compose appends automatically makes container names mismatch the docs/scripts
(explicit `container_name` is now set for each service); running the node on the host requires overriding the container hostnames (see "Build and run").

## One known unwired area

The three transports `grpc/mqtt/quic` are **skeletons** (config exists, contract constants exist, tests exist, but they do not listen on ports) —
per ② §12 they land in P2/P3/P4 respectively and do not block the P0/P1 REST + WS main path.
