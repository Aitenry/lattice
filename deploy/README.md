# Lattice deployment

Deployment assets for Lattice: a single-host Docker Compose stack for development, the node and web image build recipes, a Helm chart, production component templates, and observability assets.

## Quick start

```bash
docker compose -f deploy/compose/dev.yaml up -d --build
```

Compose encodes the start order: `pg`, `redis`, and `minio` become healthy first, then `node` and `transfer`, then `web` (nginx resolves the transfer upstream at start, so the web container waits for it). Container names are fixed (`lattice-dev-pg`, `lattice-dev-redis`, `lattice-dev-minio`, `lattice-dev-node`, `lattice-dev-transfer`, `lattice-dev-web`, `lattice-dev-nats`) so Compose does not append a `-1` suffix.

## Entry points

| Entry point | Description |
|---|---|
| http://127.0.0.1:8088 | Web console: nginx serves the frontend and reverse-proxies `/v1` to the node (including the WebSocket upgrade) and `/t/` to the transfer plane |
| http://127.0.0.1:8080 | Node directly, for debugging and smoke checks (internal gRPC is `127.0.0.1:9090`, plaintext in development) |
| http://127.0.0.1:8090 | Transfer plane directly (download data plane; clients normally use `/t/...` through port 8088) |
| http://127.0.0.1:9000, http://127.0.0.1:9001 | MinIO S3 API and console (`lattice_dev` / `lattice_dev_secret`) |
| `127.0.0.1:1883` | MQTT gateway (plaintext in development; TLS is terminated by a front proxy in production) |
| http://127.0.0.1:9100/metrics, http://127.0.0.1:9101/metrics | Prometheus scrape endpoints (node / transfer plane; unauthenticated, read-only) |
| `127.0.0.1:4222`, http://127.0.0.1:8222/healthz | NATS client (JetStream; used when `[bus] kind = "nats"`) and monitoring endpoint |

Node health endpoints are `GET /v1/health` and `GET /v1/ready`; transfer-plane health endpoints are `GET /healthz` and `GET /readyz`, and its metrics are on `/metrics`.

**Downloads go through the transfer plane (v0.19).** Every download endpoint (`/v1/hub/.../download`, `/v1/hub/.../source`, large messages, chunk `presigned_url`, recording detail/download) answers `302 /t/{token}` (same-origin relative) or `302 {transfer.public_base_url}/t/{token}` when an absolute base is configured, with a short-lived HMAC capability token. `lattice-transfer` verifies the token and streams the object from the **in-network** `[s3] endpoint`; clients never resolve or reach MinIO, and the node never proxies bytes. The service is stateless, so replicas can be scaled independently (`Range`/resume, `ETag`/304, `[s3] endpoints` failover, `/readyz` readiness). The relative form is deliberate: a LAN or desktop client resolves it against the host it already used, so no deployment hostname (and never `127.0.0.1`) is baked into a capability URL.

Set `[transfer] enabled = false` to fall back to the legacy `302 → MinIO presigned URL` path. Only in that legacy mode does `[s3] public_endpoint` matter: it is the client-facing host baked into presigned URLs, while `[s3] endpoint` is the node's in-network address. With the transfer plane enabled, `public_endpoint` is unused for downloads, but it is still the host of upload part URLs (large uploads remain direct-to-object-storage in this version).

## Images

| Dockerfile | Artifact | Build stage → runtime stage |
|---|---|---|
| [`Dockerfile.node`](Dockerfile.node) | `lattice-node:dev` | `node:22-bookworm` with a minimal stable Rust toolchain → `debian:bookworm-slim`; enables the `quic`, `webtransport`, and `wasm-host` features; builds **both** `lattice-node` and `lattice-transfer` (`--bins`); runs as UID 10001; exposes 8080/tcp, 9090/tcp, 8090/tcp (transfer), 9101/tcp (transfer metrics), and 4433/udp |
| [`Dockerfile.web`](Dockerfile.web) | `lattice-web:dev` | `node:22-alpine` → `nginx:latest` |

## Node image build notes

The image build does not reach crates.io: [`cargo-vendor.toml`](cargo-vendor.toml) replaces `crates-io` with `vendored-sources` and sets `offline = true`, and [`Dockerfile.node`](Dockerfile.node) copies a generated vendor tree from `cargo-vendor2/` into `/src/vendor`. That directory is git-ignored, so generate it once before the first build:

```bash
# run once, with network access or a populated Cargo cache
cargo vendor cargo-vendor2
```

The tree is named `cargo-vendor2/` rather than `vendor/` so the Docker build context always uses a freshly generated copy. Three details matter when changing the build recipes:

- The build stage installs a minimal Rust toolchain from the Tsinghua mirror (`RUSTUP_DIST_SERVER` and `RUSTUP_UPDATE_ROOT`); no Rust base image is used.
- For build outputs, `.dockerignore` excludes only the repository-root `/target`, not every `target` directory: vendored crates may ship their own `src/target/` directories, and excluding those breaks checksum verification during `cargo build`.
- The release build disables LTO with `CARGO_PROFILE_RELEASE_LTO=false` and mounts a BuildKit cache on `target`, so an interrupted build can resume.

## Alignment with the development configuration

[`config/dev.toml`](config/dev.toml) is copied into the node image as `/etc/lattice/config.toml`, so container hostnames work directly:

- `[pg] url = "postgres://lattice_app:lattice_dev_pw@pg:5432/lattice?sslmode=disable"`
- `[redis] url = "redis://redis:6379"`
- `[s3] endpoint = "http://minio:9000"`, `access_key = "lattice_dev"`, `secret_key = "lattice_dev_secret"`
- buckets `lattice-large`, `lattice-media`, `lattice-cold`, and `lattice-plugins`; the node creates them from the four `bucket_*` names.
- `[transfer] enabled = true`, `public_base_url = ""` (empty = the node emits a same-origin relative `/t/{token}`; the console origin fronts `/t/`), `listen = "0.0.0.0:8090"`, `metrics_listen = "0.0.0.0:9101"`, and a **development-only** shared secret. The node signs with it and the `lattice-dev-transfer` container verifies with the same value.

Compose's `MINIO_ROOT_USER` and `MINIO_ROOT_PASSWORD` must match `[s3]` byte for byte, otherwise uploads fail with 403. Two settings are overridden in Compose:

| Item | Reason |
|---|---|
| `LATTICE__NODE__METRICS=0.0.0.0:9100` | `dev.toml` binds metrics to `127.0.0.1:9100`; in a container the listener must bind all interfaces to be scraped from the host |
| the `nodekeys` volume at `/etc/lattice/keys` | without it, every rebuild rotates the signing key and invalidates all issued tokens |

When running the node directly on the host the reverse applies: point `LATTICE__PG__URL`, `LATTICE__REDIS__URL`, and `LATTICE__S3__ENDPOINT` at `127.0.0.1`, and set `LATTICE__AUTH__KEY_DIR` to a local path such as `$PWD/.dev/keys`.

The node creates its own buckets: `crates/lattice-node/src/store/s3.rs::ensure_buckets()` performs an idempotent `HEAD` on the four buckets at startup and a `PUT` when one is missing. Failures are logged as warnings because the message plane does not depend on S3; only large uploads are affected. There is no one-shot `minio-init` container, which removes a startup dependency and the "bucket missing because init never ran" failure mode.

## Verification and common commands

```bash
# static configuration check (does not start anything)
docker compose -f deploy/compose/dev.yaml config --quiet

# running stack
docker compose -f deploy/compose/dev.yaml ps
curl -fsS http://127.0.0.1:8080/v1/health
curl -fsS http://127.0.0.1:8080/v1/ready
curl -fsS http://127.0.0.1:9100/metrics | head
curl -fsS http://127.0.0.1:8090/readyz
curl -fsS http://127.0.0.1:9101/metrics | head
# a download endpoint must redirect to the transfer plane (relative /t/{token});
# an invalid token must be 404, not 500
TOKEN=$(curl -fsS -X POST http://127.0.0.1:8088/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"lattice_dev_admin_pw"}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["access_jwt"])')
curl -s -D- -o /dev/null -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8088/v1/hub/plugins/task-planner/versions/0.1.1/download | grep -i '^location:'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8088/t/not-a-token   # 404
docker compose -f deploy/compose/dev.yaml logs node | grep -i 's3 bucket'

# rebuild the backend image only, then the whole stack; clean up with volumes
docker compose -f deploy/compose/dev.yaml build node
docker compose -f deploy/compose/dev.yaml up -d --build
docker compose -f deploy/compose/dev.yaml down -v
```

## Known limitations

- `lattice_backpressure_dropped_total` is a labelled counter vector and does not appear in `/v1/admin/metrics` until the first real drop; this is expected.
- The download transfer plane covers **downloads** only. Large-file/uploads multipart part URLs are still presigned object-storage URLs (`[s3] public_endpoint` must remain client-reachable for that path), and plugin publishing still goes through the node (`PUT .../blob`), so plugin publishing works without direct MinIO access.
- The transfer plane requires at least one `[s3] endpoint` that serves the same buckets from every candidate (`[s3] endpoints` are failover replicas/gateways, not different datasets).
- The `/etc/lattice/config.toml` baked into the node image is the development configuration. A production deployment must mount a different configuration and inject secrets through environment variables.
- [`Dockerfile.web`](Dockerfile.web) runs `npm install` from `web/package.json` before the lockfile is copied, so the console image is not pinned by `web/package-lock.json`.

## Bus switch: Redis Pub/Sub to NATS

The development default is Redis Pub/Sub. To use NATS JetStream, set `[bus] kind = "nats"` in [`config/dev.toml`](config/dev.toml) and rebuild the node image, or add `LATTICE__BUS__KIND=nats` and `LATTICE__BUS__NATS_URL=nats://127.0.0.1:4222` to the `node` service environment in [`compose/dev.yaml`](compose/dev.yaml) and restart the service. The NATS container is part of the default stack.

When the node starts against NATS it creates the four streams (`LATTICE_ROUTE`, `LATTICE_BROADCAST`, `LATTICE_AUDIT`, `LATTICE_MEDIA`) idempotently. Their replication factor is 1 unless they are pre-created with the production settings described in [`production/nats/README.md`](production/nats/README.md). When NATS is unavailable the node falls back to Redis Pub/Sub and then to paused broadcast, and logs a warning.

## TURN and QUIC UDP ingress

- TURN (coturn) is deployed separately; see [`coturn/README.md`](coturn/README.md) and [`coturn/turnserver.conf`](coturn/turnserver.conf). The development stack has a `turn` profile:

  ```bash
  docker compose -f deploy/compose/dev.yaml --profile turn up -d turn
  docker compose -f deploy/compose/dev.yaml --profile turn down turn
  ```

  Node-side settings are `[media] turn_uris`, `turn_secret`, and `turn_ttl`; the secret must come from a secret store or an environment variable.

- [`quic-lb-udp.yaml`](quic-lb-udp.yaml) sketches the Kubernetes UDP ingress for QUIC, WebTransport, and TURN: an NLB Service with `externalTrafficPolicy: Local` and client source-IP preservation. It defines the network shape only; the LB-to-node mapping and the node's optional `quic` feature still have to be configured for the target cluster.

## Production assets

Everything under [`production/`](production/README.md) is a set of copyable templates, not a running cluster. The assets have been reviewed statically (YAML/TOML structure, replica counts, ports, probes, secret placeholders, and erasure-coding parameters); they have not been validated on multi-host, load-balancer, or cloud infrastructure.

| Asset | Location |
|---|---|
| Production HA template (PostgreSQL/Patroni, Redis Sentinel, NATS JetStream, MinIO, etcd, RPO/RTO targets, runbooks, rollback) | [`production/README.md`](production/README.md) |
| Helm chart (TLS/mTLS mounts, NetworkPolicy, PDB, read-only root filesystem, PITR CronJob, canary) | [`helm/lattice/README.md`](helm/lattice/README.md) |
| TLS/mTLS certificate system (cert-manager, sealed-secrets, Secret key contract, rotation) | [`production/tls/README.md`](production/tls/README.md) |
| Patroni/etcd templates and failover runbook | [`production/patroni/README.md`](production/patroni/README.md) |
| Backup/PITR templates (three backup layers, retention, encryption, archive verification) | [`production/backup/README.md`](production/backup/README.md) |
| Prometheus rules, scrape configuration, and Grafana dashboard | [`observability/README.md`](observability/README.md) |

```bash
# static checks that need no cluster
docker compose -f deploy/compose/dev.yaml config --quiet
docker compose -f deploy/compose/ha-dev.yaml config --quiet
helm lint deploy/helm/lattice
helm template lattice deploy/helm/lattice --namespace lattice > /dev/null
```
