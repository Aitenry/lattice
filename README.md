# Lattice

A unified message transport platform: multi-protocol ingress, all-format messages, offline redelivery, and high-availability deployment.

Lattice is a single-binary Rust platform node, a React administration console, and a set of deployment assets for local development and production-style environments.

Current design version: **v0.19** draft (the design, platform API, and database documents share this version).

## Architecture

```
 Desktop / web / device clients
              │
              │  REST · WebSocket · gRPC · MQTT · QUIC · WebTransport
              ▼
   ┌──────────────────────────────────────────────┐
   │                 lattice-node                 │
   │  ingress → pipeline → routing → storage      │
   └───────┬───────────────┬──────────────┬───────┘
           │               │              │
      PostgreSQL      Redis / NATS      MinIO
```

The node handles protocol ingress, validation, deduplication, persistence, online and offline routing, media signalling, the plugin runtime, the admin API, and observability. PostgreSQL is the durable store, Redis provides hot state and the default pub/sub path, NATS JetStream is the optional primary bus, and MinIO stores large objects, media segments, and plugin packages.

## Capabilities

- **Multi-protocol ingress**: REST, WebSocket (same-port upgrade), gRPC, MQTT (TLS/mTLS, QoS 2, wildcards, shared subscriptions), QUIC, and WebTransport over HTTP/3.
- **Message pipeline**: deduplication and idempotency, chunked large files into object storage, online routing with multi-device delivery, offline queue redelivery with reconciliation.
- **Format adaptation**: a plugin system with built-in conversion and an optional WASM host; plugin packages are signature-verifiable and versioned.
- **HA download transfer plane**: plugin packages, source archives, large messages, chunks, and recording segments are delivered through a stateless `lattice-transfer` service behind a short-lived HMAC capability URL. The node signs and redirects but never proxies object bytes, and clients never need to reach MinIO (`Range`/resume, multi-endpoint failover, horizontal scaling).
- **Bus and broadcast**: Redis Pub/Sub by default; NATS JetStream can be enabled as the primary bus, with automatic fallback when NATS is unavailable.
- **Media plane**: stream signalling, WebSocket tunnel fallback, TURN credential issuing, and optional recording tee into MinIO.
- **Security**: RS256 access tokens, dual-key overlap rotation, device fingerprints, role-based access control, and a zero-knowledge policy mode. Inspectable mode must be enabled explicitly.
- **Observability**: Prometheus metrics, Grafana dashboards, alert rules, and optional OTLP/gRPC tracing.

## Repository layout

```
crates/
  lattice-node/       Platform node: ingress, pipeline, routing, storage, media, admin API
                      (also builds `lattice-transfer`, the stateless download data plane)
  lattice-core/       Shared types: envelope, frame, IDs, keys, protocol constants
  lattice-plugins/    Format-adaptation plugins and the optional WASM host
web/                  Admin console (Vite + React + TypeScript + Ant Design, English/Chinese)
deploy/               Dockerfiles, compose stacks, Helm chart, production templates, observability assets
openapi/              OpenAPI 3.1 contract for REST, WebSocket, and SSE
proto/                Internal gRPC contract
.github/workflows/    CI for Rust, web, Helm, and observability assets
```

## Requirements

- Stable Rust toolchain (edition 2021).
- Node.js 22 and npm 10 for the console.
- Docker Engine with Compose v2 for the development stack.
- Helm 3 and Python 3 only when working with the deployment chart and observability assets.

## Quick start

### Full development stack

The node image is built offline from a generated vendor tree. On a fresh checkout, create it once:

```bash
cargo vendor cargo-vendor2
```

This step needs network access or a populated Cargo cache. Then start the stack:

```bash
docker compose -f deploy/compose/dev.yaml up -d --build
```

| Entry point | Address |
| --- | --- |
| Console (nginx proxying `/v1` and `/t`, the transfer plane) | http://127.0.0.1:8088 |
| Node REST and WebSocket | http://127.0.0.1:8080 |
| Transfer plane (direct, for debugging) | http://127.0.0.1:8090 |
| MinIO console | http://127.0.0.1:9001 |
| Prometheus metrics (node / transfer) | http://127.0.0.1:9100/metrics, http://127.0.0.1:9101/metrics |
| MQTT gateway | `127.0.0.1:1883` |
| NATS client and monitoring | `127.0.0.1:4222`, http://127.0.0.1:8222/healthz |

Health checks: `GET /v1/health` and `GET /v1/ready` (node), `GET /healthz` and `GET /readyz` (transfer plane).

Download endpoints (`/v1/hub/.../download`, large messages, chunks, recordings) answer `302 /t/{token}` (same-origin relative; or an absolute `{transfer.public_base_url}/t/{token}` when configured); the transfer service streams the object with `Range` support. With `[transfer] enabled=false` the legacy MinIO presigned redirect is kept.

The development stack creates an administrator account on first start. The local default is `admin` / `lattice_dev_admin_pw`, defined in `deploy/config/dev.toml`. It is a local development credential only: set a different bootstrap password and rotate it before exposing any environment.

### Run the node on the host

```bash
# Middleware only
docker compose -f deploy/compose/dev.yaml up -d pg redis minio

# The node's dev configuration uses compose service names, so point it at localhost
export LATTICE__PG__URL='postgres://lattice_app:lattice_dev_pw@127.0.0.1:5432/lattice?sslmode=disable'
export LATTICE__REDIS__URL='redis://127.0.0.1:6379'
export LATTICE__S3__ENDPOINT='http://127.0.0.1:9000'
export LATTICE__AUTH__KEY_DIR="$PWD/.dev/keys"

cargo run -p lattice-node -- --config deploy/config/dev.toml

# The transfer plane is a separate, stateless process (same crate/image)
cargo run -p lattice-node --bin lattice-transfer -- --config deploy/config/dev.toml
```

`[transfer] public_base_url` in `dev.toml` is empty, so download endpoints emit a same-origin relative `/t/{token}` and the client resolves it against the console origin. Set `LATTICE__TRANSFER__PUBLIC_BASE_URL` only when the transfer service is reached on a different origin; when running the transfer binary directly behind no proxy, point it at `http://127.0.0.1:8090`.

The key directory is created on first start and receives an RS256 key pair. In production, mount the key pair from a secret store instead of generating it in the container.

### Console development

```bash
cd web
npm ci
npm run dev
```

The dev server proxies `/v1` to `http://127.0.0.1:8080`. Override the target with `VITE_API_TARGET`; see `web/.env.example`.

The console ships with English as the source language and a Simplified Chinese overlay. The language and theme choices are persisted in `localStorage`.

## Build and test

```bash
cargo check --workspace --all-targets
cargo test --workspace

cd web
npm ci
npm run build
npm run verify
```

`npm run verify` runs the TypeScript check and the production build without writing outside the web workspace.

Optional node features are disabled by default:

| Feature | Effect |
| --- | --- |
| `quic` | QUIC proxy and relay |
| `webtransport` | WebTransport gateway; requires `quic` |
| `wasm-host` | WASM plugin host |
| `otel` | OTLP/gRPC trace export |

```bash
cargo build -p lattice-node --features quic,webtransport
```

## Configuration

The node reads a TOML file from `--config` or `LATTICE_CONFIG`, then applies environment overrides in the form `LATTICE__{SECTION}__{FIELD}`. Environment variables take precedence and are the supported way to inject production secrets.

- Development defaults: `deploy/config/dev.toml`
- Production template: `deploy/production/config/production.toml.example`
- Database migrations: embedded in `crates/lattice-node/migrations/` and applied at startup under a lock

## Deployment

- `deploy/compose/dev.yaml`: single-host development stack with PostgreSQL, Redis, MinIO, NATS, node, and web, plus an optional TURN profile.
- `deploy/compose/ha-dev.yaml`: multi-node development stack behind a load balancer for failover drills.
- `deploy/helm/lattice`: Helm chart with autoscaling, disruption budget, network policy, ingress, backup, point-in-time recovery, and optional canary release.
- `deploy/production/`: component-level templates for Patroni and etcd, NATS JetStream, Redis Sentinel, MinIO erasure coding, TLS, backup, and recovery.
- `deploy/observability/`: Prometheus scrape configuration, alert rules, and Grafana dashboards.
- Images: `deploy/Dockerfile.node` and `deploy/Dockerfile.web`.

The production templates in `deploy/production/` are infrastructure starting points, not a turnkey cluster. They are intentionally explicit about which topology properties and drills still require validation in the target environment.

## API contracts

- `openapi/lattice.openapi.yaml`: REST, WebSocket, and SSE contract, including MQTT and gRPC boundary registrations.
- `proto/lattice.proto`: internal node-to-node gRPC contract.
- `openapi/README.md`: artifact scope, coverage, conventions, and validation notes.
- `web/README.md`: console architecture, page-to-API mapping, and UI conventions.
- `crates/README.md`: backend crate layout, run instructions, and testing notes.

## Security model

- The default policy is **zero-knowledge**: the service does not decrypt or parse message payloads. Content inspection requires an explicit `inspectable` deployment mode.
- Access tokens are RS256 JWTs. Refresh tokens are rotating and stored only as hashes. Signing keys support a dual-key overlap window during rotation.
- Roles are `admin`, `ops`, and `user`. The least-privileged `user` role is scoped to its own profile, devices, conversations, messages, topics, and plugin submissions.
- A user-published plugin becomes visible to others only after an administrator approves it. Approved versions are immutable; changes require a new reviewed version.
- Secrets belong in environment variables or a secret manager, never in a TOML file, ConfigMap, image, or log.

## License

MIT. See [LICENSE](LICENSE).
