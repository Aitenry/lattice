# Backend crates

The Rust workspace behind the Lattice platform node. It builds two binaries from the `lattice-node` package: `lattice-node`, which exposes the message API, the admin API, the WebSocket, MQTT, gRPC, QUIC, and WebTransport listeners and owns the pipeline that turns an inbound frame into a persisted, routed message, and `lattice-transfer`, the stateless download data plane (capability-token verified streaming from object storage).

## Workspace layout

```
crates/
  lattice-core/       Types shared by every layer (no I/O)
  lattice-plugins/    Format-plugin registry, sidecar client, optional WASM host
  lattice-node/       The platform node binary/runtime plus the `lattice-transfer` data-plane binary
```

| Crate | Responsibility | Main modules |
| --- | --- | --- |
| `lattice-core` | Envelope and frame definitions, protocol constants, IDs, key material, error types | `envelope`, `frame`, `protocol`, `ids`, `keys`, `error` |
| `lattice-plugins` | Plugin manifest and limits, sidecar transport, WASM runtime | `manifest`, `registry`, `sidecar`, `wasm`, `limits` |
| `lattice-node` | Ingress, pipeline, routing, storage, admin API, media plane, jobs, degradation | see below |

### Node modules

| Module | Role |
| --- | --- |
| `transport/` | HTTP and admin routes, WebSocket frames, MQTT gateway, internal gRPC, QUIC, WebTransport |
| `pipeline/` | Validation, policy, format detection, deduplication, chunking, encryption, inspectable mode, WAL fallback |
| `routing/` | Online delivery, offline pending queues, topics, sequence watermarks, cross-node forwarding, media signalling and recording, audit export |
| `store/` | PostgreSQL, Redis, S3, NATS, and local WAL backends |
| `auth/` | JWT issuing and rotation, password hashing, device fingerprints, RBAC |
| `admin/` | Operator endpoints for users, devices, queues, nodes, audit, config, keys, plugins, and the plugin review plane |
| `hub.rs` | User-facing plugin catalog, publishing, downloads, install records, and review workflow |
| `transfer/` | Download transfer plane: capability tokens, streaming S3 reads with `Range`/failover, the `/t/{token}` HTTP server and its metrics; `src/bin/lattice-transfer.rs` is the standalone entry point |
| `live.rs` | Shared snapshots for the console's SSE stream |
| `jobs.rs`, `maintenance/` | Partition maintenance, cleanup, retention, and periodic reconciliation |
| `degrade.rs` | Dependency-health probes and degradation decisions |
| `observe/` | Prometheus metrics and optional OTLP tracing |
| `config.rs` | TOML loading, defaults, environment overrides, and the embedded sample configuration |

## Build and run

```bash
# Fast feedback
cargo check --workspace --all-targets
cargo test --workspace

# Run the node against the local development stack
docker compose -f deploy/compose/dev.yaml up -d pg redis minio
export LATTICE__PG__URL='postgres://lattice_app:lattice_dev_pw@127.0.0.1:5432/lattice?sslmode=disable'
export LATTICE__REDIS__URL='redis://127.0.0.1:6379'
export LATTICE__S3__ENDPOINT='http://127.0.0.1:9000'
export LATTICE__AUTH__KEY_DIR="$PWD/.dev/keys"
cargo run -p lattice-node -- --config deploy/config/dev.toml

# Stateless download data plane (same config; separate process, scale independently)
cargo run -p lattice-node --bin lattice-transfer -- --config deploy/config/dev.toml
```

`dev.toml` uses the compose service names `pg`, `redis`, and `minio`; the overrides above are required when the node runs directly on the host. Add `LATTICE__TRANSFER__PUBLIC_BASE_URL` when the transfer service is reached on a different origin than the console. The key directory is created automatically and receives an RS256 key pair on first start. Production deployments must mount the key pair from a secret store.

### Download transfer plane

Download endpoints answer `302 /t/{token}` (same-origin relative when `[transfer] public_base_url` is empty) or `302 {transfer.public_base_url}/t/{token}` when an absolute base is configured; the token is a short-lived HMAC capability for exactly one object, and `lattice-transfer` streams it from the internal `[s3] endpoint` (with `[s3] endpoints` failover). The node only signs; it neither proxies object bytes nor exposes the object store to clients. With `enabled = false` the legacy MinIO presigned redirect is kept, so the switch is also the rollback lever. Token lifetime, secret length, timeouts, cache policy, and failure mappings are centralized in design doc §17.17; the contract is doc ⑤ §12.9.

### Configuration

The node reads a TOML file from `--config` or `LATTICE_CONFIG`, then applies `LATTICE__{SECTION}__{FIELD}` environment overrides. Environment variables are authoritative and are the supported way to inject production secrets. `lattice-transfer` reads the same file and uses `[transfer]` (secret/listen/limits) plus `[s3]`.

`deploy/config/dev.toml` mirrors the compile-time sample configuration in `config.rs`; keep the two in sync when adding a setting. Migrations are embedded from `crates/lattice-node/migrations/` by `sqlx::migrate!` and applied at startup under an advisory lock.

### Optional features

| Feature | Enables | Notes |
| --- | --- | --- |
| `quic` | QUIC listener and proxy relay | Off by default; pulls in `quinn` and `rcgen` |
| `webtransport` | WebTransport gateway over HTTP/3 | Implies `quic`; bridges browser streams to the QUIC listener |
| `wasm-host` | WASM plugin runtime | Off by default; the host is usable, request-path integration is limited |
| `otel` | OTLP/gRPC trace export | Off by default; no global tracer is registered without it |

```bash
cargo build -p lattice-node --features quic,webtransport
```

### Internal gRPC code generation

`build.rs` compiles `proto/lattice.proto` with a vendored `protoc`, so no system protobuf compiler is required. Generated stubs live in `OUT_DIR` and are not committed.

## Protocol surface

- **REST and SSE**: `/v1/*`, described by `openapi/lattice.openapi.yaml`.
- **WebSocket**: `GET /v1/ws`, with a length-prefixed binary frame protocol shared through `lattice-core::frame`.
- **MQTT**: a 3.1.1/5 subset with PSK or password authentication, topic mapping, QoS handling, wildcard and shared subscriptions, and per-device rate limiting.
- **gRPC**: an internal `NodeInternal` service for cross-node route relay, chunk retrieval, heartbeat, and sequence-watermark sync.
- **QUIC and WebTransport**: optional media relay paths behind the `quic` and `webtransport` features.
- **Transfer plane**: `GET|HEAD /t/{token}` on `lattice-transfer` (plus `/healthz`, `/readyz`, `/metrics`), a stateless capability-token download data plane outside the `/v1` business API.

## Testing

- Unit tests live beside the modules they cover; run them with `cargo test --workspace`.
- Integration and end-to-end drills use the compose stacks under `deploy/compose/` and the deployment assets under `deploy/production/`.
- The CI workflow runs the Rust build and tests, the web build, Helm rendering validation, and observability asset checks.

## Known boundaries

- QUIC, WebTransport, and the WASM host are optional, feature-gated paths; the default build does not compile them.
- The node's PostgreSQL, Redis, and NATS clients use a single endpoint; high availability must be provided by a stable address in front of each dependency (VIP, load balancer, or DNS). S3 reads additionally accept `[s3] endpoints` for transfer-plane failover, but uploads still target the single `[s3] endpoint`.
- Uploads are not part of the transfer plane yet: large multipart part URLs remain presigned object-storage URLs, and `[s3] public_endpoint` must stay client-reachable for that path.
- Production HA assets under `deploy/production/` are templates. Cluster-level failover, multi-host networking, and cloud-specific load balancing require validation in the target environment.
