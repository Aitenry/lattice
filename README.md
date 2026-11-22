# Lattice

A unified message transport platform: multi-protocol ingress, all-format messages, offline redelivery, and high-availability deployment.

Lattice consists of three parts: a single-binary Rust platform node, a React admin console, and a set of deployment assets that can go straight to production.

## Capabilities

- **Multi-protocol ingress**: REST, WebSocket (same-port upgrade), gRPC, MQTT (TLS/mTLS, QoS2, wildcards and shared subscriptions), QUIC, WebTransport (HTTP/3)
- **Message pipeline**: dedup and idempotency, chunked large files into object storage, online routing with multi-device delivery, offline queue redelivery with reconciliation
- **Format adaptation**: plugin system (built-in conversion plus an optional WASM host, Ed25519 signature verification)
- **Bus and broadcast**: Redis Pub/Sub as the default path, NATS JetStream as the primary path, automatic fallback on failure
- **Media plane**: media signalling, WS tunnel, TURN credentials, recording tee (segmented into MinIO)
- **Security**: RS256 JWT, dual-key overlap rotation, device fingerprints, RBAC, zero-knowledge policy mode (inspectable mode must be enabled explicitly)
- **Observability**: Prometheus metrics, Grafana dashboards, alert rules, OTLP/gRPC tracing (optional feature)

## Repository layout

```
crates/
  lattice-node/       Platform node: ingress + message pipeline + online routing + storage + media + admin API
  lattice-core/       Cross-module types: envelope, frame, IDs, keys
  lattice-plugins/    Format-adaptation plugins and the optional WASM host
web/                  Admin console (Vite + React + TypeScript + Ant Design, bilingual English/Chinese)
deploy/               Dockerfiles, compose (dev / ha), Helm chart, production components, observability assets
openapi/              OpenAPI 3.1 contract for REST / WS / SSE
proto/                gRPC contract
.github/workflows/    CI (rust / web / helm / observability)
```

## Quick start

### Full dev stack (Docker)

```bash
docker compose -f deploy/compose/dev.yaml up -d --build
```

| Entry point | Address |
| --- | --- |
| Console (nginx proxying `/v1`) | http://127.0.0.1:8088 |
| Node REST / WS | http://127.0.0.1:8080 |
| MinIO console | http://127.0.0.1:9001 |
| Prometheus metrics | http://127.0.0.1:9100/metrics |

Health checks: `GET /v1/health`, `GET /v1/ready`.

Default administrator: `admin` / `lattice_dev_admin_pw` (see `deploy/config/dev.toml`; **dev only**, in production the secret is injected and rotated right after the first start).

### Run the node locally

```bash
# middleware only
docker compose -f deploy/compose/dev.yaml up -d pg redis minio

# node: dev.toml uses container service names, so override the hosts when running on the host
cargo run -p lattice-node -- --config deploy/config/dev.toml
```

Configuration sources: `--config` or `LATTICE_CONFIG` points at a TOML file; production overrides go through `LATTICE__{SECTION}__{FIELD}` environment variables.

### Console development

```bash
cd web
npm ci
npm run dev      # the /v1 proxy target is VITE_API_TARGET, see web/.env.example
```

The console ships with English (default) and Simplified Chinese; the switch lives in the header and the choice is persisted in `localStorage`.

## Build and checks

```bash
cargo check --workspace --all-targets
cargo test --workspace

cd web && npm ci && npm run build
```

Optional features are off by default; enable them explicitly:

| feature | Effect |
| --- | --- |
| `quic` | QUIC proxy skeleton |
| `webtransport` | WebTransport (HTTP/3) gateway (requires `quic`) |
| `wasm-host` | WASM plugin host |
| `otel` | OTLP/gRPC trace export |

```bash
cargo build -p lattice-node --features quic,webtransport
```

## Deployment

- `deploy/compose/dev.yaml`: single-host dev stack (pg / redis / minio / nats / node / web, optional turn)
- `deploy/compose/ha-dev.yaml`: HA drill stack (multiple nodes behind a load balancer)
- `deploy/helm/lattice`: production Helm chart (HPA / PDB / NetworkPolicy / Ingress / backup / PITR / canary)
- `deploy/production/`: component-level rollout for Patroni + etcd, NATS, Redis Sentinel/HA, MinIO, TLS, backup and restore
- Images: `deploy/Dockerfile.node`, `deploy/Dockerfile.web`

## API contracts

- `openapi/lattice.openapi.yaml`: REST / WebSocket / SSE
- `proto/lattice.proto`: node-internal gRPC

## Notes

This repository contains the product code and deployment assets only; design documents, end-to-end/drill/load-test scripts and their reports live outside this repository.

## License

MIT, see [LICENSE](LICENSE).
