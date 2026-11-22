# Lattice deployment (web + node in one compose)

Build and start the full stack with one command:

````powershell
docker compose -f deploy/compose/dev.yaml up -d --build
```

| Entry point | Description |
|---|---|
| http://127.0.0.1:8088 | **web** (nginx serves the frontend, `/v1` reverse-proxied to node; includes WS upgrade) |
| http://127.0.0.1:8080 | **node** directly (for debugging / smoke scripts) |
| http://127.0.0.1:9000 | MinIO S3 API |
| http://127.0.0.1:9001 | MinIO console (`lattice_dev` / `lattice_dev_secret`) |
| `127.0.0.1:1883` | MQTT gateway (P3; plaintext in dev, TLS via a front proxy in production) |
| http://127.0.0.1:9100/metrics | Prometheus scrape endpoint (unauthenticated, read-only) |
| `127.0.0.1:4222` | NATS client (JetStream; used when `[bus] kind=nats`) |
| http://127.0.0.1:8222/healthz | NATS monitoring endpoint |

> **The Host of presigned downloads must be reachable by browsers/clients**: in dev.toml [s3] public_endpoint = "http://127.0.0.1:9000" (the address at which the host reaches MinIO) and [s3] endpoint = "http://minio:9000" is only for nodes. If 8088 is accessed from another machine, public_endpoint must be changed to an address that machine can resolve (or MinIO needs a reverse proxy/domain), otherwise the plugin download 302 points at a 127.0.0.1 it cannot resolve. Signatures cover only the Host, so changing the address needs no key change.

Container names are fixed explicitly, without compose's auto-appended `-1` suffix:
`lattice-dev-pg` / `-redis` / `-minio` / `-node` / `-web` / `-nats`.

Start order: `pg, redis, minio` → (healthy) → `node` (healthy) → `web`.

**Buckets are created by node itself**: `store/s3.rs::ensure_buckets()` idempotently performs
`HEAD` on the four buckets at startup (a `PUT` when missing); failures only log a warning (the message plane does not depend on S3, only large uploads are affected).
So there is **no one-shot container such as `minio-init`**—creating buckets is the responsibility of the party that uses them:
one less container, one less startup dependency, and no more silent "bucket missing because init never ran" failures.

## Images

| File | Artifact | Layers |
|---|---|---|
| `Dockerfile.node` | `lattice-node:dev` (105MB) | built on `node:22-bookworm` → runs on `debian:bookworm-slim` |
| `Dockerfile.web` | `lattice-web:dev` (193MB) | built on `node:22-alpine` → served by `nginx:latest` |

Both base images already exist locally, so **no Docker Hub pull is needed** (pulling large images stalls for a long time in this environment).

### Why the backend builder is node:22-bookworm

The host has no rust base image, and `docker pull rust:1-bookworm` (~1.6GB) hangs in this environment.
`node:22-bookworm` already ships `curl`/`git`/`gcc`/`make`, which is enough to install Rust, so it is reused.

## Three build-time pitfalls (all measured and worked around in the Dockerfile)

1. **crates cannot be fetched** → pre-generate `cargo-vendor2/` (~300MB) with `cargo vendor`,
   and `deploy/cargo-vendor.toml` replaces `crates-io` with `vendored-sources` and sets `offline = true`,
   so the build never reaches crates.io.
   > `cargo-vendor2/` is in `.gitignore`; a fresh clone must run this once first:
   > ````powershell
   > scripts\cargo.cmd vendor --respect-source-config cargo-vendor
   > ```
   > The non-`vendor/` directory name is deliberate: Windows Docker Desktop's file-sharing cache keeps serving old file contents
   > after a directory is replaced wholesale (measured: `COPY vendor/rand/.cargo_vcs_info.json` returned the previous bytes, causing
   > checksum verification failures); a new directory name plus Dockerfile `COPY cargo-vendor ./vendor` reliably avoids it.

2. **rustup cannot download in the container** → measurements:
   - `rsproxy.cn`: **DNS resolution fails** inside the container (`bad address`)
   - `static.rust-lang.org`: resolves, but downloads stall for a long time
   - `mirrors.tuna.tsinghua.edu.cn/rustup`: **21MB / 2.4s** ✅
   So `RUSTUP_DIST_SERVER` / `RUSTUP_UPDATE_ROOT` both point at the Tsinghua mirror.

3. **`.dockerignore`'s `**/target` wrongly excludes vendor** → the `cc` crate ships a `src/target/` directory;
   once excluded, the build fails with `failed to calculate checksum of: /src/vendor/cc/src/target/llvm.rs`.
   Now only the root `/target` is excluded.

Also: `Cargo.toml`'s release profile sets `lto = "thin"`, which the image build disables with
`CARGO_PROFILE_RELEASE_LTO=false` (saves several minutes), and adds a BuildKit cache mount on `target`
so an interrupted build can resume.

## Alignment points with dev.toml

`deploy/config/dev.toml` is copied verbatim into the image at `/etc/lattice/config.toml`, so container hostnames work directly:

- `[pg] url = ...@pg:5432/lattice`
- `[redis] url = redis://redis:6379`
- `[s3] endpoint = http://minio:9000`, `access_key = lattice_dev`, `secret_key = lattice_dev_secret`
- buckets: `lattice-large` / `lattice-media` / `lattice-cold` / `lattice-plugins` (client plugin hub)
  → compose's `MINIO_ROOT_USER/PASSWORD` must be **byte-identical** to `[s3]`, otherwise uploads get 403;
  the buckets themselves are created idempotently by node at startup from the four `bucket_*` names in `dev.toml`.

Two places need overrides:

| Item | Reason |
|---|---|
| `LATTICE__NODE__METRICS=0.0.0.0:9100` | dev.toml binds `127.0.0.1:9100`; inside a container it must bind all interfaces to be scraped from the host |
| the `nodekeys` volume mounted at `/etc/lattice/keys` | otherwise every rebuild rotates the signing key and all issued tokens become invalid |

> When running node **directly on the host** the opposite applies: `pg`/`redis`/`minio` must be overridden to `127.0.0.1`
> (`LATTICE__PG__URL`, `LATTICE__REDIS__URL`, `LATTICE__S3__ENDPOINT`, `LATTICE__AUTH__KEY_DIR`).

## Verified results

```
lattice-dev-node   Up (healthy)
lattice-dev-web    Up (healthy)

(no minio-init container; buckets are created by node itself, logs show "s3 bucket created" / "s3 bucket present")

scripts\smoke-container.ps1   8/8  OK=True
   ready / web_index / web_proxy_ready / login_via_web /
   create_user / create_dm / send_message(seq=1, persisted) /
   read_watermark / upload_init_s3(part_count=2, part_size=8MB) / metrics

scripts\ws-container.ps1      5/5  OK=True
   login(device_fp echoed back) / ws_upgrade_via_nginx / hello_sent /
   reply_frame(cmd=1) / hello_ack_body(protocol 1-1)
```

The bucket-creation path was also verified on its own: after deleting `lattice-cold` from MinIO's data directory and restarting node,
the bucket was recreated automatically (not merely detected as existing).

## Common commands

````powershell
:: backend build only
docker compose -f deploy/compose/dev.yaml build node

:: full stack rebuild
docker compose -f deploy/compose/dev.yaml up -d --build

:: status / logs
docker compose -f deploy/compose/dev.yaml ps
docker logs -f lattice-dev-node

:: full cleanup (including data volumes)
docker compose -f deploy/compose/dev.yaml down -v
```

## Known limitations

- **observability**: `lattice_backpressure_dropped_total` is an `IntCounterVec` and
  does **not appear in `/v1/admin/metrics`** before the first real drop happens (not a bug).
- **`/etc/lattice/config.toml` inside the node image is the dev config**; production must mount a different one and inject Secrets.
- `web`'s `npm install` has no lockfile (no `package-lock.json` in the repo), so dependency versions are not reproducible.

## Bus switch (Redis → NATS)

dev still uses Redis PubSub by default (the degraded path). To use NATS JetStream:

```powershell
docker compose -f deploy/compose/dev.yaml up -d nats node
set LATTICE__BUS__KIND=nats
set LATTICE__BUS__NATS_URL=nats://127.0.0.1:4222
```

Node startup idempotently creates the JetStream streams (LATTICE_ROUTE/LATTICE_BROADCAST/LATTICE_AUDIT); when NATS is unavailable it falls back to Redis per the ② §4.8 degradation matrix (warn in logs, startup not blocked).

## TURN / QUIC UDP ingress

- **TURN (coturn) is deployed separately**: see [`deploy/coturn/README.md`](coturn/README.md) and
  [`deploy/coturn/turnserver.conf`](coturn/turnserver.conf). For dev, start it with a compose profile:

  ```powershell
  docker compose -f deploy/compose/dev.yaml --profile turn up -d turn
  # self-check (real TURN allocation + expiry rejection): node scripts/turn-deploy-test.mjs
  docker compose -f deploy/compose/dev.yaml --profile turn rm -s -f turn
  ```

  node-side config `[media] turn_uris/turn_secret/turn_ttl` (the secret must come from a Secret/env).
- **K8s UDP ingress skeleton for QUIC / WebTransport / TURN**: `deploy/quic-lb-udp.yaml`
  (NLB UDP + `externalTrafficPolicy: Local` + client source IP preservation; only a network shape, **it does not mean the QUIC proxy is implemented**).

## Production HA / TLS / backup assets (templates, offline validation)

The `compose/` in this directory is **single-host dev**; production HA assets live in the locations below (all are copyable templates,
not a running cluster, and have not been validated on real multi-host/LB/cloud environments):

| Asset | Location | Validation |
|---|---|---|
| Production HA skeleton (PG/Redis/NATS/MinIO/etcd topology, RPO/RTO, runbooks) | [`production/README.md`](production/README.md) | `python scripts/ha-manifest-check.py --docker` (182/182 PASS) |
| Helm chart (TLS/mTLS certificate mounts, NetworkPolicy, PDB, read-only root filesystem, PITR CronJob) | `helm/lattice/` (README §4/§5/§7) | `python scripts/ha-prod-validate.py` (multi-profile `helm lint/template` + structure validation) |
| Certificate system (cert-manager Issuer/Certificate, sealed-secrets, Secret key-name contract, rotation) | `production/tls/` | production asset checks in `ha-prod-validate.py` |
| PG Patroni + etcd DCS templates and failover runbook | `production/patroni/` | same as above + `ha-manifest-check.py` |
| Backup / PITR (three-layer backup, retention/encryption, archive health verification) | `production/backup/` | same as above (`archive-verify.sql` is byte-identical to the same-origin file in the chart) |

> These validations are all **offline/single-host**: they start no production containers, touch no real multi-host setup, and do not prove HA compliance
> (unverified boundaries are in `production/README.md` §7 and `production/tls/README.md` §7).
