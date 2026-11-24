# Lattice Helm Chart

Deploys the `lattice-node` cluster, the web console, and the standalone `lattice-transfer` download plane. The chart owns the Kubernetes resource layout only: PostgreSQL, Redis, NATS, and object storage are external dependencies, and TLS and JWT private keys are supplied by the operator or cert-manager; the chart generates none.

- TLS and cert-manager guidance: [deploy/production/tls/README.md](../../production/tls/README.md)
- Backup and PITR policy: [deploy/production/backup/README.md](../../production/backup/README.md)
- Canary and rollback runbook: [deploy/production/canary-runbook.md](../../production/canary-runbook.md)

## Prerequisites

| Dependency | Requirement |
| --- | --- |
| Kubernetes | 1.26 or newer; uses `apps/v1`, `networking.k8s.io/v1`, `autoscaling/v2`, `policy/v1`, and `batch/v1` |
| Helm | Helm 3 |
| External data plane | PostgreSQL, Redis, and S3-compatible object storage. The dev stack is [deploy/compose/dev.yaml](../../compose/dev.yaml) |
| NATS JetStream | Optional; required when `deps.bus.kind=nats`. The default bus is `redis-pubsub` |
| Images | Build and push [deploy/Dockerfile.node](../../Dockerfile.node) and [deploy/Dockerfile.web](../../Dockerfile.web) to a registry reachable from the cluster |
| JWT signing key | An RS256 private key must exist in a Secret; the chart generates no keys |
| TLS | Optional. Use a pre-created Secret (`tls.provider=existingSecret`, recommended) or cert-manager (`tls.provider=certManager`); the chart renders no Issuer or ClusterIssuer |
| PITR | `backup.pitr.enabled=true` needs a `pg-replication-url` Secret key for an account with the `REPLICATION` privilege; `pg_basebackup` cannot use the application account |

## Install

The JWT signing key Secret must exist before the release starts:

```bash
kubectl create namespace lattice --dry-run=client -o yaml | kubectl apply -f -
kubectl -n lattice create secret generic lattice-jwt-keys \
  --from-file=jwt.key.pem=./jwt.key.pem
```

In production, pre-create the Secret rather than using `--set`, then install or upgrade:

```bash
kubectl -n lattice create secret generic lattice-prod-secrets \
  --from-literal=pg-url='postgres://...' --from-literal=redis-url='redis://...' \
  --from-literal=s3-access-key='...' --from-literal=s3-secret-key='...' \
  --from-literal=admin-bootstrap-password='...' \
  --from-literal=transfer-secret="$(openssl rand -hex 32)"
# add --from-literal=pg-replication-url='postgres://...' when backup.pitr.enabled=true

helm upgrade --install lattice deploy/helm/lattice \
  --namespace lattice --create-namespace \
  --set image.repository=registry.example.com/lattice-node --set image.tag="<node-tag>" \
  --set webImage.repository=registry.example.com/lattice-web --set webImage.tag="<web-tag>" \
  --set deps.s3.publicEndpoint=https://minio.example.com \
  --set secrets.existingSecret=lattice-prod-secrets
```

The Secret contract uses fixed key names: `pg-url`, `pg-replication-url`, `redis-url`, `s3-access-key`, `s3-secret-key`, `admin-bootstrap-password`, and `transfer-secret`. The Deployments inject them with `secretKeyRef` as environment variables such as `LATTICE__PG__URL`, `LATTICE__TRANSFER__SECRET`; credentials never enter the ConfigMap. The bootstrap account is created only on first start, when the `users` table is empty. `transfer-secret` is the shared HMAC key of the download transfer plane: it must be at least 32 bytes and byte-identical for the node (signs tokens) and the `lattice-transfer` Deployment (verifies them), and both refuse to start while `transfer.enabled=true` and it is missing or too short.

## Key values

| Value | Default | Behavior |
| --- | --- | --- |
| `replicaCount` | `3` | Stateless node replicas; keep at least three to tolerate one node failure |
| `node.resources` | requests 2 CPU / 4Gi, limits 4 CPU / 8Gi | Per-node request and burst headroom |
| `deps.s3.publicEndpoint` | `""` | Host used in presigned URLs. Must resolve for clients; when empty, the in-cluster endpoint is used and external downloads can fail |
| `deps.bus.kind` | `redis-pubsub` | Set to `nats` and also set `deps.bus.natsUrl` for JetStream |
| `mqtt.enabled` | `false` | Exposes the MQTT listener (1883 plaintext by default); see `tls.mqtt` for TLS |
| `grpc.enabled` | `true` | Internal gRPC on 9090 through an in-cluster Service |
| `tls.enabled` / `tls.provider` | `false` / `existingSecret` | Master TLS switch. `existingSecret` uses pre-created Secrets; `certManager` renders `Certificate` resources and needs cert-manager |
| `tls.grpc.enabled`, `tls.mqtt.enabled`, `tls.quic.enabled` | all `false` | In-node TLS/mTLS listeners: gRPC 9090 (`requireKnownNodeCn` binds CN to node ID), MQTT 8883 (`requireClientCert`), QUIC 4433 |
| `tls.http.web.enabled` | `false` | Extra 8443 TLS listener on web nginx for deployments without an Ingress or external LB |
| `security.node.readOnlyRootFilesystem` | `true` | Node root is read-only; `/var/lib/lattice` (local WAL, emptyDir 2Gi) and `/tmp` are writable |
| `networkPolicy.enabled` | `false` | Renders deny-ingress policies with explicit port and namespace rules |
| `networkPolicy.metricsNamespace` | `""` | When set, port 9100 is reachable only from that namespace. Empty leaves metrics open to all sources |
| `networkPolicy.ingressControllerNamespace` | `""` | When set, only that namespace may reach node port 8080; `networkPolicy.ingressFrom` adds extra peers |
| `podDisruptionBudget.enabled` / `minAvailable` | `true` / `2` | Node PDB keeps two replicas available; disable or adjust when reducing replicas |
| `podDisruptionBudget.web.enabled` | `false` | Enable only when web replicas are greater than one; a single replica with a PDB blocks draining |
| `autoscaling.enabled` | `false` | CPU-based HPA, 70% target, 3 to 20 replicas. Scaling by connection count needs prometheus-adapter and is not implemented here |
| `metrics.serviceMonitor.enabled` | `false` | Requires the Prometheus Operator; otherwise use [deploy/observability](../../observability/README.md) |
| `backup.enabled` / `backup.pitr.enabled` | `false` / `false` | Logical `pg_dump` CronJob; physical baseline plus archive-health verification CronJob |
| `canary.enabled` / `canary.weight` / `canary.replicaCount` | `false` / `20` / `1` | Adds canary resources only. Weight is ingress-nginx `canary-weight` 0-100 for `/v1`; canary replicas are fixed and excluded from HPA/PDB |
| `canary.byHeader` / `canary.byHeaderValue` | `""` | Non-empty `byHeader` routes matching requests to canary regardless of weight; empty `byHeaderValue` matches any header presence |
| `transfer.enabled` / `transfer.replicaCount` | `true` / `2` | Renders the `lattice-transfer` Deployment, Service, and PDB and makes downloads redirect to `{publicBaseUrl}/t/{token}`; needs `secrets.transferSecret` |
| `transfer.publicBaseUrl` | `""` | Public edge that routes `/t/`. Empty derives `https://<ingress.host>` when `ingress.enabled`, else the in-cluster Service DNS |
| `transfer.tokenTtlSecs` / `transfer.maxInflight` | `300` / `256` | Capability token lifetime (clamped 30-3600 s by the node) and concurrent downloads per replica (0 = 256) |
| `secrets.transferSecret` | `""` | Shared HMAC key (>= 32 bytes); also accepted as the `transfer-secret` key of `secrets.existingSecret` |
| `transfer.autoscaling.enabled` / `transfer.pdb.enabled` | `false` / `true` | Transfer HPA (CPU 70%, 2-8 replicas) and PDB keeping one replica available |

## TLS and mTLS

The chart renders Certificate resources, mounts Secrets at the paths the process expects, and writes the matching TLS keys into the ConfigMap. Private keys stay in Secrets and never enter values or Git.

| Interface | Termination | Mount and keys | Values |
| --- | --- | --- | --- |
| HTTP/WS | Node has no built-in HTTPS listener; terminate at the Ingress, external LB, or web nginx 8443 | Ingress TLS Secret, or `/etc/nginx/tls` | `ingress.tls`, `tls.http.web` |
| MQTT | Node terminates TLS on 8883 | `/etc/lattice/tls/mqtt`: `server.crt`, `server.key`, `client-ca.crt` | `tls.mqtt`, `mqtt.enabled=true` |
| gRPC | Node terminates mTLS for cross-node calls | `/etc/lattice/tls/grpc`: `server.crt`, `server.key`, `ca.crt` | `tls.grpc` |
| QUIC/WebTransport | Node terminates server-side TLS on UDP 4433 | `/etc/lattice/tls/quic`: `server.crt`, `server.key` | `tls.quic` |

In `existingSecret` mode, create the Secrets named by `tls.*.secretName` (`lattice-node-grpc-tls`, `lattice-node-mqtt-tls`, `lattice-node-quic-tls`, `lattice-web-tls`) and the Ingress TLS Secret. In `certManager` mode the chart renders up to five `cert-manager.io/v1` Certificates (Ingress, node gRPC, MQTT, QUIC, and web; each only when the matching listener or Ingress is enabled) with `privateKey.rotationPolicy: Always`; the referenced Issuer or ClusterIssuer must already exist. TLS listeners read certificates at startup, so restart node and web Pods after rotation. If an external LB terminates TLS, set `ingress.tls.enabled=false` and do not expose port 8080 outside the cluster.

## Security and networking

- Node Pods run as non-root UID/GID 10001 with `RuntimeDefault` seccomp, `allowPrivilegeEscalation=false`, all capabilities dropped, a read-only root filesystem, and no service-account token. Only `/var/lib/lattice` and `/tmp` are writable.
- Web nginx starts as root to bind port 80 and drop worker privileges, so `runAsNonRoot` is not set. It still has a read-only root filesystem, explicit emptyDirs, and only `NET_BIND_SERVICE`, `CHOWN`, `SETGID`, and `SETUID`. A fully non-root web tier needs an unprivileged image on port 8080, which the chart does not provide.
- NetworkPolicy denies node ingress by default, then allows web and Ingress sources to 8080, the monitoring namespace to 9100 when configured, node-to-node traffic to 9090, and the MQTT/QUIC ports. The web policy allows ingress to 80 and 8443 and egress only to DNS and node port 8080. Node egress stays unrestricted by default because PostgreSQL, Redis, NATS, and S3 targets vary; `networkPolicy.egress.enabled=true` makes it deny-by-default with only DNS and `networkPolicy.egress.allow`.
- The node PDB keeps two of three replicas available. PDBs govern voluntary disruption only; they do not protect against node failure.

## Download transfer plane

`transfer.enabled=true` (the default) deploys `lattice-transfer` from the node image, with entrypoint `/usr/local/bin/lattice-transfer`. It mounts the same `config.toml` ConfigMap as the node (the `[s3]` and `[transfer]` sections are shared) and receives `LATTICE__TRANSFER__SECRET` and the S3 credentials through `secretKeyRef`. The node signs a short-lived HMAC token per object and answers download endpoints with `302 {publicBaseUrl}/t/{token}`; any transfer replica verifies the token and streams the object from the internal S3 endpoint with `Range`/`If-Range` pass-through. Object bytes never pass through the node, and clients need neither object-storage credentials nor MinIO reachability.

`transfer.publicBaseUrl` is the public edge that routes `/t/` to the transfer Service. When it is empty the ConfigMap derives it: `https://<ingress.host>` when `ingress.enabled=true`, otherwise `http://<release>-lattice-transfer:8090`, which resolves only inside the cluster — pin the value for any deployment without an Ingress. The Ingress derivation always uses `https`; set the value explicitly when TLS terminates elsewhere or the public scheme is `http`.

With `ingress.enabled=true` the Ingress gets a `/t` Prefix path (ahead of `/`) pointing at the transfer Service on `8090`, and keeps `proxy-buffering: off` with a 3600-second read timeout for the streamed response. Without an Ingress, route `/t/` at the external load balancer yourself. The transfer Service is ClusterIP only; the chart exposes no NodePort or LoadBalancer for it.

Probes: `/healthz` (liveness, process only) and `/readyz` (readiness, at least one object-storage endpoint reachable by a short TCP probe) on `8090`; `/metrics` on `transfer.service.metricsPort` (`9101`), scraped by its own ServiceMonitor when `metrics.serviceMonitor.enabled=true`. With `networkPolicy.enabled=true` the transfer Pods get their own policy: ingress to `8090` from `networkPolicy.ingressControllerNamespace` (plus `networkPolicy.ingressFrom` peers), metrics `9101` per `networkPolicy.metricsNamespace`, and egress limited to DNS plus TCP `9000` to object storage.

Rotating `transfer-secret` requires a rollout of both the node and the transfer Deployment. When a release already uses `secrets.existingSecret`, add the `transfer-secret` key before upgrading, otherwise the Pods stop with `CreateContainerConfigError`. `transfer.enabled=false` removes every transfer resource and leaves the node on the legacy presigned-URL download path.

## Health and troubleshooting

```bash
kubectl -n lattice get pods -l app.kubernetes.io/name=lattice
kubectl -n lattice port-forward svc/lattice-node 8080:8080
curl -fsS http://127.0.0.1:8080/v1/health
curl -fsS http://127.0.0.1:8080/v1/ready
```

`/v1/ready` returns 503 when the node is draining or PostgreSQL is unreachable. A Redis-only failure returns 200 with `deps.redis=degraded`; read the `deps` object before treating a pod as healthy.

- **`no account can log in`**: the `users` table is empty and no `admin-bootstrap-password` is set; the node refuses to create a default account.
- **`Permission denied` writing a file**: add the missing writable path under `readOnlyRootFilesystem=true` (node: `/var/lib/lattice`, `/tmp`; web: `/var/cache/nginx`, `/var/run`, `/tmp`).
- **TLS handshake fails**: Secret keys or mount paths are wrong, or the certificate SAN does not contain the address clients use.
- **Presigned download points at an unresolvable host**: set `deps.s3.publicEndpoint` to an address clients can resolve (only relevant with `transfer.enabled=false`).
- **`/t/...` downloads return `404 token_invalid`, `410 token_expired`, or `503 upstream_unavailable`**: the token is forged or expired (check `transfer.tokenTtlSecs`, and that node and transfer read the same `transfer-secret`), or the transfer plane cannot reach object storage (`/readyz` on a transfer Pod reports how many endpoints answer; `transfer.publicBaseUrl` must match the host clients actually call).
- **WebSocket or SSE disconnects after 60 seconds**: raise the read timeout on every proxy in front of the node; the chart's Ingress sets 3600 seconds.

## Backup and PITR

Two layers are available; the chart automates neither database-side WAL archiving nor restore drills.

| Job | Schedule | Timeout | Job history | TTL | Output |
| --- | --- | --- | --- | --- | --- |
| `pg-backup` (`backup.enabled`) | `0 3 * * *` | 2h | 3 success / 3 failure | 7 days | `pg_dump -Fc` under `lattice-cold/backup/pg/` |
| `pg-basebackup` (`backup.pitr.enabled`) | `15 2 * * *` | 6h | 2 success / 3 failure | 7 days | `pg_basebackup -Ft -z -Xfetch` under `lattice-cold/wal/pg/lattice-pg/base/<timestamp>/` |
| `pg-pitr-verify` (`backup.pitr.enabled`) | `*/15 * * * *` | 10 minutes | 1 success / 3 failure | 3 days | read-only archive check; a `FATAL` line fails the Job |

All three CronJobs use `concurrencyPolicy: Forbid`, so two dumps or base backups cannot load the primary at once. Object-storage retention is controlled by `backup.keepDays` (30 days for logical dumps) and `backup.pitr.keepDays` (14 days for physical baselines). The verification Job checks `archive_mode=on`, a successful archive attempt, archive lag within `backup.pitr.maxArchiveLagSeconds` (300 by default), the last failure not being newer than the last success, and at least one streaming replica when `backup.pitr.requireReplica` is true.

WAL archiving is performed by the PostgreSQL-side `archive_command`, typically [deploy/production/patroni/wal-gateway.sh](../../production/patroni/wal-gateway.sh) against the same bucket and `wal/pg/lattice-pg` prefix. Without that chain, the physical baseline alone cannot restore to a point in time.

```bash
pg_restore --clean --if-exists -d "$PG_URL" <dump-file>
```

Limitations: `pg_dump` is a daily full dump, not PITR; RPO depends on the WAL archive chain. The chart supplies the baseline and health verification only. Enable bucket versioning and object lock for the cold bucket, and run restore drills against a scratch database before relying on the backup.

## Upgrade and rollback

Nodes are stateless and use a rolling update with `maxUnavailable=0`. A `preStop` sleep of 10 seconds lets Endpoints and load balancers drain before SIGTERM; `terminationGracePeriodSeconds` defaults to 45 seconds. While draining, the node returns 503 on `/v1/ready`, rejects new `/v1/ws` connections, and closes existing connections with a `byef` shutdown frame.

Database migrations run idempotently at node startup and are forward-only. Destructive changes must use an expand/contract sequence, or rolling back to the previous image fails on missing or extra columns. `helm rollback` restores workloads but never database contents. To roll back TLS or security hardening, set the relevant `tls.*` values back to false, set `security.*.readOnlyRootFilesystem=false` if required, and set `networkPolicy.enabled=false`, then run `helm upgrade`; this is a configuration rollback, not a data rollback.

This chart version adds the `transfer.*` values and the `transfer-secret` Secret key. An upgrade from an older release that passes `--reuse-values` must merge the new defaults (for example `--set transfer.enabled=false`, or a values file) because the templates read `transfer.*` directly. When `secrets.existingSecret` is used, create the `transfer-secret` key before the upgrade.

## Validation

Template-level checks that run without a cluster:

```bash
helm lint deploy/helm/lattice
RENDER=$(mktemp)
helm template lattice deploy/helm/lattice -n lattice \
  --set backup.enabled=true --set backup.pitr.enabled=true \
  --set ingress.enabled=true --set mqtt.enabled=true \
  --set tls.enabled=true --set tls.certManager.enabled=true \
  --set networkPolicy.enabled=true > "$RENDER"
```

These commands check template syntax and rendering only. This repository does not include a live-cluster test suite for this chart; a successful render is not evidence that NetworkPolicy, PDB, CronJob, or ingress-nginx behavior works in a particular cluster. Validate those in a staging cluster before production.

## Canary release

Canary is off by default. When enabled, the chart adds a canary node Deployment and Service, a canary NetworkPolicy when `networkPolicy.enabled`, a canary ServiceMonitor when `metrics.serviceMonitor.enabled`, and two `/v1` Ingresses when `ingress.enabled`. The stable Deployment, Service, HPA, and PDB are unchanged. Canary Pods carry `lattice.io/track=canary` and a separate `app.kubernetes.io/component=node-canary` selector, so the stable Service never selects them. The canary Deployment shares the node PodSpec helper with stable, including Secret environment injection, volumes, security context, and probes; only the image, replica count, and selector labels differ. Canary replicas are fixed and excluded from HPA and PDB because they must remain interruptible.

With `ingress.enabled=true`, `<release>-node-api` sends `/v1` to the stable node Service, while `<release>-node-api-canary` uses the same host and path and adds ingress-nginx canary annotations. A percentage of `/v1` HTTP, WebSocket, and SSE traffic goes to canary, or exact header matches are routed there. The `/v1` prefix is longer than the existing `/` route, so console routes stay on web. Because `/v1` bypasses web nginx when canary is enabled, the Ingress sets 3600-second read and send timeouts, disables proxy buffering, and uses `web.clientMaxBodySize` for uploads. Without an Ingress, the canary workload and Services are still rendered, but weighted routing is the external load balancer's or service mesh's job.

A safe rollout sequence:

```bash
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values \
  --set canary.enabled=true --set canary.weight=0 --set canary.image.tag="<canary-tag>"
kubectl -n lattice rollout status deploy/<release>-node-canary
kubectl -n lattice logs deploy/<release>-node-canary -f
# Ramp gradually and watch error rate, latency, backlog, and reconnects.
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values --set canary.weight=5
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values --set canary.weight=25
# Route a test account by header, independent of weight.
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values \
  --set canary.byHeader=x-lattice-canary --set canary.byHeaderValue=always
curl -H 'x-lattice-canary: always' https://lattice.example.com/v1/health
```

Rollback in order: set `canary.weight=0` to return all traffic to stable while keeping canary replicas for logs, then set `canary.enabled=false` to delete the canary resources, and finally use `helm rollback` if stable also needs reverting. With canary disabled, the `/v1` Ingress pair is removed and `/v1` is served by web nginx again. Do not delete the canary Ingress by hand; changing values is declarative and auditable.

Canary metrics are scraped by its own ServiceMonitor when `metrics.serviceMonitor.enabled=true`, or can be read with `kubectl -n lattice port-forward svc/<release>-node-canary 9101:9100`. Compare canary and stable 5xx rate, P99 latency, WebSocket reconnects, and `lattice_backpressure_dropped_total` over the same window; return weight to zero on significant degradation.

Known limits:

1. Weight splitting, header matching, and `/v1` prefix priority are not verified against a live ingress-nginx controller in this repository. Confirm the traffic ratio in staging before production.
2. MQTT and QUIC device traffic is out of scope. Device sessions are stateful, so a random percentage shift forces reconnects; use device-scoped configuration or a separate access pool for device rollouts.
3. External load balancer weights are not managed by this chart. Traffic that bypasses the Ingress must be weighted on the external LB.
4. HPA and PDB do not cover canary Pods; they may be evicted during draining deliberately.
5. gRPC port 9090 and same-node internal calls are not split proportionally; DNS still selects the stable or canary Service.
6. `helm upgrade --reuse-values` and Ingress annotation reload behavior on a real cluster are unverified here.
