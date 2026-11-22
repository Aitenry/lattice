# Lattice Helm Chart

Deploys the `lattice-node` cluster + web console (`deploy/helm/lattice`). Interfaces/data model/values follow
docs ⑤/⑥ and design §17 respectively; this chart only decides "how resources are laid out".

## 1. Prerequisites

| Dependency | Description |
| --- | --- |
| Kubernetes ≥ 1.26 | APIs used: apps/v1, networking.k8s.io/v1, autoscaling/v2, policy/v1, batch/v1 |
| External PG / Redis / MinIO | the chart does **not** embed production clusters; dev uses `deploy/compose/dev.yaml` |
| NATS JetStream (optional) | required when `deps.bus.kind=nats`; defaults to `redis-pubsub` |
| Internal gRPC | `grpc.enabled` (on by default, port 9090, in-cluster Service); production must enable mTLS: `tls.enabled=true` + `tls.grpc.enabled=true` |
| TLS (optional) | one of two certificate sources: `tls.provider=existingSecret` (pre-created Secret, recommended) or `tls.provider=certManager` (requires cert-manager in the cluster; the Issuer/ClusterIssuer is still pre-created by operations). The chart **generates no private keys** |
| Images | build and push to a registry reachable from the cluster: `deploy/Dockerfile.node`, `deploy/Dockerfile.web` |
| JWT private key Secret | the chart generates no private keys; this must be pre-created (see below) |
| PITR (optional) | `backup.pitr.enabled=true` requires an extra `pg-replication-url` in the Secret (an account with **REPLICATION privilege**; the application account `lattice_app` cannot run `pg_basebackup`) |
| Production TLS/certificate system | certificate matrix, cert-manager manifests and sealed-secrets flow: [`deploy/production/tls/README.md`](../../production/tls/README.md) |
| Backup/PITR policy | retention, encryption, object lock and off-site replicas: [`deploy/production/backup/README.md`](../../production/backup/README.md) |
| Canary release (optional) | with `canary.enabled=true`, ingress-nginx canary annotations split traffic by weight/header (the controller must support `canary-weight`/`canary-by-header`, see §10); without an Ingress only the canary workload is deployed and weights are the external LB/mesh's responsibility |

```bash
# Private key: RS256 private key + optional jwt.key.prev.pem (dual-key rotation in parallel)
kubectl -n lattice create secret generic lattice-jwt-keys \
  --from-file=jwt.key.pem=./jwt.key.pem
```

## 2. Installation

```bash
helm upgrade --install lattice deploy/helm/lattice \
  --namespace lattice --create-namespace \
  --set image.repository=registry.example.com/lattice-node \
  --set image.tag=0.5.0 \
  --set webImage.repository=registry.example.com/lattice-web \
  --set webImage.tag=0.5.0 \
  --set deps.s3.publicEndpoint=https://minio.example.com \
  --set secrets.s3AccessKey=... --set secrets.s3SecretKey=... \
  --set secrets.adminBootstrapPassword='...'   #  --set secrets.adminBootstrapPassword='...'   # the account is created only on first start when the users table is empty
```

In production, avoid `--set` for passwords; pre-create the Secret and reuse it instead:

```bash
kubectl -n lattice create secret generic lattice-prod-secrets \
  --from-literal=pg-url='postgres://...' \
  --from-literal=pg-replication-url='postgres://replicator:...@pg-lattice.lattice.internal:5432/lattice?sslmode=verify-full' \
  --from-literal=redis-url='redis://...' \
  --from-literal=s3-access-key='...' \
  --from-literal=s3-secret-key='...' \
  --from-literal=admin-bootstrap-password='...'
helm upgrade --install lattice deploy/helm/lattice -n lattice \
  --set secrets.existingSecret=lattice-prod-secrets
```

Secret contract (fixed key names): `pg-url` / `pg-replication-url` / `redis-url` / `s3-access-key` /
`s3-secret-key` / `admin-bootstrap-password`. The Deployment injects them via `secretKeyRef` as
env vars such as `LATTICE__PG__URL`; credentials **never appear** in the ConfigMap.

## 3. Key values

| Value | Default | Description |
| --- | --- | --- |
| `replicaCount` | 3 | ② §7.1 requires ≥3; stateless, so rolling updates and scaling are fine |
| `node.resources` | requests 2C4G | ② §7.3 |
| `deps.s3.publicEndpoint` | `""` | **Host of presigned URLs**. Must be an address clients can resolve; when empty the in-cluster endpoint is used (downloads from outside the cluster fail) |
| `deps.bus.kind` | `redis-pubsub` | switching to `nats` also requires `deps.bus.natsUrl`; the subscriber side still follows the ② §4.8 degradation matrix |
| `mqtt.enabled` | false | additionally exposes 1883 (plaintext) when enabled; see `tls.mqtt` for TLS |
| `grpc.enabled` | true | internal gRPC 9090; with `tls.grpc.enabled=true` the Secret is mounted and client certificates are required (mTLS) |
| `tls.enabled` | false | TLS master switch; certificate source in `tls.provider` |
| `tls.provider` | `existingSecret` | `existingSecret` (pre-created by operations) or `certManager` (renders a Certificate CR) |
| `tls.certManager.enabled` | false | requires cert-manager in the cluster; the chart only renders Certificates, never Issuers |
| `tls.http.web.enabled` | false | extra 8443 ssl listener on web nginx (for direct-connect shapes without an Ingress/LB) |
| `tls.grpc.enabled` | false | in-node gRPC mTLS (server.crt/server.key/ca.crt); `tls.grpc.requireKnownNodeCn` binds node_id |
| `tls.mqtt.enabled` | false | in-node MQTT TLS/mTLS (8883; server.crt/server.key/client-ca.crt) |
| `tls.quic.enabled` | false | in-node QUIC/WebTransport UDP TLS (4433; server.crt/server.key) |
| `security.node.readOnlyRootFilesystem` | true | read-only root filesystem for node; WAL (/var/lib/lattice) and /tmp use emptyDir |
| `security.web.readOnlyRootFilesystem` | true | read-only root filesystem for web; /var/cache/nginx, /var/run and /tmp that nginx needs use emptyDir |
| `networkPolicy.enabled` | false | deny ingress by default; allow by port + namespace (web/ingress→8080, monitoring→9100, node-to-node→9090, MQTT/QUIC ports) |
| `networkPolicy.ingressControllerNamespace` | `""` | e.g. `ingress-nginx`; non-empty = only that namespace may reach 8080 |
| `networkPolicy.metricsNamespace` | `""` | e.g. `monitoring`; non-empty = 9100 opens only to that namespace |
| `networkPolicy.web.enabled` | true | also renders the web NetworkPolicy (ingress→80/8443, egress only to node:8080+DNS) |
| `networkPolicy.egress.enabled` | false | when on, node egress is denied by default and only DNS + `egress.allow` pass |
| `podDisruptionBudget.minAvailable` | 2 | the N-1 of ② §7.3 |
| `podDisruptionBudget.web.enabled` | false | enable only when web replicas >1 (a single replica blocks draining) |
| `autoscaling.enabled` | false | CPU 70% by default; scaling by connection count needs prometheus-adapter (see the note in ② §7.3) |
| `metrics.serviceMonitor.enabled` | false | requires the Prometheus Operator; otherwise use static scraping in `deploy/observability/prometheus` |
| `backup.enabled` | false | logical backup CronJob: pg_dump → `lattice-cold/backup/pg/`, kept for `keepDays` days |
| `backup.pitr.enabled` | false | PITR: physical baseline CronJob (pg_basebackup → `wal/pg/lattice-pg/base/` in the same bucket) + archive health verification CronJob |
| `canary.enabled` | false | canary master switch (off by default = no canary resources rendered); when on it adds canary node Deployment/Service and leaves stable workloads unchanged, see §10 |
| `canary.weight` | 20 | ingress-nginx `canary-weight` (0-100). `0` = canary replicas kept but 0% traffic; applies only to `/v1` traffic through the Ingress |
| `canary.image.tag` | `""` | canary image tag; empty = same as `image.tag` (NOTES warns "same as no canary"). Empty `repository`/`pullPolicy` likewise reuse `image.*` |
| `canary.replicaCount` | 1 | canary replicas (excluded from HPA/PDB; must be ≥1, `0` fails the template outright—an empty Service turns canary traffic into 503s) |
| `canary.byHeader` / `canary.byHeaderValue` | `""` | exact canary by request header (ingress-nginx `canary-by-header`): a match always goes to canary, handy for early validation by internal accounts; empty = split by weight only |

## 4. TLS / mTLS (certificate mounts and least privilege)

The chart does exactly three things: **render Certificate CRs** (certManager mode), **mount Secrets at the paths the process expects**, and
**write the corresponding TLS config keys into the ConfigMap**. Private keys live only in Secrets and never enter values/git/ConfigMap.

| Interface | Termination point (code fact) | Mount/Secret | values | Verification |
| --- | --- | --- | --- | --- |
| HTTP/WS | node has **no** HTTPS/WSS listener (`main.rs` only binds `[node] listen_http`); terminated by the Ingress/LB or web nginx 8443 | Ingress TLS Secret or `/etc/nginx/tls` | `ingress.tls` / `tls.http.web` | certificate SAN contains the access domain; plaintext HTTP 8080 is in-cluster only (restricted by NetworkPolicy) |
| MQTT | node `[mqtt] tls_enabled/tls_bind=8883` | `/etc/lattice/tls/mqtt`: `server.crt`/`server.key`/`client-ca.crt` | `tls.mqtt.*`, `mqtt.enabled=true` | device certificate chain verification (`require_client_cert=true`, fail-closed) |
| gRPC | node `[grpc] tls_*` (cross-node mTLS) | `/etc/lattice/tls/grpc`: `server.crt`/`server.key`/`ca.crt` | `tls.grpc.*` | mutual certificates; the CN must be a known `node_id` (`require_known_node_cn`) |
| QUIC/WebTransport | node `[quic] cert/key` (UDP 4433) | `/etc/lattice/tls/quic`: `server.crt`/`server.key` | `tls.quic.*` | server-side TLS; QUIC has no client certificates, identity goes through the join token |

- **existingSecret mode (recommended)**: operations creates the following Secrets (fixed key names; `defaultMode: 0400` is set by the Deployment):
  `lattice-node-grpc-tls`, `lattice-node-mqtt-tls`, `lattice-node-quic-tls`, `lattice-web-tls`, ingress TLS Secret.
  generation/rotation: see [`deploy/production/tls/README.md`](../../production/tls/README.md) (cert-manager or sealed-secrets).
- **certManager mode**: `tls.certManager.enabled=true` renders 5 `cert-manager.io/v1` Certificates
  (ingress/node-grpc/node-mqtt/node-quic/web); `issuerRef` points at an Issuer/ClusterIssuer pre-created by operations,
  `privateKey.rotationPolicy: Always`, and `duration/renewBefore` are tunable. Issuer/ClusterIssuer are **not in the chart**
  (cluster-level trust roots should not be managed by an application chart); see `deploy/production/tls/cert-manager.yaml` for an example.
- **After certificate rotation, node/web must be rolled**: TLS listeners read certificates at process startup; a kubelet Secret update does not hot-reload.
- If an external LB terminates TLS for the Ingress, set `ingress.tls.enabled=false` and do not expose 8080 outside the cluster.

## 5. Security context / NetworkPolicy / PDB

- node: `runAsNonRoot=true` (uid/gid 10001; the image already has the lattice user), `seccompProfile=RuntimeDefault`,
  `allowPrivilegeEscalation=false`, `capabilities.drop=[ALL]`, `readOnlyRootFilesystem=true`; 
  the only writable directories are `/var/lib/lattice` (local WAL, emptyDir 2Gi) and `/tmp` (emptyDir 128Mi);
  `automountServiceAccountToken=false` (nodes do not call the K8s API).
- web: the official nginx image's master needs root to bind 80 and drop worker privileges, so `runAsNonRoot` is not set;
  read-only root filesystem + emptyDir (`/var/cache/nginx`, `/var/run`, `/tmp`) + `drop ALL` followed by only the
  `NET_BIND_SERVICE/CHOWN/SETGID/SETUID` that nginx needs; `automountServiceAccountToken=false`.
  Fully non-root requires an unprivileged image and listening on 8080 (the chart does not do this).
- NetworkPolicy: deny ingress by default, allow per port (see the value table in §3); web denies ingress by default and allows only DNS and node:8080 on egress.
  Egress is **not** restricted by default (nodes connect to external PG/Redis/NATS/S3; with `networkPolicy.egress.enabled` it becomes deny-by-default,
  allowing only DNS + `egress.allow`).
- PDB: node `minAvailable=2` (the N-1 of 3 replicas); `podDisruptionBudget.web` can be enabled when web replicas >1.

## 6. Health and troubleshooting

```bash
# the actual version tag is passed with --set image.tag; nothing is guessed by default
kubectl -n lattice get pods -l app.kubernetes.io/name=lattice
kubectl -n lattice port-forward svc/lattice-node 8080:8080
curl -s localhost:8080/v1/ready
curl -s localhost:8080/v1/health
kubectl -n lattice port-forward svc/lattice-web 8088:80   #kubectl -n lattice port-forward svc/lattice-web 8088:80   # console
```

- **Pod fails to start and the log says `no account can log in`**: the `users` table is empty and no
  `admin-bootstrap-password` is set (⑤ §8.2: no account is created with a default password—better not to start than to leave a backdoor).
- **Pod fails to start and the log says `Permission denied` when writing a file**: usually a missing emptyDir under `readOnlyRootFilesystem=true`
  (node: `/var/lib/lattice`, `/tmp`; web: `/var/cache/nginx`, `/var/run`, `/tmp`).
- **TLS handshake fails although certificate paths are configured**: Secret key names/paths do not match (gRPC `server.crt|server.key|ca.crt`;
  MQTT `server.crt|server.key|client-ca.crt`; QUIC `server.crt|server.key`), or the certificate SAN does not contain the access address.
- **Plugin download 302 points at an unresolvable host**: `deps.s3.publicEndpoint` is unset or wrong (⑥ §4.1).
- **WS/SSE drops after 60 seconds**: the Ingress `proxy-read-timeout` was not raised (the chart defaults to 3600s; if another LB sits in front, align it too).

## 7. Backup and PITR

Two layers, both required:

1. **Logical baseline** (`backup.enabled`): daily `pg_dump -Fc` → `lattice-cold/backup/pg/`, used for single-table/single-database restores.
2. **Physical baseline + WAL archiving** (`backup.pitr.enabled` + PG-side `archive_command`):
   - the PG side sets `archive_mode=on` and `archive_command → deploy/production/patroni/wal-gateway.sh` (bucket `lattice-cold`,
     prefix `wal/pg/lattice-pg/wal/`);
   - the chart's `-pg-basebackup` CronJob runs `pg_basebackup -Ft -z -Xfetch` daily → `base/<TS>/` under the same prefix;
   - the chart's `-pg-pitr-verify` CronJob checks every 15 minutes that `archive_mode`/archive lag ≤300s/last failure/replica presence hold,
     and fails the Job on FATAL (wired to the `kube_job_failed` alert).
   - retention/encryption/object lock/off-site replica policy: [`deploy/production/backup/README.md`](../../production/backup/README.md);
     restore drills: `scripts/pitr-drill.ps1`, `scripts/restore-runbook.md`.
- **Scheduling/retention/alerting rules** (item by item against the table in `deploy/production/backup/README.md` §2):
  - all three CronJobs use `concurrencyPolicy: Forbid`—the same task never runs concurrently, so two `pg_dump`/`pg_basebackup` runs cannot load the primary together;
  - Job history retention: physical baseline 2 successful / 3 failed, archive verification 1 successful / 3 failed, logical backup 3 successful / 3 failed;
    `ttlSecondsAfterFinished` cleans up leftover Jobs/Pods beyond the history counts as a fallback (archive verification 3 days, physical baseline 7 days, logical backup 7 days);
  - timeout fallback: `activeDeadlineSeconds` = 2h for logical backup, 6h for physical baseline, 10min for archive verification (must be < the 15min schedule interval);
  - any Job failure = archive chain/baseline problem → production hooks `kube_job_failed`-style alerts (`deploy/observability` covers application
    metrics only; Job failure alerts must be configured on the platform side); handling procedure in `deploy/production/backup/README.md` §3.

```bash
# logical backup restore
mc cp lattice-cold/backup/pg/lattice-20261121T030000Z.dump .
pg_restore --clean --if-exists -d "$PG_URL" lattice-20261121T030000Z.dump
```

> Limitation: `pg_dump` is a daily full baseline, **not PITR**; RPO depends on PG's WAL archive chain (the database side is responsible,
> and the chart only does baseline + verification, not `archive_command`). For `lattice-cold`, enable versioning + object lock (⑥ §4.1).

## 8. Upgrade and rollback

- nodes are stateless with `RollingUpdate maxUnavailable=0`; migrations run idempotently at node startup, **forward-only** (⑥ §8);
- **Drain**: the Deployment sets `lifecycle.preStop` (`node.preStopSleepSeconds`, 10s by default) so Endpoints/LB draining propagates before SIGTERM; once draining, the node returns 503 on `/v1/ready`, rejects new `/v1/ws` connections, and existing connections receive `byef{shutdown}` (`scripts/drain-e2e.mjs` 14/14 verifies node-side behavior); `terminationGracePeriodSeconds` defaults to 45s to cover the drain window;
- destructive migrations must use the expand/contract two-phase approach, otherwise rolling back to the old image fails on missing/extra columns;
- `helm rollback` rolls back workloads only, **not the database**; for TLS/CronJob rollback see the values diff per release;
- rolling back this chart's TLS/security hardening: set `tls.*` back to false, `security.*.readOnlyRootFilesystem=false` and
  `networkPolicy.enabled=false`, then `helm upgrade` (old Pods are replaced by rolling update); no database change needed.
- **Canary rollback (see §10)**: first `--set canary.weight=0` to take 100% of traffic back to stable (canary replicas stay,
  for reading logs/reproducing issues), then `--set canary.enabled=false` to delete canary resources; `helm rollback <release> <revision>`
  reverts the whole release. Note that with canary enabled `/v1` goes from the Ingress directly to node (and back to web nginx when disabled), invisible to client URLs.

## 9. Validation (offline, no cluster required)

```bash
# 1) template level
helm lint deploy/helm/lattice \
  --set backup.enabled=true --set backup.pitr.enabled=true --set ingress.enabled=true \
  --set ingress.tls.enabled=true --set mqtt.enabled=true --set autoscaling.enabled=true \
  --set networkPolicy.enabled=true --set tls.enabled=true --set tls.certManager.enabled=true \
  --set tls.grpc.enabled=true --set tls.mqtt.enabled=true --set tls.quic.enabled=true \
  --set tls.http.web.enabled=true

helm template lattice deploy/helm/lattice -n lattice [same --set] > .dev/helm-rendered.yaml
```

`helm template` only guarantees template syntax; **structure/contract** is covered by repo scripts (none need a cluster):

```bash
python scripts/ha-prod-validate.py            #python scripts/ha-prod-validate.py            # multi-profile render + Python structure validation + production asset validation
python scripts/helm-canary-validate.py        #python scripts/helm-canary-validate.py        # canary templates + PITR scheduling assertions, plus regression of the old 47 / 182 items
python .tooling/helm-validate.py .dev/helm-rendered.yaml   #python .tooling/helm-validate.py .dev/helm-rendered.yaml   # legacy single-profile contract validation (kept for compatibility)
```

Canary-specific (off by default, affects none of the profiles above):

```bash
# canary-enabled render (default profile + weight 20 + different stable/canary tags)
helm template lattice deploy/helm/lattice -n lattice \
  --set canary.enabled=true --set canary.weight=20 --set canary.image.tag=v9.9.9 --set ingress.enabled=true

# assert canary on/off, weight 0, header split, identical env, no render by default, rollback docs present (no cluster/ingress needed)
python scripts/helm-canary-validate.py --helm .tooling/helm/windows-amd64/helm.exe
```

`scripts/ha-prod-validate.py` covers: multiple values profiles (default/full-featured/hardened/TLS off) `helm lint` + `helm template`,
resource fields/duplicate names, ConfigMap TOML parseability, TLS config paths aligned with volumeMounts, Secret key coverage,
securityContext (non-root/seccomp/read-only root/emptyDir), NetworkPolicy allowing only required ports, PDB selectors,
CronJob scheduling and retention parameters, and TLS/Patroni/PITR asset structure and placeholder checks under `deploy/production/**`.
Where kubeconform is unavailable the script falls back to Python structure validation (`--kubeconform` can point at the binary).

`scripts/helm-canary-validate.py` covers: with canary disabled **no canary resource/annotation is rendered** (the stable render is byte-identical to
the previous version and the Deployment count is unchanged); with canary enabled the Deployment/Service/Ingress counts and backend targets, `canary-weight` (including 0
and out-of-range failure), `canary-by-header(-value)`, identical canary/stable env/volumeMounts, the stable
Service selector not selecting canary Pods (no cross-talk), NetworkPolicy/ServiceMonitor/HPA combination semantics,
canary image tag and replicas, and the `Forbid`/history retention/TTL/timeout of the PITR/backup CronJobs together with
consistency against `deploy/production/backup/README.md`; finally it regresses the old `.tooling/helm-validate.py` (47 items)
and `scripts/ha-manifest-check.py` (182/177 items).

## 10. Canary release

Off by default (`canary.enabled=false`): no canary resources are rendered, and `helm template` output is byte-identical to
the version before this feature (`scripts/helm-canary-validate.py` asserts this with a baseline render). When enabled it only **adds** resources; the stable
Deployment/Service/HPA/PDB are unchanged.

### 10.1 Implementation and tradeoffs

| Option | Verdict | Rationale |
|---|---|---|
| **Two Deployments + ingress-nginx canary annotations** (this implementation) | ✅ chosen | native K8s Services have no weight field; ingress-nginx's `canary: "true"` + `canary-weight: 0-100` and `canary-by-header(-value)` provide weighted/targeted splitting with zero extra components and pure K8s APIs |
| service mesh VirtualService/TrafficSplit | ❌ not used | more expressive but requires a mesh in the cluster; CRDs/versions couple tightly to the application chart and installation prerequisites get heavier |
| change web nginx upstream weights | ❌ not used | only covers traffic through web, and nginx weights are static config (changing them = ConfigMap change + rollout), so they cannot follow the release cadence like Ingress annotations |

Resources and traffic paths (`canary.enabled=true`):

- **canary node Deployment** `<fullname>-node-canary`: **shares** the PodSpec from `_node.tpl` with stable
  (Secret env injection, volumes, securityContext, probes and topology spread are identical); only the image tag, replica count and
  selector labels differ; the selector uses `app.kubernetes.io/component=node-canary` to stay fully separate from stable
  (the stable selector is immutable and cannot take a track label), so the stable Service **never** sends traffic to canary Pods.
- **canary node Service** `<fullname>-node-canary`: ClusterIP, only a backend for the Ingress/external LB;
  fixed at `canary.replicaCount`, **excluded from HPA/PDB** (canary instances must be stoppable at any time and not disturbed by scaling policy).
- **/v1 dual Ingress** (only when `ingress.enabled=true`):
  - `<fullname>-node-api`: `/v1` → stable node Service (the regular arm);
  - `<fullname>-node-api-canary`: same host + same path, adding only canary annotations → canary node Service.
    ingress-nginx sends `/v1` HTTP/WS/SSE traffic to canary by `canary-weight` percentage (or exact header match).
  - Why this Ingress pair exists: the chart's existing Ingress points at **web** (the console); pairing web with node-canary
    would canary the entire site. The `/v1` prefix is longer than the existing `/` (higher priority), so console routes are unaffected;
    with canary disabled this pair is not rendered and `/v1` still goes through web nginx reverse proxy (behavior matches the previous version).
  - Long-connection/upload annotation fallback: with canary enabled `/v1` goes directly to node and no longer passes web nginx, so the Ingress declares explicitly
    `proxy-read-timeout/proxy-send-timeout=3600`, SSE `proxy-buffering=off`, `proxy-body-size` (= 
    `web.clientMaxBodySize`; plugin packages of 20MiB+ need it).
- **canary NetworkPolicy** (when `networkPolicy.enabled`): reuses the stable rules (`_node.tpl` is the single source),
  changing only the podSelector—otherwise canary Pods are selected by no NP and, in a default-deny cluster, equal allow-all.
- **canary ServiceMonitor** (when `metrics.serviceMonitor.enabled`): scrapes canary metrics separately, since canary evaluation
  cannot rely on stable aggregates alone.
- **Images**: empty `canary.image.repository/tag/pullPolicy` reuse `image.*` respectively; when `canary.image.tag` is empty
  NOTES warns "same image as stable, so the canary is meaningless".

### 10.2 Usage steps (recommended cadence)

```bash
# 1) deploy canary with 0% traffic first (pre-check: image pulls, ready, no anomalies in logs)
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values \
  --set canary.enabled=true --set canary.weight=0 \
  --set canary.image.tag=0.6.0-rc1 \
  --set webImage.tag=0.5.0            #  --set webImage.tag=0.5.0            # console stays stable (a node canary does not require a new frontend)
kubectl -n lattice rollout status deploy/<release>-node-canary
kubectl -n lattice logs deploy/<release>-node-canary -f

# 2) ramp in steps of 5% → 25% → 100%, observing each step for ≥10min (error rate/latency/backlog/WS reconnects)
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values --set canary.weight=5
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values --set canary.weight=25

# 3) early validation by internal accounts: match by header (unaffected by weight)
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values \
  --set canary.byHeader=x-lattice-canary --set canary.byHeaderValue=always
curl -H 'x-lattice-canary: always' https://lattice.example.com/v1/health

# 4) verify: the share of /v1 requests hitting canary ≈ weight (ingress-nginx logs/metrics; canary's own metrics below)
kubectl -n lattice get ingress <release>-node-api-canary -o yaml | grep -E 'canary-(weight|by-header)'
```

### 10.3 Rollback (stop the bleeding in seconds first)

```bash
# a) 0% traffic to canary: canary replicas kept (logs/repro), stable takes 100% — the fastest way to stop the bleeding
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values --set canary.weight=0

# b) delete canary resources entirely (back to pure stable; /v1 is served by web nginx reverse proxy again)
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values --set canary.enabled=false

# c) roll back stable to the previous revision as well (including image tag/config)
helm rollback <release> <previous revision>
```

> Do not roll back by "deleting the Ingress/changing selectors": once the canary Ingress is deleted on its own, `/v1` falls back to the web reverse proxy
> (it works, but switches the traffic path); controlling it through values is declarative and auditable.

### 10.4 Observability and judging

- canary metrics: with `metrics.serviceMonitor.enabled` use the canary ServiceMonitor; otherwise
  scrape `/metrics` via `kubectl -n lattice port-forward svc/<release>-node-canary 9101:9100`;
- key judgments: canary's 5xx rate, P99 latency, WS disconnects/reconnects and `lattice_backpressure_dropped_total`,
  compared with stable over the same time window; **any significant degradation → weight=0**, do not wait for 100% rollout;
- node version observability: Pod image tag / `kubectl get pods --show-labels` (`lattice.io/track=canary`) are used to
  confirm which version traffic landed on; "hello response carries the node version" from the design is a node-side TODO, and this chart does not change the protocol.

### 10.5 Unverified boundaries (must not be treated as accepted)

1. This host has **no real K8s/ingress-nginx**: weight splitting, `canary-by-header` behavior and `/v1` vs prefix priority only have
   render assertions and are **not verified by capturing traffic on a real controller**; confirm the ratio with `curl` counting in staging before going live.
2. **MQTT/QUIC device traffic is out of scope for this canary**: device connections are stateful, and randomly shifting 5% means devices randomly reconnect to the new version;
   device canaries should use device-scoped configuration or a separate access pool (the chart does not do this).
3. **External LB weights are not covered**: in the production topology (`deploy/production/README.md` §1) traffic from Nginx/Envoy directly to node
   does not pass this chart's Ingress, and its canary weight is configured on the external LB; the chart only provides the stable/canary Services.
4. **HPA/PDB/anti-affinity do not cover canary**: canary has fixed replicas and no PDB/HPA; canary may be evicted during node draining
   (interruptibility of canary instances is a deliberate tradeoff).
5. gRPC (9090) and same-node internal calls are still decided by the stable/canary Service DNS; no proportional gRPC splitting is done.
6. `helm upgrade --reuse-values` and Ingress annotation hot-reload behavior on a real cluster are unverified (asserted at template level only).

See [`deploy/production/canary-runbook.md`](../../production/canary-runbook.md) (production canary/rollback runbook and
acceptance checklist) and the unverified list in [`deploy/production/README.md`](../../production/README.md) §7.
