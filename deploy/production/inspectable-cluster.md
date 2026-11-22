# Inspectable isolated cluster deployment delta list (default node-local shape vs inspectable isolated cluster)

> Work package: REMAINING **E28** (P2) / PL-15 WBS **15.12** (inspectable isolated cluster deployment checklist).
> Authoritative sources: design **§17.7** (deployment modes and naming), **§17.14** (documentation backfill),
> ② **§4.6 / §6.1 / §6.3**, ⑥ **§6 / §7**, ⑤ **§8.3 / §9.3**; decision item **D3** (KEK custodian, see design §18).
> Render validation: `python scripts/inspectable-diff.py` → `perf/reports/inspectable-diff-<date>.md|json`.
> Nature: **offline authoring + offline render comparison**; nothing is installed into any cluster, no
> containers are started, and the dev stack is not touched.

---

## 0. Conclusion in one sentence

`zero-knowledge` (default) and `inspectable` are not a "switch" on the same cluster, but **two physically
isolated deployment shapes**: the former holds no key on the node that could decrypt payloads; the latter
requires the KEK to be hosted by an external KMS/Vault so the server can decrypt for audit/scanning, and
**must be a physically isolated cluster** (dedicated LB/PG/MinIO, see design §17.7).
**In this repository, only the deployment layer of "inspectable" (mode declaration + isolated topology) is
landable today; the node-side KEK wrapping/decryption/content-audit path is still unimplemented (REMAINING
E15)** — this document enumerates item by item what is a node-local capability and what must be provided by
external components, without presenting placeholder capabilities as implemented.

---

## 1. Authoritative definitions of the two shapes

| Dimension | Shape A: default (zero-knowledge, node-local) | Shape B: inspectable (isolated cluster) |
| --- | --- | --- |
| Mode name (the only legal values) | `zero-knowledge` | `inspectable` (the v0.1 "transparent mode" is retired) |
| Can the server read payload plaintext | **No**: no decryption, no decompression, no parsing; routing/dedup read envelope headers only | By design **yes**: KEK→decrypt→audit/scan/transform→re-encrypt for downstream |
| Encryption location | SDK side only (E2E); the server holds no session key | SDK + server-side decryption chain (KEK wrapped by KMS/Vault) |
| KEK custodian | **None** (the node has no KEK) | External KMS/Vault (D3 default: node-local wrapping; high compliance may split out a dedicated decryption sidecar; **not implemented in code**, see §4) |
| Cluster boundary | Main cluster (may share infrastructure with other workloads) | **Dedicated LB + dedicated PG + dedicated MinIO** (hard requirement of design §17.7); Redis/NATS should be dedicated too, so pending/broadcast streams never cross shapes |
| Compression | SDK side | Design allows server-side compression (② §4.6); **the code currently never compresses** (`server_side_compress` returns `None`) |
| Console payload display | Never displayed (the server does not have it either) | Hidden by default; readable only through an explicit admin operation + `reason` + audit trail (⑤ §9.3; **content endpoint not implemented**, see §4) |

---

## 2. Deployment delta list (dimension by dimension)

The table below shows "what must change relative to A to run B". ✅ = an executable landing point already
exists in this repository; 🟡 = partial; ❌ = requires external implementation/environment constraints.

### 2.1 Topology and entry points

| Item | Shape A default | Shape B inspectable | Landing point |
| --- | --- | --- | --- |
| Namespace | Shared with business workloads | **Dedicated namespace** (dedicated quota + dedicated NetworkPolicy domain + dedicated RBAC) | ✅ ops side |
| Entry LB/Ingress | Main cluster entry | **Dedicated LB/Ingress**, dedicated domain/certificate domain | ✅ chart `ingress.*` (the overlay sets a dedicated host) + ops LB |
| Node replicas/topology | Shared node pool | Dedicated node pool (compliance data never lands on shared nodes), resource declaration separate from the main cluster | ✅ `node.nodeSelector/tolerations`; the rest is ops-side |
| Dependency PG | Main cluster PG | **Dedicated PG cluster** (dedicated account/database/backup chain) | ✅ point at a dedicated endpoint (URL injected via `existingSecret`) |
| Dependency MinIO | Main cluster MinIO | **Dedicated MinIO cluster** (dedicated bucket policy/accounts/SSE-KMS keys) | ✅ chart `deps.s3.endpoint/publicEndpoint` (overlay) |
| Redis/NATS | Main cluster instances | Dedicated instances (pending/broadcast/audit streams are not shared with the main cluster, preventing cross-shape leakage) | ✅ chart `deps.bus.kind/natsUrl` + `existingSecret` (Redis URL) |
| Backup/PITR | Main cluster backup chain | **Dedicated backup chain** + dedicated encryption key (SSE-KMS) + dedicated retention/object-lock policy | 🟡 chart `backup.*`/`pitr.*` are reusable, but buckets/keys must be dedicated |

### 2.2 Network policy

| Item | Shape A default | Shape B inspectable | Landing point |
| --- | --- | --- | --- |
| Inbound | The chart **renders no NetworkPolicy** by default (allow-all with external security groups as the backstop; can be enabled optionally) | **Deny inbound by default**: allow only the ingress-nginx namespace and web Pods → 8080; 9100 only from the monitoring namespace; 9090 only between nodes | ✅ chart `networkPolicy.enabled` + `ingressControllerNamespace` + `metricsNamespace` |
| Outbound | Unrestricted by default (a node connects to several dependencies) | **Deny outbound by default**: allow only DNS + the isolated PG/Redis/NATS/MinIO + the external KMS endpoint; **`0.0.0.0/0` forbidden** | ✅ chart `networkPolicy.egress.enabled/allow` (the overlay provides 5 isolated allow entries) |
| MQTT/QUIC | Enabled as needed | **Disabled** by default (smaller attack surface); when enabled, sources must be explicit (`mqttFrom`/`udpFrom`) | ✅ chart `mqtt.enabled=false` (the overlay keeps the default off) |
| Cross-shape connectivity | — | **Zero connectivity**: no business port may be reachable between A and B; only offline release artifacts are shared | ✅ policy/firewall (ops) |

### 2.3 Key custody and rotation

| Item | Shape A default (node-local) | Shape B inspectable | Landing point |
| --- | --- | --- | --- |
| Node dependency credentials (PG/Redis/S3/admin) | Chart-embedded Secret (optionally `existingSecret`) | **`existingSecret` mandatory**: hosted by the isolated namespace's Vault/ExternalSecrets/cloud KMS, the chart renders no Secret | ✅ chart `secrets.existingSecret` |
| JWT signing keys | `auth.keysSecret` (pre-created by ops, may be shared) | **Dedicated JWT key domain** (tokens are not interchangeable across shapes; the private key is generated by KMS/HSM and then injected) | ✅ chart `auth.keysSecret` (the overlay sets a dedicated name) |
| Payload session keys | Not held by the server (E2E) | Still negotiated by clients; the server unwraps via the KEK only **inside audit windows** | ❌ not implemented in code (E15) |
| KEK | **None** | KMS/Vault wrapping, **annual rotation**, dual-KEK overlap window | ❌ the node has no KMS client; `POST /v1/admin/keys/rotate {target:"kek"}` explicitly returns 202 + `implemented:false` (audit `keys_rotate` + metric `lattice_key_rotate_total`, no fake success) |
| Object storage encryption | Per main cluster policy | **SSE-KMS with dedicated keys** (a separate CMK per shape) + object lock/immutability window | 🟡 MinIO/S3 side (ops) |
| Secret rotation | Routine | Dedicated rotation cadence + two-person approval + audit | 🟡 ops process |
| Blast radius of a breach | A compromised node ≠ readable historical payloads | **A compromised node = reachable KEK = decryptable content** (the core risk of D3; high compliance needs a dedicated decryption sidecar) | ❌ D3 not finalized (design §18) |

> **D3 decision reminder**: the default is "node-local (KMS-wrapped)". If compliance requires "a compromised
> node must not leak the KEK", a dedicated decryption sidecar must be used (design §18 D3; ② §6.3). Neither
> option is **implemented** in this repository; this document only fixes the deployment deltas and check items.

### 2.4 Audit

| Item | Shape A default | Shape B inspectable | Landing point |
| --- | --- | --- | --- |
| Audit scope | Administrative/security events (login, roles, keys, releases, etc.) written to `audit_log` | Adds **content access auditing**: who read which payload, when, and with what `reason`; KEK fingerprint retained | ❌ the content access endpoint does not exist (see §4); only the audit table schema is available |
| Audit destination | PG `audit_log` | **External SIEM/tamper-proof storage** (WORM/object lock), with local hot buffering only | ❌ external integration required (the node has no SIEM exporter) |
| Audit immutability | Relies on PG backups/permissions | Dedicated audit account + append-only writes + hash chain/WORM + dedicated retention | 🟡 ops/external |
| KEK fingerprint | — | `kek_fingerprint()` reserved: read from dynamic config `kek.active_fingerprint`, **only an audit reference placeholder** (no callers today) | 🟡 placeholder exists (`pipeline/encrypt.rs`), not wired |
| Alerting | Main cluster alerting | Content access is a P1 alert with a dedicated notification path | 🟡 external rules required (PL-14 rules are reusable) |

### 2.5 Retrieval (content retrieval/metadata retrieval)

| Item | Shape A default | Shape B inspectable | Landing point |
| --- | --- | --- | --- |
| Metadata retrieval | `GET /v1/admin/messages` (filter by `id/conv/user/state`, **payload never returned**, at least one highly selective condition required) | Same | ✅ implemented (⑤ §8.3) |
| Delivery details | `GET /v1/admin/messages/{id}/delivery` | Same | ✅ implemented |
| Content reading | **Does not exist** (in zero-knowledge mode the server has no plaintext, and any content endpoint should return 403 `zero_knowledge`) | Design requires `GET /v1/admin/messages/{id}/content` (admin + explicit `reason` + audit) | ❌ **both the endpoint and content storage/index are unimplemented** (`pipeline/encrypt.rs::ensure_can_inspect` gate function exists but has no callers) |
| Full-text/content index | Not done | Possible by design (index/sensitive-word/virus scanning after decryption); **must live in a dedicated retrieval service on the isolated cluster** and not pollute the main messaging path | ❌ requires an external retrieval service (Elasticsearch/OpenSearch, etc.) and the decryption path (depends on E15) |
| Retrieval compliance | No content data | The index is equally **sensitive data**: dedicated encryption, dedicated retention, dedicated access audit | ❌ ops/external |

> Conclusion: **the "retrieval" capability cannot be provided by the node alone today.** The node only offers
> metadata retrieval; content retrieval requires (a) the E15 decryption path in place + (b) an external
> indexing/scanning service + (c) content access auditing. All three are required.

### 2.6 Performance and capacity

| Item | Shape A default | Shape B inspectable | Notes |
| --- | --- | --- | --- |
| Messaging-plane CPU | Zero knowledge: no payload parsing, lowest overhead | Per-message decryption + audit hooks + (optional) re-encryption → more CPU; the exact multiplier is **unmeasured** | Design §2 targets such as 50k connections/1500 msg/s have not been validated under inspectable |
| Compression | SDK side | Server-side compression allowed (saves bandwidth/storage, costs CPU); **the code never compresses**, so there is neither benefit nor cost today | `server_side_compress` is a placeholder returning `None` |
| Storage | Payload ciphertext (client-encrypted) | Same + content audit table/index (capacity must be declared separately) | Dedicated PG/MinIO capacity is declared separately from the main cluster |
| Node sizing | From 2C4G | Recommend a separate declaration (reserve 20–50% CPU and dedicated disk IO for decryption/audit); **this repository provides no measured capacity curve** | Environment-constrained, see §7 |
| Media plane | 8Mbps/stream, ≤5k streams/node | Media also passes through the audit cluster → higher bandwidth/storage cost; UDP ingress is off by default | Design §17.9 |

### 2.7 Compliance boundary (can an "auditable content" conclusion be issued)

| Compliance item | Shape A default | Shape B inspectable | Status |
| --- | --- | --- | --- |
| Data residency | Same domain as business workloads | Dedicated cluster/storage/backups, region declarable independently | 🟡 expressible at the deployment layer, needs a real isolated environment to validate |
| Content auditability | **No** (the server has no plaintext) | Possible by design, but requires KEK custody, content access trails, and tamper-proof audit | ❌ depends on E15; **cannot issue a "content auditing is ready" conclusion today** |
| KEK/data separation | Not applicable | KMS and PG/MinIO in different trust domains, keys never on disk | ❌ the node has no KMS integration |
| Audit independence | Ordinary | Dedicated SIEM + dedicated account + WORM | ❌ external required |
| Cross-shape data isolation | — | Zero sharing: dedicated credentials/dedicated object storage/dedicated JWT domain/dedicated audit | ✅ expressible in the values overlay (this document §3) |
| Operations admission | Routine | Two-person approval/least privilege/operation trails; KEK rotation window drills | ❌ process and real drills (environment-constrained) |
| Legal/forensics | Not applicable | Must support point-in-time export + hash verification + WORM retention | ❌ external forensic process required |

---

## 3. Deployment-layer landing: values overlay + render comparison (delivered by this work package)

### 3.1 Files

| File | Role |
| --- | --- |
| `deploy/production/inspectable/values-inspectable.yaml` | Helm values overlay for the inspectable shape (mode/isolated dependencies/dedicated Secret domain/network policy/dedicated entry point/compliance labels) |
| `scripts/inspectable-diff.py` | Renders both shapes offline and asserts "differences are limited to expected items", including negative self-tests |
| `perf/reports/inspectable-diff-<date>.md|json` | Comparison report (delta list + assertions + boundaries) |

> **Deliberately not done**: the overlay **renders no KMS/KEK Secret/environment variable/configuration
> item** — the node does not consume them, and rendering them would only create the illusion that "KMS is
> wired in". The KEK lifecycle is entirely carried by components outside the cluster (§2.3).

### 3.2 Rendering and validation (no cluster required)

```bash
# 1) Lint both shapes
.tooling/helm/windows-amd64/helm.exe lint deploy/helm/lattice
.tooling/helm/windows-amd64/helm.exe lint deploy/helm/lattice \
    -f deploy/production/inspectable/values-inspectable.yaml

# 2) Render both shapes (default vs inspectable)
.tooling/helm/windows-amd64/helm.exe template lattice deploy/helm/lattice -n lattice
.tooling/helm/windows-amd64/helm.exe template lattice deploy/helm/lattice -n lattice \
    -f deploy/production/inspectable/values-inspectable.yaml

# 3) One-shot comparison + assertions + report (recommended; CI-friendly)
python scripts/inspectable-diff.py
```

### 3.3 Expected differences (allowlist, asserted item by item by the script)

| Category | Difference | Why it is expected |
| --- | --- | --- |
| Mode declaration | ConfigMap `[policy] mode`: `zero-knowledge`→`inspectable` | The only mode switch of shape B (fixed at node startup) |
| Isolated object storage | `[s3] endpoint`/`public_endpoint` point at the dedicated MinIO | Design §17.7 requires a dedicated MinIO |
| Isolated bus | `[bus] kind=redis-pubsub`→`nats`; `nats_url` points at the dedicated cluster | Broadcast/audit streams are not shared across shapes |
| Dedicated Secret domain | The built-in `Secret/lattice-secrets` is **no longer rendered**; the `secretKeyRef` of the 5 env vars points at `lattice-inspectable-node-secrets` | `existingSecret` is mandatory (KMS/Vault custody) |
| Dedicated JWT key domain | `volumes.jwt-keys.secretName`→`lattice-inspectable-jwt-keys` | Tokens are not interchangeable across shapes |
| Network policy | Adds `NetworkPolicy/lattice-node` + `NetworkPolicy/lattice-web` | Default deny + allow only isolated dependencies (§2.2) |
| Dedicated entry point | Adds `Ingress/lattice` (dedicated host) | Dedicated LB/Ingress |
| Compliance labels | 4 node Pod annotations (deployment-mode/isolation/kek-custodian/audit-pipeline) | For the policy engine/audit collection |
| Derived item | Pod annotation `checksum/config` changes | Derived automatically from the ConfigMap content change, not manually maintained |

The script asserts that **every real difference hits the allowlist with correct key values**, that the
allowlist has no dead rules, and it runs 3 negative self-tests (change the mode value / delete an expected
NetworkPolicy / change the web replica count → the checker must report unexpected), preventing a "no-op
comparator". For the latest result see `perf/reports/inspectable-diff-20261122.md` (RESULT line).

> Common production hardening items (TLS/mTLS, backup/PITR CronJobs, HPA, web/PDB) are **not inspectable
> differences** and both shapes should stack the same chart profile; the script additionally performs one
> "inspectable overlay + hardened profile" combined render, asserting only that rendering succeeds + mode/
> network policy/no plaintext credentials, without a verbatim diff.

---

## 4. Capability ownership: what the node implements and what must be provided externally

> Authoritative code locations: `crates/lattice-node/src/pipeline/encrypt.rs`, `config.rs` (`[policy] model`),
> `transport/ws.rs` (mode reporting), `admin/mod.rs` (keys rotate / messages metadata), `crates/lattice-core/src/protocol.rs::Mode`.

### 4.1 Node-local **implemented** capabilities (usable once deployed)

> **Deployment pitfall (read this)**: `[policy] mode` performs no value validation — only the exact string `inspectable` takes effect, while `Inspectable`/`transparent`/typos are **silently treated as `zero-knowledge`**. Bringing up an inspectable cluster must assert via `helm template -f values-inspectable.yaml` that `mode = "inspectable"` is rendered, and re-check with `GET /v1/admin/config` inside the Pod; never rely on "the configuration looks like it says inspectable".

| Capability | Status | Evidence/notes |
| --- | --- | --- |
| Mode value recognition (`inspectable` / anything else falls back to `zero-knowledge`) | 🟡 | `config.rs::mode()` maps **only the literal `inspectable`** to inspectable; any other value (including typos) **silently falls back to zero-knowledge, with no error and no warning** — hence the rendered value must be asserted (`scripts/inspectable-diff.py` asserts the rendered value, not just the path), and `GET /v1/admin/config` should re-check after deployment |
| Mode fixed at process startup (not switchable at runtime) | ✅ | The mode comes from configuration, with no hot-switch API (a prerequisite of the physical isolation in design §17.7) |
| Mode reported to clients | ✅ | The WS `hello` frame carries the `mode` field (`transport/ws.rs`), and the SDK uses it to decide whether to require E2E encryption |
| **No decryption path** in zero-knowledge mode (fail-closed) | ✅ | Only the mode gate + reference functions exist; no decryption call is wired; the audit/transform path does not exist |
| Gate function rejecting "server reads plaintext" operations in zero-knowledge mode | 🟡 | `ensure_can_inspect()` exists but **has no callers today** (there is no content endpoint to attach it to) |
| KEK fingerprint reference (audit trail slot) | 🟡 | `kek_fingerprint()` reads dynamic config `kek.active_fingerprint`; **no callers** |
| Server-side compression hook | 🟡 | `server_side_compress()` exists and always returns `None` (i.e. "no compression"; semantically equivalent to no compressible benefit) |
| **Honest failure** of the KEK rotation endpoint | ✅ | `POST /v1/admin/keys/rotate {target:"kek"}` → 202 + `implemented:false`, writing audit `keys_rotate` + metric `lattice_key_rotate_total`, **never faking success** |
| Admin metadata retrieval | ✅ | `GET /v1/admin/messages?id|conv|user&state` (payload not returned) + `/{id}/delivery` |
| **Deployment expression** of dedicated keys/endpoints/network policy | ✅ | This work package's values overlay + chart (§3) |

### 4.2 Node-local **unimplemented** capabilities (REMAINING E15; must not be claimed as available)

| Capability | Gap | Impact |
| --- | --- | --- |
| KEK wrapping/unwrapping (KMS/Vault client) | No KMS client dependency or configuration item whatsoever | The server **cannot decrypt**; inspectable stops at the mode declaration |
| Dual-KEK parallel rotation window | No KEK storage/version management | `target=kek` rotation is unavailable (202+implemented:false) |
| Downstream re-encryption | No encryption implementation (the server holds no session key) | Content cannot be written back per protocol after auditing |
| Content audit hooks (sensitive words/virus scanning/content audit table ingest) | Not wired; the plugin system (WASM/sidecar) exists but is not connected to the inspectable path | No content audit conclusion can be issued |
| Content reading endpoint `GET /v1/admin/messages/{id}/content` | Route does not exist | The console's "explicitly open a payload" capability is unavailable (⑤ §9.3 contract unimplemented) |
| Content index/retrieval | None | Retrieval needs an external service (§2.5) |

### 4.3 **Must be provided externally** (hard dependencies of the inspectable shape)

| External component | Role | Deployment requirement |
| --- | --- | --- |
| KMS / Vault / HSM | Wrap the KEK, annual rotation, dual-KEK overlap, audit key operations | A separate trust domain; the node accesses it over mTLS (the chart does not render its credentials; ops injects an existing Secret/CSI) |
| Dedicated PG cluster | Messaging/audit metadata; dedicated backup chain and restore drills | Design §11/§17.13; dedicated accounts/network segment |
| Dedicated MinIO (or object storage) | Payload/chunks/plugins/cold backups; SSE-KMS with a dedicated CMK + object lock | Dedicated EC/replication topology; dedicated bucket policies |
| Dedicated Redis / NATS | Pending/connection state/broadcast and audit streams | Not shared across shapes, so content-side data cannot leak into the main cluster |
| Dedicated LB/Ingress + DNS + certificate domain | Entry isolation | Dedicated VIP/domain/certificate; not shared with the main cluster |
| Audit SIEM / WORM storage | Tamper-proof audit + P1 content access alerts | Dedicated account, dedicated retention |
| Content retrieval/scanning service | Full-text index, sensitive words, virus scanning | Reads only the decrypted isolated data, with dedicated encryption and access audit |
| Compliance/process | Two-person approval, key rotation drills, forensic export | Organizational process, not code |

---

## 5. Pre-go-live checklist (copyable)

- [ ] Dedicated namespace / node pool / quota created; resource declarations separate from the main cluster.
- [ ] Dedicated PG/Redis/NATS/MinIO ready, with addresses on a **different network segment** from the main cluster; zero cross-shape connectivity verified with network policy.
- [ ] `existingSecret` (`lattice-inspectable-node-secrets`) hosted by KMS/Vault; the chart render contains **no Secret**.
- [ ] Dedicated JWT keys (`lattice-inspectable-jwt-keys`) injected; confirm main-cluster tokens are rejected on cluster B.
- [ ] Dedicated Ingress/LB/domain/DNS in effect; a dedicated certificate domain.
- [ ] NetworkPolicy: inbound deny by default, outbound deny by default with no `0.0.0.0/0` (asserted by `python scripts/inspectable-diff.py`).
- [ ] Mode confirmed as `inspectable` (`GET /v1/admin/config` or render validation), and **confirmed that the cluster boundary is physically isolated**.
- [ ] External KMS ready, and **explicitly recorded**: the node currently has no KMS client → content audit/decryption unavailable (E15).
- [ ] Audit pipeline (SIEM/WORM) accepted; content access (once the future endpoint ships) is a P1 alert.
- [ ] Dedicated backup/PITR bucket, dedicated encryption key, and restore drill completed.
- [ ] Performance baselines declared separately as a "dedicated cluster"; re-measure after the inspectable decryption path lands (that path does not exist today, so main-cluster load-test numbers must not be cited).
- [ ] Rollback plan: see §6.

---

## 6. Rollback and change constraints

1. **The mode cannot be switched at runtime** (a prerequisite of the physical isolation in design §17.7):
   `zero-knowledge` ↔ `inspectable` can only be done by **deploying a new cluster + data migration**; there is
   no "change configuration and hot-switch" path.
2. Rolling back an inspectable cluster release = Helm `helm rollback` (the chart changes no data-plane schema);
   if a mode change is involved, the order must be "create a new isolated cluster → migrate and validate →
   switch the entry point → observe → roll back", and changing the mode in place is forbidden.
3. Data migration boundary: content-class data (payload/audit/index) **must not** be migrated back from the
   inspectable cluster to the main cluster (violates physical isolation); only metadata/configuration may be migrated.
4. Key rollback: when KEK rotation fails, roll back using the dual-KEK overlap window (the old KEK can still
   decrypt during the window); that capability is currently **unimplemented**.
5. Render-layer rollback: delete the overlay file and re-render with the default values to return to shape A
   (both shapes can use the same chart version).
6. After rollback you must re-verify: no cross-shape traffic on the entry point, no audit gaps, and a complete dedicated backup chain.

---

## 7. Unvalidated items (environment-constrained, recorded honestly)

| Item | Why unvalidated |
| --- | --- |
| Real KMS/Vault integration and KEK rotation | The node has no KMS client (E15 not closed); no KMS environment available |
| Real isolated cluster installation (dedicated LB/PG/MinIO/Redis/NATS) | Single-host Docker, no more than 3 hosts and no real LB; recorded as environment-constrained items B01/B02/B11 |
| End-to-end verification of cross-shape token/credential isolation | Requires two real clusters |
| Performance/capacity curves under inspectable (decryption/audit/compression overhead) | The decryption path is unimplemented, so there is nothing to measure; main-cluster load-test numbers are not cited |
| End-to-end trails of content access auditing | The content endpoint and audit hooks are unimplemented |
| Content retrieval/index/scanning services | Requires external components and the decryption path |
| Audit WORM/tamper-proofing and the SIEM alert path | Requires external infrastructure |
| Final D3 (KEK custodian) decision | The design §18 decision is not finalized; this document records deltas against the default (node-local wrapping) without presupposing a conclusion |

---

## 8. References

- Design the design document (outside this repository): **§17.7** deployment modes and naming; **§17.14** documentation backfill; **§18** decision D3; **§2** RTO/RPO.
- ② the platform implementation document (outside this repository): **§4.6** compression/encryption; **§6.1/§6.3** key management; **§7.5** recovery order.
- ⑥ the platform database design document (outside this repository): **§6** encryption and KMS; **§7** backup/restore.
- ⑤ the platform API document (outside this repository): **§8.3** read-only principle; **§9.3** content access contract.
- Plans: plan PL-15 (outside this repository) (15.12); plan PL-10 (outside this repository) (10.5/10.12);
  `platform/plan/REMAINING.md` (E15 / E28 / D3).
- Deployment assets: `deploy/helm/lattice/` (chart), `deploy/production/` (production skeleton).
- Render comparison: `scripts/inspectable-diff.py` → `perf/reports/inspectable-diff-<date>.md`.
