# Production TLS / mTLS certificate system (template, not integration-tested)

> **Status: a copyable template, not an issued certificate system.** This machine only has a single-host
> dev environment — no cert-manager, no Vault/KMS, no second host — so the contents of this directory
> have **only been structurally validated offline** (`python scripts/ha-prod-validate.py` production asset
> checks); **no certificate has ever been issued and no real TLS/mTLS handshake has ever been performed**.
> When "production TLS achieved" may be declared: after completing the certificate issuance/rotation/
> revocation drill per §7 on a real cluster and filing the evidence.
>
> Design basis: the design document (outside this repository) §17 (transport security), ② §7 (deployment), ⑤ §10/§11 (gRPC/MQTT).
> For Helm-side values/templates see [`deploy/helm/lattice/README.md`](../../helm/lattice/README.md) §4.

Lattice's TLS termination points are **not uniform**; they fall into three classes by interface (aligned
with what the code actually does — do not configure from assumptions):

| Interface | Who terminates TLS | Code facts | Certificate mount / Secret | mTLS |
|---|---|---|---|---|
| **HTTP / WS** | Ingress Controller, LB, or web nginx (optional 8443) | The node only binds `[node] listen_http` (`crates/lattice-node/src/main.rs`); there is **no** built-in HTTPS/WSS listener; 8080 inside the cluster is always plaintext | Ingress TLS Secret (`ingress.tls.secretName`) or web nginx `/etc/nginx/tls` (`tls.http.web`) | Optional: Ingress client CA annotation / nginx `ssl_verify_client` |
| **MQTT** | The node itself (`[mqtt] tls_enabled`, default port 8883) | `mqtt.tls_*` configuration items; with `require_client_cert=true`, **a missing or bad certificate is rejected during the handshake** (fail-closed) | `/etc/lattice/tls/mqtt/`: `server.crt` / `server.key` / `client-ca.crt` (Secret `${RELEASE}-mqtt-tls`, default `lattice-node-mqtt-tls`) | **Yes** (device certificate X.509 identity, ⑤ §11) |
| **gRPC** | The node itself (`[grpc] tls_*`, internal 9090) | All three of `tls_cert/tls_key/tls_client_ca` = mTLS; `require_known_node_cn` requires the client CN to be a known `node_id` | `/etc/lattice/tls/grpc/`: `server.crt` / `server.key` / `ca.crt` (Secret default `lattice-node-grpc-tls`) | **Yes** (node-to-node calls) |
| **QUIC / WebTransport** | The node itself (`[quic] cert/key`, UDP 4433) | rustls server-side TLS; the QUIC layer **does not authenticate client certificates**, identity relies on `stream-sig` + join token | `/etc/lattice/tls/quic/`: `server.crt` / `server.key` (Secret default `lattice-node-quic-tls`) | No (server-side TLS) |
| PG / Redis / NATS / MinIO | Each component itself or a fronting LB | See the component READMEs (`patroni/README.md` §TLS placeholder, `redis/sentinel.conf`, `nats-*.conf`, MinIO SSE) | Each component's own certificate/Secret mounts | PG optionally `hostssl`; NATS/Redis optional |

> Do not configure TLS directly on the node's 8080: the code has no such listener, so the configuration
> has no effect; in production 8080 should only be reachable inside the cluster via NetworkPolicy (see
> Helm chart §5), with all external traffic going through Ingress/LB.

## 1. Trust root and certificate hierarchy (recommended)

```
internal CA (root, private key stored offline)   public domain certificate (optional, ACME)
 └─ cert-manager ClusterIssuer (CA)              └─ ClusterIssuer (ACME) ── Ingress domain
     ├─ lattice-node-grpc-tls   (serverAuth + clientAuth, SAN=node Service DNS)
     ├─ lattice-node-mqtt-tls   (serverAuth, SAN=node Service DNS/mqtt)
     ├─ lattice-node-quic-tls   (serverAuth, SAN=node Service DNS)
     └─ config-client CA        ──► device certificates (MQTT mTLS, issued by device management/factory, never enter K8s)
```

- Keep the **root CA private key offline or in KMS/Vault** — never in the cluster, never in git; only the
  **issuing CA key** lives in the cluster (the Secret behind the cert-manager `ca` Issuer, readable only in
  the cert-manager namespace).
- gRPC certificate `usages` include both `server auth` + `client auth`: the same certificate serves both as
  server and as outbound client (the node reuses `tls_cert/tls_key` for egress), avoiding two Secrets whose
  rotation could drift apart.
- MQTT device certificates are issued by a **separate client CA** (separate from the cluster internal CA):
  device private keys must never enter the cluster, and their exposure surface differs.
- If the Ingress domain faces the public internet, issue a separate Certificate via ACME
  (Let's Encrypt/enterprise CA); use the internal CA for internal mTLS.

## 2. cert-manager flow (chart `tls.provider=certManager`)

Prerequisite: cert-manager is installed in the cluster (CRD `certificates.cert-manager.io` exists).
**Issuers/ClusterIssuers are not part of the Helm chart** — a cluster-level trust root should not be managed
by an application chart; ops pre-creates it:

```bash
# 1) Generate the internal CA (on an offline machine; the private key stays only in CA custody)
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 -keyout lattice-ca.key -out lattice-ca.crt \
  -subj "/CN=Lattice Internal CA/O=Lattice" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# 2) Put the CA key pair into the cert-manager namespace (referenced by the CA Issuer; restrict RBAC)
kubectl -n cert-manager create secret tls lattice-internal-ca-key-pair \
  --cert=lattice-ca.crt --key=lattice-ca.key

# 3) Create the ClusterIssuer (manifest: lattice-internal-ca in cert-manager.yaml in this directory)
kubectl apply -f deploy/production/tls/cert-manager.yaml

# 4) Render the Certificate from the chart (or apply the Certificate example in the manifest directly)
helm upgrade --install lattice deploy/helm/lattice -n lattice \
  --set tls.enabled=true --set tls.provider=certManager --set tls.certManager.enabled=true \
  --set tls.certManager.issuerRef.name=lattice-internal-ca

# 5) Verify (Certificate READY=True; all Secret keys present)
kubectl -n lattice get certificate
kubectl -n lattice get secret lattice-node-grpc-tls -o jsonpath='{.data}' | tr ',' '\n'
```

- The defaults `duration: 2160h` (90 days) / `renewBefore: 360h` (renew 15 days early) can be changed per
  compliance requirements;
- `privateKey.rotationPolicy: Always` = rotate the private key on every renewal (recommended; the old key is
  never written to disk);
- **Always roll-restart node/web after rotation**: the process reads certificates only at startup (kubelet
  Secret updates are not hot-reloaded): `kubectl -n lattice rollout restart deploy/lattice-node`
  (`preStop 10s + maxUnavailable=0` keeps it non-disruptive);
- MQTT device-side certificate rotation must be done in device management (run the old and new CA in
  parallel for a while, then retire the old CA).

## 3. sealed-secrets flow (GitOps, `tls.provider=existingSecret`)

Certificates/private keys never enter git: encrypt the Secret into a `SealedSecret` with
[sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) before committing (only the target
cluster's controller private key can decrypt it; bound to namespace+name).

```bash
# 1) Obtain the PEM from a secure location (input to kubectl create secret, never in the repo or shell history)
kubectl -n lattice create secret generic lattice-node-grpc-tls \
  --from-file=server.crt=./server.crt \
  --from-file=server.key=./server.key \
  --from-file=ca.crt=./ca.crt \
  --dry-run=client -o yaml > .dev/grpc-tls-secret.yaml

# 2) Encrypt with the cluster public key (the sealed-secrets controller cert; structure can be checked offline with kubeconform)
kubeseal --format yaml --cert ./sealed-secrets-pub.pem \
  < .dev/grpc-tls-secret.yaml > deploy/production/tls/sealed/node-grpc-tls.sealed.yaml

# 3) Commit the SealedSecret; after GitOps syncs, the controller decrypts it into a Secret (same keys/content as manual creation)
kubectl apply -f deploy/production/tls/sealed/node-grpc-tls.sealed.yaml
kubectl -n lattice get sealedsecret lattice-node-grpc-tls   # READY=True
```

For the manifest shape see `sealed-secret.example.yaml` (`encryptedData` must be generated by `kubeseal`;
the example is an empty shell and **must not be applied directly**). Others that need sealing:
`lattice-jwt-keys`, `lattice-prod-secrets` (pg/redis/s3 passwords), `lattice-node-mqtt-tls`,
`lattice-node-quic-tls`, `lattice-web-tls`, and the ingress TLS Secret.

## 4. Least-privilege Secret requirements (mandatory)

| Item | Requirement | Why |
|---|---|---|
| Secret granularity | **One Secret per component** (gRPC/MQTT/QUIC/JWT/DB passwords kept separate) | Compromise of one is not total loss; rotations do not entangle |
| Key-name contract | Fixed key names (table below); PEM/passwords only, no unrelated fields | The chart mounts precisely via `items`/`secretKeyRef`; a wrong key name = startup failure |
| Mount permissions | `defaultMode: 0400` (already set by the chart); mount only the keys needed | The process reads only the certificates it needs; other users in the container cannot read them |
| values/git | **Never** place private keys/passwords there; `--set` passwords end up in the Helm release secret (use existingSecret in production) | Keep private keys out of git/CI logs/Helm releases |
| K8s RBAC | node/web carry no ServiceAccount token (chart already sets `automountServiceAccountToken: false`); only ops/CI can read these Secrets | The application process does not need the K8s API; shrink the Secret read surface |
| CA private key | Offline/KMS/Vault; the cluster holds only the cert-manager CA copy | Root CA compromise = every certificate must be reissued |
| Backup | TLS Secrets are covered by the cluster etcd backup; **back up the CA private key separately offline** (otherwise no new certificates can be issued after disaster recovery) | Disaster-recovery availability |
| Audit | Certificate issuance/rotation/revocation go through a ticket, recording serial numbers/validity | Security audit requirement |

Key-name contract:

| Secret | Keys | Purpose |
|---|---|---|
| `lattice-node-grpc-tls` | `server.crt` `server.key` `ca.crt` | node gRPC mTLS (`[grpc] tls_cert/tls_key/tls_client_ca`) |
| `lattice-node-mqtt-tls` | `server.crt` `server.key` `client-ca.crt` | node MQTT TLS/mTLS (`[mqtt] tls_*`/`client_ca`) |
| `lattice-node-quic-tls` | `server.crt` `server.key` | node QUIC/WebTransport TLS (`[quic] cert/key`) |
| `lattice-web-tls` | `tls.crt` `tls.key` (optional `ca.crt`) | web nginx 8443 ssl (`tls.http.web.enabled`) |
| `<ingress tls.secretName>` | `tls.crt` `tls.key` | Ingress/LB terminating TLS for HTTP/WS |
| `lattice-jwt-keys` | `jwt.key.pem` (optional `jwt.key.prev.pem`) | RS256 signing private key (chart contract) |
| `lattice-prod-secrets` | `pg-url` `pg-replication-url` `redis-url` `s3-access-key` `s3-secret-key` `admin-bootstrap-password` | Business credentials (Helm `secrets.existingSecret`) |

## 5. Rotation procedure (certificates)

1. Trigger: cert-manager renews automatically before `renewBefore` expires (or run `kubectl cert-manager renew`
   manually; in sealed-secrets mode, regenerate the PEM + re-run kubeseal + commit).
2. Validate the new certificate: `kubectl -n lattice get secret ... -o jsonpath='{.data.server\.crt}' | base64 -d | openssl x509 -noout -dates -subject -ext subjectAltName`.
3. **Roll-restart** node (and/or web): `kubectl -n lattice rollout restart deploy/lattice-node`, then watch
   `/v1/ready` return 200 and `kubectl rollout status` complete (PDB + maxUnavailable=0 preserve capacity).
4. Sync client/device-side trust in the new chain (mTLS clients must update their CA bundle); remove the old
   certificate from clients only after it expires.
5. Record: serial number, validity, restart time, blast radius (RTO counts against the change window; the
   data plane is not involved).

**Revocation** (private key compromise): revoke with the CA immediately (`openssl ca -revoke` or Vault
revoke) → issue a replacement certificate → update the Secret → roll-restart → update the device trust
chain; if root CA compromise is suspected, rebuild the trust root per §1 and reissue everything.

## 6. Verification commands (what can be done on a single host)

```bash
# Certificate chain/validity (certificate files can be checked without a cluster)
openssl verify -CAfile ca.crt server.crt
openssl x509 -in server.crt -noout -subject -dates -ext subjectAltName

# Real handshake (needs a reachable endpoint; there is no production cluster on this machine, so this is unvalidated)
openssl s_client -connect pg-lattice.example.internal:5432 -servername pg-lattice.example.internal -CAfile ca.crt </dev/null
openssl s_client -connect mqtt.example.internal:8883 -cert device.crt -key device.key -CAfile client-ca.crt </dev/null
openssl s_client -connect ingress.example.internal:443 -servername ingress.example.internal </dev/null

# gRPC mTLS (with grpcurl; requires the proto and certificates)
grpcurl -cacert ca.crt -cert client.crt -key client.key \
  -d '{}' node.example.internal:9090 lattice.internal.NodePing/Ping

# QUIC/UDP TLS (OpenSSL ≥3.2)
openssl s_client -quic -connect quic.example.internal:4433 -alpn h3 -CAfile ca.crt </dev/null
```

The offline-checkable items are covered by `scripts/ha-prod-validate.py`: Secret key-name contract,
Secret names referenced by containers/values, `secretName`/`usages`/`dnsNames` of the Certificate CR,
certificate paths in ConfigMaps matching volumeMounts, and no plaintext private keys/passwords.
**Unvalidated**: real issuance, real handshakes, rotation/revocation, device-side certificates, and
Ingress/LB configuration.

## 7. Unvalidated boundaries (must not be skipped)

1. cert-manager is not installed and no certificate has ever been issued → the `Certificate` `Ready` path is unvalidated;
2. No real TLS/mTLS handshake has been performed (PG/Redis/NATS/MinIO/node are all untested end to end), and the certificate chain/SAN/protocol versions are unverified;
3. Rolling restart and connection migration after certificate rotation are unvalidated (especially long-lived WS/MQTT connections);
4. sealed-secrets controller decryption and GitOps sync are unvalidated;
5. Ingress/LB TLS termination, client CA verification, and the mixed form with web nginx 8443 are unvalidated;
6. The device certificate lifecycle (factory issuance/revocation/expiry) is unvalidated;
7. Public domain certificate automation is not provided (ACME account/rate limits/DNS challenge not wired).

## 8. Rollback

| Scenario | Rollback |
|---|---|
| Files in this directory (not deployed) | Just delete `deploy/production/tls/`; they are not part of runtime and hold no cluster state |
| Helm TLS enabled causing handshake failures | Set `tls.enabled/tls.*` back to false with `helm upgrade` (certificate mounts/ports disappear with the render) and roll-restart the nodes; **do not** just delete the Secret (Pods then hang on mount failure) |
| cert-manager issued the wrong certificate or cannot issue | First roll back `issuerRef`/Certificate parameters, then `kubectl delete certificate` to trigger reissue; keep the certificate Secret (the old certificate can still serve) |
| Private key compromise | Revoke + reissue + roll-restart per §5; if the root CA is compromised, rebuild the trust root per §1 |
| SealedSecret cannot be decrypted | Check the namespace/name binding and the controller public key; roll back the GitOps commit, use a manual Secret as an emergency measure, and seal it afterwards |
