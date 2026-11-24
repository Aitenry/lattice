# Production TLS and mTLS certificate templates

> **Status: copyable template, not an issued certificate system.** No cert-manager, Vault, or KMS is available
> here, no certificate has been issued, and no TLS or mTLS handshake has been performed. All steps are unexecuted.

## Termination points

| Interface | Terminates TLS | Code facts | Certificate mount | mTLS |
|---|---|---|---|---|
| HTTP/WS | Ingress controller, LB, or web nginx 8443 | The node only binds `[node] listen_http` in [`main.rs`](../../../crates/lattice-node/src/main.rs); no HTTPS/WSS listener exists and 8080 is plaintext | Ingress TLS Secret (`ingress.tls.secretName`) or web nginx `/etc/nginx/tls` (`tls.http.web`) | Optional (Ingress client CA or nginx `ssl_verify_client`) |
| MQTT | The node, `[mqtt] tls_enabled`, port 8883 | `require_client_cert=true` rejects a missing or bad client certificate during the handshake (fail-closed) | `/etc/lattice/tls/mqtt/`: `server.crt`, `server.key`, `client-ca.crt` (Secret `lattice-node-mqtt-tls`) | Yes, device X.509 identity |
| gRPC | The node, `[grpc] tls_*`, internal 9090 | Setting `tls_cert`, `tls_key`, and `tls_client_ca` enables mTLS; `require_known_node_cn` requires a known `node_id` CN | `/etc/lattice/tls/grpc/`: `server.crt`, `server.key`, `ca.crt` (Secret `lattice-node-grpc-tls`) | Yes, node-to-node |
| QUIC/WebTransport | The node, `[quic] cert/key`, UDP 4433 | rustls server-side TLS; client certificates are not authenticated, identity relies on `stream-sig` plus the join token | `/etc/lattice/tls/quic/`: `server.crt`, `server.key` (Secret `lattice-node-quic-tls`) | No |
| PostgreSQL, Redis, NATS, MinIO | Each component or a fronting LB | Component-specific; see [`patroni/README.md`](../patroni/README.md), [`redis/README.md`](../redis/README.md), `nats-*.conf`, and [`minio/README.md`](../minio/README.md) | Each component's certificate or Secret mount | PostgreSQL optionally `hostssl`; Redis and NATS optional |

Do not configure TLS on the node's 8080: no listener exists there, so restrict 8080 to the cluster network and terminate external traffic at the Ingress or LB.

## Trust root

The issuer hierarchy is an internal root CA with its key offline, a cert-manager CA `ClusterIssuer` that issues the
gRPC, MQTT, and QUIC certificates, and a separate device CA for MQTT client certificates outside the cluster; public
Ingress domains use an ACME `ClusterIssuer`. Only the issuing CA key lives in the cluster, in the Secret behind the
CA `ClusterIssuer`. gRPC `usages` include both `server auth` and `client auth`, so one certificate serves inbound
mTLS and the node's outbound identity, and device private keys never enter the cluster.

## cert-manager flow

Prerequisite: cert-manager is installed and the `certificates.cert-manager.io` CRD exists. The chart does not
create Issuers.

```bash
# Create the internal CA offline; the private key stays in CA custody
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 -keyout lattice-ca.key -out lattice-ca.crt \
  -subj "/CN=Lattice Internal CA/O=Lattice" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Load the CA key pair into the cert-manager namespace (restrict RBAC)
kubectl -n cert-manager create secret tls lattice-internal-ca-key-pair \
  --cert=lattice-ca.crt --key=lattice-ca.key

# Apply the ClusterIssuers and example Certificates, or let the chart render them
kubectl apply -f deploy/production/tls/cert-manager.yaml
helm upgrade --install lattice deploy/helm/lattice -n lattice \
  --set tls.enabled=true --set tls.provider=certManager --set tls.certManager.enabled=true \
  --set tls.certManager.issuerRef.name=lattice-internal-ca

# Verify readiness and Secret keys
kubectl -n lattice get certificate
kubectl -n lattice get secret lattice-node-grpc-tls -o jsonpath='{.data}' | tr ',' '\n'
```

Defaults are `duration: 2160h` (90 days) and `renewBefore: 360h` (renew 15 days early), and
`privateKey.rotationPolicy: Always` rotates the key on every renewal. Roll-restart node and web after rotation
because certificates are read only at startup: `kubectl -n lattice rollout restart deploy/lattice-node`. MQTT
device rotation runs old and new client CAs in parallel in device management before retiring the old one.

## sealed-secrets flow

For GitOps, encrypt each Secret into a `SealedSecret` with
[sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) before committing; only the target cluster's
controller key can decrypt it, and the object is bound to a namespace and name.

```bash
# Build the Secret from PEM files kept outside version control
kubectl -n lattice create secret generic lattice-node-grpc-tls \
  --from-file=server.crt=./server.crt --from-file=server.key=./server.key \
  --from-file=ca.crt=./ca.crt --dry-run=client -o yaml > grpc-tls-secret.yaml

# Encrypt with the cluster public key
kubeseal --format yaml --cert ./sealed-secrets-pub.pem < grpc-tls-secret.yaml > grpc-tls.sealed.yaml

# Apply and confirm decryption
kubectl apply -f grpc-tls.sealed.yaml
kubectl -n lattice get sealedsecret lattice-node-grpc-tls     # READY=True
```

[`sealed-secret.example.yaml`](sealed-secret.example.yaml) shows only the manifest shape; its `encryptedData`
values are invalid placeholders and it must not be applied. Also seal `lattice-node-mqtt-tls`,
`lattice-node-quic-tls`, `lattice-web-tls`, the ingress TLS Secret, `lattice-jwt-keys`, and
`lattice-prod-secrets`.

## Secret contract

| Item | Requirement | Why |
|---|---|---|
| Granularity and key names | One Secret per component, fixed key names from the table below, PEM and passwords only | Limits blast radius, keeps rotations independent, and the chart mounts by key name |
| Mount and RBAC | `defaultMode: 0400`; mount only needed keys; node and web set `automountServiceAccountToken: false` | Other users cannot read the key and the process does not need the Kubernetes API |
| Values and git | No private keys or passwords in values; `--set` passwords leak into the release Secret | Use `existingSecret` in production |
| CA private key and backup | CA key offline, KMS, or Vault; back it up separately from etcd | Root CA compromise means reissuing everything; without the key no new certificates can be issued |

| Secret | Keys | Purpose |
|---|---|---|
| `lattice-node-grpc-tls` | `server.crt`, `server.key`, `ca.crt` | gRPC mTLS (`[grpc] tls_cert`, `tls_key`, `tls_client_ca`) |
| `lattice-node-mqtt-tls` | `server.crt`, `server.key`, `client-ca.crt` | MQTT TLS/mTLS (`[mqtt] tls_*`, `client_ca`) |
| `lattice-node-quic-tls` | `server.crt`, `server.key` | QUIC/WebTransport TLS (`[quic] cert/key`) |
| `lattice-web-tls`, Ingress `tls.secretName` | `tls.crt`, `tls.key` (optional `ca.crt`) | web nginx 8443 and Ingress/LB termination |
| `lattice-jwt-keys` | `jwt.key.pem` (optional `jwt.key.prev.pem`) | RS256 signing key |
| `lattice-prod-secrets` | `pg-url`, `pg-replication-url`, `redis-url`, `s3-access-key`, `s3-secret-key`, `admin-bootstrap-password` | Business credentials (`secrets.existingSecret`) |

## Rotation and revocation

1. cert-manager renews before `renewBefore`; to force it run `kubectl cert-manager renew`. In sealed-secrets mode,
   regenerate the PEM, re-run `kubeseal`, and commit.
2. Validate the new certificate:
   `kubectl -n lattice get secret lattice-node-grpc-tls -o jsonpath='{.data.server\.crt}' | base64 -d | openssl x509 -noout -dates -subject -ext subjectAltName`.
3. Roll-restart node and web, then watch `/v1/ready` return 200 and `kubectl rollout status` complete.
4. Update client and device trust bundles, and remove the old certificate from clients only after it expires.
5. Record serial number, validity, restart time, and blast radius.

For revocation after key compromise, revoke with the CA (`openssl ca -revoke` or Vault), issue a replacement,
update the Secret, roll-restart, and update device trust. If the root CA is compromised, rebuild the trust root and
reissue everything.

## Verification

```bash
# Chain and validity; no cluster required
openssl verify -CAfile ca.crt server.crt
openssl x509 -in server.crt -noout -subject -dates -ext subjectAltName

# Real handshakes need a reachable endpoint; none has been run here (QUIC needs OpenSSL 3.2 or newer)
openssl s_client -connect pg-lattice.example.internal:5432 -servername pg-lattice.example.internal -CAfile ca.crt </dev/null
openssl s_client -connect mqtt.example.internal:8883 -cert device.crt -key device.key -CAfile client-ca.crt </dev/null
openssl s_client -connect ingress.example.internal:443 -servername ingress.example.internal </dev/null
grpcurl -cacert ca.crt -cert client.crt -key client.key -d '{}' node.example.internal:9090 lattice.internal.v1.NodeInternal/Heartbeat
openssl s_client -quic -connect quic.example.internal:4433 -alpn h3 -CAfile ca.crt </dev/null
```

With a reachable kubeconfig, `kubectl apply --dry-run=client -f deploy/production/tls/cert-manager.yaml` checks
the manifests against the cluster API schemas. Confirm no private key was committed with
`grep -R "BEGIN .*PRIVATE KEY" deploy/production/tls`, which should return nothing.

## Unvalidated boundaries

1. cert-manager is not installed and no certificate has been issued, so the `Certificate` readiness path is untested.
2. No TLS or mTLS handshake has been performed against PostgreSQL, Redis, NATS, MinIO, the node, or the Ingress; chain, SAN, and protocol versions are unverified.
3. Rolling restart and connection migration after rotation are untested, especially for long-lived WebSocket and MQTT sessions.
4. sealed-secrets decryption, GitOps sync, Ingress/LB termination, client CA verification, and the web nginx 8443 shape are untested.
5. The device certificate lifecycle is untested, and public ACME automation with DNS challenge is not provided.

## Rollback

| Scenario | Action |
|---|---|
| Files in this directory (not deployed) | Delete `deploy/production/tls/`; they hold no cluster state |
| TLS enabled and handshakes fail | Set `tls.enabled` and the `tls.*` flags back to false with `helm upgrade` and roll-restart; do not just delete the Secret or Pods hang on the mount |
| Wrong certificate issued | Roll back `issuerRef` or Certificate parameters, then `kubectl delete certificate` to trigger reissue; keep the Secret so the old certificate still serves |
| Private key compromise | Revoke, reissue, and roll-restart; rebuild the root if the CA is compromised |
| SealedSecret cannot be decrypted | Check the namespace and name binding and the controller public key; roll back the GitOps commit and use a manual Secret as an emergency measure |
