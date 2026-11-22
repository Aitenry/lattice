# TURN (coturn) deployment skeleton

 TURN is **deployed separately** per design §17.9: media flows through coturn, never through Lattice nodes. Nodes only expose
 `GET /v1/media/turn-credentials` (⑤ §9.7) to issue short-lived coturn REST API credentials.

## 1. Node-side configuration (② §4.2.1)

```toml
[media]
turn_uris = ["turn:turn.example.com:3478?transport=udp", "turn:turn.example.com:3478?transport=tcp"]
# Production must inject these via Secret/env; never write them into a ConfigMap or image
# LATTICE__MEDIA__TURN_SECRET = <coturn static-auth-secret>
turn_ttl = 600          # ≤600s, truncated server-side at the upper bound
```

## 2. coturn configuration

- Template: [`turnserver.conf`](turnserver.conf) (`REPLACE_WITH_SECRET_FROM_SECRET_MANAGER` is rendered from a Secret);
- Key items: `use-auth-secret` + `static-auth-secret` (same as the node's `turn_secret`), `fingerprint`,
  `min-port/max-port` (open UDP in security groups/NetworkPolicy), production `external-ip`, TURN over TLS recommended on 5349;
- **Never** put the secret in images, ConfigMaps or logs; when rotating, update coturn and the node env together, and old credentials expire after at most `turn_ttl`.

## 3. dev (compose profile)

```powershell
# Start only coturn (leaves the default dev stack untouched)
docker compose -f deploy/compose/dev.yaml --profile turn up -d turn

# Self-check: run a real allocation inside the container with turnutils_uclient
docker exec lattice-dev-turn turnutils_uclient -v -c -O -n 1 -p 3478 \
  -u "<expiry>:<user_id>" -w "<credential>" 127.0.0.1
```

 The dev secret defaults to `lattice_dev_turn_secret` (overridable via `TURN_SECRET`), consistent with the verification approach in `scripts/turn-coturn-e2e.mjs`;
 stop it after capturing evidence: `docker compose -f deploy/compose/dev.yaml --profile turn down turn`.

## 4. Production considerations (not drilled in dev)

- LB/security groups: allow UDP 3478/TCP 3478 (or TLS 5349) plus the relay port range; on K8s use the UDP Service shape in `deploy/quic-lb-udp.yaml`;
- Capacity: estimate relay bandwidth per stream × concurrency; `total-quota`/`bps-capacity` guard against abuse;
- Observability: coturn's own logs/metrics plus node metrics such as `lattice_grpc_route_fallback_total`; alert on credential expiry/error rates;
- High availability: multiple instances behind DNS round-robin/LB; credentials are stateless HMAC and do not depend on coturn local state, so scale out horizontally with the same secret.

## 5. Verified / not verified

- ✅ Node credential algorithm against real coturn allocations: `scripts/turn-credentials-test.mjs` 11/11, `scripts/turn-coturn-e2e.mjs` 7/7
  (fresh credentials allocate, expired credentials are rejected, wrong secret is rejected).
- ⚠️ Not verified: `external-ip` across NAT/public internet, TURN over TLS/DTLS, production cluster capacity, secret rotation and the old-credential window.
