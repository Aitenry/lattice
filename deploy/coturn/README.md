# TURN (coturn) deployment

TURN runs as a separate service. Media flows through coturn, never through Lattice nodes; nodes only expose `GET /v1/media/turn-credentials` to issue short-lived coturn REST API credentials.

## Node-side configuration

```toml
[media]
turn_uris = ["turn:turn.example.com:3478?transport=udp", "turn:turn.example.com:3478?transport=tcp"]
turn_ttl = 600          # capped at 600s server-side
# Production: inject the secret through a Secret or environment variable, never a ConfigMap or image.
# turn_secret = "<coturn static-auth-secret>"
# LATTICE__MEDIA__TURN_SECRET=<coturn static-auth-secret>
```

The endpoint returns `enabled=false` without an error when `turn_uris` or `turn_secret` is empty, so TURN stays an optional acceleration path. Credentials follow the coturn convention: username `<expiry_unix>:<user_id>`, credential `base64(HMAC-SHA1(secret, username))`.

## coturn configuration

- Template: [`turnserver.conf`](turnserver.conf); `REPLACE_WITH_SECRET_FROM_SECRET_MANAGER` is rendered from a Secret.
- Key items: `use-auth-secret` and `static-auth-secret` (the same value as the node's `turn_secret`), `fingerprint`, `min-port`/`max-port` (open the matching UDP range in security groups or NetworkPolicy), production `external-ip`, and TURN over TLS recommended on 5349.
- Never put the secret in images, ConfigMaps, or logs. Rotate coturn and the node environment together; credentials issued before the rotation stop working immediately, and any credential has a maximum lifetime of `turn_ttl`.

## Development profile

```bash
# start only coturn; the default development stack is untouched
docker compose -f deploy/compose/dev.yaml --profile turn up -d turn

# self-check: compute a credential and run a real allocation inside the container
expiry=$(( $(date +%s) + 600 ))
username="$expiry:test-user"
credential=$(printf %s "$username" | openssl dgst -sha1 -hmac "${TURN_SECRET:-lattice_dev_turn_secret}" -binary | base64)
docker exec lattice-dev-turn turnutils_uclient -v -c -O -n 1 -p 3478 -u "$username" -w "$credential" 127.0.0.1

# stop coturn
docker compose -f deploy/compose/dev.yaml --profile turn down turn
```

The development secret defaults to `lattice_dev_turn_secret` (override with `TURN_SECRET`), matching [`../compose/dev.yaml`](../compose/dev.yaml). The computed credential uses the same algorithm and TTL as `GET /v1/media/turn-credentials`.

## Production considerations

- LB/security groups: allow UDP 3478 and TCP 3478 (or TLS 5349) plus the relay port range; on Kubernetes use the UDP Service shape in [`../quic-lb-udp.yaml`](../quic-lb-udp.yaml).
- Capacity: estimate relay bandwidth per stream × concurrency; `total-quota` and `bps-capacity` guard against abuse.
- Observability: coturn logs and metrics plus node metrics such as `lattice_grpc_route_fallback_total`; alert on credential and allocation errors.
- High availability: multiple instances behind DNS round-robin or an L4 load balancer; credentials are stateless HMAC values, so instances scale out with the same secret.

## Unvalidated boundaries

- `external-ip` across NAT or the public internet, TURN over TLS/DTLS, production cluster capacity, and coordinated secret rotation between coturn and the node are outside what these templates validate.
- The templates describe the intended deployment; they are not a capacity or interoperability result.
