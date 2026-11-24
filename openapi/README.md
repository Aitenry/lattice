# OpenAPI contract

`lattice.openapi.yaml` is the machine-readable contract for the platform's HTTP surface. It is written by hand, not generated from route macros, so it can describe semantics that code does not express: status-code matrices, error reasons, audit actions, TTLs, pagination rules, and implementation boundaries.

The artifact is OpenAPI 3.1 and uses the JSON Schema 2020-12 dialect.

## Coverage

The current artifact describes **97 HTTP operations across 82 paths**.

| Domain | Operations | Scope |
| --- | --- | --- |
| Probes | 2 | `/v1/health`, `/v1/ready` |
| Authentication | 3 | Login, refresh, logout |
| Users and devices | 8 | Current user, profiles, roles, quotas, suspension, purge, device registration and revocation |
| Conversations | 8 | Conversations, members, read watermarks |
| Messages and chunks | 4 | Message metadata, delivery state, chunk retrieval |
| Uploads | 5 | Multipart upload session lifecycle |
| Topics | 5 | Subscriptions, history, publish |
| Admin | 39 | Online state, nodes, queues, SSE, metrics, users, devices, search, plugins, formats, configuration, keys, audit |
| Media | 5 | TURN credentials, recording search, download, manifest |
| Plugin hub | 17 | User-facing catalog, publishing, versions, downloads, install records, statistics, and the admin review plane |
| WebSocket | 1 | `GET /v1/ws` upgrade entry; the frame protocol is in the `x-ws` extension |
| **Total** | **97** | |

Non-HTTP protocols are registered as top-level extensions rather than disguised as REST operations:

- `x-ws`: frame format, per-frame limits, the 13 commands, and heartbeat parameters.
- `x-mqtt-gateway`: topic mapping, QoS behavior, authentication, rate limiting, and implementation boundaries.
- `x-grpc-services`: the internal `NodeInternal` and `PluginSidecar` services with timeout and failure behavior.
- `x-openapi-provenance`: artifact metadata and coverage counts.

## Conventions

**Authentication.** The message and admin APIs use `Authorization: Bearer <access-jwt>`. Access tokens are RS256 and short-lived. Operations that set `security: []` are the probes, login and refresh, the WebSocket upgrade, and the internal metrics endpoint.

**Idempotency.** Every write operation accepts an optional `Idempotency-Key` header containing a ULID. Replaying the same key returns the original response with `Idempotent-Replay: true`. Reusing a key with a different request body returns `409 CONFLICT`. The scope is caller, method, path, and key, with a 24-hour retention window.

**Pagination.** Cursor-based list endpoints accept `before_seq`, `after_seq`, and `limit` (half-open interval, default 50). Offset-based endpoints accept `page` and `page_size` (default 1 and 50). Responses are wrapped as `{items, next_cursor?, total?}`. Pagination values are decimal integers; malformed values return `422 FORMAT` with a query-parameter reason.

**Errors.** Every error uses `{code, message, envelope_id?, details?, trace_id}`. The status-to-code mapping is defined in `components.schemas.ErrorCode`:

`AUTH_FAIL`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `PROTOCOL`, `TOO_LARGE`, `FORMAT`, `RATE`, `QUOTA`, `PLUGIN`, `INTERNAL`.

Shared `4xx` and `5xx` responses are reused through `components.responses`.

**Rate limits.** `X-RateLimit-*` and `X-Quota-Storage-*` headers describe the caller's remaining budget. `Retry-After` is returned on `429` and `503`.

**Versioning.** The path carries the major version (`/v1`). A breaking change requires a parallel `/v2`; additive changes keep `/v1` and update this artifact.

**Content types.** JSON for REST, `text/event-stream` for SSE, and `application/grpc` or WebSocket frames for the non-HTTP protocols. Downloads use a `302` redirect to the **transfer plane** (`{transfer.public_base_url}/t/{token}`, a short-lived HMAC capability served by `lattice-transfer`) or, when `[transfer] enabled=false`, to a legacy MinIO presigned URL. The `/t/{token}` route is a separate data plane, not part of this admin contract.

## Validation

The artifact must parse as YAML and remain structurally consistent. A minimal local check:

```bash
python - <<'PY'
import yaml

with open('openapi/lattice.openapi.yaml', encoding='utf-8') as fh:
    doc = yaml.safe_load(fh)

assert doc['openapi'] == '3.1.0'
assert doc.get('jsonSchemaDialect', '').endswith('2020-12/schema')
paths = doc['paths']
operations = [
    (path, method)
    for path, item in paths.items()
    for method in item
    if method in {'get', 'post', 'put', 'patch', 'delete', 'head', 'options'}
]
print(f'{len(operations)} operations across {len(paths)} paths')
PY
```

For a schema-aware lint, any OpenAPI 3.1 validator can consume the file; the repository does not require one for local development.

A change is ready when:

1. Every new or changed operation has a summary, parameters, request body where applicable, and all meaningful responses.
2. Error responses use the shared schemas rather than ad-hoc shapes.
3. The coverage table in this README and the `x-openapi-provenance.coverage` block match the file.
4. The file still parses and keeps `openapi: 3.1.0`, the 2020-12 dialect, and no YAML anchors.

## Change process

1. Change the implementation and this artifact in the same commit.
2. Bump `info.version` when the contract changes.
3. Update the coverage counts in `x-openapi-provenance.coverage` and in the table above.
4. If a route is removed or renamed, check the web console and the deployment probes for callers before merging.
5. Keep descriptions behavioural rather than historical: describe what the endpoint guarantees, not how an earlier revision differed.

## Boundaries

- The artifact is hand-written. There is no generated diff against Rust route definitions in this repository; review the route table and the implementation together.
- WebSocket, MQTT, and gRPC are boundary registrations. Their detailed frame, topic, and RPC contracts live in the protocol code and in `proto/lattice.proto`, not in OpenAPI schemas.
- SSE events and downloads declare media types and headers; their payloads are described in the operation documentation rather than as JSON schemas. The transfer-plane `/t/{token}` endpoint itself is intentionally outside this document (it is a separate, token-authorized data plane with its own `/healthz`, `/readyz`, `/metrics`).
- `/v1/admin/metrics` returns Prometheus text and is intentionally unauthenticated when bound to an internal interface. Restrict it with network policy or a firewall in production.
- The artifact covers the platform HTTP API only. It does not describe the desktop client's local storage model or the internal gRPC messages.
