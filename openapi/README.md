# `openapi/`: Lattice platform OpenAPI 3.1 contract artifact (REMAINING E05)

This directory is the **machine-readable authoritative artifact for the platform REST/SSE/probe API contract**. It consists of the single
[`lattice.openapi.yaml`](lattice.openapi.yaml) file, which maps one-to-one to
the platform API design document (Doc ⑤, v0.18; maintained outside this repository).

> Doc ⑤ remains the contract authority; this file is its equivalent machine-readable form. If the two conflict, **Doc ⑤ wins and this file must be backfilled**.

## 1. Artifact nature: hand-written, not auto-generated

- **Not** generated from Rust route macros / `utoipa`: the axum route macros stay unchanged, and no heavyweight generation dependency was introduced;
  when routes change, this file must be edited by hand in the same commit.
- Why hand-written: `utoipa` would require annotating every handler/struct and changing route macros, and its benefit (automatic drift detection)
  is already covered by the CI comparison in `scripts/openapi-diff.py`; a hand-written artifact can also capture semantics that are
  **not visible in code** in Doc ⑤ (status-code matrix, `reason`, audit actions, TTL, pagination semantics, boundaries).
- Artifact changes must land in the same commit as the implementation/Doc ⑤; CI uses the diff script to block "present in the doc but missing from the artifact".

## 2. Coverage (v1: 93 HTTP operations / 78 paths)

| Domain | Operations | Doc ⑤ section |
| --- | --- | --- |
| probes | 2 | §6 `/v1/health`, `/v1/ready` |
| auth | 3 | §1 login / refresh / logout |
| users (incl. devices) | 8 | §2 Users and devices |
| conversations | 8 | §3 Conversations and members |
| messages (incl. chunks) | 4 | §4 Message metadata / download / chunk recovery |
| uploads | 5 | §5 Large-object multipart upload |
| topics | 5 | §7 Subscriptions / unsubscriptions / history / publish |
| admin | 39 | §8.1–§8.6 Admin API (online/nodes/queues/SSE/metrics/users/devices/search/plugins/formats/config/keys/audit) |
| media | 5 | §9.7 + §8.4 Media helpers (TURN credentials, recording search/download/manifest) |
| hub | 13 | §12 User-facing plugin hub |
| ws | 1 | §9 `GET /v1/ws` upgrade entry (frame protocol in the `x-ws` extension) |
| **Total** | **93** | |

Non-HTTP protocols are registered as **top-level extensions** (not disguised as REST operations):

- `x-ws`: frame format, per-frame limits, 13 commands (hello/byef/envelope/chunk/ack/receipt/
  ping/pong/keepalive/stream-sig/stream-data/request-chunks/error), and heartbeat parameters for `/v1/ws`;
- `x-mqtt-gateway`: MQTT topic mapping, QoS/auth/rate limiting, and "current implementation boundaries" (§11);
- `x-grpc-services`: 6 internal gRPC methods (NodeInternal 4 + PluginSidecar 2) with timeout/failure behavior (§10);
- `x-openapi-provenance`: artifact provenance and coverage counts (for the diff script/audit checks).

## 3. General conventions (aligned with Doc ⑤ §0)

- **Authentication**: global `bearerAuth` (RS256 access JWT); operations with `security: []` (probes, login/refresh, ws upgrade,
  and the internal-network `/v1/admin/metrics`) require no authentication.
- **Idempotency**: all write operations (POST/PUT/PATCH/DELETE) take an optional `Idempotency-Key` parameter; semantics are in
  [`crates/lattice-node/src/transport/http/idempotency.rs`](../crates/lattice-node/src/transport/http/idempotency.rs).
  Note: Doc ⑤ §0.3 writes `details.reason` for "same key, different request body" as `idempotency_mismatch`,
  while the REMAINING E12 task card specifies `idempotency_conflict`; the middleware emits both
  `details.reason = idempotency_conflict` and `details.contract_reason = idempotency_mismatch`,
  so clients should parse leniently by `CONFLICT` + the `reason` prefix.
- **Pagination**: offset-based `page/page_size` (default 1/50; hub catalog defaults to 20 and caps at 100); cursor-based
  `before_seq/after_seq/limit` (half-open interval, default 50); responses are wrapped as `{items, next_cursor?, total?}`.
- **Errors**: unified `{code, message, envelope_id?, details?, trace_id}`; the HTTP status ↔ code mapping is in
  `components.schemas.ErrorCode` (`AUTH_FAIL/FORBIDDEN/NOT_FOUND/CONFLICT/PROTOCOL/TOO_LARGE/
  FORMAT/RATE/QUOTA/PLUGIN/INTERNAL`). Every operation's `4xx/5xx` responses are reused via `components.responses`.
- **Rate-limit headers**: `X-RateLimit-*`, `X-Quota-Storage-*`, `Retry-After` (429/503).
- **Versioning**: path version `/v1`; breaking changes require running `/v2` in parallel (Doc ⑤ §0.8).

## 4. Difference validation (runnable in CI)

```powershell
# Repository root; anything missing -> exit 1, CI blocks
python scripts/openapi-diff.py

# Machine-readable report (CI artifact)
python scripts/openapi-diff.py --json --report .dev/openapi-diff.json

# Strict mode: EXTRA and §13 count differences also fail (recommended once before a release)
python scripts/openapi-diff.py --strict
```

What the script does:

1. Parse the **per-route inventory** of Doc ⑤ §1–§12: route table rows (including merged forms such as `| POST | `/x/suspend` \| `/resume` |`),
   `METHOD /v1/...` entries in section headings, and inline endpoints in body text such as §12.7;
   automatically drop **counter-examples/planned items** from the doc (for example `GET /v1/admin/archive/search` in §14 I6
   and `GET /v1/messages/{<id>.c0}` in §4.4).
2. Parse the artifact's `paths` + methods, normalize path templates (`{id}`/`{t}`/`{ns}`/`{v}` all become `{p}`), and compare:
   - **MISSING** (in the doc, absent from the artifact) -> exit 1;
   - **EXTRA** (in the artifact, not itemized in the doc list) -> WARN by default, exit 1 with `--strict`;
     `GET /v1/ws` is the WS upgrade entry (the doc registers it only as "13 commands"), so it is allowlisted and not counted as EXTRA.
3. Cross-check the **§13 "API inventory vs. implementation" count table** (auth 3 / users·devices 5 / admin 35 / hub 13 …);
   that table uses the **legacy v0.6 basis** (the §2/§7/§8 lists are more detailed), so differences are emitted as WARN with a three-column comparison:
   `declared / per-doc-item / openapi`, to support manual alignment; it only fails with `--strict`.
4. Validate non-HTTP boundaries: `x-ws.commands == 13`, `x-grpc-services` method count `== 6`, and `x-mqtt-gateway` is present.

Environments without PyYAML automatically fall back to a **dedicated indentation parser** (paths/methods remain complete; WS/gRPC count checks still run);
CI is recommended to run `pip install pyyaml` (consistent with the existing `docs` job).

Minimal CI integration steps (the `docs` job in `.github/workflows/ci.yml` already runs `pip install pyyaml`):

```yaml
      - name: OpenAPI ↔ Doc ⑤ contract coverage
        run: python scripts/openapi-diff.py --json --report .dev/openapi-diff.json
```

The local full self-check `scripts/check-all.ps1` already includes this step.

## 5. Known boundaries (stated honestly)

- **The §13 count table is out of date**: `admin 35` (actual per-item count 39), `users/devices 5` (actual 8), `topics 4`
  (actual 5, since `POST /v1/topics/{t}/publish` is implemented). The diff script relies on the §1–§12 per-item list and emits WARN;
  Doc ⑤ itself is unchanged (the E05 scope is the artifact + diff script, and doc-tree changes are out of scope).
- **WS/MQTT/gRPC are not OpenAPI operations**: only protocol boundaries are registered; the actual frame/topic/RPC contracts are in Doc ⑤ §9/§10/§11.
- **Streaming and downloads have no OpenAPI-level schema**: SSE (`text/event-stream`), 302 presigned downloads, and WS frames
  only declare media types and response headers; concrete payloads are in the corresponding Doc ⑤ sections.
- **`/v1/admin/metrics` is Prometheus text**: `security: []` (Doc ⑤ §0.2 marks it as "internal network only",
  enforced by network policy rather than JWT).
- This artifact does not cover the client-side local model (Doc ④ / RytenBench contract) or the internal gRPC proto
  (authoritative in `proto/lattice.proto`).

## 6. Change process

1. Change the implementation/Doc ⑤ (in the same commit);
2. Hand-edit the corresponding path/operation/schema in `lattice.openapi.yaml`;
3. `python scripts/openapi-diff.py` -> MISSING=0;
4. Sync the counts in `x-openapi-provenance.coverage` and the §2 table in this document;
5. The artifact must keep `openapi: 3.1.0` and the JSON Schema 2020-12 dialect (this file already declares
   `jsonSchemaDialect`), and must avoid YAML anchors (to stay compatible across language parsers).
