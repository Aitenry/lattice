# Development → production seed

This directory brings up the isolated **production-profile** stack and seeds it with a
deliberately small slice of the development instance at `http://localhost:8088`.

```powershell
# 1. generate secrets, pin images, start the stack, wait for readiness
pwsh -File deploy/migrate/init-prod.ps1

# 2. export from dev, import into prod, copy plugin objects, verify end to end
node deploy/migrate/seed.mjs
```

The production console then runs at **http://127.0.0.1:8089** (Compose project
`lattice-prod`), next to the untouched development stack on 8088.

## What is migrated

| Data | Rows | Notes |
|---|---|---|
| Users | 3 | `admin` / Eddie, `ops` / Lucas, `user` / Mia — password hashes included, so the existing development passwords keep working |
| Plugin catalog | 4 | published plugins owned by those accounts: `global-time-zones`, `music-player`, `personal-ledger`, `task-planner` |
| Plugin versions | 4 | **only** the version each plugin points at as `latest_version`; no historical versions |
| Plugin packages + sources | 8 objects | copied between MinIO instances through the S3 API (SigV4), byte-for-byte with the recorded size/sha256 |
| Plugin install data | 7 | `hub_plugin_installs` rows for the three users: `data` jsonb, `data_rev`, `enabled`, installed `version` |

Everything else is intentionally excluded: messages, conversations, conversations members,
devices, delivery logs, read watermarks, topic offsets, audit log, metric snapshots, the
`pd-e2e` test account and its six test plugins, the removed `ui-review-demo` plugin, and all
historical plugin versions. `hub_plugin_installs.last_device` is cleared because devices are
not migrated; the installed `version` strings are kept as-is, so an installation that is
older than the latest version legitimately shows "update available" in the console.

## What the seed verifies

`seed.mjs` fails closed on any mismatch and only prints its summary after all checks pass:

1. **Fingerprints** — an MD5 over the canonical `row_to_json` text of the filtered rows is
   computed in the dev and production databases and compared for all four tables
   (installs exclude `last_device`). Counts must match too.
2. **Objects** — every package/source object is read from dev MinIO, checked against the
   database size/sha256, written to production MinIO, read back and re-hashed.
3. **API** — all three accounts log in; the catalog exposes exactly four plugins with one
   (latest) version each; every install record matches the dev `version`, `enabled`,
   `data_rev` and carries a `data` payload; ownership is intact (`/v1/hub/mine`).
4. **Downloads** — each package and source download returns `302` with the expected
   `x-content-sha256`/`x-content-length`, then the transfer plane streams bytes whose hash
   matches; an invalid capability token is `404`.
5. **Console** — `http://127.0.0.1:8089` serves the SPA and proxies `/v1`.
6. **Cleanup** — verification downloads bump the download counters asynchronously, so the
   seed restores the exact dev counters, deletes the verification devices and audit rows,
   blanks `LATTICE__ADMIN__BOOTSTRAP_PASSWORD`, reloads the node and console, and asserts the
   final row counts.

## Re-running, rollback, operations

- The seed is re-runnable: it re-exports, replaces the four tables in one transaction and
  re-copies objects. A guard refuses to run once production contains message/conversation
  data, so it cannot wipe a live instance by accident.
- Rollback: `docker compose -f deploy/compose/prod.yaml down -v` removes the production
  containers and volumes; the development stack is unaffected.
- Secrets live in `deploy/config/prod.env` (git-ignored, ACL restricted to the current user).
  `init-prod.ps1` never overwrites an existing file.
- The first boot creates a throwaway bootstrap administrator because the node requires one to
  apply schema and start; the seed replaces it with the migrated `admin` (Eddie) row and then
  blanks the bootstrap password, so no bootstrap backdoor remains.
- **Rotate the three development passwords** after the first login: the production console
  keeps the development credentials by design (that is what "migrate the users" preserved).
  The `admin` account can reset them from *Users* in the console.
- The stack is a production *profile* on a single Docker host, not the HA topology. The
  console port is the only one published off loopback; PostgreSQL, Redis, MinIO, NATS, MQTT
  and the metrics/transfer ports are bound to `127.0.0.1`. TLS termination, Patroni, Redis
  Sentinel, MinIO erasure coding and multi-node gRPC/mTLS remain the assets under
  [`deploy/production/`](../production/README.md).
- NATS runs without application-level authentication in this profile because the node's
  NATS client (`async-nats 0.53`) ignores credentials embedded in the bus URL; the client
  port is loopback-only and private to the Compose network.
