# PostgreSQL backup and point-in-time recovery

> **Status: policy and templates, not a validated backup system.** No MinIO bucket, Kubernetes cluster, or
> object-storage restore has been exercised here, and no end-to-end backup or restore drill is recorded, so
> every RPO/RTO figure below is a target or a parameter-derived bound, never a measurement.

## Backup layers

All three layers are required. The logical dump is a recovery convenience, not a PITR substitute.

| Layer | Content | Frequency | Tool and location | Restore granularity | RPO |
|---|---|---|---|---|---|
| Logical full | `pg_dump -Fc`, one database | Daily, `backup.schedule` (default `0 3 * * *`) | Helm CronJob `*-pg-backup` -> `lattice-cold/backup/pg/` | One database or table | 24h; no PITR |
| Physical base | `pg_basebackup -Ft -z -Xfetch` | Daily, `backup.pitr.baseBackupSchedule` (default `15 2 * * *`) | CronJob `*-pg-basebackup` -> `lattice-cold/wal/pg/lattice-pg/base/<TS>/` | Whole cluster | Point of the base |
| WAL archive | Every WAL segment; `archive_timeout=60s` forces a segment switch | Continuous | `archive_command` -> [`../patroni/wal-gateway.sh`](../patroni/wal-gateway.sh) -> `.../wal/` (replace with WAL-G or pgBackRest in production) | Any point in time | Target 5 min; mechanical bound is one 60s segment plus upload time |

A physical base plus the WAL archive is what makes PITR possible: restore the base, then replay WAL to
`recovery_target_time` with `recovery_target_action=promote` and `recovery_target_timeline=latest`. Setting
`recovery_target_time` without a `recovery.signal` file is a trap: PostgreSQL performs crash recovery and
reports success without stopping at the target. A logical dump cannot be replayed to a point in time.

## Schedules, retention, and Job policy

| Task | Default schedule | Retention | Notes |
|---|---|---|---|
| `pg_dump` logical full | `0 3 * * *` | `backup.keepDays=30` days | One copy per day; pruned by object timestamp with `mc rm --older-than` |
| `pg_basebackup` physical base | `15 2 * * *` | `backup.pitr.keepDays=14` days | Staggered 45 minutes from the dump so both do not load the primary at once |
| `*-pg-pitr-verify` archive check | `*/15 * * * *` | Produces no business objects | A failed Job is the alert signal |
| WAL archive | Continuous, `archive_timeout=60s` | At least as long as the base window | MinIO lifecycle in [`bucket-setup.sh`](../minio/bucket-setup.sh) or the WAL-G `delete` command |

For production, keep daily fulls for 7 days, one per week for 8 weeks, and one per month for 12 months (GFS).
WAL retention must cover the oldest retained base, otherwise that base cannot be replayed forward. Size the
backup window from data volume: `scratchSize` (default `64Gi`) should be at least the compressed base size
times 1.2, and throttle primary I/O with `pg_basebackup max-rate`. The chart's CronJobs use
`concurrencyPolicy: Forbid`, so a task never overlaps itself.

| CronJob | backoffLimit | activeDeadlineSeconds | Successful/failed Job history | ttlSecondsAfterFinished |
|---|---|---|---|---|
| `*-pg-backup` | 2 | 7200 (2h) | 3 / 3 | 604800 (7 days) |
| `*-pg-basebackup` | 1 | 21600 (6h) | 2 / 3 | 604800 (7 days) |
| `*-pg-pitr-verify` | 1 | 600 (10min) | 1 / 3 | 259200 (3 days) |

- Keep the archive check's timeout below its 15-minute schedule; with `Forbid`, an overrunning run makes the
  next one be skipped and the check appears to stop reporting.
- `ttlSecondsAfterFinished` only removes leftover Jobs and Pods beyond the history counts. It does not replace
  object-storage retention, which decides how far back you can restore.
- Job failure alerts must be configured on the platform side: [`deploy/observability`](../../observability/prometheus/lattice-alerts.yml)
  contains application metric rules only, so add `kube_job_failed`, stalled-archive, `pg_wal` growth, and object-storage or `mc` upload alerts.

## Archive verification

The SQL is read-only and runs as an application account. Run it manually after any archiving change:

```sh
psql "$PG_URL" -v ON_ERROR_STOP=1 -v max_archive_lag_seconds=300 -v require_replica=true \
  -tA -f deploy/production/backup/archive-verify.sql
# Expected: one line starting with OK archived_count=... last_archived_wal=... lag=...s replicas=... sync=...
```

The Helm CronJob mounts its own copy at [`deploy/helm/lattice/files/archive-verify.sql`](../../helm/lattice/files/archive-verify.sql).
The two files must stay byte-identical so an online incident can be reproduced against the same queries;
check with `diff -u deploy/production/backup/archive-verify.sql deploy/helm/lattice/files/archive-verify.sql`.

For a bare-metal deployment, [`pitr-verify.sh`](pitr-verify.sh) runs the same SQL and exits non-zero on
`FATAL`; it reads `PG_URL`, `MAX_ARCHIVE_LAG_SECONDS` (default 300), and `REQUIRE_REPLICA` (default true)
from a mode-0600 environment file. [`base-backup.sh`](base-backup.sh) is the bare-metal equivalent of the
base CronJob: `pg_basebackup` with `BASEBACKUP_ARGS` (default `-Ft -z -Xfetch -c fast -P`), upload to
`$BUCKET/$PREFIX/base/<TS>/`, then `mc rm --older-than` pruning. It reads `PG_REPLICATION_URL` (a
REPLICATION-privileged account, not `lattice_app`), `S3_ENDPOINT`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `BUCKET`,
`PREFIX`, `KEEP_DAYS`, and `SCRATCH_DIR`. Both helpers are plain `sh`; check them with
`sh -n deploy/production/backup/base-backup.sh` before scheduling them.

## Restore procedure

1. Choose the target time `T`, for example one minute before an accidental delete, and confirm it is inside
   the retention window.
2. Extract the newest physical base earlier than `T` into a new data directory; never overwrite the live one:
   `mkdir -p /var/lib/postgresql/restore && tar -xzf base.tar.gz -C /var/lib/postgresql/restore`.
3. Create `recovery.signal` in the new data directory and set `restore_command`, `recovery_target_time='T'`,
   `recovery_target_action='promote'`, and `recovery_target_timeline='latest'`.
4. Start a spare instance (`pg_ctl -D /var/lib/postgresql/restore -o "-p 5433" start`) and verify the timeline, `pg_is_in_recovery()=f`, and rows on both sides of `T`.
5. Move the stable endpoint to the new primary, rebuild the remaining replicas with `pg_basebackup`, and let
   the node reconcile pending state (the `lock:reconcile` task) before ramping traffic back up.
6. Do not write the old data directory back after a PITR restore; it conflicts with the archived timeline.
   Keep the original instance until the restore is confirmed.

## Encryption and tamper protection

| Layer | Requirement | Guidance |
|---|---|---|
| Transport | Uploads over TLS | `mc alias` with an `https://` endpoint; the node's internal `http://` limit does not apply to the backup host |
| Server-side encryption | SSE-S3 or SSE-KMS | Enable KMS in MinIO (`MINIO_KMS_AUTO_ENCRYPTION=on`, or `mc encrypt set sse-kms`); keys stay in KMS/HSM, never in the bucket |
| Client-side encryption | Optional re-wrap for off-site media | `age -r <public-key>` or `gpg --encrypt` before `mc cp`; keep the private key offline |
| Tamper protection | Object lock plus versioning on `lattice-cold` | [`bucket-setup.sh`](../minio/bucket-setup.sh) creates the bucket with lock enabled; GOVERNANCE can be cleared, COMPLIANCE cannot |
| Access control | Dedicated IAM user limited to the backup prefixes | Never root; inject keys through a Secret |
| Off-site copy | Asynchronous replication (`mc replicate add`) | Replication lag is the cross-site RPO; check it with `mc replication status` |
| Key rotation | Annual review of KMS keys, `mc` credentials, and lock retention | Re-run one archive check and one PITR drill after rotation |

Encryption changes the restore procedure: the decryption step belongs in the drill, and the key must not live in the same fault domain as the backup.

## Unvalidated boundaries

1. The object-storage archive path has never run against a real MinIO bucket; `mc` behavior under retries,
   timeouts, and partial uploads is untested.
2. The Helm CronJobs have never run on a cluster, and object lifecycle / `mc rm --older-than` retention and
   Job history/TTL behavior are unobserved.
3. Restore of SSE-KMS or client-side-encrypted backups, and of object-locked backups, has not been drilled.
4. Cross-site replication and a restore from the off-site copy are not validated.
5. Backup windows for large databases and the effect of rate limiting on the primary are unmeasured.
6. `pg_wal` growth thresholds caused by archive failures have not been measured, so alert values are guesses.
