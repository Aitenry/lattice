# Backup / PITR productionization (template, not wired to real object storage)

> **Status: policy and templates, not a validated backup system.** This repository has only been
> validated in a **single-host temporary PG16 container** ("local-directory WAL archiving + restore";
> `perf/reports/pitr-20261121.txt`, 34/34, archive lag 4.1s, PG automated segment RTO 3.92s).
> **The object-storage (MinIO) archive path, cross-host operation, retention/encryption policy, and
> real Helm CronJob execution are all unvalidated** (no production MinIO/cluster on this machine).
> Authoritative numbers and drill definitions: `deploy/production/README.md` §3.

## 1. Backup layers (three layers, all required)

| Layer | Content | Frequency | Tool/location | Restore granularity | RPO |
|---|---|---|---|---|---|
| **L1 logical full** | `pg_dump -Fc` single database | Daily (`backup.schedule`, default 03:00) | Helm CronJob `*-pg-backup` → `lattice-cold/backup/pg/` | Single database/single table | 24h (not PITR) |
| **L2 physical base** | `pg_basebackup -Ft -z -Xfetch` | Daily (`backup.pitr.baseBackupSchedule`, default 02:15) | Helm CronJob `*-pg-basebackup` → `lattice-cold/wal/pg/lattice-pg/base/<TS>/` | Whole cluster | Point of the base backup |
| **L3 WAL archive** | Every WAL segment (`archive_timeout=60s` forces segment switch) | Continuous | PG `archive_command` → `deploy/production/patroni/wal-gateway.sh` → same bucket `.../wal/` (production should switch to WAL-G/pgBackRest) | Any point in time (PITR) | ≤5min (design value; mechanical upper bound = 60s segment switch + upload time) |

> L2 + L3 together = PITR: start from a physical base of some day, and `restore_command` replays WAL
> from the archive to the target time (`recovery_target_time` + `recovery_target_action=promote`;
> setting only `recovery_target_time` while missing `recovery.signal` yields a "false success" that
> performs crash recovery only, see `patroni/README.md` §3.2).
> L1 is not PITR — do not use it as the basis for an RPO claim.

## 2. Scheduling and retention policy

Aligned with the Helm chart defaults (when changing one, keep the chart's `templates/backup-cronjob.yaml` /
`templates/pitr-cronjob.yaml` and this file in sync; `scripts/helm-canary-validate.py` asserts that
"schedule/concurrency/history retention/TTL/timeout" match on both sides).

### 2.1 Object-storage retention (business data: determines how far back you can restore)

| Task | Default schedule | Retention | Notes |
|---|---|---|---|
| `pg_dump` logical full | `0 3 * * *` | `backup.keepDays=30` days | 1 copy per day; clean by object timestamp with `mc rm --older-than` |
| `pg_basebackup` physical base | `15 2 * * *` | `backup.pitr.keepDays=14` days | Staggered 45 minutes from pg_dump so they do not load the primary simultaneously |
| `pg-pitr-verify` archive check | `*/15 * * * *` | Produces no business objects | Failure = Job failure → alert (see §3) |
| WAL archive | Continuous (`archive_timeout=60s`) | Matches the base retention window (≥14 days) | Managed by MinIO lifecycle (`bucket-setup.sh`) or the WAL-G `delete` command |

Recommended production retention: daily fulls for the last 7 days + 1 per week for the last 8 weeks +
1 per month for the last 12 months (GFS); WAL must at least cover the longest-retained base
(otherwise the physical base cannot be replayed to the latest point in time).
**Base backup window** is sized by data volume: `scratchSize` (default 64Gi) must be ≥ compressed base size ×1.2;
limit primary IO headroom with `pg_basebackup max-rate`.

### 2.2 K8s Job retention (troubleshooting evidence / concurrency protection)

Applies to the Helm CronJob form only (for the bare-metal systemd timer/cron equivalents see the header
comments in `base-backup.sh` / `pitr-verify.sh`). All three CronJobs use `concurrencyPolicy: Forbid`: the same
task never runs concurrently, so two `pg_dump`/`pg_basebackup` runs cannot load the primary at once, and
the verify task cannot slow down the base task.

| CronJob | concurrencyPolicy | backoffLimit | activeDeadlineSeconds | `successfulJobsHistoryLimit` / `failedJobsHistoryLimit` | ttlSecondsAfterFinished |
|---|---|---|---|---|---|
| `*-pg-backup` (L1 logical full) | Forbid | 2 | 7200 (2h) | 3 / 3 | 604800 (7 days) |
| `*-pg-basebackup` (L2 physical base) | Forbid | 1 | 21600 (6h) | 2 / 3 | 604800 (7 days) |
| `*-pg-pitr-verify` (archive check) | Forbid | 1 | 600 (10min) | 1 / 3 | 259200 (3 days) |

- `activeDeadlineSeconds` is the timeout safety net: scale the base job up with data volume; **the archive
  check must stay < the 15min schedule interval** (otherwise the previous run has not finished and the next
  is skipped by Forbid, which looks like "the check never returns a result");
- `ttlSecondsAfterFinished` only cleans up leftover Jobs/Pods "beyond the history count" (for example ones that
  accumulated while the schedule was paused); it does **not** replace the object-storage retention in §2.1;
- Do not confuse the two retention layers: object storage decides "how far back you can restore", Job/TTL only
  decides "how long troubleshooting logs are kept";
- Failure alerts only recognize Job failure (`kube_job_failed` / CronJob failure metrics) — **`deploy/observability`
  in this repository only has application metrics; Job failure alerts must be configured on the platform side**,
  otherwise backup failures are silent.

## 3. Verification and alerting (an unverified backup is no backup)

- **Automated check** (Helm `-pg-pitr-verify`, every 15 minutes):
  `archive_mode=on`, last archive lag ≤ `maxArchiveLagSeconds` (default 300s),
  the most recent failure is not later than the most recent success, and when `requireReplica` at least 1 streaming replica.
  The SQL is the same file for the Helm template and this directory: `archive-verify.sql` here and
  `deploy/helm/lattice/files/archive-verify.sql` are **verbatim identical** (`scripts/ha-prod-validate.py` verifies).
  Manual re-run:
  ```sh
  psql "$PG_URL" -v ON_ERROR_STOP=1 -v max_archive_lag_seconds=300 -v require_replica=true \
    -tA -f archive-verify.sql
  # Expect a single line: OK archived_count=... last_archived_wal=... lag=...s replicas=2 sync=1
  ```
- **Restore drill** (quarterly): follow `scripts/restore-runbook.md` §13 / `scripts/pitr-drill.ps1` for one
  complete PITR (base + WAL replay + data verification before/after the target + promote), and record RTO/RPO in `perf/reports/`.
- **Alerting** (must be configured on the platform alerting side; `deploy/observability/prometheus/lattice-alerts.yml`
  currently only contains application metric rules and **does not** include Job/CronJob failure alerts — do not assume
  that installing those rules gives you backup alerting):
  `lattice-pg-pitr-verify` Job failure (2 consecutive, `kube_job_failed`-class alert),
  growing `pg_stat_archiver.failed_count`,
  `last_archived_time` > 5min, `pg_wal` directory > threshold, CronJob with no success for over 26h (missing base),
  object storage 4xx/5xx, `mc` upload failure. For Job failure history retention see §2.2 (3 failures + TTL).
- After each drill/incident record: RTO (T0→traffic fully restored), RPO (last successful archive point), failure cause, improvements.

## 4. Encryption and tamper protection

| Layer | Requirement | Implementation guidance |
|---|---|---|
| Transport | Backup uploads over TLS | `mc alias` with an `https://` endpoint (intra-cluster http on node `[s3]` is a code limitation; the backup side can use a separate alias) |
| Encryption at rest (server side) | SSE-S3 / SSE-KMS | Enable KMS in MinIO (`MINIO_KMS_AUTO_ENCRYPTION=on` or `mc encrypt set sse-kms`); keys live in KMS/HSM, never in the bucket |
| Encryption at rest (client side, optional) | Wrap backup files again (cross-cloud/offline media) | `age -r <public-key>` or `gpg --encrypt` before `mc cp`; keep the decryption private key offline |
| Tamper protection | `lattice-cold` object lock (GOVERNANCE 30d) + versioning | Enabled when `deploy/production/minio/bucket-setup.sh` creates the bucket; tune retention for compliance (COMPLIANCE cannot be removed — use with care) |
| Access control | Backup-dedicated IAM user/bucket policy allowing only `s3:PutObject/GetObject/DeleteObject` on the backup prefix | Do not use root; inject access keys into the CronJob via a Secret (already done in the Helm chart) |
| Off-site copy | Cross-site replication (MinIO `mc replicate add` / cloud bucket replication), asynchronous | Replication lag = cross-site RPO; check lag periodically with `mc replication status` |
| Key rotation | Annual review of KMS master keys, `mc` credentials, object-lock retention | After rotation, regression-test one `archive-verify` plus one PITR drill |

> Encryption does **not** change RPO/RTO, it only changes the restore procedure: the decryption step must be
> written into the drill script, and the decryption key must not sit in the same fault domain as the backup
> (otherwise it is as good as no backup).

## 5. Relationship to repository scripts

| Existing script/document | Relationship |
|---|---|
| `deploy/production/patroni/wal-gateway.sh` | Reference implementation of `archive_command`/`restore_command`; this directory's core assumptions (bucket `lattice-cold`, prefix `wal/pg/lattice-pg`) match it |
| `scripts/pitr-drill.ps1` | Full single-host PITR drill (base→write→force archive→restore to point in time→verify); the validation script for this directory's policy |
| `scripts/backup-restore-drill.ps1` | Logical backup/restore (pg_dump/pg_restore/snapshot consistency); corresponds to L1 |
| `scripts/restore-runbook.md` | Restore runbook (including PITR steps and report template); this directory defines policy only, that document governs the steps |
| `deploy/helm/lattice` | Scheduling and automated-check templates for L1/L2/L3 (`backup.enabled` / `backup.pitr.enabled`) |
| `deploy/production/backup/archive-verify.sql` | Archive health SQL; same source as the chart's `files/archive-verify.sql` |
| `deploy/production/backup/base-backup.sh` / `pitr-verify.sh` | Bare-metal (non-K8s) equivalents, same logic as the Helm CronJob inline commands, verifiable offline with `sh -n` |

## 6. Restore procedure (summary, full steps in restore-runbook)

1. Choose the target point in time `T` (for example 1 minute before the accidental delete); confirm that `T` falls within the retention window.
2. Take the most recent physical base **earlier than T** and extract it to a new data directory (do not overwrite the live directory).
3. Configure `restore_command` (`wal-gateway.sh restore`) + `recovery.signal` +
   `recovery_target_time='T'` + `recovery_target_action='promote'` + `recovery_target_timeline='latest'`.
4. Start a temporary instance → verify `pg_is_in_recovery()=f`, timeline, data before and after `T`; record RTO.
5. Switch the VIP/new primary → rebuild the remaining replicas with `pg_basebackup` → reconciliation (`scripts/reconcile.py`) → phased traffic ramp-up.
6. After PITR restore **do not** write the old data directory back (it would conflict with the archived timeline); keep the original instance until confirmed.

## 7. Unvalidated boundaries (must not be skipped)

1. Object-storage archive/retrieval path (`wal-gateway.sh` has never run against a real MinIO bucket; logged in `perf/README.md` §8.5);
2. The Helm L1/L2 CronJobs have never run on a real cluster (no production K8s is deployed on this machine);
3. Retention-policy object lifecycle (`mc rm --older-than` / MinIO ILM) is unvalidated;
4. The restore path for encryption (SSE-KMS / age) and object lock is unvalidated;
5. Cross-site replication and off-site restore are unvalidated;
6. Backup windows for large databases and the impact of rate limiting on the primary have not been load-tested;
7. Disk alert thresholds for `pg_wal` backlog caused by archive failures have not been measured.
