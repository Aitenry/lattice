#!/bin/sh
# =============================================================================
# Lattice PG physical base backup (bare-metal / non-K8s reference script)
# -----------------------------------------------------------------------------
# **Same logic** as the Helm chart `backup.pitr` CronJob (`-pg-basebackup`):
#   pg_basebackup (tar+gzip+WAL fetched with the base) → upload to the same bucket/prefix as WAL
#   archiving → prune by retention days.
# Why a standalone script: production does not necessarily run K8s; a bare-metal systemd timer
# needs the same contract (bucket/prefix/retention parameters identical to Helm values and
# patroni/wal-gateway.sh), otherwise the restore chain will be assembled incorrectly.
#
# Prerequisites (environment variables from a Secret/EnvironmentFile, 0600, never committed):
#   PG_REPLICATION_URL   postgres://<replication-user>:<pw>@<stable-endpoint>:5432/lattice?sslmode=verify-full
#                        (must be an account with REPLICATION privilege; the application account lattice_app will not work)
#   S3_ENDPOINT          endpoint for backups (https preferred; the in-cluster http restriction does not apply to the backup host)
#   S3_ACCESS_KEY / S3_SECRET_KEY / BUCKET / PREFIX
#   KEEP_DAYS            physical base retention days (default 14, same as Helm backup.pitr.keepDays)
#   SCRATCH_DIR          local scratch directory (default /var/backups/lattice; must be ≥ compressed base size ×1.2)
#   BASEBACKUP_ARGS      default "-Ft -z -Xfetch -c fast -P" (same as Helm values)
#
# Usage:
#   ./base-backup.sh
#   # systemd timer example: OnCalendar=*-*-* 02:15:00 (aligned with Helm baseBackupSchedule)
#
# Exit codes: 0 = base uploaded and pruning complete; non-zero = backup failed (systemd/timer will alert).
# =============================================================================
set -eu

: "${PG_REPLICATION_URL:?PG_REPLICATION_URL required (account with REPLICATION privilege)}"
: "${S3_ENDPOINT:?S3_ENDPOINT required}"
: "${S3_ACCESS_KEY:?S3_ACCESS_KEY required}"
: "${S3_SECRET_KEY:?S3_SECRET_KEY required}"
BUCKET="${BUCKET:-lattice-cold}"
PREFIX="${PREFIX:-wal/pg/lattice-pg}"
KEEP_DAYS="${KEEP_DAYS:-14}"
SCRATCH_DIR="${SCRATCH_DIR:-/var/backups/lattice}"
BASEBACKUP_ARGS="${BASEBACKUP_ARGS:--Ft -z -Xfetch -c fast -P}"
MC_ALIAS="${MC_ALIAS:-lattice-backup}"

TS=$(date -u +%Y%m%dT%H%M%SZ)   # timestamp taken at run time, never template-render time
BASE_DIR="${SCRATCH_DIR}/base-${TS}"
mkdir -p "${BASE_DIR}"

echo "== pg_basebackup -> ${BASE_DIR} =="
# shellcheck disable=SC2086  # BASEBACKUP_ARGS is intentionally split on spaces into multiple arguments
pg_basebackup "${PG_REPLICATION_URL}" -D "${BASE_DIR}" ${BASEBACKUP_ARGS}
test -f "${BASE_DIR}/base.tar.gz"   # -Ft output; a missing file counts as failure, never upload a partial base

{
  echo "ts=${TS}"
  echo "args=${BASEBACKUP_ARGS}"
  echo "tool=$(pg_basebackup --version 2>/dev/null | head -1)"
  echo "wal_prefix=${PREFIX}"
} > "${BASE_DIR}/manifest.txt"

echo "== upload -> ${BUCKET}/${PREFIX}/base/${TS}/ =="
mc alias set "${MC_ALIAS}" "${S3_ENDPOINT}" "${S3_ACCESS_KEY}" "${S3_SECRET_KEY}" >/dev/null
# Overwrite on same name = idempotent retry (re-running after a partial upload failure does not create duplicate directories)
mc cp --recursive "${BASE_DIR}" "${MC_ALIAS}/${BUCKET}/${PREFIX}/base/${TS}/"
echo "uploaded: ${BUCKET}/${PREFIX}/base/${TS}/"

# Retention: prune base directories only; WAL archive retention is managed by MinIO lifecycle / WAL-G delete
mc rm --recursive --force --older-than "${KEEP_DAYS}d" "${MC_ALIAS}/${BUCKET}/${PREFIX}/base/" || true

# Clean the local scratch directory as well (a full disk would fail the next base backup)
rm -rf "${BASE_DIR}"
echo "RESULT: base backup OK ts=${TS}"
