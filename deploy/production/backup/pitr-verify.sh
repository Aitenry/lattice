#!/bin/sh
# =============================================================================
# Lattice PG archive/PITR health check (bare-metal / non-K8s reference script)
# -----------------------------------------------------------------------------
# **Same logic** as the Helm chart `backup.pitr` CronJob (`-pg-pitr-verify`):
#   runs archive-verify.sql from this directory (verbatim identical to the chart's
#   files/archive-verify.sql), prints OK/FATAL; FATAL returns a non-zero exit code
#   (systemd timer/cron and the alerting platform raise the alert from it).
#
# Prerequisites (environment variables from a Secret/EnvironmentFile, 0600):
#   PG_URL                      an application/read-only account is sufficient (pg_stat_archiver is readable, no superuser needed)
#   MAX_ARCHIVE_LAG_SECONDS     allowed archive lag (default 300, same as Helm backup.pitr.maxArchiveLagSeconds)
#   REQUIRE_REPLICA             whether to require >=1 streaming replica (default true, same as Helm)
#   ARCHIVE_VERIFY_SQL          SQL path (defaults to archive-verify.sql in the same directory)
#
# Usage:
#   ./pitr-verify.sh
#   # systemd timer example: OnCalendar=*:0/15 (aligned with Helm verifySchedule */15)
#
# Exit codes: 0 = OK; 1 = FATAL (archive stalled/archiving off/no replica); 2 = psql execution failed.
# =============================================================================
set -eu

: "${PG_URL:?PG_URL required}"
MAX_ARCHIVE_LAG_SECONDS="${MAX_ARCHIVE_LAG_SECONDS:-300}"
REQUIRE_REPLICA="${REQUIRE_REPLICA:-true}"
ARCHIVE_VERIFY_SQL="${ARCHIVE_VERIFY_SQL:-$(dirname "$0")/archive-verify.sql}"

if [ ! -f "${ARCHIVE_VERIFY_SQL}" ]; then
  echo "pitr-verify: SQL not found: ${ARCHIVE_VERIFY_SQL}" >&2
  exit 2
fi

# Prints a single line OK ... / FATAL ...; -tA strips table decoration so the script can parse it
if ! OUT=$(psql "${PG_URL}" -v ON_ERROR_STOP=1 \
    -v max_archive_lag_seconds="${MAX_ARCHIVE_LAG_SECONDS}" \
    -v require_replica="${REQUIRE_REPLICA}" \
    -tA -f "${ARCHIVE_VERIFY_SQL}"); then
  echo "pitr-verify: psql execution failed (connection/permission/SQL error)" >&2
  exit 2
fi

echo "archive-check: ${OUT}"
case "${OUT}" in
  OK*) exit 0 ;;
  *)
    echo "pitr-verify: FATAL — archive path or replication topology is abnormal; follow deploy/production/backup/README.md §3" >&2
    exit 1
    ;;
esac
