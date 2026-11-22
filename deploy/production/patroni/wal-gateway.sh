#!/bin/sh
# =============================================================================
# Lattice PG WAL archive/fetch gateway — reference implementation of archive_command / restore_command
# -----------------------------------------------------------------------------
# Why it is needed: PostgreSQL's archive_command must be a single command that is "idempotent, retryable,
# and returns non-zero on failure"; shipping WAL straight to MinIO has to handle the case "upload succeeded
# but the command timed out and PG judged it failed → retry the same segment", i.e. duplicate uploads
# (overwriting the same object name is enough; this script overwrites with mc cp and verifies the size).
#
# Prerequisites (provided by the deployer in production):
#   - the MinIO client `mc` installed on the host/in the container (or replaced with `aws s3 cp` / WAL-G);
#   - the mc alias pre-configured (read-only config file, password never on the command line):
#       mc alias set lattice-s3 https://minio.lattice.internal:9000 "$S3_ACCESS_KEY" "$S3_SECRET_KEY"
#   - environment variables:
#       WAL_S3_ALIAS  mc alias name (default lattice-s3)
#       WAL_BUCKET    archive bucket (default lattice-cold, matching [s3] bucket_cold)
#       WAL_PREFIX    object prefix (default wal/pg/lattice-pg)
#
# Usage (written into postgresql.parameters in patroni.yml):
#   archive_command: /usr/local/bin/wal-gateway.sh archive %p %f
#   restore_command: /usr/local/bin/wal-gateway.sh restore %f %p
#
# Exit-code semantics (required by the PG documentation):
#   archive_command 0 = archived; non-zero = PG keeps the segment and retries periodically (retrying
#   continuously within archive_timeout).
#   restore_command 0 = fetched; non-zero = the segment does not exist (PG then stops at the recovery
#   target or errors out).
#
# Boundaries (the real MinIO archive path has not been validated on this machine):
#   - This script only does "single-object put/get + size verification"; it provides no
#     encryption/compression/retention policy/cross-site replication. In production switch to WAL-G
#     (`wal-g wal-push` / `wal-g wal-fetch`) or pgBackRest, which already handle encryption, resumable
#     transfer, verification, and retention. This file is the minimal runnable example of "archiving must
#     be on" in the skeleton.
#   - While object storage is unavailable PG keeps retrying → the pg_wal directory grows; this must alert
#     (see README §3.4).
# =============================================================================
set -eu

MODE="${1:-}"
ALIAS="${WAL_S3_ALIAS:-lattice-s3}"
BUCKET="${WAL_BUCKET:-lattice-cold}"
PREFIX="${WAL_PREFIX:-wal/pg/lattice-pg}"

if [ "$MODE" = "archive" ]; then
  WAL_PATH="${2:?archive requires the WAL source path %p}"
  WAL_FILE="${3:?archive requires the WAL file name %f}"
  DEST="${ALIAS}/${BUCKET}/${PREFIX}/wal/${WAL_FILE}"
  KEY="wal/${WAL_FILE}"

  # Idempotent: the same-named object already exists with the same size → succeed immediately (overwrite
  # would also work, this just saves an upload).
  if command -v mc >/dev/null 2>&1; then
    if mc stat "${DEST}" >/dev/null 2>&1; then
      SRC_SIZE=$(wc -c < "${WAL_PATH}")
      REMOTE_SIZE=$(mc stat --json "${DEST}" 2>/dev/null | sed -n 's/.*"size":\([0-9]*\).*/\1/p')
      if [ -n "${REMOTE_SIZE}" ] && [ "${SRC_SIZE}" = "${REMOTE_SIZE}" ]; then
        exit 0
      fi
    fi
    # mc cp overwrites the same-named object: retries never create duplicate copies
    mc cp --quiet "${WAL_PATH}" "${DEST}"
  elif command -v aws >/dev/null 2>&1; then
    aws s3 cp --only-show-errors "${WAL_PATH}" "s3://${BUCKET}/${PREFIX}/${KEY}"
  else
    echo "wal-gateway: neither mc nor the aws cli is available" >&2
    exit 1
  fi
  exit 0
fi

if [ "$MODE" = "restore" ]; then
  WAL_FILE="${2:?restore requires the WAL file name %f}"
  DEST_PATH="${3:?restore requires the target path %p}"
  SRC="${ALIAS}/${BUCKET}/${PREFIX}/wal/${WAL_FILE}"
  KEY="wal/${WAL_FILE}"

  if command -v mc >/dev/null 2>&1; then
    mc cp --quiet "${SRC}" "${DEST_PATH}"
  elif command -v aws >/dev/null 2>&1; then
    aws s3 cp --only-show-errors "s3://${BUCKET}/${PREFIX}/${KEY}" "${DEST_PATH}"
  else
    echo "wal-gateway: neither mc nor the aws cli is available" >&2
    exit 1
  fi
  # Size consistency: an empty/truncated file counts as failure, so PG errors out instead of silently
  # replaying a corrupt WAL
  if [ ! -s "${DEST_PATH}" ]; then
    rm -f "${DEST_PATH}"
    exit 1
  fi
  exit 0
fi

echo "usage: $0 archive <wal_path> <wal_file> | $0 restore <wal_file> <dest_path>" >&2
exit 2
