#!/bin/sh
# =============================================================================
# MinIO production bucket initialization — versioning / object lock / lifecycle / dedicated IAM user
# -----------------------------------------------------------------------------
# Why this is needed: on startup the node's `store/s3.rs::ensure_buckets()` only does HEAD → PUT on
# **plain buckets**; it neither creates versioning nor enables object lock. And object lock can only be
# enabled **at bucket creation** (it cannot be added afterwards).
# So: run this script first to create the 4 buckets (the node skips them once HEAD succeeds), then start lattice-node.
#
# The four buckets (one-to-one with [s3] bucket_*; keep this in sync when changing configuration):
#   lattice-large    large files/chunks ([s3] bucket_large)
#   lattice-media    media/recording ([s3] bucket_media)
#   lattice-cold     cold data/backups/WAL archive ([s3] bucket_cold; wal-gateway.sh in that directory writes here too)
#   lattice-plugins  client plugin center ([s3] bucket_plugins)
#
# Usage (requires the mc client; preferably run on an ops machine/container that can reach MinIO):
#   export MINIO_ENDPOINT=http://minio.lattice.internal:9000
#   export MINIO_ROOT_USER=... MINIO_ROOT_PASSWORD=...
#   export MINIO_APP_ACCESS_KEY=lattice_app MINIO_APP_SECRET_KEY=...
#   ./bucket-setup.sh
#
# Idempotent: safe to re-run (mb --ignore-existing / version enable / ilm overwrite / policy overwrite).
# =============================================================================
set -eu

ALIAS="${MINIO_ALIAS:-lattice-s3}"
ENDPOINT="${MINIO_ENDPOINT:?MINIO_ENDPOINT required (for example http://minio.lattice.internal:9000)}"
ROOT_USER="${MINIO_ROOT_USER:?MINIO_ROOT_USER required}"
ROOT_PASS="${MINIO_ROOT_PASSWORD:?MINIO_ROOT_PASSWORD required}"
APP_ACCESS="${MINIO_APP_ACCESS_KEY:-lattice_app}"
APP_SECRET="${MINIO_APP_SECRET_KEY:?MINIO_APP_SECRET_KEY required (node [s3] secret_key)}"

BUCKETS="lattice-large lattice-media lattice-cold lattice-plugins"

echo "== 1) mc alias (root, initialization only) =="
mc alias set "${ALIAS}" "${ENDPOINT}" "${ROOT_USER}" "${ROOT_PASS}"

echo "== 2) Create buckets: lattice-cold with object lock; the rest plain + versioning =="
for b in ${BUCKETS}; do
  if [ "${b}" = "lattice-cold" ]; then
    # Object lock must be enabled at creation (--with-lock implies versioning); lattice-cold holds
    # backups/WAL/archives and needs tamper protection
    mc mb --ignore-existing --with-lock "${ALIAS}/${b}"
  else
    mc mb --ignore-existing "${ALIAS}/${b}"
  fi
done
for b in ${BUCKETS}; do
  mc version enable "${ALIAS}/${b}"
done

echo "== 3) Lifecycle (example policy; adjust to the actual retention policy [!]) =="
# Cold bucket: transition to lower tier after 365 days / expire only applies to the "backup prefix",
# to avoid deleting business cold data by accident
# This only demonstrates "expire temporary chunks"; no business data expiry is set (business deletion goes through the purge API)
mc ilm rule add --expire-days 7 --prefix "uploads/" "${ALIAS}/lattice-large" 2>/dev/null || true
# Default retention for the object-lock bucket: GOVERNANCE 30 days (a privileged user can clear it early;
# COMPLIANCE cannot be cleared — use with care)
# Note: node writes carry no x-amz-object-lock-* header → a default retention policy must be enabled
# deliberately; this skeleton does not apply object-level retention, so that node-side delete/cleanup is not
# locked. Enable it separately for compliance and validate the node delete path.
# mc retention set --default GOVERNANCE 30d "${ALIAS}/lattice-cold"

echo "== 4) Dedicated IAM user (the node must not use the root account) =="
# Ignore if it already exists (idempotent); rotate the password with `mc admin user add`
mc admin user add "${ALIAS}" "${APP_ACCESS}" "${APP_SECRET}" >/dev/null 2>&1 || true

cat > /tmp/lattice-app-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"],
      "Resource": ["arn:aws:s3:::lattice-large", "arn:aws:s3:::lattice-media",
                   "arn:aws:s3:::lattice-cold", "arn:aws:s3:::lattice-plugins"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                 "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"],
      "Resource": ["arn:aws:s3:::lattice-large/*", "arn:aws:s3:::lattice-media/*",
                   "arn:aws:s3:::lattice-cold/*", "arn:aws:s3:::lattice-plugins/*"]
    }
  ]
}
EOF
mc admin policy create "${ALIAS}" lattice-app /tmp/lattice-app-policy.json
mc admin policy attach "${ALIAS}" lattice-app --user "${APP_ACCESS}"
rm -f /tmp/lattice-app-policy.json

echo "== 5) Verify =="
mc ls "${ALIAS}"
for b in ${BUCKETS}; do
  printf 'bucket=%s versioning=' "${b}"
  mc version info "${ALIAS}/${b}" | sed -n 's/.*versioning \([a-z]*\).*/\1/p' | head -n 1
done
echo "root: mc admin info ${ALIAS}    # all 4 nodes online, 4 drives each, EC=12+4"
echo "RESULT: buckets ready (4; object lock=frozen? check with mc stat)"

# -----------------------------------------------------------------------------
# Cross-site replication (optional, design §11: MinIO cross-site sync is optional disaster recovery)
# -----------------------------------------------------------------------------
# Option A (per-bucket replication, asynchronous; requires versioning on both source and target):
#   mc replicate add lattice-s3/lattice-large \
#     --remote-bucket "https://s3-dr.example.com/lattice-large" \
#     --remote-user lattice-repl --remote-password "$REPL_PASSWORD" \
#     --replicate "delete,delete-marker" --priority 1
#   mc replication status lattice-s3/lattice-large
# Option B (site-level replication, bidirectional; once configured both sites replicate all buckets and IAM to each other):
#   mc admin replicate add site-a site-b
#   mc admin replicate info site-a
# Notes:
#   - Replication is **asynchronous** → site-level RPO = replication lag (monitor the lag reported by `mc replicate status`);
#   - Object lock/retention policy is not replicated to the peer automatically (configure both sides identically);
#   - This repository has **not validated** any cross-site path (see README §6).
