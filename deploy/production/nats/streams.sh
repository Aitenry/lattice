#!/bin/sh
# =============================================================================
# NATS JetStream Stream pre-creation script (replicas=3) — must run before lattice-node starts
# -----------------------------------------------------------------------------
# Why pre-creation is mandatory (see the header of nats-0.conf):
#   The node code creates streams with async-nats `get_or_create_stream`, and
#   `stream::Config::default()` has replicas=1; moreover get_or_create does **no config comparison**
#   for an existing stream (cargo-vendor2/async-nats/src/jetstream/context.rs:805-837).
#   => Create the streams with replicas=3 first; when the node starts it finds them and reuses them as-is;
#   => If the node starts first it creates streams with replicas=1, and a single node failure loses that
#      Stream's data (no redundancy in a 3-node cluster).
#
# Parameters aligned with crates/lattice-node/src/store/nats.rs::stream_specs() (changing the code requires
# changing this file too):
#   LATTICE_ROUTE      route.>           WorkQueue  File  24h (also see ROUTE_MAX_AGE=24h in code)
#   LATTICE_BROADCAST  topic.>           Limits     File  24h
#   LATTICE_AUDIT      audit.log         Limits     File  7d
#   LATTICE_MEDIA      media.record.>    Limits     File  1h
#
# Usage:
#   export NATS_URL=nats://lattice-nats.lattice.internal:4222
#   export NATS_USER=lattice NATS_PASSWORD=...   # production auth (optional, no auth in dev)
#   ./streams.sh            # create/verify; idempotent, safe to re-run
#   ./streams.sh --check    # verify only, do not create
#
# Requires the `nats` CLI (the nats-server image ships a binary of the same name; install the matching
# client version in production).
# =============================================================================
set -eu

NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
NATS_USER="${NATS_USER:-}"
NATS_PASSWORD="${NATS_PASSWORD:-}"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

nats_cmd() {
  if [ -n "${NATS_USER}" ]; then
    nats --server "${NATS_URL}" --user "${NATS_USER}" --password "${NATS_PASSWORD}" "$@"
  else
    nats --server "${NATS_URL}" "$@"
  fi
}

# One-to-one with stream_specs(); adding/changing a stream requires changing both sides
add_stream() {
  name=$1; subject=$2; retention=$3; max_age=$4
  if nats_cmd stream info "${name}" >/dev/null 2>&1; then
    echo "stream ${name} already exists, reusing it (configuration unchanged)"
  elif [ "${CHECK_ONLY}" = "1" ]; then
    echo "MISSING stream ${name}"
  else
    # shellcheck disable=SC2086
    nats_cmd stream add "${name}" \
      --subjects "${subject}" \
      --retention "${retention}" \
      --storage file \
      --max-age "${max_age}" \
      --replicas 3 \
      --discard old \
      --defaults
    echo "stream ${name} created (subjects=${subject} retention=${retention} max-age=${max_age} replicas=3)"
  fi
}

add_stream LATTICE_ROUTE     'route.>'        workqueue 24h
add_stream LATTICE_BROADCAST 'topic.>'        limits    24h
add_stream LATTICE_AUDIT     'audit.log'      limits    168h
add_stream LATTICE_MEDIA     'media.record.>' limits    1h

echo
echo "== Verify: every stream must have 3 replicas =="
rc=0
for s in LATTICE_ROUTE LATTICE_BROADCAST LATTICE_AUDIT LATTICE_MEDIA; do
  if ! nats_cmd stream info "${s}" >/dev/null 2>&1; then
    [ "${CHECK_ONLY}" = "1" ] && continue
    echo "FAIL  ${s} does not exist"
    rc=1
    continue
  fi
  replicas=$(nats_cmd stream info "${s}" -j 2>/dev/null | sed -n 's/.*"num_replicas": *\([0-9]*\).*/\1/p' | head -n 1)
  if [ "${replicas}" = "3" ]; then
    echo "PASS  ${s} replicas=${replicas}"
  else
    echo "FAIL  ${s} replicas=${replicas:-unknown} (expected 3; fix: nats stream update ${s} --replicas 3, or delete and recreate the stream)"
    rc=1
  fi
done

if [ "${rc}" = "0" ]; then
  echo "RESULT: PASS (all 4 Streams have 3 replicas)"
else
  echo "RESULT: FAIL"
fi
exit "${rc}"
