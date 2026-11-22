#!/bin/sh
# =============================================================================
# Idempotent database creation after the first bootstrap: lattice (owner=lattice_app)
# -----------------------------------------------------------------------------
# Why it is needed: Patroni's `bootstrap.users` creates roles only, not databases; but the node's
# `[pg] url = postgres://lattice_app@.../lattice` requires the database to exist, and sqlx migrations
# are executed by the node at startup (the node never creates databases). So "first deployment" needs an
# idempotent step.
#
# Mount at /usr/local/bin/init-lattice-db.sh; patroni.yml's `bootstrap.post_bootstrap` calls it after the
# new primary starts (it runs only once, when the cluster is initdb'ed).
# It can also be run manually (when switching or re-creating databases):
#   docker exec -u postgres <patroni-container> /usr/local/bin/init-lattice-db.sh
#   # or bare metal: sudo -u postgres /usr/local/bin/init-lattice-db.sh
# =============================================================================
set -eu

PSQL="${PSQL:-psql}"
PGHOST="${PGHOST:-/var/run/postgresql}"   # local unix socket
PGUSER_SUPER="${PGUSER_SUPER:-postgres}"

"${PSQL}" -v ON_ERROR_STOP=1 -h "${PGHOST}" -U "${PGUSER_SUPER}" -d postgres <<'SQL'
SELECT 'CREATE DATABASE lattice OWNER lattice_app ENCODING ''UTF8'''
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'lattice')\gexec
SQL

echo "init-lattice-db: database lattice present (owner=lattice_app)"
