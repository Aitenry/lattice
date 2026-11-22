-- =============================================================================
-- Lattice PG archive / PITR health check (read-only; no superuser required)
-- -----------------------------------------------------------------------------
-- Purpose: run once every 15 minutes by the backup.pitr.verifySchedule CronJob (psql -f this file),
--          prints a single line `OK ...` or `FATAL ...`; the CronJob script derives the exit code from
--          the prefix (non-zero triggers the Job failure alert).
-- Alignment: this file and deploy/production/backup/archive-verify.sql are **verbatim identical**
--          (use either one at deploy time); scripts/ha-prod-validate.py verifies both copies match,
--          preventing "fixed in the template, not synced to the production script".
--
-- psql variables (passed by the caller with -v):
--   max_archive_lag_seconds  maximum allowed archive lag in seconds (default 300; the mechanical upper
--                            bound of the ≤5min design RPO)
--   require_replica          whether to require at least 1 streaming replica (default true; prerequisite
--                            for synchronous replication/automatic failover)
--
-- Checks (short-circuit in order; the first hit is FATAL):
--   1) archive_mode=on            -- otherwise there is no WAL archiving, hence no PITR;
--   2) at least 1 WAL segment archived successfully -- last_archived_time is not null;
--   3) archive lag <= threshold   -- repeated failures or unreachable object storage show up as a
--                                     stalled last_archived_time;
--   4) the latest attempt did not fail after the latest success -- failed_count is **cumulative**, so
--                                     historical failures must not alert forever;
--   5) a replica exists when require_replica -- a dropped Patroni synchronous replica first shows up
--                                     here as no replica.
-- =============================================================================
WITH arch AS (
    SELECT current_setting('archive_mode')::text       AS archive_mode,
           last_archived_time,
           last_archived_wal,
           last_failed_time,
           failed_count,
           archived_count
    FROM pg_stat_archiver
),
rep AS (
    SELECT count(*)                                   AS replicas,
           count(*) FILTER (WHERE sync_state = 'sync') AS sync_replicas
    FROM pg_stat_replication
)
SELECT CASE
    WHEN arch.archive_mode <> 'on' THEN
        'FATAL archive_mode=' || arch.archive_mode || ' (WAL archiving off -> no PITR)'
    WHEN arch.last_archived_time IS NULL THEN
        'FATAL archive_mode=on but no WAL has ever been archived (check archive_command / wal-gateway.sh)'
    WHEN now() - arch.last_archived_time > make_interval(secs => :'max_archive_lag_seconds'::int) THEN
        'FATAL archive lag ' || round(extract(epoch FROM now() - arch.last_archived_time))::text
        || 's > ' || :'max_archive_lag_seconds' || 's (RPO upper bound breached)'
    WHEN arch.last_failed_time IS NOT NULL
         AND (arch.last_archived_time IS NULL OR arch.last_failed_time > arch.last_archived_time) THEN
        'FATAL last archive attempt failed at ' || arch.last_failed_time::text
        || ' (failed_count=' || arch.failed_count || ')'
    WHEN :'require_replica'::boolean AND rep.replicas = 0 THEN
        'FATAL no streaming replica connected (sync replication / auto failover precondition)'
    ELSE
        'OK archived_count=' || arch.archived_count
        || ' last_archived_wal=' || coalesce(arch.last_archived_wal, '-')
        || ' lag=' || round(extract(epoch FROM now() - arch.last_archived_time))::text || 's'
        || ' replicas=' || rep.replicas
        || ' sync=' || rep.sync_replicas
END
FROM arch
CROSS JOIN rep;
