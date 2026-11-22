-- =============================================================================
-- Lattice PG archive / PITR health check (read-only; superuser not required)
-- -----------------------------------------------------------------------------
-- Purpose: run by the backup.pitr.verifySchedule CronJob every 15 minutes (psql -f on this file),
--       printing a single line `OK ...` or `FATAL ...`; the CronJob script derives the exit code from the prefix (non-zero triggers a Job failure alert).
-- Aligned with: this file is **byte-identical** to deploy/production/backup/archive-verify.sql (use one or the other when deploying);
--       scripts/ha-prod-validate.py verifies both copies match, preventing "fixed in the template but not synced to the production script".
--
-- psql variables (passed by the caller via -v):
--   max_archive_lag_seconds  maximum allowed archive lag in seconds (default 300; the mechanism-level bound of the design's RPO ≤5min)
--   require_replica          whether at least one streaming replica is required (default true; prerequisite for synchronous replication/automatic failover)
--
-- Criteria (short-circuiting in order; the first hit is FATAL):
--   1) archive_mode=on            — otherwise there is no WAL archiving, hence no PITR;
--   2) at least 1 WAL segment archived successfully — last_archived_time is non-null;
--   3) archive lag <= threshold   — repeated failures/unreachable object storage show up as a stalled last_archived_time;
--   4) the last failed attempt is not later than the last success — failed_count is **cumulative**, so historical failures must not alert forever;
--   5) a replica exists when require_replica — a synchronous-replication outage under Patroni shows up here first as no replica.
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
