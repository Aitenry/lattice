-- 0006_hub_source.sql — plugin version source packages (v2 contract §1.1 / design §17.16 / doc ⑤ §12.4 / doc ⑥ §2.3, §4.1)
--
-- Optional **source-code zip** per version (independent of the install package): the four columns are either all empty (no source for this version),
-- or all non-empty. The source package uses the same bucket `lattice-plugins` as the install package, with an extra `source/` segment in the object key:
--   {plugin_id}/{version}/source/{source_asset_name}
--
-- Migration discipline (⑥ §8): forward only; idempotent and re-entrant (IF NOT EXISTS / DO blocks).
--
-- Note: PG's `add column if not exists` does **not support inline CHECK constraints** (an inline form would
-- fail on a re-run because the constraint already exists), so columns and constraints are done in two steps: add columns idempotently first, then
-- add constraints in a DO block after checking `pg_constraint`.

-- ---------- version source-package metadata (all nullable) ----------
alter table hub_plugin_versions add column if not exists source_asset_name text;  -- ≤128, .zip
alter table hub_plugin_versions add column if not exists source_size       bigint; -- 1..50MiB
alter table hub_plugin_versions add column if not exists source_sha256     text;   -- lowercase hex, 64 chars
alter table hub_plugin_versions add column if not exists source_object_key text;   -- {plugin_id}/{version}/source/{source_asset_name}

-- ---------- constraints (same approach as the size/sha256 CHECKs in 0005: constrain values structurally) ----------
-- A source package has three legal states:
--   ① no source: all four columns empty;
--   ② declared but not uploaded: asset_name/size/sha256 set, object_key NULL (written at POST time,
--      at which point the client receives the `source_upload` target and details show `has_source=false`);
--   ③ uploaded: all four columns set, and object_key must look like `.../source/{asset_name}`.
-- Why ②/③ must be distinguished: `has_source`, the download 404, and PUT idempotency all depend on "does the object really exist",
-- not merely on "was the metadata declared"; object_key serves as the upload-complete marker so that no extra boolean column is needed.
-- Why do it at the constraint layer: application-level validation is bypassed by "ops writing to the DB directly, bypassing the API" (same reasoning as ⑥ §2.3).
do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'hub_versions_source_check'
      and conrelid = 'hub_plugin_versions'::regclass
  ) then
    alter table hub_plugin_versions
      add constraint hub_versions_source_check check (
        (source_asset_name is null and source_size is null
         and source_sha256 is null and source_object_key is null)
        or (
          source_asset_name is not null
          and source_size is not null
          and source_sha256 is not null
          and source_size > 0
          and source_size <= 52428800                                   -- 50MiB (§17.16)
          and source_sha256 ~ '^[0-9a-f]{64}$'                          -- lowercase hex
          and source_asset_name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip$'
          and (
            source_object_key is null                                   -- ② declared, not uploaded
            or (
              source_object_key like '%/source/%'                       -- ③ uploaded
              and right(source_object_key, length(source_asset_name)) = source_asset_name
            )
          )
        )
      );
  end if;
end $$;
