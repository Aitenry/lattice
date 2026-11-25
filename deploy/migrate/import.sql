-- ---------------------------------------------------------------------------
-- import.sql — load the production seed into the production PostgreSQL instance
--
-- Runs inside the production PostgreSQL container (psql -f) after the node has
-- applied the schema on its first start. The four target tables are replaced
-- atomically; the fresh-instance guard refuses to run once real message traffic
-- exists, so this can be re-run after a failed seed but never against a live
-- production database by accident.
--
-- Devices and audit rows are NOT migrated (out of scope). The device id in
-- hub_plugin_installs.last_device therefore has no referent in production, so it
-- is cleared; every other column is copied verbatim.
-- ---------------------------------------------------------------------------
\set ON_ERROR_STOP on

begin;

do $$
begin
  if (select count(*) from messages) > 0 or (select count(*) from conversations) > 0 then
    raise exception 'refusing to reseed: production already contains message/conversation data';
  end if;
end $$;

truncate table hub_plugin_installs, hub_plugin_versions, hub_plugins, users cascade;

\copy users (id, username, password_hash, display_name, status, role, capabilities, quota, created_at, updated_at, avatar) from '/tmp/lattice-migrate/users.csv' with (format csv, header true)

\copy hub_plugins (id, plugin_id, name, description, readme, icon, category, tags, owner_id, status, latest_version, downloads, created_at, updated_at) from '/tmp/lattice-migrate/hub_plugins.csv' with (format csv, header true)

\copy hub_plugin_versions (id, plugin_row_id, version, asset_name, size, sha256, object_key, changelog, manifest, status, downloads, uploaded_by, published_at, created_at, source_asset_name, source_size, source_sha256, source_object_key, meta, review_note, reviewed_by, reviewed_at, submitted_at) from '/tmp/lattice-migrate/hub_plugin_versions.csv' with (format csv, header true)

\copy hub_plugin_installs (user_id, plugin_id, version, enabled, data, data_rev, data_updated_at, last_device, updated_at) from '/tmp/lattice-migrate/hub_plugin_installs.csv' with (format csv, header true)

-- Devices are out of scope; do not keep dangling device references.
update hub_plugin_installs set last_device = null;

-- Structural guards: exactly the three accounts, one (latest) version per plugin,
-- every install pointing at a migrated plugin.
do $$
declare
  n_users int;
  bad_plugin int;
  bad_install int;
begin
  select count(*) into n_users from users;
  if n_users <> 3 then
    raise exception 'expected 3 users after import, found %', n_users;
  end if;

  select count(*) into bad_plugin
  from hub_plugins p
  where (select count(*) from hub_plugin_versions v where v.plugin_row_id = p.id) <> 1
     or not exists (
       select 1 from hub_plugin_versions v
       where v.plugin_row_id = p.id and v.version = p.latest_version and v.status = 'published'
     );
  if bad_plugin <> 0 then
    raise exception '% plugin(s) do not have exactly one published latest version', bad_plugin;
  end if;

  select count(*) into bad_install
  from hub_plugin_installs i
  where not exists (select 1 from hub_plugins p where p.plugin_id = i.plugin_id);
  if bad_install <> 0 then
    raise exception '% install record(s) reference a plugin that was not imported', bad_install;
  end if;
end $$;

commit;

select 'users' as table_name, count(*) as rows_imported from users
union all select 'hub_plugins', count(*) from hub_plugins
union all select 'hub_plugin_versions', count(*) from hub_plugin_versions
union all select 'hub_plugin_installs', count(*) from hub_plugin_installs;
