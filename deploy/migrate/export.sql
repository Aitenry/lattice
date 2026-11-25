-- ---------------------------------------------------------------------------
-- export.sql — extract the production seed from the development instance
--
-- Runs inside the development PostgreSQL container (psql -f). It writes CSV files
-- to /tmp/lattice-migrate/ inside that container; the orchestrator (seed.mjs) then
-- copies the directory to the production container. No data leaves the containers
-- as text, so UTF-8 display names / plugin metadata round-trip byte for byte.
--
-- Scope (the only data the production instance keeps):
--   users                exactly admin (Eddie), ops (Lucas), user (Mia)
--   hub_plugins          published plugins owned by those three accounts
--   hub_plugin_versions  only the version each plugin points at as latest_version
--   hub_plugin_installs  install records (data jsonb / revision / enabled) for those users
--
-- Everything else (messages, conversations, devices, audit, metrics, removed test
-- plugins, historical plugin versions) is intentionally excluded.
-- ---------------------------------------------------------------------------
\set ON_ERROR_STOP on

-- Guard: the three accounts must exist, otherwise the seed would silently be empty.
do $$
declare n int;
begin
  select count(*) into n from users where username in ('admin', 'ops', 'user');
  if n <> 3 then
    raise exception 'expected 3 target users (admin, ops, user), found %', n;
  end if;
end $$;

\copy (select u.id, u.username, u.password_hash, u.display_name, u.status, u.role, u.capabilities, u.quota, u.created_at, u.updated_at, u.avatar from users u where u.username in ('admin', 'ops', 'user') order by u.username) to '/tmp/lattice-migrate/users.csv' with (format csv, header true)

\copy (select p.id, p.plugin_id, p.name, p.description, p.readme, p.icon, p.category, p.tags, p.owner_id, p.status, p.latest_version, p.downloads, p.created_at, p.updated_at from hub_plugins p join users u on u.id = p.owner_id where u.username in ('admin', 'ops', 'user') and p.status = 'published' and p.latest_version is not null order by p.plugin_id) to '/tmp/lattice-migrate/hub_plugins.csv' with (format csv, header true)

\copy (select v.id, v.plugin_row_id, v.version, v.asset_name, v.size, v.sha256, v.object_key, v.changelog, v.manifest, v.status, v.downloads, v.uploaded_by, v.published_at, v.created_at, v.source_asset_name, v.source_size, v.source_sha256, v.source_object_key, v.meta, v.review_note, v.reviewed_by, v.reviewed_at, v.submitted_at from hub_plugin_versions v join hub_plugins p on p.id = v.plugin_row_id join users u on u.id = p.owner_id where u.username in ('admin', 'ops', 'user') and p.status = 'published' and p.latest_version is not null and v.version = p.latest_version and v.status = 'published' order by p.plugin_id) to '/tmp/lattice-migrate/hub_plugin_versions.csv' with (format csv, header true)

\copy (select i.user_id, i.plugin_id, i.version, i.enabled, i.data, i.data_rev, i.data_updated_at, i.last_device, i.updated_at from hub_plugin_installs i join users u on u.id = i.user_id join hub_plugins p on p.plugin_id = i.plugin_id where u.username in ('admin', 'ops', 'user') and p.status = 'published' and p.latest_version is not null and exists (select 1 from users o where o.id = p.owner_id and o.username in ('admin', 'ops', 'user')) order by i.user_id, i.plugin_id) to '/tmp/lattice-migrate/hub_plugin_installs.csv' with (format csv, header true)

-- Human-readable summary in the psql log.
select 'users' as table_name, count(*) as rows_exported from users where username in ('admin', 'ops', 'user')
union all
select 'hub_plugins', count(*) from hub_plugins p join users u on u.id = p.owner_id where u.username in ('admin', 'ops', 'user') and p.status = 'published' and p.latest_version is not null
union all
select 'hub_plugin_versions', count(*) from hub_plugin_versions v join hub_plugins p on p.id = v.plugin_row_id join users u on u.id = p.owner_id where u.username in ('admin', 'ops', 'user') and p.status = 'published' and p.latest_version is not null and v.version = p.latest_version and v.status = 'published'
union all
select 'hub_plugin_installs', count(*) from hub_plugin_installs i join users u on u.id = i.user_id join hub_plugins p on p.plugin_id = i.plugin_id where u.username in ('admin', 'ops', 'user') and p.status = 'published' and p.latest_version is not null and exists (select 1 from users o where o.id = p.owner_id and o.username in ('admin', 'ops', 'user'));
