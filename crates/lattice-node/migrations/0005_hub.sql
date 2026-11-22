-- 0005_hub.sql — client plugin hub (design §6.9 / design §17.16 / doc ⑤ §12 / doc ⑥ §2.3, §4.1)
--
-- **Unrelated** to the `plugins` table from 0003: that table holds server-side format handlers (WASM/sidecar), while this migration is
-- distribution and install records for desktop-client third-party plugins. Their lifecycles differ, so they do not share a state machine.
--
-- Migration discipline (⑥ §8): forward only; idempotent and re-entrant (IF NOT EXISTS / DO blocks).

-- ---------- plugin record (owner + catalog fields + latest-version pointer) ----------
create table if not exists hub_plugins (
  id             text primary key,                        -- ULID
  plugin_id      text not null unique,                    -- client PluginManifest.id (§17.16 regex)
  name           text not null,
  description    text not null default '',
  readme         text not null default '',
  icon           text,
  category       text not null default 'other'
                 check (category in ('productivity','ai','media','devtools','data','other')),
  tags           text[] not null default '{}',
  owner_id       text not null references users(id),
  status         text not null default 'published'
                 check (status in ('published','removed')),
  latest_version text,
  downloads      bigint not null default 0,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);
create index if not exists hub_plugins_catalog_idx on hub_plugins (status, updated_at desc);
create index if not exists hub_plugins_owner_idx   on hub_plugins (owner_id);

-- ---------- versions (package metadata + object key + state machine pending→published→removed) ----------
create table if not exists hub_plugin_versions (
  id            text primary key,                         -- ULID
  plugin_row_id text not null references hub_plugins(id) on delete cascade,
  version       text not null,                            -- semver (§17.16)
  asset_name    text not null,
  size          bigint not null check (size > 0 and size <= 20971520),
  sha256        text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  object_key    text not null,                            -- lattice-plugins/{plugin_id}/{version}/{asset_name}
  changelog     text not null default '',
  manifest      jsonb not null default '{}'::jsonb,
  status        text not null default 'pending'
                check (status in ('pending','published','removed')),
  downloads     bigint not null default 0,
  uploaded_by   text references users(id),
  published_at  timestamptz,
  created_at    timestamptz not null default now(),
  unique (plugin_row_id, version)
);
create index if not exists hub_versions_plugin_idx
  on hub_plugin_versions (plugin_row_id, status, published_at desc);

-- ---------- install records + plugin data snapshot (one row per user per plugin) ----------
create table if not exists hub_plugin_installs (
  user_id         text not null references users(id) on delete cascade,
  plugin_id       text not null,
  version         text not null,
  enabled         boolean not null default true,
  data            jsonb not null default '{}'::jsonb,
  data_rev        bigint not null default 0,
  data_updated_at timestamptz,
  last_device     text,
  updated_at      timestamptz not null default now(),
  primary key (user_id, plugin_id)
);
create index if not exists hub_installs_plugin_idx on hub_plugin_installs (plugin_id);
