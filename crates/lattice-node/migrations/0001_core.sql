-- 0001_core.sql — users / devices / conversations / members
-- Authoritative: doc ⑥ §2.3 (DDL), design §8.1 / §17.11 (values)
-- Migration discipline (⑥ §8): forward only; must be idempotent and re-entrant (IF NOT EXISTS / conditional checks)

create table if not exists users (
  id            text primary key,                       -- ULID (§8.1: always text, never uuid)
  username      text not null unique,
  password_hash text not null,                          -- argon2id
  display_name  text,
  status        text not null default 'active'
                check (status in ('active','suspended','deleted')),
  role          text not null default 'viewer'
                check (role in ('admin','ops','viewer')), -- admin-plane RBAC (⑥ §2.3 D14; a different domain from conversation_members.role)
  capabilities  jsonb not null default '{}'::jsonb,     -- {formats[],compression[],e2e,quic,webrtc}
  quota         jsonb not null default '{}'::jsonb,     -- {msg_per_s,bytes_per_s,topics,storage_bytes}
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

-- Add columns for existing databases (⑥ §8 migration discipline: must be idempotent and re-entrant)
alter table users add column if not exists role text not null default 'viewer'
  check (role in ('admin','ops','viewer'));

create index if not exists users_status_idx on users (status) where status <> 'active';

create table if not exists devices (
  id          text primary key,
  user_id     text not null references users(id) on delete cascade,
  name        text,
  platform    text,                                     -- windows|macos|linux|android|ios|iot
  token_hash  text,                                     -- hash of the refresh token (hash only, §17.11)
  fingerprint text,
  last_seen   timestamptz,
  revoked_at  timestamptz
);

create index if not exists devices_user_idx on devices (user_id, revoked_at);

-- One active device per user per fingerprint (⑥ §2.3 / D10: otherwise the device table grows without bound + ghost routes)
create unique index if not exists devices_active_fp_uk
  on devices (user_id, fingerprint)
  where revoked_at is null and fingerprint is not null;

create index if not exists devices_token_idx on devices (token_hash) where revoked_at is null;

create table if not exists conversations (
  id         text primary key,
  kind       text not null check (kind in ('dm','group','topic')),
  name       text,
  created_at timestamptz not null default now()
);

create index if not exists conversations_kind_idx on conversations (kind, created_at desc);

-- Topics and subscriptions reuse these two tables (⑥ §2.3 D13: no separate topics/subscriptions tables exist)
create unique index if not exists conversations_topic_name_uk
  on conversations (name) where kind = 'topic';

create table if not exists conversation_members (
  conv_id   text not null references conversations(id) on delete cascade,
  user_id   text not null references users(id) on delete cascade,
  joined_at timestamptz not null default now(),
  role      text not null default 'member' check (role in ('member','owner')),
  primary key (conv_id, user_id)
);

create index if not exists conversation_members_user_idx on conversation_members (user_id);
