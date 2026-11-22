-- 0002_messages.sql — messages / dedup / chunk index / watermark / read / dynamic config / delivery audit
-- Authoritative: doc ⑥ §2.3

-- ---------- messages (partitioned by month) ----------
-- A partitioned table's primary key must include the partition key → PK (id, created_at) (⑥ §9 D1, same class of fix)
create table if not exists messages (
  id           text not null,
  conv_id      text not null,
  sender       text not null,
  env_type     text not null,
  content_type text,
  size         bigint not null check (size >= 0),
  chunk_total  int not null default 1 check (chunk_total >= 1),
  payload      bytea,                                   -- ≤1MB inline (§17.6)
  payload_ref  text,                                    -- large-object MinIO object key
  status       text not null default 'persisted'
               check (status in ('persisted','expired','dropped')),  -- §17.3 subset on a message row
  seq          bigint not null check (seq > 0),
  created_at   timestamptz not null default now(),
  expires_at   timestamptz,                             -- null = never expires (ttl_seconds=0)
  primary key (id, created_at)
) partition by range (created_at);

create index if not exists messages_conv_seq_idx  on messages (conv_id, seq desc);
create index if not exists messages_expires_idx   on messages (expires_at) where expires_at is not null;
create index if not exists messages_sender_idx    on messages (sender, created_at desc);
-- Note: there is **no** unique (conv_id, seq) — a partitioned table cannot have a global unique index across months (⑥ §9 D6),
-- so seq uniqueness is guaranteed by lattice:seq:{conv} + conv_seq_watermark and reconciled by lock:reconcile-seq.

-- ---------- dedup cold layer (not partitioned: global unique constraint) ----------
create table if not exists message_dedup (
  id         text primary key,                          -- logical message id or chunk <id>.c<i> (§17.2)
  conv_id    text,
  created_at timestamptz not null default now(),
  expires_at timestamptz                                -- null = retained with the message (never-expiring message, §17.5)
);
create index if not exists message_dedup_ttl_idx on message_dedup (expires_at);

-- ---------- chunk index ----------
create table if not exists chunks_index (
  id          text primary key,                         -- = '<msg_id>.c<idx>'
  msg_id      text not null,                            -- **no foreign key**: messages has no single-column unique index on id (⑥ §9 D3)
  total       int  not null check (total >= 1),
  idx         int  not null check (idx >= 0 and idx < total),
  size        bigint not null,
  checksum    bytea,                                    -- per-chunk xxhash64
  storage_key text,                                     -- null for network chunks; object key for MinIO chunks
  uploaded_at timestamptz not null default now()
);
create unique index if not exists chunks_index_msg_idx_uk on chunks_index (msg_id, idx);
create index if not exists chunks_index_uploaded_idx on chunks_index (uploaded_at);

-- ---------- watermark ----------
create table if not exists conv_seq_watermark (
  conv_id    text primary key,
  seq        bigint not null,
  updated_at timestamptz not null default now()
);

create table if not exists topic_offsets (
  user_id     text not null,
  topic       text not null,
  last_offset bigint not null default 0,                -- §18 D6 default: one watermark per user per topic
  updated_at  timestamptz not null default now(),
  primary key (user_id, topic)
);

-- ---------- read watermark (business read state, independent of the delivery state machine) ----------
-- §17.4-4 + ⑤ §3: POST /v1/conversations/{id}/read writes this table; the conversation list's unread is derived from it
create table if not exists read_watermark (
  conv_id       text not null,
  user_id       text not null,                          -- redundant column: batch queries for "conversations I am in"
  device_id     text not null,                          -- per device; multi-device read progress never overwrites each other
  last_read_seq bigint not null default 0,
  updated_at    timestamptz not null default now(),
  primary key (conv_id, device_id)
);
create index if not exists read_watermark_user_idx on read_watermark (user_id, updated_at desc);

-- ---------- authoritative dynamic config values ----------
-- `lattice:cfg` only broadcasts changes and is not persistent (⑥ §9 D12): authoritative values must land in PG, otherwise a restart silently falls back to TOML
create table if not exists dynamic_config (
  key        text primary key,
  value      jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);

-- ---------- delivery audit ----------
-- PK includes to_device: each device ACKs independently (§17.4-2), so it is **not partitioned** (⑥ §2.7)
create table if not exists delivery_log (
  msg_id     text not null,
  to_user    text not null,
  to_device  text not null,
  state      text not null,                             -- §17.3 eight states
  attempts   int  not null default 0,
  last_at    timestamptz,
  acked_at   timestamptz,
  node_id    text,
  created_at timestamptz not null default now(),
  primary key (msg_id, to_user, to_device)
);
create index if not exists delivery_log_user_state_idx on delivery_log (to_user, state, last_at desc);
create index if not exists delivery_log_created_idx    on delivery_log (created_at);
create index if not exists delivery_log_dlq_idx        on delivery_log (last_at desc) where state = 'dlq';

-- ---------- partition pre-creation ----------
-- Pre-created 3 months ahead (⑥ §2.5, task lock:partition-maint); the migration first creates -1..+3 months so the first batch is usable
do $$
declare
  start_month date := date_trunc('month', now())::date - interval '1 month';
  m date;
  part text;
begin
  for i in 0..4 loop
    m := (start_month + (i || ' month')::interval)::date;
    part := 'messages_y' || to_char(m, 'YYYY') || 'm' || to_char(m, 'MM');
    execute format(
      'create table if not exists %I partition of messages for values from (%L) to (%L)',
      part, m, (m + interval '1 month')::date
    );
  end loop;
end $$;
