-- 0003_audit_metrics.sql — audit / metric snapshot / formats / plugins
-- Authoritative: doc ⑥ §2.3

-- ---------- audit (partitioned by week) ----------
-- ⑥ §9 D1: the old draft's single-column id primary key cannot be created on a partitioned table → PK (id, created_at)
create table if not exists audit_log (
  id         bigint generated always as identity,
  actor      text,
  action     text not null,
  target     text,
  detail     jsonb not null default '{}'::jsonb,
  ip         inet,
  created_at timestamptz not null default now(),
  primary key (id, created_at)
) partition by range (created_at);

create index if not exists audit_log_actor_idx  on audit_log (actor, created_at desc);
create index if not exists audit_log_action_idx on audit_log (action, created_at desc);

-- ---------- metric snapshot (data source for console trend charts) ----------
-- ⑥ §2.2/§2.5/§2.6 (unified in v0.6): partitioned **by day**. Online retention is only 30 days, so the partition span must
-- be smaller than the retention period, otherwise "daily DROP of old partitions" cannot work (a monthly partition holds both data to delete and data not to delete).
create table if not exists metric_snapshot (
  ts     timestamptz not null,
  scope  text not null,                                 -- node|cluster|user|topic|queue
  name   text not null,                                 -- connections|msg_rate|pending_depth|...
  labels jsonb not null default '{}'::jsonb,
  value  double precision not null,
  primary key (ts, scope, name, labels)
) partition by range (ts);

create index if not exists metric_snapshot_name_idx on metric_snapshot (name, ts desc);

-- ---------- formats and plugins ----------
create table if not exists formats (
  id           text primary key,
  type         text not null unique,                    -- the type namespace from design §5
  mime         text,
  handler      text not null default 'builtin' check (handler in ('builtin','plugin')),
  detect_rules jsonb not null default '{}'::jsonb,
  builtin      boolean not null default true,
  created_at   timestamptz not null default now()
);

create table if not exists plugins (
  id           text primary key,
  ns           text not null,
  version      int  not null,
  wasm         bytea,                                   -- WASM form
  sidecar_addr text,                                    -- sidecar form (the two are mutually exclusive)
  signature    bytea not null,                          -- Ed25519
  status       text not null default 'staging'
               check (status in ('staging','canary','active','rolled_back')),
  canary_ratio int not null default 0 check (canary_ratio between 0 and 100),
  config       jsonb not null default '{}'::jsonb,
  published_at timestamptz,
  unique (ns, version),
  check ((wasm is null) <> (sidecar_addr is null))      -- exactly one form
);

create index if not exists plugins_ns_status_idx on plugins (ns, status);

-- ---------- partition pre-creation ----------
do $$
declare
  start_week date := (date_trunc('week', now())::date - interval '2 week');
  w date;
  part text;
begin
  for i in 0..5 loop
    w := (start_week + (i * 7 || ' day')::interval)::date;
    part := 'audit_log_y' || to_char(w, 'IYYY') || 'w' || to_char(w, 'IW');
    execute format(
      'create table if not exists %I partition of audit_log for values from (%L) to (%L)',
      part, w, (w + interval '7 day')::date
    );
  end loop;
end $$;

do $$
declare
  start_day date := (current_date - interval '1 day');
  d date;
  part text;
begin
  -- 1 day back to 7 days ahead (⑥ §2.5: the pre-creation window is compatible with the 30-day retention; daily volume is 10⁵, so one partition is small enough)
  for i in 0..8 loop
    d := (start_day + i)::date;
    part := 'metric_snapshot_y' || to_char(d, 'YYYY') || 'm' || to_char(d, 'MM') || 'd' || to_char(d, 'DD');
    execute format(
      'create table if not exists %I partition of metric_snapshot for values from (%L) to (%L)',
      part, d, (d + 1)::date
    );
  end loop;
end $$;
