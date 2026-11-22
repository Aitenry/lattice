-- 0004_seed.sql — built-in format registry (the type namespace from design §5 + §6.1 FormatSpec)
-- Idempotent: on conflict do nothing; plugin formats are registered via the admin plane POST /v1/admin/formats

insert into formats (id, type, mime, handler, detect_rules, builtin) values
  ('01JFORMATTEXT00000000000000', 'text',    'text/plain',            'builtin', '{"magic":[],"ext":[".txt"]}', true),
  ('01JFORMATJSON00000000000000', 'json',    'application/json',      'builtin', '{"magic":["7b"],"ext":[".json"]}', true),
  ('01JFORMATXML000000000000000', 'xml',     'application/xml',       'builtin', '{"magic":["3c3f786d6c"],"ext":[".xml"]}', true),
  ('01JFORMATPROTO0000000000000', 'proto',   'application/protobuf',  'builtin', '{"magic":[],"ext":[".pb"]}', true),
  ('01JFORMATMSGPACK00000000000', 'msgpack', 'application/msgpack',   'builtin', '{"magic":[],"ext":[".msgpack"]}', true),
  ('01JFORMATBINARY000000000000', 'binary',  'application/octet-stream', 'builtin', '{"magic":[],"ext":[]}', true),
  ('01JFORMATFILE00000000000000', 'file',    'application/octet-stream', 'builtin', '{"magic":[],"ext":[]}', true),
  ('01JFORMATIMAGE0000000000000', 'image',   'image/*',               'builtin', '{"magic":["89504e47","ffd8ff"],"ext":[".png",".jpg"]}', true),
  ('01JFORMATMEDIA0000000000000', 'media',   'video/*',               'builtin', '{"magic":["00000018"],"ext":[".mp4"]}', true),
  ('01JFORMATSTREAM000000000000', 'stream',  'application/vnd.lattice.stream', 'builtin', '{"magic":[],"ext":[]}', true)
on conflict (type) do nothing;

-- Initial dynamic config rows: authoritative values (⑥ §2.3). The node reads this table at startup, then subscribes to `lattice:cfg`
insert into dynamic_config (key, value, updated_by) values
  ('ratelimit.msg_per_s',        '100'::jsonb,  'bootstrap'),
  ('ratelimit.bytes_per_s',      '26214400'::jsonb, 'bootstrap'),
  ('ratelimit.topics_per_user',  '100'::jsonb,  'bootstrap'),
  ('plugins.enabled',            'true'::jsonb, 'bootstrap'),
  ('canary.ratio',               '0'::jsonb,    'bootstrap')
on conflict (key) do nothing;
