-- 0009_media_recordings.sql — media recording segment index (PL-13 13.6 search/download)
--
-- Background: the recording path (minimal version + bus mode) only writes raw frames to object storage as `[4B BE len][body]` segments
--       (key `media/record/{stream_id}/{node_id}/{first_seq:020}.bin`) with **no index at all**,
--       so there is no way to list "which segments a stream recorded" and no download entry point. This adds a **metadata-only index table**:
--       each time a segment object is written, one row is inserted idempotently (`object_key` unique), and
--       the API `GET /v1/media/recordings*` reads only this table + issues MinIO presigned URLs on the spot.
--
-- No payload is stored: the object content is still "frame boundaries + raw WS tunnel body", not a playable file; this table stores only
--       search fields such as segment bounds/frame count/byte count/object location (② §3.2: large objects live in object storage, PG stores no bytes).
--
-- Idempotency rules (consistent with the two recording paths):
--   * the bus path's object key is determined by the **segment's first frame seq** (a replay overwrites the same object) → on replay the same
--     `object_key` is inserted again and deduped by `on conflict (object_key) do nothing`;
--   * the direct-write path (bus=redis-pubsub / publish-failure degradation) has an object key containing UTC seconds + an in-process flush sequence,
--     so a replay gets a different key → treated as a new segment (matching the new object in object storage one-to-one).
--
-- Field semantics:
--   * `first_seq`/`last_seq`: on the **bus path** these are the first/last frame seq of the segment (high bits from the millisecond timestamp + in-process counter,
--     see `routing/media_record.rs::next_record_seq`), used for replay idempotency and ordered playback;
--     the **direct-write path has no frame seq concept** (the raw `stream-data` body contains no seq), so these are NULL —
--     no sequence is fabricated, and callers can simply order by `created_at`;
--   * `frames`: frames in the segment (counted by `[4B len]` boundaries); `size_bytes`: object byte count (including each frame's 4B prefix);
--   * `bucket`: the bucket holding the object (`[media] record_bucket`, falling back to `[s3] bucket_media`), used to issue download URLs;
--   * `created_at`: index write time (= after the object is durably stored); `started_at`/`ended_at`: the
--     frame time range covered by the segment (approximated from frame arrival time on the bus path, NULL on the direct-write path);
--   * `codec`/`format`: reserved for later MP4/OGG packaging and transcoding (**not written in this round**, always NULL).
--
-- Migration discipline (⑥ §8): forward only; idempotent and re-entrant (`create table/index if not exists` +
--   checking `pg_constraint` before adding constraints). This file is tracked by sqlx migrations and normally runs only once.

create table if not exists media_recordings (
  id         text primary key,                 -- ULID (§17.2: always text, never uuid)
  stream_id  text not null,
  node_id    text not null,
  object_key text not null unique,             -- idempotency key: only one row per object
  first_seq  bigint,                           -- the direct-write path has no frame seq → NULL
  last_seq   bigint,                           -- same as above
  frames     integer not null,                 -- frames in the segment (≥1; an empty segment is neither stored nor indexed)
  size_bytes bigint not null,                  -- object byte count
  bucket     text not null,                    -- bucket holding the object
  created_at timestamptz not null default now(),
  started_at timestamptz,                      -- time of the segment's first frame (NULL on the direct-write path)
  ended_at   timestamptz,                      -- time of the segment's last frame (NULL on the direct-write path)
  codec      text,                             -- reserved: codec (always NULL in this round)
  format     text                              -- reserved: container format MP4/OGG (always NULL in this round)
);

-- Main list/filter query: `where stream_id = $1 order by created_at desc, id desc limit n`.
-- created_at and id are combined in one index so cursor pagination (before=id) also uses it.
create index if not exists media_recordings_stream_created_idx
  on media_recordings (stream_id, created_at desc, id desc);
-- List/pagination without a stream filter (most recent recordings overall).
create index if not exists media_recordings_created_idx
  on media_recordings (created_at desc, id desc);

-- Defensive value constraints (already guaranteed by the API/write path; these only block dirty data written directly to the DB bypassing the API).
do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'media_recordings_size_check'
      and conrelid = 'media_recordings'::regclass
  ) then
    alter table media_recordings
      add constraint media_recordings_size_check
      check (frames >= 1 and size_bytes >= 0);
  end if;
end $$;
