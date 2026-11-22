-- 0010_media_recording_manifest.sql — media recording playback manifest index (PL-13 13.6)
--
-- Background: 0009 only indexes the segment object's bounds/size/frame count; a client given a 4MiB
--       `[4B BE len][body]` raw frame container still **has no idea where the frame boundaries are**; this adds
--       a **playback manifest** object per segment (`media/manifest/record/...`,
--       one-to-one with the segment object, with a key deterministically derivable from object_key):
--
--         {version:1, stream_id, node_id, object_key, size,
--          frames:[{seq,offset,len,ts?}], total_bytes, created_at,
--          codec:null, format:"raw-frames", playable:false, frames_truncated}
--
--       The manifest contains only a **frame index** (in-segment byte offset/length/frame seq), not frame payload bytes; it still describes
--       the raw frame container rather than a playable file (no MP4/OGG packaging/transcoding → `playable:false`).
--       A manifest write/generation failure only WARNs and does not block recording forwarding (same rule as the index table).
--
-- Field semantics:
--   * `manifest_key`: full key of the manifest object (the bucket is the same as the index row's `bucket`);
--   * **NULL = old row (written in the 0009 era) / manifest generation failed**: the manifest API returns
--     404 not_found for these rows instead of fabricating a manifest; read/write functions select by column name, and old clients ignore the new field (backward compatible);
--   * idempotency: the manifest key is deterministically derived from object_key (a replay overwrites the same object), and on replay
--     `on conflict (object_key) do nothing` keeps the first manifest_key (same object → same key).
--
-- Migration discipline (⑥ §8): forward only; idempotent and re-entrant (`add column if not exists`).
--   This file is tracked by sqlx migrations and normally runs only once.

alter table media_recordings
  add column if not exists manifest_key text;
