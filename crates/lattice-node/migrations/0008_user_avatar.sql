-- 0008_user_avatar.sql — user avatar (v0.8: profile gains "avatar")
--
-- Background: users reported "the user avatar cannot be set". Account profiles previously had only display_name, so the account menu / user
--       management page could only render initials. This adds a nullable avatar column to users:
--         user  = set/change/clear their own (PATCH /v1/users/me)
--         ops   = view/modify in user management (PATCH /v1/admin/users/{id})
--         admin = same as above
--       The value allows only an https:// URL or data:image/(png|jpeg|webp|gif);base64,... (② §9.1:
--       no object storage/avatar-cropping service is introduced); format, MIME allowlist, and size cap are validated by the API layer
--       (character/byte length, data URL prefix, and base64 validity are all in `validate_avatar` in
--       `transport/http.rs`, with error code 422 FORMAT + details.field=avatar).
--
-- Capacity: the API layer caps the whole string at ≤ 256 KiB of UTF-8 bytes (262144 B, including the data URL prefix);
--       this migration sets the DB fallback cap to 300 KiB (307200 B) — a 25% margin that avoids "API validation
--       passes, DB write fails" 500s, while still blocking oversized rows written directly to the DB bypassing the API (a text column
--       can itself store 1GB, so no constraint means no cap).
--
-- Migration discipline (⑥ §8): forward only; idempotent and re-entrant.
--   PostgreSQL's `add column if not exists` is idempotent; but `add constraint` has no
--   `if not exists`, so constraints are added after checking `pg_constraint` (same approach as 0007),
--   which can be replayed safely on existing and fresh databases. sqlx still runs the whole migration in a single transaction.
--
-- Other notes: this file is tracked by sqlx migrations (`_sqlx_migrations`) and normally runs only once;
--   existing data is not scrubbed (every current user's avatar is NULL = no avatar, and the frontend falls back to initials).

-- ---------- 1) Add column: avatar text (nullable, NULL = no avatar) ----------
alter table users add column if not exists avatar text;

-- ---------- 2) DB fallback length constraint: ≤ 300 KiB ----------
-- The API layer caps at 256 KiB; the 300 KiB here is only a defensive fallback that normal requests never reach.
do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'users_avatar_len_check'
      and conrelid = 'users'::regclass
  ) then
    alter table users
      add constraint users_avatar_len_check
      check (avatar is null or octet_length(avatar) <= 307200);
  end if;
end $$;
