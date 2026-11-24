-- 0012_hub_review.sql — plugin hub admin review workflow
--
-- Product rule (2026-11-23):
--   * a user-published plugin (first publish **and every new version**) is visible to other
--     users only after an administrator approves it;
--   * the owner can still see the submitted/rejected version; everybody else gets 404;
--   * an approved (`published`) version is immutable: changing it requires a new version
--     that goes through review again;
--   * only an admin may approve/reject.
--
-- State machine of `hub_plugin_versions.status`:
--   pending  -- POST metadata, package body not uploaded yet (30-min draft TTL) -->
--   review   -- package body stored, waiting for an administrator -->
--   published-- approved; the only state visible/installable to other users
--   rejected -- an administrator rejected it; owner sees the note and may re-submit
--   removed  -- owner unpublish / expired draft / GC (terminal)
--
-- `meta` snapshots the catalog fields (name/description/readme/icon/category/tags) of the
-- submitted version. They are applied to `hub_plugins` only when the version is approved,
-- so editing a draft never mutates an already published plugin page.
--
-- Migration discipline (⑥ §8): forward only; idempotent and re-entrant.

-- ---------- widen the version status domain ----------
alter table hub_plugin_versions drop constraint if exists hub_plugin_versions_status_check;
alter table hub_plugin_versions add constraint hub_plugin_versions_status_check
  check (status in ('pending','review','published','rejected','removed'));

-- ---------- review bookkeeping ----------
alter table hub_plugin_versions add column if not exists meta         jsonb; -- catalog-field snapshot of this submission
alter table hub_plugin_versions add column if not exists review_note  text;  -- rejection reason shown to the owner
alter table hub_plugin_versions add column if not exists reviewed_by  text references users(id);
alter table hub_plugin_versions add column if not exists reviewed_at  timestamptz;
alter table hub_plugin_versions add column if not exists submitted_at timestamptz; -- latest submit-for-review time (resubmits update it)

-- Review queue: the admin list is "all rows in review, oldest first" and stays small.
create index if not exists hub_versions_review_idx
  on hub_plugin_versions (status, submitted_at)
  where status = 'review';

-- Existing published versions keep their behavior; their `meta` stays NULL so approving a
-- future version never resurrects stale catalog fields from an old row.
