-- 0007_roles_user.sql — admin-plane RBAC role rename: viewer → user (v0.7)
--
-- Background: per the product definition, admin-plane roles change from "admin / ops / viewer (read-only)" to
--       "admin / ops / user (user, read-only)" — **rename only, no relaxation of semantics**:
--         user  = read-only (online/nodes/queues/audit/lists/search)
--         ops   = read-only + actions (drain / replay / queue.purge / block / device revoke)
--         admin = everything, including mutations (create account / change role / quota / purge / config / keys.rotate / plugin publish)
--       Compatibility for the old value is kept only on the read path (server `Role::parse("viewer") => User`,
--       so old DB data and old JWT claims keep working); write endpoints accept only admin|ops|user.
--
-- Migration discipline (⑥ §8): forward only; idempotent and re-entrant.
-- Execution order (**the order itself is part of correctness**):
--   1) Drop the old CHECK constraint first — the old `role in ('admin','ops','viewer')` would immediately reject changing rows
--      to `'user'`; so it must be "drop old constraint → migrate data → create new constraint".
--      (Semantically it is still "data first, new constraint last"; PG's CHECK validates row by row immediately, so the
--       update cannot run while the old constraint is still in force.)
--   2) update existing viewer → user;
--   3) column default viewer → user;
--   4) create the new constraint role in ('admin','ops','user').
-- sqlx runs the whole migration in a single transaction: any failed step rolls back (the old constraint/old data are never
-- left "half-migrated"), so dropping the constraint and then updating is safe.
--
-- Other notes: this file is tracked by sqlx migrations (`_sqlx_migrations`) and normally runs only once;
--   it is still made idempotent here (`drop constraint if exists` + DO-block existence check and rebuild), so it can be replayed
--   manually against an existing DB for verification. PG's `add constraint` has no `if not exists` syntax, so it is dropped first and
--   rebuilt after checking `pg_constraint`.

-- ---------- 1) Drop the old CHECK constraint (role in admin,ops,viewer) ----------
-- On old databases the constraint name comes from 0001's inline/add-column statements and is uniformly users_role_check.
alter table users drop constraint if exists users_role_check;

-- ---------- 2) Migrate existing data: read-only role viewer → user ----------
update users set role = 'user', updated_at = now() where role = 'viewer';

-- ---------- 3) Column default: viewer → user ----------
-- Only as a DDL fallback; admin-plane account creation still requires an explicit role (default user, least privilege),
-- avoiding "forgot to pass a role" silently landing on more privilege than expected.
alter table users alter column role set default 'user';

-- ---------- 4) New CHECK constraint: role in (admin,ops,user) ----------
do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'users_role_check'
      and conrelid = 'users'::regclass
  ) then
    alter table users
      add constraint users_role_check check (role in ('admin', 'ops', 'user'));
  end if;
end $$;
