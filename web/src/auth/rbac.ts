import type { Role } from '@/api/types'

/**
 * RBAC capability matrix (aligned row by row with the permission table in the API docs).
 *
 * The UI only hides buttons; enforcement happens on the server: an unauthorised request
 * returns `403 FORBIDDEN`, so every call site still has to handle ApiError (never rely
 * on the frontend hiding things).
 */
export type Capability =
  | 'read' // read-only: online/nodes/queue/audit/lists/search
  | 'dispose' // operational: drain / replay / queue.purge / revoke device / ban
  | 'mutate' // changes: publish or roll back plugins / quota / keys.rotate / purge / dynamic config / create account / change role

const RANK: Record<Role, number> = { user: 1, ops: 2, admin: 3 }

const NEED: Record<Capability, number> = {
  read: RANK.user,
  dispose: RANK.ops,
  mutate: RANK.admin,
}

export function can(role: Role | string | undefined, cap: Capability): boolean {
  if (!role) return false
  const r = RANK[role as Role]
  if (!r) return false
  return r >= NEED[cap]
}

/** Role badge colours (admin red, ops gold, user blue) */
export const ROLE_COLOR: Record<string, string> = {
  admin: 'red',
  ops: 'gold',
  user: 'blue',
}

/** English source labels; call sites wrap them in `t(...)` for the Chinese overlay */
export const ROLE_LABEL: Record<string, string> = {
  admin: 'Admin',
  ops: 'Ops',
  user: 'User',
}
