import type { JwtClaims } from '@/api/types'

/**
 * Decodes the JWT payload (no signature check — the server verifies signatures; the
 * frontend only reads claims).
 *
 * Why the frontend decodes it at all: the login response `user` object does **not**
 * contain `role`; role only appears inside the access JWT (a 900s snapshot). The console
 * needs it for button-level RBAC, so it has to be decoded here.
 */
export function decodeJwt(token: string): JwtClaims | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4)
    const json = decodeURIComponent(
      atob(padded)
        .split('')
        .map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join(''),
    )
    return JSON.parse(json) as JwtClaims
  } catch {
    return null
  }
}
