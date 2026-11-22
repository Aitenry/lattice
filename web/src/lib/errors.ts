import { ApiError } from '@/api/http'
import { tr } from './labels'

/**
 * Turns a backend error into one sentence that a human understands and can quote
 * back to operations.
 *
 * Why not render `e.display` directly in every page: `display` looks like
 * `[INTERNAL] Failed to deserialize query string: ...` — error code, English text and
 * reason chained together, leaving an administrator unable to tell what to do. Here
 * every known code gets a plain-language hint, while the code itself and the trace_id
 * are kept in parentheses for troubleshooting.
 */
const HINTS: Record<string, string> = {
  AUTH_FAIL: 'Your session expired or the credentials are wrong; please sign in again',
  FORBIDDEN: 'Your role is not allowed to perform this action; administrator rights are required',
  NOT_FOUND: 'The record was not found; it may have been deleted or the ID changed',
  FORMAT: 'The submitted or queried content is invalid; check the conditions',
  TOO_LARGE: 'Content exceeds the size limit; use chunked upload or split it into smaller parts',
  RATE: 'Too many requests and the operation was rate limited; wait a few seconds and retry',
  CONFLICT: 'This record was just changed by someone else; refresh and try again',
  INTERNAL:
    'The server or one of its dependencies failed; retry later, and if it keeps failing check the service status on the Overview page',
  NETWORK: 'Cannot reach the service; make sure the node is running and the network is reachable',
  PARSE: 'The request could not be parsed; the client version may not match the server',
}

const FALLBACK = 'The action did not succeed; retry later, and if it keeps failing send the details in parentheses to your maintainer'

export function errText(e: unknown): string {
  if (!(e instanceof ApiError)) {
    return e instanceof Error ? e.message : String(e)
  }

  const hint = tr(HINTS[e.code] ?? FALLBACK)
  const meta = [e.code]
  if (e.status) meta.push(`HTTP ${e.status}`)
  if (e.reason) meta.push(`reason=${e.reason}`)
  if (e.dep) meta.push(`dep=${e.dep}`)

  const head = tr('{hint} ({meta})', { hint, meta: meta.join(' · ') })
  return e.traceId ? tr('{head} · trace {trace}', { head, trace: e.traceId }) : head
}
