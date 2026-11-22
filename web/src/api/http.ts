import axios, {
  type AxiosError,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from 'axios'
import type { ApiErrorBody, LoginResp } from './types'
import { ulid } from '@/lib/ulid'
import { decodeJwt } from '@/auth/jwt'

declare module 'axios' {
  interface AxiosRequestConfig {
    /** Internal flag: this request already retried once after a 401, preventing an infinite loop when refresh fails */
    _retry?: boolean
    /** Internal flag: idempotency key for write requests (⑤ §0.3) */
    _idem?: string
  }
}

/**
 * Structured error from ⑤ §0.5 / §0.6.
 *
 * Why wrap HTTP errors: the console must tell "not enough permission (403
 * FORBIDDEN)" apart from "a dependency is down (503 INTERNAL + details.dep)" and
 * hint differently; a raw AxiosError only says "Request failed with status code
 * 403", which tells operators nothing.
 */
export class ApiError extends Error {
  code: string
  status: number
  details?: Record<string, unknown>
  traceId?: string
  envelopeId?: string

  constructor(init: {
    code: string
    message: string
    status: number
    details?: Record<string, unknown>
    traceId?: string
    envelopeId?: string
  }) {
    super(init.message)
    this.name = 'ApiError'
    this.code = init.code
    this.status = init.status
    this.details = init.details
    this.traceId = init.traceId
    this.envelopeId = init.envelopeId
  }

  /** `details.dep` (on 503, names the unavailable dependency: pg/redis/bus) */
  get dep(): string | undefined {
    const d = this.details?.['dep']
    return typeof d === 'string' ? d : undefined
  }

  get reason(): string | undefined {
    const r = this.details?.['reason']
    return typeof r === 'string' ? r : undefined
  }

  /** One-line message for humans (includes trace_id for log correlation) */
  get display(): string {
    const bits = [`[${this.code}] ${this.message}`]
    if (this.reason) bits.push(`reason=${this.reason}`)
    if (this.dep) bits.push(`dep=${this.dep}`)
    if (this.traceId) bits.push(`trace=${this.traceId}`)
    return bits.join(' · ')
  }
}

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------

/**
 * Session lives in memory + `sessionStorage` only (② §9.1): access/refresh tokens
 * never touch localStorage, so closing the tab ends them; a same-tab reload still
 * works. Legacy localStorage values are cleared at startup (upgrade compatibility).
 */
const STORAGE_KEY = 'lattice.admin.session'
const LEGACY_KEY = 'lattice.admin.session'

export interface Session {
  accessJwt: string
  refreshToken: string
  /** device.fingerprint from ⑤ §1.1; WS hello must report it verbatim (v0.8 contract) */
  fingerprint: string
  deviceId: string
  username: string
  displayName: string | null
  userId: string
  /** Snapshot decoded from the JWT claim; users.role stays authoritative (⑤ §0.2) */
  role: string
  /** Access token expiry (epoch ms) */
  expiresAt: number
}

type SessionListener = (s: Session | null) => void
const listeners = new Set<SessionListener>()

/**
 * Keep the session across tabs/reloads (user feedback: after login, a new tab
 * still bounced to the login page).
 *
 * Trade-off: sessionStorage stays this tab's main store (access + refresh);
 * "refresh token + identity" also goes to localStorage, **never the access token**.
 * A new tab silently refreshes at startup (rotation updates the persisted value), so
 * new same-origin tabs stay logged in while access never touches localStorage.
 */
const REMEMBER_KEY = 'lattice.admin.remember'
interface RememberedAuth {
  refreshToken: string
  fingerprint: string
  deviceId: string
  username: string
  displayName: string | null
  userId: string
  role: string
}

function readRemembered(): RememberedAuth | null {
  try {
    const raw = localStorage.getItem(REMEMBER_KEY)
    if (!raw) return null
    const v = JSON.parse(raw) as RememberedAuth
    if (!v?.refreshToken || !v?.username) return null
    return v
  } catch {
    return null
  }
}

function remember(s: Session | null): void {
  try {
    if (!s) {
      localStorage.removeItem(REMEMBER_KEY)
      return
    }
    const v: RememberedAuth = {
      refreshToken: s.refreshToken,
      fingerprint: s.fingerprint,
      deviceId: s.deviceId,
      username: s.username,
      displayName: s.displayName,
      userId: s.userId,
      role: s.role,
    }
    localStorage.setItem(REMEMBER_KEY, JSON.stringify(v))
  } catch {
    /* localStorage is unwritable in private mode: fall back to this tab only */
  }
}

function readStored(): Session | null {
  try {
    // Before v0.13 tokens were mistakenly stored in localStorage; clear them at
    // startup so "tokens survive closing the tab" cannot happen
    if (typeof localStorage !== 'undefined') localStorage.removeItem(LEGACY_KEY)
    const raw = sessionStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as Session
    if (!parsed?.accessJwt || !parsed?.refreshToken) return null
    return parsed
  } catch {
    return null
  }
}

let current: Session | null = readStored()

export const session = {
  get(): Session | null {
    return current
  },
  set(s: Session | null) {
    current = s
    try {
      if (s) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(s))
      else sessionStorage.removeItem(STORAGE_KEY)
    } catch {
      /* sessionStorage may be unwritable in private mode; the in-memory state still works */
    }
    remember(s)
    listeners.forEach((fn) => fn(s))
  },
  subscribe(fn: SessionListener) {
    listeners.add(fn)
    return () => listeners.delete(fn)
  },
}

/** Notify upper layers when the session dies (AuthProvider routes to login and shows the reason) */
let onUnauthorized: ((err: ApiError) => void) | null = null
export function setUnauthorizedHandler(fn: ((err: ApiError) => void) | null) {
  onUnauthorized = fn
}

// ---------------------------------------------------------------------------
// Axios instances
// ---------------------------------------------------------------------------

const BASE = '/v1'

/** Bare instance: token refresh must not use the intercepted instance, or 401 → refresh → 401 recurses forever */
const raw = axios.create({ baseURL: BASE, timeout: 15000 })

export const http: AxiosInstance = axios.create({
  baseURL: BASE,
  timeout: 20000,
  headers: { Accept: 'application/json' },
})

http.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const s = current
  if (s?.accessJwt) config.headers.set('Authorization', `Bearer ${s.accessJwt}`)

  // ⑤ §0.3: every write call carries an idempotency key by default (retries cause no duplicate side effects)
  const method = (config.method ?? 'get').toUpperCase()
  if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(method) && !config.headers.get('Idempotency-Key')) {
    const key = ulid()
    config.headers.set('Idempotency-Key', key)
    config._idem = key
  }
  return config
})

/** Single-flight refresh: ten concurrent 401s trigger one refresh (⑤ §1.2 rotation forbids concurrent refreshes) */
let refreshing: Promise<string> | null = null

async function refreshAccessToken(): Promise<string> {
  const s = current
  if (!s?.refreshToken) throw new ApiError({ code: 'AUTH_FAIL', message: 'no refresh token', status: 401 })

  const { data } = await raw.post<LoginResp>('/auth/refresh', { refresh_token: s.refreshToken })
  const next: Session = {
    ...s,
    accessJwt: data.access_jwt,
    refreshToken: data.refresh_token,
    fingerprint: data.device?.fingerprint ?? s.fingerprint,
    deviceId: data.device?.id ?? s.deviceId,
    expiresAt: Date.now() + (data.expires_in ?? 900) * 1000,
  }
  session.set(next)
  return next.accessJwt
}

/**
 * Startup after a new tab/reload: sessionStorage is empty but localStorage holds a
 * remembered identity, so silently exchange the refresh token for an access token
 * and restore the session. On failure, clear the remember record and return false.
 */
export async function bootstrapPersistedSession(): Promise<boolean> {
  if (current) return true
  const remembered = readRemembered()
  if (!remembered) return false
  try {
    const { data } = await raw.post<LoginResp>('/auth/refresh', {
      refresh_token: remembered.refreshToken,
    })
    const claims = decodeJwt(data.access_jwt)
    const next: Session = {
      accessJwt: data.access_jwt,
      refreshToken: data.refresh_token,
      fingerprint: data.device?.fingerprint ?? remembered.fingerprint,
      deviceId: data.device?.id ?? remembered.deviceId,
      username: remembered.username,
      displayName: remembered.displayName,
      userId: remembered.userId,
      role: claims?.role ?? remembered.role,
      expiresAt: Date.now() + (data.expires_in ?? 900) * 1000,
    }
    session.set(next)
    return true
  } catch {
    // Refresh expired or rotated by another tab: drop the persisted identity and return to login
    remember(null)
    return false
  }
}

function toApiError(err: AxiosError<ApiErrorBody>): ApiError {
  const res = err.response
  const body = res?.data
  const status = res?.status ?? 0

  if (body && typeof body === 'object' && typeof body.code === 'string') {
    return new ApiError({
      code: body.code,
      message: body.message ?? err.message,
      status,
      details: body.details,
      traceId: body.trace_id,
      envelopeId: body.envelope_id,
    })
  }

  // Non-contract error body (e.g. plain-text 413/502 blocked by a gateway/Nginx)
  const raw = res?.data as unknown
  const text = typeof raw === 'string' ? raw.slice(0, 200) : ''
  return new ApiError({
    code: status === 0 ? 'NETWORK' : 'INTERNAL',
    message: text || err.message || 'request failed',
    status,
  })
}

http.interceptors.response.use(
  (r) => r,
  async (error: AxiosError<ApiErrorBody>) => {
    const original = error.config
    const status = error.response?.status ?? 0
    const url = original?.url ?? ''
    const isAuthCall = url.includes('/auth/login') || url.includes('/auth/refresh')

    // 401: try one silent renewal first; failure terminates the session
    if (status === 401 && original && !original._retry && !isAuthCall && current?.refreshToken) {
      original._retry = true
      try {
        refreshing = refreshing ?? refreshAccessToken()
        const jwt = await refreshing
        refreshing = null
        original.headers.set('Authorization', `Bearer ${jwt}`)
        // Replay with the same idempotency key: if already executed, the server returns the first result instead of re-running
        if (original._idem) original.headers.set('Idempotency-Key', original._idem)
        return http.request(original)
      } catch (e) {
        refreshing = null
        const apiErr = e instanceof ApiError ? e : toApiError(e as AxiosError<ApiErrorBody>)
        session.set(null)
        onUnauthorized?.(apiErr)
        return Promise.reject(apiErr)
      }
    }

    const apiErr = toApiError(error)
    if (status === 401 && !isAuthCall) {
      session.set(null)
      onUnauthorized?.(apiErr)
    }
    return Promise.reject(apiErr)
  },
)

/** Probe (unauthenticated): lets the login page show whether the node is ready */
export async function probeReady(): Promise<{ ready: boolean; deps: Record<string, string>; node_id: string; version: string }> {
  const { data } = await raw.get('/ready', { timeout: 5000 })
  return data
}

export async function probeHealth(): Promise<void> {
  await raw.get('/health', { timeout: 5000 })
}
