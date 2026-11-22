import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { message } from 'antd'
import { ApiError, bootstrapPersistedSession, session, setUnauthorizedHandler, type Session } from '@/api/http'
import { errText } from '@/lib/errors'
import { bindTranslator } from '@/lib/labels'
import { login as loginApi, logout as logoutApi } from '@/api/endpoints'
import { useI18n } from '@/i18n'
import { decodeJwt } from './jwt'
import { can, type Capability } from './rbac'

interface AuthContextValue {
  session: Session | null
  ready: boolean
  role: string
  can: (cap: Capability) => boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

/** Browser-side device fingerprint (must match the value used at login and in WS hello) */
function localFingerprint(): string {
  const KEY = 'lattice.admin.device_fp'
  const existed = localStorage.getItem(KEY)
  if (existed) return existed
  const buf = new Uint8Array(16)
  crypto.getRandomValues(buf)
  const hex = Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('')
  const fp = `sha256:${hex}`
  localStorage.setItem(KEY, fp)
  return fp
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const { t } = useI18n()
  const [current, setCurrent] = useState<Session | null>(session.get())
  const [ready, setReady] = useState(false)

  // The console lives inside the i18n provider, so this is the one place that binds the
  // translator for non-hook helpers (`errText`, `fmtRelative`, ...), which are called from
  // event handlers and plain functions where no hook can run. This is an idempotent write
  // to a plain module cache (no React state), done during render so the binding is already
  // in place before any child page renders — on load and on every locale switch.
  bindTranslator(t)

  useEffect(() => {
    let alive = true
    const unsub = session.subscribe((s) => setCurrent(s))
    // When this tab's sessionStorage is empty, try to restore the login from the refresh
    // identity in localStorage (new tab / browser restart); only if that fails show the
    // login page. Keep the Spin on the first screen until the decision is made.
    if (session.get()) {
      setReady(true)
    } else {
      bootstrapPersistedSession()
        .catch(() => false)
        .finally(() => {
          if (alive) setReady(true)
        })
    }
    return () => {
      alive = false
      unsub()
    }
  }, [])

  useEffect(() => {
    setUnauthorizedHandler((err: ApiError) => {
      message.error(t('Session ended: {error}', { error: errText(err) }))
    })
    return () => setUnauthorizedHandler(null)
  }, [t])

  const login = useCallback(async (username: string, password: string) => {
    const resp = await loginApi({
      username,
      password,
      device_name: navigator.userAgent.includes('Mac') ? 'web-console-mac' : 'web-console',
      device_fp: localFingerprint(),
    })
    const claims = decodeJwt(resp.access_jwt)
    if (!claims?.role) {
      // No role means the token shape does not match the API contract — reject instead of
      // letting the console run half-alive with empty permissions.
      throw new ApiError({
        code: 'AUTH_FAIL',
        message: 'access token has no role claim; permissions cannot be determined (API §0.2)',
        status: 200,
      })
    }
    session.set({
      accessJwt: resp.access_jwt,
      refreshToken: resp.refresh_token,
      fingerprint: resp.device?.fingerprint ?? localFingerprint(),
      deviceId: resp.device?.id ?? '',
      username: resp.user?.username ?? username,
      displayName: resp.user?.display_name ?? null,
      userId: resp.user?.id ?? claims.sub,
      role: claims.role,
      expiresAt: Date.now() + (resp.expires_in ?? 900) * 1000,
    })
  }, [])

  const logout = useCallback(async () => {
    try {
      await logoutApi()
    } catch {
      // A failed logout does not block local cleanup (the token may already be expired)
    }
    session.set(null)
  }, [])

  const value = useMemo<AuthContextValue>(
    () => ({
      session: current,
      ready,
      role: current?.role ?? '',
      can: (cap: Capability) => can(current?.role, cap),
      login,
      logout,
    }),
    [current, ready, login, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
