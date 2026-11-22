import { useEffect, useRef, useState } from 'react'
import { session } from '@/api/http'
import { useI18n } from '@/i18n'
import type { StreamEvent } from '@/api/types'

export type SseStatus = 'idle' | 'connecting' | 'open' | 'polling' | 'error'

/**
 * Admin-console realtime stream (SSE).
 *
 * Why not the browser's native `EventSource`: it **cannot set request headers**, while
 * `/v1/admin/stream` requires `Authorization: Bearer` (the same JWT used everywhere
 * else). So this uses `fetch` + ReadableStream and parses SSE frames by hand:
 * `id:` / `event:` / `data:` / blank line as separator.
 *
 * **Automatic reconnect after a drop**: native `EventSource` reconnects on its own, so
 * a hand-written implementation must do it too — otherwise a single node restart would
 * freeze every push-driven page on its last frame forever. Backoff: 1s → 2s → 4s → …
 * → 30s. This is not polling: it only reconnects after the connection drops, and there
 * is no timer while the connection is alive.
 *
 * The server caps SSE at 100 concurrent connections and answers `429 RATE` beyond that.
 * In that case the status becomes `polling` and the caller-provided `poll` runs every
 * 5s as a fallback snapshot (the REST admin API is not subject to the SSE connection
 * limit), while the backoff reconnect keeps running in the background; once the stream
 * is back the hook returns to push mode automatically.
 */
export function useAdminStream(options: {
  enabled: boolean
  onEvent: (e: StreamEvent) => void
  /** 429 fallback polling: pull a snapshot every 5s (omitted = no polling) */
  poll?: () => void | Promise<void>
}): { status: SseStatus; lastError: string | null } {
  const { enabled, onEvent, poll } = options
  const { t } = useI18n()
  const [status, setStatus] = useState<SseStatus>('idle')
  const [lastError, setLastError] = useState<string | null>(null)
  const handlerRef = useRef(onEvent)
  handlerRef.current = onEvent
  const pollRef = useRef(poll)
  pollRef.current = poll
  // Keep the translator in a ref: switching language must not tear down the stream.
  const translateRef = useRef(t)
  translateRef.current = t

  useEffect(() => {
    if (!enabled) {
      setStatus('idle')
      return
    }

    const ac = new AbortController()
    let alive = true
    let attempt = 0

    /** One connection's lifetime. Returns true when the drop is worth reconnecting. */
    async function connectOnce(): Promise<boolean> {
      const s = session.get()
      if (!s?.accessJwt) return false
      setStatus('connecting')

      try {
        const resp = await fetch('/v1/admin/stream', {
          headers: {
            Authorization: `Bearer ${s.accessJwt}`,
            Accept: 'text/event-stream',
          },
          signal: ac.signal,
        })

        if (resp.status === 429) {
          setStatus('polling')
          setLastError(
            translateRef.current(
              'The realtime channel has reached its connection limit; close other console tabs and it will reconnect automatically',
            ),
          )
          return true
        }
        if (resp.status === 401 || resp.status === 403) {
          setStatus('error')
          setLastError(translateRef.current('Your session has expired; please sign in again'))
          return false
        }
        if (!resp.ok || !resp.body) {
          setStatus('error')
          setLastError(translateRef.current('Realtime channel handshake failed: HTTP {status}', { status: resp.status }))
          return true
        }

        setStatus('open')
        setLastError(null)
        attempt = 0
        const reader = resp.body.getReader()
        const decoder = new TextDecoder()
        let buf = ''

        while (alive) {
          const { done, value } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })

          // SSE separates frames with a blank line
          let idx: number
          while ((idx = buf.indexOf('\n\n')) >= 0) {
            const raw = buf.slice(0, idx)
            buf = buf.slice(idx + 2)

            let event = 'message'
            let id: string | undefined
            const dataLines: string[] = []
            for (const line of raw.split('\n')) {
              if (line.startsWith(':')) continue // comment line (`: ping` heartbeat, every 30s)
              if (line.startsWith('event:')) event = line.slice(6).trim()
              else if (line.startsWith('id:')) id = line.slice(3).trim()
              else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim())
            }
            if (!dataLines.length) continue
            let parsed: Record<string, unknown> = {}
            try {
              parsed = JSON.parse(dataLines.join('\n')) as Record<string, unknown>
            } catch {
              parsed = { raw: dataLines.join('\n') }
            }
            handlerRef.current({ event, id, data: parsed })
          }
        }
        // Server closed the stream normally (node restart / rolling release) — worth reconnecting
        return alive
      } catch (e) {
        if (!alive) return false
        setStatus('error')
        setLastError(e instanceof Error ? e.message : String(e))
        return true
      }
    }

    async function loop() {
      while (alive) {
        const retry = await connectOnce()
        if (!alive || !retry) return
        attempt += 1
        const wait = Math.min(30_000, 1000 * 2 ** Math.min(attempt, 5))
        await new Promise((r) => window.setTimeout(r, wait))
      }
    }

    void loop()
    return () => {
      alive = false
      ac.abort()
    }
  }, [enabled])

  // 429 fallback: poll the REST snapshot every 5s (stops automatically once push resumes)
  useEffect(() => {
    if (!enabled || status !== 'polling' || !pollRef.current) return
    let alive = true
    const tick = () => {
      if (!alive) return
      Promise.resolve(pollRef.current?.()).catch(() => undefined)
    }
    tick()
    const timer = window.setInterval(tick, 5000)
    return () => {
      alive = false
      window.clearInterval(timer)
    }
  }, [enabled, status])

  return { status, lastError }
}
