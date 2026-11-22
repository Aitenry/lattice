import dayjs from 'dayjs'
import { tr } from './labels'

/** RFC3339 (UTC, millisecond precision) → readable local time */
export function fmtTime(v: string | null | undefined): string {
  if (!v) return '—'
  const d = dayjs(v)
  return d.isValid() ? d.format('YYYY-MM-DD HH:mm:ss') : String(v)
}

/**
 * Relative time (main display in the UI; the absolute time goes into a tooltip).
 *
 * Units are deliberate: "3 min ago" reads better than a raw timestamp for operators.
 */
export function fmtRelative(v: string | null | undefined): string {
  if (!v) return '—'
  const d = dayjs(v)
  if (!d.isValid()) return String(v)
  const sec = dayjs().diff(d, 'second')
  if (sec < -60) return tr('After {time}', { time: fmtTime(v) })
  if (sec < 10) return tr('Just now')
  if (sec < 60) return tr('{count} sec ago', { count: sec })
  if (sec < 3600) return tr('{count} min ago', { count: Math.floor(sec / 60) })
  if (sec < 86400) return tr('{count} hr ago', { count: Math.floor(sec / 3600) })
  if (sec < 86400 * 30) return tr('{count} d ago', { count: Math.floor(sec / 86400) })
  return fmtTime(v)
}

export function fmtBytes(n: number | null | undefined): string {
  if (n == null) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = n
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

export function fmtDuration(sec: number | null | undefined): string {
  if (sec == null) return '—'
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const s = sec % 60
  if (h) return tr('{hours} h {minutes} min', { hours: h, minutes: m })
  if (m) return tr('{minutes} min {seconds} s', { minutes: m, seconds: s })
  return tr('{seconds} s', { seconds: s })
}

/** Rate (msg/s) → "100 msg/s" */
export function fmtRate(n: number | null | undefined): string {
  if (n == null) return tr('Unlimited')
  return tr('{count} msg/s', { count: n })
}

/** Delivery state → antd Tag colour */
export function stateColor(state: string | undefined): string {
  switch (state) {
    case 'acked':
    case 'delivered':
      return 'green'
    case 'routed':
      return 'blue'
    case 'persisted':
    case 'queued':
    case 'pending':
      return 'cyan'
    case 'dlq':
    case 'failed':
      return 'red'
    case 'expired':
      return 'orange'
    default:
      return 'default'
  }
}

export function statusColor(status: string | undefined): string {
  switch (status) {
    case 'active':
      return 'green'
    case 'suspended':
      return 'red'
    case 'deleted':
      return 'default'
    default:
      return 'default'
  }
}

/** Safe stringification of a JSON value (detail may be an object, a string or empty) */
export function prettyJson(v: unknown, indent = 0): string {
  if (v == null) return '—'
  if (typeof v === 'string') return v
  try {
    return JSON.stringify(v, null, indent)
  } catch {
    return String(v)
  }
}
