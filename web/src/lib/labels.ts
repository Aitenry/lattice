import type { Placeholders, Translate } from '@/i18n'

/**
 * Turns English enums from the API into readable console copy (single source, so every
 * page does not invent its own wording).
 *
 * Rules:
 * 1. Table cells show the mapped copy; the raw value only appears under "technical details";
 * 2. An unknown value falls back to the raw value — never to a blank cell;
 * 3. Colour only expresses semantics (success/warning/failure/neutral), never decoration.
 *
 * The mapped values are English source strings: call sites wrap them in `t(...)`
 * (`t(pick(ACCOUNT_STATUS, row.status))`) so the Chinese overlay applies.
 *
 * Plain (non-hook) modules such as `errText`, `fmtRelative` and the event-handler
 * helpers cannot call `useI18n`. They use `tr(...)` below; the console binds the active
 * translator whenever the locale changes, and until then the English source is returned.
 */
let boundTranslate: Translate | null = null

/** Bind (or clear) the translator used by non-hook modules. */
export function bindTranslator(t: Translate | null): void {
  boundTranslate = t
}

/** Translate a user-visible string from a module that cannot use the `useI18n` hook. */
export function tr(source: string, placeholders?: Placeholders): string {
  return boundTranslate ? boundTranslate(source, placeholders) : source
}

export function pick(map: Record<string, string>, value: string | null | undefined, fallback = '—'): string {
  if (!value) return fallback
  return map[value] ?? value
}

/** Account status (users.status) */
export const ACCOUNT_STATUS: Record<string, string> = {
  active: 'Active',
  suspended: 'Suspended',
  deleted: 'Deleted',
}

/** Message delivery state (delivery_log.state) */
export const DELIVERY_STATE: Record<string, string> = {
  pending: 'Pending',
  queued: 'Queued',
  persisted: 'Persisted',
  routed: 'Routed to node',
  delivered: 'Delivered',
  acked: 'Acknowledged',
  dlq: 'Retry failed',
  expired: 'Expired',
  failed: 'Failed to send',
}

export const DELIVERY_STATE_HINT: Record<string, string> = {
  persisted: 'The message is stored in the database; the delivery target is not fixed yet',
  routed: 'Pushed to the node hosting the recipient (this does not mean the client received it)',
  delivered: 'Handed to the device connection',
  acked: 'The client acknowledged receipt — only this step proves the recipient really got it',
  dlq: 'Still undelivered after several retries, so it moved to "Delivery failures" for manual handling',
  expired: 'Past the retention period; no further delivery attempts',
}

/** Conversation kind */
export const CONV_KIND: Record<string, string> = {
  dm: 'Direct message',
  group: 'Group',
  topic: 'Broadcast',
}

export const CONV_KIND_HINT: Record<string, string> = {
  dm: 'Private chat with exactly two members',
  group: 'Multi-person chat, delivered per member',
  topic: 'Topic broadcast: high volume, not stored as messages, and no per-message delivery receipt',
}

/** Device platform */
export const PLATFORM: Record<string, string> = {
  ios: 'iOS',
  android: 'Android',
  web: 'Web',
  macos: 'macOS',
  mac: 'macOS',
  windows: 'Windows',
  linux: 'Linux',
  server: 'Server',
}

/** Scope of an offline-queue purge */
export const QUEUE_SCOPE: Record<string, string> = {
  user: 'All devices of this user',
  device: 'Single device',
  topic: 'Topic subscription',
}

/** Node health */
export const NODE_HEALTH: Record<string, string> = {
  ok: 'Healthy',
  healthy: 'Healthy',
  degraded: 'Degraded',
  warn: 'Warning',
  down: 'Unavailable',
}

/** Key role */
export const KEY_ROLE: Record<string, string> = {
  current: 'Current',
  previous: 'Previous (parallel verification)',
}

/** Key rotation target */
export const KEY_TARGET: Record<string, string> = {
  jwt: 'Login token signing key',
  kek: 'Data encryption master key',
  internal_ca: 'Node mutual-TLS certificate',
}

/** Dynamic config entries */
export const CONFIG_KEY: Record<string, string> = {
  ratelimit: 'Global rate limits',
  canary: 'Plugin canary config',
  plugins_enabled: 'Enabled plugins',
  // The server currently returns dynamic config as dotted keys (see the actual shape of
  // GET /v1/admin/config); map those too so the config page never shows a raw key name
  // as the main column (this file's rule: raw values only go to technical details).
  'ratelimit.bytes_per_s': 'Global limit · bandwidth per user',
  'ratelimit.topics_per_user': 'Global limit · topics per user',
  'canary.ratio': 'Plugin canary ratio',
  'plugins.enabled': 'Enabled plugins',
}

export const CONFIG_KEY_HINT: Record<string, string> = {
  ratelimit: 'Per-user limit on messages and bytes sent per second',
  canary: 'Route a share of traffic to the new plugin version',
  plugins_enabled: 'Plugins that are currently allowed to be invoked',
  'ratelimit.bytes_per_s': 'Uplink bandwidth available per user per second (bytes)',
  'ratelimit.topics_per_user': 'Maximum number of broadcast topics one user may subscribe to',
  'canary.ratio': 'Share of invocation traffic routed to the canary plugin version',
  'plugins.enabled': 'Plugins that are currently allowed to be invoked (switch)',
}

/** Audit action (audit_log.action; values defined by the server) */
export const AUDIT_ACTION: Record<string, string> = {
  login: 'Sign in',
  logout: 'Sign out',
  'user.create': 'Create account',
  'user.role': 'Change role',
  'user.quota': 'Adjust quota',
  'user.suspend': 'Ban account',
  'user.resume': 'Unban account',
  'user.purge': 'Compliance delete',
  'device.revoke': 'Revoke device',
  'queue.purge': 'Purge offline queue',
  replay: 'Replay failed deliveries',
  'plugin.publish': 'Publish plugin',
  'plugin.rollback': 'Roll back plugin',
  'plugin.canary': 'Plugin canary',
  'format.upsert': 'Update file format',
  'config.patch': 'Change dynamic config',
  'keys.rotate': 'Rotate keys',
  'node.drain': 'Drain node',
}

/** Audit actions offered in the filter dropdown (the rest can be typed) */
export const AUDIT_ACTION_OPTIONS = Object.entries(AUDIT_ACTION).map(([value, label]) => ({ value, label }))

/**
 * Translated audit-action options, for call sites that hold a translator.
 * `AUDIT_ACTION_OPTIONS` is kept for callers that render the English labels themselves.
 */
export function auditActionOptions(t: Translate): { value: string; label: string }[] {
  return Object.entries(AUDIT_ACTION).map(([value, label]) => ({ value, label: t(label) }))
}

/** Plugin status */
export const PLUGIN_STATUS: Record<string, string> = {
  active: 'Running',
  enabled: 'Enabled',
  disabled: 'Disabled',
  draft: 'Draft',
  deprecated: 'Deprecated',
}

/** Status → Tag colour (semantic colours, consistent across the console) */
export function toneOf(value: string | undefined): 'success' | 'warning' | 'error' | 'processing' | 'default' {
  switch (value) {
    case 'active':
    case 'acked':
    case 'delivered':
    case 'ok':
    case 'healthy':
    case 'current':
      return 'success'
    case 'persisted':
    case 'routed':
    case 'queued':
    case 'pending':
      return 'processing'
    case 'suspended':
    case 'dlq':
    case 'failed':
    case 'down':
      return 'error'
    case 'expired':
    case 'degraded':
    case 'warn':
    case 'deleted':
      return 'warning'
    default:
      return 'default'
  }
}

/** Plugin-hub categories (design §17.16) */
export const HUB_CATEGORY: Record<string, string> = {
  productivity: 'Productivity',
  ai: 'AI',
  media: 'Media',
  devtools: 'Developer tools',
  data: 'Data & charts',
  other: 'Other',
}

/** Plugin-hub category options (order follows HUB_CATEGORY declaration order) */
export const HUB_CATEGORY_OPTIONS = Object.entries(HUB_CATEGORY).map(([value, label]) => ({
  value,
  label,
}))

/** Translated plugin-hub category options, for call sites that hold a translator. */
export function hubCategoryOptions(t: Translate): { value: string; label: string }[] {
  return Object.entries(HUB_CATEGORY).map(([value, label]) => ({ value, label: t(label) }))
}
