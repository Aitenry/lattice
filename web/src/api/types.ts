/**
 * Type declarations aligned with doc ⑤ (the platform API doc).
 *
 * Naming rule: field names **copy the server JSON verbatim** (no camelCase
 * conversion), so when the contract changes a grep matches instantly without a
 * mental mapping layer. The source section is noted above each type.
 */

/** ⑤ §0.5 Error response body */
export interface ApiErrorBody {
  code: string
  message: string
  envelope_id?: string
  details?: Record<string, unknown>
  trace_id?: string
}

/** ⑤ §0.2 Admin roles (authoritative value users.role, signed into the token snapshot at login) */
export type Role = 'admin' | 'ops' | 'user'

/** ⑤ §0.4 Offset pagination (uniform across admin lists) */
export interface Paged<T> {
  items: T[]
  total: number
  page?: number
  page_size?: number
}

/** ⑤ §1.1 Login response */
export interface LoginResp {
  access_jwt: string
  refresh_token: string
  expires_in: number
  /** v0.8: must be returned when the server generates the fingerprint; WS hello reports it verbatim */
  device: { id: string; fingerprint: string }
  user: {
    id: string
    username: string
    display_name: string | null
    /** v0.8 avatar: `https://` URL or `data:image/...;base64,...`; null = not set */
    avatar: string | null
    capabilities: {
      formats?: string[]
      compression?: string[]
      e2e?: boolean
      quic?: boolean
      webrtc?: boolean
    }
  }
}

/** The part of the JWT payload we care about (⑤ §0.2: role is a 900s snapshot) */
export interface JwtClaims {
  sub: string
  role: Role
  exp: number
  iat?: number
  [k: string]: unknown
}

/** ⑤ §8.1 Online state */
export interface OnlineDevice {
  device: string
  node: string
  protocol: string
  connected_at: string
  duration_s: number
  remote_ip: string
  caps?: Record<string, unknown>
  local?: boolean
}

export interface OnlineResp {
  user: string
  devices: OnlineDevice[]
  index?: unknown
}

export interface OnlineStats {
  online_users: number
  online_devices: number
  by_protocol: Record<string, number>
  by_node: Record<string, number>
  node_id: string
  updated_at: string
}

export interface NodeRow {
  node_id: string
  version?: string
  connections?: number
  heartbeat_at?: string
  health?: string
  [k: string]: unknown
}

export interface DrainReq {
  reason: string
  wait_seconds: number
}

export interface DrainProgress {
  node_id: string
  remaining_connections?: number
  /** Actual backend field (implemented as byef_sent; sent_byef is a legacy-spelling alias) */
  byef_sent?: number
  sent_byef?: number
  state?: string
  [k: string]: unknown
}

export interface QueueResp {
  user: string
  scope: string
  depth: number
  oldest_seq: number | null
  device_depth: number
}

export interface QueuePurgeReq {
  user: string
  scope?: 'user' | 'device' | 'topic'
  /** RFC3339 or unix seconds; omitted = purge all pending deliveries in the scope (⑥ §3.1 score is seq, so range scans are costly) */
  before_ts?: string
  reason: string
}

/** ⑤ §8.2 User */
export interface AdminUser {
  id: string
  username: string
  display_name: string | null
  /** v0.8 avatar (null = not set; lists fall back to name initials) */
  avatar: string | null
  status: string
  role: Role
  quota: Quota
  created_at: string
}

export interface Quota {
  msg_per_s?: number
  bytes_per_s?: number
  topics?: number
  storage_bytes?: number
}

export interface CreateUserReq {
  username: string
  password: string
  display_name?: string
  role?: Role
}

/**
 * ⑤ §2 Self-service profile (`GET/PATCH /v1/users/me`).
 *
 * Fields share their source with `GET /v1/users/{id}` plus `role`/`updated_at`: the
 * account menu needs the role, and saves refresh the local session display name
 * without a re-login.
 */
export interface UserProfile {
  id: string
  username: string
  display_name: string | null
  /** v0.8 avatar: `https://` URL or `data:image/(png|jpeg|webp|gif);base64,...` (≤256KiB); null = not set */
  avatar: string | null
  status: string
  role: Role
  capabilities?: unknown
  quota?: Quota
  created_at?: string
  updated_at?: string
}

/** Admin password reset response (`POST /v1/admin/users/{id}/password`, no password material) */
export interface PasswordResetResp {
  ok: boolean
  user_id?: string
  /** Number of active device sessions revoked (old refresh tokens die immediately) */
  sessions_revoked: number
}

/** Self-service password change response (`POST /v1/users/me/password`) */
export interface PasswordChangeResp {
  ok: boolean
  /** Number of **other** device sessions revoked */
  sessions_revoked: number
  /** Current device kept (no re-login needed) */
  current_device_kept?: boolean
}

export interface DeviceRow {
  id: string
  user_id: string
  name: string | null
  platform: string | null
  fingerprint: string
  last_seen: string | null
  revoked_at: string | null
}

/** ⑤ §8.3 Conversations / messages */
export interface ConvRow {
  id: string
  kind: string
  name: string | null
  members: number
  last_seq: number | null
  last_msg_at: string | null
}

export interface ConvDetail {
  id: string
  kind: string
  name: string | null
  created_at: string
  members: { user_id: string; role: string }[]
}

export interface MessageRow {
  id: string
  conv_id: string
  sender?: string
  env_type?: string
  content_type?: string
  size?: number
  chunk_total?: number
  seq: number
  status: string
  created_at: string
  expires_at?: string | null
  payload_ref?: string | null
}

export interface DeliveryRow {
  to_user: string
  device: string
  state: string
  attempts: number
  last_at: string | null
  acked_at: string | null
}

export interface DlqRow {
  id?: string
  msg_id: string
  to_user: string
  device: string
  state: string
  attempts: number
  last_at: string | null
  [k: string]: unknown
}

export interface ReplayReq {
  msg_ids: string[]
  reason: string
}

export interface ReplayResp {
  accepted: number
  rejected: string[]
}

/** ⑤ §8.6 Audit (note: the implementation supports only actor/action/page; see the gap table in web/README) */
export interface AuditRow {
  id: string
  actor: string | null
  action: string
  target: string | null
  detail: unknown
  created_at: string
}

/**
 * ⑤ §9.7 Media recordings (PL-13 13.6): **index metadata** for WS tunnel segments.
 *
 * The server idempotently inserts one row per `[4B len][body]` segment object; the
 * API exposes metadata only:
 * - no payload / frame content at all;
 * - `first_seq`/`last_seq`/`started_at`/`ended_at` null means the direct-write path
 *   had no frame numbers (raw `stream-data` bodies carry no seq), not missing data;
 *   sort by `created_at` instead;
 * - `codec`/`format` are always null for now (no MP4/OGG muxing, raw segments only).
 */
export interface MediaRecordingRow {
  id: string
  stream_id: string
  node_id: string
  object_key: string
  bucket: string
  first_seq: number | null
  last_seq: number | null
  frames: number
  size_bytes: number
  created_at: string
  started_at: string | null
  ended_at: string | null
  codec: string | null
  format: string | null
}

/**
 * `GET /v1/media/recordings` response: newest first (`created_at desc, id desc`)
 * with cursor pagination. `next_before` = the next page's `before` cursor; null = no
 * older page.
 */
export interface MediaRecordingListResp {
  items: MediaRecordingRow[]
  limit: number
  next_before: string | null
}

/** `GET /v1/media/recordings/{id}`: metadata + presigned download URL (TTL in `presign_ttl_seconds`) */
export interface MediaRecordingDetail extends MediaRecordingRow {
  /** MinIO presigned GET (valid 5 minutes; opens directly in a browser, no auth header) */
  presigned_url: string
  presign_ttl_seconds: number
  /** Server download endpoint path (302 to the presigned URL; the console calls it as a blob) */
  download_url: string
}

/** ⑤ §8.4 Plugins / formats / config / keys */
export interface PluginRow {
  ns: string
  id?: string
  version?: number
  status?: string
  canary_ratio?: number
  /** Plugin form: WASM in the sandbox, or a separate sidecar process */
  form?: string
  published_at?: string
  calls?: number
  [k: string]: unknown
}

/**
 * §8.4 `GET /v1/admin/plugins` response.
 *
 * `wasm` is the WASM plugin runtime (sandbox) state: **the field is absent when the
 * feature is off**, and the UI renders the status card only when present — never
 * assumes or fabricates it.
 */
export interface AdminPluginsResp {
  items: PluginRow[]
  wasm?: WasmRuntimeState | null
}

/** WASM runtime state (fields from the server implementation; unknown/new fields pass through to the raw JSON foldout) */
export interface WasmRuntimeState {
  enabled: boolean
  compiled: boolean
  /** Whether plugins load from the PG `plugins` table (PL-10) */
  from_db?: boolean
  wasm_dir?: string | null
  max_wasm_bytes?: number | null
  /** Number of configured trusted signing public keys */
  trusted_keys: number
  trusted_key_ids?: string[]
  /** Signature algorithm (e.g. ed25519_ring); null/absent = verification not implemented */
  signature_verification?: string | null
  require_verified_signature?: boolean
  loaded: WasmPluginEntry[]
  rejected: WasmRejectEntry[]
  sources?: WasmRuntimeSources
  metrics?: Record<string, unknown>
  security?: Record<string, unknown>
  [k: string]: unknown
}

/** Successfully loaded WASM plugins (fields vary slightly by version; unknown fields pass through) */
export interface WasmPluginEntry {
  plugin?: string | null
  ns?: string | null
  version?: string | null
  source?: string | null
  bytes?: number | null
  verified?: boolean | null
  generation?: number | null
  [k: string]: unknown
}

/** WASM plugins rejected at load (bad signature/wasm, unreadable dir, etc.; fail-closed) */
export interface WasmRejectEntry {
  plugin?: string | null
  ns?: string | null
  kind?: string | null
  reason?: string | null
  [k: string]: unknown
}

/** WASM source counts: how many each source loaded/rejected — directory (wasm_dir) and PG registry (plugins table) */
export interface WasmRuntimeSources {
  dir?: { loaded?: number; rejected?: number; [k: string]: unknown } | null
  pg?: {
    enabled?: boolean
    error?: string | null
    rows?: number
    loaded?: number
    rejected?: number
    skipped?: number
    oversized?: number
    conflicts?: number
    canary_ignored?: number
    state?: string
    query_ms?: number
    [k: string]: unknown
  } | null
  [k: string]: unknown
}

export interface PluginActionReq {
  ns: string
  /** The server's `plugins.version` is an integer, not a semver string */
  version: number
  action: 'publish' | 'rollback' | 'canary'
  ratio?: number
  reason: string
}

export interface FormatRow {
  id?: string
  type: string
  mime: string
  handler: string
  [k: string]: unknown
}

export interface ConfigItem {
  value: unknown
  source: string
}

export interface ConfigSnapshot {
  items: Record<string, ConfigItem>
}

export interface ConfigPatchResp {
  changed: string[]
  authority: string
}

export interface KeyRow {
  fingerprint: string
  role: 'current' | 'previous' | string
}

export interface KeysResp {
  items: KeyRow[]
  ttl_seconds: number
}

/**
 * ⑤ §12 Plugin hub (user-facing `/v1/hub`) — **not the same thing as §8.4 `plugins`
 * (server format plugins)**: this distributes third-party desktop client (RytenBench)
 * plugins; fields copy the server JSON verbatim.
 */

/** Plugin publisher (⑤ §12.1 owner) */
export interface HubOwner {
  id: string
  username: string
  display_name: string | null
}

/** Catalog sort (design §17.16; default recent) */
export type HubSort = 'recent' | 'popular' | 'name'

/** ⑤ §12.1 Catalog row (`installed`/`installed_version`/`update_available` are caller-relative) */
export interface HubPluginRow {
  plugin_id: string
  name: string
  description: string
  icon: string | null
  category: string
  tags: string[]
  owner: HubOwner
  latest_version: string | null
  /** Latest version archive size in bytes */
  size: number | null
  /** Whether the latest version ships source (v2 contract §1.5; detail versions[] is authoritative) */
  has_source?: boolean
  downloads: number
  versions_count: number
  updated_at: string
  installed: boolean
  installed_version: string | null
  update_available: boolean
  /** Extra field the implementation returns beyond ⑤ §12.1: caller's install enabled state (null when not installed) */
  install_enabled?: boolean | null
}

/**
 * Review state of a hub version (migration 0012 / product rule 2026-11-23).
 *
 * `pending`  → metadata submitted, package body not uploaded yet
 * `review`   → package stored, waiting for an administrator
 * `published`→ approved; the only state other users can see/install
 * `rejected` → rejected; the owner sees `review_note` and may correct + resubmit
 */
export type HubVersionStatus = 'pending' | 'review' | 'published' | 'rejected' | 'removed'

/** ⑤ §12.2 Version row (v2 contract §1.5 adds four source fields) */
export interface HubVersionRow {
  version: string
  asset_name: string
  size: number
  /** Lowercase hex, 64 chars */
  sha256: string
  changelog: string
  manifest: unknown
  downloads: number
  published_at: string | null
  /** Review state; the public catalog only ever returns `published` */
  status?: HubVersionStatus
  /** Owner/admin only: when this submission entered review */
  submitted_at?: string | null
  /** Owner/admin only: rejection reason */
  review_note?: string | null
  /** Owner/admin only: last review action time */
  reviewed_at?: string | null
  /** Whether this version has a source package uploaded */
  has_source: boolean
  source_asset_name: string | null
  /** Source package size in bytes (null when no source) */
  source_size: number | null
  /** Source package SHA-256 (lowercase hex; null when no source) */
  source_sha256: string | null
}

/** ⑤ §12.2 Caller's own install record (the implementation returns null when not installed; the doc says "absent") */
export interface HubMyInstall {
  version: string
  enabled: boolean
  data_rev: number
  data_updated_at: string | null
}

/** ⑤ §12.2 Detail */
export interface HubPluginDetail {
  plugin_id: string
  name: string
  description: string
  readme: string | null
  icon: string | null
  category: string
  tags: string[]
  owner: HubOwner
  latest_version: string | null
  downloads: number
  created_at: string
  updated_at: string
  versions: HubVersionRow[]
  my_install: HubMyInstall | null
}

/** ⑤ §12.3 Publish request (the console builds the manifest snapshot from the form) */
export interface HubPublishReq {
  plugin_id: string
  version: string
  name: string
  description?: string
  readme?: string
  icon?: string
  category?: string
  tags?: string[]
  changelog?: string
  asset_name: string
  size: number
  sha256: string
  manifest: Record<string, unknown>
  /** v2 contract §1.2: optional source package declaration (absent = no source for this version) */
  source?: HubSourceMeta
}

/** v2 contract §1.2: source package metadata (declared in the POST before upload) */
export interface HubSourceMeta {
  /** ≤128 chars, .zip, path separators forbidden */
  asset_name: string
  /** 1..50MiB */
  size: number
  /** Lowercase hex, 64 chars */
  sha256: string
}

/** ⑤ §12.3 `upload` part of the publish response: target for the step-2 raw byte PUT */
export interface HubUploadTarget {
  method: string
  /** Like `/v1/hub/plugins/{plugin_id}/versions/{version}/blob` (note the /v1 prefix) */
  path: string
  headers: Record<string, string>
  max_bytes: number
  expires_at: string
}

/** ⑤ §12.3 Publish response (201; retrying the same version+sha returns 200 with `upload` possibly null) */
export interface HubPublishResp {
  plugin: Record<string, unknown>
  version: Record<string, unknown>
  upload: HubUploadTarget | null
  /** v2 contract §1.2: PUT target while the source package is not yet uploaded; null when absent/already uploaded */
  source_upload?: HubUploadTarget | null
  idempotent_reused?: boolean
  idempotent?: boolean
  /** True when the same package is already waiting for administrator review */
  submitted?: boolean
}

/** ⑤ §12.4 Upload response */
export interface HubUploadResp {
  plugin_id: string
  version: string
  status: string
  sha256: string
  size: number
  published_at: string | null
  /** Set when the upload moved the version into `review` (2026-11-23 review flow) */
  submitted_at?: string | null
  /** True when the package is now waiting for an administrator */
  review_required?: boolean
  download_path: string
  idempotent?: boolean
}

/** ⑤ §12.4 Source package upload response (v2 contract §1.3) */
export interface HubSourceUploadResp {
  plugin_id: string
  version: string
  status: string
  source_asset_name: string | null
  source_size: number | null
  source_sha256: string | null
  download_path: string
  idempotent?: boolean
}

/** ⑤ §12.8 Stats (console metric cards) */
export interface HubStats {
  plugins: number
  versions: number
  installs: number
  downloads_total: number
  storage_bytes: number
  top: { plugin_id: string; name: string; downloads: number }[]
  recent: { plugin_id: string; version: string; published_at: string | null }[]
}

/** ⑤ §12.7 Install record (list item; `plugin` is null once the plugin is unpublished) */
export interface HubInstallRow {
  plugin_id: string
  version: string
  enabled: boolean
  data_rev: number
  data_updated_at: string | null
  last_device: string | null
  updated_at: string
  plugin?: { name: string; icon: string | null; latest_version: string | null; status: string } | null
  /** Returned only when `include_data=1` */
  data?: unknown
}

/**
 * `GET /v1/hub/mine` row: my plugin including submissions that are not approved yet.
 *
 * `state` reflects what the owner most needs to see: an approved plugin stays `published`
 * even while a newer version is `review` (then `review_version` is set as well).
 */
export interface HubMineRow {
  plugin_id: string
  name: string
  description: string
  icon: string | null
  category: string
  tags: string[]
  status: string
  state: 'published' | 'review' | 'rejected' | 'pending'
  latest_version: string | null
  versions_count: number
  review_version: string | null
  rejected_version: string | null
  rejected_note: string | null
  created_at: string
  updated_at: string
}

/** `GET /v1/admin/hub/reviews` row (administrator review queue) */
export interface HubReviewRow {
  plugin_id: string
  name: string
  owner: HubOwner
  version: string
  asset_name: string
  size: number
  sha256: string
  changelog: string
  has_source: boolean
  submitted_at: string
}

/** ⑤ §8.5 SSE event */
export interface StreamEvent {
  event: string
  id?: string
  data: Record<string, unknown>
}
