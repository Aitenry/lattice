import type { AxiosProgressEvent } from 'axios'
import { http } from './http'
import type {
  AdminPluginsResp,
  AdminUser,
  AuditRow,
  ConfigPatchResp,
  ConfigSnapshot,
  ConvDetail,
  ConvRow,
  CreateUserReq,
  DeliveryRow,
  DeviceRow,
  DlqRow,
  DrainProgress,
  DrainReq,
  FormatRow,
  HubInstallRow,
  HubPluginDetail,
  HubPluginRow,
  HubPublishReq,
  HubPublishResp,
  HubSort,
  HubSourceUploadResp,
  HubStats,
  HubUploadResp,
  HubUploadTarget,
  KeysResp,
  LoginResp,
  MediaRecordingDetail,
  MediaRecordingListResp,
  MessageRow,
  NodeRow,
  OnlineResp,
  OnlineStats,
  Paged,
  PasswordChangeResp,
  PasswordResetResp,
  PluginActionReq,
  QueuePurgeReq,
  QueueResp,
  Quota,
  ReplayReq,
  ReplayResp,
  Role,
  UserProfile,
} from './types'

/**
 * Admin API endpoint wrappers (one per doc ⑤ §8 section).
 *
 * Conventions:
 * - Path parameters are always `encodeURIComponent`-encoded: ULIDs are safe, topic
 *   names and usernames are not;
 * - Dangerous operations put `reason` explicitly in the body — ⑤ §8 requires a reason
 *   for them and records it in `audit_log.detail`; without it the server returns 422;
 * - Pagination always uses `page`/`page_size` (⑤ §0.4 offset style).
 */

// §1 Authentication ---------------------------------------------------------

export async function login(input: {
  username: string
  password: string
  device_name?: string
  device_fp?: string
}): Promise<LoginResp> {
  const { data } = await http.post<LoginResp>('/auth/login', input)
  return data
}

export async function logout(): Promise<void> {
  await http.post('/auth/logout')
}

// §2 Self-service profile / password (self; any role) --------

/** My profile (`GET /v1/users/me`): initial values for the account menu / profile dialog. */
export async function getMyProfile(): Promise<UserProfile> {
  const { data } = await http.get<UserProfile>('/users/me')
  return data
}

/**
 * Update my profile (`PATCH /v1/users/me`).
 *
 * Every field is optional (omitted = unchanged; empty string = clear): an empty
 * display name clears it, an empty avatar clears the avatar. Avatar accepts only an
 * `https://` URL or `data:image/(png|jpeg|webp|gif);base64,...` (≤256KiB encoded);
 * anything else returns 422 `details.field=avatar`. Audit `self.update` records only
 * avatar_changed, never the value. Callers sync local session state without re-login.
 */
export async function updateMyProfile(body: {
  display_name?: string
  avatar?: string
}): Promise<UserProfile> {
  const { data } = await http.patch<UserProfile>('/users/me', body)
  return data
}

/**
 * Change my password (`POST /v1/users/me/password`).
 *
 * Verifies the old password; on success the server revokes **other** devices'
 * refresh tokens (the current device is kept). A wrong old password returns
 * 422 FORMAT (`details.reason=old_password`), not 401.
 */
export async function changeMyPassword(body: {
  old_password: string
  new_password: string
}): Promise<PasswordChangeResp> {
  const { data } = await http.post<PasswordChangeResp>('/users/me/password', body)
  return data
}

// §8.1 Online state and nodes ------------------------------------------

export async function getOnlineStats(): Promise<OnlineStats> {
  const { data } = await http.get<OnlineStats>('/admin/online/stats')
  return data
}

export async function getOnline(params?: { user?: string; device?: string }): Promise<OnlineResp> {
  const { data } = await http.get<OnlineResp>('/admin/online', { params })
  return data
}

export async function listNodes(): Promise<Paged<NodeRow>> {
  const { data } = await http.get<Paged<NodeRow>>('/admin/nodes')
  return data
}

export async function drainNode(nodeId: string, body: DrainReq): Promise<{ task_id: string }> {
  const { data } = await http.post<{ task_id: string }>(
    `/admin/nodes/${encodeURIComponent(nodeId)}/drain`,
    body,
  )
  return data
}

export async function getDrainProgress(nodeId: string): Promise<DrainProgress> {
  const { data } = await http.get<DrainProgress>(`/admin/nodes/${encodeURIComponent(nodeId)}/drain`)
  return data
}

export async function getQueue(params: { user: string; scope?: 'user' | 'device' | 'topic' }): Promise<QueueResp> {
  const { data } = await http.get<QueueResp>('/admin/queue', { params })
  return data
}

export async function purgeQueue(body: QueuePurgeReq): Promise<{ removed: number; scanned?: number }> {
  const { data } = await http.post<{ removed: number; scanned?: number }>('/admin/queue/purge', body)
  return data
}

// §8.2 Users / devices / quotas / compliant deletion --------------

export async function listUsers(params?: {
  q?: string
  status?: string
  page?: number
  page_size?: number
}): Promise<Paged<AdminUser>> {
  const { data } = await http.get<Paged<AdminUser>>('/admin/users', { params })
  return data
}

export async function createUser(body: CreateUserReq): Promise<AdminUser> {
  const { data } = await http.post<AdminUser>('/admin/users', body)
  return data
}

export async function setUserQuota(userId: string, body: Quota & { reason: string }): Promise<{ id: string; quota: Quota }> {
  const { data } = await http.post<{ id: string; quota: Quota }>(
    `/admin/users/${encodeURIComponent(userId)}/quota`,
    body,
  )
  return data
}

export async function setUserRole(userId: string, body: { role: Role; reason: string }): Promise<unknown> {
  const { data } = await http.post(`/admin/users/${encodeURIComponent(userId)}/role`, body)
  return data
}

export async function suspendUser(userId: string, reason: string): Promise<unknown> {
  const { data } = await http.post(`/admin/users/${encodeURIComponent(userId)}/suspend`, { reason })
  return data
}

export async function resumeUser(userId: string, reason: string): Promise<unknown> {
  const { data } = await http.post(`/admin/users/${encodeURIComponent(userId)}/resume`, { reason })
  return data
}

/**
 * Update a user's profile (`PATCH /v1/admin/users/{id}`, admin|ops).
 *
 * Changes `display_name` and `avatar` (omitted = unchanged; empty string = clear);
 * username/role/status each have dedicated endpoints. Avatar validation matches the
 * self-service API (`https://` or data URL ≤256KiB, else 422 `details.field=avatar`).
 * `reason` is required and audited as `user.update` (records only avatar_changed).
 */
export async function updateUserProfile(
  userId: string,
  body: { display_name?: string; avatar?: string; reason: string },
): Promise<AdminUser> {
  const { data } = await http.patch<AdminUser>(`/admin/users/${encodeURIComponent(userId)}`, body)
  return data
}

/**
 * Admin resets a user's password (`POST /v1/admin/users/{id}/password`, admin only).
 *
 * The server re-hashes with argon2id and revokes all of the user's device sessions
 * (old refresh tokens die immediately). The response carries only `{ok, user_id,
 * sessions_revoked}` and no password material whatsoever.
 */
export async function resetUserPassword(
  userId: string,
  body: { new_password: string; reason: string },
): Promise<PasswordResetResp> {
  const { data } = await http.post<PasswordResetResp>(
    `/admin/users/${encodeURIComponent(userId)}/password`,
    body,
  )
  return data
}

export async function purgeUser(userId: string, body: { reason: string; confirm_username: string }): Promise<{ task_id: string }> {
  const { data } = await http.post<{ task_id: string }>(`/admin/users/${encodeURIComponent(userId)}/purge`, body)
  return data
}

export async function getPurgeProgress(userId: string): Promise<unknown> {
  const { data } = await http.get(`/admin/users/${encodeURIComponent(userId)}/purge`)
  return data
}

export async function listDevices(params?: { user?: string; revoked?: boolean }): Promise<{ items: DeviceRow[] }> {
  const { data } = await http.get<{ items: DeviceRow[] }>('/admin/devices', { params })
  return data
}

export async function revokeDevice(deviceId: string): Promise<void> {
  await http.delete(`/admin/devices/${encodeURIComponent(deviceId)}`)
}

// §8.3 Conversations / messages / dead letters ------------------------

export async function listConversations(params?: {
  q?: string
  kind?: string
  page?: number
  page_size?: number
}): Promise<Paged<ConvRow>> {
  const { data } = await http.get<Paged<ConvRow>>('/admin/conversations', { params })
  return data
}

export async function getConversation(id: string): Promise<ConvDetail> {
  const { data } = await http.get<ConvDetail>(`/admin/conversations/${encodeURIComponent(id)}`)
  return data
}

/** Note: the server requires at least one of id / conv / user (else 422 details.reason=selectivity) */
export async function searchMessages(params: {
  id?: string
  conv?: string
  user?: string
  state?: string
  page?: number
  page_size?: number
}): Promise<Paged<MessageRow>> {
  const { data } = await http.get<Paged<MessageRow>>('/admin/messages', { params })
  return data
}

export async function getDelivery(msgId: string): Promise<{ id: string; deliveries: DeliveryRow[] }> {
  const { data } = await http.get<{ id: string; deliveries: DeliveryRow[] }>(
    `/admin/messages/${encodeURIComponent(msgId)}/delivery`,
  )
  return data
}

export async function listDlq(params?: {
  conv?: string
  user?: string
  page?: number
  page_size?: number
}): Promise<{ items: DlqRow[] }> {
  const { data } = await http.get<{ items: DlqRow[] }>('/admin/dlq', { params })
  return data
}

export async function replayDlq(body: ReplayReq): Promise<ReplayResp> {
  const { data } = await http.post<ReplayResp>('/admin/replay', body)
  return data
}

// §8.4 Plugins / formats / config / keys ----------------------------

/**
 * `GET /v1/admin/plugins`: format plugin list + WASM runtime state (`wasm`, absent
 * when the feature is off). `items` is the original format plugin list; `wasm` feeds
 * the read-only sandbox status card on the plugin management page.
 */
export async function listPlugins(): Promise<AdminPluginsResp> {
  const { data } = await http.get<AdminPluginsResp>('/admin/plugins')
  return data
}

export async function pluginAction(body: PluginActionReq): Promise<unknown> {
  const { data } = await http.post('/admin/plugins', body)
  return data
}

export async function pluginStats(ns: string, window = '1h'): Promise<Record<string, unknown>> {
  const { data } = await http.get<Record<string, unknown>>(
    `/admin/plugins/${encodeURIComponent(ns)}/stats`,
    { params: { window } },
  )
  return data
}

export async function listFormats(): Promise<{ items: FormatRow[] }> {
  const { data } = await http.get<{ items: FormatRow[] }>('/admin/formats')
  return data
}

export async function upsertFormat(body: Partial<FormatRow> & { reason?: string }): Promise<FormatRow> {
  const { data } = await http.post<FormatRow>('/admin/formats', body)
  return data
}

export async function getConfig(): Promise<ConfigSnapshot> {
  const { data } = await http.get<ConfigSnapshot>('/admin/config')
  return data
}

export async function patchConfig(body: {
  ratelimit?: unknown
  plugins_enabled?: string[]
  canary?: unknown
  reason: string
}): Promise<ConfigPatchResp> {
  const { data } = await http.patch<ConfigPatchResp>('/admin/config', body)
  return data
}

export async function listKeys(): Promise<KeysResp> {
  const { data } = await http.get<KeysResp>('/admin/keys')
  return data
}

export async function rotateKeys(body: { target: 'jwt' | 'kek' | 'internal_ca'; reason: string }): Promise<unknown> {
  const { data } = await http.post('/admin/keys/rotate', body)
  return data
}

// §8.6 Audit --------------------------------------------------------------

/**
 * Audit query.
 *
 * ⚠ Implementation gap (see the "contract differences" section of web/README): doc ⑤
 * §8.6 allows `target` / `from` / `to`, but the backend only accepts `actor` /
 * `action` / `page` / `page_size`, so only the implemented parameters are exposed
 * here — otherwise the UI would issue queries the server silently ignores and users
 * would believe the filters worked.
 */
export async function listAudit(params?: {
  actor?: string
  action?: string
  page?: number
  page_size?: number
}): Promise<Paged<AuditRow>> {
  const { data } = await http.get<Paged<AuditRow>>('/admin/audit', { params })
  return data
}

// §9.7 Media recordings (PL-13 13.6; admin/ops only) -----------
//
// The source is the `media_recordings` index table, **no payload**: it only
// describes the raw `[4B len][body]` segment objects in object storage. Playback and
// transcoding (MP4/OGG) are not implemented yet, so only full-segment download works.

/**
 * `GET /v1/media/recordings[?stream_id=&limit=&before=]`: reverse cursor pagination.
 *
 * `stream_id` is an exact match; `before` is the previous response's `next_before`
 * (omitted = first/newest page). The server returns 422 for unknown cursors; the
 * console always takes cursors from responses and never builds its own.
 */
export async function listMediaRecordings(params?: {
  stream_id?: string
  limit?: number
  before?: string
}): Promise<MediaRecordingListResp> {
  const { data } = await http.get<MediaRecordingListResp>('/media/recordings', { params })
  return data
}

/** `GET /v1/media/recordings/{id}`: recording metadata + presigned download URL (TTL 300s) */
export async function getMediaRecording(id: string): Promise<MediaRecordingDetail> {
  const { data } = await http.get<MediaRecordingDetail>(
    `/media/recordings/${encodeURIComponent(id)}`,
  )
  return data
}

/**
 * `GET /v1/media/recordings/{id}/download`: the server 302s to a MinIO presigned GET.
 *
 * Same as hub downloads: `window.open` cannot carry `Authorization`, so axios uses
 * `responseType: 'blob'` to fetch the final bytes (the token only covers the first
 * hop; the presigned URL needs none), then an `<a download>` writes the file.
 * Direct cross-origin object storage access requires MinIO to allow the console
 * Origin; on failure the page falls back to the `presigned_url` in the detail.
 */
export async function downloadMediaRecording(id: string): Promise<Blob> {
  const { data } = await http.get<Blob>(
    `/media/recordings/${encodeURIComponent(id)}/download`,
    { responseType: 'blob', timeout: 180_000 },
  )
  return data
}

// §8.1 Prometheus text (metrics page preview) ---------

export async function getMetricsText(): Promise<string> {
  const { data } = await http.get<string>('/admin/metrics', { responseType: 'text' })
  return data
}

// §12 Plugin hub (user-facing /v1/hub) ------------------------------
//
// **Not the same API group** as §8.4 server format plugins: this distributes desktop
// client plugin packages. Auth is always a signed-in user (`Authorization` injected
// by the http instance); paths per ⑤ §12.

/** ⑤ §12.8 Catalog/storage overview (metric cards at the top of the console) */
export async function getHubStats(): Promise<HubStats> {
  const { data } = await http.get<HubStats>('/hub/stats')
  return data
}

/** ⑤ §12.1 Catalog (q matches name/description/plugin_id/tags, case-insensitive) */
export async function listHubPlugins(params?: {
  q?: string
  category?: string
  sort?: HubSort
  page?: number
  page_size?: number
}): Promise<Paged<HubPluginRow>> {
  const { data } = await http.get<Paged<HubPluginRow>>('/hub/plugins', { params })
  return data
}

/** ⑤ §12.2 Detail (readme, version list, caller's install record) */
export async function getHubPlugin(pluginId: string): Promise<HubPluginDetail> {
  const { data } = await http.get<HubPluginDetail>(
    `/hub/plugins/${encodeURIComponent(pluginId)}`,
  )
  return data
}

/** ⑤ §12.3 Publish step 1: submit metadata, get the PUT target for the archive */
export async function publishHubPlugin(body: HubPublishReq): Promise<HubPublishResp> {
  const { data } = await http.post<HubPublishResp>('/hub/plugins', body)
  return data
}

/**
 * ⑤ §12.4 Publish step 2: PUT the raw bytes.
 *
 * `upload.path` is an absolute path from the server (with a `/v1` prefix) while the
 * http instance baseURL is already `/v1`, so using it as-is would give `/v1/v1/...`;
 * strip one segment here. Content-Type comes from the server value (archive
 * `application/octet-stream`, source package `application/zip`), defaulting to
 * octet-stream.
 */
async function putHubArchive(
  target: HubUploadTarget,
  file: Blob,
  timeoutMs: number,
  onProgress?: (percent: number) => void,
): Promise<HubUploadResp> {
  const path = target.path.startsWith('/v1/') ? target.path.slice(3) : target.path
  const headers: Record<string, string> = { ...target.headers }
  if (!headers['Content-Type']) headers['Content-Type'] = 'application/octet-stream'
  const { data } = await http.put<HubUploadResp>(path, file, {
    headers,
    timeout: timeoutMs,
    onUploadProgress: (e: AxiosProgressEvent) => {
      if (!onProgress) return
      onProgress(e.total ? Math.round((e.loaded / e.total) * 100) : 0)
    },
  })
  return data
}

/** ⑤ §12.4 Archive upload (≤20MiB, 120s allowed on slow networks) */
export async function uploadHubBlob(
  target: HubUploadTarget,
  file: Blob,
  onProgress?: (percent: number) => void,
): Promise<HubUploadResp> {
  // A 20MiB archive can exceed the default 20s on slow networks; the progress callback feeds the modal progress bar
  return putHubArchive(target, file, 120_000, onProgress)
}

/** ⑤ §12.4 (v2 contract §1.3) source package upload (≤50MiB, 300s allowed on slow networks) */
export async function uploadHubSource(
  target: HubUploadTarget,
  file: Blob,
  onProgress?: (percent: number) => void,
): Promise<HubSourceUploadResp> {
  const data = await putHubArchive(target, file, 300_000, onProgress)
  return data as unknown as HubSourceUploadResp
}

/**
 * ⑤ §12.5 Download.
 *
 * The endpoint itself is a `302` → MinIO presigned URL; browser XHR follows it
 * automatically, so `responseType: 'blob'` fetches the final bytes (Authorization
 * covers only the first hop; the presigned URL needs none). `window.open` is not an
 * option: it cannot carry the login token and would get a 401.
 */
export async function downloadHubVersion(pluginId: string, version: string): Promise<Blob> {
  const { data } = await http.get<Blob>(
    `/hub/plugins/${encodeURIComponent(pluginId)}/versions/${encodeURIComponent(version)}/download`,
    { responseType: 'blob', timeout: 120_000 },
  )
  return data
}

/** ⑤ §12.5 (v2 contract §1.4) download source package: 404 `source_missing` when absent */
export async function downloadHubSource(pluginId: string, version: string): Promise<Blob> {
  const { data } = await http.get<Blob>(
    `/hub/plugins/${encodeURIComponent(pluginId)}/versions/${encodeURIComponent(version)}/source`,
    { responseType: 'blob', timeout: 300_000 },
  )
  return data
}

/** ⑤ §12.6 Unpublish one version (version becomes removed; archive kept 30 days for rollback) */
export async function deleteHubVersion(pluginId: string, version: string): Promise<void> {
  await http.delete(
    `/hub/plugins/${encodeURIComponent(pluginId)}/versions/${encodeURIComponent(version)}`,
  )
}

/** ⑤ §12.6 Unpublish plugin (install records are kept) */
export async function deleteHubPlugin(pluginId: string): Promise<void> {
  await http.delete(`/hub/plugins/${encodeURIComponent(pluginId)}`)
}

/** ⑤ §12.7 Current user's install records (cross-device sync; read-only in the console) */
export async function listHubInstalls(params?: {
  include_data?: boolean
}): Promise<{ items: HubInstallRow[] }> {
  const { data } = await http.get<{ items: HubInstallRow[] }>('/hub/installs', {
    params: params?.include_data ? { include_data: 1 } : undefined,
  })
  return data
}
