import { useCallback, useEffect, useRef, useState } from 'react'
import { LIST_PAGE_SIZE, LIST_SCROLL_Y } from '@/components/listLayout'
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Drawer,
  Dropdown,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  App as AntApp,
} from 'antd'
import type { MenuProps } from 'antd'
import {
  DeleteOutlined,
  DownOutlined,
  PictureOutlined,
  PlusOutlined,
  ReloadOutlined,
} from '@ant-design/icons'
import { errText } from '@/lib/errors'
import {
  createUser,
  getPurgeProgress,
  listUsers,
  purgeUser,
  resetUserPassword,
  resumeUser,
  setUserQuota,
  setUserRole,
  suspendUser,
  updateUserProfile,
} from '@/api/endpoints'
import type { AdminUser, Quota, Role } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { ReasonModal } from '@/components/ReasonModal'
import { ROLE_LABEL } from '@/auth/rbac'
import { RoleTag } from '@/components/RoleTag'
import { UserAvatar, initialOfName } from '@/components/UserAvatar'
import { fmtBytes, fmtTime } from '@/lib/format'
import { ACCOUNT_STATUS, pick, toneOf } from '@/lib/labels'
import { HelpTip } from '@/components/HelpTip'
import { useI18n, type Translate } from '@/i18n'

const ROLES: Role[] = ['admin', 'ops', 'user']

const ROLE_HINT: Record<Role, string> = {
  admin: 'Full access, including change operations',
  ops: 'Can perform disposition actions, but cannot change config or accounts',
  user: 'Regular user (read-only)',
}

/**
 * The part of `GET /v1/admin/users/{id}/purge` the progress drawer renders.
 *
 * The endpoint returns three blocks: `progress` (per-store item counts), `cleanup`
 * (background cascade progress; null until a compliance delete actually starts) and
 * `residual` (measured right now, to confirm nothing is left).
 */
interface PurgeCounts {
  pg_messages?: number
  pg_devices?: number
  minio_objects?: number
}

interface PurgeCleanup {
  phase?: string
  messages_deleted?: number
  chunks_deleted?: number
  objects_deleted?: number
  objects_failed?: number
  redis_keys_deleted?: number
  started_at?: string | null
  finished_at?: string | null
  last_error?: string | null
  object_keys?: string[]
  manifest_truncated?: boolean
}

interface PurgeResidual {
  pg_messages?: number
  pg_chunks?: number
  pg_delivery_log?: number
  pg_devices?: number
  pg_user_status?: string | null
  minio_objects_recorded?: number
  cleanup_phase?: string
}

interface PurgeProgressData {
  user_id?: string
  progress?: PurgeCounts
  cleanup?: PurgeCleanup | null
  residual?: PurgeResidual
}

/** Cleanup phases written by the node (`jobs.rs::PurgeProgress`) in plain language */
const PURGE_PHASE_LABEL: Record<string, string> = {
  queued: 'Queued',
  objects: 'Deleting files',
  redis: 'Clearing cache',
  done: 'Done',
  error: 'Failed',
}

function purgePhaseText(phase: string | undefined, t: Translate): string {
  if (!phase) return '—'
  return t(PURGE_PHASE_LABEL[phase] ?? phase)
}

function purgeCountText(v: number | undefined): string {
  return typeof v === 'number' ? String(v) : '—'
}

/** One-line quota summary (the table cannot stack four fields) */
function quotaSummary(q: Quota | undefined, t: Translate): string {
  if (!q) return t('Not set')
  const rate = q.msg_per_s ? t('{rate} msg/s', { rate: q.msg_per_s }) : t('Unlimited rate')
  const storage = q.storage_bytes ? fmtBytes(q.storage_bytes) : t('Unlimited')
  return t('{rate} · storage {storage}', { rate, storage })
}

// ---------------------------------------------------------------------------
// Avatar (v0.8): same limits as the server — the whole data URL stored in the DB is
// ≤256KiB (the DB has its own 300KiB guard). The console shrinks a selected local image
// to 128px on a canvas before encoding, so the list response never carries the original.
// ---------------------------------------------------------------------------

const AVATAR_MAX_BYTES = 256 * 1024
const AVATAR_INPUT_MAX_BYTES = 8 * 1024 * 1024
const AVATAR_MIMES = ['image/png', 'image/jpeg', 'image/webp', 'image/gif']

function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

function readAsDataUrl(file: Blob, t: Translate): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result ?? ''))
    reader.onerror = () => reject(new Error(t('Failed to read the image')))
    reader.readAsDataURL(file)
  })
}

/** Local image → a data URL the server accepts (shrink to 128px + quality ladder, ≤256KiB after encoding) */
async function compressAvatarFile(file: File, t: Translate): Promise<string> {
  if (!AVATAR_MIMES.includes(file.type)) {
    throw new Error(t('Only PNG / JPEG / WebP / GIF images are supported'))
  }
  if (file.size > AVATAR_INPUT_MAX_BYTES) {
    throw new Error(t('Image is too large (over 8MB); compress it before selecting'))
  }
  if (file.type === 'image/gif') {
    const raw = await readAsDataUrl(file, t)
    if (raw.length > AVATAR_MAX_BYTES) {
      throw new Error(t('Encoded GIF avatar exceeds 256KB; choose a smaller image'))
    }
    return raw
  }
  const objectUrl = URL.createObjectURL(file)
  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const el = new Image()
      el.onload = () => resolve(el)
      el.onerror = () => reject(new Error(t('Image decoding failed (the file may be corrupted)')))
      el.src = objectUrl
    })
    const scale = Math.min(1, 128 / Math.max(img.naturalWidth || 1, img.naturalHeight || 1))
    let width = Math.max(1, Math.round((img.naturalWidth || 1) * scale))
    let height = Math.max(1, Math.round((img.naturalHeight || 1) * scale))
    for (let attempt = 0; attempt < 6; attempt += 1) {
      const canvas = document.createElement('canvas')
      canvas.width = width
      canvas.height = height
      const ctx = canvas.getContext('2d')
      if (!ctx) throw new Error(t('This browser does not support avatar compression'))
      ctx.fillStyle = '#ffffff'
      ctx.fillRect(0, 0, width, height)
      ctx.drawImage(img, 0, 0, width, height)
      const quality = Math.max(0.4, 0.9 - attempt * 0.12)
      const webp = canvas.toDataURL('image/webp', quality)
      const dataUrl = webp.startsWith('data:image/webp') ? webp : canvas.toDataURL('image/jpeg', quality)
      if (dataUrl.length <= AVATAR_MAX_BYTES) return dataUrl
      width = Math.max(32, Math.round(width * 0.8))
      height = Math.max(32, Math.round(height * 0.8))
    }
    throw new Error(t('Compressed image still exceeds 256KB; choose a smaller image'))
  } finally {
    URL.revokeObjectURL(objectUrl)
  }
}

/** Local pre-check for external avatar URLs (same rule as the server) */
function normalizeAvatarUrl(raw: string, t: Translate): string {
  const url = raw.trim()
  if (!url.startsWith('https://') || url.length > 2048 || /\s/.test(url)) {
    throw new Error(t('Avatar URL must be an https:// image address'))
  }
  return url
}

/** Initials of the display name (placeholder circle in tables/dialogs when there is no avatar): same rule as the account area/user-avatar */
function initialOf(user: AdminUser): string {
  return initialOfName(user.display_name || user.username)
}

export default function UsersPage() {
  const { t } = useI18n()
  const { message } = AntApp.useApp()
  const { can, session } = useAuth()
  const [rows, setRows] = useState<AdminUser[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [q, setQ] = useState('')
  const [status, setStatus] = useState<string | undefined>()
  const [loading, setLoading] = useState(false)
  // Rows per page follow the viewport height so the table fills the card without a scrollbar
  const pageSize = LIST_PAGE_SIZE
  const [err, setErr] = useState<string | null>(null)

  const [createOpen, setCreateOpen] = useState(false)
  const [createForm] = Form.useForm()
  const [creating, setCreating] = useState(false)

  const [quotaTarget, setQuotaTarget] = useState<AdminUser | null>(null)
  const [quotaForm] = Form.useForm()

  const [roleTarget, setRoleTarget] = useState<AdminUser | null>(null)
  const [roleValue, setRoleValue] = useState<Role>('user')

  // Edit profile (admin|ops) and reset password (admin only): both dialogs are driven by
  // "target user + Form instance", using key={target.id} + initialValues so reopening
  // them never keeps stale input.
  const [editTarget, setEditTarget] = useState<AdminUser | null>(null)
  const [editForm] = Form.useForm()
  const [editSaving, setEditSaving] = useState(false)
  // Avatar edit state: when touched=false the save request omits avatar (server semantics: omitted = unchanged)
  const [editAvatar, setEditAvatar] = useState<string | null>(null)
  const [editAvatarTouched, setEditAvatarTouched] = useState(false)
  const [editAvatarUrl, setEditAvatarUrl] = useState('')
  const [editAvatarBusy, setEditAvatarBusy] = useState(false)
  const editAvatarInputRef = useRef<HTMLInputElement | null>(null)
  const [resetTarget, setResetTarget] = useState<AdminUser | null>(null)
  const [resetForm] = Form.useForm()
  const [resetSaving, setResetSaving] = useState(false)

  const [reason, setReason] = useState<
    | null
    | { kind: 'suspend' | 'resume'; user: AdminUser }
    | { kind: 'purge'; user: AdminUser }
  >(null)

  const [purgeInfo, setPurgeInfo] = useState<{ user: AdminUser; data: PurgeProgressData } | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setErr(null)
    try {
      const r = await listUsers({ q: q || undefined, status, page, page_size: pageSize })
      setRows(r.items ?? [])
      setTotal(r.total ?? 0)
    } catch (e) {
      setErr(errText(e))
    } finally {
      setLoading(false)
    }
  }, [q, status, page, pageSize])

  useEffect(() => {
    void load()
  }, [load])

  async function submitCreate() {
    const v = await createForm.validateFields()
    setCreating(true)
    try {
      await createUser({
        username: v.username,
        password: v.password,
        display_name: v.display_name || undefined,
        role: v.role,
      })
      message.success(t('Account created. Share the initial password with the owner through a secure channel'))
      setCreateOpen(false)
      createForm.resetFields()
      void load()
    } catch (e) {
      message.error(errText(e))
    } finally {
      setCreating(false)
    }
  }

  async function submitQuota() {
    if (!quotaTarget) return
    const v = await quotaForm.validateFields()
    const body: Quota & { reason: string } = {
      reason: v.reason,
      msg_per_s: v.msg_per_s ?? undefined,
      bytes_per_s: v.bytes_per_s ? Math.round(Number(v.bytes_per_s) * 1024 * 1024) : undefined,
      topics: v.topics ?? undefined,
      storage_bytes: v.storage_gb ? Math.round(Number(v.storage_gb) * 1024 * 1024 * 1024) : undefined,
    }
    try {
      await setUserQuota(quotaTarget.id, body)
      message.success(t('Quota updated; it takes effect immediately'))
      setQuotaTarget(null)
      void load()
    } catch (e) {
      message.error(errText(e))
    }
  }

  async function submitRole() {
    if (!roleTarget) return
    try {
      await setUserRole(roleTarget.id, {
        role: roleValue,
        reason: t('Role changed from the console to {role}', { role: t(ROLE_LABEL[roleValue]) }),
      })
      message.success(t('Role updated: it applies when the user signs in again, or within 15 minutes at the latest'))
      setRoleTarget(null)
      void load()
    } catch (e) {
      message.error(errText(e))
    }
  }

  /** Open "Edit profile": the avatar starts from the target user's current value (omitted on save if untouched) */
  function openEditProfile(user: AdminUser) {
    setEditAvatar(user.avatar ?? null)
    setEditAvatarTouched(false)
    setEditAvatarUrl('')
    setEditTarget(user)
  }

  /** Console picks a local image: canvas-compress it into a ≤256KiB data URL (the same cap as the server) */
  async function pickEditAvatar(file: File | undefined) {
    if (!file) return
    setEditAvatarBusy(true)
    try {
      setEditAvatar(await compressAvatarFile(file, t))
      setEditAvatarTouched(true)
    } catch (e) {
      message.error(errMessage(e))
    } finally {
      setEditAvatarBusy(false)
    }
  }

  /** Console uses an external avatar URL (https:// only; the server rejects other schemes too) */
  function applyEditAvatarUrl() {
    try {
      setEditAvatar(normalizeAvatarUrl(editAvatarUrl, t))
      setEditAvatarTouched(true)
      setEditAvatarUrl('')
    } catch (e) {
      message.error(errMessage(e))
    }
  }

  /** Console edits a user profile (admin|ops): display name/avatar, with a mandatory reason written to audit `user.update` */
  async function submitProfile() {
    if (!editTarget) return
    const v = await editForm.validateFields()
    setEditSaving(true)
    try {
      const body: { display_name?: string; avatar?: string; reason: string } = {
        display_name: v.display_name ?? '',
        reason: v.reason,
      }
      // Omit the avatar when untouched (omitted = unchanged; empty string = clear the avatar)
      if (editAvatarTouched) body.avatar = editAvatar ?? ''
      await updateUserProfile(editTarget.id, body)
      message.success(t('User profile updated'))
      setEditTarget(null)
      void load()
    } catch (e) {
      message.error(errText(e))
    } finally {
      setEditSaving(false)
    }
  }

  /**
   * Admin resets a password (admin only): set a new password + mandatory reason.
   * On success all refresh tokens for that user are revoked, so they must sign in again
   * with the new password.
   */
  async function submitResetPassword() {
    if (!resetTarget) return
    const v = await resetForm.validateFields()
    setResetSaving(true)
    try {
      const r = await resetUserPassword(resetTarget.id, {
        new_password: v.new_password,
        reason: v.reason,
      })
      message.success(
        t('Password reset. Signed out all sessions for this user ({count} devices); they must sign in with the new password', {
          count: r.sessions_revoked ?? 0,
        }),
      )
      setResetTarget(null)
      void load()
    } catch (e) {
      message.error(errText(e))
    } finally {
      setResetSaving(false)
    }
  }

  function openQuota(user: AdminUser) {
    setQuotaTarget(user)
  }

  /** Initial values via initialValues + key: the Modal uses destroyOnClose, so setFieldsValue would lose them */
  const quotaInitial = quotaTarget
    ? {
        msg_per_s: quotaTarget.quota?.msg_per_s,
        bytes_per_s: quotaTarget.quota?.bytes_per_s
          ? Math.round((quotaTarget.quota.bytes_per_s / 1024 / 1024) * 10) / 10
          : undefined,
        topics: quotaTarget.quota?.topics,
        storage_gb: quotaTarget.quota?.storage_bytes
          ? Math.round((quotaTarget.quota.storage_bytes / 1024 / 1024 / 1024) * 10) / 10
          : undefined,
      }
    : {}

  const rowMenu = (r: AdminUser): MenuProps['items'] => {
    const isSelf = r.id === session?.userId
    const items: MenuProps['items'] = []
    // Profile maintenance: admin + ops (ops may change the display name, but not reset passwords/create accounts/change roles)
    if (can('dispose')) {
      items.push({ key: 'profile', label: t('Edit profile') })
    }
    if (can('mutate')) {
      items.push({
        key: 'password',
        label: t('Reset password'),
        disabled: r.status === 'deleted',
        title: r.status === 'deleted' ? t('A deleted account cannot have its password reset') : undefined,
      })
      items.push({ type: 'divider' })
      items.push({
        key: 'role',
        label: t('Change role'),
        disabled: isSelf,
        title: isSelf ? t('You cannot change your own role') : undefined,
      })
      items.push({ key: 'quota', label: t('Adjust quota') })
    }
    if (can('dispose')) {
      items.push({ type: 'divider' })
      if (r.status === 'suspended') items.push({ key: 'resume', label: t('Unban account'), disabled: isSelf })
      else items.push({ key: 'suspend', label: t('Ban account'), danger: true, disabled: isSelf })
    }
    items.push({ key: 'progress', label: t('View deletion progress') })
    if (can('mutate')) {
      items.push({ type: 'divider' })
      items.push({ key: 'purge', label: t('Compliance delete (irreversible)'), danger: true, disabled: isSelf })
    }
    return items
  }

  const purgeCleanup = purgeInfo?.data.cleanup
  const purgeResidual = purgeInfo?.data.residual

  return (
    <div className="page-fill">

      {err && <Alert type="error" showIcon message={t('Failed to load')} description={err} />}

      <Card className="list-card">
        <div className="toolbar">
          <div className="toolbar-right">
            <Space>
              <Button icon={<ReloadOutlined />} loading={loading} onClick={load}>
                {t('Refresh')}
              </Button>
              {can('mutate') && (
                <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
                  {t('New account')}
                </Button>
              )}
            </Space>
          </div>
          <Input.Search
            allowClear
            placeholder={t('Search username or display name')}
            style={{ width: 260 }}
            onSearch={(v) => {
              setPage(1)
              setQ(v.trim())
            }}
          />
          <Select
            allowClear
            placeholder={t('Account status')}
            style={{ width: 150 }}
            value={status}
            onChange={(v) => {
              setPage(1)
              setStatus(v)
            }}
            options={[
              { value: 'active', label: t('Active') },
              { value: 'suspended', label: t('Suspended') },
              { value: 'deleted', label: t('Deleted') },
            ]}
          />
          <span className="muted">{t('{count} accounts', { count: total })}</span>
        </div>

        <Table<AdminUser>
          size="small"
          scroll={{ y: LIST_SCROLL_Y }}
          rowKey="id"
          loading={loading}
          dataSource={rows}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: false,
            onChange: (p) => setPage(p),
            showTotal: (count) => t('{count} accounts', { count }),
          }}
          columns={[
            {
              title: t('Avatar'),
              dataIndex: 'avatar',
              width: 64,
              align: 'center',
              render: (v: string | null, r) => (
                <Tooltip
                  title={
                    v
                      ? t('Avatar set')
                      : t('No avatar set; showing the initials "{initials}"', { initials: initialOf(r) })
                  }
                >
                  <span>
                    <UserAvatar name={r.display_name || r.username} src={v} size={32} />
                  </span>
                </Tooltip>
              ),
            },
            {
              title: t('User'),
              dataIndex: 'username',
              render: (v: string, r) => (
                <Space direction="vertical" size={0}>
                  <span className="cell-title">{r.display_name || v}</span>
                  <span className="cell-sub">
                    @{v}
                    <Tooltip title={t('User ID (API identifier): {id}', { id: r.id })}>
                      <span style={{ marginLeft: 8, cursor: 'help' }}>ID</span>
                    </Tooltip>
                  </span>
                </Space>
              ),
            },
            {
              title: t('Status'),
              dataIndex: 'status',
              width: 96,
              render: (v: string) => <Tag color={toneOf(v)}>{t(pick(ACCOUNT_STATUS, v, 'Unknown'))}</Tag>,
            },
            {
              title: (
                <Space size={2}>
                  {t('Role')}
                  <HelpTip title={t('Determines which menus and buttons are visible. Admin > Ops > Read-only.')} />
                </Space>
              ),
              dataIndex: 'role',
              width: 96,
              render: (v: string) => <RoleTag role={v} />,
            },
            {
              title: (
                <Space size={2}>
                  {t('Usage limits')}
                  <HelpTip title={t('Limits the message rate and storage this user may consume. Not set means the platform default applies.')} />
                </Space>
              ),
              dataIndex: 'quota',
              render: (qv: Quota) => <span style={{ fontSize: 13 }}>{quotaSummary(qv, t)}</span>,
            },
            {
              title: t('Created'),
              dataIndex: 'created_at',
              width: 160,
              render: (v) => <span style={{ fontSize: 13 }}>{fmtTime(v)}</span>,
            },
            {
              title: t('Actions'),
              width: 96,
              render: (_, r) => (
                <Dropdown
                  menu={{
                    items: rowMenu(r),
                    onClick: async ({ key }) => {
                      if (key === 'profile') {
                        openEditProfile(r)
                      } else if (key === 'password') {
                        setResetTarget(r)
                      } else if (key === 'role') {
                        setRoleTarget(r)
                        setRoleValue(r.role)
                      } else if (key === 'quota') {
                        openQuota(r)
                      } else if (key === 'suspend' || key === 'resume' || key === 'purge') {
                        setReason({ kind: key, user: r })
                      } else if (key === 'progress') {
                        try {
                          setPurgeInfo({ user: r, data: (await getPurgeProgress(r.id)) as PurgeProgressData })
                        } catch (e) {
                          message.error(errText(e))
                        }
                      }
                    },
                  }}
                  trigger={['click']}
                >
                  <Button size="small">
                    {t('Manage')} <DownOutlined />
                  </Button>
                </Dropdown>
              ),
            },
          ]}
        />
      </Card>

      {/* New account */}
      <Modal
        open={createOpen}
        title={t('New account')}
        okText={t('Create account')}
        cancelText={t('Cancel')}
        confirmLoading={creating}
        onOk={submitCreate}
        onCancel={() => setCreateOpen(false)}
        destroyOnClose
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 14 }}
          message={t('There is no self-service sign-up. After creating the account, give the username and initial password to the owner and ask them to change it soon.')}
        />
        <Form form={createForm} layout="vertical" initialValues={{ role: 'user' }} requiredMark={false}>
          <Form.Item
            name="username"
            label={t('Username (sign-in name)')}
            rules={[
              { required: true, message: t('Enter a username') },
              { pattern: /^[A-Za-z0-9._-]{3,64}$/, message: t('3–64 characters: letters, digits, dot, underscore, hyphen only') },
            ]}
          >
            <Input placeholder={t('e.g. alice')} autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="password"
            label={t('Initial password')}
            rules={[
              { required: true, message: t('Enter an initial password') },
              { min: 8, max: 128, message: t('Must be 8–128 characters') },
            ]}
          >
            <Input.Password autoComplete="new-password" placeholder={t('At least 8 characters')} />
          </Form.Item>
          <Form.Item name="display_name" label={t('Display name (optional)')}>
            <Input placeholder={t('e.g. Jane Doe')} />
          </Form.Item>
          <Form.Item name="role" label={t('Role')} extra={t('Pick "user" if unsure; you can change it later.')}>
            <Select options={ROLES.map((r) => ({ value: r, label: `${t(ROLE_LABEL[r])} — ${t(ROLE_HINT[r])}` }))} />
          </Form.Item>
        </Form>
      </Modal>

      {/* Quota */}
      <Modal
        open={Boolean(quotaTarget)}
        title={t('Adjust usage limits · {user}', { user: quotaTarget?.display_name || quotaTarget?.username || '' })}
        okText={t('Save')}
        cancelText={t('Cancel')}
        onOk={submitQuota}
        onCancel={() => setQuotaTarget(null)}
        destroyOnClose
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 13 }}>
          {t('Leave a field empty to use the platform default. Upper bounds are enforced platform-wide; values above them are rejected by the server.')}
        </Typography.Paragraph>
        <Form
          form={quotaForm}
          key={quotaTarget?.id ?? 'quota'}
          layout="vertical"
          requiredMark={false}
          initialValues={quotaInitial}
        >
          <Form.Item name="msg_per_s" label={t('Send rate limit (msgs/s)')}>
            <InputNumber min={1} max={1000} style={{ width: '100%' }} placeholder={t('e.g. 100')} />
          </Form.Item>
          <Form.Item name="bytes_per_s" label={t('Bandwidth limit (MB/s)')}>
            <InputNumber min={0.1} step={1} style={{ width: '100%' }} placeholder={t('e.g. 25')} />
          </Form.Item>
          <Form.Item name="topics" label={t('Topics the user may subscribe to')}>
            <InputNumber min={0} max={1000} style={{ width: '100%' }} placeholder={t('e.g. 100')} />
          </Form.Item>
          <Form.Item name="storage_gb" label={t('Storage quota (GB)')}>
            <InputNumber min={0} step={1} style={{ width: '100%' }} placeholder={t('e.g. 10')} />
          </Form.Item>
          <Form.Item name="reason" label={t('Reason for change (recorded in audit)')} rules={[{ required: true, message: t('Enter a reason') }]}>
            <Input.TextArea rows={2} placeholder={t('e.g. this user is more active; temporary increase')} />
          </Form.Item>
        </Form>
      </Modal>

      {/* Change role */}
      <Modal
        open={Boolean(roleTarget)}
        title={t('Change role · {user}', { user: roleTarget?.display_name || roleTarget?.username || '' })}
        okText={t('Save')}
        cancelText={t('Cancel')}
        onOk={submitRole}
        onCancel={() => setRoleTarget(null)}
        destroyOnClose
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 14 }}
          message={t('Role changes are written into the sign-in token: they apply immediately when the user signs in again, otherwise within 15 minutes. The last admin cannot be demoted.')}
        />
        <Select
          style={{ width: '100%' }}
          value={roleValue}
          onChange={(v) => setRoleValue(v)}
          options={ROLES.map((r) => ({ value: r, label: `${t(ROLE_LABEL[r])} — ${t(ROLE_HINT[r])}` }))}
        />
      </Modal>

      {/* Edit profile (admin|ops) */}
      <Modal
        open={Boolean(editTarget)}
        title={t('Edit profile · {user}', { user: editTarget?.username ?? '' })}
        okText={t('Save')}
        cancelText={t('Cancel')}
        confirmLoading={editSaving}
        onOk={submitProfile}
        onCancel={() => setEditTarget(null)}
        destroyOnClose
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 14 }}
          message={t('The username is the stable identifier for sign-in and audit and cannot change after creation; here you can adjust the display name and avatar. Saving is recorded in the audit log (without the avatar data itself).')}
        />
        <Form
          form={editForm}
          key={editTarget?.id ?? 'edit-profile'}
          layout="vertical"
          requiredMark={false}
          initialValues={{ display_name: editTarget?.display_name ?? '', reason: '' }}
        >
          <Form.Item label={t('Avatar')}>
            <Space align="start" size={16}>
              <UserAvatar
                name={editTarget?.display_name || editTarget?.username}
                src={editAvatar}
                size={64}
                style={{ fontSize: 24 }}
              />
              <Space direction="vertical" size={8}>
                <Space wrap size={8}>
                  <Button
                    size="small"
                    icon={<PictureOutlined />}
                    loading={editAvatarBusy}
                    onClick={() => editAvatarInputRef.current?.click()}
                  >
                    {t('Choose local image')}
                  </Button>
                  <Button
                    size="small"
                    icon={<DeleteOutlined />}
                    disabled={!editAvatar}
                    onClick={() => {
                      setEditAvatar(null)
                      setEditAvatarTouched(true)
                    }}
                  >
                    {t('Clear avatar')}
                  </Button>
                </Space>
                <span className="muted" style={{ fontSize: 12 }}>
                  {t('Supports PNG / JPEG / WebP / GIF, compressed to at most 256KB; initials are shown when no avatar is set.')}
                </span>
              </Space>
            </Space>
          </Form.Item>
          <Form.Item label={t('Use an image URL (optional)')}>
            <Space.Compact style={{ width: '100%' }}>
              <Input
                placeholder="https://example.com/avatar.png"
                value={editAvatarUrl}
                onChange={(e) => setEditAvatarUrl(e.target.value)}
                onPressEnter={applyEditAvatarUrl}
              />
              <Button onClick={applyEditAvatarUrl} disabled={!editAvatarUrl.trim()}>
                {t('Use link')}
              </Button>
            </Space.Compact>
          </Form.Item>
          <input
            ref={editAvatarInputRef}
            type="file"
            accept="image/png,image/jpeg,image/webp,image/gif"
            style={{ display: 'none' }}
            onChange={(e) => {
              void pickEditAvatar(e.target.files?.[0])
              e.target.value = ''
            }}
          />
          <Form.Item name="display_name" label={t('Display name')}>
            <Input placeholder={t('Leave empty to show no name')} maxLength={64} allowClear />
          </Form.Item>
          <Form.Item
            name="reason"
            label={t('Reason for change (recorded in audit)')}
            rules={[{ required: true, message: t('Enter a reason') }]}
          >
            <Input.TextArea rows={2} maxLength={500} showCount placeholder={t('e.g. user asked to change their avatar / the name was entered incorrectly')} />
          </Form.Item>
        </Form>
      </Modal>

      {/* Reset password (admin only; ops do not see this menu item) */}
      <Modal
        open={Boolean(resetTarget)}
        title={t('Reset password · {user}', { user: resetTarget?.display_name || resetTarget?.username || '' })}
        okText={t('Confirm reset')}
        cancelText={t('Cancel')}
        confirmLoading={resetSaving}
        okButtonProps={{ danger: true }}
        onOk={submitResetPassword}
        onCancel={() => setResetTarget(null)}
        destroyOnClose
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 14 }}
          message={t('After the reset, every device for this user is signed out immediately and must sign in with the new password. The new password is not shown here; hand it over through a secure channel.')}
        />
        <Form form={resetForm} key={resetTarget?.id ?? 'reset-password'} layout="vertical" requiredMark={false}>
          <Form.Item
            name="new_password"
            label={t('New password')}
            rules={[
              { required: true, message: t('Enter a new password') },
              { min: 8, max: 128, message: t('Must be 8–128 characters') },
            ]}
          >
            <Input.Password autoComplete="new-password" placeholder={t('At least 8 characters')} />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label={t('Confirm new password')}
            dependencies={['new_password']}
            rules={[
              { required: true, message: t('Enter the new password again') },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || value === getFieldValue('new_password')) return Promise.resolve()
                  return Promise.reject(new Error(t('The two passwords do not match')))
                },
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" placeholder={t('Type the new password again')} />
          </Form.Item>
          <Form.Item
            name="reason"
            label={t('Reason for reset (recorded in audit)')}
            rules={[{ required: true, message: t('Enter a reason') }]}
          >
            <Input.TextArea rows={2} maxLength={500} showCount placeholder={t('e.g. the user forgot their password and identity was verified by phone')} />
          </Form.Item>
        </Form>
      </Modal>

      {/* Ban / unban / compliance delete */}
      <ReasonModal
        open={Boolean(reason)}
        danger={reason?.kind !== 'resume'}
        title={
          reason?.kind === 'suspend'
            ? t('Ban account {user}', { user: reason.user.display_name || reason.user.username })
            : reason?.kind === 'resume'
              ? t('Unban {user}', { user: reason.user.display_name || reason.user.username })
              : t('Compliance delete {user}', { user: reason?.user.display_name || reason?.user.username || '' })
        }
        description={
          reason?.kind === 'purge'
            ? t('This permanently deletes the account, its messages, files and cache, and cannot be undone (audit logs are kept). Make sure the user or legal has confirmed first.')
            : reason?.kind === 'suspend'
              ? t('The account can no longer sign in immediately and live connections are dropped; data is kept and the ban can be lifted at any time.')
              : t('The account is active again and can sign in.')
        }
        confirmText={
          reason?.kind === 'purge' ? { label: t('Type the username to confirm'), expect: reason.user.username } : undefined
        }
        okText={reason?.kind === 'purge' ? t('Delete permanently') : t('Confirm')}
        onCancel={() => setReason(null)}
        onSubmit={async (why) => {
          if (!reason) return
          if (reason.kind === 'suspend') await suspendUser(reason.user.id, why)
          else if (reason.kind === 'resume') await resumeUser(reason.user.id, why)
          else await purgeUser(reason.user.id, { reason: why, confirm_username: reason.user.username })
          message.success(t('Action submitted'))
          void load()
        }}
      />

      <Drawer
        open={Boolean(purgeInfo)}
        width={520}
        title={t('Deletion progress · {user}', { user: purgeInfo?.user.display_name || purgeInfo?.user.username || '' })}
        onClose={() => setPurgeInfo(null)}
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 13 }}>
          {t('Deletion runs in steps: disable the account, clean up messages and files, then remove it from the database. Below is the current progress.')}
        </Typography.Paragraph>

        {purgeCleanup ? (
          <Descriptions column={1} size="small" bordered style={{ marginBottom: 12 }}>
            <Descriptions.Item label={t('Cleanup phase')}>
              {purgePhaseText(purgeCleanup.phase, t)}
            </Descriptions.Item>
            <Descriptions.Item label={t('Deleted messages')}>
              {purgeCountText(purgeCleanup.messages_deleted)}
            </Descriptions.Item>
            <Descriptions.Item label={t('Deleted chunks')}>
              {purgeCountText(purgeCleanup.chunks_deleted)}
            </Descriptions.Item>
            <Descriptions.Item label={t('Deleted files')}>
              {purgeCountText(purgeCleanup.objects_deleted)}
            </Descriptions.Item>
            <Descriptions.Item label={t('File deletions that failed')}>
              {purgeCountText(purgeCleanup.objects_failed)}
            </Descriptions.Item>
            <Descriptions.Item label={t('Cleared cache keys')}>
              {purgeCountText(purgeCleanup.redis_keys_deleted)}
            </Descriptions.Item>
            <Descriptions.Item label={t('Started / ended')}>
              {purgeCleanup.started_at ? fmtTime(purgeCleanup.started_at) : '—'}
              {' / '}
              {purgeCleanup.finished_at ? fmtTime(purgeCleanup.finished_at) : '—'}
            </Descriptions.Item>
          </Descriptions>
        ) : (
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 12 }}
            message={t('No deletion task has been started for this account.')}
          />
        )}

        {purgeCleanup?.last_error ? (
          <Alert
            type="error"
            showIcon
            style={{ marginBottom: 12 }}
            message={t('The last cleanup attempt failed')}
            description={purgeCleanup.last_error}
          />
        ) : null}

        {purgeResidual ? (
          <Descriptions column={1} size="small" bordered title={t('Remaining right now')}>
            <Descriptions.Item label={t('Remaining messages')}>
              {purgeCountText(purgeResidual.pg_messages)}
            </Descriptions.Item>
            <Descriptions.Item label={t('Remaining chunks')}>
              {purgeCountText(purgeResidual.pg_chunks)}
            </Descriptions.Item>
            <Descriptions.Item label={t('Remaining delivery records')}>
              {purgeCountText(purgeResidual.pg_delivery_log)}
            </Descriptions.Item>
            <Descriptions.Item label={t('Remaining devices')}>
              {purgeCountText(purgeResidual.pg_devices)}
            </Descriptions.Item>
            <Descriptions.Item label={t('Recorded objects')}>
              {purgeCountText(purgeResidual.minio_objects_recorded)}
            </Descriptions.Item>
            <Descriptions.Item label={t('Account status')}>
              {t(pick(ACCOUNT_STATUS, purgeResidual.pg_user_status))}
            </Descriptions.Item>
          </Descriptions>
        ) : null}
      </Drawer>
    </div>
  )
}
