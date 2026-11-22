import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { Alert, App as AntApp, Button, Dropdown, Form, Input, Layout, Menu, Modal, Space, Tooltip } from 'antd'
import type { MenuProps } from 'antd'
import {
  ApiOutlined,
  AppstoreOutlined,
  CloudServerOutlined,
  DeleteOutlined,
  PictureOutlined,
  TagsOutlined,
  AuditOutlined,
  CodeOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  DeploymentUnitOutlined,
  IdcardOutlined,
  KeyOutlined,
  LockOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  MessageOutlined,
  MoonOutlined,
  QuestionCircleOutlined,
  SettingOutlined,
  SunOutlined,
  TeamOutlined,
  ThunderboltOutlined,
  VideoCameraOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { useAuth } from '@/auth/AuthProvider'
import { ROLE_LABEL } from '@/auth/rbac'
import type { Role } from '@/api/types'
import { probeReady, session as tokenSession } from '@/api/http'
import { changeMyPassword, getMyProfile, updateMyProfile } from '@/api/endpoints'
import { errText } from '@/lib/errors'
import { GlossaryDrawer } from '@/components/GlossaryDrawer'
import LanguageSwitch from '@/components/LanguageSwitch'
import { RoleTag } from '@/components/RoleTag'
import { UserAvatar } from '@/components/UserAvatar'
import { useThemeMode } from '@/components/ThemeProvider'
import { useI18n, type Translate } from '@/i18n'

const { Header, Sider, Content } = Layout

interface NavItem {
  key: string
  icon: ReactNode
  /** Visible roles (menu differences are a product requirement: admin sees everything, ops sees operations, users see business pages only) */
  roles: Role[]
  label: string
  group: string
}

/**
 * Navigation groups by "what do you want to do right now" instead of flattening a dozen
 * endpoints into a menu. Group order = usage frequency: daily dashboard → people →
 * content → operations → compliance → system.
 */
const NAV: NavItem[] = [
  { key: '/', icon: <DashboardOutlined />, label: 'Dashboard', group: 'Overview', roles: ['admin', 'ops', 'user'] },
  { key: '/users', icon: <TeamOutlined />, label: 'Users', group: 'Users & devices', roles: ['admin', 'ops'] },
  { key: '/nodes', icon: <CloudServerOutlined />, label: 'Server nodes', group: 'Operations', roles: ['admin', 'ops'] },
  { key: '/devices', icon: <ApiOutlined />, label: 'Devices', group: 'Users & devices', roles: ['admin', 'ops'] },
  { key: '/conversations', icon: <MessageOutlined />, label: 'Conversations', group: 'Conversations & messages', roles: ['admin', 'ops', 'user'] },
  { key: '/messages', icon: <DatabaseOutlined />, label: 'Message search', group: 'Conversations & messages', roles: ['admin', 'ops', 'user'] },
  { key: '/topics', icon: <TagsOutlined />, label: 'Broadcast topics', group: 'Conversations & messages', roles: ['admin', 'ops', 'user'] },
  { key: '/dlq', icon: <WarningOutlined />, label: 'Delivery failures', group: 'Operations', roles: ['admin', 'ops'] },
  { key: '/queue', icon: <ThunderboltOutlined />, label: 'Offline queue', group: 'Operations', roles: ['admin', 'ops'] },
  { key: '/recordings', icon: <VideoCameraOutlined />, label: 'Media recordings', group: 'Operations', roles: ['admin', 'ops'] },
  { key: '/audit', icon: <AuditOutlined />, label: 'Audit log', group: 'Compliance', roles: ['admin', 'ops'] },
  { key: '/hub', icon: <AppstoreOutlined />, label: 'Plugin hub', group: 'Extensions', roles: ['admin', 'ops', 'user'] },
  { key: '/plugins', icon: <DeploymentUnitOutlined />, label: 'Plugins', group: 'Extensions', roles: ['admin'] },
  { key: '/formats', icon: <CodeOutlined />, label: 'File formats', group: 'Extensions', roles: ['admin', 'ops'] },
  { key: '/config', icon: <SettingOutlined />, label: 'Dynamic config', group: 'Extensions', roles: ['admin'] },
  { key: '/keys', icon: <KeyOutlined />, label: 'Key management', group: 'Extensions', roles: ['admin'] },
]

const GROUP_ORDER = ['Overview', 'Users & devices', 'Conversations & messages', 'Operations', 'Compliance', 'Extensions']

function buildMenu(role: Role, t: Translate): MenuProps['items'] {
  return GROUP_ORDER.map((group) => {
    const items = NAV.filter((n) => n.group === group && n.roles.includes(role)).map((n) => ({
      key: n.key,
      icon: n.icon,
      label: t(n.label),
    }))
    if (items.length === 0) return null
    return { type: 'group' as const, label: t(group), children: items }
  }).filter(Boolean) as MenuProps['items']
}

// ---------------------------------------------------------------------------
// Avatar (v0.8): same rule as the server — what is stored is a data URL string of at
// most 256 KiB; the server also has a 300 KiB database CHECK as a backstop. A locally
// picked image is first scaled to 128px on a canvas, so a multi-MB original / huge
// base64 blob never ends up in PostgreSQL (it would also bloat the list pages).
// ---------------------------------------------------------------------------

/** Server limit: the whole string (including the `data:image/...;base64,` prefix) ≤ 256 KiB */
const AVATAR_MAX_BYTES = 256 * 1024
/** Original-file guard when picking an image (over this size, ask the user to compress it first to avoid freezing the page) */
const AVATAR_INPUT_MAX_BYTES = 8 * 1024 * 1024
/** Must match the server MIME allowlist; SVG is deliberately rejected (it can embed scripts, avatars render through <img>) */
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

/** Local image → a data URL the server accepts (scale to 128px + quality steps, ≤256 KiB after encoding) */
async function compressAvatarFile(file: File, t: Translate): Promise<string> {
  if (!AVATAR_MIMES.includes(file.type)) {
    throw new Error(t('Only PNG, JPEG, WebP or GIF images are supported'))
  }
  if (file.size > AVATAR_INPUT_MAX_BYTES) {
    throw new Error(t('The image is too large (over 8 MB); compress it first and choose it again'))
  }
  // GIF may be animated and canvas keeps only the first frame; upload it as-is, subject to the same 256 KiB encoded limit
  if (file.type === 'image/gif') {
    const raw = await readAsDataUrl(file, t)
    if (raw.length > AVATAR_MAX_BYTES) {
      throw new Error(t('The GIF avatar exceeds 256 KB after encoding; choose a smaller image'))
    }
    return raw
  }
  const objectUrl = URL.createObjectURL(file)
  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const el = new Image()
      el.onload = () => resolve(el)
      el.onerror = () => reject(new Error(t('Could not decode the image (the file may be corrupted)')))
      el.src = objectUrl
    })
    // Avatars render at 64px at most, so 128px is enough for 2x screens
    const scale = Math.min(1, 128 / Math.max(img.naturalWidth || 1, img.naturalHeight || 1))
    let width = Math.max(1, Math.round((img.naturalWidth || 1) * scale))
    let height = Math.max(1, Math.round((img.naturalHeight || 1) * scale))
    for (let attempt = 0; attempt < 6; attempt += 1) {
      const canvas = document.createElement('canvas')
      canvas.width = width
      canvas.height = height
      const ctx = canvas.getContext('2d')
      if (!ctx) throw new Error(t('This browser does not support avatar compression'))
      // Fill white before converting a transparent PNG to JPEG/WebP, otherwise the default background is black
      ctx.fillStyle = '#ffffff'
      ctx.fillRect(0, 0, width, height)
      ctx.drawImage(img, 0, 0, width, height)
      const quality = Math.max(0.4, 0.9 - attempt * 0.12)
      const webp = canvas.toDataURL('image/webp', quality)
      // Browsers without WebP encoding fall back to a PNG data URL, which is large; use JPEG then
      const dataUrl = webp.startsWith('data:image/webp') ? webp : canvas.toDataURL('image/jpeg', quality)
      if (dataUrl.length <= AVATAR_MAX_BYTES) return dataUrl
      width = Math.max(32, Math.round(width * 0.8))
      height = Math.max(32, Math.round(height * 0.8))
    }
    throw new Error(t('The image is still over 256 KB after compression; choose a smaller image'))
  } finally {
    URL.revokeObjectURL(objectUrl)
  }
}

/** Local pre-check for external avatar URLs (same rule as the server, saves a 422 round trip) */
function normalizeAvatarUrl(raw: string, t: Translate): string {
  const url = raw.trim()
  if (!url.startsWith('https://') || url.length > 2048 || /\s/.test(url)) {
    throw new Error(t('Avatar URL must be an image address starting with https://'))
  }
  return url
}

export default function AppLayout() {
  const { t } = useI18n()
  const { session, role, logout } = useAuth()
  const { mode, toggle: toggleTheme } = useThemeMode()
  const { message } = AntApp.useApp()
  const currentRole = (role as Role) || 'user'
  const menuItems = useMemo(() => buildMenu(currentRole, t), [currentRole, t])
  const nav = useNavigate()
  const loc = useLocation()
  const [collapsed, setCollapsed] = useState(false)
  const [glossary, setGlossary] = useState(false)
  // Renaming in the account menu updates the header/sidebar immediately (and writes back to the local session, no re-login needed)
  const [shownName, setShownName] = useState<string | null>(session?.displayName ?? null)
  // Avatar shown in the header/account menu (null = no avatar, fall back to the name initial); updated right after saving
  const [shownAvatar, setShownAvatar] = useState<string | null>(null)
  const [profileOpen, setProfileOpen] = useState(false)
  const [profileInit, setProfileInit] = useState<{ display_name: string }>({ display_name: '' })
  const [profileForm] = Form.useForm()
  const [profileSaving, setProfileSaving] = useState(false)
  const [profileErr, setProfileErr] = useState<string | null>(null)
  // Avatar edit state: when touched=false the save request omits avatar (= unchanged), so every save does not rewrite a large field
  const [profileAvatar, setProfileAvatar] = useState<string | null>(null)
  const [profileAvatarTouched, setProfileAvatarTouched] = useState(false)
  const [avatarUrl, setAvatarUrl] = useState('')
  const [avatarBusy, setAvatarBusy] = useState(false)
  const avatarInputRef = useRef<HTMLInputElement | null>(null)
  const [pwdOpen, setPwdOpen] = useState(false)
  const [pwdForm] = Form.useForm()
  const [pwdSaving, setPwdSaving] = useState(false)
  const [pwdErr, setPwdErr] = useState<string | null>(null)
  const [node, setNode] = useState<{ tone: 'ok' | 'warn' | 'bad'; text: string; detail: string }>({
    tone: 'bad',
    text: t('Connecting to service'),
    detail: t('Probing node status'),
  })

  useEffect(() => {
    setShownName(session?.displayName ?? null)
  }, [session?.displayName])

  // The avatar is not in the login snapshot (the JWT only carries role), so fetch the
  // self-service profile once after entering the shell: the display name follows the
  // server (it may have changed elsewhere) and the avatar renders the header/account menu.
  useEffect(() => {
    let alive = true
    void (async () => {
      try {
        const p = await getMyProfile()
        if (!alive) return
        setShownName(p.display_name ?? null)
        setShownAvatar(p.avatar ?? null)
      } catch {
        // A failed profile fetch must not block the shell: the avatar falls back to the name initial
      }
    })()
    return () => {
      alive = false
    }
  }, [])

  useEffect(() => {
    let alive = true
    async function tick() {
      try {
        const r = await probeReady()
        if (!alive) return
        const degraded = Object.entries(r.deps ?? {}).filter(([, v]) => v !== 'ok')
        setNode({
          tone: !r.ready || degraded.length === 0 ? (r.ready ? 'ok' : 'bad') : 'warn',
          text: !r.ready
            ? t('Service is not ready yet')
            : degraded.length
              ? t('Some dependencies are degraded')
              : t('Service is running normally'),
          detail: degraded.length
            ? t('Degraded dependencies: {list}', {
                list: degraded.map(([k, v]) => `${k} (${v})`).join(', '),
              })
            : t('Node {node} · all dependencies healthy', { node: r.node_id ?? '—' }),
        })
      } catch {
        if (!alive) return
        setNode({
          tone: 'bad',
          text: t('Cannot reach the service'),
          detail: t('The node is unreachable; check whether the backend is running'),
        })
      }
    }
    void tick()
    const timer = window.setInterval(tick, 15000)
    return () => {
      alive = false
      window.clearInterval(timer)
    }
  }, [t])

  const current = useMemo(() => {
    const matched = NAV.filter((n) => (n.key === '/' ? loc.pathname === '/' : loc.pathname.startsWith(n.key)))
    return matched.length ? matched[matched.length - 1] : NAV[0]
  }, [loc.pathname])

  async function openProfile() {
    setProfileErr(null)
    try {
      // Read the latest server values (not the login snapshot: the display name/avatar may have changed elsewhere)
      const p = await getMyProfile()
      setProfileInit({ display_name: p.display_name ?? '' })
      setProfileAvatar(p.avatar ?? null)
      setProfileAvatarTouched(false)
      setAvatarUrl('')
      setProfileOpen(true)
    } catch (e) {
      message.error(errText(e))
    }
  }

  /** Pick a local image: compress it on a canvas into a data URL ≤256 KiB (same limit as the server) */
  async function pickAvatarFile(file: File | undefined) {
    if (!file) return
    setProfileErr(null)
    setAvatarBusy(true)
    try {
      setProfileAvatar(await compressAvatarFile(file, t))
      setProfileAvatarTouched(true)
    } catch (e) {
      setProfileErr(errMessage(e))
    } finally {
      setAvatarBusy(false)
    }
  }

  /** Use an external avatar: only https:// is accepted (the server also rejects http/file/javascript and other schemes) */
  function applyAvatarUrl() {
    setProfileErr(null)
    try {
      setProfileAvatar(normalizeAvatarUrl(avatarUrl, t))
      setProfileAvatarTouched(true)
      setAvatarUrl('')
    } catch (e) {
      setProfileErr(errMessage(e))
    }
  }

  async function submitProfile() {
    const v = await profileForm.validateFields()
    setProfileSaving(true)
    setProfileErr(null)
    try {
      const body: { display_name?: string; avatar?: string } = { display_name: v.display_name ?? '' }
      // Omit the avatar when unchanged (server semantics: omitted = unchanged; empty string = clear)
      if (profileAvatarTouched) body.avatar = profileAvatar ?? ''
      const p = await updateMyProfile(body)
      setShownName(p.display_name ?? null)
      setShownAvatar(p.avatar ?? null)
      // Sync the local session (sessionStorage + AuthProvider subscription) so the account area does not regress on refresh
      if (session) tokenSession.set({ ...session, displayName: p.display_name, username: p.username })
      message.success(t('Profile saved'))
      setProfileOpen(false)
    } catch (e) {
      setProfileErr(errText(e))
    } finally {
      setProfileSaving(false)
    }
  }

  async function submitPassword() {
    const v = await pwdForm.validateFields()
    setPwdSaving(true)
    setPwdErr(null)
    try {
      const r = await changeMyPassword({
        old_password: v.old_password,
        new_password: v.new_password,
      })
      message.success(
        r.sessions_revoked > 0
          ? t('Password changed; {count} other devices were signed out and must sign in again (this session stays signed in)', {
              count: r.sessions_revoked,
            })
          : t('Password changed; this session stays signed in'),
      )
      setPwdOpen(false)
      pwdForm.resetFields()
    } catch (e) {
      setPwdErr(errText(e))
    } finally {
      setPwdSaving(false)
    }
  }

  const displayName = shownName || session?.username || ''
  // Avatar in the header/dropdown: show the image when set, otherwise a circle with the name initial (same component and rule as the account area/user list)
  const avatarNode = (size: number) => (
    <UserAvatar name={displayName} src={shownAvatar} size={size} />
  )

  const userMenu: MenuProps['items'] = [
    {
      key: 'who',
      label: (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '2px 0' }}>
          {avatarNode(32)}
          <div>
            <div style={{ fontSize: 13, fontWeight: 600 }}>{shownName || session?.username}</div>
            <div className="muted" style={{ fontSize: 12 }}>
              {t(ROLE_LABEL[role] ?? role)} · {session?.username}
            </div>
          </div>
        </div>
      ),
      disabled: true,
    },
    { type: 'divider' },
    { key: 'profile', icon: <IdcardOutlined />, label: t('My profile') },
    { key: 'password', icon: <LockOutlined />, label: t('Change password') },
    { key: 'glossary', icon: <QuestionCircleOutlined />, label: t('Guide & glossary') },
    { key: 'logout', icon: <LogoutOutlined />, label: t('Sign out'), danger: true },
  ]

  return (
    <Layout className="app-shell">
      <Sider
        className="app-sider"
        theme="dark"
        width={236}
        collapsedWidth={80}
        collapsed={collapsed}
        trigger={null}
        collapsible
      >
        <div className="sider-brand">
          <div className="sider-logo">L</div>
          {!collapsed && (
            <div className="sider-brand-text">
              <span className="sider-brand-name">Lattice</span>
              <span className="sider-brand-sub">{t('Admin console')}</span>
            </div>
          )}
        </div>
        <div className="sider-menu">
          <Menu
            theme="dark"
            mode="inline"
            selectedKeys={[current.key]}
            items={menuItems}
            onClick={({ key }) => nav(key)}
          />
        </div>
        {!collapsed && (
          <div className="sider-footer">
            <div>{t('v0.1.0 · Admin')}</div>
            <div>{session?.username ? t('Signed in: {user}', { user: session.username }) : ''}</div>
          </div>
        )}
      </Sider>

      <Layout className="app-main">
        <Header className="app-header">
          <div className="header-left">
            <Button
              type="text"
              icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
              onClick={() => setCollapsed((v) => !v)}
              aria-label={collapsed ? t('Expand sidebar') : t('Collapse sidebar')}
            />
            <span className="header-crumb">
              {t(current.group)} / <strong>{t(current.label)}</strong>
            </span>
          </div>

          <div className="header-right">
            <Tooltip title={node.detail}>
              <span className={`node-pill ${node.tone}`}>
                <span className="dot" />
                {node.text}
              </span>
            </Tooltip>
            <Button type="text" icon={<QuestionCircleOutlined />} onClick={() => setGlossary(true)}>
              {t('Guide')}
            </Button>
            <LanguageSwitch size="small" />
            <Tooltip title={mode === 'dark' ? t('Switch to light mode') : t('Switch to dark mode')}>
              <Button
                type="text"
                aria-label={mode === 'dark' ? t('Switch to light mode') : t('Switch to dark mode')}
                data-testid="theme-toggle"
                icon={mode === 'dark' ? <SunOutlined /> : <MoonOutlined />}
                onClick={toggleTheme}
              />
            </Tooltip>
            <Dropdown
              menu={{
                items: userMenu,
                onClick: async ({ key }) => {
                  if (key === 'profile') void openProfile()
                  if (key === 'password') {
                    setPwdErr(null)
                    setPwdOpen(true)
                  }
                  if (key === 'glossary') setGlossary(true)
                  if (key === 'logout') {
                    await logout()
                    nav('/login')
                  }
                },
              }}
              trigger={['click']}
              placement="bottomRight"
            >
              <div className="user-chip">
                {avatarNode(28)}
                <span className="name">{shownName || session?.username}</span>
                <RoleTag role={role} style={{ marginInlineEnd: 0 }} />
              </div>
            </Dropdown>
          </div>
        </Header>

        <Content className="app-content">
          <div className="app-content-inner">
            <Outlet />
          </div>
        </Content>
      </Layout>

      {/* My profile (any signed-in role; PATCH /v1/users/me) */}
      <Modal
        open={profileOpen}
        title={t('My profile')}
        okText={t('Save')}
        cancelText={t('Cancel')}
        confirmLoading={profileSaving}
        onOk={submitProfile}
        onCancel={() => setProfileOpen(false)}
        destroyOnClose
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 14 }}
          message={t(
            'The username is the login credential and audit identifier and cannot be changed. Display name and avatar are shown to other users and take effect immediately after saving.',
          )}
        />
        {profileErr && <Alert type="error" showIcon message={profileErr} style={{ marginBottom: 12 }} />}
        <Form
          form={profileForm}
          layout="vertical"
          requiredMark={false}
          initialValues={profileInit}
          preserve={false}
        >
          <Form.Item label={t('Avatar')}>
            <Space align="start" size={16}>
              <UserAvatar
                name={profileInit.display_name || displayName}
                src={profileAvatar}
                size={64}
                style={{ fontSize: 24 }}
              />
              <Space direction="vertical" size={8}>
                <Space wrap size={8}>
                  <Button
                    size="small"
                    icon={<PictureOutlined />}
                    loading={avatarBusy}
                    onClick={() => avatarInputRef.current?.click()}
                  >
                    {t('Choose local image')}
                  </Button>
                  <Button
                    size="small"
                    icon={<DeleteOutlined />}
                    disabled={!profileAvatar}
                    onClick={() => {
                      setProfileAvatar(null)
                      setProfileAvatarTouched(true)
                    }}
                  >
                    {t('Clear avatar')}
                  </Button>
                </Space>
                <span className="muted" style={{ fontSize: 12 }}>
                  {t('Supports PNG, JPEG, WebP and GIF; automatically compressed to 256 KB. When unset, the name initial is shown.')}
                </span>
              </Space>
            </Space>
          </Form.Item>
          <Form.Item label={t('Use an image URL (optional)')}>
            <Space.Compact style={{ width: '100%' }}>
              <Input
                placeholder="https://example.com/avatar.png"
                value={avatarUrl}
                onChange={(e) => setAvatarUrl(e.target.value)}
                onPressEnter={applyAvatarUrl}
              />
              <Button onClick={applyAvatarUrl} disabled={!avatarUrl.trim()}>
                {t('Use URL')}
              </Button>
            </Space.Compact>
          </Form.Item>
          <Form.Item name="display_name" label={t('Display name')}>
            <Input placeholder={t('Leave empty to show the username only')} maxLength={64} allowClear />
          </Form.Item>
        </Form>
        <input
          ref={avatarInputRef}
          type="file"
          accept="image/png,image/jpeg,image/webp,image/gif"
          style={{ display: 'none' }}
          onChange={(e) => {
            void pickAvatarFile(e.target.files?.[0])
            // Allow picking the same file twice (clearing the value re-triggers onChange)
            e.target.value = ''
          }}
        />
        <div className="muted" style={{ fontSize: 12 }}>
          {t('Sign-in name: {user}', { user: session?.username ?? '' })}
        </div>
      </Modal>

      {/* Change password (self-service; keeps the current session, revokes other devices) */}
      <Modal
        open={pwdOpen}
        title={t('Change password')}
        okText={t('Update password')}
        cancelText={t('Cancel')}
        confirmLoading={pwdSaving}
        onOk={submitPassword}
        onCancel={() => setPwdOpen(false)}
        destroyOnClose
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 14 }}
          message={t(
            'After a successful change, sessions on other devices are signed out (they must sign in again); this browser stays signed in.',
          )}
        />
        {pwdErr && <Alert type="error" showIcon message={pwdErr} style={{ marginBottom: 12 }} />}
        <Form form={pwdForm} layout="vertical" requiredMark={false} preserve={false}>
          <Form.Item
            name="old_password"
            label={t('Current password')}
            rules={[{ required: true, message: t('Enter your current password') }]}
          >
            <Input.Password autoComplete="current-password" placeholder={t('Enter your current password')} />
          </Form.Item>
          <Form.Item
            name="new_password"
            label={t('New password')}
            rules={[
              { required: true, message: t('Enter a new password') },
              { min: 8, max: 128, message: t('Must be 8–128 characters') },
            ]}
          >
            <Input.Password
              autoComplete="new-password"
              placeholder={t('At least 8 characters and different from the current password')}
            />
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
            <Input.Password autoComplete="new-password" placeholder={t('Enter the new password again')} />
          </Form.Item>
        </Form>
      </Modal>

      <GlossaryDrawer open={glossary} onClose={() => setGlossary(false)} />
    </Layout>
  )
}
