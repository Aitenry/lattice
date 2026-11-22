import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  App as AntApp,
  Avatar,
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Empty,
  Form,
  Input,
  Modal,
  Pagination,
  Popconfirm,
  Progress,
  Row,
  Segmented,
  Select,
  Space,
  Spin,
  Table,
  Tag,
  Tooltip,
  Typography,
  Upload,
} from 'antd'
import {
  AppstoreOutlined,
  ClockCircleOutlined,
  CloudUploadOutlined,
  DeleteOutlined,
  DownloadOutlined,
  HddOutlined,
  HistoryOutlined,
  InboxOutlined,
  ReloadOutlined,
  SearchOutlined,
  TeamOutlined,
  UserOutlined,
} from '@ant-design/icons'
import { ApiError } from '@/api/http'
import {
  deleteHubPlugin,
  deleteHubVersion,
  downloadHubSource,
  downloadHubVersion,
  getHubPlugin,
  getHubStats,
  listHubPlugins,
  publishHubPlugin,
  uploadHubBlob,
  uploadHubSource,
} from '@/api/endpoints'
import type {
  HubOwner,
  HubPluginDetail,
  HubPluginRow,
  HubPublishReq,
  HubSort,
  HubStats,
  HubVersionRow,
} from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { HelpTip } from '@/components/HelpTip'
import { JsonPeek } from '@/components/JsonPeek'
import { StatCard } from '@/components/StatCard'
import { useI18n, type Translate } from '@/i18n'
import { errText } from '@/lib/errors'
import { fmtBytes, fmtRelative, fmtTime } from '@/lib/format'
import { HUB_CATEGORY, hubCategoryOptions, pick } from '@/lib/labels'

/**
 * Plugin hub (⑤ §12, the user-facing `/v1/hub`).
 *
 * What it distributes is **third-party plugins for the desktop client** (zip packages the
 * client installs; the platform never executes them). That is a completely separate set of
 * tables and state machines from the server-side format plugins (§8.4) on the "Plugins"
 * page — the two are deliberately kept apart here.
 *
 * Publishing takes two steps (⑤ §12.3/§12.4): first POST the metadata to obtain an upload
 * target, then PUT the raw bytes. The console never parses the zip; it only hashes the file
 * and builds the manifest snapshot from the form fields. Consistency between the package's
 * `plugin.json` and the manifest is enforced by install-time checks on the client (② §4.9
 * trust model).
 *
 * v2 (contract §1): each version may also carry an optional **source zip**, using the same
 * "declare first, then PUT" flow with an extra `source_upload` returned by the server. The
 * byte limits are 20MiB for the package and 50MiB for the source archive.
 */

/** Fixed catalogue page size (same as the list pages, so the height does not jump when paging) */
const PAGE_SIZE = 12
/** Design §17.16: plugin package limit 20MiB */
const MAX_PACKAGE_BYTES = 20 * 1024 * 1024
/** v2 contract §1.1 / §17.16: per-version source archive limit 50MiB */
const MAX_SOURCE_BYTES = 50 * 1024 * 1024
/** Design §17.16: readme ≤16KiB (counted in bytes) */
const MAX_README_BYTES = 16 * 1024

const SORT_OPTIONS = [
  { label: 'Recently updated', value: 'recent' as const },
  { label: 'Most downloaded', value: 'popular' as const },
  { label: 'By name', value: 'name' as const },
]

/** Design §17.16 values: plugin_id / semver / asset_name regexes */
const PLUGIN_ID_RE = /^[a-z0-9][a-z0-9._-]{1,63}$/
const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]{1,32})?$/
const ASSET_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip$/

interface UploadFormValues {
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
}

type UploadPhase = 'idle' | 'hashing' | 'meta' | 'upload' | 'source' | 'done'

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function byteLength(s: string | undefined | null): number {
  if (!s) return 0
  return new TextEncoder().encode(s).length
}

/** Whether WebCrypto is available (on insecure origins such as <http://intranet> `subtle` is undefined) */
function hasWebCrypto(): boolean {
  return typeof crypto !== 'undefined' && typeof crypto.subtle?.digest === 'function'
}

/** Browser-side SHA-256 (checksum before upload; throws a readable error on insecure origins) */
async function sha256Hex(data: ArrayBuffer, t: Translate): Promise<string> {
  if (!hasWebCrypto()) {
    throw new Error(
      t('This page is not in a secure context (HTTPS or localhost required), so the browser cannot compute SHA-256 and uploads are unavailable'),
    )
  }
  const digest = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')
}

/** Guess the plugin ID from the package filename (task-planner-1.4.2.zip → task-planner); empty when unsure */
function guessPluginId(filename: string): string {
  const base = filename
    .replace(/\.zip$/i, '')
    .replace(/[-_.]v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/, '')
  const id = base
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^[^a-z0-9]+/, '')
    .slice(0, 64)
  return PLUGIN_ID_RE.test(id) ? id : ''
}

function ownerLabel(owner: HubOwner | undefined, t: Translate): string {
  if (!owner) return t('Unknown publisher')
  return owner.display_name?.trim() || owner.username || t('Unknown publisher')
}

/** Save via a blob + a[download] (window.open cannot carry the Authorization header) */
function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** Publish failure reason → one actionable hint (error semantics from ⑤ §12.3/§12.4) */
const HUB_REASON_HINT: Record<string, string> = {
  version_published:
    'This version was already published with different package content. Published versions cannot be overwritten; bump the version number (for example from 1.0.0 to 1.0.1) and upload again.',
  manifest_mismatch:
    'The plugin ID / version in the manifest snapshot does not match the submission: check whether the plugin ID and version were swapped or contain spaces.',
  package:
    'Package structure check failed: it must be a zip file with plugin.json at the root (or inside a single top-level directory).',
  checksum:
    'The package content does not match the checksum computed by the browser: the file may have changed after selection, so choose it again.',
  plugin_id:
    'Invalid plugin ID: use lowercase letters, digits, dot, underscore or hyphen only, 2–64 characters, starting with a letter or digit.',
  version: 'Invalid version: use a value like 1.4.2, optionally with a suffix such as -beta.1.',
  asset_name:
    'Invalid package filename: it must start with a letter or digit, end with .zip, and contain no path separators.',
  name: 'Invalid name: it cannot be empty and must be at most 64 characters.',
  description: 'Description too long: at most 500 characters.',
  readme: 'Plugin description too long: at most 16 KiB (about 5,400 Chinese characters).',
  icon: 'Icon URL too long: at most 512 characters.',
  tags: 'Too many or too-long tags: at most 8 tags of 24 characters each.',
  changelog: 'Changelog too long: at most 2000 characters.',
  size: 'Invalid package size: the limit is 20 MiB.',
  sha256: 'Invalid checksum format: 64 lowercase hexadecimal characters are required.',
  not_owner:
    'This plugin ID is already published by someone else: only its publisher or an admin can add versions to it. Choose a different plugin ID.',
  hub_publish: 'Too many publish operations: at most 10 per hour. Try again later.',
  hub_upload: 'Too many package uploads: at most 60 per hour. Try again later.',
  hub_source: 'Too many source archive uploads: at most 60 per hour. Try again later.',
  source_asset_name:
    'Invalid source archive filename: it must start with a letter or digit, end with .zip, and contain no path separators.',
  source_size: 'Invalid source archive size: the limit is 50 MiB.',
  source_sha256: 'Invalid source archive checksum format: 64 lowercase hexadecimal characters are required.',
  source_not_declared:
    'This version was published without a source archive: sources must be declared in the publish metadata (POST) and cannot be added to an undeclared version afterwards.',
  source_published:
    'This version already has a different source archive. Sources cannot be overwritten; publish a new version to change them.',
  source_missing: 'This version has no source archive.',
}

function hubSubmitError(e: unknown, t: Translate): string {
  const base = errText(e)
  if (!(e instanceof ApiError)) return base
  const statusHint =
    e.status === 409
      ? t('Version already exists: the same version was published before with different content. Bump the version number and try again.')
      : e.status === 422
        ? t('Validation failed: the submitted metadata or package did not pass platform checks. Fix the reason below and try again.')
        : e.status === 413
          ? t('The upload exceeds the platform limits (package 20 MiB / source archive 50 MiB). Trim it and upload again.')
          : e.status === 429
            ? t('Too many requests: the platform is rate limiting you. Try again later.')
            : e.status === 403
              ? t('Not permitted: only the publisher or an admin can add new versions to an existing plugin.')
              : ''
  const reasonHint = e.reason ? HUB_REASON_HINT[e.reason] : undefined
  const hint = reasonHint ? t(reasonHint) : statusHint
  return hint ? `${hint}\n${t('Technical details: {detail}', { detail: base })}` : base
}

// ---------------------------------------------------------------------------
// Small components
// ---------------------------------------------------------------------------

/** Plugin icon: render the URL when it is a directly usable image, otherwise fall back to the initial (remixicon names are resolved by the client, the console has no icon font) */
function PluginIcon({ icon, name, size = 42 }: { icon: string | null; name: string; size?: number }) {
  const isImage = Boolean(icon && /^(https?:\/\/|data:image\/)/i.test(icon))
  if (isImage) {
    return <Avatar shape="square" size={size} src={icon} style={{ flex: `0 0 ${size}px`, borderRadius: 10 }} />
  }
  return (
    <Avatar
      shape="square"
      size={size}
      style={{
        flex: `0 0 ${size}px`,
        borderRadius: 10,
        fontSize: Math.round(size / 2.4),
        fontWeight: 600,
      }}
    >
      {(name || '?').trim().slice(0, 1).toUpperCase()}
    </Avatar>
  )
}

function PluginCard({ item, onOpen }: { item: HubPluginRow; onOpen: (pluginId: string) => void }) {
  const { t } = useI18n()
  const shownTags = item.tags.slice(0, 4)
  const restTags = item.tags.length - shownTags.length
  return (
    <Card
      hoverable
      size="small"
      role="button"
      tabIndex={0}
      onClick={() => onOpen(item.plugin_id)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onOpen(item.plugin_id)
        }
      }}
      style={{ height: '100%' }}
      styles={{
        body: {
          padding: 16,
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          gap: 10,
        },
      }}
    >
      <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
        <PluginIcon icon={item.icon} name={item.name} />
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
            <Typography.Text strong ellipsis style={{ fontSize: 14, flex: '0 1 auto', minWidth: 0 }}>
              {item.name}
            </Typography.Text>
            <Tag color="blue" style={{ marginInlineEnd: 0, flex: '0 0 auto' }}>
              {item.latest_version ?? '—'}
            </Tag>
          </div>
          <div className="cell-sub" title={item.plugin_id}>
            {item.plugin_id}
          </div>
        </div>
      </div>

      <Typography.Paragraph
        type="secondary"
        ellipsis={{ rows: 2 }}
        style={{ margin: 0, fontSize: 13, minHeight: 40 }}
      >
        {item.description || t('No description from the publisher')}
      </Typography.Paragraph>

      <div style={{ minHeight: 24 }}>
        {shownTags.length ? (
          <Space size={[4, 4]} wrap>
            {shownTags.map((tag) => (
              <Tag key={tag} style={{ marginInlineEnd: 0 }}>
                {tag}
              </Tag>
            ))}
            {restTags > 0 && <Tag style={{ marginInlineEnd: 0 }}>+{restTags}</Tag>}
          </Space>
        ) : (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t('No tags')}
          </Typography.Text>
        )}
      </div>

      <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: 6 }}>
        <Space size={12} wrap>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            <DownloadOutlined /> {t('{count} downloads', { count: item.downloads.toLocaleString() })}
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            <ClockCircleOutlined /> {fmtRelative(item.updated_at)}
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            <UserOutlined /> {ownerLabel(item.owner, t)}
          </Typography.Text>
        </Space>
        {(item.installed || item.update_available) && (
          <Space size={4} wrap>
            {item.installed && (
              <Tag color="green" style={{ marginInlineEnd: 0 }}>
                {t('Installed')}
                {item.installed_version ? ` v${item.installed_version}` : ''}
              </Tag>
            )}
            {item.installed && item.install_enabled === false && (
              <Tag style={{ marginInlineEnd: 0 }}>{t('Disabled')}</Tag>
            )}
            {item.update_available && (
              <Tag color="orange" style={{ marginInlineEnd: 0 }}>
                {t('Update to {version}', { version: item.latest_version ?? '' })}
              </Tag>
            )}
          </Space>
        )}
      </div>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function PluginHubPage() {
  const { message } = AntApp.useApp()
  const { session, role } = useAuth()
  const { t } = useI18n()

  // Catalogue
  const [stats, setStats] = useState<HubStats | null>(null)
  const [items, setItems] = useState<HubPluginRow[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [q, setQ] = useState('')
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState<string | undefined>(undefined)
  const [sort, setSort] = useState<HubSort>('recent')
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)

  // Detail drawer
  const [detailId, setDetailId] = useState<string | null>(null)
  const [detail, setDetail] = useState<HubPluginDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [downloading, setDownloading] = useState<string | null>(null)
  const [downloadingSource, setDownloadingSource] = useState<string | null>(null)

  // Upload wizard
  const [uploadOpen, setUploadOpen] = useState(false)
  const [uploadForm] = Form.useForm<UploadFormValues>()
  const [upFile, setUpFile] = useState<File | null>(null)
  const [upSize, setUpSize] = useState(0)
  const [upSha, setUpSha] = useState<string | null>(null)
  const [hashBusy, setHashBusy] = useState(false)
  // Source zip (optional): hashed and submitted independently of the package
  const [srcFile, setSrcFile] = useState<File | null>(null)
  const [srcSize, setSrcSize] = useState(0)
  const [srcSha, setSrcSha] = useState<string | null>(null)
  const [srcHashBusy, setSrcHashBusy] = useState(false)
  const [busy, setBusy] = useState(false)
  const [phase, setPhase] = useState<UploadPhase>('idle')
  const [percent, setPercent] = useState<number | null>(null)
  const [upErr, setUpErr] = useState<string | null>(null)

  const loadStats = useCallback(async () => {
    try {
      setStats(await getHubStats())
    } catch (e) {
      setErr(errText(e))
    }
  }, [])

  const loadList = useCallback(async () => {
    setLoading(true)
    setErr(null)
    try {
      const r = await listHubPlugins({
        q: search || undefined,
        category,
        sort,
        page,
        page_size: PAGE_SIZE,
      })
      setItems(r.items ?? [])
      setTotal(r.total ?? 0)
    } catch (e) {
      setErr(errText(e))
    } finally {
      setLoading(false)
    }
  }, [search, category, sort, page])

  useEffect(() => {
    void loadStats()
  }, [loadStats])

  useEffect(() => {
    void loadList()
  }, [loadList])

  // Debounce the search box: fire the request 300ms after typing stops, so each keystroke does not hit the API
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setSearch(q.trim())
      setPage(1)
    }, 300)
    return () => window.clearTimeout(timer)
  }, [q])

  // Step back a page after deleting the last row of the current page instead of staying on an empty page
  useEffect(() => {
    if (!loading && items.length === 0 && page > 1) {
      setPage((p) => Math.max(1, p - 1))
    }
  }, [loading, items.length, page])

  const refreshAll = useCallback(() => {
    void loadList()
    void loadStats()
  }, [loadList, loadStats])

  // ---------- Detail ----------

  const openDetail = useCallback(
    async (pluginId: string) => {
      setDetailId(pluginId)
      setDetail(null)
      setDetailLoading(true)
      try {
        setDetail(await getHubPlugin(pluginId))
      } catch (e) {
        message.error(errText(e))
        setDetailId(null)
      } finally {
        setDetailLoading(false)
      }
    },
    [message],
  )

  const closeDetail = useCallback(() => {
    setDetailId(null)
    setDetail(null)
    setDownloading(null)
  }, [])

  async function handleDownload(row: HubVersionRow) {
    if (!detail) return
    const filename = row.asset_name || `${detail.plugin_id}-${row.version}.zip`
    setDownloading(row.version)
    try {
      const blob = await downloadHubVersion(detail.plugin_id, row.version)
      let checked = false
      try {
        if ((await sha256Hex(await blob.arrayBuffer(), t)) !== row.sha256) {
          message.error(
            t('The download does not match the checksum recorded by the platform; the file may be corrupted, so saving was cancelled'),
          )
          return
        }
        checked = true
      } catch {
        // No WebCrypto on insecure origins: save anyway, but skip the integrity check
      }
      saveBlob(blob, filename)
      message.success(
        checked
          ? t('Saving {filename} (integrity check passed)', { filename })
          : t('Saving {filename} (integrity check unavailable in this environment)', { filename }),
      )
    } catch (e) {
      if (e instanceof ApiError && e.code === 'NETWORK') {
        message.error(
          t('Download failed: the browser cannot read the package. If the console and the object storage are on different origins, allow cross-origin access'),
        )
      } else {
        message.error(errText(e))
      }
    } finally {
      setDownloading(null)
    }
  }

  async function handleDownloadSource(row: HubVersionRow) {
    if (!detail) return
    const filename = row.source_asset_name || `${detail.plugin_id}-${row.version}-src.zip`
    setDownloadingSource(row.version)
    try {
      const blob = await downloadHubSource(detail.plugin_id, row.version)
      let checked = false
      try {
        if (row.source_sha256 && (await sha256Hex(await blob.arrayBuffer(), t)) !== row.source_sha256) {
          message.error(
            t('The downloaded source archive does not match the checksum recorded by the platform; the file may be corrupted, so saving was cancelled'),
          )
          return
        }
        checked = true
      } catch {
        // No WebCrypto on insecure origins: save anyway, but skip the integrity check
      }
      saveBlob(blob, filename)
      message.success(
        checked
          ? t('Saving source archive {filename} (integrity check passed)', { filename })
          : t('Saving source archive {filename} (integrity check unavailable in this environment)', { filename }),
      )
    } catch (e) {
      if (e instanceof ApiError && e.code === 'NETWORK') {
        message.error(
          t('Download failed: the browser cannot read the source archive. If the console and the object storage are on different origins, allow cross-origin access'),
        )
      } else if (e instanceof ApiError && e.reason === 'source_missing') {
        message.warning(t('This version has no source archive'))
      } else {
        message.error(errText(e))
      }
    } finally {
      setDownloadingSource(null)
    }
  }

  async function handleDeleteVersion(version: string) {
    if (!detail) return
    try {
      await deleteHubVersion(detail.plugin_id, version)
      message.success(t('Version {version} has been removed', { version }))
      try {
        setDetail(await getHubPlugin(detail.plugin_id))
      } catch {
        closeDetail()
      }
      refreshAll()
    } catch (e) {
      message.error(errText(e))
    }
  }

  async function handleDeletePlugin() {
    if (!detail) return
    try {
      await deleteHubPlugin(detail.plugin_id)
      message.success(t('Plugin removed; it no longer appears in the catalogue'))
      closeDetail()
      refreshAll()
    } catch (e) {
      message.error(errText(e))
    }
  }

  const canManageDetail =
    detail != null &&
    (role === 'admin' || (session?.userId != null && detail.owner.id === session.userId))

  // ---------- Upload wizard ----------

  function openUpload() {
    setUpFile(null)
    setUpSize(0)
    setUpSha(null)
    setHashBusy(false)
    setSrcFile(null)
    setSrcSize(0)
    setSrcSha(null)
    setSrcHashBusy(false)
    setBusy(false)
    setPhase('idle')
    setPercent(null)
    setUpErr(null)
    uploadForm.resetFields()
    setUploadOpen(true)
  }

  async function pickFile(file: File) {
    setUpErr(null)
    setPhase('idle')
    setPercent(null)
    setUpFile(file)
    setUpSize(file.size)
    setUpSha(null)

    if (!file.name.toLowerCase().endsWith('.zip')) {
      setUpErr(t('Only .zip plugin packages are supported; choose another file'))
      return
    }
    if (file.size <= 0) {
      setUpErr(t('This file is empty; choose another file'))
      return
    }
    if (file.size > MAX_PACKAGE_BYTES) {
      setUpErr(t('The package is {size}, over the 20 MiB limit; trim it and upload again', { size: fmtBytes(file.size) }))
      return
    }

    setHashBusy(true)
    setPhase('hashing')
    try {
      setUpSha(await sha256Hex(await file.arrayBuffer(), t))
      setPhase('idle')
      // Prefill the filename and plugin ID only when the user has not typed them, never overwrite input
      const current = uploadForm.getFieldsValue(['asset_name', 'plugin_id'])
      if (!current.asset_name) uploadForm.setFieldValue('asset_name', file.name)
      const guessed = guessPluginId(file.name)
      if (!current.plugin_id && guessed) uploadForm.setFieldValue('plugin_id', guessed)
    } catch (e) {
      setUpErr(e instanceof Error ? e.message : String(e))
      setPhase('idle')
    } finally {
      setHashBusy(false)
    }
  }

  /** Pick the source zip (optional): only hash it, no form fields; same rules as the package but a 50MiB limit */
  async function pickSourceFile(file: File) {
    setUpErr(null)
    setSrcFile(file)
    setSrcSize(file.size)
    setSrcSha(null)

    if (!file.name.toLowerCase().endsWith('.zip')) {
      setUpErr(t('Source archives must be .zip files; choose another file'))
      return
    }
    if (file.size <= 0) {
      setUpErr(t('This source file is empty; choose another file'))
      return
    }
    if (file.size > MAX_SOURCE_BYTES) {
      setUpErr(
        t('The source archive is {size}, over the 50 MiB limit; trim it and upload again', { size: fmtBytes(file.size) }),
      )
      setSrcFile(null)
      setSrcSize(0)
      return
    }

    setSrcHashBusy(true)
    try {
      setSrcSha(await sha256Hex(await file.arrayBuffer(), t))
    } catch (e) {
      setUpErr(e instanceof Error ? e.message : String(e))
      setSrcFile(null)
      setSrcSize(0)
    } finally {
      setSrcHashBusy(false)
    }
  }

  function finishUpload() {
    setUpFile(null)
    setUpSize(0)
    setUpSha(null)
    setSrcFile(null)
    setSrcSize(0)
    setSrcSha(null)
    setPercent(null)
    setPhase('idle')
    setUpErr(null)
    uploadForm.resetFields()
    setUploadOpen(false)
    refreshAll()
  }

  async function submitUpload() {
    if (busy) return
    if (!upFile) {
      setUpErr(t('Choose the plugin package (.zip) to upload first'))
      return
    }
    if (!upSha) {
      setUpErr(
        hashBusy
          ? t('Still computing the checksum; wait a moment and try again')
          : t('The checksum is not ready yet; choose the file again'),
      )
      return
    }
    if (srcFile && !srcSha) {
      setUpErr(
        srcHashBusy
          ? t('Still computing the source archive checksum; wait a moment and try again')
          : t('The source archive checksum is not ready yet; choose the source archive again'),
      )
      return
    }
    if (srcFile && !ASSET_NAME_RE.test(srcFile.name)) {
      setUpErr(
        t('Invalid source archive filename: it must start with a letter or digit, end with .zip, and contain no path separators'),
      )
      return
    }
    let values: UploadFormValues
    try {
      values = await uploadForm.validateFields()
    } catch {
      return
    }
    const pkgFile = upFile
    const pkgSize = upSize
    const pkgSha = upSha
    const sourceFile = srcFile
    const sourceSize = srcSize
    const sourceSha = srcSha

    setBusy(true)
    setUpErr(null)
    setPercent(null)
    let step: 'meta' | 'upload' | 'source' = 'meta'
    try {
      const pluginId = values.plugin_id.trim()
      const version = values.version.trim()
      const name = values.name.trim()
      const body: HubPublishReq = {
        plugin_id: pluginId,
        version,
        name,
        description: (values.description ?? '').trim(),
        readme: values.readme?.trim() ? values.readme : undefined,
        icon: values.icon?.trim() || undefined,
        category: values.category ?? 'other',
        tags: (values.tags ?? []).map((tag) => tag.trim()).filter(Boolean),
        changelog: (values.changelog ?? '').trim(),
        asset_name: values.asset_name.trim(),
        size: pkgSize,
        sha256: pkgSha,
        // The platform only checks that id/version match the request; the client verifies plugin.json at install time
        manifest: { id: pluginId, name, version },
        // v2 contract §1.2: sources must be declared in the metadata POST; omitted means this version has none
        source: sourceFile
          ? { asset_name: sourceFile.name, size: sourceSize, sha256: sourceSha ?? '' }
          : undefined,
      }

      step = 'meta'
      setPhase('meta')
      const ack = await publishHubPlugin(body)
      const needPackage = ack.upload != null
      // At least one package upload succeeded, so this counts as published; a source failure only offers a retry (see catch)
      if (needPackage) {
        step = 'upload'
        setPhase('upload')
        setPercent(0)
        await uploadHubBlob(ack.upload!, pkgFile, (p) => setPercent(p))
      }
      if (ack.source_upload) {
        if (sourceFile) {
          step = 'source'
          setPhase('source')
          setPercent(0)
          await uploadHubSource(ack.source_upload, sourceFile, (p) => setPercent(p))
        } else {
          message.warning(
            t('The server returned a source upload target, but no source file was selected this time; skipped'),
          )
        }
      }
      setPhase('done')
      if (!needPackage && !ack.source_upload) {
        // Retry with the same version and sha: the server returns 200 and no body upload is needed
        message.success(t('This version was already published with identical content; no need to upload again'))
      } else {
        message.success(t('Published {name} {version}; other users can download it now', { name, version }))
      }
      finishUpload()
    } catch (e) {
      setPhase('idle')
      setPercent(null)
      const base = hubSubmitError(e, t)
      setUpErr(
        step === 'source'
          ? `${base}\n${t('The package was published successfully; only the source archive upload failed. Click "Publish" again with the same version: unchanged package content is not written twice, and the source upload is retried.')}`
          : base,
      )
      message.error(errText(e))
    } finally {
      setBusy(false)
    }
  }

  // ---------- Render ----------

  const phaseText =
    phase === 'hashing'
      ? t('Computing the SHA-256 checksum in the browser…')
      : phase === 'meta'
        ? t('Step 1: submitting the plugin metadata…')
        : phase === 'upload'
          ? t('Step 2: uploading the package {percent}% (keep this window open)', { percent: percent ?? 0 })
          : phase === 'source'
            ? t('Step 3: uploading the source archive {percent}% (keep this window open)', { percent: percent ?? 0 })
            : phase === 'done'
              ? t('Publish complete')
              : ''

  const progressPercent =
    phase === 'meta'
      ? 10
      : phase === 'upload'
        ? 20 + Math.round((percent ?? 0) * 0.45)
        : phase === 'source'
          ? 66 + Math.round((percent ?? 0) * 0.3)
          : phase === 'done'
            ? 100
            : 0

  return (
    <div className="page-fill">
      {/* Filter row: page-level actions always sit on the far right (hard README constraint) */}
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Input
          allowClear
          prefix={<SearchOutlined />}
          placeholder={t('Search plugin name, description, ID or tag')}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ width: 280 }}
        />
        <Select
          allowClear
          placeholder={t('All categories')}
          value={category}
          onChange={(v) => {
            setCategory(v)
            setPage(1)
          }}
          options={hubCategoryOptions(t)}
          style={{ width: 140 }}
        />
        <Segmented
          options={
            SORT_OPTIONS.map((option) => ({
              label: t(option.label),
              value: option.value,
            })) as { label: string; value: string }[]
          }
          value={sort}
          onChange={(v) => {
            setSort(v as HubSort)
            setPage(1)
          }}
        />
        <div className="toolbar-right">
          <Button icon={<ReloadOutlined />} loading={loading} onClick={refreshAll}>
            {t('Refresh')}
          </Button>
          <Button type="primary" icon={<CloudUploadOutlined />} onClick={openUpload}>
            {t('Upload plugin')}
          </Button>
        </div>
      </div>

      {err && <Alert type="error" showIcon message={t('Failed to load')} description={err} />}

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            label={t('Plugins')}
            value={stats ? stats.plugins.toLocaleString() : '—'}
            hint={t('Plugins visible in the catalogue (published with at least one downloadable version)')}
            icon={<AppstoreOutlined />}
            tone="blue"
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            label={t('Versions')}
            value={stats ? stats.versions.toLocaleString() : '—'}
            hint={t('Total published versions across all plugins (old versions can be removed one by one)')}
            icon={<HistoryOutlined />}
            tone="violet"
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            label={t('Installs')}
            value={stats ? stats.installs.toLocaleString() : '—'}
            hint={t('Install records across all users; removing a plugin does not delete them')}
            icon={<TeamOutlined />}
            tone="green"
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            label={t('Storage used')}
            value={stats ? fmtBytes(stats.storage_bytes) : '—'}
            hint={t('Combined size of every downloadable package (a reference for capacity planning)')}
            icon={<HddOutlined />}
            tone="slate"
          />
        </Col>
      </Row>

      <Card className="list-card">
        <div className="hub-scroll">
          <Spin spinning={loading}>
            {items.length > 0 ? (
              <div className="hub-grid">
                {items.map((item) => (
                  <PluginCard key={item.plugin_id} item={item} onOpen={(id) => void openDetail(id)} />
                ))}
              </div>
            ) : (
              <div style={{ minHeight: 240, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description={
                    search || category
                      ? t('No plugins match; try another keyword or category')
                      : t('The plugin hub is empty; click "Upload plugin" in the top right to publish the first one')
                  }
                />
              </div>
            )}
          </Spin>
        </div>
        {total > 0 && (
          <div className="hub-pager">
            <Pagination
              size="small"
              current={page}
              pageSize={PAGE_SIZE}
              total={total}
              showSizeChanger={false}
              showTotal={(count) => t('{count} plugins', { count })}
              onChange={(p) => setPage(p)}
            />
          </div>
        )}
      </Card>

      {/* Detail drawer */}
      <Drawer
        open={detailId != null}
        onClose={closeDetail}
        width={760}
        destroyOnClose
        title={detail ? detail.name : t('Plugin details')}
        extra={
          canManageDetail ? (
            <Popconfirm
              title={t('Remove this plugin?')}
              description={t('Once removed it disappears from the catalogue and other users cannot download it. Install records are kept and come back if the same plugin is published again. Packages are kept for 30 days before automatic cleanup.')}
              okText={t('Remove')}
              okButtonProps={{ danger: true }}
              cancelText={t('Cancel')}
              onConfirm={() => void handleDeletePlugin()}
            >
              <Button danger size="small" icon={<DeleteOutlined />}>
                {t('Remove plugin')}
              </Button>
            </Popconfirm>
          ) : null
        }
      >
        {detailLoading ? (
          <div style={{ padding: '80px 0', textAlign: 'center' }}>
            <Spin />
          </div>
        ) : detail ? (
          <div className="stack">
            <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
              <PluginIcon icon={detail.icon} name={detail.name} size={54} />
              <div style={{ minWidth: 0, flex: 1 }}>
                <Space size={8} wrap>
                  <Typography.Title level={5} style={{ margin: 0 }}>
                    {detail.name}
                  </Typography.Title>
                  <Tag color="blue" style={{ marginInlineEnd: 0 }}>
                    {detail.latest_version ?? t('No downloadable version')}
                  </Tag>
                  <Tag style={{ marginInlineEnd: 0 }}>
                    {t(pick(HUB_CATEGORY, detail.category, detail.category))}
                  </Tag>
                </Space>
                <div className="cell-sub" style={{ marginTop: 4 }}>
                  {detail.plugin_id}
                </div>
                <Typography.Text type="secondary" style={{ fontSize: 13 }}>
                  {detail.description || t('No description from the publisher')}
                </Typography.Text>
              </div>
            </div>

            {detail.tags.length > 0 && (
              <Space size={[4, 4]} wrap>
                {detail.tags.map((tag) => (
                  <Tag key={tag}>{tag}</Tag>
                ))}
              </Space>
            )}

            <Descriptions size="small" column={2} bordered>
              <Descriptions.Item label={t('Publisher')}>{ownerLabel(detail.owner, t)}</Descriptions.Item>
              <Descriptions.Item label={t('Total downloads')}>
                {t('{count} downloads', { count: detail.downloads.toLocaleString() })}
              </Descriptions.Item>
              <Descriptions.Item label={t('First published')}>{fmtTime(detail.created_at)}</Descriptions.Item>
              <Descriptions.Item label={t('Last updated')}>{fmtTime(detail.updated_at)}</Descriptions.Item>
            </Descriptions>

            {detail.my_install && (
              <div className="soft-panel">
                <b>{t('Your install:')}</b>{' '}
                {t('Version {version} · {state}', {
                  version: detail.my_install.version,
                  state: detail.my_install.enabled ? t('Enabled') : t('Disabled'),
                })}
                {detail.my_install.data_rev > 0
                  ? ` · ${t('plugin data revision {rev} (updated {time})', {
                      rev: detail.my_install.data_rev,
                      time: fmtTime(detail.my_install.data_updated_at),
                    })}`
                  : ''}
              </div>
            )}

            <Card
              size="small"
              title={t('Plugin description')}
              extra={
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {t('Raw text from the publisher; the console does not render rich text')}
                </Typography.Text>
              }
            >
              {detail.readme ? (
                <div style={{ whiteSpace: 'pre-wrap', fontSize: 13, lineHeight: 1.8 }}>{detail.readme}</div>
              ) : (
                <Typography.Text type="secondary">{t('The publisher did not write a plugin description')}</Typography.Text>
              )}
            </Card>

            <Card
              size="small"
              title={t('Versions')}
              extra={
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {t('{count} downloadable versions', { count: detail.versions.length })}
                </Typography.Text>
              }
            >
              <Table<HubVersionRow>
                size="small"
                rowKey="version"
                className="drawer-table"
                dataSource={detail.versions}
                pagination={false}
                locale={{ emptyText: t('This plugin has no downloadable version yet') }}
                columns={[
                  {
                    title: t('Version'),
                    dataIndex: 'version',
                    width: 120,
                    render: (v: string, row) => (
                      <Tooltip title={row.changelog || t('No changelog provided')}>
                        <Tag color={row.version === detail.latest_version ? 'blue' : 'default'}>{v}</Tag>
                      </Tooltip>
                    ),
                  },
                  {
                    title: t('Size'),
                    dataIndex: 'size',
                    width: 90,
                    render: (v: number) => fmtBytes(v),
                  },
                  {
                    title: (
                      <Space size={2}>
                        {t('Checksum')}
                        <HelpTip
                          title={t('First 12 characters of the package SHA-256. After download the client verifies the full value and refuses to install a package that does not match.')}
                        />
                      </Space>
                    ),
                    dataIndex: 'sha256',
                    width: 130,
                    render: (v: string) => (
                      <Tooltip title={v}>
                        <span className="table-id">{v.slice(0, 12)}</span>
                      </Tooltip>
                    ),
                  },
                  {
                    title: t('Downloads'),
                    dataIndex: 'downloads',
                    width: 76,
                    render: (v: number) => v.toLocaleString(),
                  },
                  {
                    title: t('Published'),
                    dataIndex: 'published_at',
                    width: 124,
                    render: (v: string | null) =>
                      v ? (
                        <Tooltip title={fmtTime(v)}>
                          <span>{fmtRelative(v)}</span>
                        </Tooltip>
                      ) : (
                        '—'
                      ),
                  },
                  {
                    title: (
                      <Space size={2}>
                        {t('Source')}
                        <HelpTip
                          title={t('Each version can optionally carry a source zip (≤50 MiB), which the client downloads together with an install or update. Sources can only be declared at publish time and cannot be overwritten afterwards.')}
                        />
                      </Space>
                    ),
                    dataIndex: 'has_source',
                    width: 112,
                    render: (has: boolean, row) =>
                      has ? (
                        <Space size={0}>
                          <Tag color="green" style={{ marginInlineEnd: 0 }}>
                            {t('Yes')}
                          </Tag>
                          <Button
                            size="small"
                            type="link"
                            icon={<DownloadOutlined />}
                            loading={downloadingSource === row.version}
                            onClick={() => void handleDownloadSource(row)}
                          >
                            {t('Source')}
                          </Button>
                        </Space>
                      ) : (
                        <Typography.Text type="secondary">{t('No')}</Typography.Text>
                      ),
                  },
                  {
                    title: t('Actions'),
                    width: canManageDetail ? 168 : 96,
                    render: (_, row) => (
                      <Space size={0}>
                        <Button
                          size="small"
                          type="link"
                          icon={<DownloadOutlined />}
                          loading={downloading === row.version}
                          onClick={() => void handleDownload(row)}
                        >
                          {t('Download')}
                        </Button>
                        {canManageDetail && (
                          <Popconfirm
                            title={t('Delete this version?')}
                            description={t('The version disappears from the catalogue and the latest version falls back to the highest remaining one. The package is kept for 30 days before automatic cleanup. To change the content, publish a new version.')}
                            okText={t('Delete')}
                            okButtonProps={{ danger: true }}
                            cancelText={t('Cancel')}
                            onConfirm={() => void handleDeleteVersion(row.version)}
                          >
                            <Button size="small" type="link" danger icon={<DeleteOutlined />}>
                              {t('Delete')}
                            </Button>
                          </Popconfirm>
                        )}
                      </Space>
                    ),
                  },
                ]}
              />
            </Card>

            <JsonPeek
              data={detail}
              label={t('Raw response of the plugin detail API (GET /v1/hub/plugins/{plugin_id})')}
            />
          </div>
        ) : null}
      </Drawer>

      {/* Upload wizard: pick the package, hash it, fill in metadata, then POST and PUT */}
      <Modal
        open={uploadOpen}
        title={t('Upload plugin')}
        width={760}
        okText={t('Publish')}
        cancelText={t('Cancel')}
        confirmLoading={busy}
        closable={!busy}
        maskClosable={false}
        forceRender
        cancelButtonProps={{ disabled: busy }}
        onOk={() => void submitUpload()}
        onCancel={() => {
          if (!busy) setUploadOpen(false)
        }}
      >
        {upErr && (
          <Alert
            type="error"
            showIcon
            style={{ marginBottom: 14 }}
            message={t('Upload failed')}
            description={<span style={{ whiteSpace: 'pre-line' }}>{upErr}</span>}
          />
        )}

        <Upload.Dragger
          accept=".zip"
          multiple={false}
          maxCount={1}
          disabled={busy || hashBusy}
          style={{ marginBottom: 12 }}
          fileList={
            upFile
              ? [{ uid: 'picked-package', name: upFile.name, size: upFile.size, status: 'done' as const }]
              : []
          }
          beforeUpload={(file) => {
            void pickFile(file as File)
            return Upload.LIST_IGNORE
          }}
          onRemove={() => {
            if (busy) return false
            setUpFile(null)
            setUpSize(0)
            setUpSha(null)
            setUpErr(null)
            setPhase('idle')
            return true
          }}
          showUploadList={{ showPreviewIcon: false, showRemoveIcon: !busy }}
        >
          <p className="ant-upload-drag-icon">
            <InboxOutlined />
          </p>
          <p className="ant-upload-text">{t('Click to choose, or drop the plugin package (.zip) here')}</p>
          <p className="ant-upload-hint">
            {t('The package (required) must be at most 20 MiB and contain plugin.json at the root or in a single top-level directory. The platform only validates the structure; it never executes package code.')}
          </p>
        </Upload.Dragger>

        {(upFile || hashBusy) && (
          <div className="soft-panel" style={{ marginBottom: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
              <span>
                <b>{upFile?.name}</b>
                {upFile ? ` · ${fmtBytes(upSize)}` : ''}
              </span>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {hashBusy
                  ? t('Computing SHA-256…')
                  : upSha
                    ? t('SHA-256 ready')
                    : t('Checksum not computed')}
              </Typography.Text>
            </div>
            {upSha && (
              <div className="table-id" style={{ marginTop: 4, wordBreak: 'break-all' }}>
                {upSha}
              </div>
            )}
          </div>
        )}

        <div style={{ marginBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <Typography.Text strong>{t('Source archive (optional, recommended)')}</Typography.Text>
            <HelpTip
              title={t('A per-version source zip (≤50 MiB). It is stored with the version; after installing, the client can download and unpack it into the local source directory and edit the plugin with the model. If it contains plugin.json, its id must equal the plugin ID. The platform only validates the structure and never executes the code.')}
            />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {t('Once uploaded the sources can be downloaded; they cannot be replaced for the same version')}
            </Typography.Text>
          </div>
          <Upload.Dragger
            accept=".zip"
            multiple={false}
            maxCount={1}
            disabled={busy || srcHashBusy}
            style={{ marginBottom: 8 }}
            fileList={
              srcFile
                ? [{ uid: 'picked-source', name: srcFile.name, size: srcFile.size, status: 'done' as const }]
                : []
            }
            beforeUpload={(file) => {
              void pickSourceFile(file as File)
              return Upload.LIST_IGNORE
            }}
            onRemove={() => {
              if (busy) return false
              setSrcFile(null)
              setSrcSize(0)
              setSrcSha(null)
              return true
            }}
            showUploadList={{ showPreviewIcon: false, showRemoveIcon: !busy }}
          >
            <p className="ant-upload-drag-icon">
              <InboxOutlined />
            </p>
            <p className="ant-upload-text">
              {t('Click to choose, or drop the source zip here (skip it to publish this version without sources)')}
            </p>
            <p className="ant-upload-hint">
              {t('At most 50 MiB; a complete project directory is fine (plugin.json is optional, but when present its id must equal the plugin ID).')}
            </p>
          </Upload.Dragger>
          {(srcFile || srcHashBusy) && (
            <div className="soft-panel">
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
                <span>
                  <b>{srcFile?.name}</b>
                  {srcFile ? ` · ${fmtBytes(srcSize)}` : ''}
                </span>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {srcHashBusy
                    ? t('Computing SHA-256…')
                    : srcSha
                      ? t('SHA-256 ready')
                      : t('Checksum not computed')}
                </Typography.Text>
              </div>
              {srcSha && (
                <div className="table-id" style={{ marginTop: 4, wordBreak: 'break-all' }}>
                  {srcSha}
                </div>
              )}
            </div>
          )}
        </div>

        <Form form={uploadForm} layout="vertical" requiredMark={false} initialValues={{ category: 'other' }} disabled={busy}>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item
                name="plugin_id"
                label={
                  <Space size={2}>
                    {t('Plugin ID')}
                    <HelpTip
                      title={t('The unique identifier of the plugin on the platform; it cannot be changed after publishing, and the id in the package plugin.json must match it. Use lowercase letters, digits, dot, underscore or hyphen only, 2–64 characters.')}
                    />
                  </Space>
                }
                rules={[
                  { required: true, message: t('Enter the plugin ID') },
                  {
                    pattern: PLUGIN_ID_RE,
                    message: t('Use lowercase letters, digits, dot, underscore or hyphen only, 2–64 characters, starting with a letter or digit'),
                  },
                ]}
              >
                <Input placeholder={t('e.g. task-planner')} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="version"
                label={
                  <Space size={2}>
                    {t('Version')}
                    <HelpTip
                      title={t('Must be a version that does not exist yet (for example 1.4.2). A published version cannot be overwritten, so changing the content requires a new version number; the version in the package plugin.json must match it.')}
                    />
                  </Space>
                }
                rules={[
                  { required: true, message: t('Enter the version') },
                  { pattern: VERSION_RE, message: t('Use a value like 1.4.2, optionally with a suffix such as -beta.1') },
                ]}
              >
                <Input placeholder={t('e.g. 1.4.2')} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="name"
                label={t('Plugin name')}
                rules={[
                  { required: true, whitespace: true, message: t('Enter the plugin name') },
                  { max: 64, message: t('The name must be at most 64 characters') },
                ]}
              >
                <Input placeholder={t('e.g. Task Planner')} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="category" label={t('Category')}>
                <Select
                  options={hubCategoryOptions(t)}
                  placeholder={t('Choose a category (defaults to Other)')}
                />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="tags"
                label={t('Tags (optional)')}
                rules={[
                  {
                    validator: (_, value?: string[]) => {
                      const list = (value ?? []).map((tag) => tag.trim()).filter(Boolean)
                      if (list.length > 8) return Promise.reject(new Error(t('At most 8 tags')))
                      if (list.some((tag) => tag.length > 24)) {
                        return Promise.reject(new Error(t('Each tag must be at most 24 characters')))
                      }
                      return Promise.resolve()
                    },
                  },
                ]}
              >
                <Select
                  mode="tags"
                  tokenSeparators={[',', ' ']}
                  placeholder={t('Type and press Enter, e.g. planning')}
                  options={[]}
                />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="icon"
                label={t('Icon (optional)')}
                rules={[{ max: 512, message: t('The icon URL must be at most 512 characters') }]}
              >
                <Input placeholder={t('e.g. ri:calendar-todo-line')} />
              </Form.Item>
            </Col>
            <Col span={24}>
              <Form.Item
                name="description"
                label={t('Description (optional)')}
                rules={[{ max: 500, message: t('The description must be at most 500 characters') }]}
              >
                <Input.TextArea
                  rows={2}
                  placeholder={t('One sentence on what this plugin does (shown on the card, up to two lines)')}
                />
              </Form.Item>
            </Col>
            <Col span={24}>
              <Form.Item
                name="readme"
                label={
                  <Space size={2}>
                    {t('Plugin description / README (optional)')}
                    <HelpTip
                      title={t('The long-form description from the publisher. Line breaks are preserved and the limit is 16 KiB; the client plugin repository displays it.')}
                    />
                  </Space>
                }
                rules={[
                  {
                    validator: (_, value?: string) =>
                      byteLength(value) > MAX_README_BYTES
                        ? Promise.reject(new Error(t('The description exceeds 16 KiB (about 5,400 Chinese characters)')))
                        : Promise.resolve(),
                  },
                ]}
              >
                <Input.TextArea rows={3} placeholder={t('Markdown, e.g. "## Features" followed by a bullet list')} />
              </Form.Item>
            </Col>
            <Col span={24}>
              <Form.Item
                name="changelog"
                label={t('Changelog (optional)')}
                rules={[{ max: 2000, message: t('The changelog must be at most 2000 characters') }]}
              >
                <Input.TextArea
                  rows={2}
                  placeholder={t('What changed in this version (shown as the tooltip in the version list)')}
                />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="asset_name"
                label={t('Package filename')}
                rules={[
                  { required: true, message: t('Enter the package filename') },
                  {
                    pattern: ASSET_NAME_RE,
                    message: t('Must start with a letter or digit, end with .zip, and contain no path separators'),
                  },
                ]}
              >
                <Input placeholder={t('Filled in automatically after you choose a zip')} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item label={t('Submission order')}>
                <div className="soft-panel" style={{ lineHeight: 1.6 }}>
                  {t('Metadata is submitted first, then the package body; the version only appears in the catalogue after both steps succeed.')}
                </div>
              </Form.Item>
            </Col>
          </Row>
          <div className="soft-panel">
            <b>{t('Manifest snapshot:')}</b>{' '}
            {t('The platform builds it from the plugin ID, name and version above; make sure the id and version in plugin.json inside the package match, or the client refuses the install.')}
          </div>

          {(busy || phase === 'done') && (
            <div style={{ marginTop: 14 }}>
              <Progress
                percent={progressPercent}
                status={phase === 'done' ? 'success' : 'active'}
                showInfo={phase !== 'meta'}
              />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {phaseText}
              </Typography.Text>
            </div>
          )}
        </Form>
      </Modal>
    </div>
  )
}
