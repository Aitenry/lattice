import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Alert,
  App as AntApp,
  Button,
  Card,
  Descriptions,
  Drawer,
  Empty,
  Input,
  Result,
  Skeleton,
  Space,
  Spin,
  Table,
  Tooltip,
  Typography,
} from 'antd'
import {
  ClockCircleOutlined,
  CopyOutlined,
  DownloadOutlined,
  LeftOutlined,
  LinkOutlined,
  ReloadOutlined,
  RightOutlined,
} from '@ant-design/icons'
import { downloadMediaRecording, getMediaRecording, listMediaRecordings } from '@/api/endpoints'
import type { MediaRecordingDetail, MediaRecordingRow } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { HelpTip } from '@/components/HelpTip'
import { JsonPeek } from '@/components/JsonPeek'
import { LIST_PAGE_SIZE, LIST_SCROLL_Y } from '@/components/listLayout'
import { errText } from '@/lib/errors'
import { fmtBytes, fmtTime } from '@/lib/format'
import { useI18n, type Translate } from '@/i18n'

/**
 * Media recordings (⑤ §9.7 / PL-13 13.6): the **index** page for WS-tunnel recording segments.
 *
 * Capability boundaries, stated honestly instead of pretending there is a player:
 * - The server currently only stores raw `[4B len][body]` segment objects, with no MP4/OGG container
 *   and no transcoding, so this page offers metadata plus whole-segment download and **no in-browser playback**;
 * - Recording is off by default (`[media] record_enabled=false`), and the empty state has to say so, otherwise
 *   operators will assume the feature is broken;
 * - The list uses reverse cursor paging (`before` = last id of the previous page), hence "Previous/Next"
 *   instead of antd page numbers: a cursor cannot know the total, and the page length is fixed at `LIST_PAGE_SIZE`;
 * - The API returns metadata only, **never any payload or frame content**, so the table neither shows nor requests it.
 */

/** Filename to save under: prefer the segment object name (.../{first_seq:020}.bin), fall back to the recording ID */
function recordingFileName(d: MediaRecordingDetail): string {
  const base = d.object_key.split('/').filter(Boolean).pop()
  return base && base.includes('.') ? base : `recording-${d.id}.bin`
}

/** blob → browser download (same approach as the plugin hub download; no new window) */
function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 30_000)
}

/**
 * Copy text: prefer the Clipboard API (secure contexts: HTTPS / localhost), and fall back
 * to a hidden textarea plus execCommand (older browsers / permission denied).
 */
async function copyToClipboard(value: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value)
      return true
    }
  } catch {
    /* fallback */
  }
  try {
    const area = document.createElement('textarea')
    area.value = value
    area.setAttribute('readonly', '')
    area.style.position = 'fixed'
    area.style.top = '-1000px'
    area.style.opacity = '0'
    document.body.appendChild(area)
    area.select()
    const ok = document.execCommand('copy')
    area.remove()
    return ok
  } catch {
    return false
  }
}

/** The refresh time shows hours/minutes/seconds only; the full date is in the tooltip (visible on hover) */
function fmtClock(at: Date): string {
  return at.toLocaleTimeString('zh-CN', { hour12: false })
}

/** Sequence range: the direct-write path has no frame sequence (first/last_seq are null), so show "not recorded" instead of faking 0 */
function seqRange(d: MediaRecordingRow, t: Translate): string {
  if (d.first_seq == null && d.last_seq == null) return t('Not recorded')
  return `${d.first_seq ?? '—'} ~ ${d.last_seq ?? '—'}`
}

export default function RecordingsPage() {
  const { message } = AntApp.useApp()
  const { t } = useI18n()
  const { can } = useAuth()
  // The server gate is `require_role(Ops)`: media recordings are readable by admin/ops only, and user requests get a 403.
  // The UI hides data and requests behind the same gate, so a regular user who types the URL sees a permission hint instead of a pile of failed loads.
  const canRead = can('dispose')

  const [rows, setRows] = useState<MediaRecordingRow[]>([])
  const [nextBefore, setNextBefore] = useState<string | null>(null)
  // Cursor stack: each page records its own `before`; stack[0] is always undefined (the first page = newest recordings)
  const [stack, setStack] = useState<Array<string | undefined>>([undefined])
  const [streamFilter, setStreamFilter] = useState('')
  const [searchText, setSearchText] = useState('')
  // A counter forces a re-run on refresh/repeat search (so an unchanged state value cannot get stuck)
  const [reloadToken, setReloadToken] = useState(0)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  // Time of the last successful refresh (the toolbar shows "updated at HH:mm:ss"; the full date is in the tooltip)
  const [lastRefreshedAt, setLastRefreshedAt] = useState<Date | null>(null)
  // With fast paging an old request may arrive late: discard stale responses by sequence number so the table does not flash back
  const reqSeq = useRef(0)

  const [detailOpen, setDetailOpen] = useState(false)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detail, setDetail] = useState<MediaRecordingDetail | null>(null)
  const [detailErr, setDetailErr] = useState<string | null>(null)
  const [downloading, setDownloading] = useState(false)

  const load = useCallback(async () => {
    if (!canRead) return
    const seq = ++reqSeq.current
    setLoading(true)
    setErr(null)
    try {
      const r = await listMediaRecordings({
        stream_id: streamFilter || undefined,
        limit: LIST_PAGE_SIZE,
        before: stack[stack.length - 1],
      })
      if (seq !== reqSeq.current) return
      setRows(r.items ?? [])
      setNextBefore(r.next_before ?? null)
      setLastRefreshedAt(new Date())
    } catch (e) {
      if (seq !== reqSeq.current) return
      setRows([])
      setNextBefore(null)
      setErr(errText(e))
    } finally {
      if (seq === reqSeq.current) setLoading(false)
    }
  }, [canRead, stack, streamFilter])

  useEffect(() => {
    void load()
  }, [load, reloadToken])

  const page = stack.length
  const firstPage = stack.length <= 1
  const lastPage = !nextBefore

  function applySearch(raw: string) {
    setSearchText(raw)
    setStack([undefined])
    setStreamFilter(raw.trim())
    setReloadToken((t) => t + 1)
  }

  function goPrev() {
    if (firstPage) return
    setStack((s) => s.slice(0, -1))
  }

  function goNext() {
    if (!nextBefore) return
    setStack((s) => [...s, nextBefore])
  }

  function refresh() {
    setReloadToken((t) => t + 1)
  }

  async function openDetail(row: MediaRecordingRow) {
    setDetailOpen(true)
    setDetail(null)
    setDetailErr(null)
    setDetailLoading(true)
    try {
      setDetail(await getMediaRecording(row.id))
    } catch (e) {
      setDetailErr(errText(e))
    } finally {
      setDetailLoading(false)
    }
  }

  function closeDetail() {
    setDetailOpen(false)
    setDetail(null)
    setDetailErr(null)
  }

  async function handleDownload() {
    if (!detail) return
    setDownloading(true)
    try {
      const blob = await downloadMediaRecording(detail.id)
      saveBlob(blob, recordingFileName(detail))
      message.success(t('Download started ({size})', { size: fmtBytes(blob.size) }))
    } catch (e) {
      // The download endpoint is a 302 to object storage: if the browser cannot fetch the final bytes because of
      // CORS, fall back to the presigned URL from the detail response (it needs no auth header, so the browser can download it).
      const reason = errText(e)
      if (detail.presigned_url) {
        window.open(detail.presigned_url, '_blank', 'noopener,noreferrer')
        message.warning({
          content: t(
            'Direct download failed ({reason}); opened the presigned link instead. If the browser blocks it, use "Copy presigned URL" above to download manually.',
            { reason },
          ),
          duration: 6,
        })
      } else {
        message.error({
          content: t('Download failed: {reason}. Try again later, or ask an administrator to check object storage.', {
            reason,
          }),
          duration: 6,
        })
      }
    } finally {
      setDownloading(false)
    }
  }

  /** Copy (stream_id / presigned URL): report failures explicitly instead of failing silently */
  async function copyValue(value: string | null | undefined, subject: string) {
    if (!value) {
      message.warning(t('There is no {subject} to copy', { subject }))
      return
    }
    const ok = await copyToClipboard(value)
    if (ok) message.success(t('Copied {subject}', { subject }))
    else message.error(t('Copy failed: the browser did not grant clipboard access. Select the text and copy it manually.'))
  }

  // A regular user has no media permission: send no request and show a permission hint instead
  if (!canRead) {
    return (
      <div className="page-fill">
        <Card className="list-card">
          <Result
            status="403"
            title={t('No permission to view media recordings')}
            subTitle={t(
              'Media recordings are an operations safeguard: only administrators and operations roles can view them, and this account does not have that permission. For connection troubleshooting, contact an administrator.',
            )}
          />
        </Card>
      </div>
    )
  }

  const emptyDescription = streamFilter ? (
    <Space direction="vertical" size={2} style={{ maxWidth: 560 }}>
      <span>{t('No recordings match this stream')}</span>
      <span className="muted" style={{ fontSize: 12 }}>
        {t(
          'Current filter: {filter}. Recordings match the stream ID exactly — check the casing and the full ID. Clear the search box and press Enter (or click search) to see every recording.',
          { filter: streamFilter },
        )}
      </span>
    </Space>
  ) : (
    <Space direction="vertical" size={2} style={{ maxWidth: 620 }}>
      <span>{t('No recordings yet (recording is off by default)')}</span>
      <span className="muted" style={{ fontSize: 12 }}>
        {t('Recording is off by default. After setting')}{' '}
        <span className="inline-code">[media] record_enabled = true</span>{' '}
        {t(
          'on the server, raw frames forwarded through the tunnel are written to object storage in segments and show up here newest first; this page is a read-only index and never stores or shows payloads.',
        )}
      </span>
    </Space>
  )

  return (
    <div className="page-fill">
      {err && <Alert type="error" showIcon message={t('Failed to load')} description={err} />}

      <Card className="list-card">
        <div className="toolbar">
          <div className="toolbar-right">
            <Tooltip title={firstPage ? t('Already on the first page (newest recordings)') : t('Back to newer recordings')}>
              <Button
                icon={<LeftOutlined />}
                disabled={firstPage || loading}
                onClick={goPrev}
                aria-label={t('Previous page')}
              >
                {t('Previous page')}
              </Button>
            </Tooltip>
            <Tooltip title={lastPage ? t('Already on the last page (no older recordings)') : t('View older recordings')}>
              <Button
                icon={<RightOutlined />}
                disabled={lastPage || loading}
                onClick={goNext}
                aria-label={t('Next page')}
              >
                {t('Next page')}
              </Button>
            </Tooltip>
            <Button icon={<ReloadOutlined />} loading={loading} onClick={refresh} aria-label={t('Refresh')}>
              {t('Refresh')}
            </Button>
          </div>
          <Input.Search
            allowClear
            enterButton
            value={searchText}
            placeholder={t('Filter by exact stream ID')}
            style={{ width: 300 }}
            onChange={(e) => setSearchText(e.target.value)}
            onSearch={(v) => applySearch(v)}
          />
          <HelpTip
            title={t(
              'Recording is off by default (server setting [media] record_enabled). When enabled, raw frames forwarded through the WS tunnel become segment files in object storage; this page shows only the segment index and never stores or shows payloads. Newest first, paged with Previous/Next by cursor, so no total count is shown.',
            )}
          />
          <span
            className="toolbar-meta"
            title={
              lastRefreshedAt
                ? t('Last successful refresh: {time}', { time: fmtTime(lastRefreshedAt.toISOString()) })
                : t('Not refreshed yet')
            }
          >
            <ClockCircleOutlined />
            {loading
              ? t('Refreshing…')
              : lastRefreshedAt
                ? t('Updated at {time}', { time: fmtClock(lastRefreshedAt) })
                : t('Waiting for the first load')}
            <span className="dot-sep" />
            {t('Page {page}{last}', { page, last: lastPage ? t(' (last page)') : '' })}
            {streamFilter ? t(' · Filter: {filter}', { filter: streamFilter }) : ''}
          </span>
        </div>

        {loading && rows.length === 0 ? (
          <div className="recordings-skeleton" aria-busy="true" aria-label={t('Loading recordings')}>
            <Skeleton active title={false} paragraph={{ rows: 8 }} />
          </div>
        ) : (
          <Table<MediaRecordingRow>
          size="small"
          scroll={{ y: LIST_SCROLL_Y }}
          rowKey="id"
          loading={loading}
          dataSource={rows}
          pagination={false}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={emptyDescription} /> }}
          onRow={(row) => ({
            onClick: () => void openDetail(row),
            style: { cursor: 'pointer' },
          })}
          columns={[
            {
              title: t('Stream ID'),
              dataIndex: 'stream_id',
              ellipsis: true,
              render: (v: string) => (
                <Tooltip title={v}>
                  <span className="cell-title mono">{v}</span>
                </Tooltip>
              ),
            },
            {
              title: t('Node'),
              dataIndex: 'node_id',
              width: 170,
              ellipsis: true,
              render: (v: string) => (
                <Tooltip title={v}>
                  <span className="cell-sub">{v}</span>
                </Tooltip>
              ),
            },
            {
              title: (
                <Space size={2}>
                  {t('First sequence')}
                  <HelpTip
                    title={t(
                      'Sequence number of the first frame in this recording segment. Raw frames on the direct-write path carry no sequence (the server returns null), so "—" means not recorded — not data loss.',
                    )}
                  />
                </Space>
              ),
              dataIndex: 'first_seq',
              width: 112,
              render: (v: number | null) => (v == null ? <span className="muted">—</span> : v),
            },
            {
              title: t('Last sequence'),
              dataIndex: 'last_seq',
              width: 112,
              render: (v: number | null) => (v == null ? <span className="muted">—</span> : v),
            },
            {
              title: (
                <Space size={2}>
                  {t('Frames')}
                  <HelpTip
                    title={t(
                      'Number of raw frames in this recording object (the segment format is length-prefixed frames, not MP4).',
                    )}
                  />
                </Space>
              ),
              dataIndex: 'frames',
              width: 96,
              render: (v: number) => (v == null ? '—' : v),
            },
            {
              title: (
                <Space size={2}>
                  {t('File size')}
                  <HelpTip title={t('Size in bytes of this recording file in object storage (raw segments, not playable video).')} />
                </Space>
              ),
              dataIndex: 'size_bytes',
              width: 118,
              render: (v: number) => fmtBytes(v),
            },
            {
              title: t('Recorded at'),
              dataIndex: 'created_at',
              width: 176,
              render: (v: string) => fmtTime(v),
            },
            {
              title: t('Actions'),
              width: 88,
              render: (_, row) => (
                <Button
                  size="small"
                  type="link"
                  onClick={(e) => {
                    e.stopPropagation()
                    void openDetail(row)
                  }}
                >
                  {t('Details')}
                </Button>
              ),
            },
              ]}
            />
          )}
      </Card>

      <Drawer open={detailOpen} width={580} title={t('Recording details')} onClose={closeDetail} destroyOnClose>
        {detailLoading && (
          <div style={{ padding: 24, textAlign: 'center' }}>
            <Spin />
          </div>
        )}
        {!detailLoading && detailErr && (
          <Alert type="error" showIcon message={t('Failed to load details')} description={detailErr} />
        )}
        {!detailLoading && !detailErr && detail && (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Alert
              type="info"
              showIcon
              message={t(
                'Only the raw recording segment can be downloaded. There is no in-browser playback and no MP4/OGG container yet (the server does not transcode).',
              )}
            />
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label={t('Stream ID')}>
                <Space size={8} wrap>
                  <Typography.Text className="mono" style={{ wordBreak: 'break-all' }}>
                    {detail.stream_id}
                  </Typography.Text>
                  <Button
                    size="small"
                    icon={<CopyOutlined />}
                    onClick={() => void copyValue(detail.stream_id, 'stream_id')}
                  >
                    {t('Copy stream_id')}
                  </Button>
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label={t('Node')}>
                <span className="cell-sub">{detail.node_id}</span>
              </Descriptions.Item>
              <Descriptions.Item label={t('Sequence range')}>{seqRange(detail, t)}</Descriptions.Item>
              <Descriptions.Item label={t('Frames')}>{detail.frames}</Descriptions.Item>
              <Descriptions.Item label={t('File size')}>{fmtBytes(detail.size_bytes)}</Descriptions.Item>
              <Descriptions.Item label={t('Recorded at')}>{fmtTime(detail.created_at)}</Descriptions.Item>
              <Descriptions.Item label={t('Started / ended')}>
                {detail.started_at || detail.ended_at
                  ? `${fmtTime(detail.started_at)} ~ ${fmtTime(detail.ended_at)}`
                  : t('Not recorded (the direct-write path has no frame timestamps)')}
              </Descriptions.Item>
              <Descriptions.Item label={t('Container format')}>
                {detail.format ?? t('Raw segment (no container)')}
              </Descriptions.Item>
              <Descriptions.Item label={t('Object location')}>
                <span className="cell-sub">{`${detail.bucket}/${detail.object_key}`}</span>
              </Descriptions.Item>
              <Descriptions.Item label={t('Recording ID')}>
                <Typography.Text className="mono" copyable>
                  {detail.id}
                </Typography.Text>
              </Descriptions.Item>
            </Descriptions>

            <Space direction="vertical" size={10} style={{ width: '100%' }}>
              <Space wrap size={8}>
                <Button
                  type="primary"
                  icon={<DownloadOutlined />}
                  loading={downloading}
                  onClick={() => void handleDownload()}
                >
                  {t('Download raw segment')}
                </Button>
                <Button
                  icon={<CopyOutlined />}
                  onClick={() => void copyValue(detail.presigned_url, t('presigned URL'))}
                >
                  {t('Copy presigned URL')}
                </Button>
                <Button
                  icon={<LinkOutlined />}
                  onClick={() => window.open(detail.presigned_url, '_blank', 'noopener,noreferrer')}
                >
                  {t('Open in new window')}
                </Button>
              </Space>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {t(
                  'The presigned link is valid for {seconds} seconds: open it in a browser or hand it to a download tool; no login token is needed. If "Download raw segment" fails (for example because object storage blocks cross-origin requests), use the copy button above to get the link and download manually.',
                  { seconds: detail.presign_ttl_seconds },
                )}
              </Typography.Text>
              <Typography.Paragraph
                className="mono recording-copy-note"
                ellipsis={{ rows: 2, expandable: true, symbol: t('Expand') }}
                style={{ marginBottom: 0 }}
              >
                {detail.presigned_url}
              </Typography.Paragraph>
            </Space>

            <JsonPeek
              data={detail}
              label={t('Raw response of the recording detail endpoint (includes the presigned link; no payload or frame content)')}
            />
          </Space>
        )}
      </Drawer>
    </div>
  )
}
