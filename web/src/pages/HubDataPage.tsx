import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Alert,
  App as AntApp,
  Button,
  Card,
  Drawer,
  Empty,
  Input,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import { CodeOutlined, CopyOutlined, DownloadOutlined, ReloadOutlined } from '@ant-design/icons'
import { listHubInstalls } from '@/api/endpoints'
import type { HubInstallRow } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { HelpTip } from '@/components/HelpTip'
import { PluginIcon } from '@/components/PluginIcon'
import { LIST_PAGE_SIZE, LIST_SCROLL_Y } from '@/components/listLayout'
import { useI18n } from '@/i18n'
import { errText } from '@/lib/errors'
import { fmtBytes, fmtRelative, fmtTime, prettyJson } from '@/lib/format'

/**
 * My plugin data.
 *
 * The platform keeps one install record per (user, plugin) plus an optional JSON snapshot that
 * RytenBench syncs (≤256 KiB per plugin). Until now the user-facing `/v1/hub/installs` endpoint
 * existed but the console had no page for it, so "my settings are backed up" could not be
 * verified from the platform side. This page is the read-only view: the signed-in account's
 * records, versions, enabled flags and snapshots. Writes stay in RytenBench (the sync owner);
 * the console never edits or deletes them.
 */

const encoder = new TextEncoder()

/** Snapshot text as shown in the drawer (and copied/downloaded verbatim). */
function snapshotText(data: unknown): string {
  return data == null ? '{}' : prettyJson(data, 2)
}

/**
 * UTF-8 size of the stored snapshot. The server returns `{}` when no snapshot was ever
 * uploaded, which must read as "no data" rather than a 2-byte snapshot.
 */
function snapshotBytes(data: unknown): number {
  const text = snapshotText(data)
  return text === '{}' ? 0 : encoder.encode(text).length
}

export default function HubDataPage() {
  const { t } = useI18n()
  const { message } = AntApp.useApp()
  const { session } = useAuth()

  const [rows, setRows] = useState<HubInstallRow[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [q, setQ] = useState('')
  const [selected, setSelected] = useState<HubInstallRow | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setErr(null)
    try {
      // include_data=1: the snapshot comes with the list, so opening the drawer is instant and
      // there is no second request that could fail on its own.
      const r = await listHubInstalls({ include_data: true })
      setRows(r.items ?? [])
    } catch (e) {
      setErr(errText(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return rows
    return rows.filter((r) => `${r.plugin?.name ?? ''} ${r.plugin_id}`.toLowerCase().includes(needle))
  }, [rows, q])

  const summary = useMemo(() => {
    const withData = rows.filter((r) => snapshotBytes(r.data) > 0).length
    const bytes = rows.reduce((sum, r) => sum + snapshotBytes(r.data), 0)
    const last = rows.reduce<string | null>(
      (acc, r) => (!acc || r.updated_at > acc ? r.updated_at : acc),
      null,
    )
    return { withData, bytes, last }
  }, [rows])

  async function copySnapshot(row: HubInstallRow) {
    try {
      await navigator.clipboard.writeText(snapshotText(row.data))
      message.success(t('Copied to clipboard'))
    } catch (e) {
      message.error(errText(e))
    }
  }

  function downloadSnapshot(row: HubInstallRow) {
    const url = URL.createObjectURL(new Blob([snapshotText(row.data)], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `${row.plugin_id}-${row.version}-plugin-data.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    // Revoking after the click task lets the browser start the download first.
    window.setTimeout(() => URL.revokeObjectURL(url), 1500)
    message.success(t('Downloaded'))
  }

  return (
    <div className="page-fill">
      <Alert
        type="info"
        showIcon
        message={t('Plugin data is stored per account on this platform')}
        description={
          <>
            {t(
              'RytenBench uploads the install record and the data snapshot (at most 256 KiB per plugin) of every installed plugin. The snapshot is whatever the plugin exports — settings, and for data-heavy plugins (like the ledger) its business tables too. This page is a read-only view of the signed-in account: if RytenBench signs in with another account, sign in with that account here. The platform keeps snapshots so a reinstall can be filled in and conflicts resolved; it never executes plugin code.',
            )}
            <div style={{ marginTop: 6 }}>
              {t('Currently viewing: {user}', { user: session?.username ?? '—' })}
            </div>
          </>
        }
      />

      {err && <Alert type="error" showIcon message={t('Failed to load')} description={err} />}

      <Card className="list-card">
        <div className="toolbar">
          <Input.Search
            allowClear
            placeholder={t('Search by plugin name or ID')}
            style={{ width: 280 }}
            onChange={(e) => setQ(e.target.value)}
          />
          <span className="toolbar-meta">
            {t('{count} plugins', { count: rows.length })}
            <span className="dot-sep" />
            {t('{count} with data', { count: summary.withData })}
            <span className="dot-sep" />
            {t('Snapshot size {size}', { size: fmtBytes(summary.bytes) })}
            {summary.last && (
              <>
                <span className="dot-sep" />
                {t('Last sync {time}', { time: fmtRelative(summary.last) })}
              </>
            )}
          </span>
          <div className="toolbar-right">
            <HelpTip
              title={t(
                'Snapshots are the JSON that RytenBench syncs for a plugin, capped at 256 KiB per plugin. Depending on the plugin it holds settings only, or settings plus its business data (the personal ledger exports its 10 tables). They are the platform-side copy used to restore a device — not live plugin code.',
              )}
            />
            <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void load()}>
              {t('Refresh')}
            </Button>
          </div>
        </div>

        <Table<HubInstallRow>
          size="small"
          rowKey="plugin_id"
          loading={loading}
          dataSource={filtered}
          scroll={{ y: LIST_SCROLL_Y }}
          locale={{
            emptyText: (
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description={
                  <Space direction="vertical" size={2}>
                    <span>{t('No plugin data has been synced yet')}</span>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {t(
                        'In RytenBench, sign in with the same account and install a plugin; the install record and snapshot are uploaded automatically.',
                      )}
                    </Typography.Text>
                  </Space>
                }
              />
            ),
          }}
          pagination={{
            pageSize: LIST_PAGE_SIZE,
            showSizeChanger: false,
            showTotal: (count) => t('{count} plugins', { count }),
          }}
          columns={[
            {
              title: t('Plugin'),
              render: (_, r) => (
                <Space size={10} align="center">
                  <PluginIcon icon={r.plugin?.icon ?? null} name={r.plugin?.name ?? r.plugin_id} size={34} />
                  <Space direction="vertical" size={0}>
                    <Space size={6}>
                      <span className="cell-title">{r.plugin?.name ?? r.plugin_id}</span>
                      {!r.plugin && <Tag style={{ marginInlineEnd: 0 }}>{t('Not published')}</Tag>}
                    </Space>
                    <span className="cell-sub">{r.plugin_id}</span>
                  </Space>
                </Space>
              ),
            },
            {
              title: t('Version'),
              width: 170,
              render: (_, r) => (
                <Space size={6}>
                  <Tag color="blue" style={{ marginInlineEnd: 0 }}>
                    v{r.version}
                  </Tag>
                  {r.plugin?.latest_version && r.plugin.latest_version !== r.version && (
                    <Tag color="gold" style={{ marginInlineEnd: 0 }}>
                      {t('Update available')}
                    </Tag>
                  )}
                </Space>
              ),
            },
            {
              title: t('Status'),
              width: 100,
              render: (_, r) =>
                r.enabled ? (
                  <Tag color="green" style={{ marginInlineEnd: 0 }}>
                    {t('Enabled')}
                  </Tag>
                ) : (
                  <Tag style={{ marginInlineEnd: 0 }}>{t('Disabled')}</Tag>
                ),
            },
            {
              title: (
                <Space size={2}>
                  {t('Data snapshot')}
                  <HelpTip
                    title={t(
                      'A JSON snapshot of the plugin data that RytenBench syncs, at most 256 KiB per plugin. It is whatever the plugin exports (settings, and sometimes its business tables). "No data snapshot" means the plugin has synced an install record but no data yet.',
                    )}
                  />
                </Space>
              ),
              width: 210,
              render: (_, r) => {
                const bytes = snapshotBytes(r.data)
                return (
                  <Space direction="vertical" size={0}>
                    {bytes > 0 ? (
                      <span>
                        {fmtBytes(bytes)}
                        <span className="muted"> · {t('Data version')} {r.data_rev}</span>
                      </span>
                    ) : (
                      <span className="muted">{t('No data snapshot')}</span>
                    )}
                    <span className="cell-sub">
                      {r.data_updated_at ? fmtRelative(r.data_updated_at) : '—'}
                    </span>
                  </Space>
                )
              },
            },
            {
              title: t('Last device'),
              dataIndex: 'last_device',
              width: 160,
              ellipsis: true,
              render: (v: string | null) =>
                v ? (
                  <Tooltip title={v}>
                    <span className="cell-sub">{v.length > 18 ? `${v.slice(0, 18)}…` : v}</span>
                  </Tooltip>
                ) : (
                  <Typography.Text type="secondary">—</Typography.Text>
                ),
            },
            {
              title: t('Last sync'),
              dataIndex: 'updated_at',
              width: 130,
              render: (v: string) => (
                <Tooltip title={fmtTime(v)}>
                  <span>{fmtRelative(v)}</span>
                </Tooltip>
              ),
            },
            {
              title: t('Actions'),
              width: 120,
              render: (_, r) => (
                <Button
                  size="small"
                  type="link"
                  icon={<CodeOutlined />}
                  disabled={snapshotBytes(r.data) === 0}
                  onClick={() => setSelected(r)}
                >
                  {t('View data')}
                </Button>
              ),
            },
          ]}
        />
      </Card>

      <Drawer
        open={selected != null}
        onClose={() => setSelected(null)}
        width={640}
        title={
          selected
            ? `${selected.plugin?.name ?? selected.plugin_id} · v${selected.version} · ${t('Plugin data')}`
            : ''
        }
        extra={
          selected && (
            <Space size={8}>
              <Button icon={<CopyOutlined />} onClick={() => void copySnapshot(selected)}>
                {t('Copy JSON')}
              </Button>
              <Button icon={<DownloadOutlined />} onClick={() => downloadSnapshot(selected)}>
                {t('Download JSON')}
              </Button>
            </Space>
          )
        }
      >
        {selected && (
          <>
            <Space wrap size={18} style={{ marginBottom: 12 }}>
              <span className="muted">
                {t('Data version')}: <b>{selected.data_rev}</b>
              </span>
              <span className="muted">
                {t('Data updated')}: {fmtTime(selected.data_updated_at)}
              </span>
              <span className="muted">
                {t('Last device')}: {selected.last_device ?? '—'}
              </span>
            </Space>
            <pre className="raw-block" style={{ maxHeight: 480 }}>
              {snapshotText(selected.data)}
            </pre>
          </>
        )}
      </Drawer>
    </div>
  )
}
