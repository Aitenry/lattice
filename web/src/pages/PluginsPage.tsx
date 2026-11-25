import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  App as AntApp,
  Button,
  Card,
  Descriptions,
  Drawer,
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
} from 'antd'
import {
  DatabaseOutlined,
  FolderOpenOutlined,
  ReloadOutlined,
  RocketOutlined,
  ThunderboltOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { errText } from '@/lib/errors'
import { listPlugins, pluginAction, pluginStats } from '@/api/endpoints'
import type { AdminPluginsResp, PluginRow, WasmRuntimeState } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { PLUGIN_STATUS, pick, toneOf } from '@/lib/labels'
import { fmtBytes, fmtRelative, fmtTime } from '@/lib/format'
import { HelpTip } from '@/components/HelpTip'
import { useI18n, type Translate } from '@/i18n'

/** The stats endpoint has an unstable shape: scalars go straight into the table, complex values are collapsed */
function scalarEntries(data: unknown): [string, string][] {
  if (!data || typeof data !== 'object') return []
  return Object.entries(data as Record<string, unknown>)
    .filter(([, v]) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')
    .map(([k, v]) => [k, String(v)])
}

/** Count fallback: show "—" when the API omits the field instead of faking a 0 */
function countText(v: number | null | undefined): string {
  return typeof v === 'number' ? String(v) : '—'
}

/** Display name of a loaded plugin: ns > plugin > unknown; version optional */
function loadedName(entry: Record<string, unknown>, t: Translate): string {
  const ns = entry.ns ?? entry.plugin
  return typeof ns === 'string' && ns ? ns : t('Unnamed plugin')
}

/**
 * WASM runtime status card (read-only).
 *
 * Data comes from the `wasm` section of `GET /v1/admin/plugins`. **When the feature is off the API
 * omits this field and the whole card is hidden** (the caller decides); nothing here guesses
 * defaults or allows any action.
 *
 * Layout: status tags in the card header, three headline numbers and load/rejection details in
 * the main column, source facts in a side column. The old design packed six equally-sized tiles
 * into one row and put everything else in the same column, which made the page look crowded; the
 * two-column split keeps numbers and narrative apart without hiding any field.
 */
function WasmStatusPanel({ wasm }: { wasm: WasmRuntimeState }) {
  const { t } = useI18n()
  const loaded = Array.isArray(wasm.loaded) ? wasm.loaded : []
  const rejected = Array.isArray(wasm.rejected) ? wasm.rejected : []
  const dir = wasm.sources?.dir ?? null
  const pg = wasm.sources?.pg ?? null
  const enabled = Boolean(wasm.enabled)
  const trustLabel =
    typeof wasm.signature_verification === 'string' &&
    wasm.signature_verification &&
    wasm.signature_verification !== 'not_implemented'
      ? wasm.signature_verification
      : t('Signature verification off')
  const dirLoaded = dir?.loaded
  const dirRejected = dir?.rejected
  const trustedKeys = wasm.trusted_key_ids?.length ?? wasm.trusted_keys ?? 0
  const pgMeta =
    !pg || pg.enabled === false
      ? t('Not enabled')
      : typeof pg.rows === 'number'
        ? t('Queried {count} rows · {conflicts} conflicts', {
            count: pg.rows,
            conflicts: typeof pg.conflicts === 'number' ? pg.conflicts : 0,
          })
        : '—'

  return (
    <section className="panel wasm-card">
      <div className="panel-head">
        <span className="panel-title">
          <ThunderboltOutlined />
          {t('WASM plugin runtime')}
          <HelpTip
            title={t(
              'Loads signed .wasm plugins from the plugin directory and the PG registry. WASM runs inside a wasmtime sandbox that limits resources, but that is not a substitute for signatures: failed verification is rejected without affecting startup or other plugins.',
            )}
          />
        </span>
      </div>
      <div className="wasm-grid">
        <div className="wasm-main">
          <div className="wasm-summary">
            <div className="wasm-stat">
              <div className="wasm-stat-label">{t('Loaded plugins')}</div>
              <div className="wasm-stat-value">{countText(loaded.length)}</div>
              <div className="wasm-stat-hint">
                {t('Directory {fromDir} · Database {fromDb}', {
                  fromDir: countText(dirLoaded),
                  fromDb: countText(pg?.loaded),
                })}
              </div>
            </div>
            <div className="wasm-stat">
              <div className="wasm-stat-label">{t('Rejected')}</div>
              <div
                className="wasm-stat-value"
                style={{ color: rejected.length ? 'var(--tone-orange-fg)' : undefined }}
              >
                {countText(rejected.length)}
              </div>
              <div className="wasm-stat-hint">{t('Fail-closed: a rejection never blocks startup')}</div>
            </div>
            <div className="wasm-stat">
              <div className="wasm-stat-label">{t('Trusted public keys')}</div>
              <div className="wasm-stat-value">{countText(trustedKeys)}</div>
              <div className="wasm-stat-hint">{trustLabel}</div>
            </div>
          </div>

          {loaded.length ? (
            <div className="wasm-block">
              <div className="wasm-block-head">
                <span className="wasm-block-title">{t('Load details')}</span>
                <span className="wasm-block-sub">
                  {t('Loaded (source: {source}; in load order)', {
                    source: wasm.from_db ? t('directory + database') : t('directory'),
                  })}
                </span>
              </div>
              <Space wrap size={[8, 8]}>
                {loaded.map((entry, index) => {
                  const item = entry as Record<string, unknown>
                  const source = typeof item.source === 'string' ? item.source : null
                  const version =
                    typeof item.version === 'string'
                      ? item.version
                      : typeof item.version === 'number'
                        ? String(item.version)
                        : null
                  return (
                    <Tag key={`${loadedName(item, t)}-${version ?? index}`} color="blue">
                      {loadedName(item, t)}
                      {version ? <span style={{ opacity: 0.75 }}> @ {version}</span> : null}
                      {source ? <span style={{ opacity: 0.75 }}> · {source}</span> : null}
                    </Tag>
                  )
                })}
              </Space>
            </div>
          ) : (
            <div className="wasm-empty">
              <div className="wasm-empty-title">
                {enabled
                  ? t('The WASM runtime is enabled, but no plugin is loaded yet.')
                  : t('The WASM runtime is disabled, and no plugin is loaded.')}
              </div>
              <div className="muted">
                {t('Put signed plugins into')} <span className="inline-code">{wasm.wasm_dir || 'wasm_dir'}</span>
                {t(', or publish them in the PG registry and refresh this page.')}
              </div>
              <div className="muted">
                {t(
                  'Unsigned plugins and plugins that fail verification are listed under "Rejection details" and never block startup.',
                )}
              </div>
            </div>
          )}

          {rejected.length ? (
            <div className="wasm-block">
              <div className="wasm-block-head">
                <span className="wasm-block-title">
                  <WarningOutlined /> {t('Rejection details')}
                </span>
                <Tag color="orange">{rejected.length}</Tag>
              </div>
              <div className="wasm-reject-list">
                {rejected.slice(0, 5).map((entry, index) => {
                  const item = entry as Record<string, unknown>
                  const kind = typeof item.kind === 'string' ? item.kind : 'unknown'
                  const plugin =
                    typeof item.plugin === 'string' ? item.plugin : typeof item.ns === 'string' ? item.ns : '—'
                  const reason = typeof item.reason === 'string' ? item.reason : ''
                  return (
                    <div key={`${plugin}-${index}`} className="wasm-reject-item">
                      <span className="kind">{kind}</span>
                      <span className="plugin">{plugin}</span>
                      <span className="reason">{reason || '—'}</span>
                    </div>
                  )
                })}
                {rejected.length > 5 ? (
                  <span className="wasm-block-sub">{t('Only the first 5 are shown.')}</span>
                ) : null}
              </div>
            </div>
          ) : null}
        </div>

        <aside className="wasm-side">
          <div className="wasm-side-title">{t('Security & sources')}</div>
          <div className="wasm-side-row">
            <span className="k">{t('Max module')}</span>
            <span className="v">
              {typeof wasm.max_wasm_bytes === 'number' ? fmtBytes(wasm.max_wasm_bytes) : '—'}
            </span>
          </div>

          <div className="wasm-side-sep" />

          <div className="wasm-source">
            <div className="wasm-side-sub">
              <FolderOpenOutlined /> {t('Plugin directory')}
            </div>
            <div className="wasm-side-path mono">{wasm.wasm_dir || '—'}</div>
            <div className="wasm-side-meta">
              {t('Loaded {loaded} · Rejected {rejected}', {
                loaded: countText(dirLoaded),
                rejected: countText(dirRejected),
              })}
            </div>
          </div>

          <div className="wasm-source">
            <div className="wasm-side-sub">
              <DatabaseOutlined /> {t('PG registry')}
            </div>
            <div className="wasm-side-meta">{pgMeta}</div>
            <div className="wasm-side-meta">
              {t('Loaded {loaded} · Rejected {rejected}', {
                loaded: countText(pg?.loaded),
                rejected: countText(pg?.rejected),
              })}
              {' · '}
              {t('Directory takes precedence')}
            </div>
          </div>
        </aside>
      </div>
    </section>
  )
}

export default function PluginsPage() {
  const { message } = AntApp.useApp()
  const { t } = useI18n()
  const { can } = useAuth()
  const [rows, setRows] = useState<PluginRow[]>([])
  const [wasm, setWasm] = useState<WasmRuntimeState | null>(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [actionOpen, setActionOpen] = useState(false)
  const [form] = Form.useForm()
  const [stats, setStats] = useState<{ ns: string; data: unknown } | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setErr(null)
    try {
      const r: AdminPluginsResp = await listPlugins()
      setRows(r.items ?? [])
      // When the feature is off the API has no wasm field: null = hide the whole block, never fake "disabled"
      setWasm(r.wasm ?? null)
    } catch (e) {
      setErr(errText(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  async function submitAction() {
    const v = await form.validateFields()
    try {
      await pluginAction({
        ns: v.ns,
        version: v.version,
        action: v.action,
        ratio: v.action === 'canary' ? v.ratio : undefined,
        reason: v.reason,
      })
      message.success(t('Submitted; the plugin takes effect on the next call'))
      setActionOpen(false)
      form.resetFields()
      void load()
    } catch (e) {
      message.error(errText(e))
    }
  }

  const action = Form.useWatch('action', form)
  const statEntries = scalarEntries(stats?.data)

  return (
    <div className="page-fill">
      {err && <Alert type="error" showIcon message={t('Failed to load')} description={err} />}

      <Card className="list-card">
        <div className="toolbar">
          {wasm ? (
            <>
              <Tag color={wasm.enabled ? 'green' : 'default'}>
                {wasm.enabled ? t('Runtime enabled') : t('Runtime disabled')}
              </Tag>
              <Tag color={wasm.compiled ? 'blue' : 'default'}>
                {wasm.compiled ? t('Can compile and run') : t('Not compiled')}
              </Tag>
              {wasm.require_verified_signature ? <Tag color="gold">{t('Signed plugins only')}</Tag> : null}
            </>
          ) : null}
          <span className="muted">{t('{count} plugins', { count: rows.length })}</span>
          <HelpTip
            title={t(
              'Server-side plugins (WASM / sidecar) extend format detection and message processing — not the desktop-client Plugin hub. Publishing switches all traffic, canary routes only a share, and rollback returns to an earlier version; every action is written to the audit log.',
            )}
          />
          <div className="toolbar-right">
            <Button icon={<ReloadOutlined />} loading={loading} onClick={load}>
              {t('Refresh')}
            </Button>
            {can('mutate') && (
              <Button
                type="primary"
                icon={<RocketOutlined />}
                onClick={() => {
                  setActionOpen(true)
                }}
              >
                {t('Publish / roll back / canary')}
              </Button>
            )}
          </div>
        </div>

        <div className="card-scroll">
          {/* WASM runtime status: rendered only when the API returns a wasm field (the feature is enabled) */}
          {wasm ? <WasmStatusPanel wasm={wasm} /> : null}

          <section className="panel plugins-registry" style={{ marginTop: wasm ? 18 : 0 }}>
            <div className="panel-head">
              <span className="panel-title">
                {t('Plugin registry')}
                <HelpTip
                  title={t(
                    'Versions of server plugins registered in the PG table: each row is one namespace and the current version is what nodes load. Publish switches all traffic, canary routes only a share, and rollback returns to an earlier version; every action is written to the audit log.',
                  )}
                />
              </span>
              <span className="panel-sub">{t('{count} plugins', { count: rows.length })}</span>
            </div>

            <Table<PluginRow>
              size="small"
              tableLayout="fixed"
              rowKey={(r) => String(r.ns)}
              loading={loading}
              dataSource={rows}
              locale={{
                emptyText: (
                  <div className="plugins-empty">
                    <div>{t('No plugins registered yet')}</div>
                    <div className="muted">
                      {t('Publish a version with "Publish / roll back / canary" and it appears here.')}
                    </div>
                  </div>
                ),
              }}
              pagination={false}
              columns={[
                {
                  title: t('Plugin (namespace)'),
                  dataIndex: 'ns',
              width: 220,
              render: (v: string) => (
                <Tooltip title={v}>
                  <span className="mono plugins-ns">{v}</span>
                </Tooltip>
              ),
            },
            {
              title: t('Execution form'),
              dataIndex: 'form',
              width: 100,
              responsive: ['xl'],
              render: (v: string | undefined) =>
                v ? (
                  <Tag color={v === 'sidecar' ? 'purple' : 'blue'}>{v === 'sidecar' ? t('Sidecar') : 'WASM'}</Tag>
                ) : (
                  '—'
                ),
            },
            {
              title: t('Current version'),
              dataIndex: 'version',
              width: 90,
              render: (v: number | undefined) => (v == null ? '—' : `v${v}`),
            },
            {
              title: t('Status'),
              dataIndex: 'status',
              width: 100,
              render: (v: string | undefined) => (
                <Tag color={toneOf(v)}>{t(pick(PLUGIN_STATUS, v, v ? v : t('Unknown')))}</Tag>
              ),
            },
            {
              title: t('Canary share'),
              dataIndex: 'canary_ratio',
              width: 110,
              render: (v: number | undefined, r) => {
                if (r.status === 'active') return <span className="muted">{t('All traffic')}</span>
                if (r.status === 'canary' && v) return <span>{t('{ratio}% of traffic', { ratio: v })}</span>
                return <span className="muted">—</span>
              },
            },
            {
              title: t('Published'),
              dataIndex: 'published_at',
              width: 150,
              responsive: ['xl'],
              render: (v: string | undefined) =>
                v ? (
                  <Tooltip title={fmtTime(v)}>
                    <span>{fmtRelative(v)}</span>
                  </Tooltip>
                ) : (
                  '—'
                ),
            },
            {
              title: t('Actions'),
              width: 100,
              render: (_, r) => (
                <Button
                  size="small"
                  type="link"
                  onClick={async () => {
                    try {
                      setStats({ ns: r.ns, data: await pluginStats(r.ns) })
                    } catch (e) {
                      message.error(errText(e))
                    }
                  }}
                >
                  {t('View stats')}
                </Button>
              ),
            },
              ]}
            />
          </section>
        </div>
      </Card>

      <Modal
        open={actionOpen}
        title={t('Plugin publish / rollback / canary')}
        okText={t('Submit')}
        cancelText={t('Cancel')}
        onOk={submitAction}
        onCancel={() => setActionOpen(false)}
        destroyOnClose
      >
        <Form form={form} layout="vertical" requiredMark={false} initialValues={{ action: 'publish', ratio: 10 }}>
          <Form.Item
            name="ns"
            label={t('Plugin (namespace)')}
            rules={[{ required: true, message: t('Enter the plugin namespace') }]}
          >
            <Select
              showSearch
              placeholder={t('Select or type a plugin namespace')}
              options={rows.map((r) => ({ value: r.ns, label: r.ns }))}
            />
          </Form.Item>
          <Form.Item
            name="version"
            label={t('Target version')}
            rules={[{ required: true, message: t('Enter a version') }]}
          >
            <InputNumber min={1} precision={0} style={{ width: '100%' }} placeholder={t('e.g. 3')} />
          </Form.Item>
          <Form.Item name="action" label={t('What to do')} rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'publish', label: t('Publish a new version (switch all traffic)') },
                { value: 'canary', label: t('Canary release (route part of the traffic)') },
                { value: 'rollback', label: t('Roll back to a specific version') },
              ]}
            />
          </Form.Item>
          {action === 'canary' && (
            <Form.Item name="ratio" label={t('Canary share (%)')} rules={[{ required: true, message: t('Enter a share') }]}>
              <InputNumber min={1} max={100} style={{ width: '100%' }} placeholder={t('e.g. 10')} />
            </Form.Item>
          )}
          <Form.Item
            name="reason"
            label={t('Action reason (recorded in the audit log)')}
            rules={[{ required: true, message: t('Enter a reason') }]}
          >
            <Input.TextArea
              rows={2}
              placeholder={t('e.g. fix a transcoding memory leak — start with 10% and watch for 30 minutes')}
            />
          </Form.Item>
        </Form>
      </Modal>

      <Drawer
        open={Boolean(stats)}
        width={520}
        title={t('Plugin stats · {ns}', { ns: stats?.ns ?? '' })}
        onClose={() => setStats(null)}
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 13 }}>
          {t(
            'Calls over the last hour: latency, failure rate and peak memory. When the numbers look wrong, consider rolling back first.',
          )}
        </Typography.Paragraph>
        {statEntries.length ? (
          <Descriptions column={1} size="small" bordered style={{ marginBottom: 12 }}>
            {statEntries.map(([k, v]) => (
              <Descriptions.Item key={k} label={k}>
                {v}
              </Descriptions.Item>
            ))}
          </Descriptions>
        ) : null}
      </Drawer>
    </div>
  )
}
