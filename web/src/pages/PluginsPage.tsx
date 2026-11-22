import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  App as AntApp,
  Button,
  Card,
  Descriptions,
  Drawer,
  Empty,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd'
import {
  AppstoreOutlined,
  DatabaseOutlined,
  FolderOpenOutlined,
  ReloadOutlined,
  RocketOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { errText } from '@/lib/errors'
import { listPlugins, pluginAction, pluginStats } from '@/api/endpoints'
import type { AdminPluginsResp, PluginRow, WasmRuntimeState } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { PLUGIN_STATUS, pick, toneOf } from '@/lib/labels'
import { fmtBytes } from '@/lib/format'
import { JsonPeek } from '@/components/JsonPeek'
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
 * Data comes from the `wasm` section of `GET /v1/admin/plugins`: enabled/compiled/trusted_keys/
 * loaded/rejected/sources stats. **When the feature is off the API omits this field and the whole card is hidden**
 * (the caller decides); nothing here guesses defaults or allows any action.
 */
function WasmStatusPanel({ wasm, loading }: { wasm: WasmRuntimeState; loading: boolean }) {
  const { t } = useI18n()
  const loaded = Array.isArray(wasm.loaded) ? wasm.loaded : []
  const rejected = Array.isArray(wasm.rejected) ? wasm.rejected : []
  const dir = wasm.sources?.dir ?? null
  const pg = wasm.sources?.pg ?? null
  const enabled = Boolean(wasm.enabled)
  const compiled = Boolean(wasm.compiled)
  const trustLabel =
    typeof wasm.signature_verification === 'string' && wasm.signature_verification && wasm.signature_verification !== 'not_implemented'
      ? wasm.signature_verification
      : t('Signature verification off')
  const dirLoaded = dir?.loaded
  const dirRejected = dir?.rejected

  return (
    <div className="wasm-panel" data-testid="wasm-panel">
      <div className="wasm-panel-head">
        <div>
          <div className="wasm-panel-title">
            <ThunderboltOutlined />
            {t('WASM plugin sandbox')}
            <Tag color={enabled ? 'green' : 'default'}>{enabled ? t('Runtime enabled') : t('Runtime disabled')}</Tag>
            <Tag color={compiled ? 'blue' : 'default'}>{compiled ? t('Can compile and run') : t('Not compiled')}</Tag>
            {wasm.require_verified_signature ? <Tag color="gold">{t('Signed plugins only')}</Tag> : null}
          </div>
          <div className="wasm-panel-sub">
            {t(
              'Read-only status, from the WASM section of the plugin API. WASM plugins run inside a wasmtime sandbox: it limits resources, but',
            )}
            <b>{t(' not a substitute for signatures')}</b>
            {t(': plugins that fail signature verification are refused, and node readiness is unaffected.')}
          </div>
        </div>
        {typeof wasm.wasm_dir === 'string' && wasm.wasm_dir ? (
          <span className="wasm-panel-sub">
            <FolderOpenOutlined /> {wasm.wasm_dir}
          </span>
        ) : null}
      </div>

      <div className="wasm-stats">
        <div className="wasm-stat">
          <div className="wasm-stat-label">{t('Runtime')}</div>
          <div className="wasm-stat-value small">{enabled ? t('Enabled') : t('Not enabled')}</div>
          <div className="wasm-stat-hint">{compiled ? t('Module compilation ready') : t('Module compilation unavailable')}</div>
        </div>
        <div className="wasm-stat">
          <div className="wasm-stat-label">{t('Loaded plugins')}</div>
          <div className="wasm-stat-value">{countText(loaded.length)}</div>
          <div className="wasm-stat-hint">
            {t('Directory {fromDir} · Database {fromDb}', { fromDir: countText(dirLoaded), fromDb: countText(pg?.loaded) })}
          </div>
        </div>
        <div className="wasm-stat">
          <div className="wasm-stat-label">{t('Trusted public keys')}</div>
          <div className="wasm-stat-value">{countText(wasm.trusted_keys)}</div>
          <div className="wasm-stat-hint">{trustLabel}</div>
        </div>
        <div className="wasm-stat">
          <div className="wasm-stat-label">{t('Rejected')}</div>
          <div className="wasm-stat-value" style={{ color: rejected.length ? 'var(--tone-orange-fg)' : undefined }}>
            {countText(rejected.length)}
          </div>
          <div className="wasm-stat-hint">{t('Fail-closed: a rejection never blocks startup')}</div>
        </div>
        <div className="wasm-stat">
          <div className="wasm-stat-label">{t('Source · plugin directory')}</div>
          <div className="wasm-stat-value small">
            {t('Loaded {loaded} · Rejected {rejected}', {
              loaded: countText(dirLoaded),
              rejected: countText(dirRejected),
            })}
          </div>
          <div className="wasm-stat-hint">{t('wasm_dir scan')}</div>
        </div>
        <div className="wasm-stat">
          <div className="wasm-stat-label">{t('Source · PG registry')}</div>
          <div className="wasm-stat-value small">
            {pg?.enabled === false
              ? t('Not enabled')
              : t('Loaded {loaded} · Rejected {rejected}', {
                  loaded: countText(pg?.loaded),
                  rejected: countText(pg?.rejected),
                })}
          </div>
          <div className="wasm-stat-hint">
            {typeof pg?.rows === 'number' ? t('Queried {count} rows · ', { count: pg.rows }) : ''}
            {typeof pg?.conflicts === 'number' ? t('{count} conflicts · ', { count: pg.conflicts }) : ''}
            {t('Directory takes precedence')}
          </div>
        </div>
      </div>

      {loaded.length ? (
        <div>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t('Loaded (source: {source}; in load order)', {
              source: wasm.from_db ? t('directory + database') : t('directory'),
            })}
          </Typography.Text>
          <Space wrap size={[8, 8]} style={{ marginTop: 8 }}>
            {loaded.map((entry, index) => {
              const item = entry as Record<string, unknown>
              const source = typeof item.source === 'string' ? item.source : null
              const version = typeof item.version === 'string' ? item.version : null
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
        <Empty
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          description={
            <span className="wasm-panel-sub">
              {enabled
                ? t('The WASM runtime is enabled, but no plugin is loaded yet.')
                : t('The WASM runtime is disabled, and no plugin is loaded.')}{' '}
              {t('Put signed plugins into')}{' '}
              <span className="mono">{wasm.wasm_dir || 'wasm_dir'}</span>
              {t(', or publish them in the PG plugin registry and refresh this page. Unsigned plugins and plugins that fail verification are listed under "Rejected".')}
            </span>
          }
        />
      )}

      {rejected.length ? (
        <div>
          <Alert
            type="warning"
            showIcon
            icon={<WarningOutlined />}
            message={t('{count} plugins were refused (fail-closed; other plugins and node readiness are unaffected)', {
              count: rejected.length,
            })}
            style={{ marginBottom: 8 }}
          />
          <div className="wasm-reject-list">
            {rejected.slice(0, 5).map((entry, index) => {
              const item = entry as Record<string, unknown>
              const kind = typeof item.kind === 'string' ? item.kind : 'unknown'
              const plugin = typeof item.plugin === 'string' ? item.plugin : typeof item.ns === 'string' ? item.ns : '—'
              const reason = typeof item.reason === 'string' ? item.reason : ''
              return (
                <div key={`${plugin}-${index}`} className="wasm-reject-item">
                  <span className="kind">{kind}</span>
                  <span className="plugin">{plugin}</span>
                  <span style={{ minWidth: 0 }}>{reason}</span>
                </div>
              )
            })}
            {rejected.length > 5 ? (
              <span className="wasm-panel-sub">{t('Showing the first 5 only; see technical details for every reason.')}</span>
            ) : null}
          </div>
        </div>
      ) : null}

      <div className="wasm-foot">
        <span>
          <AppstoreOutlined />{' '}
          {t('Max module {size}', {
            size: typeof wasm.max_wasm_bytes === 'number' ? fmtBytes(wasm.max_wasm_bytes) : '—',
          })}
        </span>
        <span>
          <SafetyCertificateOutlined />{' '}
          {t('Trusted keys: {count}', { count: wasm.trusted_key_ids?.length ?? wasm.trusted_keys ?? 0 })}
        </span>
        <span>
          <DatabaseOutlined />{' '}
          {wasm.from_db ? t('Reads the database registry') : t('Does not read the database registry')}
        </span>
      </div>

      <JsonPeek data={wasm} label={t('Raw response of the WASM section of the plugin API (read-only; with load and rejection details and safety notes)')} />
      {loading ? <span className="wasm-panel-sub">{t('Refreshing…')}</span> : null}
    </div>
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
    <div className="page-scroll">
      <div className="toolbar">
        <div className="toolbar-right">
          <Space>
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
          </Space>
        </div>
      </div>

      {err && <Alert type="error" showIcon message={t('Failed to load')} description={err} />}

      {/* WASM runtime status card: rendered only when the API returns a wasm field (the feature is enabled) */}
      {wasm ? <WasmStatusPanel wasm={wasm} loading={loading} /> : null}

      <Card>
        <Table<PluginRow>
          size="small"
          rowKey={(r) => String(r.ns)}
          loading={loading}
          dataSource={rows}
          locale={{ emptyText: <Empty description={t('No plugins registered yet')} image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
          pagination={false}
          columns={[
            {
              title: t('Plugin'),
              dataIndex: 'ns',
              render: (v: string) => <span className="cell-sub">{v}</span>,
            },
            { title: t('Current version'), dataIndex: 'version', width: 120, render: (v) => v ?? '—' },
            {
              title: t('Status'),
              dataIndex: 'status',
              width: 120,
              render: (v: string | undefined) => (
                <Tag color={toneOf(v)}>{t(pick(PLUGIN_STATUS, v, v ? v : t('Unknown')))}</Tag>
              ),
            },
            {
              title: t('Canary share'),
              dataIndex: 'canary_ratio',
              width: 110,
              render: (v: number | undefined) =>
                v == null ? (
                  <span className="muted">{t('All traffic')}</span>
                ) : (
                  <span>{t('{ratio}% of traffic', { ratio: v })}</span>
                ),
            },
            { title: t('Calls'), dataIndex: 'calls', width: 100, render: (v) => (v == null ? '—' : v.toLocaleString()) },
            {
              title: t('Actions'),
              width: 90,
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
          <Form.Item name="version" label={t('Target version')} rules={[{ required: true, message: t('Enter a version') }]}>
            <Input placeholder={t('e.g. 1.4.2')} />
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
        <JsonPeek data={stats?.data} label={t('Raw response of the plugin stats endpoint (GET /v1/admin/plugins/{ns}/stats)')} />
      </Drawer>
    </div>
  )
}
