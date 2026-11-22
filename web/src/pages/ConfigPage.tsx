import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Card,
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
  App as AntApp,
} from 'antd'
import { EditOutlined, ReloadOutlined } from '@ant-design/icons'
import { errText } from '@/lib/errors'
import { getConfig, patchConfig } from '@/api/endpoints'
import type { ConfigItem, ConfigSnapshot } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { fmtBytes } from '@/lib/format'
import { CONFIG_KEY, CONFIG_KEY_HINT, pick } from '@/lib/labels'
import { HelpTip } from '@/components/HelpTip'
import { JsonPeek } from '@/components/JsonPeek'
import { useI18n, type Translate } from '@/i18n'

/** Turn a config value into one plain-language line (the main table column); the raw JSON lives in the technical details */
function valueSummary(key: string, value: unknown, t: Translate): string {
  if (value == null) return t('Not set')
  if (key === 'ratelimit' && typeof value === 'object') {
    const v = value as Record<string, unknown>
    const rate = v['msg_per_s']
    const bytes = v['bytes_per_s']
    return [
      typeof rate === 'number' ? t('{rate} msg/s', { rate }) : t('No rate limit'),
      typeof bytes === 'number' ? t('Bandwidth {size}/s', { size: fmtBytes(bytes) }) : null,
    ]
      .filter(Boolean)
      .join(' · ')
  }
  if (key === 'canary' && typeof value === 'object') {
    const v = value as Record<string, unknown>
    const plugin = v['plugin']
    const ratio = v['ratio']
    if (!plugin) return t('Canary disabled')
    return t('Plugin {plugin}, canary {ratio}% of traffic', { plugin: String(plugin), ratio: String(ratio ?? '—') })
  }
  if (key === 'plugins_enabled' && Array.isArray(value)) {
    return value.length ? value.join(', ') : t('No plugins enabled')
  }
  // The server currently returns individual settings by dotted key (ratelimit.bytes_per_s and friends):
  // a bare number is not readable in a table, so turn it into plain language; the raw value stays in "technical details".
  if (key === 'ratelimit.bytes_per_s' && typeof value === 'number') {
    return t('{size}/s per user', { size: fmtBytes(value) })
  }
  if (key === 'ratelimit.topics_per_user' && typeof value === 'number') {
    return t('{count} topics per user', { count: value })
  }
  if (key === 'canary.ratio' && typeof value === 'number') {
    return t('Canary {ratio}% of traffic', { ratio: value })
  }
  if (key === 'plugins.enabled' && typeof value === 'boolean') {
    return value ? t('Enabled') : t('Not enabled')
  }
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

export default function ConfigPage() {
  const { message } = AntApp.useApp()
  const { t } = useI18n()
  const { can } = useAuth()
  const [snap, setSnap] = useState<ConfigSnapshot | null>(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [editKey, setEditKey] = useState<string | null>(null)
  const [form] = Form.useForm()

  const load = useCallback(async () => {
    setLoading(true)
    setErr(null)
    try {
      setSnap(await getConfig())
    } catch (e) {
      setErr(errText(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  function openEdit(key: string, _item: ConfigItem | undefined) {
    // Only switch the key: initial values come from the Modal Form's initialValues (setFieldsValue is lost under destroyOnClose)
    form.resetFields()
    setEditKey(key)
  }

  async function submit() {
    if (!editKey) return
    const f = await form.validateFields()
    let value: unknown
    if (editKey === 'ratelimit') {
      value = {
        msg_per_s: f.msg_per_s ?? undefined,
        bytes_per_s: f.bytes_per_s_mb ? Math.round(Number(f.bytes_per_s_mb) * 1048576) : undefined,
      }
    } else if (editKey === 'canary') {
      value = { plugin: f.plugin, ratio: f.ratio }
    } else if (editKey === 'plugins_enabled') {
      value = f.plugins ?? []
    } else {
      try {
        value = JSON.parse(f.json)
      } catch {
        message.error(t('Not valid JSON; check the brackets and quotes'))
        return
      }
    }
    try {
      const r = await patchConfig({ [editKey]: value, reason: f.reason } as never)
      message.success(
        t('Applied: {keys}', {
          keys:
            (r.changed ?? [])
              .map((k) => t(pick(CONFIG_KEY, k, k)))
              .join(', ') || t('no changes'),
        }),
      )
      setEditKey(null)
      form.resetFields()
      void load()
    } catch (e) {
      message.error(errText(e))
    }
  }

  const items = snap?.items ?? {}
  const keys = Object.keys(items)
  const editValue = editKey ? (items[editKey]?.value ?? null) : null
  const editInitial = (() => {
    if (!editKey) return {}
    const v = (editValue ?? {}) as Record<string, unknown>
    if (editKey === 'ratelimit') {
      return {
        msg_per_s: v['msg_per_s'],
        bytes_per_s_mb:
          typeof v['bytes_per_s'] === 'number' ? Math.round((v['bytes_per_s'] as number) / 1048576) : undefined,
      }
    }
    if (editKey === 'canary') return { plugin: v['plugin'], ratio: v['ratio'] }
    if (editKey === 'plugins_enabled') return { plugins: Array.isArray(editValue) ? editValue : [] }
    return { json: JSON.stringify(editValue ?? null, null, 2) }
  })()

  return (
    <div className="page-scroll">

      <div className="toolbar">
        <div className="toolbar-right">
        <Button icon={<ReloadOutlined />} loading={loading} onClick={load}>
          {t('Refresh')}
        </Button>
        </div>
      </div>

      {err && <Alert type="error" showIcon message={t('Failed to load')} description={err} />}

      <Card
        title={
          <Space size={4}>
            {t('Current configuration')}
            <HelpTip
              title={t(
                'Configuration is stored in the database and broadcast to every node after a change; each node keeps a short-lived cache, so changes apply within a few seconds.',
              )}
            />
          </Space>
        }
        extra={<Typography.Text type="secondary">{t('{count} settings', { count: keys.length })}</Typography.Text>}
      >
        <Table<{ key: string; item: ConfigItem }>
          size="small"
          rowKey="key"
          loading={loading}
          dataSource={keys.map((k) => ({ key: k, item: items[k] }))}
          pagination={false}
          locale={{ emptyText: <Empty description={t('No configuration items')} image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
          expandable={{
            expandedRowRender: (r) => (
              <JsonPeek data={r.item} label={t('Raw value of configuration key {key}', { key: r.key })} />
            ),
          }}
          columns={[
            {
              title: t('Configuration key'),
              dataIndex: 'key',
              width: 280,
              render: (v: string) => (
                <Space direction="vertical" size={0}>
                  <span className="cell-title">{t(pick(CONFIG_KEY, v, v))}</span>
                  <span className="cell-sub">{v}</span>
                </Space>
              ),
            },
            {
              title: t('Current value'),
              dataIndex: 'item',
              render: (_: unknown, r) => (
                <Space direction="vertical" size={0}>
                  <span style={{ fontSize: 13 }}>{valueSummary(r.key, r.item?.value, t)}</span>
                  {CONFIG_KEY_HINT[r.key] ? <span className="muted" style={{ fontSize: 12 }}>{t(CONFIG_KEY_HINT[r.key])}</span> : null}
                </Space>
              ),
            },
            {
              title: t('Value source'),
              dataIndex: 'item',
              width: 140,
              render: (_: unknown, r) => (
                <Tag color="purple">
                  {r.item?.source === 'db' || String(r.item?.source ?? '').startsWith('pg')
                    ? t('Database (authoritative)')
                    : r.item?.source ?? t('Unknown')}
                </Tag>
              ),
            },
            {
              title: t('Actions'),
              width: 90,
              render: (_, r) =>
                can('mutate') ? (
                  <Button size="small" type="link" icon={<EditOutlined />} onClick={() => openEdit(r.key, r.item)}>
                    {t('Edit')}
                  </Button>
                ) : (
                  <Typography.Text type="secondary">—</Typography.Text>
                ),
            },
          ]}
        />
      </Card>

      <Modal
        open={Boolean(editKey)}
        title={t('Edit "{name}"', { name: t(pick(CONFIG_KEY, editKey ?? '', editKey ?? '')) })}
        okText={t('Save and apply')}
        cancelText={t('Cancel')}
        onOk={submit}
        onCancel={() => setEditKey(null)}
        destroyOnClose
      >
        <Form form={form} key={editKey ?? 'config'} layout="vertical" requiredMark={false} initialValues={editInitial}>
          {editKey === 'ratelimit' && (
            <>
              <Form.Item name="msg_per_s" label={t('Max messages per second per user')}>
                <InputNumber min={1} max={10000} style={{ width: '100%' }} placeholder={t('e.g. 100')} />
              </Form.Item>
              <Form.Item name="bytes_per_s_mb" label={t('Max bandwidth per second per user (MB)')}>
                <InputNumber min={0.1} step={1} style={{ width: '100%' }} placeholder={t('e.g. 25')} />
              </Form.Item>
            </>
          )}
          {editKey === 'canary' && (
            <>
              <Form.Item name="plugin" label={t('Plugin namespace')}>
                <Input placeholder={t('e.g. lattice.plugin.transcode')} />
              </Form.Item>
              <Form.Item name="ratio" label={t('Canary share (%)')}>
                <InputNumber min={0} max={100} style={{ width: '100%' }} placeholder={t('e.g. 5')} />
              </Form.Item>
            </>
          )}
          {editKey === 'plugins_enabled' && (
            <Form.Item name="plugins" label={t('Enabled plugins (multiple allowed)')}>
              <Select mode="tags" placeholder={t('Type a plugin namespace and press Enter')} />
            </Form.Item>
          )}
          {editKey && !['ratelimit', 'canary', 'plugins_enabled'].includes(editKey) && (
            <Form.Item name="json" label={t('Configuration value (JSON)')} rules={[{ required: true, message: t('Required') }]}>
              <Input.TextArea rows={6} style={{ fontFamily: 'monospace' }} />
            </Form.Item>
          )}
          <Form.Item
            name="reason"
            label={t('Reason for the change (recorded in the audit log)')}
            rules={[{ required: true, message: t('Enter a reason') }]}
          >
            <Input.TextArea rows={2} placeholder={t('e.g. upstream pressure is high — temporarily lower the rate limit to 50 msg/s')} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
