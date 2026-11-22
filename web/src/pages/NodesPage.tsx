import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Alert,
  App as AntApp,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Modal,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography
} from 'antd'
import { ReloadOutlined, ThunderboltOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { drainNode, getDrainProgress, listNodes } from '@/api/endpoints'
import { probeReady } from '@/api/http'
import type { DrainProgress, NodeRow } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { errText } from '@/lib/errors'
import { NODE_HEALTH, pick } from '@/lib/labels'
import { fmtRelative, fmtTime } from '@/lib/format'
import { HelpTip } from '@/components/HelpTip'
import { useI18n } from '@/i18n'

/**
 * Server nodes (PL-16 / ⑤ §8.1): node list + heartbeat + connection count + drain.
 *
 * Draining is a dangerous operation: a reason is mandatory (recorded in the audit log),
 * and the dialog explains the impact and the idempotency semantics. Drain progress is
 * polled once per second until connections reach zero or the wait window expires; failures
 * (403 / network) are shown as-is.
 */
export default function NodesPage() {
  const { t } = useI18n()
  const { can } = useAuth()
  const { message } = AntApp.useApp()
  const [rows, setRows] = useState<NodeRow[]>([])
  const [loading, setLoading] = useState(false)
  const [ready, setReady] = useState<{ ready: boolean; deps: Record<string, string> } | null>(null)
  const [drainOpen, setDrainOpen] = useState(false)
  const [drainTarget, setDrainTarget] = useState<string | null>(null)
  const [draining, setDraining] = useState(false)
  const [drainProgress, setDrainProgress] = useState<DrainProgress | null>(null)
  const [form] = Form.useForm<{ reason: string; wait_seconds: number }>()
  const timer = useRef<number | null>(null)

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const [page, probe] = await Promise.all([listNodes(), probeReady().catch(() => null)])
      setRows(page.items ?? [])
      if (probe) setReady({ ready: probe.ready, deps: probe.deps })
    } catch (e) {
      if (!silent) message.error(errText(e))
    } finally {
      if (!silent) setLoading(false)
    }
  }, [message])

  useEffect(() => {
    void load()
    timer.current = window.setInterval(() => void load(true), 5000)
    return () => {
      if (timer.current) window.clearInterval(timer.current)
    }
  }, [load])

  const openDrain = (nodeId: string) => {
    setDrainTarget(nodeId)
    setDrainProgress(null)
    form.setFieldsValue({ reason: '', wait_seconds: 30 })
    setDrainOpen(true)
  }

  const startDrain = async () => {
    const values = await form.validateFields()
    if (!drainTarget) return
    setDraining(true)
    try {
      await drainNode(drainTarget, { reason: values.reason.trim(), wait_seconds: values.wait_seconds })
      message.success(t('Drain started; draining connections now'))
      let latest: DrainProgress | null = null
      for (let i = 0; i < 35; i += 1) {
        latest = await getDrainProgress(drainTarget)
        setDrainProgress(latest)
        if ((latest.remaining_connections ?? 0) <= 0) break
        await new Promise((r) => window.setTimeout(r, 1000))
      }
      await load(true)
    } catch (e) {
      message.error(errText(e))
    } finally {
      setDraining(false)
    }
  }

  const columns: ColumnsType<NodeRow> = [
    {
      title: t('Node'),
      dataIndex: 'node_id',
      render: (v: string) => (
        <Space direction="vertical" size={0}>
          <Typography.Text copyable>{v}</Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {ready?.deps
              ? t('Dependencies: {deps}', {
                  deps: Object.entries(ready.deps)
                    .map(([k, s]) => `${k}:${s}`)
                    .join(' · '),
                })
              : t('Dependency status unknown')}
          </Typography.Text>
        </Space>
      )
    },
    {
      title: t('Health'),
      dataIndex: 'health',
      width: 110,
      filters: [
        { text: 'ok', value: 'ok' },
        { text: 'degraded', value: 'degraded' },
        { text: 'down', value: 'down' }
      ],
      onFilter: (v, r) => (r.health ?? '') === v,
      render: (v?: string) => (
        <Tag color={v === 'ok' || v === 'healthy' ? 'green' : v ? 'orange' : 'default'}>
          {t(pick(NODE_HEALTH, v, 'Unknown'))}
        </Tag>
      )
    },
    {
      title: t('Version'),
      dataIndex: 'version',
      width: 120,
      render: (v?: string) => v || '—'
    },
    {
      title: t('Connections'),
      dataIndex: 'connections',
      width: 110,
      sorter: (a, b) => (a.connections ?? 0) - (b.connections ?? 0),
      render: (v?: number) => <Typography.Text strong>{v ?? 0}</Typography.Text>
    },
    {
      title: t('Last heartbeat'),
      dataIndex: 'heartbeat_at',
      width: 190,
      render: (v?: string) =>
        v ? (
          <Tooltip title={fmtTime(v)}>
            <span>{fmtRelative(v)}</span>
          </Tooltip>
        ) : (
          <Typography.Text type="secondary">{t('Never reported')}</Typography.Text>
        )
    },
    {
      title: t('Actions'),
      key: 'actions',
      width: 130,
      render: (_, row) => (
        <Tooltip
          title={
            can('dispose')
              ? t('Sends byef(shutdown) to this node, makes /ready return 503 and refuses new WS connections; afterwards the load balancer or process exit finishes the job')
              : t('Your role cannot drain nodes')
          }
        >
          <Button
            size="small"
            danger
            icon={<ThunderboltOutlined />}
            disabled={!can('dispose')}
            onClick={() => openDrain(row.node_id)}
          >
            {t('Drain node')}
          </Button>
        </Tooltip>
      )
    }
  ]

  return (
    <div className="page-scroll">
      <Card
        title={
          <Space>
            {t('Server nodes')}
            <HelpTip title={t('Heartbeats are written every 10s; the connection count is realtime. Draining stops the node from accepting new connections and sends byef to live ones — used for rolling upgrades and decommissioning.')} />
          </Space>
        }
        extra={
          <Space>
            {ready ? (
              <Tag color={ready.ready ? 'green' : 'red'}>{ready.ready ? t('Ready') : t('Not ready')}</Tag>
            ) : null}
            <Button size="small" icon={<ReloadOutlined />} loading={loading} onClick={() => void load()}>
              {t('Refresh')}
            </Button>
          </Space>
        }
      >
        <Table
          rowKey="node_id"
          size="small"
          loading={loading}
          dataSource={rows}
          columns={columns}
          pagination={false}
          scroll={{ x: 820 }}
        />
      </Card>

      <Modal
        open={drainOpen}
        title={t('Drain node: {node}', { node: drainTarget ?? '' })}
        okText={draining ? t('Draining…') : t('Confirm drain')}
        okButtonProps={{ danger: true, loading: draining }}
        onOk={() => void startDrain()}
        onCancel={() => {
          if (!draining) setDrainOpen(false)
        }}
        destroyOnClose
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message={t('Draining makes /ready return 503 immediately, refuses new WS connections and sends byef{shutdown} to live connections. Connected clients must reconnect to another node on their own.')}
        />
        <Form form={form} layout="vertical" preserve={false}>
          <Form.Item
            name="reason"
            label={t('Reason (written to the audit log, required)')}
            rules={[
              { required: true, message: t('A drain reason is required') },
              { max: 200, message: t('Reason is too long (≤200 characters)') }
            ]}
          >
            <Input placeholder={t('e.g. rolling upgrade / node maintenance / fault isolation')} maxLength={200} showCount />
          </Form.Item>
          <Form.Item
            name="wait_seconds"
            label={t('Wait window (seconds, ≤30)')}
            rules={[{ required: true, message: t('A wait window is required') }]}
          >
            <InputNumber min={0} max={30} style={{ width: 160 }} />
          </Form.Item>
        </Form>
        {drainProgress ? (
          <Descriptions size="small" column={1} style={{ marginTop: 12 }} bordered>
            <Descriptions.Item label={t('Current node')}>{drainProgress.node_id}</Descriptions.Item>
            <Descriptions.Item label={t('Remaining connections')}>{drainProgress.remaining_connections ?? '—'}</Descriptions.Item>
            <Descriptions.Item label={t('byef sent')}>{drainProgress.byef_sent ?? drainProgress.sent_byef ?? '—'}</Descriptions.Item>
            <Descriptions.Item label={t('Status')}>{drainProgress.state ?? (draining ? 'draining' : '—')}</Descriptions.Item>
          </Descriptions>
        ) : null}
      </Modal>
    </div>
  )
}
