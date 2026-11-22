import { useCallback, useState } from 'react'
import { Card, Col, Empty, Row, Space, Table, Tag, Tooltip, Typography } from 'antd'
import {
  ApiOutlined,
  CloudServerOutlined,
  TeamOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import type { NodeRow, StreamEvent } from '@/api/types'
import { useAdminStream } from '@/lib/useSse'
import { listNodes, getOnlineStats } from '@/api/endpoints'
import { probeReady } from '@/api/http'
import { fmtRelative, fmtTime } from '@/lib/format'
import { NODE_HEALTH, pick } from '@/lib/labels'
import { StatCard } from '@/components/StatCard'
import { HelpTip } from '@/components/HelpTip'
import { JsonPeek } from '@/components/JsonPeek'
import { useI18n } from '@/i18n'

/**
 * Overview page: in normal operation **all data comes from server pushes** (⑤ §8.5 SSE
 * realtime stream); this page has no timers and no refresh button. Only when the SSE
 * connection count hits its limit (429) does §8.5 degrade to 5s REST polling (`poll`).
 *
 * Three events each feed one block:
 * - `online` (1s) → online users / online devices / current snapshot
 * - `node`   (2s) → server node table
 * - `deps`   (5s) → service dependencies
 *
 * Why: polling has two flaws — numbers are always "at most N seconds old", and one
 * refresh fires a burst of requests; pushes arrive only when something changes, and
 * every number on the page carries its push time.
 */

interface OnlineSnap {
  online_users?: number
  online_devices?: number
  by_protocol?: Record<string, number>
  by_node?: Record<string, number>
  node_id?: string
  uptime_s?: number
  updated_at?: string
}

interface DepsSnap {
  ready?: boolean
  deps?: Record<string, string>
  node_id?: string
  version?: string
}

const DEP_LABEL: Record<string, string> = {
  pg: 'Database',
  redis: 'Cache',
  s3: 'Object storage',
  bus: 'Message bus',
}

const SSE_TEXT: Record<string, { text: string; tone: string }> = {
  open: { text: 'Live', tone: 'green' },
  connecting: { text: 'Connecting', tone: 'blue' },
  polling: { text: 'Connection limit reached · polling every 5s', tone: 'orange' },
  error: { text: 'Disconnected', tone: 'red' },
  idle: { text: 'Not enabled', tone: 'default' },
}

export default function OverviewPage() {
  const { t } = useI18n()
  const [online, setOnline] = useState<OnlineSnap | null>(null)
  const [nodes, setNodes] = useState<NodeRow[]>([])
  const [deps, setDeps] = useState<DepsSnap | null>(null)
  const [lastAt, setLastAt] = useState<string | null>(null)

  // ⑤ §8.5 429 fallback: poll the same data every 5s (REST is not capped by the SSE connection limit)
  const pollSnapshot = useCallback(async () => {
    try {
      const [stats, nodesPage, ready] = await Promise.all([getOnlineStats(), listNodes(), probeReady()])
      setOnline(stats as OnlineSnap)
      setNodes(nodesPage.items ?? [])
      setDeps(ready as DepsSnap)
      setLastAt(new Date().toISOString())
    } catch {
      /* keep the previous frame while dependencies are down; the next poll/push restores it */
    }
  }, [])

  const { status, lastError } = useAdminStream({
    enabled: true,
    poll: pollSnapshot,
    onEvent: (e: StreamEvent) => {
      const d = (e.data ?? {}) as Record<string, unknown>
      if (e.event === 'online') {
        setOnline(d as OnlineSnap)
        setLastAt(new Date().toISOString())
      } else if (e.event === 'node') {
        setNodes((d.items as NodeRow[]) ?? [])
      } else if (e.event === 'deps') {
        setDeps(d as DepsSnap)
      }
    },
  })

  const sseInfo = SSE_TEXT[status] ?? SSE_TEXT.idle
  const depRows = Object.entries(deps?.deps ?? {})
  const depBroken = depRows.filter(([, v]) => v !== 'ok')

  return (
    <div className="page-scroll">
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            label={t('Online users')}
            value={online?.online_users ?? '—'}
            hint={t('Accounts with at least one live connection')}
            icon={<TeamOutlined />}
            tone="blue"
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            label={t('Online devices')}
            value={online?.online_devices ?? '—'}
            hint={t('Established client connections (one person on several devices counts once per device)')}
            icon={<ApiOutlined />}
            tone="violet"
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            label={t('Cluster nodes')}
            value={nodes.length || '—'}
            hint={
              nodes.length > 1
                ? t('Multi-node deployment; connections are spread across nodes')
                : t('Single-node deployment')
            }
            icon={<CloudServerOutlined />}
            tone="slate"
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <StatCard
            label={t('Realtime channel')}
            value={<Tag color={sseInfo.tone}>{t(sseInfo.text)}</Tag>}
            small
            hint={
              lastError ??
              (lastAt ? t('Last push at {time}', { time: fmtTime(lastAt) }) : t('Waiting for the first push…'))
            }
            icon={<ThunderboltOutlined />}
            tone={status === 'open' ? 'green' : 'orange'}
          />
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={10}>
          <Card
            title={
              <Space size={4}>
                {t('Service dependencies')}
                <HelpTip
                  title={t(
                    'Base services the platform depends on. When any of them is unhealthy, write operations fail (reads may still work). The server pushes this status every 5 seconds.',
                  )}
                />
              </Space>
            }
            extra={
              <Tag color={deps?.ready && !depBroken.length ? 'green' : 'red'}>
                {deps
                  ? deps.ready
                    ? depBroken.length
                      ? t('Partially degraded')
                      : t('All healthy')
                    : t('Not ready')
                  : t('Waiting for push')}
              </Tag>
            }
          >
            {depRows.length === 0 ? (
              <Empty description={t('Waiting for the server to push dependency status')} image={Empty.PRESENTED_IMAGE_SIMPLE} />
            ) : (
              <Space direction="vertical" size={10} style={{ width: '100%' }}>
                {depRows.map(([key, value]) => (
                  <div
                    key={key}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      width: '100%',
                    }}
                  >
                    <span>
                      {t(DEP_LABEL[key] ?? key)}
                      <span className="table-id" style={{ marginLeft: 8 }}>
                        {key}
                      </span>
                    </span>
                    <Tag color={value === 'ok' ? 'green' : 'red'}>
                      {value === 'ok' ? t('OK') : value === 'degraded' ? t('Degraded') : t('Unavailable')}
                    </Tag>
                  </div>
                ))}
                <div className="muted" style={{ paddingTop: 4 }}>
                  {t('Node ID')} <span className="mono">{deps?.node_id ?? '—'}</span>
                  {deps?.version ? ` · ${t('Version')} ${deps.version}` : ''}
                </div>
              </Space>
            )}
          </Card>
        </Col>

        <Col xs={24} lg={14}>
          <Card
            title={
              <Space size={4}>
                {t('Server nodes')}
                <HelpTip
                  title={t(
                    'Every server in the cluster. A node whose connection count stays at 0 or whose heartbeat stops is probably offline. Heartbeats are written every 10 seconds; the connection count is realtime.',
                  )}
                />
              </Space>
            }
            extra={<Typography.Text type="secondary">{t('{count} nodes', { count: nodes.length })}</Typography.Text>}
          >
            <Table<NodeRow>
              size="small"
              rowKey={(r) => String(r.node_id)}
              dataSource={nodes}
              pagination={false}
              locale={{
                emptyText: (
                  <Empty description={t('Waiting for the server to push node heartbeats')} image={Empty.PRESENTED_IMAGE_SIMPLE} />
                ),
              }}
              columns={[
                {
                  title: t('Node'),
                  dataIndex: 'node_id',
                  render: (v: string) => <span className="cell-sub">{v}</span>,
                },
                { title: t('Version'), dataIndex: 'version', width: 90, render: (v) => v ?? '—' },
                {
                  title: t('Connections'),
                  dataIndex: 'connections',
                  width: 90,
                  render: (v) => (v ?? 0).toLocaleString(),
                },
                {
                  title: t('Health'),
                  dataIndex: 'health',
                  width: 96,
                  render: (v: string | undefined) => (
                    <Tag color={v === 'ok' || v === 'healthy' ? 'green' : v ? 'orange' : 'default'}>
                      {t(pick(NODE_HEALTH, v, 'Unknown'))}
                    </Tag>
                  ),
                },
                {
                  title: t('Last heartbeat'),
                  dataIndex: 'heartbeat_at',
                  width: 120,
                  render: (v: string | undefined) => (
                    <Tooltip title={fmtTime(v)}>
                      <span>{fmtRelative(v)}</span>
                    </Tooltip>
                  ),
                },
              ]}
            />
          </Card>
        </Col>
      </Row>

      <Card
        title={
          <Space size={4}>
            {t('Current snapshot')}
            <HelpTip
              title={t('Online index summary pushed once per second, including the breakdown by protocol and by node.')}
            />
          </Space>
        }
        extra={
          <Typography.Text type="secondary">
            {online?.updated_at ? t('Updated at {time}', { time: fmtTime(online.updated_at) }) : t('Waiting for push')}
          </Typography.Text>
        }
      >
        <Space direction="vertical" size={8} style={{ width: '100%' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
            <span className="muted">{t('Reporting node')}</span>
            <span className="mono">{online?.node_id ?? '—'}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
            <span className="muted">{t('By protocol')}</span>
            <span style={{ fontSize: 13 }}>
              {Object.entries(online?.by_protocol ?? {})
                .map(([k, v]) => `${k} ${v}`)
                .join(' · ') || '—'}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
            <span className="muted">{t('By node')}</span>
            <span style={{ fontSize: 13 }}>
              {Object.entries(online?.by_node ?? {})
                .map(([k, v]) => `${k} ${v}`)
                .join(' · ') || '—'}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
            <span className="muted">{t('Node uptime')}</span>
            <span style={{ fontSize: 13 }}>
              {typeof online?.uptime_s === 'number'
                ? t('{hours} h {minutes} min', {
                    hours: Math.floor(online.uptime_s / 3600),
                    minutes: Math.floor((online.uptime_s % 3600) / 60),
                  })
                : '—'}
            </span>
          </div>
          <JsonPeek data={online} label={t('Raw payload (all fields of the online event)')} />
        </Space>
      </Card>
    </div>
  )
}
