import { useCallback, useState } from 'react'
import { Card, Empty, Table, Tag, Tooltip } from 'antd'
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
    <div className="page-fill">
      <Card className="list-card">
        <div className="toolbar">
          <Tag color={deps ? (deps.ready && !depBroken.length ? 'green' : depBroken.length ? 'orange' : 'red') : 'default'}>
            {deps
              ? deps.ready
                ? depBroken.length
                  ? t('Partially degraded')
                  : t('All healthy')
                : t('Not ready')
              : t('Waiting for push')}
          </Tag>
          <span className="muted">{t('{count} nodes', { count: nodes.length })}</span>
          <span className="muted">
            {online?.updated_at ? t('Updated at {time}', { time: fmtTime(online.updated_at) }) : t('Waiting for push')}
          </span>
          <HelpTip
            title={t(
              'All data on this page is pushed by the server over the realtime channel (the same stream that reports online users, node heartbeats and dependency health); nothing is polled. When the connection limit is reached it falls back to a 5s refresh.',
            )}
          />
          <div className="toolbar-right">
            <Tag color={sseInfo.tone}>{t(sseInfo.text)}</Tag>
          </div>
        </div>

        <div className="card-scroll">
          <div className="metric-strip">
            <div className="metric-cell">
              <div className="metric-head">
                <span>{t('Online users')}</span>
                <TeamOutlined />
              </div>
              <div className="metric-value">{online?.online_users ?? '—'}</div>
              <div className="metric-hint">{t('Accounts with at least one live connection')}</div>
            </div>
            <div className="metric-cell">
              <div className="metric-head">
                <span>{t('Online devices')}</span>
                <ApiOutlined />
              </div>
              <div className="metric-value">{online?.online_devices ?? '—'}</div>
              <div className="metric-hint">
                {t('Established client connections (one person on several devices counts once per device)')}
              </div>
            </div>
            <div className="metric-cell">
              <div className="metric-head">
                <span>{t('Cluster nodes')}</span>
                <CloudServerOutlined />
              </div>
              <div className="metric-value">{nodes.length || '—'}</div>
              <div className="metric-hint">
                {nodes.length > 1
                  ? t('Multi-node deployment; connections are spread across nodes')
                  : t('Single-node deployment')}
              </div>
            </div>
            <div className="metric-cell">
              <div className="metric-head">
                <span>{t('Realtime channel')}</span>
                <ThunderboltOutlined />
              </div>
              <div className="metric-value small">
                <Tag color={sseInfo.tone}>{t(sseInfo.text)}</Tag>
              </div>
              <div className="metric-hint">
                {lastError ??
                  (lastAt ? t('Last push at {time}', { time: fmtTime(lastAt) }) : t('Waiting for the first push…'))}
              </div>
            </div>
          </div>

          <div className="split-2" style={{ marginTop: 14 }}>
            <section className="panel">
              <div className="panel-head">
                <span className="panel-title">
                  {t('Service dependencies')}
                  <HelpTip
                    title={t(
                      'Base services the platform depends on. When any of them is unhealthy, write operations fail (reads may still work). The server pushes this status every 5 seconds.',
                    )}
                  />
                </span>
                <Tag color={deps?.ready && !depBroken.length ? 'green' : 'red'}>
                  {deps
                    ? deps.ready
                      ? depBroken.length
                        ? t('Partially degraded')
                        : t('All healthy')
                      : t('Not ready')
                    : t('Waiting for push')}
                </Tag>
              </div>

              {depRows.length === 0 ? (
                <Empty description={t('Waiting for the server to push dependency status')} image={Empty.PRESENTED_IMAGE_SIMPLE} />
              ) : (
                <div>
                  {depRows.map(([key, value]) => (
                    <div key={key} className="kv-row">
                      <span className="k">
                        {t(DEP_LABEL[key] ?? key)}
                        <span className="dep-key">{key}</span>
                      </span>
                      <Tag color={value === 'ok' ? 'green' : 'red'}>
                        {value === 'ok' ? t('OK') : value === 'degraded' ? t('Degraded') : t('Unavailable')}
                      </Tag>
                    </div>
                  ))}
                  <div className="muted" style={{ paddingTop: 4 }}>
                    {t('Node ID')} <span className="inline-mono">{deps?.node_id ?? '—'}</span>
                    {deps?.version ? ` · ${t('Version')} ${deps.version}` : ''}
                  </div>
                </div>
              )}
            </section>

            <section className="panel">
              <div className="panel-head">
                <span className="panel-title">
                  {t('Server nodes')}
                  <HelpTip
                    title={t(
                      'Every server in the cluster. A node whose connection count stays at 0 or whose heartbeat stops is probably offline. Heartbeats are written every 10 seconds; the connection count is realtime.',
                    )}
                  />
                </span>
                <span className="panel-sub">{t('{count} nodes', { count: nodes.length })}</span>
              </div>
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
            </section>
          </div>

          <section className="panel" style={{ marginTop: 18 }}>
            <div className="panel-head">
              <span className="panel-title">
                {t('Current snapshot')}
                <HelpTip
                  title={t('Online index summary pushed once per second, including the breakdown by protocol and by node.')}
                />
              </span>
              <span className="panel-sub">
                {online?.updated_at ? t('Updated at {time}', { time: fmtTime(online.updated_at) }) : t('Waiting for push')}
              </span>
            </div>

            <div>
              <div className="kv-row">
                <span className="k">{t('Reporting node')}</span>
                <span className="v mono">{online?.node_id ?? '—'}</span>
              </div>
              <div className="kv-row">
                <span className="k">{t('By protocol')}</span>
                <span className="v">
                  {Object.entries(online?.by_protocol ?? {})
                    .map(([k, v]) => `${k} ${v}`)
                    .join(' · ') || '—'}
                </span>
              </div>
              <div className="kv-row">
                <span className="k">{t('By node')}</span>
                <span className="v">
                  {Object.entries(online?.by_node ?? {})
                    .map(([k, v]) => `${k} ${v}`)
                    .join(' · ') || '—'}
                </span>
              </div>
              <div className="kv-row">
                <span className="k">{t('Node uptime')}</span>
                <span className="v">
                  {typeof online?.uptime_s === 'number'
                    ? t('{hours} h {minutes} min', {
                        hours: Math.floor(online.uptime_s / 3600),
                        minutes: Math.floor((online.uptime_s % 3600) / 60),
                      })
                    : '—'}
                </span>
              </div>
            </div>

            <JsonPeek data={online} label={t('Raw payload (all fields of the online event)')} />
          </section>
        </div>
      </Card>
    </div>
  )
}
