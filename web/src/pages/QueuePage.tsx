import { useState } from 'react'
import { Alert, Button, Card, Col, Empty, Input, Row, Select, Space, Table, Tag, Typography, App as AntApp } from 'antd'
import { DeleteOutlined, SearchOutlined } from '@ant-design/icons'
import { errText } from '@/lib/errors'
import { getQueue, purgeQueue } from '@/api/endpoints'
import type { QueueResp } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { ReasonModal } from '@/components/ReasonModal'
import { StatCard } from '@/components/StatCard'
import { HelpTip } from '@/components/HelpTip'
import { QUEUE_SCOPE, pick } from '@/lib/labels'
import { useI18n } from '@/i18n'

const SCOPES = [
  { value: 'user', label: 'All devices of this user' },
  { value: 'device', label: 'Single device' },
  { value: 'topic', label: 'Topic subscription' },
] as const

export default function QueuePage() {
  const { message } = AntApp.useApp()
  const { t } = useI18n()
  const { can } = useAuth()
  const [user, setUser] = useState('')
  const [scope, setScope] = useState<'user' | 'device' | 'topic'>('user')
  const [data, setData] = useState<QueueResp | null>(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [purgeOpen, setPurgeOpen] = useState(false)

  async function query() {
    if (!user) {
      setErr(t('Enter a user ID first (you can find one on the Users page)'))
      return
    }
    setLoading(true)
    setErr(null)
    try {
      setData(await getQueue({ user, scope }))
    } catch (e) {
      setErr(errText(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page-scroll">

      {err && <Alert type="error" showIcon message={t('Query failed')} description={err} />}

      <Card>
        <div className="toolbar">
          <div className="toolbar-right">
            {can('dispose') && (
              <Button danger icon={<DeleteOutlined />} disabled={!data} onClick={() => setPurgeOpen(true)}>
                {t('Purge queue')}
              </Button>
            )}
          </div>
          <Input
            allowClear
            placeholder={t('User ID')}
            style={{ width: 320 }}
            value={user}
            onChange={(e) => setUser(e.target.value.trim())}
          />
          <Select
            style={{ width: 200 }}
            value={scope}
            onChange={setScope}
            options={SCOPES.map((s) => ({ value: s.value, label: t(s.label) }))}
          />
          <Button type="primary" icon={<SearchOutlined />} loading={loading} onClick={query}>
            {t('Search')}
          </Button>
        </div>

        {data ? (
          <>
            <Row gutter={[16, 16]} style={{ marginTop: 4 }}>
              <Col xs={24} sm={12} xl={6}>
                <StatCard
                  label={t('Messages awaiting delivery')}
                  value={data.depth}
                  hint={t('Messages to deliver in order once the recipient comes online')}
                  tone="blue"
                />
              </Col>
              <Col xs={24} sm={12} xl={6}>
                <StatCard
                  label={t('Oldest sequence number')}
                  value={data.oldest_seq ?? '—'}
                  hint={t('A smaller sequence number means the backlog is older')}
                  tone="slate"
                />
              </Col>
              <Col xs={24} sm={12} xl={6}>
                <StatCard
                  label={t('Largest per-device backlog')}
                  value={data.device_depth}
                  hint={t('The busiest device after splitting the backlog by device')}
                  tone="orange"
                />
              </Col>
              <Col xs={24} sm={12} xl={6}>
                <StatCard
                  label={t('Scope')}
                  value={<Tag color="blue">{t(pick(QUEUE_SCOPE, data.scope, data.scope))}</Tag>}
                  small
                  hint={t('User {user}', { user: data.user })}
                  tone="violet"
                />
              </Col>
            </Row>
            <Table
              style={{ marginTop: 12 }}
              size="small"
              rowKey="k"
              pagination={false}
              dataSource={[
                { k: t('Queue depth'), v: t('{count} items', { count: data.depth }) },
                { k: t('Oldest undelivered sequence'), v: data.oldest_seq ?? '—' },
                { k: t('Largest per-device backlog'), v: t('{count} items', { count: data.device_depth }) },
                { k: t('Scope'), v: t(pick(QUEUE_SCOPE, data.scope, data.scope)) },
                { k: t('User'), v: data.user },
              ]}
              columns={[
                { title: t('Item'), dataIndex: 'k', width: 200 },
                { title: t('Value'), dataIndex: 'v', render: (v) => <span className="mono">{v}</span> },
              ]}
            />
          </>
        ) : (
          <Empty
            description={t('Enter a user ID and click "Search" to see that user\'s backlog')}
            image={Empty.PRESENTED_IMAGE_SIMPLE}
          />
        )}
      </Card>

      <Card
        title={
          <Space size={4}>
            {t('What purging does')}
            <HelpTip
              title={t('Purging only affects the pending queue; messages already stored in the database are not deleted.')}
            />
          </Space>
        }
      >
        <div className="soft-panel">
          <p style={{ margin: 0 }}>
            {t(
              'The queue is ordered by message sequence (that is what preserves order when catching up), so a purge by time cannot delete everything in one step: the server pulls batches of sequence numbers, looks up each message timestamp, and deletes only the ones that match. With a large backlog the purge is slower — that is expected.',
            )}
          </p>
          <p style={{ margin: '8px 0 0' }}>
            {t(
              'With no time bound it empties the entire selected scope, which is a plain delete and the fastest option. Purged messages are not re-delivered, but the messages themselves stay in the database and can be found by ID in message search.',
            )}
          </p>
        </div>
      </Card>

      <ReasonModal
        open={purgeOpen}
        danger
        title={t('Purge offline queue · {user}', { user })}
        description={t(
          'Scope: {scope}. Purged messages are not re-delivered, but the message bodies are kept.',
          { scope: t(pick(QUEUE_SCOPE, scope, scope)) },
        )}
        okText={t('Confirm purge')}
        onCancel={() => setPurgeOpen(false)}
        onSubmit={async (why) => {
          const r = await purgeQueue({ user, scope, reason: why })
          message.success(
            t('Purged {removed} messages{scanned}', {
              removed: r.removed,
              scanned: r.scanned != null ? t(' (scanned {count})', { count: r.scanned }) : '',
            }),
          )
          void query()
        }}
      />

      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {t(
          'Tip: when the goal is to get messages to a user again, check whether their device is online before purging the queue.',
        )}
      </Typography.Text>
    </div>
  )
}
