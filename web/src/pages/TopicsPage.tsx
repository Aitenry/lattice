import { useCallback, useEffect, useState } from 'react'
import { App as AntApp, Button, Card, Empty, Input, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { listConversations } from '@/api/endpoints'
import type { ConvRow } from '@/api/types'
import { LIST_PAGE_SIZE, LIST_SCROLL_Y } from '@/components/listLayout'
import { errText } from '@/lib/errors'
import { fmtRelative, fmtTime } from '@/lib/format'
import { HelpTip } from '@/components/HelpTip'
import { useI18n } from '@/i18n'

/**
 * Broadcast topics (PL-16 / ⑤ §7): a Topic reuses conversations(kind='topic'); this is
 * just a read-only console view (member count, last seq, last message time) — subscription
 * relations are in the conversation detail / audit logs.
 *
 * Why no "New topic": subscribe and publish are **user-facing** semantics
 * (`/v1/topics/{t}/subscribe`), so the console does not subscribe on users' behalf; it is
 * for troubleshooting only. The empty state says topics are "created when a client subscribes".
 */
export default function TopicsPage() {
  const { t } = useI18n()
  const { message } = AntApp.useApp()
  const [items, setItems] = useState<ConvRow[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const pageSize = LIST_PAGE_SIZE
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await listConversations({ kind: 'topic', q: q.trim() || undefined, page, page_size: pageSize })
      setItems(data.items ?? [])
      setTotal(data.total ?? 0)
    } catch (e) {
      message.error(errText(e))
    } finally {
      setLoading(false)
    }
  }, [message, page, pageSize, q])

  useEffect(() => {
    void load()
  }, [load])

  const columns: ColumnsType<ConvRow> = [
    {
      title: t('Topic'),
      dataIndex: 'id',
      render: (v: string, row) => (
        <Space direction="vertical" size={0}>
          <Typography.Text copyable>{v}</Typography.Text>
          {row.name ? (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {row.name}
            </Typography.Text>
          ) : null}
        </Space>
      )
    },
    {
      title: t('Subscribers'),
      dataIndex: 'members',
      width: 110,
      sorter: (a, b) => (a.members ?? 0) - (b.members ?? 0),
      render: (v?: number) => <Tag color={(v ?? 0) > 0 ? 'blue' : 'default'}>{t('{count} members', { count: v ?? 0 })}</Tag>
    },
    {
      title: t('Last seq'),
      dataIndex: 'last_seq',
      width: 120,
      render: (v?: number | null) => (v == null ? '—' : <Typography.Text code>{v}</Typography.Text>)
    },
    {
      title: t('Last message'),
      dataIndex: 'last_msg_at',
      width: 190,
      render: (v?: string | null) =>
        v ? (
          <Tooltip title={fmtTime(v)}>
            <span>{fmtRelative(v)}</span>
          </Tooltip>
        ) : (
          <Typography.Text type="secondary">{t('None')}</Typography.Text>
        )
    },
    {
      title: t('Type'),
      dataIndex: 'kind',
      width: 90,
      render: () => <Tag>topic</Tag>
    }
  ]

  return (
    <div className="page-fill">
      <Card className="list-card">
        <div className="toolbar">
          <Input
            allowClear
            prefix={<SearchOutlined />}
            placeholder={t('Search by topic ID or name')}
            value={q}
            onChange={(e) => {
              setQ(e.target.value)
              setPage(1)
            }}
            onPressEnter={() => void load()}
            style={{ width: 260 }}
          />
          <span className="muted">{t('{count} topics', { count: total })}</span>
          <HelpTip
            title={t(
              'A topic is created when a client calls /v1/topics/{t}/subscribe; offline broadcast messages are backfilled from the topic_offsets watermark. This is a troubleshooting view only; it does not subscribe for users.',
            )}
          />
          <div className="toolbar-right">
            <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void load()}>
              {t('Refresh')}
            </Button>
          </div>
        </div>

        <Table
          rowKey="id"
          size="small"
          loading={loading}
          dataSource={items}
          columns={columns}
          locale={{
            emptyText: (
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description={t('No broadcast topics yet (created when a client first subscribes)')}
              />
            ),
          }}
          scroll={{ y: LIST_SCROLL_Y }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: false,
            showTotal: (count) => t('{count} topics', { count }),
            onChange: (p) => setPage(p),
          }}
        />
      </Card>
    </div>
  )
}
