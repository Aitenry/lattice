import { useCallback, useEffect, useState } from 'react'
import { LIST_PAGE_SIZE, LIST_SCROLL_Y } from '@/components/listLayout'
import { Alert, Button, Card, Descriptions, Drawer, Empty, Input, Select, Space, Table, Tag, Tooltip, Typography, App as AntApp } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { errText } from '@/lib/errors'
import { getConversation, listConversations } from '@/api/endpoints'
import type { ConvDetail, ConvRow } from '@/api/types'
import { fmtRelative, fmtTime } from '@/lib/format'
import { CONV_KIND, CONV_KIND_HINT, pick } from '@/lib/labels'
import { HelpTip } from '@/components/HelpTip'
import { useI18n } from '@/i18n'

const KIND_COLOR: Record<string, string> = { dm: 'blue', group: 'purple', topic: 'gold' }

const MEMBER_ROLE: Record<string, string> = {
  owner: 'Group owner',
  admin: 'Group admin',
  member: 'Group member',
}

export default function ConversationsPage() {
  const { t } = useI18n()
  const { message } = AntApp.useApp()
  const [rows, setRows] = useState<ConvRow[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [q, setQ] = useState('')
  const [kind, setKind] = useState<string | undefined>()
  const [loading, setLoading] = useState(false)
  // Rows per page follow the viewport height so the table fills the card without a scrollbar
  const pageSize = LIST_PAGE_SIZE
  const [err, setErr] = useState<string | null>(null)
  const [detail, setDetail] = useState<ConvDetail | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setErr(null)
    try {
      const r = await listConversations({ q: q || undefined, kind, page, page_size: pageSize })
      setRows(r.items ?? [])
      setTotal(r.total ?? 0)
    } catch (e) {
      setErr(errText(e))
    } finally {
      setLoading(false)
    }
  }, [q, kind, page, pageSize])

  useEffect(() => {
    void load()
  }, [load])

  return (
    <div className="page-fill">

      {err && <Alert type="error" showIcon message={t('Failed to load')} description={err} />}

      <Card className="list-card">
        <div className="toolbar">
          <div className="toolbar-right">
            <Button icon={<ReloadOutlined />} loading={loading} onClick={load}>
              {t('Refresh')}
            </Button>
          </div>
          <Input.Search
            allowClear
            placeholder={t('Search conversation name or ID')}
            style={{ width: 260 }}
            onSearch={(v) => {
              setPage(1)
              setQ(v.trim())
            }}
          />
          <Select
            allowClear
            placeholder={t('Conversation type')}
            style={{ width: 160 }}
            value={kind}
            onChange={(v) => {
              setPage(1)
              setKind(v)
            }}
            options={[
              { value: 'dm', label: t('Direct') },
              { value: 'group', label: t('Group') },
              { value: 'topic', label: t('Broadcast') },
            ]}
          />
          <span className="muted">{t('{count} conversations', { count: total })}</span>
        </div>

        <Table<ConvRow>
          size="small"
          scroll={{ y: LIST_SCROLL_Y }}
          rowKey="id"
          loading={loading}
          dataSource={rows}
          locale={{ emptyText: <Empty description={t('No matching conversations')} image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: false,
            onChange: (p) => setPage(p),
            showTotal: (count) => t('{count} conversations', { count }),
          }}
          columns={[
            {
              title: t('Conversation'),
              dataIndex: 'name',
              render: (v: string | null, r) => (
                <Space direction="vertical" size={0}>
                  <span className="cell-title">
                    {v || t('Unnamed {kind}', { kind: t(pick(CONV_KIND, r.kind, 'conversation')) })}
                  </span>
                  <span className="cell-sub">{r.id}</span>
                </Space>
              ),
            },
            {
              title: t('Type'),
              dataIndex: 'kind',
              width: 110,
              render: (v: string) => (
                <Tooltip title={t(CONV_KIND_HINT[v] ?? '')}>
                  <Tag color={KIND_COLOR[v] ?? 'default'}>{t(pick(CONV_KIND, v, v))}</Tag>
                </Tooltip>
              ),
            },
            { title: t('Member count'), dataIndex: 'members', width: 96, render: (v) => v ?? '—' },
            {
              title: (
                <Space size={2}>
                  {t('Latest sequence')}
                  <HelpTip title={t('Messages inside a conversation are numbered sequentially; clients use the number to backfill missed messages. A static number means no new messages recently.')} />
                </Space>
              ),
              dataIndex: 'last_seq',
              width: 110,
              render: (v) => v ?? '—',
            },
            {
              title: t('Last message'),
              dataIndex: 'last_msg_at',
              width: 130,
              render: (v: string | null) =>
                v ? (
                  <Tooltip title={fmtTime(v)}>
                    <span>{fmtRelative(v)}</span>
                  </Tooltip>
                ) : (
                  <span className="muted">{t('No messages yet')}</span>
                ),
            },
            {
              title: t('Actions'),
              width: 90,
              render: (_, r) => (
                <Button
                  size="small"
                  type="link"
                  onClick={async () => {
                    try {
                      setDetail(await getConversation(r.id))
                    } catch (e) {
                      message.error(errText(e))
                    }
                  }}
                >
                  {t('View members')}
                </Button>
              ),
            },
          ]}
        />
      </Card>

      <Drawer open={Boolean(detail)} width={520} title={t('Conversation details')} onClose={() => setDetail(null)}>
        {detail && (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label={t('Name')}>{detail.name || t('Unnamed conversation')}</Descriptions.Item>
              <Descriptions.Item label={t('Type')}>
                <Tag color={KIND_COLOR[detail.kind] ?? 'default'}>{t(pick(CONV_KIND, detail.kind, detail.kind))}</Tag>
                <span className="muted" style={{ marginLeft: 8 }}>
                  {t(CONV_KIND_HINT[detail.kind] ?? '')}
                </span>
              </Descriptions.Item>
              <Descriptions.Item label={t('Created')}>{fmtTime(detail.created_at)}</Descriptions.Item>
              <Descriptions.Item label={t('Conversation ID')}>
                <Typography.Text className="mono" copyable>
                  {detail.id}
                </Typography.Text>
              </Descriptions.Item>
            </Descriptions>

            <div>
              <Typography.Text strong>{t('Members ({count})', { count: detail.members.length })}</Typography.Text>
              <Table
                style={{ marginTop: 8 }}
                size="small"
                rowKey="user_id"
                pagination={false}
                dataSource={detail.members}
                columns={[
                  {
                    title: t('User ID'),
                    dataIndex: 'user_id',
                    render: (v: string) => <span className="cell-sub">{v}</span>,
                  },
                  {
                    title: t('Role in conversation'),
                    dataIndex: 'role',
                    width: 140,
                    render: (v: string) => t(pick(MEMBER_ROLE, v, v)),
                  },
                ]}
              />
            </div>
          </Space>
        )}
      </Drawer>
    </div>
  )
}
