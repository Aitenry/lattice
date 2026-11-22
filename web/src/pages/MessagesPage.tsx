import { useCallback, useState } from 'react'
import { LIST_PAGE_SIZE, LIST_SCROLL_Y } from '@/components/listLayout'
import {
  Alert,
  Button,
  Card,
  Drawer,
  Empty,
  Input,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  App as AntApp,
} from 'antd'
import { DownloadOutlined, SearchOutlined } from '@ant-design/icons'
import { errText } from '@/lib/errors'
import { getDelivery, searchMessages } from '@/api/endpoints'
import type { DeliveryRow, MessageRow } from '@/api/types'
import { fmtBytes, fmtTime } from '@/lib/format'
import { DELIVERY_STATE, DELIVERY_STATE_HINT, pick, toneOf } from '@/lib/labels'
import { HelpTip } from '@/components/HelpTip'
import { collectAllPages, csvFilename, downloadText, toCsv } from '@/lib/csv'
import { JsonPeek } from '@/components/JsonPeek'
import { useI18n } from '@/i18n'

const STATES = ['persisted', 'routed', 'delivered', 'acked', 'expired', 'dlq', 'failed']

export default function MessagesPage() {
  const { t } = useI18n()
  const { message } = AntApp.useApp()
  const [rows, setRows] = useState<MessageRow[]>([])
  const [loading, setLoading] = useState(false)
  // Rows per page follow the viewport height so the table fills the card without a scrollbar
  const pageSize = LIST_PAGE_SIZE
  const [err, setErr] = useState<string | null>(null)
  const [searched, setSearched] = useState(false)
  const [total, setTotal] = useState(0)
  const [exporting, setExporting] = useState(false)

  const [byId, setById] = useState('')
  const [byConv, setByConv] = useState('')
  const [byUser, setByUser] = useState('')
  const [state, setState] = useState<string | undefined>()
  const [page, setPage] = useState(1)

  const [delivery, setDelivery] = useState<{ id: string; deliveries: DeliveryRow[] } | null>(null)

  const run = useCallback(
    async (p = page, ps = pageSize) => {
      if (!byId && !byConv && !byUser) {
        setErr(
          t(
            'Enter at least one search condition (message ID, conversation ID or sender ID). An unfiltered full-table search would strain the database, so the server rejects it.',
          ),
        )
        return
      }
      setLoading(true)
      setErr(null)
      setSearched(true)
      try {
        const r = await searchMessages({
          id: byId || undefined,
          conv: byConv || undefined,
          user: byUser || undefined,
          state,
          page: p,
          page_size: ps,
        })
        setRows(r.items ?? [])
        setTotal(r.total ?? 0)
      } catch (e) {
        setErr(errText(e))
      } finally {
        setLoading(false)
      }
    },
    [byId, byConv, byUser, state, page, pageSize, t],
  )

  const hasFilter = Boolean(byId || byConv || byUser)
  const exportCsv = useCallback(async () => {
    if (!hasFilter) {
      message.warning(t('Enter at least one search condition before exporting (an unfiltered export would saturate the database)'))
      return
    }
    setExporting(true)
    try {
      const { rows: all, total: serverTotal, truncated } = await collectAllPages<MessageRow>((p, ps) =>
        searchMessages({
          id: byId || undefined,
          conv: byConv || undefined,
          user: byUser || undefined,
          state,
          page: p,
          page_size: ps
        })
      )
      const header = ['id', 'conv_id', 'sender', 'env_type', 'content_type', 'size_bytes', 'seq', 'status', 'created_at', 'expires_at', 'payload_ref']
      const data = all.map((r) => [
        r.id, r.conv_id, r.sender ?? '', r.env_type ?? '', r.content_type ?? '', r.size ?? '',
        r.seq, r.status, fmtTime(r.created_at), r.expires_at ? fmtTime(r.expires_at) : '', r.payload_ref ?? ''
      ])
      downloadText(csvFilename('lattice-messages'), toCsv(header, data))
      message.success(
        truncated
          ? t('Exported the first {count} rows (of {total}; truncated at the 10,000-row limit)', {
              count: all.length,
              total: serverTotal,
            })
          : t('Exported metadata for {count} messages', { count: all.length }),
      )
    } catch (e) {
      message.error(errText(e))
    } finally {
      setExporting(false)
    }
  }, [byConv, byId, byUser, hasFilter, message, state, t])

  const summary = delivery
    ? delivery.deliveries.reduce(
        (acc, d) => {
          const tone = toneOf(d.state)
          if (tone === 'success') acc.acked += 1
          else if (tone === 'error') acc.failed += 1
          else acc.pending += 1
          return acc
        },
        { acked: 0, pending: 0, failed: 0 },
      )
    : { acked: 0, pending: 0, failed: 0 }

  return (
    <div className="page-fill">

      {err && <Alert type="error" showIcon message={t('Search failed')} description={err} />}

      <Card className="list-card">
        <div className="toolbar">
          <Input
            allowClear
            placeholder={t('Message ID')}
            style={{ width: 230 }}
            value={byId}
            onChange={(e) => setById(e.target.value.trim())}
          />
          <Input
            allowClear
            placeholder={t('Conversation ID')}
            style={{ width: 230 }}
            value={byConv}
            onChange={(e) => setByConv(e.target.value.trim())}
          />
          <Input
            allowClear
            placeholder={t('Sender user ID')}
            style={{ width: 200 }}
            value={byUser}
            onChange={(e) => setByUser(e.target.value.trim())}
          />
          <Select
            allowClear
            placeholder={t('Delivery state')}
            style={{ width: 150 }}
            value={state}
            onChange={setState}
            options={STATES.map((s) => ({ value: s, label: t(pick(DELIVERY_STATE, s)) }))}
          />
          <HelpTip title={t('Fill in at least one of the three conditions; results contain metadata only, never content — messages are encrypted on the client before upload, so the server only holds ciphertext. Reading content is a separate compliance process ("inspectable mode") that requires explicit authorisation and full audit; it is not available in this console.')} />
          <div className="toolbar-right">
            <Button icon={<DownloadOutlined />} loading={exporting} onClick={() => void exportCsv()}>
              {t('Export CSV')}
            </Button>
            <Button
              type="primary"
              icon={<SearchOutlined />}
              loading={loading}
              onClick={() => {
                setPage(1)
                void run(1, pageSize)
              }}
            >
              {t('Search')}
            </Button>
          </div>
        </div>

        <Table<MessageRow>
          size="small"
          scroll={{ y: LIST_SCROLL_Y }}
          rowKey="id"
          loading={loading}
          dataSource={rows}
          locale={{
            emptyText: (
              <Empty
                description={searched ? t('No matching messages') : t('Fill in a condition and click "Search"')}
                image={Empty.PRESENTED_IMAGE_SIMPLE}
              />
            ),
          }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: false,
            onChange: (p) => {
              setPage(p)
              void run(p)
            },
            showTotal: (count) => t('{count} rows', { count }),
          }}
          columns={[
            {
              title: t('Message'),
              dataIndex: 'id',
              render: (v: string) => <span className="cell-sub">{v}</span>,
            },
            {
              title: t('Conversation'),
              dataIndex: 'conv_id',
              render: (v: string) => <span className="cell-sub">{v}</span>,
            },
            { title: t('Type'), dataIndex: 'env_type', width: 100, render: (v) => v || t('Regular message') },
            { title: t('Size'), dataIndex: 'size', width: 90, render: (v) => fmtBytes(v) },
            {
              title: (
                <Space size={2}>
                  {t('Sequence')}
                  <HelpTip title={t('Increments within a conversation; clients use it to detect missed messages.')} />
                </Space>
              ),
              dataIndex: 'seq',
              width: 80,
            },
            {
              title: t('Delivery state'),
              dataIndex: 'status',
              width: 130,
              render: (v: string) => (
                <Tooltip title={t(DELIVERY_STATE_HINT[v] ?? '')}>
                  <Tag color={toneOf(v)}>{t(pick(DELIVERY_STATE, v, v))}</Tag>
                </Tooltip>
              ),
            },
            { title: t('Created'), dataIndex: 'created_at', width: 160, render: (v) => fmtTime(v) },
            {
              title: t('Actions'),
              width: 104,
              render: (_, r) => (
                <Button
                  size="small"
                  type="link"
                  onClick={async () => {
                    try {
                      setDelivery(await getDelivery(r.id))
                    } catch (e) {
                      message.error(errText(e))
                    }
                  }}
                >
                  {t('Delivery details')}
                </Button>
              ),
            },
          ]}
        />
      </Card>

      <Drawer
        open={Boolean(delivery)}
        width={640}
        title={t('Delivery details')}
        onClose={() => setDelivery(null)}
      >
        {delivery && (
          <Space direction="vertical" size={14} style={{ width: '100%' }}>
            <Space size={8} wrap>
              <Tag color="green">{t('Acknowledged {count}', { count: summary.acked })}</Tag>
              <Tag color="blue">{t('In progress {count}', { count: summary.pending })}</Tag>
              <Tag color="red">{t('Failed {count}', { count: summary.failed })}</Tag>
            </Space>
            <Typography.Text type="secondary" style={{ fontSize: 13 }}>
              {t('A message may be delivered to several devices at once. Only "acknowledged" means the client really received it.')}
            </Typography.Text>
            <Table<DeliveryRow>
              size="small"
              rowKey={(r) => `${r.to_user}:${r.device}`}
              dataSource={delivery.deliveries}
              pagination={false}
              locale={{ emptyText: <Empty description={t('This message has no delivery records')} image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
              columns={[
                {
                  title: t('Recipient'),
                  dataIndex: 'to_user',
                  render: (v) => <span className="cell-sub">{v}</span>,
                },
                {
                  title: t('Device'),
                  dataIndex: 'device',
                  render: (v) => <span className="cell-sub">{v}</span>,
                },
                {
                  title: t('Status'),
                  dataIndex: 'state',
                  width: 120,
                  render: (v: string) => (
                    <Tooltip title={t(DELIVERY_STATE_HINT[v] ?? '')}>
                      <Tag color={toneOf(v)}>{t(pick(DELIVERY_STATE, v, v))}</Tag>
                    </Tooltip>
                  ),
                },
                { title: t('Attempts'), dataIndex: 'attempts', width: 90 },
                { title: t('Last attempt'), dataIndex: 'last_at', width: 150, render: (v) => fmtTime(v) },
                { title: t('Acknowledged at'), dataIndex: 'acked_at', width: 150, render: (v) => fmtTime(v) },
              ]}
            />
            <JsonPeek data={delivery} label={t('Raw response of the delivery-detail endpoint (GET /v1/admin/messages/{id}/delivery)')} />
          </Space>
        )}
      </Drawer>
    </div>
  )
}
