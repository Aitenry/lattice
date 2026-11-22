import { useCallback, useEffect, useState } from 'react'
import { LIST_PAGE_SIZE, LIST_SCROLL_Y } from '@/components/listLayout'
import { Alert, Button, Card, Empty, Input, Space, Table, Tag, Tooltip, App as AntApp } from 'antd'
import { ReloadOutlined, RedoOutlined } from '@ant-design/icons'
import { errText } from '@/lib/errors'
import { listDlq, replayDlq } from '@/api/endpoints'
import type { DlqRow } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { ReasonModal } from '@/components/ReasonModal'
import { fmtTime } from '@/lib/format'
import { DELIVERY_STATE, DELIVERY_STATE_HINT, pick, toneOf } from '@/lib/labels'
import { useI18n } from '@/i18n'

export default function DlqPage() {
  const { message } = AntApp.useApp()
  const { t } = useI18n()
  const { can } = useAuth()
  const [rows, setRows] = useState<DlqRow[]>([])
  const [conv, setConv] = useState('')
  const [user, setUser] = useState('')
  const [loading, setLoading] = useState(false)
  // How many rows a page holds is derived from the viewport height, so the table fills the card without a scrollbar
  const pageSize = LIST_PAGE_SIZE
  const [err, setErr] = useState<string | null>(null)
  const [selected, setSelected] = useState<string[]>([])
  const [replayOpen, setReplayOpen] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setErr(null)
    try {
      const r = await listDlq({ conv: conv || undefined, user: user || undefined })
      setRows(r.items ?? [])
      setSelected([])
    } catch (e) {
      setErr(errText(e))
    } finally {
      setLoading(false)
    }
  }, [conv, user])

  useEffect(() => {
    void load()
  }, [load])

  const rowKey = (r: DlqRow) => r.msg_id ?? r.id ?? JSON.stringify(r)

  return (
    <div className="page-fill">

      {err && <Alert type="error" showIcon message={t('Failed to load')} description={err} />}

      <Card className="list-card">
        <div className="toolbar">
          <div className="toolbar-right">
            <Space>
              <Button icon={<ReloadOutlined />} loading={loading} onClick={load}>
                {t('Refresh')}
              </Button>
              {can('dispose') && (
                <Button
                  type="primary"
                  icon={<RedoOutlined />}
                  disabled={!selected.length}
                  onClick={() => setReplayOpen(true)}
                >
                  {t('Replay selected ({count})', { count: selected.length })}
                </Button>
              )}
            </Space>
          </div>
          <Input.Search
            allowClear
            placeholder={t('Filter by conversation ID')}
            style={{ width: 250 }}
            onSearch={(v) => setConv(v.trim())}
          />
          <Input.Search
            allowClear
            placeholder={t('Filter by recipient user ID')}
            style={{ width: 250 }}
            onSearch={(v) => setUser(v.trim())}
          />
          <span className="muted">{t('{count} items', { count: rows.length })}</span>
        </div>

        <div className="soft-panel" style={{ marginBottom: 12 }}>
          <b>{t('What replay does:')}</b>{' '}
          {t(
            'Puts these messages back into the delivery queue and sends them again in the original order. Messages that have expired or been deleted cannot be replayed; after you submit, they are listed separately and do not count as a failure.',
          )}
        </div>

        <Table<DlqRow>
          size="small"
          scroll={{ y: LIST_SCROLL_Y }}
          rowKey={rowKey}
          loading={loading}
          dataSource={rows}
          locale={{
            emptyText: (
              <Empty
                description={t('No failed messages — the delivery queue is healthy')}
                image={Empty.PRESENTED_IMAGE_SIMPLE}
              />
            ),
          }}
          rowSelection={{
            selectedRowKeys: selected,
            onChange: (keys) => setSelected(keys.map(String)),
            getCheckboxProps: (r) => ({ disabled: !r.msg_id }),
          }}
          pagination={{ pageSize, showTotal: (count) => t('{count} items', { count }) }}
          columns={[
            {
              title: t('Message'),
              dataIndex: 'msg_id',
              render: (v: string | undefined) => <span className="cell-sub">{v ?? '—'}</span>,
            },
            {
              title: t('Recipient'),
              dataIndex: 'to_user',
              render: (v: string | undefined) => <span className="cell-sub">{v ?? '—'}</span>,
            },
            {
              title: t('Target device'),
              dataIndex: 'device',
              render: (v: string | undefined) => <span className="cell-sub">{v ?? '—'}</span>,
            },
            {
              title: t('Status'),
              dataIndex: 'state',
              width: 120,
              render: (v: string | undefined) => (
                <Tooltip title={t(DELIVERY_STATE_HINT[v ?? ''] ?? '')}>
                  <Tag color={toneOf(v)}>{t(pick(DELIVERY_STATE, v, '—'))}</Tag>
                </Tooltip>
              ),
            },
            {
              title: t('Attempts'),
              dataIndex: 'attempts',
              width: 90,
              render: (v) => (v == null ? '—' : t('{count} attempts', { count: v })),
            },
            { title: t('Last attempt'), dataIndex: 'last_at', width: 160, render: (v) => fmtTime(v as string | null) },
          ]}
        />
      </Card>

      <ReasonModal
        open={replayOpen}
        title={t('Replay {count} failed messages', { count: selected.length })}
        description={t(
          'Messages are delivered again in the original order. If a message has expired or has been deleted, the server rejects it and returns it separately; the rest are re-sent as usual.',
        )}
        okText={t('Confirm replay')}
        onCancel={() => setReplayOpen(false)}
        onSubmit={async (why) => {
          const r = await replayDlq({ msg_ids: selected, reason: why })
          if (r.rejected?.length) {
            message.warning(
              t('Accepted {accepted}; {rejected} could not be replayed (expired or deleted)', {
                accepted: r.accepted,
                rejected: r.rejected.length,
              }),
            )
          } else {
            message.success(
              t('Accepted {count}; check the final state on the Messages page later', { count: r.accepted }),
            )
          }
          void load()
        }}
      />
    </div>
  )
}
