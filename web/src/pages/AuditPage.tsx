import { useCallback, useEffect, useState } from 'react'
import { LIST_PAGE_SIZE, LIST_SCROLL_Y } from '@/components/listLayout'
import { Alert, App as AntApp, Button, Card, Empty, Input, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { DownloadOutlined, ReloadOutlined } from '@ant-design/icons'
import { errText } from '@/lib/errors'
import { listAudit } from '@/api/endpoints'
import type { AuditRow } from '@/api/types'
import { fmtTime, prettyJson } from '@/lib/format'
import { collectAllPages, csvFilename, downloadText, toCsv } from '@/lib/csv'
import { AUDIT_ACTION, AUDIT_ACTION_OPTIONS, pick } from '@/lib/labels'
import { HelpTip } from '@/components/HelpTip'
import { JsonPeek } from '@/components/JsonPeek'
import { useI18n, type Translate } from '@/i18n'

/** The most useful part of `detail` is the reason, so pull it out for the table; the full payload goes in the expanded row */
function detailSummary(detail: unknown, t: Translate): string {
  if (!detail) return '—'
  if (typeof detail === 'string') return detail
  if (typeof detail === 'object') {
    const obj = detail as Record<string, unknown>
    for (const key of ['reason', 'note', 'message']) {
      if (typeof obj[key] === 'string' && obj[key]) return String(obj[key])
    }
    const keys = Object.keys(obj)
    return keys.length
      ? t('Contains {count} fields: {fields}', { count: keys.length, fields: keys.slice(0, 4).join(', ') })
      : '—'
  }
  return prettyJson(detail)
}

export default function AuditPage() {
  const { message } = AntApp.useApp()
  const { t } = useI18n()
  const [exporting, setExporting] = useState(false)
  const [rows, setRows] = useState<AuditRow[]>([])
  const [total, setTotal] = useState(0)
  const [actor, setActor] = useState('')
  const [action, setAction] = useState('')
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  // How many rows a page holds is derived from the viewport height, so the table fills the card without a scrollbar
  const pageSize = LIST_PAGE_SIZE
  const [err, setErr] = useState<string | null>(null)

  const load = useCallback(
    async (p = page, ps = pageSize) => {
      setLoading(true)
      setErr(null)
      try {
        const r = await listAudit({
          actor: actor || undefined,
          action: action || undefined,
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
    [actor, action, page, pageSize],
  )

  // Load the first page on entry; filters and paging only change state, and this effect re-requests with the
  // **latest** filter values. (The old code called load directly from onSearch/onChange, but that closure still
  // held the previous actor/action, so the first search after typing a filter actually queried the old values and
  // the filter looked broken; see the E23 regression.)
  useEffect(() => {
    void load()
  }, [load])

  /** Export **every page** of the current filter (up to 10,000 rows; when truncated, say so instead of pretending it is complete) */
  const exportCsv = useCallback(async () => {
    setExporting(true)
    try {
      const { rows: all, total, truncated } = await collectAllPages<AuditRow>((p, ps) =>
        listAudit({ actor: actor || undefined, action: action || undefined, page: p, page_size: ps })
      )
      const header = ['id', 'time', 'actor', 'action', 'target', 'detail_summary', 'detail_json']
      const data = all.map((r) => [
        r.id,
        fmtTime(r.created_at),
        r.actor ?? '',
        r.action,
        r.target ?? '',
        detailSummary(r.detail, t),
        r.detail ? JSON.stringify(r.detail) : ''
      ])
      downloadText(csvFilename('lattice-audit'), toCsv(header, data))
      message.success(
        truncated
          ? t('Exported the first {count} rows (of {total}; truncated at the 10,000-row limit)', {
              count: all.length,
              total,
            })
          : t('Exported {count} audit records', { count: all.length })
      )
    } catch (e) {
      message.error(errText(e))
    } finally {
      setExporting(false)
    }
  }, [action, actor, message, t])

  return (
    <div className="page-fill">

      {err && <Alert type="error" showIcon message={t('Failed to load')} description={err} />}

      <Card className="list-card">
        <div className="toolbar">
          <div className="toolbar-right">
            <Button icon={<ReloadOutlined />} loading={loading} onClick={() => load()}>
              {t('Refresh')}
            </Button>
            <Button icon={<DownloadOutlined />} loading={exporting} onClick={() => void exportCsv()}>
              {t('Export CSV')}
            </Button>
          </div>
          <Input.Search
            allowClear
            placeholder={t('Actor user ID')}
            style={{ width: 250 }}
            onSearch={(v) => {
              setPage(1)
              setActor(v.trim())
            }}
          />
          <Select
            allowClear
            showSearch
            placeholder={t('Action type')}
            style={{ width: 260 }}
            value={action || undefined}
            onChange={(v) => {
              setPage(1)
              setAction(v ?? '')
            }}
            filterOption={(input, option) =>
              String(option?.label ?? '').includes(input) || String(option?.value ?? '').includes(input)
            }
            options={AUDIT_ACTION_OPTIONS.map((o) => ({ value: o.value, label: t(o.label) }))}
          />
          <Button
            onClick={() => {
              setPage(1)
              void load(1, pageSize)
            }}
          >
            {t('Search')}
          </Button>
          <HelpTip
            title={t(
              'This version only filters by actor and action type (time-range filtering is not implemented yet), so there is no time picker — that avoids filters that look applied but are not. Expand any row to see the full record of that action; audit data is read-only and cannot be modified or deleted from the console.',
            )}
          />
          <span className="muted">{t('{count} items', { count: total })}</span>
        </div>

        <Table<AuditRow>
          size="small"
          scroll={{ y: LIST_SCROLL_Y }}
          rowKey="id"
          loading={loading}
          dataSource={rows}
          locale={{ emptyText: <Empty description={t('No audit records match the filter')} image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
          expandable={{
            expandedRowRender: (r) => (
              <JsonPeek
                data={r.detail}
                label={t('Full detail field of this audit record (raw response from the audit API)')}
              />
            ),
            rowExpandable: (r) => Boolean(r.detail),
          }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: false,
            onChange: (p) => {
              setPage(p)
            },
            showTotal: (count) => t('{count} items', { count }),
          }}
          columns={[
            { title: t('Time'), dataIndex: 'created_at', width: 160, render: (v) => fmtTime(v) },
            {
              title: t('Action'),
              dataIndex: 'action',
              width: 190,
              render: (v: string) => (
                <Space direction="vertical" size={0}>
                  <span className="cell-title">{t(pick(AUDIT_ACTION, v, v))}</span>
                  <span className="cell-sub">{v}</span>
                </Space>
              ),
            },
            {
              title: t('Actor'),
              dataIndex: 'actor',
              width: 200,
              render: (v: string | null) => <span className="cell-sub">{v ?? t('System')}</span>,
            },
            {
              title: t('Target'),
              dataIndex: 'target',
              width: 200,
              render: (v: string | null) => <span className="cell-sub">{v ?? '—'}</span>,
            },
            {
              title: t('Description'),
              dataIndex: 'detail',
              render: (v: unknown) => (
                <Tooltip title={prettyJson(v)}>
                  <Typography.Text ellipsis style={{ maxWidth: 420, display: 'inline-block', fontSize: 13 }}>
                    {detailSummary(v, t)}
                  </Typography.Text>
                </Tooltip>
              ),
            },
            {
              title: t('Retention'),
              width: 96,
              render: () => <Tag>{t('90 days')}</Tag>,
            },
          ]}
        />
      </Card>
    </div>
  )
}
