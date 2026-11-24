import { useCallback, useEffect, useState } from 'react'
import { Alert, App as AntApp, Button, Card, Empty, Input, Modal, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { CheckOutlined, CloseOutlined, ReloadOutlined } from '@ant-design/icons'
import { approveHubVersion, listHubReviews, rejectHubVersion } from '@/api/endpoints'
import type { HubReviewRow } from '@/api/types'
import { LIST_PAGE_SIZE, LIST_SCROLL_Y } from '@/components/listLayout'
import { HelpTip } from '@/components/HelpTip'
import { useI18n } from '@/i18n'
import { errText } from '@/lib/errors'
import { fmtBytes, fmtRelative, fmtTime } from '@/lib/format'
import { hubOwnerLabel } from '@/lib/labels'

/**
 * Plugin review (administrator only).
 *
 * Review lives on its own page: it is a gate over the whole catalog and would otherwise push
 * the catalog itself off the plugin-hub screen. A submitted version appears here after the
 * publisher uploads the package and leaves the queue on approve (published) or reject
 * (the publisher sees `review_note` and may correct + resubmit the same version).
 */
export default function HubReviewPage() {
  const { t } = useI18n()
  const { message } = AntApp.useApp()
  const pageSize = LIST_PAGE_SIZE

  const [rows, setRows] = useState<HubReviewRow[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const [rejectTarget, setRejectTarget] = useState<HubReviewRow | null>(null)
  const [rejectReason, setRejectReason] = useState('')

  const load = useCallback(
    async (p: number) => {
      setLoading(true)
      setErr(null)
      try {
        const r = await listHubReviews({ page: p, page_size: pageSize })
        setRows(r.items ?? [])
        setTotal(r.total ?? 0)
      } catch (e) {
        setErr(errText(e))
      } finally {
        setLoading(false)
      }
    },
    [pageSize],
  )

  useEffect(() => {
    void load(page)
  }, [load, page])

  async function handleApprove(row: HubReviewRow) {
    const key = `${row.plugin_id}@${row.version}`
    setBusy(key)
    try {
      await approveHubVersion(row.plugin_id, row.version)
      message.success(
        t('Approved {name} {version}; other users can now see and install it', {
          name: row.name,
          version: row.version,
        }),
      )
      if (rows.length === 1 && page > 1) setPage((p) => p - 1)
      else void load(page)
    } catch (e) {
      message.error(errText(e))
    } finally {
      setBusy(null)
    }
  }

  async function submitReject() {
    if (!rejectTarget) return
    const reason = rejectReason.trim()
    if (!reason) {
      message.warning(t('Please give the publisher a rejection reason'))
      return
    }
    const row = rejectTarget
    setBusy(`${row.plugin_id}@${row.version}`)
    try {
      await rejectHubVersion(row.plugin_id, row.version, reason)
      message.success(t('Rejected {name} {version}; the publisher sees the reason', { name: row.name, version: row.version }))
      setRejectTarget(null)
      setRejectReason('')
      if (rows.length === 1 && page > 1) setPage((p) => p - 1)
      else void load(page)
    } catch (e) {
      message.error(errText(e))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="page-fill">
      {err && <Alert type="error" showIcon message={t('Failed to load')} description={err} />}

      <Card className="list-card">
        <div className="toolbar">
          <span className="muted">{t('{count} waiting', { count: total })}</span>
          <HelpTip title={t('A plugin becomes visible to other users only after approval.')} />
          <div className="toolbar-right">
            <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void load(page)}>
              {t('Refresh')}
            </Button>
          </div>
        </div>

        <Table<HubReviewRow>
          size="small"
          rowKey={(r) => `${r.plugin_id}@${r.version}`}
          loading={loading}
          dataSource={rows}
          scroll={{ y: LIST_SCROLL_Y }}
          locale={{
            emptyText: (
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description={t('No plugin is waiting for review')}
              />
            ),
          }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: false,
            onChange: (p) => setPage(p),
            showTotal: (count) => t('{count} items', { count }),
          }}
          columns={[
            {
              title: t('Plugin'),
              render: (_, r) => (
                <Space direction="vertical" size={0}>
                  <Space size={6}>
                    <span className="cell-title">{r.name}</span>
                    <Tag color="blue" style={{ marginInlineEnd: 0 }}>
                      v{r.version}
                    </Tag>
                  </Space>
                  <span className="cell-sub">{r.plugin_id}</span>
                </Space>
              ),
            },
            {
              title: t('Publisher'),
              width: 160,
              render: (_, r) => hubOwnerLabel(r.owner, t),
            },
            {
              title: t('Changelog'),
              dataIndex: 'changelog',
              ellipsis: true,
              render: (v: string) =>
                v ? (
                  <Tooltip title={v}>
                    <span>{v}</span>
                  </Tooltip>
                ) : (
                  <Typography.Text type="secondary">—</Typography.Text>
                ),
            },
            {
              title: t('Package'),
              width: 150,
              render: (_, r) => (
                <Space size={6}>
                  <span>{fmtBytes(r.size)}</span>
                  {r.has_source && (
                    <Tag color="green" style={{ marginInlineEnd: 0 }}>
                      {t('Source')}
                    </Tag>
                  )}
                </Space>
              ),
            },
            {
              title: t('Submitted'),
              dataIndex: 'submitted_at',
              width: 130,
              render: (v: string) => (
                <Tooltip title={fmtTime(v)}>
                  <span>{fmtRelative(v)}</span>
                </Tooltip>
              ),
            },
            {
              title: t('Actions'),
              width: 190,
              render: (_, r) => {
                const rowBusy = busy === `${r.plugin_id}@${r.version}`
                return (
                  <Space size={4}>
                    <Button
                      size="small"
                      type="primary"
                      icon={<CheckOutlined />}
                      loading={rowBusy}
                      onClick={() => void handleApprove(r)}
                    >
                      {t('Approve')}
                    </Button>
                    <Button
                      size="small"
                      danger
                      icon={<CloseOutlined />}
                      disabled={rowBusy}
                      onClick={() => {
                        setRejectReason('')
                        setRejectTarget(r)
                      }}
                    >
                      {t('Reject')}
                    </Button>
                  </Space>
                )
              },
            },
          ]}
        />
      </Card>

      <Modal
        open={rejectTarget != null}
        title={t('Reject submission')}
        okText={t('Reject')}
        okButtonProps={{ danger: true }}
        cancelText={t('Cancel')}
        confirmLoading={busy != null && rejectTarget != null && busy === `${rejectTarget.plugin_id}@${rejectTarget.version}`}
        onOk={() => void submitReject()}
        onCancel={() => {
          setRejectTarget(null)
          setRejectReason('')
        }}
      >
        <div style={{ marginBottom: 10 }}>
          {rejectTarget
            ? t(
                '{name} {version} stays invisible to other users. The publisher sees the reason below and can correct and resubmit the same version.',
                { name: rejectTarget.name, version: rejectTarget.version },
              )
            : ''}
        </div>
        <Input.TextArea
          rows={4}
          maxLength={500}
          showCount
          value={rejectReason}
          onChange={(e) => setRejectReason(e.target.value)}
          placeholder={t('Why is this submission rejected? (required, up to 500 characters)')}
        />
      </Modal>
    </div>
  )
}
