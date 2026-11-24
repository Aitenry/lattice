import { useCallback, useEffect, useState } from 'react'
import { LIST_PAGE_SIZE, LIST_SCROLL_Y } from '@/components/listLayout'
import { Alert, Button, Card, Empty, Input, Popconfirm, Space, Switch, Table, Tag, Tooltip, Typography, App as AntApp } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { errText } from '@/lib/errors'
import { listDevices, revokeDevice } from '@/api/endpoints'
import type { DeviceRow } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { fmtRelative, fmtTime } from '@/lib/format'
import { PLATFORM, pick } from '@/lib/labels'
import { HelpTip } from '@/components/HelpTip'
import { useI18n } from '@/i18n'

export default function DevicesPage() {
  const { t } = useI18n()
  const { message } = AntApp.useApp()
  const { can, role, session } = useAuth()
  // Regular accounts only ever see their own devices (the server enforces the same scope);
  // the "filter by user" box would be misleading there, so it is hidden.
  const ownScope = role === 'user'
  const [rows, setRows] = useState<DeviceRow[]>([])
  const [user, setUser] = useState('')
  const [revoked, setRevoked] = useState<boolean>(false)
  const [loading, setLoading] = useState(false)
  // Rows per page follow the viewport height so the table fills the card without a scrollbar
  const pageSize = LIST_PAGE_SIZE
  const [err, setErr] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setErr(null)
    try {
      const r = await listDevices({ user: ownScope ? undefined : user || undefined, revoked })
      setRows(r.items ?? [])
    } catch (e) {
      setErr(errText(e))
    } finally {
      setLoading(false)
    }
  }, [ownScope, user, revoked])

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
          {!ownScope && (
            <Input.Search
              allowClear
              placeholder={t('Filter by user ID')}
              style={{ width: 300 }}
              onSearch={(v) => setUser(v.trim())}
            />
          )}
          <Space size={6}>
            <Switch size="small" checked={revoked} onChange={setRevoked} />
            <Typography.Text type="secondary">{t('Revoked only')}</Typography.Text>
            <HelpTip title={t('Revoking signs the device out immediately and invalidates its credentials; the user must sign in again.')} />
          </Space>
          <span className="muted">{t('{count} devices', { count: rows.length })}</span>
        </div>

        <Table<DeviceRow>
          size="small"
          scroll={{ y: LIST_SCROLL_Y }}
          rowKey="id"
          loading={loading}
          dataSource={rows}
          locale={{ emptyText: <Empty description={t('No matching devices')} image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
          pagination={{ pageSize, showSizeChanger: false, showTotal: (count) => t('{count} devices', { count }) }}
          columns={[
            {
              title: t('Device'),
              dataIndex: 'name',
              render: (v: string | null, r) => (
                <Space direction="vertical" size={0}>
                  <span className="cell-title">{v || t('Unnamed device')}</span>
                  <span className="cell-sub">{t(pick(PLATFORM, r.platform, r.platform || 'Unknown platform'))}</span>
                </Space>
              ),
            },
            {
              title: t('Device owner'),
              dataIndex: 'user_id',
              render: (v: string) => <span className="cell-sub">{v}</span>,
            },
            {
              title: (
                <Space size={2}>
                  {t('Device fingerprint')}
                  <HelpTip title={t('Unique identifier assigned when the device comes online. Useful for issues such as "the same account behaves oddly on two devices".')} />
                </Space>
              ),
              dataIndex: 'fingerprint',
              render: (v: string) => (
                <Tooltip title={v}>
                  <Typography.Text className="cell-sub" copyable={{ text: v, tooltips: [t('Copy full fingerprint'), t('Copied')] }}>
                    {v.length > 22 ? `${v.slice(0, 22)}…` : v}
                  </Typography.Text>
                </Tooltip>
              ),
            },
            {
              title: t('Last active'),
              dataIndex: 'last_seen',
              width: 130,
              render: (v: string | null) =>
                v ? (
                  <Tooltip title={fmtTime(v)}>
                    <span>{fmtRelative(v)}</span>
                  </Tooltip>
                ) : (
                  <span className="muted">{t('Never online')}</span>
                ),
            },
            {
              title: t('Status'),
              dataIndex: 'revoked_at',
              width: 130,
              render: (v: string | null) =>
                v ? (
                  <Tooltip title={t('Revoked at {time}', { time: fmtTime(v) })}>
                    <Tag color="red">{t('Revoked')}</Tag>
                  </Tooltip>
                ) : (
                  <Tag color="green">{t('Usable')}</Tag>
                ),
            },
            {
              title: t('Actions'),
              width: 96,
              render: (_, r) =>
                can('dispose') || (ownScope && r.user_id === session?.userId) ? (
                  <Popconfirm
                    title={t('Revoke this device remotely?')}
                    description={t('The device goes offline immediately and the user must sign in again. The account itself is not affected.')}
                    okText={t('Revoke')}
                    okButtonProps={{ danger: true }}
                    cancelText={t('Cancel')}
                    onConfirm={async () => {
                      try {
                        await revokeDevice(r.id)
                        message.success(t('Device revoked'))
                        void load()
                      } catch (e) {
                        message.error(errText(e))
                      }
                    }}
                  >
                    <Button size="small" danger type="link" disabled={Boolean(r.revoked_at)}>
                      {t('Revoke')}
                    </Button>
                  </Popconfirm>
                ) : (
                  <Typography.Text type="secondary">—</Typography.Text>
                ),
            },
          ]}
        />
      </Card>
    </div>
  )
}
