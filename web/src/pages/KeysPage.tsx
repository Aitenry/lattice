import { useCallback, useEffect, useState } from 'react'
import { Alert, Button, Card, Form, Input, Modal, Select, Space, Table, Tag, Typography, App as AntApp } from 'antd'
import { ReloadOutlined, SwapOutlined } from '@ant-design/icons'
import { errText } from '@/lib/errors'
import { listKeys, rotateKeys } from '@/api/endpoints'
import type { KeysResp } from '@/api/types'
import { LIST_PAGE_SIZE, LIST_SCROLL_Y } from '@/components/listLayout'
import { useAuth } from '@/auth/AuthProvider'
import { fmtDuration } from '@/lib/format'
import { KEY_ROLE, KEY_TARGET, pick } from '@/lib/labels'
import { HelpTip } from '@/components/HelpTip'
import { useI18n } from '@/i18n'

export default function KeysPage() {
  const { message } = AntApp.useApp()
  const { t } = useI18n()
  const { can } = useAuth()
  const [data, setData] = useState<KeysResp | null>(null)
  const [loading, setLoading] = useState(false)
  const [page, setPage] = useState(1)
  const pageSize = LIST_PAGE_SIZE
  const [err, setErr] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const [form] = Form.useForm()

  const load = useCallback(async () => {
    setLoading(true)
    setErr(null)
    try {
      setData(await listKeys())
    } catch (e) {
      setErr(errText(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const keyRows = data?.items ?? []
  // Keep the current page valid when keys are rotated out
  useEffect(() => {
    const maxPage = Math.max(1, Math.ceil(keyRows.length / pageSize))
    if (page > maxPage) setPage(maxPage)
  }, [keyRows.length, page, pageSize])

  async function submit() {
    const v = await form.validateFields()
    try {
      await rotateKeys({ target: v.target, reason: v.reason })
      message.success(t('Rotation accepted: the new key starts issuing, the old key keeps verifying for 24 hours'))
      setOpen(false)
      form.resetFields()
      void load()
    } catch (e) {
      message.error(errText(e))
    }
  }

  return (
    <div className="page-fill">
      {err && <Alert type="error" showIcon message={t('Failed to load')} description={err} />}

      <Card className="list-card">
        <div className="toolbar">
          <span className="muted">
            {t('Login token lifetime')}:{' '}
            {data?.ttl_seconds != null
              ? t('{duration} ({seconds} s)', {
                  duration: fmtDuration(data.ttl_seconds),
                  seconds: data.ttl_seconds,
                })
              : '—'}{' '}
            · {t('{count} keys', { count: data?.items?.length ?? 0 })}
          </span>
          <HelpTip
            title={t(
              'The new key starts issuing tokens while the old key keeps verifying signatures; both run in parallel for 24 hours. Users are not signed out during this window. After 24 hours the old key expires, and tokens that have not been refreshed by then require signing in again.',
            )}
          />
          <div className="toolbar-right">
            <Button icon={<ReloadOutlined />} loading={loading} onClick={load}>
              {t('Refresh')}
            </Button>
            {can('mutate') && (
              <Button
                danger
                type="primary"
                icon={<SwapOutlined />}
                onClick={() => {
                  setOpen(true)
                }}
              >
                {t('Rotate keys')}
              </Button>
            )}
          </div>
        </div>

        <Table<{ fingerprint: string; role: string }>
          size="small"
          scroll={{ y: LIST_SCROLL_Y }}
          rowKey="fingerprint"
          loading={loading}
          dataSource={keyRows.slice((page - 1) * pageSize, page * pageSize)}
          pagination={{
            current: page,
            pageSize,
            total: keyRows.length,
            showSizeChanger: false,
            onChange: (p) => setPage(p),
            showTotal: (count) => t('{count} keys', { count }),
          }}
          locale={{ emptyText: t('No key records') }}
          columns={[
            {
              title: (
                <Space size={2}>
                  {t('Fingerprint')}
                  <HelpTip
                    title={t(
                      'The fingerprint is a public digest of the key: it tells you which key is in use, but it cannot be reversed into the key itself.',
                    )}
                  />
                </Space>
              ),
              dataIndex: 'fingerprint',
              render: (v: string) => (
                <Typography.Text className="cell-sub" copyable={{ text: v, tooltips: [t('Copy fingerprint'), t('Copied')] }}>
                  {v}
                </Typography.Text>
              ),
            },
            {
              title: t('Key role'),
              dataIndex: 'role',
              width: 180,
              render: (v: string) => (
                <Tag color={v === 'current' ? 'green' : 'default'}>{t(pick(KEY_ROLE, v, v))}</Tag>
              ),
            },
          ]}
        />
      </Card>

      <Modal
        open={open}
        title={t('Rotate keys')}
        okText={t('Confirm rotation')}
        okButtonProps={{ danger: true }}
        cancelText={t('Cancel')}
        onOk={submit}
        onCancel={() => setOpen(false)}
        destroyOnClose
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 14 }}
          message={t(
            'Rotation does not affect active sessions: the old and new keys run in parallel for 24 hours, so users do not need to sign in again.',
          )}
        />
        <Form form={form} layout="vertical" requiredMark={false} initialValues={{ target: 'jwt' }}>
          <Form.Item name="target" label={t('Which key to rotate')} rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'jwt', label: t('Login token signing key (affects all sign-ins)') },
                { value: 'kek', label: t('Data encryption master key (affects decryption of historical data)') },
                { value: 'internal_ca', label: t('Node mutual-trust certificate (affects node-to-node traffic)') },
              ]}
            />
          </Form.Item>
          <Form.Item
            name="reason"
            label={t('Rotation reason (recorded in the audit log)')}
            rules={[{ required: true, message: t('Enter a reason') }]}
          >
            <Input.TextArea rows={3} placeholder={t('e.g. quarterly rotation / suspected key leak')} />
          </Form.Item>
        </Form>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {t('Available targets: {targets}', {
            targets: Object.values(KEY_TARGET)
              .map((v) => t(v))
              .join(', '),
          })}
        </Typography.Text>
      </Modal>
    </div>
  )
}
