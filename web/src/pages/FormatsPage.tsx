import { useCallback, useEffect, useState } from 'react'
import { Alert, Button, Card, Empty, Form, Input, Modal, Space, Table, Tag, Typography, App as AntApp } from 'antd'
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons'
import { LIST_PAGE_SIZE, LIST_SCROLL_Y } from '@/components/listLayout'
import { errText } from '@/lib/errors'
import { listFormats, upsertFormat } from '@/api/endpoints'
import type { FormatRow } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { HelpTip } from '@/components/HelpTip'
import { JsonPeek } from '@/components/JsonPeek'
import { useI18n } from '@/i18n'

export default function FormatsPage() {
  const { message } = AntApp.useApp()
  const { t } = useI18n()
  const { can } = useAuth()
  const [rows, setRows] = useState<FormatRow[]>([])
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
      const r = await listFormats()
      setRows(r.items ?? [])
    } catch (e) {
      setErr(errText(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  // Keep the current page valid when the registry shrinks
  useEffect(() => {
    const maxPage = Math.max(1, Math.ceil(rows.length / pageSize))
    if (page > maxPage) setPage(maxPage)
  }, [rows.length, page, pageSize])

  async function submit() {
    const v = await form.validateFields()
    try {
      let detect: unknown = undefined
      if (v.detect_rules) {
        try {
          detect = JSON.parse(v.detect_rules)
        } catch {
          message.error(t('Detection rules are not valid JSON; check the brackets and quotes'))
          return
        }
      }
      await upsertFormat({ type: v.type, mime: v.mime, handler: v.handler, detect_rules: detect } as never)
      message.success(t('Saved; newly uploaded files will be detected with the new rules'))
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
          <span className="muted">{t('{count} formats', { count: rows.length })}</span>
          <div className="toolbar-right">
            <Button icon={<ReloadOutlined />} loading={loading} onClick={load}>
              {t('Refresh')}
            </Button>
            {can('mutate') && (
              <Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>
                {t('Add / update format')}
              </Button>
            )}
          </div>
        </div>

        <Table<FormatRow>
          size="small"
          scroll={{ y: LIST_SCROLL_Y }}
          rowKey={(r) => String(r.id ?? `${r.type}:${r.mime}`)}
          loading={loading}
          dataSource={rows.slice((page - 1) * pageSize, page * pageSize)}
          locale={{ emptyText: <Empty description={t('No formats registered yet')} image={Empty.PRESENTED_IMAGE_SIMPLE} /> }}
          pagination={{
            current: page,
            pageSize,
            total: rows.length,
            showSizeChanger: false,
            onChange: (p) => setPage(p),
            showTotal: (count) => t('{count} formats', { count }),
          }}
          expandable={{
            expandedRowRender: (r) => (
              <JsonPeek data={r} label={t('Raw response of the format registry endpoint (GET /v1/admin/formats)')} />
            ),
          }}
          columns={[
            {
              title: (
                <Space size={2}>
                  {t('Content type')}
                  <HelpTip title={t('The type name used inside the platform; clients pick their upload method from it.')} />
                </Space>
              ),
              dataIndex: 'type',
              width: 200,
              render: (v) => <Tag color="blue">{v}</Tag>,
            },
            {
              title: t('MIME type'),
              dataIndex: 'mime',
              render: (v: string) => <span className="cell-sub">{v}</span>,
            },
            {
              title: t('Handler'),
              dataIndex: 'handler',
              render: (v: string) => <span className="cell-sub">{v}</span>,
            },
          ]}
        />
      </Card>

      <Modal
        open={open}
        title={t('Add / update format')}
        okText={t('Save')}
        cancelText={t('Cancel')}
        onOk={submit}
        onCancel={() => setOpen(false)}
        destroyOnClose
      >
        <Form form={form} layout="vertical" requiredMark={false}>
          <Form.Item name="type" label={t('Content type')} rules={[{ required: true, message: t('Enter the internal type name') }]}>
            <Input placeholder={t('e.g. json, image')} />
          </Form.Item>
          <Form.Item name="mime" label={t('MIME type')} rules={[{ required: true, message: t('Enter a MIME type') }]}>
            <Input placeholder={t('e.g. application/json')} />
          </Form.Item>
          <Form.Item name="handler" label={t('Handler')} rules={[{ required: true, message: t('Enter a handler') }]}>
            <Input placeholder={t('e.g. builtin:json')} />
          </Form.Item>
          <Form.Item
            name="detect_rules"
            label={
              <Space size={2}>
                {t('Detection rules (advanced, optional)')}
                <HelpTip
                  title={t(
                    'Detect the type from file-header bytes, file extension and other traits, written as JSON. Leave empty to trust only the type the client declares.',
                  )}
                />
              </Space>
            }
          >
            <Input.TextArea rows={4} placeholder='{"magic":"7B","min_len":2}' style={{ fontFamily: 'monospace' }} />
          </Form.Item>
        </Form>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {t(
            'If the platform has the signing plugin installed, changing detection rules also triggers plugin signature verification; a failed check is rejected.',
          )}
        </Typography.Text>
      </Modal>
    </div>
  )
}
