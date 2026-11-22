import { useEffect, useState } from 'react'
import { Alert, Input, Modal, Typography } from 'antd'
import { errText } from '@/lib/errors'
import { useI18n } from '@/i18n'

/**
 * Shared dialog for risky actions (API §8: "a risky action must carry a reason, written
 * to audit_log.detail").
 *
 * Extracted so each page does not grow its own reason input with a different field name
 * or validation — a single missing `reason` returns 422, and that is exactly the kind of
 * detail every call site forgets.
 */
export function ReasonModal(props: {
  open: boolean
  title: string
  description?: string
  /** Asks the user to type the target name again (e.g. confirm_username for purge) */
  confirmText?: { label: string; expect: string }
  okText?: string
  danger?: boolean
  onCancel: () => void
  onSubmit: (reason: string) => Promise<void>
}) {
  const { t } = useI18n()
  const { open, title, description, confirmText, okText, danger, onCancel, onSubmit } = props
  const [reason, setReason] = useState('')
  const [confirm, setConfirm] = useState('')
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    if (open) {
      setReason('')
      setConfirm('')
      setErr(null)
      setLoading(false)
    }
  }, [open])

  const confirmOk = !confirmText || confirm === confirmText.expect
  const reasonOk = reason.trim().length > 0

  async function submit() {
    setLoading(true)
    setErr(null)
    try {
      await onSubmit(reason.trim())
      onCancel()
    } catch (e) {
      setErr(errText(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal
      open={open}
      title={title}
      okText={okText ?? t('Confirm')}
      cancelText={t('Cancel')}
      okButtonProps={{ danger, disabled: !reasonOk || !confirmOk, loading }}
      onOk={submit}
      onCancel={onCancel}
      destroyOnClose
    >
      {description && (
        <Typography.Paragraph type="secondary" style={{ marginBottom: 12 }}>
          {description}
        </Typography.Paragraph>
      )}
      {err && <Alert type="error" showIcon message={err} style={{ marginBottom: 12 }} />}
      <Typography.Text strong>{t('Reason (recorded in audit)')}</Typography.Text>
      <Input.TextArea
        rows={3}
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder={t('e.g. node maintenance window / user requested deletion / backlog cleanup')}
        style={{ marginTop: 6, marginBottom: confirmText ? 12 : 0 }}
        maxLength={500}
        showCount
      />
      {confirmText && (
        <>
          <Typography.Text strong>{confirmText.label}</Typography.Text>
          <Input
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder={t('Type {value} to confirm', { value: confirmText.expect })}
            style={{ marginTop: 6 }}
          />
        </>
      )}
    </Modal>
  )
}
