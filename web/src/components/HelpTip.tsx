import type { ReactNode } from 'react'
import { Tooltip } from 'antd'
import { QuestionCircleOutlined } from '@ant-design/icons'
import { useI18n } from '@/i18n'

/** Small question mark that explains a term or field. It sits next to every internal concept so users do not have to read the docs. */
export function HelpTip(props: { title: ReactNode; label?: string }) {
  const { t } = useI18n()
  return (
    <Tooltip title={props.title}>
      <QuestionCircleOutlined className="help-tip" aria-label={props.label ?? t('Help')} />
    </Tooltip>
  )
}
