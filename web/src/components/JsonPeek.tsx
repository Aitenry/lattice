import { Collapse, Typography } from 'antd'
import { prettyJson } from '@/lib/format'
import { useI18n } from '@/i18n'

/**
 * "Technical details" collapsible block.
 *
 * These JSON blobs used to be spread over the page and were one of the main reasons the
 * console was hard to read. They are collapsed by default now, expanded only when
 * troubleshooting, and the copy button is still there.
 */
export function JsonPeek(props: { data: unknown; label?: string; indent?: number }) {
  const { t } = useI18n()
  const text = prettyJson(props.data, props.indent ?? 2)
  return (
    <Collapse
      ghost
      size="small"
      items={[
        {
          key: 'raw',
          label: <Typography.Text type="secondary">{t('Technical details (raw API data)')}</Typography.Text>,
          children: (
            <div>
              <div style={{ marginBottom: 6 }}>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {props.label ?? t('For troubleshooting only; everyday work does not need this.')}
                </Typography.Text>
              </div>
              <pre className="raw-block">{text}</pre>
            </div>
          ),
        },
      ]}
    />
  )
}
