import { Tag } from 'antd'
import type { CSSProperties } from 'react'
import { ROLE_COLOR, ROLE_LABEL } from '@/auth/rbac'
import { useI18n } from '@/i18n'

/**
 * Role badge (v0.9): one set of colours and labels across the console.
 *
 * Colours live in `auth/rbac.ts` as `ROLE_COLOR` (admin red / ops gold / user blue); both
 * the header account area and the user-management list use this component instead of each
 * writing its own Tag.
 */
export function RoleTag(props: { role: string | null | undefined; style?: CSSProperties }) {
  const { t } = useI18n()
  if (!props.role) {
    return (
      <Tag color="default" style={props.style}>
        {t('Unknown')}
      </Tag>
    )
  }
  return (
    <Tag color={ROLE_COLOR[props.role] ?? 'default'} style={props.style}>
      {t(ROLE_LABEL[props.role] ?? props.role)}
    </Tag>
  )
}
