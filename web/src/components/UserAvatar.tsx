import { Avatar } from 'antd'
import type { CSSProperties } from 'react'
import { useI18n } from '@/i18n'

/**
 * Shared avatar (v0.9).
 *
 * One rule across the console: with `src` (an `https://` link or a server data URL) show
 * the image; otherwise fall back to a circle with the initial of the display name /
 * username. Colours come from CSS variables (`.user-avatar` plus --avatar-bg/--avatar-fg
 * in styles.css) and follow the light/dark theme; pages must not set
 * `style={{ background: '#dbeafe' }}` themselves.
 */

/** Initial: the first character, uppercased; an empty value falls back to `?` */
export function initialOfName(name: string | null | undefined): string {
  const text = (name ?? '').trim()
  if (!text) return '?'
  const first = Array.from(text)[0] ?? '?'
  return first.toUpperCase()
}

export function UserAvatar(props: {
  /** Name used for the initial fallback (display name first, then username) */
  name: string | null | undefined
  /** Avatar URL; empty/null shows the initial */
  src?: string | null
  size?: number
  /** Extra class names (spacing/alignment only, never colours) */
  className?: string
  style?: CSSProperties
}) {
  const { t } = useI18n()
  const className = ['user-avatar', props.className].filter(Boolean).join(' ')
  return (
    <Avatar
      size={props.size ?? 32}
      src={props.src || undefined}
      className={className}
      style={props.style}
      alt={props.name ? t('Avatar of {name}', { name: props.name }) : t('Avatar')}
    >
      {initialOfName(props.name)}
    </Avatar>
  )
}
