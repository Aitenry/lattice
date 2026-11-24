import { Avatar } from 'antd'

/**
 * Plugin icon (hub catalogue + detail drawer).
 *
 * Render the publisher-supplied URL only when it is a directly usable image; remixicon names
 * are resolved by the desktop client and the console has no icon font, so everything else
 * falls back to the first letter of the name.
 */
export function PluginIcon({ icon, name, size = 42 }: { icon: string | null; name: string; size?: number }) {
  const isImage = Boolean(icon && /^(https?:\/\/|data:image\/)/i.test(icon))
  if (isImage) {
    return <Avatar shape="square" size={size} src={icon} style={{ flex: `0 0 ${size}px`, borderRadius: 10 }} />
  }
  return (
    <Avatar
      shape="square"
      size={size}
      style={{
        flex: `0 0 ${size}px`,
        borderRadius: 10,
        fontSize: Math.round(size / 2.4),
        fontWeight: 600,
      }}
    >
      {(name || '?').trim().slice(0, 1).toUpperCase()}
    </Avatar>
  )
}
